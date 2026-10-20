// SPDX-License-Identifier: GPL-2.0
//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_ARGS 64
// 128 KiB: Linux allows a single argument string of up to 128 KiB
// (MAX_ARG_STRLEN), so one Bash command of a harness always fits; only a
// command line of many large arguments exceeds it, and then args_truncated
// says so (P-19).
#define MAX_ARGS_BYTES 131072
#define FILENAME_LEN 256

#define KIND_EXEC 0
#define KIND_EXIT 1
#define KIND_FORK 2 // a tracked process created a child; header only, no filename or args
#define KIND_EXEC_OK 3 // an exec took effect; header only, tid names the thread whose attempt it was

#define path_is(fn, literal) __extension__({ \
	int _match = 1; \
	_Pragma("clang loop unroll(full)") \
	for (unsigned _i = 0; _i < sizeof(literal); _i++) \
		_match &= ((fn)[_i] == (literal)[_i]); \
	_match; \
})

static __always_inline int filename_is_shell(const char *fn) {
	return path_is(fn, "/bin/sh")   || path_is(fn, "/usr/bin/sh")   ||
	       path_is(fn, "/bin/bash") || path_is(fn, "/usr/bin/bash") ||
	       path_is(fn, "/bin/dash") || path_is(fn, "/usr/bin/dash") ||
	       path_is(fn, "/bin/zsh")  || path_is(fn, "/usr/bin/zsh");
}

struct event_hdr {
	__u32 pid;
	__u32 ppid; // parent tgid when the process exec'd, from the task struct
	__u32 kind;
	__u32 nargs;
	__s64 ts_ns;
	__s32 exit_code;
	__u8  has_exit_code;
	__u8  is_toplevel;
	__u8  args_truncated; // the filename or the arguments did not fit
	__u8  pad0;
	__u32 filename_len;
	__u32 args_size;
	__u32 tid; // the thread that made the exec attempt (KIND_EXEC, KIND_EXEC_OK)
	__u32 pad1;
};

struct exec_scratch {
	struct event_hdr hdr;
	char filename[FILENAME_LEN];
	char args[MAX_ARGS_BYTES * 2]; // Padded to satisfy verifier worst-case offset+size bounds
};

struct proc_info {
	__u8 is_shell;
	__u8 is_toplevel;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, struct proc_info);
} tracked_pids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u8);
} config_map SEC(".maps");

static __always_inline __u8 get_use_pid_filter() {
	__u32 zero = 0;
	__u8 *val = bpf_map_lookup_elem(&config_map, &zero);
	return val ? *val : 0;
}

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} root_pid_map SEC(".maps");

static __always_inline __u32 get_root_pid() {
	__u32 zero = 0;
	__u32 *val = bpf_map_lookup_elem(&root_pid_map, &zero);
	return val ? *val : 0;
}

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 23); // 8 MiB: an exec record can be 128 KiB
} events SEC(".maps");

// drop_count counts bpf_ringbuf_output failures on events. A full ring
// buffer discards the record and returns a negative errno. Without this
// counter, an honest agent's action lost here is indistinguishable
// downstream from one the agent never performed (a false T2 fabrication
// verdict). Userspace sums the percpu slots and snapshots them in Stop().
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} drop_count SEC(".maps");

static __always_inline void count_drop(void)
{
	__u32 zero = 0;
	__u64 *count = bpf_map_lookup_elem(&drop_count, &zero);
	if (count)
		__sync_fetch_and_add(count, 1);
}

// untracked_count counts descendants that could not be added to tracked_pids
// because the map was full. Such a process, and every process it forks
// afterwards, is silently outside the tracked tree: its events never reach
// the ground truth, which downstream reads as the agent never acting (or as
// fabrication when the agent claimed it). One increment can stand for a whole
// lost subtree, so the value is a lower bound and only zero versus non-zero
// is meaningful. Kept apart from drop_count so a report can tell ring loss
// from tree loss. Userspace sums the percpu slots and snapshots them in Stop().
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} untracked_count SEC(".maps");

static __always_inline void count_untracked(void)
{
	__u32 zero = 0;
	__u64 *count = bpf_map_lookup_elem(&untracked_count, &zero);
	if (count)
		__sync_fetch_and_add(count, 1);
}

// state_lost_count counts records this program lost because a state map it
// writes per process or per connection was full (execs). Unlike a ring buffer
// drop the failure happens in a map update, so it is easy to miss: a process whose entry could not be stored never gets its exit record, so its exit and exit code vanish from the ground truth.
// Userspace sums the percpu slots and snapshots them in Stop().
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} state_lost_count SEC(".maps");

static __always_inline void count_state_lost(void)
{
	__u32 zero = 0;
	__u64 *count = bpf_map_lookup_elem(&state_lost_count, &zero);
	if (count)
		__sync_fetch_and_add(count, 1);
}

// heap is the scratch record, one slot per CPU. A per-CPU array would be
// the natural map, but the kernel caps a per-CPU value at 32 KiB and the
// 128 KiB command line needs 256 KiB (P-19), so this is a plain array with
// one entry per possible CPU, sized by userspace at load and indexed by the
// running CPU: record_exec runs under the sys_enter raw tracepoint, which
// calls it with preemption disabled, so the slot is private to it.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1); // overridden at load to the possible CPU count
	__type(key, __u32);
	__type(value, struct exec_scratch);
} heap SEC(".maps");

static __always_inline struct exec_scratch *scratch(void)
{
	__u32 cpu = bpf_get_smp_processor_id();
	return bpf_map_lookup_elem(&heap, &cpu);
}

// execs keeps, per tracked process, a header from the latest exec that took
// effect until it exits: the exit code lands here and the exit record is this
// header. A process whose exec attempts all failed has no entry, as one that
// never exec'd. The command line is not kept in the kernel (4096 entries of
// 256 KiB would be 1 GiB preallocated); userspace joins the exit to the
// attempt that took effect, which it already read (P-19, P-31).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, struct event_hdr);
} execs SEC(".maps");

#define CLONE_THREAD 0x10000

// task_newtask(struct task_struct *task, u64 clone_flags) fires in the
// parent.
SEC("raw_tracepoint/task_newtask")
int handle_fork(struct bpf_raw_tracepoint_args *ctx)
{
	if (!get_use_pid_filter())
		return 0;

	// A new thread shares its process's tgid, which is already tracked. Its
	// tid is not a tgid and handle_exit only deletes on tid == tgid, so
	// inserting it would leak an entry per thread and, once the number is
	// recycled as an unrelated process's pid, track a stranger.
	if (ctx->args[1] & CLONE_THREAD)
		return 0;

	__u32 parent_pid = bpf_get_current_pid_tgid() >> 32;
	struct task_struct *child_task = (struct task_struct *)ctx->args[0];
	__u32 child_pid = BPF_CORE_READ(child_task, pid);

	struct proc_info *p = bpf_map_lookup_elem(&tracked_pids, &parent_pid);
	if (!p)
		return 0;

	// Record the edge parent -> child. An exec record only exists for a child
	// that execs, and a subshell or a pipeline element running a builtin forks
	// without exec, so without this record its activity could not be tied to
	// the tree (V1 in docs/decisions/verification.md). A lost record is counted like any other.
	struct event_hdr fh = {};
	fh.pid = child_pid;
	fh.ppid = parent_pid;
	fh.kind = KIND_FORK;
	fh.ts_ns = bpf_ktime_get_ns();
	if (bpf_ringbuf_output(&events, &fh, sizeof(fh), 0))
		count_drop();

	struct proc_info child = {0};
	if (p->is_shell && p->is_toplevel) {
		child.is_toplevel = 1;
	} else {
		child.is_toplevel = 0;
	}

	if (bpf_map_update_elem(&tracked_pids, &child_pid, &child, BPF_ANY))
		count_untracked();
	return 0;
}

// nul_at reports whether the user string at s ends at index i. A
// bpf_probe_read_user_str into a buffer of n bytes returns n both for a
// string of n - 1 bytes, which fits with its NUL, and for a longer one it
// cut; the byte at n - 1 tells them apart.
static __always_inline int nul_at(const char *s, __u32 i)
{
	char c = 1;
	return !bpf_probe_read_user(&c, 1, s + i) && c == '\0';
}

// record_exec records one exec attempt at syscall entry, whether it then
// succeeds or not (P-4): the filename as the kernel was asked for it (or
// "(fexecve)" for an exec through a descriptor, which names no path), then
// argv. Shared by execve and execveat (P-21). handle_exec_ok says which
// attempt took effect (P-31).
static __always_inline int record_exec(const char *filename, const char *const *argv, int via_fd)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;

	struct exec_scratch *e = scratch();
	if (!e)
		return 0;

	e->hdr.pid = pid;
	e->hdr.tid = (__u32)pid_tgid;
	e->hdr.pad1 = 0;
	// The parent as the kernel sees it now, so it is correct whether or not
	// tracked_pids is in use.
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	e->hdr.ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->hdr.kind = KIND_EXEC;
	e->hdr.ts_ns = bpf_ktime_get_ns();
	e->hdr.exit_code = 0;
	e->hdr.has_exit_code = 0;
	e->hdr.args_size = 0;
	e->hdr.nargs = 0;
	e->hdr.args_truncated = 0;
	e->hdr.pad0 = 0;

	e->filename[0] = '\0';
	long fn_len;
	if (via_fd) {
		static const char fexecve[] = "(fexecve)";
		__builtin_memcpy(e->filename, fexecve, sizeof(fexecve));
		fn_len = sizeof(fexecve);
	} else {
		fn_len = bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);
	}
	e->hdr.filename_len = (fn_len > 0) ? fn_len : 0;
	// Fail safe: the record claims a whole filename only when the read
	// succeeded and the string provably ended inside the buffer.
	if (!via_fd && (fn_len <= 0 || (fn_len >= FILENAME_LEN && !nul_at(filename, FILENAME_LEN - 1))))
		e->hdr.args_truncated = 1;

	if (get_use_pid_filter()) {
		struct proc_info *p = bpf_map_lookup_elem(&tracked_pids, &pid);
		if (!p)
			return 0;
		e->hdr.is_toplevel = p->is_toplevel;
		__u32 root = get_root_pid();
		if (root && pid != root)
			p->is_shell = filename_is_shell(e->filename) ? 1 : 0;
	} else {
		e->hdr.is_toplevel = 1;
	}

	__u32 args_size = 0;
	__u32 nargs = 0;

	// Fail safe: args_truncated stays 0 only when every read succeeded and
	// argv provably ended (a NULL pointer) inside the area. A read can fail
	// even on a valid argv, since these reads cannot fault a page in; a
	// failure used to end the loop as if argv had ended, which recorded a
	// cut command line as whole.
#pragma clang loop unroll(full)
	for (int i = 0; i < MAX_ARGS; i++) {
		if (!argv)
			break; // Linux accepts a NULL argv as an empty one
		const char *argp = NULL;
		if (bpf_probe_read_user(&argp, sizeof(argp), &argv[i])) {
			e->hdr.args_truncated = 1;
			break;
		}
		if (!argp)
			break;

		__u32 offset = args_size & (MAX_ARGS_BYTES - 1);

		long n = bpf_probe_read_user_str(&e->args[offset], MAX_ARGS_BYTES, argp);
		if (n <= 0) {
			e->hdr.args_truncated = 1;
			break;
		}
		if (n >= MAX_ARGS_BYTES && !nul_at(argp, MAX_ARGS_BYTES - 1))
			e->hdr.args_truncated = 1; // one string did not fit

		args_size += n;
		nargs++;

		if (args_size > MAX_ARGS_BYTES)
			e->hdr.args_truncated = 1; // the last string ran past the area
		if (args_size >= MAX_ARGS_BYTES) {
			// The area is full, which is no cut unless an argument follows.
			const char *next = NULL;
			if (bpf_probe_read_user(&next, sizeof(next), &argv[i + 1]) || next)
				e->hdr.args_truncated = 1;
			break;
		}
	}
	if (nargs == MAX_ARGS && !e->hdr.args_truncated) {
		const char *more = NULL;
		if (bpf_probe_read_user(&more, sizeof(more), &argv[MAX_ARGS]) || more)
			e->hdr.args_truncated = 1; // more arguments than MAX_ARGS, or unknown
	}
	if (args_size > MAX_ARGS_BYTES)
		args_size = MAX_ARGS_BYTES;

	e->hdr.args_size = args_size;
	e->hdr.nargs = nargs;

	__u32 out_size = sizeof(struct event_hdr) + FILENAME_LEN + args_size;
	if (out_size > sizeof(struct exec_scratch))
		out_size = sizeof(struct exec_scratch);

	if (bpf_ringbuf_output(&events, e, out_size, 0))
		count_drop();
	return 0;
}

// --- syscall hooks (P-32) ---------------------------------------------------
//
// The syscall hooks are one raw tracepoint on sys_enter, as in the net probe
// (N-32). Since Linux 7.0 the perf-event syscall tracepoints of execve and
// execveat copy the user filename into the event before they run the
// program, and on the CI runner the program ran for 5 of 9 execs, with no
// count of the others; a raw tracepoint runs before any of that. The
// dispatcher switches on the syscall number before anything else, since
// sys_enter fires for every syscall on the host, handles exit_group itself,
// and tail-calls one program per exec syscall: record_exec is too large to
// inline twice in one program. The numbers and the argument registers are
// those of x86_64 (rdi, rsi, rdx, r10, r8). A 32-bit (ia32) syscall has other
// numbers; like the per-syscall tracepoints, which ignore compat syscalls on
// x86_64, the dispatcher skips it. An x32 number carries bit 30 and matches
// nothing.

#define NR_execve     59
#define NR_exit_group 231
#define NR_execveat   322

// Slots of sys_enter_progs. sysEnterPrograms in observer.go fills them in
// this order.
enum sys_slot {
	SLOT_EXECVE,
	SLOT_EXECVEAT,
	SLOT_COUNT,
};

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, SLOT_COUNT);
	__type(key, __u32);
	__type(value, __u32);
} sys_enter_progs SEC(".maps");

#define TS_COMPAT 0x0002 // thread_info.status: a 32-bit syscall is running

static __always_inline struct pt_regs *sys_regs(struct bpf_raw_tracepoint_args *ctx)
{
	return (struct pt_regs *)ctx->args[0];
}

#define SYS_ARG1(regs) BPF_CORE_READ(regs, di)
#define SYS_ARG2(regs) BPF_CORE_READ(regs, si)
#define SYS_ARG3(regs) BPF_CORE_READ(regs, dx)

// execve(2): filename, argv, envp.
SEC("raw_tracepoint/sys_enter")
int handle_execve(struct bpf_raw_tracepoint_args *ctx)
{
	struct pt_regs *regs = sys_regs(ctx);
	const char *filename = (const char *)SYS_ARG1(regs);
	const char *const *argv = (const char *const *)SYS_ARG2(regs);
	return record_exec(filename, argv, 0);
}

// execveat(2): fd, pathname, argv, envp, flags. With AT_EMPTY_PATH and an
// empty pathname fd is the file (glibc's fexecve); otherwise a relative
// pathname is relative to fd, which this program cannot resolve.
SEC("raw_tracepoint/sys_enter")
int handle_execveat(struct bpf_raw_tracepoint_args *ctx)
{
	struct pt_regs *regs = sys_regs(ctx);
	const char *filename = (const char *)SYS_ARG2(regs);
	const char *const *argv = (const char *const *)SYS_ARG3(regs);
	// AT_EMPTY_PATH execs the descriptor itself only when the pathname is
	// empty: there is no path to record. With a pathname the kernel looks it
	// up as usual whatever the flags, so it is recorded as given; one
	// relative to a directory descriptor is unresolved. An empty pathname
	// without the flag fails, and an unreadable one too; both are recorded
	// as an exec through the descriptor, as before (P-21).
	char first = 0;
	int via_fd = bpf_probe_read_user(&first, 1, filename) || first == '\0';
	return record_exec(filename, argv, via_fd);
}

// handle_exit_group stores the exit code of a process that calls
// exit_group(2) in its execs entry; handle_exit emits it.
static __always_inline void handle_exit_group(struct pt_regs *regs)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;

	struct event_hdr *cached = bpf_map_lookup_elem(&execs, &tgid);
	if (!cached)
		return;

	// The parent's wait sees only the low 8 bits: _exit(256) is status 0
	// and _exit(-1) is 255. Record that status, which is what a shell or a
	// harness reports, not the raw argument.
	cached->exit_code = (__s32)(SYS_ARG1(regs) & 0xff);
	cached->has_exit_code = 1;
}

// sys_enter(struct pt_regs *regs, long id) fires in the calling task.
SEC("raw_tracepoint/sys_enter")
int trace_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
	__u32 slot;
	switch (ctx->args[1]) {
	case NR_execve:     slot = SLOT_EXECVE; break;
	case NR_execveat:   slot = SLOT_EXECVEAT; break;
	case NR_exit_group: slot = SLOT_COUNT; break;
	default:
		return 0;
	}
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	if (BPF_CORE_READ(task, thread_info.status) & TS_COMPAT)
		return 0;
	if (slot == SLOT_COUNT) {
		handle_exit_group(sys_regs(ctx));
		return 0;
	}
	// An untracked process's exec is not recorded in filtered mode;
	// record_exec checks again, since it needs the entry.
	if (get_use_pid_filter()) {
		__u32 tgid = bpf_get_current_pid_tgid() >> 32;
		if (!bpf_map_lookup_elem(&tracked_pids, &tgid))
			return 0;
	}
	bpf_tail_call(ctx, &sys_enter_progs, slot);
	// Reached only when the slot is empty, which New rules out: the exec
	// attempt went unrecorded, so it is counted as event loss.
	count_drop();
	return 0;
}

// handle_exec_ok marks the exec that took effect (P-31). sched_process_exec
// fires only for a successful exec, after the kernel replaced the image, so a
// failed attempt never reaches it. The record names the attempting thread
// (old_pid: a non-leader thread that execs takes the leader's pid), and
// userspace joins it to that thread's latest attempt. The execs entry is
// created or replaced here, so the exit record carries the image that exited.
// sched_process_exec(struct task_struct *p, pid_t old_pid, struct
// linux_binprm *bprm) fires in the task that exec'd.
SEC("raw_tracepoint/sched_process_exec")
int handle_exec_ok(struct bpf_raw_tracepoint_args *ctx)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;

	__u8 is_toplevel = 1;
	if (get_use_pid_filter()) {
		struct proc_info *p = bpf_map_lookup_elem(&tracked_pids, &tgid);
		if (!p)
			return 0;
		is_toplevel = p->is_toplevel;
	}

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct event_hdr h = {};
	h.pid = tgid;
	// The exit record is a copy of this header and keeps this parent even if
	// the process is reparented later.
	h.ppid = BPF_CORE_READ(task, real_parent, tgid);
	h.kind = KIND_EXEC_OK;
	h.ts_ns = bpf_ktime_get_ns();
	h.is_toplevel = is_toplevel;
	h.tid = (__u32)ctx->args[1];

	if (bpf_map_update_elem(&execs, &tgid, &h, BPF_ANY))
		count_state_lost();
	if (bpf_ringbuf_output(&events, &h, sizeof(h), 0))
		count_drop();
	return 0;
}

// sched_process_exit(struct task_struct *p, ...) fires in the exiting task;
// the program reads only the current task.
SEC("raw_tracepoint/sched_process_exit")
int handle_exit(struct bpf_raw_tracepoint_args *ctx)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;

	// The process ends with its last thread, not with its leader: a leader
	// can exit first (pthread_exit, or a raw exit) or be replaced when
	// another thread execs, and the process lives on, forks and exits with
	// its own code. do_exit decrements signal->live before this tracepoint,
	// so zero means the exiting thread is the last one.
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	if (BPF_CORE_READ(task, signal, live.counter) != 0)
		return 0;

	// A tracked process that never exec'd has no execs entry, but its
	// tracked_pids entry must go too, or a later process that reuses the pid
	// is tracked although it is not a descendant.
	if (get_use_pid_filter())
		bpf_map_delete_elem(&tracked_pids, &tgid);

	struct event_hdr *cached = bpf_map_lookup_elem(&execs, &tgid);
	if (!cached)
		return 0;

	// A header-only record: userspace joins it to the command line of the
	// exec attempt that took effect last for this pid (P-31). Two threads
	// exiting at once can both read live as zero; only the one whose delete
	// succeeds emits.
	struct event_hdr xh = *cached;
	if (bpf_map_delete_elem(&execs, &tgid))
		return 0;
	xh.kind = KIND_EXIT;
	xh.ts_ns = bpf_ktime_get_ns();
	if (bpf_ringbuf_output(&events, &xh, sizeof(xh), 0))
		count_drop();
	return 0;
}
