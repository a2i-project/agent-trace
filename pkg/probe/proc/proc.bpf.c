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
// running CPU: a tracepoint program cannot migrate while it runs, so the
// slot is private to it.
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

// execs keeps, per tracked process, the header of its latest exec until it
// exits: the exit code lands here and the exit record is this header. The
// command line is not kept in the kernel (4096 entries of 256 KiB would be
// 1 GiB preallocated); userspace joins the exit to the exec it already read.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, struct event_hdr);
} execs SEC(".maps");

struct sys_enter_execve_ctx {
	__u64 pad;
	__s32 syscall_nr;
	__u32 pad2;
	const char *filename;
	const char *const *argv;
	const char *const *envp;
};

struct sched_process_exit_ctx {
	__u64 pad;
	char comm[16];
	__s32 pid;
	__s32 prio;
};

struct sys_enter_exit_group_ctx {
	__u64 pad;
	__s32 syscall_nr;
	__u32 pad2;
	__u64 error_code;
};

struct task_newtask_ctx {
	__u64 pad;
	__s32 pid;
	char comm[16];
	__u64 clone_flags;
	__s16 oom_score_adj;
};

#define CLONE_THREAD 0x10000

SEC("tracepoint/task/task_newtask")
int handle_fork(struct task_newtask_ctx *ctx)
{
	if (!get_use_pid_filter())
		return 0;

	// A new thread shares its process's tgid, which is already tracked. Its
	// tid is not a tgid and handle_exit only deletes on tid == tgid, so
	// inserting it would leak an entry per thread and, once the number is
	// recycled as an unrelated process's pid, track a stranger.
	if (ctx->clone_flags & CLONE_THREAD)
		return 0;

	__u32 parent_pid = bpf_get_current_pid_tgid() >> 32;
	__u32 child_pid = ctx->pid;

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

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct sys_enter_execve_ctx *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	struct exec_scratch *e = scratch();
	if (!e)
		return 0;

	e->hdr.pid = pid;
	// The parent as the kernel sees it now, so it is correct whether or not
	// tracked_pids is in use. An exit record is a copy of this exec record and
	// keeps this value even if the process was reparented later.
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
	long fn_len = bpf_probe_read_user_str(&e->filename, sizeof(e->filename), ctx->filename);
	e->hdr.filename_len = (fn_len > 0) ? fn_len : 0;
	if (fn_len >= FILENAME_LEN)
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

#pragma clang loop unroll(full)
	for (int i = 0; i < MAX_ARGS; i++) {
		const char *argp = NULL;
		if (bpf_probe_read_user(&argp, sizeof(argp), &ctx->argv[i]) || !argp)
			break;

		__u32 offset = args_size & (MAX_ARGS_BYTES - 1);
		
		long n = bpf_probe_read_user_str(&e->args[offset], MAX_ARGS_BYTES, argp);
		if (n <= 0)
			break;
		if (n >= MAX_ARGS_BYTES)
			e->hdr.args_truncated = 1; // one string did not fit

		args_size += n;
		nargs++;

		if (args_size >= MAX_ARGS_BYTES) {
			e->hdr.args_truncated = 1;
			break;
		}
	}
	if (nargs == MAX_ARGS && !e->hdr.args_truncated) {
		const char *more = NULL;
		if (!bpf_probe_read_user(&more, sizeof(more), &ctx->argv[MAX_ARGS]) && more)
			e->hdr.args_truncated = 1; // more arguments than MAX_ARGS
	}
	if (args_size > MAX_ARGS_BYTES)
		args_size = MAX_ARGS_BYTES;

	e->hdr.args_size = args_size;
	e->hdr.nargs = nargs;

	if (bpf_map_update_elem(&execs, &pid, &e->hdr, BPF_ANY))
		count_state_lost();

	__u32 out_size = sizeof(struct event_hdr) + FILENAME_LEN + args_size;
	if (out_size > sizeof(struct exec_scratch))
		out_size = sizeof(struct exec_scratch);

	if (bpf_ringbuf_output(&events, e, out_size, 0))
		count_drop();
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_exit_group")
int handle_exit_group(struct sys_enter_exit_group_ctx *ctx)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;

	struct event_hdr *cached = bpf_map_lookup_elem(&execs, &tgid);
	if (!cached)
		return 0;

	cached->exit_code = (__s32)ctx->error_code;
	cached->has_exit_code = 1;
	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_exit(struct sched_process_exit_ctx *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 tgid = id >> 32;
	__u32 tid = (__u32)id;

	if (tgid != tid)
		return 0;

	struct event_hdr *cached = bpf_map_lookup_elem(&execs, &tgid);
	if (!cached)
		return 0;

	// A header-only record: userspace joins it to the command line of the
	// exec record it read for this pid.
	struct event_hdr xh = *cached;
	xh.kind = KIND_EXIT;
	xh.ts_ns = bpf_ktime_get_ns();
	if (bpf_ringbuf_output(&events, &xh, sizeof(xh), 0))
		count_drop();

	bpf_map_delete_elem(&execs, &tgid);
	if (get_use_pid_filter()) {
		bpf_map_delete_elem(&tracked_pids, &tgid);
	}
	return 0;
}
