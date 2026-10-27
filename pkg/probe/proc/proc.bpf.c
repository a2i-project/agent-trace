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

// A path the probe walks from a dentry up to the process's root (P-36): the
// names leaf first, each with its NUL, packed into PATH_BYTES plus one name
// of slack, so the last name read never runs past the area. NAME_LEN is
// NAME_MAX plus the NUL, so a name is never cut. PATH_DEPTH bounds the walk:
// one step per name and one per mount crossed.
#define PATH_BYTES 4096
#define NAME_LEN 256
#define PATH_AREA (PATH_BYTES + NAME_LEN)
#define PATH_DEPTH 32

#define KIND_EXEC 0
#define KIND_EXIT 1
#define KIND_FORK 2 // a tracked process created a child; header only, no filename or args
#define KIND_EXEC_OK 3 // an exec took effect; tid names the thread whose attempt it was

// The records that follow the header:
//   KIND_EXEC     filename[FILENAME_LEN], args[args_size] (nargs strings),
//                 then the working directory, path[path_size]
//   KIND_EXEC_OK  the kernel's filename (bprm->filename) in filename[FILENAME_LEN],
//                 the interpreter (bprm->interp) in interp[FILENAME_LEN] with
//                 args_size its length (0 when it is the filename), then the
//                 file the new image runs, path[path_size]
//   KIND_EXIT, KIND_FORK  nothing
struct event_hdr {
	__u32 pid;
	__u32 ppid; // parent tgid when the process exec'd, from the task struct
	__u32 kind;
	__u32 nargs;
	__s64 ts_ns;
	__s32 exit_code;
	__u8  has_exit_code;
	__u8  args_truncated; // the filename, the arguments or the interpreter did not fit
	__u8  path_truncated; // the path is incomplete: the walk did not reach the root (P-36)
	__u8  via_fd; // KIND_EXEC: an exec through a descriptor, the filename is "(fexecve)"
	__u32 filename_len;
	__u32 args_size;
	__u32 tid; // the thread that made the exec attempt (KIND_EXEC, KIND_EXEC_OK)
	__u32 path_size; // bytes of the path at the end of the record; 0 and not truncated: none recorded
};

struct exec_scratch {
	struct event_hdr hdr;
	char filename[FILENAME_LEN];
	// Padded to satisfy verifier worst-case offset+size bounds; the
	// working directory follows the arguments, at an offset the verifier
	// bounds by 2 * MAX_ARGS_BYTES, hence the PATH_AREA beyond it.
	char args[MAX_ARGS_BYTES * 2 + PATH_AREA];
};

struct exec_ok_scratch {
	struct event_hdr hdr;
	char filename[FILENAME_LEN];
	char interp[FILENAME_LEN];
	char path[PATH_AREA];
};

// tracked_pids holds the tgids of the root and its descendants in filtered
// mode. The value carries nothing: the verifier places each process by the
// fork and exec records (V1).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, __u8);
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

// tracked_stat counts the entries of tracked_pids: live is incremented when
// handle_fork inserts a pid and decremented when handle_exit deletes one,
// and peak keeps the highest live plus seeded read back after an insert
// (P-34). One shared slot, not per CPU, since a peak needs the global count;
// it is written only on a tracked process's fork and exit. A pid userspace seeds
// (SetRootPID) is counted in tracked_seeded, which only userspace writes, so
// live goes below zero when a seeded pid exits.
struct tracked_stat {
	__s64 live;
	__s64 peak;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct tracked_stat);
} tracked_stat SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __s64);
} tracked_seeded SEC(".maps");

// tracked_inserted counts an insert into tracked_pids and raises peak to the
// occupancy it reads back. bpf2go builds for BPF v1, which has an atomic add
// but neither fetch-and-add nor compare-and-swap, so the read-back and the
// raise are plain loads and a store: an insert or a delete on another CPU
// between them can make the value read differ from this insert's own count,
// and of two raises racing, the lower can land last. Either way the peak only
// falls short, by at most the number of such races, and each value it keeps
// was the occupancy at some instant (P-34).
static __always_inline void tracked_inserted(void)
{
	__u32 zero = 0;
	struct tracked_stat *s = bpf_map_lookup_elem(&tracked_stat, &zero);
	if (!s)
		return;
	__sync_fetch_and_add(&s->live, 1);
	__s64 n = *(volatile __s64 *)&s->live;
	__s64 *seeded = bpf_map_lookup_elem(&tracked_seeded, &zero);
	if (seeded)
		n += *seeded;
	if (n > *(volatile __s64 *)&s->peak)
		*(volatile __s64 *)&s->peak = n;
}

static __always_inline void tracked_removed(void)
{
	__u32 zero = 0;
	struct tracked_stat *s = bpf_map_lookup_elem(&tracked_stat, &zero);
	if (s)
		__sync_fetch_and_add(&s->live, -1);
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

// ok_heap is handle_exec_ok's scratch record (P-36). It fits a per-CPU value,
// and sched_process_exec runs the program with preemption disabled.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct exec_ok_scratch);
} ok_heap SEC(".maps");

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
#define EEXIST 17

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

	if (!bpf_map_lookup_elem(&tracked_pids, &parent_pid))
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

	// An entry left for the pid (none should be, since handle_exit deletes
	// it) is replaced as before, without counting a second entry.
	__u8 one = 1;
	long err = bpf_map_update_elem(&tracked_pids, &child_pid, &one, BPF_NOEXIST);
	if (err == -EEXIST)
		err = bpf_map_update_elem(&tracked_pids, &child_pid, &one, BPF_ANY);
	else if (!err)
		tracked_inserted();
	if (err)
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

// kernel_nul_at is nul_at for a kernel string.
static __always_inline int kernel_nul_at(const char *s, __u32 i)
{
	char c = 1;
	return !bpf_probe_read_kernel(&c, 1, s + i) && c == '\0';
}

// The path walk (P-36). bpf_d_path is not available to a raw tracepoint
// (the kernel allows it only to tracing and LSM programs on a list of
// functions), so the probe makes the walk prepend_path makes, without its
// locks: from a dentry up to the process's root, writing the names leaf
// first, each with its NUL; a step that meets the root of a mount continues
// at the mount point in the parent mount without a name, and a walk that
// meets the namespace's top without passing the process's root ends there.
// A dentry that is its own parent without being a mount root (a disconnected
// one), a full area or a failed read ends the walk cut.
//
// Each step is one call of walk_step under bpf_loop, so the verifier checks
// the step once, with its state at entry widened, instead of every path
// through PATH_DEPTH copies of it: an open-coded loop, whose two ways
// forward per step (a name or a mount crossed) the verifier kept apart,
// exceeded its limit of a million instructions on Linux 7.0. bpf_loop is a
// base helper, available to raw tracepoints since Linux 5.17.

#define WALK_EXEC 0 // the area follows the arguments in heap's slot for this CPU
#define WALK_OK   1 // the area is ok_heap's path

struct walk_state {
	__u64 d, vm, m; // the dentry, its vfsmount and its struct mount
	__u64 root_d, root_vm; // the process's root
	__u32 size; // bytes of names written
	__u32 base; // WALK_EXEC: the offset of the area in args
	__u8 cut; // 1 until the walk reaches the root
	__u8 area; // WALK_EXEC or WALK_OK
};

// walk_area returns the area the walk writes in. The mask on base is the
// bound the verifier sees; the barrier keeps the compiler from dropping it.
static __always_inline char *walk_area(struct walk_state *w)
{
	if (w->area == WALK_OK) {
		__u32 zero = 0;
		struct exec_ok_scratch *s = bpf_map_lookup_elem(&ok_heap, &zero);
		return s ? s->path : NULL;
	}
	struct exec_scratch *e = scratch();
	if (!e)
		return NULL;
	__u32 base = w->base;
	barrier_var(base);
	base &= 2 * MAX_ARGS_BYTES - 1;
	return &e->args[base];
}

// walk_step is one step of the walk; it returns 1 to end it.
static long walk_step(__u32 i, void *ctx)
{
	struct walk_state *w = ctx;
	if (w->d == w->root_d && w->vm == w->root_vm) {
		w->cut = 0;
		return 1;
	}
	struct dentry *d = (struct dentry *)w->d;
	struct vfsmount *vm = (struct vfsmount *)w->vm;
	if (w->d == (__u64)BPF_CORE_READ(vm, mnt_root)) {
		struct mount *m = (struct mount *)w->m;
		__u64 up = (__u64)BPF_CORE_READ(m, mnt_parent);
		if (!up || up == w->m) {
			w->cut = 0; // the top of the namespace
			return 1;
		}
		w->d = (__u64)BPF_CORE_READ(m, mnt_mountpoint);
		w->m = up;
		w->vm = up + bpf_core_field_offset(struct mount, mnt);
		return 0;
	}
	__u64 parent = (__u64)BPF_CORE_READ(d, d_parent);
	__u32 off = w->size;
	if (w->d == parent || off >= PATH_BYTES)
		return 1;
	char *area = walk_area(w);
	if (!area)
		return 1;
	barrier_var(off);
	off &= PATH_BYTES - 1;
	long n = bpf_probe_read_kernel_str(area + off, NAME_LEN, BPF_CORE_READ(d, d_name.name));
	if (n <= 0)
		return 1;
	w->size = off + n;
	w->d = parent;
	return 0;
}

// walk_path walks the path of dentry d on mount vm up to the root root_d on
// root_vm into the area w names (walk_state.area, and base for WALK_EXEC).
// It returns the bytes written and sets *cut unless the walk reached the
// root. The area must hold PATH_AREA bytes.
static __always_inline __u32 walk_path(__u8 area, __u32 base, struct dentry *d, struct vfsmount *vm,
				       struct dentry *root_d, struct vfsmount *root_vm, __u8 *cut)
{
	*cut = 1;
	if (!d || !vm)
		return 0;
	struct walk_state w = {
		.d = (__u64)d,
		.vm = (__u64)vm,
		.m = (__u64)vm - bpf_core_field_offset(struct mount, mnt),
		.root_d = (__u64)root_d,
		.root_vm = (__u64)root_vm,
		.size = 0,
		.base = base,
		.cut = 1,
		.area = area,
	};
	bpf_loop(PATH_DEPTH, walk_step, &w, 0);
	// A walk that used every step ends cut unless its last step reached
	// the root.
	if (w.cut && w.d == w.root_d && w.vm == w.root_vm)
		w.cut = 0;
	*cut = w.cut;
	__u32 size = w.size;
	if (size > PATH_AREA)
		size = PATH_AREA;
	return size;
}

// Slots of sys_enter_progs. sysEnterPrograms in observer.go fills them in
// this order. The dispatcher tail-calls the exec programs; they tail-call
// SLOT_EXEC_CWD (P-36).
enum sys_slot {
	SLOT_EXECVE,
	SLOT_EXECVEAT,
	SLOT_EXEC_CWD,
	SLOT_COUNT,
};

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, SLOT_COUNT);
	__type(key, __u32);
	__type(value, __u32);
} sys_enter_progs SEC(".maps");

static __always_inline void exec_tail_call(struct bpf_raw_tracepoint_args *ctx)
{
	bpf_tail_call(ctx, &sys_enter_progs, SLOT_EXEC_CWD);
}

// emit_exec outputs the exec record in e: the header, the filename, the
// arguments and the working directory the header says it holds.
static __always_inline void emit_exec(struct exec_scratch *e)
{
	__u32 args_size = e->hdr.args_size;
	if (args_size > MAX_ARGS_BYTES)
		args_size = MAX_ARGS_BYTES;
	__u32 path_size = e->hdr.path_size;
	if (path_size > PATH_AREA)
		path_size = PATH_AREA;
	__u32 out_size = sizeof(struct event_hdr) + FILENAME_LEN + args_size + path_size;
	if (out_size > sizeof(struct exec_scratch))
		out_size = sizeof(struct exec_scratch);

	if (bpf_ringbuf_output(&events, e, out_size, 0))
		count_drop();
}

// record_exec records one exec attempt at syscall entry, whether it then
// succeeds or not (P-4): the filename as the kernel was asked for it (or
// "(fexecve)" for an exec through a descriptor, which names no path), then
// argv, then (in handle_exec_cwd) the working directory (P-36). Shared by
// execve and execveat (P-21). handle_exec_ok says which attempt took effect
// (P-31).
static __always_inline int record_exec(struct bpf_raw_tracepoint_args *ctx, const char *filename,
				       const char *const *argv, int via_fd)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;

	struct exec_scratch *e = scratch();
	if (!e)
		return 0;

	e->hdr.pid = pid;
	e->hdr.tid = (__u32)pid_tgid;
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
	e->hdr.path_truncated = 0;
	e->hdr.via_fd = via_fd ? 1 : 0;
	e->hdr.path_size = 0;

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

	// handle_exec_cwd appends the working directory and outputs the record;
	// the walk does not fit this program beside the argument loop. A tail
	// call cannot fail once New filled the slot; if it did, the record goes
	// out without a working directory.
	exec_tail_call(ctx);
	emit_exec(e);
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
	return record_exec(ctx, filename, argv, 0);
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
	return record_exec(ctx, filename, argv, via_fd);
}

// handle_exec_cwd ends an exec record that record_exec left in the scratch
// slot: it appends the working directory, from the task's fs->pwd up to its
// fs->root, after the arguments, and outputs the record (P-36). It runs in
// the same tail-call chain on the same CPU, so the slot is the one
// record_exec filled. A record whose walk did not reach the root is flagged
// path_truncated and keeps the names it read.
SEC("raw_tracepoint/sys_enter")
int handle_exec_cwd(struct bpf_raw_tracepoint_args *ctx)
{
	struct exec_scratch *e = scratch();
	if (!e)
		return 0;
	// args_size is at most MAX_ARGS_BYTES; the mask is the bound the
	// verifier sees.
	__u32 args_size = e->hdr.args_size;
	barrier_var(args_size);
	args_size &= 2 * MAX_ARGS_BYTES - 1;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct fs_struct *fs = BPF_CORE_READ(task, fs);
	__u8 cut = 1;
	__u32 n = 0;
	if (fs)
		n = walk_path(WALK_EXEC, args_size, BPF_CORE_READ(fs, pwd.dentry), BPF_CORE_READ(fs, pwd.mnt),
			      BPF_CORE_READ(fs, root.dentry), BPF_CORE_READ(fs, root.mnt), &cut);
	e->hdr.path_size = n;
	e->hdr.path_truncated = cut;
	emit_exec(e);
	return 0;
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
	// An untracked process's exec is not recorded in filtered mode. The
	// exec programs are reached only through this tail call, so this is
	// their only filter.
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
// The record also carries what the kernel ran (P-36): its own copy of the
// filename, the interpreter a script named, and the path of the file the new
// image runs (bprm->file, which becomes mm->exe_file), walked from the
// process's root.
// sched_process_exec(struct task_struct *p, pid_t old_pid, struct
// linux_binprm *bprm) fires in the task that exec'd.
SEC("raw_tracepoint/sched_process_exec")
int handle_exec_ok(struct bpf_raw_tracepoint_args *ctx)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;

	if (get_use_pid_filter() && !bpf_map_lookup_elem(&tracked_pids, &tgid))
		return 0;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct event_hdr h = {};
	h.pid = tgid;
	// The exit record is a copy of this header and keeps this parent even if
	// the process is reparented later.
	h.ppid = BPF_CORE_READ(task, real_parent, tgid);
	h.kind = KIND_EXEC_OK;
	h.ts_ns = bpf_ktime_get_ns();
	h.tid = (__u32)ctx->args[1];

	if (bpf_map_update_elem(&execs, &tgid, &h, BPF_ANY))
		count_state_lost();

	__u32 zero = 0;
	struct exec_ok_scratch *s = bpf_map_lookup_elem(&ok_heap, &zero);
	if (!s) {
		if (bpf_ringbuf_output(&events, &h, sizeof(h), 0))
			count_drop();
		return 0;
	}
	s->hdr = h;
	struct linux_binprm *bprm = (struct linux_binprm *)ctx->args[2];
	const char *fn = BPF_CORE_READ(bprm, filename);
	const char *interp = BPF_CORE_READ(bprm, interp);
	long n = bpf_probe_read_kernel_str(s->filename, FILENAME_LEN, fn);
	s->hdr.filename_len = n > 0 ? n : 0;
	if (n <= 0 || (n >= FILENAME_LEN && !kernel_nul_at(fn, FILENAME_LEN - 1)))
		s->hdr.args_truncated = 1;
	// interp is the filename itself unless a binary handler (a script's
	// #!) replaced it.
	if (interp && interp != fn) {
		long m = bpf_probe_read_kernel_str(s->interp, FILENAME_LEN, interp);
		s->hdr.args_size = m > 0 ? m : 0;
		if (m <= 0 || (m >= FILENAME_LEN && !kernel_nul_at(interp, FILENAME_LEN - 1)))
			s->hdr.args_truncated = 1;
	}

	struct file *file = BPF_CORE_READ(bprm, file);
	struct fs_struct *fs = BPF_CORE_READ(task, fs);
	__u8 cut = 1;
	__u32 p = 0;
	if (file && fs)
		p = walk_path(WALK_OK, 0, BPF_CORE_READ(file, f_path.dentry), BPF_CORE_READ(file, f_path.mnt),
			      BPF_CORE_READ(fs, root.dentry), BPF_CORE_READ(fs, root.mnt), &cut);
	s->hdr.path_size = p;
	s->hdr.path_truncated = cut;

	__u32 out_size = sizeof(struct event_hdr) + 2 * FILENAME_LEN + p;
	if (out_size > sizeof(struct exec_ok_scratch))
		out_size = sizeof(struct exec_ok_scratch);
	if (bpf_ringbuf_output(&events, s, out_size, 0))
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
	if (get_use_pid_filter() && !bpf_map_delete_elem(&tracked_pids, &tgid))
		tracked_removed();

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
