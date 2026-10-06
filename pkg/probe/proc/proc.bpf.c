// SPDX-License-Identifier: GPL-2.0
//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_ARGS 64
#define MAX_ARGS_BYTES 8192
#define FILENAME_LEN 256

#define KIND_EXEC 0
#define KIND_EXIT 1

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
	__u32 kind;
	__u32 nargs;
	__s64 ts_ns;
	__s32 exit_code;
	__u8  has_exit_code;
	__u8  is_toplevel;
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
	__uint(max_entries, 1 << 20); // 1 MiB
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

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct exec_scratch);
} heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, struct exec_scratch);
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
	/* MUTATION: thread check removed */

	__u32 parent_pid = bpf_get_current_pid_tgid() >> 32;
	__u32 child_pid = ctx->pid;

	struct proc_info *p = bpf_map_lookup_elem(&tracked_pids, &parent_pid);
	if (!p)
		return 0;

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
	__u32 zero = 0;
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	struct exec_scratch *e = bpf_map_lookup_elem(&heap, &zero);
	if (!e)
		return 0;

	e->hdr.pid = pid;
	e->hdr.kind = KIND_EXEC;
	e->hdr.ts_ns = bpf_ktime_get_ns();
	e->hdr.exit_code = 0;
	e->hdr.has_exit_code = 0;
	e->hdr.args_size = 0;
	e->hdr.nargs = 0;

	e->filename[0] = '\0';
	long fn_len = bpf_probe_read_user_str(&e->filename, sizeof(e->filename), ctx->filename);
	e->hdr.filename_len = (fn_len > 0) ? fn_len : 0;

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

		args_size += n;
		nargs++;

		if (args_size >= MAX_ARGS_BYTES)
			break;
	}

	e->hdr.args_size = args_size;
	e->hdr.nargs = nargs;

	if (bpf_map_update_elem(&execs, &pid, e, BPF_ANY))
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

	struct exec_scratch *cached = bpf_map_lookup_elem(&execs, &tgid);
	if (!cached)
		return 0;

	cached->hdr.exit_code = (__s32)ctx->error_code;
	cached->hdr.has_exit_code = 1;
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

	struct exec_scratch *cached = bpf_map_lookup_elem(&execs, &tgid);
	if (!cached)
		return 0;

	__u32 zero = 0;
	struct exec_scratch *e = bpf_map_lookup_elem(&heap, &zero);
	if (e) {
		bpf_probe_read_kernel(e, sizeof(*e), cached);
		e->hdr.kind = KIND_EXIT;
		e->hdr.ts_ns = bpf_ktime_get_ns();
		
		__u32 out_size = sizeof(struct event_hdr) + FILENAME_LEN + e->hdr.args_size;
		if (out_size > sizeof(struct exec_scratch))
			out_size = sizeof(struct exec_scratch);
		
		if (bpf_ringbuf_output(&events, e, out_size, 0))
			count_drop();
	}

	bpf_map_delete_elem(&execs, &tgid);
	if (get_use_pid_filter()) {
		bpf_map_delete_elem(&tracked_pids, &tgid);
	}
	return 0;
}
