// SPDX-License-Identifier: GPL-2.0
//go:build ignore

// Uprobe-side half of the Tier 3 network probe. Owns content: the plaintext
// bytes an agent process hands to SSL_write, before BoringSSL encrypts and
// the kernel-side net.bpf.c ever sees them.
//
// The write-bracket join described in docs/plan/06_tier3_network_design.md
// section 5.3 (active_write / NET_BIND) is abandoned -- see design doc D1 in
// section 13: on Bun, encrypted bytes are queued asynchronously, so the
// write(2)/sendmsg(2) syscalls do not fire inside the SSL_write entry/return
// window. This file therefore attaches only a single uprobe at SSL_write's
// entry (no uretprobe) and emits every captured write as a self-contained
// ssl_frame; correlator.go in userspace parses HTTP directly out of the
// plaintext and attributes it to a connection by Host header, not by a
// kernel-side join.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define SSL_CAP_LEN 16384

struct ssl_frame_hdr {
	__u32 tgid;
	__u32 tid;
	__u64 ts_ns;
	__u32 len;
};

struct ssl_frame {
	struct ssl_frame_hdr hdr;
	__u8 payload[SSL_CAP_LEN];
};

// Same shape and gating role as net.bpf.c's tracked_pids. Kept as a separate
// map (rather than shared/pinned) until S6 wires proc + net + tls together
// under one pinned map at /sys/fs/bpf/agenttrace/tracked_pids -- see
// STATE.md and design doc section 10. net.Observer.TrackPID writes to both
// copies today.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u8);
} tracked_pids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20); // 1 MiB
} ssl_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct ssl_frame);
} ssl_heap SEC(".maps");

// faulted_reads counts SSL_write calls whose bpf_probe_read_user failed and
// were therefore dropped without emitting an ssl_frame (see D5, design doc
// section 13: a faulting read must not read as "empty content" to the
// correlator, but the operator must still be warned a capture was missed).
// net.Observer.Coverage() sums this percpu counter into FaultedReads.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} faulted_reads SEC(".maps");

// drop_count counts bpf_ringbuf_output failures on ssl_events. A full ring
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

static __always_inline int is_tracked(__u32 tgid)
{
	return bpf_map_lookup_elem(&tracked_pids, &tgid) != NULL;
}

// probe_ssl_write attaches at the entry of SSL_write(SSL *ssl, const void
// *buf, int num). Per the x86_64 System V ABI, ssl is RDI, buf is RSI, num
// is EDX -- PT_REGS_PARM1/2/3 below.
SEC("uprobe/ssl_write")
int probe_ssl_write(struct pt_regs *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 tgid = id >> 32;
	if (!is_tracked(tgid))
		return 0;

	void *buf = (void *)PT_REGS_PARM2(ctx);
	__u32 num = (__u32)PT_REGS_PARM3(ctx);
	if (num == 0)
		return 0;

	__u32 zero = 0;
	struct ssl_frame *e = bpf_map_lookup_elem(&ssl_heap, &zero);
	if (!e)
		return 0;

	__u32 len = num;
	if (len > SSL_CAP_LEN)
		len = SSL_CAP_LEN;

	// A faulting read (buffer not yet faulted in, bad pointer, or a call
	// shape this probe misidentified -- see D4 in design doc section 13)
	// must not be silently reported as an empty write: the correlator
	// could then read that as "SSL_write happened but carried nothing",
	// which is indistinguishable from a genuine zero-length write. Drop
	// the frame instead; net.Observer's Coverage().FaultedReads counts
	// it so the operator is warned of a potential capture bypass, per
	// D5's "warn, don't silently agree" resolution.
	if (bpf_probe_read_user(e->payload, len, buf)) {
		__u32 zero2 = 0;
		__u64 *count = bpf_map_lookup_elem(&faulted_reads, &zero2);
		if (count)
			__sync_fetch_and_add(count, 1);
		return 0;
	}

	e->hdr.tgid = tgid;
	e->hdr.tid = (__u32)id;
	e->hdr.ts_ns = bpf_ktime_get_ns();
	e->hdr.len = len;
	if (bpf_ringbuf_output(&ssl_events, e, sizeof(e->hdr) + len, 0))
		count_drop();
	return 0;
}

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
	// Threads share the tracked tgid; see proc.bpf.c handle_fork.
	if (ctx->clone_flags & CLONE_THREAD)
		return 0;

	__u32 parent_pid = bpf_get_current_pid_tgid() >> 32;
	__u32 child_pid = ctx->pid;

	__u8 *p = bpf_map_lookup_elem(&tracked_pids, &parent_pid);
	if (!p)
		return 0;

	__u8 one = 1;
	if (bpf_map_update_elem(&tracked_pids, &child_pid, &one, BPF_ANY))
		count_untracked();
	return 0;
}

struct sched_process_exit_ctx {
	__u64 pad;
	char comm[16];
	__s32 pid;
	__s32 prio;
};

SEC("tracepoint/sched/sched_process_exit")
int handle_exit(struct sched_process_exit_ctx *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 tgid = id >> 32;
	__u32 tid = (__u32)id;

	if (tgid != tid)
		return 0;

	bpf_map_delete_elem(&tracked_pids, &tgid);
	return 0;
}
