// SPDX-License-Identifier: GPL-2.0
//go:build ignore

// Kernel-side half of the Tier 3 network probe. This program owns identity
// (pid, tid, fd, peer address, peer port) and the first-write ClientHello
// capture that yields SNI; it does not decrypt anything. Content capture
// (the SSL_write uprobe in tls.bpf.c) is a separate, not-yet-implemented
// program -- see docs/plan/06_tier3_network_design.md sections 4 and 5. The
// write-bracket join described in section 4.4 step 2 (looking up
// tls.bpf.c's active_write map to emit NET_BIND) is deferred along with it:
// this file implements only step 1 (tracked_pids gate) and step 3
// (hello-capture) of that sequence.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define AF_INET  2
#define AF_INET6 10
#define HELLO_CAP_LEN 1024

enum net_event_type {
	NET_CONNECT = 1,
	NET_HELLO   = 2,
	NET_BIND    = 3, // reserved: emitted only once tls.bpf.c exists (S5)
	NET_CLOSE   = 4,
};

struct net_event_hdr {
	__u8  type;
	__u8  family;
	__u16 port;
	__u32 tgid;
	__u32 tid;
	__u32 fd;
	__u64 ts_ns;
	__u8  addr[16];
	__u64 seq;         // NET_BIND only; always 0 until tls.bpf.c exists
	__u32 payload_len; // NET_HELLO only
};

struct net_event {
	struct net_event_hdr hdr;
	__u8 payload[HELLO_CAP_LEN];
};

struct conn_key {
	__u32 tgid;
	__u32 fd;
};

struct conn_state {
	__u8  family;
	__u8  addr[16];
	__u16 port;
	__u8  hello_captured;
	__u64 open_ts_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct conn_key);
	__type(value, struct conn_state);
} conns SEC(".maps");

// tracked_pids gates every program in this file. Section 10 of the design
// doc has this pinned and populated by pkg/probe/proc once both probes run
// together (S6); until that wiring lands, net.Observer populates its own
// copy directly via TrackPID, the same way proc.Observer seeds root_pid_map.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u8);
} tracked_pids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 18); // 256 KiB
} net_events SEC(".maps");

// drop_count counts bpf_ringbuf_output failures on net_events. A full ring
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

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct net_event);
} heap SEC(".maps");

static __always_inline int is_tracked(__u32 tgid)
{
	return bpf_map_lookup_elem(&tracked_pids, &tgid) != NULL;
}

static __always_inline struct net_event *reserve_event(void)
{
	__u32 zero = 0;
	return bpf_map_lookup_elem(&heap, &zero);
}

static __always_inline void fill_common(struct net_event_hdr *hdr, __u8 type,
					 __u32 tgid, __u32 fd)
{
	__u64 id = bpf_get_current_pid_tgid();
	hdr->type = type;
	hdr->tgid = tgid;
	hdr->tid = (__u32)id;
	hdr->fd = fd;
	hdr->ts_ns = bpf_ktime_get_ns();
	hdr->seq = 0;
	hdr->payload_len = 0;
}

// --- sys_enter_connect: records peer identity before the handshake -------

struct sys_enter_connect_ctx {
	__u64 pad;
	__s32 syscall_nr;
	__u32 pad2;
	__u64 fd;
	__u64 uservaddr;
	__u64 addrlen;
};

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct sys_enter_connect_ctx *ctx)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (!is_tracked(tgid))
		return 0;

	// Read family first with a compile-time constant size (sizeof(__u16) = 2)
	// so the BPF verifier can always bound the helper's size argument. Using
	// a dynamic size for bpf_probe_read_user -- even after masking with &=
	// 0x1f -- is rejected by stricter kernels because the verifier tracks the
	// register as potentially negative across __u64->__u32 cast boundaries.
	// Two reads with compile-time-constant sizes avoid the issue entirely.
	__u16 family;
	if (bpf_probe_read_user(&family, sizeof(family), (void *)ctx->uservaddr))
		return 0;
	if (family != AF_INET && family != AF_INET6)
		return 0;

	// Read the full address struct with a per-family constant size:
	// sizeof(sockaddr_in) = 16, sizeof(sockaddr_in6) = 28.
	__u8 sa[28] = {};
	if (family == AF_INET) {
		if (bpf_probe_read_user(sa, 16, (void *)ctx->uservaddr))
			return 0;
	} else {
		if (bpf_probe_read_user(sa, 28, (void *)ctx->uservaddr))
			return 0;
	}

	__u16 port_be = *(__u16 *)(sa + 2);
	__u16 port = ((port_be & 0xff) << 8) | (port_be >> 8);

	struct conn_key key = { .tgid = tgid, .fd = (__u32)ctx->fd };
	struct conn_state state = {0};
	state.family = (__u8)family;
	state.port = port;
	state.open_ts_ns = bpf_ktime_get_ns();
	if (family == AF_INET) {
		__builtin_memcpy(state.addr, sa + 4, 4);
	} else {
		// AF_INET6: sin6_addr starts at offset 8 in sockaddr_in6.
		// We always read 28 bytes above, so offset 8+16=24 is in bounds.
		__builtin_memcpy(state.addr, sa + 8, 16);
	}
	bpf_map_update_elem(&conns, &key, &state, BPF_ANY);

	struct net_event *e = reserve_event();
	if (!e)
		return 0;
	fill_common(&e->hdr, NET_CONNECT, tgid, key.fd);
	e->hdr.family = state.family;
	e->hdr.port = state.port;
	__builtin_memcpy(e->hdr.addr, state.addr, sizeof(state.addr));
	if (bpf_ringbuf_output(&net_events, &e->hdr, sizeof(e->hdr), 0))
		count_drop();
	return 0;
}

// --- first-write hello capture (write / sendto / sendmsg) ----------------

static __always_inline int capture_hello(__u32 tgid, __u32 fd, const void *buf, __u32 len)
{
	struct conn_key key = { .tgid = tgid, .fd = fd };
	struct conn_state *cs = bpf_map_lookup_elem(&conns, &key);
	if (!cs || cs->hello_captured)
		return 0;

	if (len > HELLO_CAP_LEN)
		len = HELLO_CAP_LEN;

	struct net_event *e = reserve_event();
	if (!e)
		return 0;
	if (len > 0 && bpf_probe_read_user(e->payload, len, buf)) {
		// A faulting read (buffer page not resident, or a bad
		// pointer) must not be silently treated as an empty capture
		// that later reads as "no content, but not disagreement" --
		// see D5 in docs/plan/06_tier3_network_design.md section 13.
		// Drop the frame instead of emitting a zero-length NET_HELLO
		// that the correlator cannot tell apart from a genuinely
		// empty write.
		return 0;
	}

	fill_common(&e->hdr, NET_HELLO, tgid, fd);
	e->hdr.family = cs->family;
	e->hdr.port = cs->port;
	__builtin_memcpy(e->hdr.addr, cs->addr, sizeof(cs->addr));
	e->hdr.payload_len = len;
	if (bpf_ringbuf_output(&net_events, e, sizeof(e->hdr) + len, 0))
		count_drop();

	cs->hello_captured = 1;
	return 0;
}

struct sys_enter_write_ctx {
	__u64 pad;
	__s32 syscall_nr;
	__u32 pad2;
	__u64 fd;
	__u64 buf;
	__u64 count;
};

SEC("tracepoint/syscalls/sys_enter_write")
int trace_write(struct sys_enter_write_ctx *ctx)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (!is_tracked(tgid))
		return 0;
	return capture_hello(tgid, (__u32)ctx->fd, (const void *)ctx->buf, (__u32)ctx->count);
}

struct sys_enter_sendto_ctx {
	__u64 pad;
	__s32 syscall_nr;
	__u32 pad2;
	__u64 fd;
	__u64 buff;
	__u64 len;
	__u64 flags;
	__u64 addr;
	__u64 addr_len;
};

SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_sendto(struct sys_enter_sendto_ctx *ctx)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (!is_tracked(tgid))
		return 0;
	return capture_hello(tgid, (__u32)ctx->fd, (const void *)ctx->buff, (__u32)ctx->len);
}

struct sys_enter_sendmsg_ctx {
	__u64 pad;
	__s32 syscall_nr;
	__u32 pad2;
	__u64 fd;
	__u64 msg;
	__u64 flags;
};

// Mirrors struct msghdr / struct iovec's user-space layout on x86_64.
struct msghdr_bpf {
	__u64 msg_name;
	__u32 msg_namelen;
	__u32 __pad1;
	__u64 msg_iov;
	__u64 msg_iovlen;
	__u64 msg_control;
	__u64 msg_controllen;
	__u32 msg_flags;
	__u32 __pad2;
};

struct iovec_bpf {
	__u64 iov_base;
	__u64 iov_len;
};

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int trace_sendmsg(struct sys_enter_sendmsg_ctx *ctx)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (!is_tracked(tgid))
		return 0;

	struct msghdr_bpf mh = {0};
	if (bpf_probe_read_user(&mh, sizeof(mh), (void *)ctx->msg))
		return 0;
	if (mh.msg_iovlen == 0)
		return 0;

	struct iovec_bpf iov = {0};
	if (bpf_probe_read_user(&iov, sizeof(iov), (void *)mh.msg_iov))
		return 0;

	// Only the first iovec is inspected. A ClientHello or an HTTP
	// request line written via sendmsg with multiple iovecs whose first
	// entry is empty or tiny would be missed; that is a known limitation
	// of this first cut, not a silent correctness bug, since a later
	// write on the same fd (if any) still gets a capture attempt as long
	// as hello_captured hasn't been set.
	return capture_hello(tgid, (__u32)ctx->fd, (const void *)iov.iov_base, (__u32)iov.iov_len);
}

// --- sys_enter_close: connection teardown ---------------------------------

struct sys_enter_close_ctx {
	__u64 pad;
	__s32 syscall_nr;
	__u32 pad2;
	__u64 fd;
};

SEC("tracepoint/syscalls/sys_enter_close")
int trace_close(struct sys_enter_close_ctx *ctx)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (!is_tracked(tgid))
		return 0;

	struct conn_key key = { .tgid = tgid, .fd = (__u32)ctx->fd };
	struct conn_state *cs = bpf_map_lookup_elem(&conns, &key);
	if (!cs)
		return 0; // close() on an fd we never saw connect() on (a file, a pipe, ...)

	struct net_event *e = reserve_event();
	if (e) {
		fill_common(&e->hdr, NET_CLOSE, tgid, key.fd);
		e->hdr.family = cs->family;
		e->hdr.port = cs->port;
		__builtin_memcpy(e->hdr.addr, cs->addr, sizeof(cs->addr));
		if (bpf_ringbuf_output(&net_events, &e->hdr, sizeof(e->hdr), 0))
			count_drop();
	}

	bpf_map_delete_elem(&conns, &key);
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
