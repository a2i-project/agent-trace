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

#define AF_UNIX  1
#define AF_INET  2
#define AF_INET6 10
#define UNIX_PATH_LEN 108 // sizeof(((struct sockaddr_un *)0)->sun_path)
#define HELLO_CAP_LEN 1024

enum net_event_type {
	NET_CONNECT = 1,
	NET_HELLO   = 2,
	NET_BIND    = 3, // reserved: emitted only once tls.bpf.c exists (S5)
	NET_CLOSE   = 4,
	// Listener capability evidence (09_observer_hardening_todo.md item 2).
	// Ground truth only: no trajectory format can claim these, and the
	// verifier never aligns them. See 08_verification_model.md D3.
	NET_SOCK_BIND   = 5,
	NET_SOCK_LISTEN = 6,
	// connect() to an AF_UNIX socket. The socket path travels in the record
	// payload (payload_len bytes), not in addr, which is too small for it.
	// AF_UNIX bind and listen reuse NET_SOCK_BIND and NET_SOCK_LISTEN with
	// family == AF_UNIX and the path in the payload the same way.
	NET_UNIX_CONNECT = 7,
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

// binds remembers the address a tracked process passed to bind(), keyed like
// conns, so a later listen(fd) event can carry the address it listens on (the
// listen syscall itself has none). It is a content aid, not an event source:
// if it is full, a listen event is still emitted, with an unknown address.
// Entries are removed on close(fd).
struct bind_state {
	__u8  family;
	__u8  addr[16];
	__u16 port;
	__u32 unix_len;                  // AF_UNIX only: bytes of unix_path in use
	__u8  unix_path[UNIX_PATH_LEN];  // AF_UNIX only
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct conn_key);
	__type(value, struct bind_state);
} binds SEC(".maps");

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

// state_lost_count counts records this program lost because a state map it
// writes per process or per connection was full (conns). Unlike a ring buffer
// drop the failure happens in a map update, so it is easy to miss: a connection whose state could not be stored gets no hello capture and no close record, and userspace emits a connection only at hello or close, so the connection itself vanishes from the ground truth.
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

// read_unix_path copies the sun_path of a user sockaddr_un into e->payload and
// returns its length, 0 when it could not be read (the event is still worth
// emitting: a connect to a socket is evidence even if the name is lost), or -1
// when there is no name at all (addrlen covers only sun_family, an unnamed
// socket, which no one connects to or binds on purpose).
//
// A pathname socket's name is NUL terminated: bpf_probe_read_user_str copes
// with a short user buffer. An abstract socket starts with a NUL byte and its
// name is exactly addrlen - 2 bytes, embedded NULs included, so it is read
// with a constant size and trimmed by addrlen. Both sizes are compile-time
// constants, see trace_connect for why. A relative pathname is reported as
// given, not resolved against the caller's cwd.
static __always_inline int read_unix_path(struct net_event *e, __u64 uaddr, __u64 addrlen)
{
	if (addrlen <= 2)
		return -1;

	__u8 first = 0;
	if (bpf_probe_read_user(&first, sizeof(first), (void *)(uaddr + 2)))
		return 0;

	long len;
	if (first != 0) {
		long n = bpf_probe_read_user_str(e->payload, UNIX_PATH_LEN, (void *)(uaddr + 2));
		if (n <= 0)
			return 0;
		len = n - 1; // drop the terminating NUL
	} else {
		if (bpf_probe_read_user(e->payload, UNIX_PATH_LEN, (void *)(uaddr + 2)))
			return 0;
		len = (long)addrlen - 2;
	}
	if (len < 0)
		len = 0;
	if (len > UNIX_PATH_LEN)
		len = UNIX_PATH_LEN;
	return (int)len;
}

// emit_unix sends one AF_UNIX record whose path is already in e->payload.
static __always_inline void emit_unix(struct net_event *e, __u8 type, __u32 tgid, __u32 fd, __u32 len)
{
	fill_common(&e->hdr, type, tgid, fd);
	e->hdr.family = AF_UNIX;
	e->hdr.port = 0;
	__builtin_memset(e->hdr.addr, 0, sizeof(e->hdr.addr));
	e->hdr.payload_len = len;
	if (bpf_ringbuf_output(&net_events, e, sizeof(e->hdr) + len, 0))
		count_drop();
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
	if (family == AF_UNIX) {
		// Capability evidence only: a connect to /var/run/docker.sock or a
		// systemd socket is how an agent delegates work to a daemon outside
		// the tracked tree. No conns entry, since no TLS rides on it.
		struct net_event *ue = reserve_event();
		if (!ue)
			return 0;
		int ulen = read_unix_path(ue, ctx->uservaddr, ctx->addrlen);
		if (ulen < 0)
			return 0;
		emit_unix(ue, NET_UNIX_CONNECT, tgid, (__u32)ctx->fd, (__u32)ulen);
		return 0;
	}
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
	if (bpf_map_update_elem(&conns, &key, &state, BPF_ANY))
		count_state_lost();

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

// --- sys_enter_bind / sys_enter_listen: listener evidence -----------------
//
// Both fire at syscall entry, so they record attempts, including a bind that
// then fails with EADDRINUSE. That matches how this project's proc probe
// treats execve. A bind is not always a listener (a client may bind a source
// address before connect), so userspace reports NET_SOCK_BIND and
// NET_SOCK_LISTEN as distinct events and listen is the one that means the
// process accepts connections. AF_UNIX sockets take the same path with the
// socket name in the payload.

struct sys_enter_bind_ctx {
	__u64 pad;
	__s32 syscall_nr;
	__u32 pad2;
	__u64 fd;
	__u64 umyaddr;
	__u64 addrlen;
};

SEC("tracepoint/syscalls/sys_enter_bind")
int trace_bind(struct sys_enter_bind_ctx *ctx)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (!is_tracked(tgid))
		return 0;

	// Constant-size reads only, see trace_connect for why.
	__u16 family;
	if (bpf_probe_read_user(&family, sizeof(family), (void *)ctx->umyaddr))
		return 0;
	if (family == AF_UNIX) {
		struct net_event *ue = reserve_event();
		if (!ue)
			return 0;
		int ulen = read_unix_path(ue, ctx->umyaddr, ctx->addrlen);
		if (ulen < 0)
			return 0;
		struct conn_key ukey = { .tgid = tgid, .fd = (__u32)ctx->fd };
		struct bind_state ubs = {0};
		ubs.family = AF_UNIX;
		ubs.unix_len = (__u32)ulen;
		__builtin_memcpy(ubs.unix_path, ue->payload, UNIX_PATH_LEN);
		bpf_map_update_elem(&binds, &ukey, &ubs, BPF_ANY);
		emit_unix(ue, NET_SOCK_BIND, tgid, ukey.fd, (__u32)ulen);
		return 0;
	}
	if (family != AF_INET && family != AF_INET6)
		return 0;

	// The kernel rejects a bind whose addrlen is shorter than the struct
	// (EINVAL), so there is nothing to observe and the bytes past addrlen
	// are not the caller's address.
	__u8 sa[28] = {};
	if (family == AF_INET) {
		if (ctx->addrlen < 16)
			return 0;
		if (bpf_probe_read_user(sa, 16, (void *)ctx->umyaddr))
			return 0;
	} else {
		if (ctx->addrlen < 28)
			return 0;
		if (bpf_probe_read_user(sa, 28, (void *)ctx->umyaddr))
			return 0;
	}

	__u16 port_be = *(__u16 *)(sa + 2);
	__u16 port = ((port_be & 0xff) << 8) | (port_be >> 8);

	struct conn_key key = { .tgid = tgid, .fd = (__u32)ctx->fd };
	struct bind_state bs = {0};
	bs.family = (__u8)family;
	bs.port = port;
	if (family == AF_INET)
		__builtin_memcpy(bs.addr, sa + 4, 4);
	else
		__builtin_memcpy(bs.addr, sa + 8, 16);
	bpf_map_update_elem(&binds, &key, &bs, BPF_ANY);

	struct net_event *e = reserve_event();
	if (!e)
		return 0;
	fill_common(&e->hdr, NET_SOCK_BIND, tgid, key.fd);
	e->hdr.family = bs.family;
	e->hdr.port = bs.port;
	__builtin_memcpy(e->hdr.addr, bs.addr, sizeof(bs.addr));
	if (bpf_ringbuf_output(&net_events, &e->hdr, sizeof(e->hdr), 0))
		count_drop();
	return 0;
}

struct sys_enter_listen_ctx {
	__u64 pad;
	__s32 syscall_nr;
	__u32 pad2;
	__u64 fd;
	__u64 backlog;
};

SEC("tracepoint/syscalls/sys_enter_listen")
int trace_listen(struct sys_enter_listen_ctx *ctx)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (!is_tracked(tgid))
		return 0;

	struct net_event *e = reserve_event();
	if (!e)
		return 0;

	struct conn_key key = { .tgid = tgid, .fd = (__u32)ctx->fd };
	fill_common(&e->hdr, NET_SOCK_LISTEN, tgid, key.fd);
	// reserve_event returns per-CPU scratch that holds the previous event,
	// so every address field is set explicitly. family 0 means the socket
	// was never bound through bind() (an ephemeral port, or an AF_UNIX
	// socket), so the address is unknown.
	e->hdr.family = 0;
	e->hdr.port = 0;
	__builtin_memset(e->hdr.addr, 0, sizeof(e->hdr.addr));
	struct bind_state *bs = bpf_map_lookup_elem(&binds, &key);
	if (bs && bs->family == AF_UNIX) {
		__u32 ulen = bs->unix_len;
		if (ulen > UNIX_PATH_LEN)
			ulen = UNIX_PATH_LEN;
		__builtin_memcpy(e->payload, bs->unix_path, UNIX_PATH_LEN);
		emit_unix(e, NET_SOCK_LISTEN, tgid, key.fd, ulen);
		return 0;
	}
	if (bs) {
		e->hdr.family = bs->family;
		e->hdr.port = bs->port;
		__builtin_memcpy(e->hdr.addr, bs->addr, sizeof(bs->addr));
	}
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
	bpf_map_delete_elem(&binds, &key);
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
