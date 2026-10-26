// SPDX-License-Identifier: GPL-2.0
//go:build ignore

// Kernel-side half of the Tier 3 network probe. This program owns identity
// (pid, tid, fd, peer address, peer port) and the first-write ClientHello
// capture that yields SNI; it does not decrypt anything. Content capture
// (the SSL_write uprobe in tls.bpf.c) is a separate program. The
// write-bracket join (looking up an active_write map to emit NET_BIND) was
// abandoned, see N-D1 in docs/decisions/network.md: this file implements the
// tracked_pids gate and the hello capture only.
//
// A connection is identified by its socket, not by the descriptor that made
// it (N-24): every send and close hook resolves its fd through the calling
// task's fd table to the socket inode, so a write by a forked child or by a
// process that received the descriptor over SCM_RIGHTS reaches the same
// conns entry (N-23). A datagram sent to an explicit address needs no
// connect() and is recorded on its own (NET_DGRAM, N-28); a DNS query is
// captured from every datagram to port 53 (N-27). Every hook is a raw
// tracepoint, whose detach does not wait for a grace period (N-32).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define AF_UNIX  1
#define AF_INET  2
#define AF_INET6 10
#define UNIX_PATH_LEN 108 // sizeof(((struct sockaddr_un *)0)->sun_path)
// HELLO_CAP_LEN bounds the bytes one record carries: the first send of a
// connection, one continuation of its ClientHello, a DNS query or a
// datagram. A ClientHello with a post-quantum key share is 1.5 to 2 KiB
// (N-31), so one send of it fits whole.
#define HELLO_CAP_LEN 4096
// HELLO_FOLLOW_MAX bounds the bytes of a ClientHello captured across sends,
// first send included: one full TLS record. HELLO_MAX_PARTS bounds the
// continuation records of one connection (N-31).
#define HELLO_FOLLOW_MAX (5 + 16384)
#define HELLO_MAX_PARTS 8
// net_event_hdr.flags: on NET_HELLO and NET_HELLO_MORE, further sends of the
// same ClientHello follow as NET_HELLO_MORE.
#define NET_FLAG_HELLO_MORE 1
#define SOCK_STREAM 1
#define SOCK_DGRAM  2
#define SOCK_RAW    3
#define MSG_FASTOPEN 0x20000000
#define DNS_PORT 53

enum net_event_type {
	NET_CONNECT = 1,
	NET_HELLO   = 2,
	NET_BIND    = 3, // reserved, never emitted: the write-bracket join is abandoned (N-D1)
	NET_CLOSE   = 4,
	// Listener capability evidence (P-8 in docs/decisions/probes.md).
	// Ground truth only: no trajectory format can claim these, and the
	// verifier never aligns them (D3 in docs/decisions/integration.md).
	NET_SOCK_BIND   = 5,
	NET_SOCK_LISTEN = 6,
	// connect() to an AF_UNIX socket. The socket path travels in the record
	// payload (payload_len bytes), not in addr, which is too small for it.
	// AF_UNIX bind and listen reuse NET_SOCK_BIND and NET_SOCK_LISTEN with
	// family == AF_UNIX and the path in the payload the same way.
	NET_UNIX_CONNECT = 7,
	// The first send on a connection through a path whose bytes are not
	// read (sendfile, splice), or whose hello read faulted: header only. It
	// marks the connection as having carried data (N-22, N-23).
	NET_SEND = 8,
	// A datagram sent with an explicit address (sendto, sendmsg, the first
	// message of sendmmsg) on a datagram or raw socket (N-28). The address
	// is the destination, not a connect()ed peer; the payload holds the
	// first bytes of the datagram. Sent once per socket and destination,
	// except to port 53, where every datagram is a DNS query (N-27).
	NET_DGRAM = 9,
	// The bytes of a later send on a connection whose first send began a
	// ClientHello it did not hold whole (N-31): the hello continues here.
	// Payload as NET_HELLO; flags says whether more follows.
	NET_HELLO_MORE = 10,
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
	// Socket inode number naming the connection on NET_CONNECT, NET_HELLO,
	// NET_SEND and NET_CLOSE (N-24), and the sending socket on NET_DGRAM;
	// 0 on the other records. tgid and fd
	// are those of the caller, which need not be the process that connected.
	__u64 sock;
	__u32 payload_len; // NET_HELLO, NET_DGRAM, and the AF_UNIX records' path
	// The socket's type (SOCK_STREAM, SOCK_DGRAM, SOCK_RAW) on the records
	// that carry sock; 0 when unknown. Userspace reads a DNS query with or
	// without the TCP length prefix by it (N-27).
	__u16 sotype;
	__u16 flags; // NET_FLAG_* bits
};

struct net_event {
	struct net_event_hdr hdr;
	// Only the first HELLO_CAP_LEN bytes are ever emitted. The second half is
	// verifier slack for the multi-iovec copy: it writes at an offset below
	// HELLO_CAP_LEN with a size of at most HELLO_CAP_LEN, and the verifier
	// bounds the two separately.
	__u8 payload[HELLO_CAP_LEN * 2];
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
	__u8  sent; // a NET_HELLO or NET_SEND was emitted
	__u8  sotype; // the socket's type, 0 when unknown
	__u8  hello_parts; // NET_HELLO_MORE records emitted (N-31)
	__u32 tgid; // the process that connected
	__u16 hello_left; // ClientHello bytes still to capture from later sends (N-31)
	__u64 open_ts_ns;
};

// conns holds one entry per tracked TCP or UDP connection, keyed by the
// socket inode number (N-24). The inode number is unique for the life of
// the socket and is not reused by the next socket the way a struct sock
// address is, so an entry left by a socket released without a close() seen
// here cannot be mistaken for a later socket's.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);
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

// tracked_pids gates every program in this file. It is this object's own
// map, neither pinned nor shared with the proc probe: net.Observer seeds the
// root with TrackPID, and handle_fork and handle_exit below follow its
// descendants.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u8);
} tracked_pids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20); // 1 MiB: a record carries up to HELLO_CAP_LEN bytes
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

// tracked_stat and tracked_seeded count the entries of tracked_pids, as in
// proc.bpf.c (P-34): live is incremented by handle_fork's insert and
// decremented by handle_exit's delete, peak keeps the highest live plus
// seeded read back after an insert, and tracked_seeded holds the pids
// userspace inserted (TrackPID), written only by userspace.
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

// tracked_inserted counts an insert and raises peak; the read-back and the
// raise are plain loads and a store, so the peak can fall short when inserts
// race on two CPUs (see proc.bpf.c).
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

// io_uring counters (N-25). Every syscall hook runs at sys_enter,
// which an operation submitted through io_uring never passes. The probe does
// not record those operations; it counts them so the capture can say it is
// blind. iouring_net_count is event loss: an operation on a socket (or one
// whose target the probe cannot resolve) by a tracked process. The other two
// are diagnostics: every operation a tracked process submitted, and every
// ring it set up. Userspace sums the percpu slots and snapshots them in
// Stop().
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} iouring_net_count SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} iouring_ops_count SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} iouring_setup_count SEC(".maps");

static __always_inline void count_in(void *map)
{
	__u32 zero = 0;
	__u64 *count = bpf_map_lookup_elem(map, &zero);
	if (count)
		__sync_fetch_and_add(count, 1);
}

// hello_fault_count counts hello reads that faulted: a send hook found a
// connection with no hello yet and could not read the bytes it sends (a
// buffer page not resident, a bad pointer, an unreadable msghdr or iovec).
// The connection is still marked sent (NET_SEND), so it is not lost; what is
// lost is its hostname, since a later send is captured in its place and is
// usually not a ClientHello. A content gap, not event loss (N-D5). One
// connection can fault more than once, and a later send can still yield its
// hello, so the value bounds the connections affected from above.
// Userspace sums the percpu slots and snapshots them in Stop().
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} hello_fault_count SEC(".maps");

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
	hdr->sock = 0;
	hdr->payload_len = 0;
	hdr->sotype = 0;
	hdr->flags = 0;
}

// --- syscall entry (N-32) ---------------------------------------------------
//
// The syscall hooks are not per-syscall tracepoints (sys_enter_connect, ...):
// detaching one of those waits for RCU grace periods under the kernel's
// event_mutex, about 60 ms each, which made Stop take over a second. One raw
// tracepoint on sys_enter, whose detach does not wait, dispatches the
// syscalls this file handles by number to one program each through a tail
// call; the programs are those the tracepoints ran, reading their arguments
// from the saved user registers. sys_enter fires for every syscall on the
// host, so the dispatcher's switch on the number comes before anything else.
// The numbers and the argument registers are those of x86_64 (rdi, rsi, rdx,
// r10, r8, r9). A 32-bit (ia32) syscall has other numbers; like the
// per-syscall tracepoints, which ignore compat syscalls on x86_64, the
// dispatcher skips it. An x32 number carries bit 30 and matches nothing.

#define NR_write          1
#define NR_close          3
#define NR_writev         20
#define NR_dup2           33
#define NR_sendfile       40
#define NR_connect        42
#define NR_sendto         44
#define NR_sendmsg        46
#define NR_bind           49
#define NR_listen         50
#define NR_splice         275
#define NR_dup3           292
#define NR_sendmmsg       307
#define NR_pwritev2       328
#define NR_io_uring_setup 425

// Slots of sys_enter_progs. sysEnterPrograms in observer.go fills them in
// this order.
enum sys_slot {
	SLOT_CONNECT,
	SLOT_BIND,
	SLOT_LISTEN,
	SLOT_WRITE,
	SLOT_SENDTO,
	SLOT_SENDMSG,
	SLOT_SENDMMSG,
	SLOT_WRITEV,
	SLOT_PWRITEV2,
	SLOT_SENDFILE,
	SLOT_SPLICE,
	SLOT_CLOSE,
	SLOT_DUP2,
	SLOT_DUP3,
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
#define SYS_ARG4(regs) BPF_CORE_READ(regs, r10)
#define SYS_ARG5(regs) BPF_CORE_READ(regs, r8)
#define SYS_ARG6(regs) BPF_CORE_READ(regs, r9)

SEC("raw_tracepoint/sys_enter")
int trace_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
	__u32 slot;
	switch (ctx->args[1]) {
	case NR_connect:  slot = SLOT_CONNECT; break;
	case NR_bind:     slot = SLOT_BIND; break;
	case NR_listen:   slot = SLOT_LISTEN; break;
	case NR_write:    slot = SLOT_WRITE; break;
	case NR_sendto:   slot = SLOT_SENDTO; break;
	case NR_sendmsg:  slot = SLOT_SENDMSG; break;
	case NR_sendmmsg: slot = SLOT_SENDMMSG; break;
	case NR_writev:   slot = SLOT_WRITEV; break;
	case NR_pwritev2: slot = SLOT_PWRITEV2; break;
	case NR_sendfile: slot = SLOT_SENDFILE; break;
	case NR_splice:   slot = SLOT_SPLICE; break;
	case NR_close:    slot = SLOT_CLOSE; break;
	case NR_dup2:     slot = SLOT_DUP2; break;
	case NR_dup3:     slot = SLOT_DUP3; break;
	case NR_io_uring_setup: slot = SLOT_COUNT; break;
	default:
		return 0;
	}
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (!is_tracked(tgid))
		return 0;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	if (BPF_CORE_READ(task, thread_info.status) & TS_COMPAT)
		return 0;
	if (slot == SLOT_COUNT) {
		// io_uring_setup: count the rings tracked processes set up. A
		// diagnostic, except on a kernel without io_uring_submit_req,
		// where the observer reports every ring as possible network
		// activity (N-25).
		count_in(&iouring_setup_count);
		return 0;
	}
	bpf_tail_call(ctx, &sys_enter_progs, slot);
	// Reached only when the slot is empty, which New rules out: the
	// syscall went unrecorded, so it is counted as event loss.
	count_drop();
	return 0;
}

// --- socket resolution (N-24) ---------------------------------------------
//
// A syscall hook sees only the descriptor number. fd_socket looks
// it up in the calling task's fd table (task->files->fdt->fd[fd]) with CO-RE
// reads and returns the struct file and the socket inode number when the
// descriptor is a socket. Every read is a bpf_probe_read_kernel, which the
// existing bpf_probe_read_user use already requires (kernel 5.5).

#define S_IFMT   00170000
#define S_IFSOCK 0140000

enum fd_result {
	FD_SOCKET = 0, // *filep and *ino are set
	FD_NONE   = 1, // no such descriptor, or not a socket
	FD_FAULT  = 2, // a kernel read failed
};

static __always_inline struct file *fd_file(__u32 fd, int *res)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct fdtable *fdt = BPF_CORE_READ(task, files, fdt);
	if (!fdt) {
		*res = FD_FAULT;
		return NULL;
	}
	unsigned int max_fds = BPF_CORE_READ(fdt, max_fds);
	if (fd >= max_fds) {
		*res = FD_NONE;
		return NULL;
	}
	struct file **fds = BPF_CORE_READ(fdt, fd);
	struct file *f = NULL;
	if (!fds || bpf_probe_read_kernel(&f, sizeof(f), &fds[fd])) {
		*res = FD_FAULT;
		return NULL;
	}
	*res = f ? FD_SOCKET : FD_NONE;
	return f;
}

static __always_inline int fd_socket(__u32 fd, struct file **filep, __u64 *ino)
{
	int res;
	struct file *f = fd_file(fd, &res);
	if (!f)
		return res;
	struct inode *inode = BPF_CORE_READ(f, f_inode);
	if (!inode)
		return FD_FAULT;
	umode_t mode = BPF_CORE_READ(inode, i_mode);
	if ((mode & S_IFMT) != S_IFSOCK)
		return FD_NONE;
	*ino = BPF_CORE_READ(inode, i_ino);
	if (!*ino)
		return FD_FAULT;
	*filep = f;
	return FD_SOCKET;
}

// sock_type returns the type of the socket behind f (SOCK_STREAM,
// SOCK_DGRAM, SOCK_RAW, ...), or 0 when it cannot be read. A socket file's
// private_data is its struct socket.
static __always_inline __u8 sock_type(struct file *f)
{
	struct socket *s = BPF_CORE_READ(f, private_data);
	if (!s)
		return 0;
	short t = BPF_CORE_READ(s, type);
	return (t > 0 && t < 256) ? (__u8)t : 0;
}

// struct file before kernel 6.13 counted references in f_count; 6.13
// replaced it with f_ref, a file_ref_t that stores the count minus one.
struct file___pre613 {
	atomic_long_t f_count;
} __attribute__((preserve_access_index));

#define FILE_REF_RELEASED 0xC000000000000000ULL

// file_last_ref reports whether the descriptor being closed holds the only
// reference to f: no other descriptor, in this process or another (a child
// after fork, a receiver of SCM_RIGHTS, a dup), and no message in flight
// still refers to it. A syscall running concurrently in another thread of a
// process whose fd table is shared also holds a reference for its duration.
static __always_inline int file_last_ref(struct file *f)
{
	if (bpf_core_field_exists(f->f_ref)) {
		__u64 c = 0;
		if (bpf_core_read(&c, sizeof(c), &f->f_ref.refcnt.counter))
			return 0;
		return c == 0 || c >= FILE_REF_RELEASED; // 0 is FILE_REF_ONEREF
	}
	struct file___pre613 *old = (void *)f;
	long n = 0;
	if (bpf_core_read(&n, sizeof(n), &old->f_count.counter))
		return 0;
	return n <= 1;
}

// lookup_conn returns the conns entry of the socket behind fd, or NULL.
static __always_inline struct conn_state *lookup_conn(__u32 fd, __u64 *ino)
{
	struct file *f = NULL;
	if (fd_socket(fd, &f, ino) != FD_SOCKET)
		return NULL;
	return bpf_map_lookup_elem(&conns, ino);
}

// emit_conn sends one record about connection cs whose payload, if any, is
// already in e->payload.
static __always_inline void emit_conn(struct net_event *e, __u8 type, __u32 tgid, __u32 fd,
				      __u64 ino, struct conn_state *cs, __u32 len, __u16 flags)
{
	fill_common(&e->hdr, type, tgid, fd);
	e->hdr.flags = flags;
	e->hdr.family = cs->family;
	e->hdr.port = cs->port;
	__builtin_memcpy(e->hdr.addr, cs->addr, sizeof(cs->addr));
	e->hdr.sock = ino;
	e->hdr.sotype = cs->sotype;
	if (len > HELLO_CAP_LEN)
		len = HELLO_CAP_LEN;
	e->hdr.payload_len = len;
	if (bpf_ringbuf_output(&net_events, e, sizeof(e->hdr) + len, 0))
		count_drop();
}

// mark_sent emits NET_SEND for the first send on cs that yields no hello.
static __always_inline void mark_sent(struct net_event *e, __u32 tgid, __u32 fd,
				      __u64 ino, struct conn_state *cs)
{
	if (cs->sent)
		return;
	emit_conn(e, NET_SEND, tgid, fd, ino, cs, 0, 0);
	cs->sent = 1;
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

// peer is an IPv4 or IPv6 address and port in host byte order.
struct peer {
	__u8  addr[16];
	__u16 port;
	__u8  family;
	__u8  _pad[5];
};

// dgram_key names one destination of one socket for the dgrams map (N-28).
struct dgram_key {
	__u64 sock;
	struct peer peer;
};

// record_connect stores a new connection of socket ino to p in conns and
// emits NET_CONNECT. A connect on a socket already in conns (a datagram
// socket connected again) starts a new connection on the same key;
// userspace emits the old one first (Coverage.Replaced).
static __always_inline void record_connect(__u32 tgid, __u32 fd, __u64 ino, __u8 sotype,
					   struct peer *p)
{
	struct conn_state state = {0};
	state.family = p->family;
	state.port = p->port;
	state.tgid = tgid;
	state.sotype = sotype;
	state.open_ts_ns = bpf_ktime_get_ns();
	__builtin_memcpy(state.addr, p->addr, sizeof(state.addr));
	if (bpf_map_update_elem(&conns, &ino, &state, BPF_ANY))
		count_state_lost();

	struct net_event *e = reserve_event();
	if (!e)
		return;
	fill_common(&e->hdr, NET_CONNECT, tgid, fd);
	e->hdr.family = state.family;
	e->hdr.port = state.port;
	__builtin_memcpy(e->hdr.addr, state.addr, sizeof(state.addr));
	e->hdr.sock = ino;
	e->hdr.sotype = sotype;
	if (bpf_ringbuf_output(&net_events, &e->hdr, sizeof(e->hdr), 0))
		count_drop();
}

SEC("raw_tracepoint/sys_enter")
int trace_connect(struct bpf_raw_tracepoint_args *ctx)
{
	struct pt_regs *regs = sys_regs(ctx);
	__u64 a_fd = SYS_ARG1(regs);
	__u64 a_uservaddr = SYS_ARG2(regs);
	__u64 a_addrlen = SYS_ARG3(regs);
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
	if (bpf_probe_read_user(&family, sizeof(family), (void *)a_uservaddr))
		return 0;
	if (family == AF_UNIX) {
		// Capability evidence only: a connect to /var/run/docker.sock or a
		// systemd socket is how an agent delegates work to a daemon outside
		// the tracked tree. No conns entry, since no TLS rides on it.
		struct net_event *ue = reserve_event();
		if (!ue)
			return 0;
		int ulen = read_unix_path(ue, a_uservaddr, a_addrlen);
		if (ulen < 0)
			return 0;
		emit_unix(ue, NET_UNIX_CONNECT, tgid, (__u32)a_fd, (__u32)ulen);
		return 0;
	}
	if (family != AF_INET && family != AF_INET6)
		return 0;

	// Read the full address struct with a per-family constant size:
	// sizeof(sockaddr_in) = 16, sizeof(sockaddr_in6) = 28.
	__u8 sa[28] = {};
	if (family == AF_INET) {
		if (bpf_probe_read_user(sa, 16, (void *)a_uservaddr))
			return 0;
	} else {
		if (bpf_probe_read_user(sa, 28, (void *)a_uservaddr))
			return 0;
	}

	__u16 port_be = *(__u16 *)(sa + 2);
	__u16 port = ((port_be & 0xff) << 8) | (port_be >> 8);

	// A descriptor that is not a socket makes connect fail (EBADF, ENOTSOCK)
	// with nothing sent, so it is not recorded. A failed kernel read loses a
	// connection the caller did make, and is counted.
	__u32 fd = (__u32)a_fd;
	struct file *f = NULL;
	__u64 ino = 0;
	int res = fd_socket(fd, &f, &ino);
	if (res == FD_FAULT)
		count_state_lost();
	if (res != FD_SOCKET)
		return 0;

	struct peer p = {0};
	p.family = (__u8)family;
	p.port = port;
	if (family == AF_INET) {
		__builtin_memcpy(p.addr, sa + 4, 4);
	} else {
		// AF_INET6: sin6_addr starts at offset 8 in sockaddr_in6.
		// We always read 28 bytes above, so offset 8+16=24 is in bounds.
		__builtin_memcpy(p.addr, sa + 8, 16);
	}
	record_connect(tgid, fd, ino, sock_type(f), &p);
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

SEC("raw_tracepoint/sys_enter")
int trace_bind(struct bpf_raw_tracepoint_args *ctx)
{
	struct pt_regs *regs = sys_regs(ctx);
	__u64 a_fd = SYS_ARG1(regs);
	__u64 a_umyaddr = SYS_ARG2(regs);
	__u64 a_addrlen = SYS_ARG3(regs);
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (!is_tracked(tgid))
		return 0;

	// Constant-size reads only, see trace_connect for why.
	__u16 family;
	if (bpf_probe_read_user(&family, sizeof(family), (void *)a_umyaddr))
		return 0;
	if (family == AF_UNIX) {
		struct net_event *ue = reserve_event();
		if (!ue)
			return 0;
		int ulen = read_unix_path(ue, a_umyaddr, a_addrlen);
		if (ulen < 0)
			return 0;
		struct conn_key ukey = { .tgid = tgid, .fd = (__u32)a_fd };
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
		if (a_addrlen < 16)
			return 0;
		if (bpf_probe_read_user(sa, 16, (void *)a_umyaddr))
			return 0;
	} else {
		if (a_addrlen < 28)
			return 0;
		if (bpf_probe_read_user(sa, 28, (void *)a_umyaddr))
			return 0;
	}

	__u16 port_be = *(__u16 *)(sa + 2);
	__u16 port = ((port_be & 0xff) << 8) | (port_be >> 8);

	struct conn_key key = { .tgid = tgid, .fd = (__u32)a_fd };
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

SEC("raw_tracepoint/sys_enter")
int trace_listen(struct bpf_raw_tracepoint_args *ctx)
{
	struct pt_regs *regs = sys_regs(ctx);
	__u64 a_fd = SYS_ARG1(regs);
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (!is_tracked(tgid))
		return 0;

	struct net_event *e = reserve_event();
	if (!e)
		return 0;

	struct conn_key key = { .tgid = tgid, .fd = (__u32)a_fd };
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

// --- send side: hello capture and the written mark (N-23) -----------------
//
// Every send hook resolves its descriptor to the socket (lookup_conn), so a
// send by any tracked process holding the connection counts, not only one by
// the process that connected. The first send that carries readable bytes
// emits NET_HELLO with up to HELLO_CAP_LEN of them; a send whose bytes are
// not read, or whose read faults, emits NET_SEND once. A faulted read is also
// counted in hello_fault_count. Either marks the
// connection as having carried data. All hooks fire at syscall entry, so a
// send that then fails still counts, like a failed connect. A zero-length
// send carries nothing and is ignored. On a connected datagram socket to
// port 53 every send is captured, one DNS query each (N-27).
//
// A first send on a stream that begins a TLS handshake record but does not
// hold the whole ClientHello (the client wrote the record in pieces, or split
// the hello over several records) is followed (N-31): the next sends on the
// connection are captured as NET_HELLO_MORE until the hello's bytes are in,
// up to HELLO_FOLLOW_MAX bytes and HELLO_MAX_PARTS records. Following stops
// at a send the capture cannot hold whole, since the one after it would not
// continue the captured bytes.

// HELLO_MAX_IOV bounds how many iovecs of a writev or sendmsg are copied
// into the hello buffer. The loop is unrolled, so the verifier sees straight
// code. A hello split over more iovecs is captured from the first eight.
#define HELLO_MAX_IOV 8

// dns_per_datagram reports whether every send on cs is captured, not only
// the first: a connected datagram socket to port 53 carries one DNS query
// per datagram, and each is recorded (N-27). A stream socket to port 53
// gets its first send only, like any connection.
static __always_inline int dns_per_datagram(struct conn_state *cs)
{
	return cs->port == DNS_PORT && cs->sotype == SOCK_DGRAM;
}

static __always_inline int wants_hello(struct conn_state *cs)
{
	return !cs->hello_captured || dns_per_datagram(cs);
}

// hello_continues reports whether the next send on cs continues a ClientHello.
static __always_inline int hello_continues(struct conn_state *cs)
{
	return cs->hello_captured && cs->hello_left && !dns_per_datagram(cs);
}

// hello_follow decides, from the first n captured bytes of a connection,
// how many bytes of its ClientHello later sends still carry, and returns the
// flags for the NET_HELLO record. whole says the capture holds the entire
// send. The record header gives the record's length and the handshake
// header the message's: a message that fits its record ends with the
// record; one larger than its record continues in further records whose
// sizes are unknown here, so up to HELLO_FOLLOW_MAX is followed and
// userspace stops at the end of the message. Bytes that do not begin a
// handshake record carrying a ClientHello are not followed.
static __always_inline __u16 hello_follow(struct conn_state *cs, struct net_event *e, __u32 n, int whole)
{
	cs->hello_left = 0;
	cs->hello_parts = 0;
	if (!whole || n < 2 || cs->sotype == SOCK_DGRAM || cs->port == DNS_PORT)
		return 0;
	if (e->payload[0] != 0x16 || e->payload[1] != 3)
		return 0;
	__u32 want = HELLO_FOLLOW_MAX;
	if (n >= 9) {
		if (e->payload[5] != 1) // handshake type client_hello
			return 0;
		__u32 rec = ((__u32)e->payload[3] << 8) | e->payload[4];
		__u32 msg = 4 + (((__u32)e->payload[6] << 16) | ((__u32)e->payload[7] << 8) |
				 e->payload[8]);
		if (msg <= rec)
			want = 5 + rec;
	}
	if (want > HELLO_FOLLOW_MAX)
		want = HELLO_FOLLOW_MAX;
	if (want <= n)
		return 0;
	cs->hello_left = (__u16)(want - n);
	return NET_FLAG_HELLO_MORE;
}

// hello_more_done accounts for n continuation bytes just captured and returns
// the flags for their NET_HELLO_MORE record.
static __always_inline __u16 hello_more_done(struct conn_state *cs, __u32 n, int whole)
{
	__u32 left = cs->hello_left;
	left = n < left ? left - n : 0;
	cs->hello_parts++;
	if (!whole || cs->hello_parts >= HELLO_MAX_PARTS)
		left = 0;
	cs->hello_left = (__u16)left;
	return left ? NET_FLAG_HELLO_MORE : 0;
}

// capture_more captures the next bytes of a ClientHello from a send of len
// bytes at buf. A send longer than what the hello still needs ends it there.
static __always_inline int capture_more(__u32 tgid, __u32 fd, __u64 ino, struct conn_state *cs,
					const void *buf, __u64 len)
{
	struct net_event *e = reserve_event();
	if (!e)
		return 0;
	__u64 n = len;
	if (n > cs->hello_left)
		n = cs->hello_left;
	int whole = 1;
	if (n > HELLO_CAP_LEN) {
		n = HELLO_CAP_LEN;
		whole = 0;
	}
	barrier_var(n);
	if (n > HELLO_CAP_LEN)
		n = HELLO_CAP_LEN;
	if (bpf_probe_read_user(e->payload, n, buf)) {
		count_in(&hello_fault_count);
		cs->hello_left = 0;
		return 0;
	}
	__u16 flags = hello_more_done(cs, (__u32)n, whole);
	emit_conn(e, NET_HELLO_MORE, tgid, fd, ino, cs, (__u32)n, flags);
	return 0;
}

static __always_inline int capture_hello(__u32 tgid, __u32 fd, const void *buf, __u64 len)
{
	if (len == 0)
		return 0;
	__u64 ino = 0;
	struct conn_state *cs = lookup_conn(fd, &ino);
	if (!cs)
		return 0;
	if (hello_continues(cs))
		return capture_more(tgid, fd, ino, cs, buf, len);
	if (!wants_hello(cs))
		return 0;

	int whole = len <= HELLO_CAP_LEN;
	if (len > HELLO_CAP_LEN)
		len = HELLO_CAP_LEN;

	struct net_event *e = reserve_event();
	if (!e)
		return 0;
	if (bpf_probe_read_user(e->payload, len, buf)) {
		// A faulting read (buffer page not resident, or a bad pointer)
		// must not be treated as an empty capture that later reads as "no
		// content, but not disagreement" (N-D5). The connection still
		// carried data, so it is marked sent, and a later write gets
		// another capture attempt. The fault is counted.
		count_in(&hello_fault_count);
		mark_sent(e, tgid, fd, ino, cs);
		return 0;
	}

	__u16 flags = hello_follow(cs, e, (__u32)len, whole);
	emit_conn(e, NET_HELLO, tgid, fd, ino, cs, (__u32)len, flags);
	cs->hello_captured = 1;
	cs->sent = 1;
	return 0;
}

struct iovec_bpf {
	__u64 iov_base;
	__u64 iov_len;
};

// copy_iov concatenates the first HELLO_MAX_IOV entries of an iovec array in
// user memory into e->payload, up to HELLO_CAP_LEN bytes, and returns how
// many bytes it copied. *fault is set when a read faulted; the bytes before
// it are kept. *cut is set when bytes of the array may be left uncopied (an
// entry beyond the cap or beyond the eighth).
static __always_inline __u32 copy_iov(struct net_event *e, __u64 iov_ptr, __u64 iovcnt, int *fault,
				      int *cut)
{
	__u32 off = 0;
	if (iovcnt > HELLO_MAX_IOV)
		*cut = 1;
#pragma unroll
	for (int i = 0; i < HELLO_MAX_IOV; i++) {
		if (i >= iovcnt)
			break;
		if (off >= HELLO_CAP_LEN) {
			*cut = 1;
			break;
		}
		struct iovec_bpf iov = {0};
		if (bpf_probe_read_user(&iov, sizeof(iov), (void *)(iov_ptr + i * sizeof(iov)))) {
			*fault = 1;
			break;
		}
		__u64 n = iov.iov_len;
		if (n > HELLO_CAP_LEN - off) {
			n = HELLO_CAP_LEN - off;
			*cut = 1;
		}
		// The verifier bounds off and n separately, not their sum: clamp
		// both against constants it can see (the barriers keep clang from
		// folding the clamps away), and the payload's slack half covers
		// off + n up to twice HELLO_CAP_LEN.
		barrier_var(n);
		if (n > HELLO_CAP_LEN)
			n = HELLO_CAP_LEN;
		__u32 at = off;
		barrier_var(at);
		at &= HELLO_CAP_LEN - 1;
		if (n == 0)
			continue;
		if (bpf_probe_read_user(&e->payload[at], n, (void *)iov.iov_base)) {
			*fault = 1;
			break;
		}
		off += n;
	}
	barrier_var(off);
	if (off > HELLO_CAP_LEN)
		off = HELLO_CAP_LEN;
	return off;
}

// capture_more_iov is capture_more for an iovec array in user memory.
static __always_inline int capture_more_iov(__u32 tgid, __u32 fd, __u64 ino, struct conn_state *cs,
					    __u64 iov_ptr, __u64 iovcnt)
{
	struct net_event *e = reserve_event();
	if (!e)
		return 0;
	int fault = 0, cut = 0;
	__u32 n = copy_iov(e, iov_ptr, iovcnt, &fault, &cut);
	if (fault) {
		count_in(&hello_fault_count);
		cs->hello_left = 0;
		return 0;
	}
	if (n == 0)
		return 0;
	int whole = 1;
	if (n >= cs->hello_left)
		n = cs->hello_left; // the hello ends inside this send
	else if (cut)
		whole = 0;
	barrier_var(n);
	if (n > HELLO_CAP_LEN)
		n = HELLO_CAP_LEN;
	__u16 flags = hello_more_done(cs, n, whole);
	emit_conn(e, NET_HELLO_MORE, tgid, fd, ino, cs, n, flags);
	return 0;
}

// capture_hello_iov is capture_hello for an iovec array in user memory.
// When nothing could be copied (every copied entry empty, or a read
// faulted), the connection is marked sent instead.
static __always_inline int capture_hello_iov(__u32 tgid, __u32 fd, __u64 iov_ptr, __u64 iovcnt)
{
	if (iovcnt == 0)
		return 0;
	__u64 ino = 0;
	struct conn_state *cs = lookup_conn(fd, &ino);
	if (!cs)
		return 0;
	if (hello_continues(cs))
		return capture_more_iov(tgid, fd, ino, cs, iov_ptr, iovcnt);
	if (!wants_hello(cs))
		return 0;

	struct net_event *e = reserve_event();
	if (!e)
		return 0;

	int fault = 0, cut = 0;
	__u32 off = copy_iov(e, iov_ptr, iovcnt, &fault, &cut);
	if (fault)
		count_in(&hello_fault_count);
	if (fault || off == 0) {
		mark_sent(e, tgid, fd, ino, cs);
		return 0;
	}
	__u16 flags = hello_follow(cs, e, off, !cut);
	emit_conn(e, NET_HELLO, tgid, fd, ino, cs, off, flags);
	cs->hello_captured = 1;
	cs->sent = 1;
	return 0;
}

// --- addressed sends (N-28) -------------------------------------------------
//
// A send that names its destination (sendto with an address, sendmsg with
// msg_name) on a datagram or raw socket sends to that address whether or
// not the socket is connected, and no connect() announces it. It is
// recorded as NET_DGRAM, once per socket and destination (dgrams, an LRU
// map: an evicted entry only repeats a record, which userspace drops),
// except that every datagram to port 53 is recorded, since each is a DNS
// query (N-27). On a stream socket an address is ignored by the kernel,
// unless MSG_FASTOPEN asks it to connect (TCP Fast Open): that is recorded
// as the connect it is, and the send's bytes as its hello.

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, struct dgram_key);
	__type(value, __u8);
} dgrams SEC(".maps");

// read_peer reads an AF_INET or AF_INET6 address from user memory into p.
// It returns 0 for any other family, an address shorter than the kernel
// accepts (16 bytes for IPv4, 24 for IPv6, SIN6_LEN_RFC2133), or a read
// that faults.
static __always_inline int read_peer(__u64 uaddr, __u64 addrlen, struct peer *p)
{
	if (!uaddr)
		return 0;
	__u16 family = 0;
	if (bpf_probe_read_user(&family, sizeof(family), (void *)uaddr))
		return 0;
	__u8 sa[24] = {};
	if (family == AF_INET) {
		if (addrlen < 16 || bpf_probe_read_user(sa, 16, (void *)uaddr))
			return 0;
		__builtin_memcpy(p->addr, sa + 4, 4);
	} else if (family == AF_INET6) {
		if (addrlen < 24 || bpf_probe_read_user(sa, 24, (void *)uaddr))
			return 0;
		__builtin_memcpy(p->addr, sa + 8, 16);
	} else {
		return 0;
	}
	__u16 port_be = *(__u16 *)(sa + 2);
	p->port = ((port_be & 0xff) << 8) | (port_be >> 8);
	p->family = (__u8)family;
	return 1;
}

// addressed_send handles a send to an explicit address. The bytes are buf
// and len, or, when iov_ptr is set, an iovec array. It returns 1 when the
// send was recorded as a datagram, so the caller skips the connection path;
// 0 otherwise (no usable address, a stream socket, an unreadable socket).
static __always_inline int addressed_send(__u32 tgid, __u32 fd, __u64 uaddr, __u64 addrlen,
					  __u64 flags, __u64 buf, __u64 len,
					  __u64 iov_ptr, __u64 iovcnt)
{
	struct dgram_key key = {0};
	if (!read_peer(uaddr, addrlen, &key.peer))
		return 0;
	struct file *f = NULL;
	__u64 ino = 0;
	if (fd_socket(fd, &f, &ino) != FD_SOCKET)
		return 0;
	__u8 st = sock_type(f);
	if (st == SOCK_STREAM) {
		if ((flags & MSG_FASTOPEN) && !bpf_map_lookup_elem(&conns, &ino))
			record_connect(tgid, fd, ino, st, &key.peer);
		return 0;
	}
	if (st != SOCK_DGRAM && st != SOCK_RAW)
		return 0;
	key.sock = ino;
	if (key.peer.port != DNS_PORT || st != SOCK_DGRAM) {
		if (bpf_map_lookup_elem(&dgrams, &key))
			return 1;
		__u8 one = 1;
		bpf_map_update_elem(&dgrams, &key, &one, BPF_ANY);
	}

	struct net_event *e = reserve_event();
	if (!e)
		return 1;
	__u32 n = 0;
	int fault = 0, cut = 0;
	if (iov_ptr) {
		n = copy_iov(e, iov_ptr, iovcnt, &fault, &cut);
	} else if (len) {
		if (len > HELLO_CAP_LEN)
			len = HELLO_CAP_LEN;
		if (bpf_probe_read_user(e->payload, len, (void *)buf))
			fault = 1;
		else
			n = (__u32)len;
	}
	if (fault)
		count_in(&hello_fault_count);
	fill_common(&e->hdr, NET_DGRAM, tgid, fd);
	e->hdr.family = key.peer.family;
	e->hdr.port = key.peer.port;
	__builtin_memcpy(e->hdr.addr, key.peer.addr, sizeof(key.peer.addr));
	e->hdr.sock = ino;
	e->hdr.sotype = st;
	barrier_var(n);
	if (n > HELLO_CAP_LEN)
		n = HELLO_CAP_LEN;
	e->hdr.payload_len = n;
	if (bpf_ringbuf_output(&net_events, e, sizeof(e->hdr) + n, 0))
		count_drop();
	return 1;
}

// send_without_bytes marks a connection sent for a path whose bytes the
// probe does not read (sendfile, splice).
static __always_inline int send_without_bytes(__u32 tgid, __u32 fd, __u64 len)
{
	if (len == 0)
		return 0;
	__u64 ino = 0;
	struct conn_state *cs = lookup_conn(fd, &ino);
	if (!cs || cs->sent)
		return 0;
	struct net_event *e = reserve_event();
	if (!e)
		return 0;
	mark_sent(e, tgid, fd, ino, cs);
	return 0;
}

SEC("raw_tracepoint/sys_enter")
int trace_write(struct bpf_raw_tracepoint_args *ctx)
{
	struct pt_regs *regs = sys_regs(ctx);
	__u64 a_fd = SYS_ARG1(regs);
	__u64 a_buf = SYS_ARG2(regs);
	__u64 a_count = SYS_ARG3(regs);
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (!is_tracked(tgid))
		return 0;
	return capture_hello(tgid, (__u32)a_fd, (const void *)a_buf, a_count);
}

SEC("raw_tracepoint/sys_enter")
int trace_sendto(struct bpf_raw_tracepoint_args *ctx)
{
	struct pt_regs *regs = sys_regs(ctx);
	__u64 a_fd = SYS_ARG1(regs);
	__u64 a_buff = SYS_ARG2(regs);
	__u64 a_len = SYS_ARG3(regs);
	__u64 a_flags = SYS_ARG4(regs);
	__u64 a_addr = SYS_ARG5(regs);
	__u64 a_addr_len = SYS_ARG6(regs);
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (!is_tracked(tgid))
		return 0;
	if (a_addr && addressed_send(tgid, (__u32)a_fd, a_addr, a_addr_len,
				     a_flags, a_buff, a_len, 0, 0))
		return 0;
	return capture_hello(tgid, (__u32)a_fd, (const void *)a_buff, a_len);
}

// Mirrors struct msghdr / struct iovec's user-space layout on x86_64. struct
// mmsghdr starts with a struct msghdr, so sendmmsg reads its first element
// with the same type.
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

static __always_inline int capture_hello_msg(__u32 tgid, __u32 fd, __u64 msg, __u64 flags)
{
	struct msghdr_bpf mh = {0};
	if (bpf_probe_read_user(&mh, sizeof(mh), (void *)msg)) {
		// The message cannot be read here, but the call may still send it.
		// Counted as a hello fault only on a connection still waiting for
		// its hello, like the reads in capture_hello_iov.
		__u64 ino = 0;
		struct conn_state *cs = lookup_conn(fd, &ino);
		if (!cs)
			return 0;
		if (wants_hello(cs) || hello_continues(cs))
			count_in(&hello_fault_count);
		cs->hello_left = 0;
		struct net_event *e = reserve_event();
		if (e)
			mark_sent(e, tgid, fd, ino, cs);
		return 0;
	}
	if (mh.msg_name && addressed_send(tgid, fd, mh.msg_name, mh.msg_namelen, flags,
					  0, 0, mh.msg_iov, mh.msg_iovlen))
		return 0;
	return capture_hello_iov(tgid, fd, mh.msg_iov, mh.msg_iovlen);
}

SEC("raw_tracepoint/sys_enter")
int trace_sendmsg(struct bpf_raw_tracepoint_args *ctx)
{
	struct pt_regs *regs = sys_regs(ctx);
	__u64 a_fd = SYS_ARG1(regs);
	__u64 a_msg = SYS_ARG2(regs);
	__u64 a_flags = SYS_ARG3(regs);
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (!is_tracked(tgid))
		return 0;
	return capture_hello_msg(tgid, (__u32)a_fd, a_msg, a_flags);
}

// Only the first message is read, for the hello, a DNS query or an
// addressed datagram; the rest are sent after it unseen. glibc sends its
// parallel A and AAAA queries this way, so the AAAA query is not recorded.
SEC("raw_tracepoint/sys_enter")
int trace_sendmmsg(struct bpf_raw_tracepoint_args *ctx)
{
	struct pt_regs *regs = sys_regs(ctx);
	__u64 a_fd = SYS_ARG1(regs);
	__u64 a_mmsg = SYS_ARG2(regs);
	__u64 a_vlen = SYS_ARG3(regs);
	__u64 a_flags = SYS_ARG4(regs);
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (!is_tracked(tgid))
		return 0;
	if (a_vlen == 0)
		return 0;
	return capture_hello_msg(tgid, (__u32)a_fd, a_mmsg, a_flags);
}

SEC("raw_tracepoint/sys_enter")
int trace_writev(struct bpf_raw_tracepoint_args *ctx)
{
	struct pt_regs *regs = sys_regs(ctx);
	__u64 a_fd = SYS_ARG1(regs);
	__u64 a_vec = SYS_ARG2(regs);
	__u64 a_vlen = SYS_ARG3(regs);
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (!is_tracked(tgid))
		return 0;
	return capture_hello_iov(tgid, (__u32)a_fd, a_vec, a_vlen);
}

// pwritev2 with offset -1 writes at the current position, which for a
// socket is a writev; any other offset fails on a socket with ESPIPE.
SEC("raw_tracepoint/sys_enter")
int trace_pwritev2(struct bpf_raw_tracepoint_args *ctx)
{
	struct pt_regs *regs = sys_regs(ctx);
	__u64 a_fd = SYS_ARG1(regs);
	__u64 a_vec = SYS_ARG2(regs);
	__u64 a_vlen = SYS_ARG3(regs);
	__u64 a_pos_l = SYS_ARG4(regs);
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (!is_tracked(tgid))
		return 0;
	if ((__s64)a_pos_l != -1)
		return 0;
	return capture_hello_iov(tgid, (__u32)a_fd, a_vec, a_vlen);
}

SEC("raw_tracepoint/sys_enter")
int trace_sendfile(struct bpf_raw_tracepoint_args *ctx)
{
	struct pt_regs *regs = sys_regs(ctx);
	__u64 a_out_fd = SYS_ARG1(regs);
	__u64 a_count = SYS_ARG4(regs);
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (!is_tracked(tgid))
		return 0;
	return send_without_bytes(tgid, (__u32)a_out_fd, a_count);
}

SEC("raw_tracepoint/sys_enter")
int trace_splice(struct bpf_raw_tracepoint_args *ctx)
{
	struct pt_regs *regs = sys_regs(ctx);
	__u64 a_fd_out = SYS_ARG3(regs);
	__u64 a_len = SYS_ARG5(regs);
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (!is_tracked(tgid))
		return 0;
	return send_without_bytes(tgid, (__u32)a_fd_out, a_len);
}

// --- connection teardown: close, dup2, dup3 (N-24) ------------------------
//
// release_fd runs when a tracked process drops descriptor fd. The connection
// ends only when that descriptor holds the last reference to the socket's
// file: while a child, a receiver of SCM_RIGHTS or a dup still holds it, the
// socket can still send, so the entry stays and a later send still marks it.

static __always_inline void release_fd(__u32 tgid, __u32 fd)
{
	struct conn_key key = { .tgid = tgid, .fd = fd };
	bpf_map_delete_elem(&binds, &key);

	struct file *f = NULL;
	__u64 ino = 0;
	if (fd_socket(fd, &f, &ino) != FD_SOCKET)
		return; // a file, a pipe, ...
	struct conn_state *cs = bpf_map_lookup_elem(&conns, &ino);
	if (!cs)
		return; // a socket no tracked process connected
	if (!file_last_ref(f))
		return;

	struct net_event *e = reserve_event();
	if (e)
		emit_conn(e, NET_CLOSE, tgid, fd, ino, cs, 0, 0);
	bpf_map_delete_elem(&conns, &ino);
}

SEC("raw_tracepoint/sys_enter")
int trace_close(struct bpf_raw_tracepoint_args *ctx)
{
	struct pt_regs *regs = sys_regs(ctx);
	__u64 a_fd = SYS_ARG1(regs);
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (!is_tracked(tgid))
		return 0;
	release_fd(tgid, (__u32)a_fd);
	return 0;
}

// dup2 and dup3 close newfd when it is open and differs from oldfd. A call
// whose oldfd is not open fails with EBADF and leaves newfd alone, so it is
// skipped.
static __always_inline int dup_over(__u32 oldfd, __u32 newfd)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (!is_tracked(tgid))
		return 0;
	if (oldfd == newfd)
		return 0;
	int res;
	if (!fd_file(oldfd, &res))
		return 0;
	release_fd(tgid, newfd);
	return 0;
}

SEC("raw_tracepoint/sys_enter")
int trace_dup2(struct bpf_raw_tracepoint_args *ctx)
{
	struct pt_regs *regs = sys_regs(ctx);
	__u64 a_oldfd = SYS_ARG1(regs);
	__u64 a_newfd = SYS_ARG2(regs);
	return dup_over((__u32)a_oldfd, (__u32)a_newfd);
}

SEC("raw_tracepoint/sys_enter")
int trace_dup3(struct bpf_raw_tracepoint_args *ctx)
{
	struct pt_regs *regs = sys_regs(ctx);
	__u64 a_oldfd = SYS_ARG1(regs);
	__u64 a_newfd = SYS_ARG2(regs);
	return dup_over((__u32)a_oldfd, (__u32)a_newfd);
}

// --- io_uring (N-25) --------------------------------------------------------
//
// trace_iouring_submit counts the operations a tracked process submits
// through io_uring. The tracepoint fires once per request, in the submitting
// task or in the ring's SQPOLL thread, which belongs to the same thread
// group, so the tgid gate holds for both. It fires before the request runs,
// so a request that later fails is still counted.
//
// An operation is network activity when its opcode only works on sockets, or
// when it moves data (read, write, splice, tee) and its descriptor is a
// socket. A data operation on a registered (fixed) file, or whose descriptor
// cannot be read, is counted too: the probe cannot tell it is not a socket.
// Everything else (file opens, stat, EPOLL_CTL, timeouts, ...) is not. libuv
// in Node.js submits only IORING_OP_EPOLL_CTL, so a Node.js process does not
// count (N-25).

#define IOSQE_FIXED_FILE 1 // bit 0 of the sqe flags, stored in req->flags

static __always_inline int iouring_socket_only_op(__u8 op)
{
	switch (op) {
	case IORING_OP_SENDMSG:
	case IORING_OP_RECVMSG:
	case IORING_OP_ACCEPT:
	case IORING_OP_CONNECT:
	case IORING_OP_SEND:
	case IORING_OP_RECV:
	case IORING_OP_SHUTDOWN:
	case IORING_OP_SOCKET:
	case IORING_OP_SEND_ZC:
	case IORING_OP_SENDMSG_ZC:
	case IORING_OP_BIND:
	case IORING_OP_LISTEN:
	case IORING_OP_RECV_ZC:
		return 1;
	}
	return 0;
}

static __always_inline int iouring_data_op(__u8 op)
{
	switch (op) {
	case IORING_OP_READV:
	case IORING_OP_WRITEV:
	case IORING_OP_READ_FIXED:
	case IORING_OP_WRITE_FIXED:
	case IORING_OP_READ:
	case IORING_OP_WRITE:
	case IORING_OP_SPLICE: // the sqe fd is fd_out
	case IORING_OP_TEE:    // likewise
	case IORING_OP_READ_MULTISHOT:
	case IORING_OP_READV_FIXED:
	case IORING_OP_WRITEV_FIXED:
		return 1;
	}
	return 0;
}

// iouring_target_may_be_socket reports whether the descriptor of request req
// is, or may be, a socket. The descriptor is req->cqe.fd, which io_init_req
// copies from the sqe before this tracepoint fires; the file itself is
// assigned only when the request runs.
static __always_inline int iouring_target_may_be_socket(struct io_kiocb *req)
{
	if (!req || !bpf_core_field_exists(req->cqe.fd) || !bpf_core_field_exists(req->flags))
		return 1;
	__u8 flags = 0; // the low byte of req->flags, whatever its width (little-endian)
	if (bpf_probe_read_kernel(&flags, sizeof(flags),
				  (void *)req + bpf_core_field_offset(req->flags)))
		return 1;
	if (flags & IOSQE_FIXED_FILE)
		return 1; // an index into the ring's registered files
	int fd = -1;
	if (bpf_core_read(&fd, sizeof(fd), &req->cqe.fd))
		return 1;
	if (fd < 0)
		return 0; // the request fails with EBADF
	struct file *f = NULL;
	__u64 ino = 0;
	return fd_socket((__u32)fd, &f, &ino) != FD_NONE;
}

// The raw tracepoint's one argument is the request (TP_PROTO(struct
// io_kiocb *req) from the kernel that introduced the name to at least 7.0).
// Its opcode is read through CO-RE, guarded, so a kernel without struct
// io_kiocb loads the program; the observer then fails to attach it and skips
// it. An opcode that cannot be read counts as a network operation.
SEC("raw_tracepoint/io_uring_submit_req")
int trace_iouring_submit(struct bpf_raw_tracepoint_args *ctx)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (!is_tracked(tgid))
		return 0;
	count_in(&iouring_ops_count);
	struct io_kiocb *req = (struct io_kiocb *)ctx->args[0];
	__u8 op = 0;
	if (!req || !bpf_core_field_exists(req->opcode) ||
	    bpf_core_read(&op, sizeof(op), &req->opcode)) {
		count_in(&iouring_net_count);
		return 0;
	}
	if (iouring_socket_only_op(op) ||
	    (iouring_data_op(op) && iouring_target_may_be_socket(req)))
		count_in(&iouring_net_count);
	return 0;
}

#define CLONE_THREAD 0x10000
#define EEXIST 17

// task_newtask fires in the parent; its arguments are the new task and the
// clone flags.
SEC("raw_tracepoint/task_newtask")
int handle_fork(struct bpf_raw_tracepoint_args *ctx)
{
	// Threads share the tracked tgid; see proc.bpf.c handle_fork.
	if (ctx->args[1] & CLONE_THREAD)
		return 0;

	__u32 parent_pid = bpf_get_current_pid_tgid() >> 32;
	struct task_struct *child = (struct task_struct *)ctx->args[0];
	__u32 child_pid = BPF_CORE_READ(child, pid);

	__u8 *p = bpf_map_lookup_elem(&tracked_pids, &parent_pid);
	if (!p)
		return 0;

	// An entry left for the pid is replaced as before, without counting a
	// second entry.
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

// sched_process_exit fires in the exiting task.
SEC("raw_tracepoint/sched_process_exit")
int handle_exit(struct bpf_raw_tracepoint_args *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 tgid = id >> 32;
	__u32 tid = (__u32)id;

	if (tgid != tid)
		return 0;

	if (!bpf_map_delete_elem(&tracked_pids, &tgid))
		tracked_removed();
	return 0;
}
