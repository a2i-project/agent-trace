// SPDX-License-Identifier: GPL-2.0
//go:build ignore

// Uprobe-side half of the Tier 3 network probe. Owns content: the plaintext
// bytes an agent process hands to SSL_write, before BoringSSL encrypts and
// the kernel-side net.bpf.c ever sees them, and the plaintext SSL_read hands
// back after decryption (N-29).
//
// The write-bracket join (an active_write map and a NET_BIND record) is
// abandoned, see N-D1 in docs/decisions/network.md: on Bun, encrypted bytes are queued asynchronously, so the
// write(2)/sendmsg(2) syscalls do not fire inside the SSL_write entry/return
// window. Every captured write is therefore a self-contained ssl_frame;
// correlator.go in userspace parses HTTP directly out of the plaintext and
// attributes it to a connection by Host header, not by a kernel-side join.
// Both directions are captured at the call's return: the entry stashes the
// arguments, the return reads as many bytes as the call returned, so a
// write that failed (and is retried with the same bytes) or wrote part of
// its buffer contributes exactly the bytes it wrote (N-37; SSL_read since
// N-29). Both directions carry the SSL* pointer, which userspace uses to
// keep the streams of one connection together (N-30). The SSL_write return
// also counts, per call, the length asked against the value returned
// (N-36), once userspace has validated the offset.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define SSL_CAP_LEN 16384

#define SSL_DIR_WRITE 0
#define SSL_DIR_READ 1

// len is the number of bytes copied into the payload, total the number the
// call wrote or read; total > len means the frame is truncated (the call
// moved more than SSL_CAP_LEN bytes).
struct ssl_frame_hdr {
	__u64 ts_ns;
	__u64 ssl;
	__u32 tgid;
	__u32 tid;
	__u32 len;
	__u32 total;
	__u32 dir;
	__u32 pad;
};

struct ssl_frame {
	struct ssl_frame_hdr hdr;
	__u8 payload[SSL_CAP_LEN];
};

// Same shape and gating role as net.bpf.c's tracked_pids, and like it this
// object's own map, neither pinned nor shared. net.Observer.TrackPID seeds
// both copies, and each object's fork and exit programs follow descendants.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u8);
} tracked_pids SEC(".maps");

// One ring for both directions, so a response is never read in userspace
// before the request that preceded it on the same thread (N-29). 4 MiB, up
// from 1 MiB when only writes were captured, since responses are the larger
// direction.
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22); // 4 MiB
} ssl_events SEC(".maps");

// ssl_read_args holds the arguments of an SSL_read call in flight, by
// pid_tgid, from its entry to its return. LRU, so an entry whose return
// never fires (the thread exited inside the call) is evicted, not leaked.
struct ssl_read_arg {
	__u64 buf;
	__u64 ssl;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);
	__type(value, struct ssl_read_arg);
} ssl_read_args SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct ssl_frame);
} ssl_heap SEC(".maps");

// ssl_write_args holds the arguments of an SSL_write call in flight, by
// pid_tgid, from its entry to its return (N-36, N-37): the buffer and the
// SSL* for the content, the length asked for the counts. LRU, as
// ssl_read_args.
struct ssl_write_arg {
	__u64 buf;
	__u64 ssl;
	__u64 num;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);
	__type(value, struct ssl_write_arg);
} ssl_write_args SEC(".maps");

// ssl_write_counting is set to 1 by userspace once the SSL_write offset
// validated. Before that the return probe runs at candidates that may be
// other functions, whose returns must not be counted as SSL_write's (N-36).
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} ssl_write_counting SEC(".maps");

// ssl_write_stat counts the SSL_write calls of tracked processes whose
// return the uretprobe saw after the offset validated (N-36): calls,
// partial writes (0 < ret < num), failed writes (ret <= 0, such as SSL_ERROR_WANT_WRITE, after which the
// caller must retry with the same bytes), and the bytes asked and
// written. Userspace sums the percpu slots and snapshots them in Stop().
struct ssl_write_counts {
	__u64 calls;
	__u64 partial;
	__u64 failed;
	__u64 bytes_requested;
	__u64 bytes_written;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct ssl_write_counts);
} ssl_write_stat SEC(".maps");

// faulted_reads counts SSL_write calls whose bpf_probe_read_user failed and
// were therefore dropped without emitting an ssl_frame (see N-D5: a faulting
// read must not read as "empty content" to the
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

// read_fault_count and read_drop_count are the SSL_read counterparts of
// faulted_reads and drop_count. Kept apart because a lost response is a
// content gap on attestation, while a lost request is a lost event (N-29).
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} read_fault_count SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} read_drop_count SEC(".maps");

static __always_inline void count_percpu(void *map)
{
	__u32 zero = 0;
	__u64 *count = bpf_map_lookup_elem(map, &zero);
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

static __always_inline int is_tracked(__u32 tgid)
{
	return bpf_map_lookup_elem(&tracked_pids, &tgid) != NULL;
}

// probe_ssl_write attaches at the entry of SSL_write(SSL *ssl, const void
// *buf, int num) and stashes ssl, buf and num for the return. Per the
// x86_64 System V ABI, ssl is RDI, buf is RSI, num is EDX --
// PT_REGS_PARM1/2/3 below. A length of zero or less is no write.
SEC("uprobe/ssl_write")
int probe_ssl_write(struct pt_regs *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	if (!is_tracked(id >> 32))
		return 0;

	int num = (int)PT_REGS_PARM3(ctx);
	if (num <= 0)
		return 0;

	struct ssl_write_arg arg = {
		.buf = (__u64)PT_REGS_PARM2(ctx),
		.ssl = (__u64)PT_REGS_PARM1(ctx),
		.num = (__u64)num,
	};
	bpf_map_update_elem(&ssl_write_args, &id, &arg, BPF_ANY);
	return 0;
}

// count_write counts one SSL_write call against the length it asked (N-36),
// once userspace has set ssl_write_counting. Atomic adds, as the other
// percpu counters: a program runs with migration, not preemption, disabled,
// so two tasks can interleave on one CPU.
static __always_inline void count_write(__u64 num, int ret)
{
	__u32 zero = 0;
	__u32 *on = bpf_map_lookup_elem(&ssl_write_counting, &zero);
	if (!on || !*on)
		return;
	struct ssl_write_counts *st = bpf_map_lookup_elem(&ssl_write_stat, &zero);
	if (!st)
		return;
	__sync_fetch_and_add(&st->calls, 1);
	__sync_fetch_and_add(&st->bytes_requested, num);
	if (ret <= 0) {
		__sync_fetch_and_add(&st->failed, 1);
		return;
	}
	__sync_fetch_and_add(&st->bytes_written, (__u64)ret);
	if ((__u64)ret < num)
		__sync_fetch_and_add(&st->partial, 1);
}

// probe_ssl_write_return attaches at SSL_write's return. It counts the call
// (N-36) and, when the call returned more than zero, copies that many bytes
// (at most SSL_CAP_LEN) from the buffer stashed at entry into a write frame
// (N-37). A failed call (an error, or SSL_ERROR_WANT_WRITE, after which the
// caller retries with the same bytes) emits nothing, so its bytes enter the
// stream once, at the retry that wrote them. A call whose entry was not
// seen (the probes were attached while it ran) has no stash and is neither
// captured nor counted.
SEC("uretprobe/ssl_write")
int probe_ssl_write_return(struct pt_regs *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 tgid = id >> 32;
	if (!is_tracked(tgid))
		return 0;

	struct ssl_write_arg *arg = bpf_map_lookup_elem(&ssl_write_args, &id);
	if (!arg)
		return 0;
	void *buf = (void *)arg->buf;
	__u64 ssl = arg->ssl;
	__u64 num = arg->num;
	bpf_map_delete_elem(&ssl_write_args, &id);

	int ret = (int)PT_REGS_RC(ctx);
	count_write(num, ret);
	if (ret <= 0)
		return 0;

	// SSL_write never returns more than it was asked; a candidate that is
	// another function might, and its frame must not claim more bytes
	// than the buffer it was given.
	__u32 total = (__u32)ret;
	if ((__u64)total > num)
		total = (__u32)num;

	__u32 zero = 0;
	struct ssl_frame *e = bpf_map_lookup_elem(&ssl_heap, &zero);
	if (!e)
		return 0;

	__u32 len = total;
	if (len > SSL_CAP_LEN)
		len = SSL_CAP_LEN;

	// A faulting read (buffer released or unmapped, bad pointer, or a call
	// shape this probe misidentified -- see N-D4)
	// must not be silently reported as an empty write: the correlator
	// could then read that as "SSL_write happened but carried nothing",
	// which is indistinguishable from a genuine zero-length write. Drop
	// the frame instead; net.Observer's Coverage().FaultedReads counts
	// it so the operator is warned of a potential capture bypass, per
	// N-D5's "warn, don't silently agree" resolution.
	if (bpf_probe_read_user(e->payload, len, buf)) {
		count_percpu(&faulted_reads);
		return 0;
	}

	e->hdr.tgid = tgid;
	e->hdr.tid = (__u32)id;
	e->hdr.ts_ns = bpf_ktime_get_ns();
	e->hdr.ssl = ssl;
	e->hdr.len = len;
	e->hdr.total = total;
	e->hdr.dir = SSL_DIR_WRITE;
	e->hdr.pad = 0;
	if (bpf_ringbuf_output(&ssl_events, e, sizeof(e->hdr) + len, 0))
		count_drop();
	return 0;
}

// probe_ssl_read_entry attaches at the entry of SSL_read(SSL *ssl, void *buf,
// int num) and stashes ssl and buf for the return, where the buffer holds
// the plaintext. The same registers as SSL_write (x86_64 System V).
SEC("uprobe/ssl_read")
int probe_ssl_read_entry(struct pt_regs *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	if (!is_tracked(id >> 32))
		return 0;

	struct ssl_read_arg arg = {
		.buf = (__u64)PT_REGS_PARM2(ctx),
		.ssl = (__u64)PT_REGS_PARM1(ctx),
	};
	bpf_map_update_elem(&ssl_read_args, &id, &arg, BPF_ANY);
	return 0;
}

// probe_ssl_read_return reads, at SSL_read's return, as many bytes as the
// call returned (at most SSL_CAP_LEN) from the buffer stashed at entry. A
// return of zero or less (an error, WANT_READ, a closed connection) carries
// no data and emits nothing.
SEC("uretprobe/ssl_read")
int probe_ssl_read_return(struct pt_regs *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 tgid = id >> 32;
	if (!is_tracked(tgid))
		return 0;

	struct ssl_read_arg *arg = bpf_map_lookup_elem(&ssl_read_args, &id);
	if (!arg)
		return 0;
	void *buf = (void *)arg->buf;
	__u64 ssl = arg->ssl;
	bpf_map_delete_elem(&ssl_read_args, &id);

	int ret = (int)PT_REGS_RC(ctx);
	if (ret <= 0)
		return 0;

	__u32 zero = 0;
	struct ssl_frame *e = bpf_map_lookup_elem(&ssl_heap, &zero);
	if (!e)
		return 0;

	__u32 len = (__u32)ret;
	if (len > SSL_CAP_LEN)
		len = SSL_CAP_LEN;

	// As for SSL_write (N-D5): a faulting read is dropped and counted,
	// never emitted as an empty read.
	if (bpf_probe_read_user(e->payload, len, buf)) {
		count_percpu(&read_fault_count);
		return 0;
	}

	e->hdr.tgid = tgid;
	e->hdr.tid = (__u32)id;
	e->hdr.ts_ns = bpf_ktime_get_ns();
	e->hdr.ssl = ssl;
	e->hdr.len = len;
	e->hdr.total = (__u32)ret;
	e->hdr.dir = SSL_DIR_READ;
	e->hdr.pad = 0;
	if (bpf_ringbuf_output(&ssl_events, e, sizeof(e->hdr) + len, 0))
		count_percpu(&read_drop_count);
	return 0;
}

#define CLONE_THREAD 0x10000
#define EEXIST 17

// The fork and exit hooks are raw tracepoints, whose detach does not wait
// for a grace period (N-32). task_newtask fires in the parent; its arguments
// are the new task and the clone flags.
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
