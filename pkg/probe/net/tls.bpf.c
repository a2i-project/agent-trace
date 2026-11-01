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
//
// The same frames come from two further content methods (N-39), selected by
// the agent's profile: tls-openssl-ex hooks OpenSSL's SSL_write_ex and
// SSL_read_ex, whose byte count is read at the return through their pointer
// argument; tls-rustls-aead hooks rustls's AEAD record methods, plaintext at
// encrypt's entry and decrypt's result at its return, on a ring of its own
// (aead_events), and follows the tracked threads' socket syscalls to tell
// userspace which socket each record went to or came from (N-40).
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define SSL_CAP_LEN 16384

#define SSL_DIR_WRITE 0
#define SSL_DIR_READ 1
// A bind record: the rustls encrypter in ssl wrote its records to the socket
// in sock (N-40). It carries no payload.
#define SSL_DIR_BIND 2

// method: who made the frame. SSL_METHOD_SSL is SSL_write and SSL_read or
// their _ex forms, ssl being the SSL*; SSL_METHOD_AEAD is a rustls record,
// ssl being the encrypter or decrypter object.
#define SSL_METHOD_SSL 0
#define SSL_METHOD_AEAD 1

// len is the number of bytes copied into the payload, total the number the
// call wrote or read; total > len means the frame is truncated (the call
// moved more than SSL_CAP_LEN bytes). sock is the inode number of the
// socket a rustls record was read from (the thread's last receive), 0 when
// unknown and on every other frame.
struct ssl_frame_hdr {
	__u64 ts_ns;
	__u64 ssl;
	__u64 sock;
	__u32 tgid;
	__u32 tid;
	__u32 len;
	__u32 total;
	__u32 dir;
	__u32 method;
};

// The payload has twice the room a frame carries, so a copy at an offset
// below SSL_CAP_LEN of at most SSL_CAP_LEN bytes stays inside it, which the
// verifier can prove for the copy of rustls's chunked payloads.
struct ssl_frame {
	struct ssl_frame_hdr hdr;
	__u8 payload[2 * SSL_CAP_LEN];
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
	__u64 readbytes; // SSL_read_ex's size_t *readbytes; 0 for SSL_read
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
	__u64 written; // SSL_write_ex's size_t *written; 0 for SSL_write
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

// ssl_read_counting is set to 1 by userspace once an SSL_read_ex offset
// validated: before that a rejected candidate's byte-count pointer may fault,
// which is not a lost response and is not counted.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} ssl_read_counting SEC(".maps");

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
// once userspace has set ssl_write_counting: ok is whether the call
// succeeded, n the bytes it wrote. Atomic adds, as the other percpu
// counters: a program runs with migration, not preemption, disabled, so two
// tasks can interleave on one CPU.
static __always_inline void count_write(__u64 num, int ok, __u64 n)
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
	if (!ok || n == 0) {
		__sync_fetch_and_add(&st->failed, 1);
		return;
	}
	__sync_fetch_and_add(&st->bytes_written, n);
	if (n < num)
		__sync_fetch_and_add(&st->partial, 1);
}

static __always_inline int flag_on(void *map)
{
	__u32 zero = 0;
	__u32 *on = bpf_map_lookup_elem(map, &zero);
	return on && *on;
}

// emit_frame copies total bytes (at most SSL_CAP_LEN) from buf into a frame
// on ssl_events. A faulting read counts in fault_map and emits nothing
// (N-D5); a full ring counts in drop_map.
static __always_inline void emit_frame(__u64 id, void *buf, __u64 ssl, __u32 total, __u32 dir, void *fault_map, void *drop_map)
{
	__u32 zero = 0;
	struct ssl_frame *e = bpf_map_lookup_elem(&ssl_heap, &zero);
	if (!e)
		return;

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
		count_percpu(fault_map);
		return;
	}

	e->hdr.tgid = id >> 32;
	e->hdr.tid = (__u32)id;
	e->hdr.ts_ns = bpf_ktime_get_ns();
	e->hdr.ssl = ssl;
	e->hdr.sock = 0;
	e->hdr.len = len;
	e->hdr.total = total;
	e->hdr.dir = dir;
	e->hdr.method = SSL_METHOD_SSL;
	if (bpf_ringbuf_output(&ssl_events, e, sizeof(e->hdr) + len, 0))
		count_percpu(drop_map);
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
	count_write(num, ret > 0, ret > 0 ? (__u64)ret : 0);
	if (ret <= 0)
		return 0;

	// SSL_write never returns more than it was asked; a candidate that is
	// another function might, and its frame must not claim more bytes
	// than the buffer it was given.
	__u32 total = (__u32)ret;
	if ((__u64)total > num)
		total = (__u32)num;
	emit_frame(id, buf, ssl, total, SSL_DIR_WRITE, &faulted_reads, &drop_count);
	return 0;
}

// probe_ssl_write_ex attaches at the entry of SSL_write_ex(SSL *s, const
// void *buf, size_t num, size_t *written) for the method tls-openssl-ex
// (N-39) and stashes its arguments: num is RDX as a size_t, written RCX.
SEC("uprobe/ssl_write_ex")
int probe_ssl_write_ex(struct pt_regs *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	if (!is_tracked(id >> 32))
		return 0;
	__u64 num = (__u64)PT_REGS_PARM3(ctx);
	if (num == 0)
		return 0;
	struct ssl_write_arg arg = {
		.buf = (__u64)PT_REGS_PARM2(ctx),
		.ssl = (__u64)PT_REGS_PARM1(ctx),
		.num = num,
		.written = (__u64)PT_REGS_PARM4(ctx),
	};
	bpf_map_update_elem(&ssl_write_args, &id, &arg, BPF_ANY);
	return 0;
}

// probe_ssl_write_ex_return: SSL_write_ex returns 1 with *written the bytes
// written, else 0. The count is read through the pointer stashed at entry;
// a fault there is counted as a faulted read once the offset validated
// (before, a rejected candidate's argument need not be a pointer). The
// frame and the counts then follow SSL_write's (N-36, N-37).
SEC("uretprobe/ssl_write_ex")
int probe_ssl_write_ex_return(struct pt_regs *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	if (!is_tracked(id >> 32))
		return 0;
	struct ssl_write_arg *arg = bpf_map_lookup_elem(&ssl_write_args, &id);
	if (!arg)
		return 0;
	struct ssl_write_arg a = *arg;
	bpf_map_delete_elem(&ssl_write_args, &id);

	int ret = (int)PT_REGS_RC(ctx);
	__u64 n = 0;
	if (ret == 1 && bpf_probe_read_user(&n, sizeof(n), (void *)a.written)) {
		if (flag_on(&ssl_write_counting))
			count_percpu(&faulted_reads);
		return 0;
	}
	count_write(a.num, ret == 1, n);
	if (ret != 1 || n == 0)
		return 0;
	if (n > a.num)
		n = a.num;
	__u32 total = n > 0xffffffffULL ? 0xffffffff : (__u32)n;
	emit_frame(id, (void *)a.buf, a.ssl, total, SSL_DIR_WRITE, &faulted_reads, &drop_count);
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

	// As for SSL_write (N-D5): a faulting read is dropped and counted,
	// never emitted as an empty read.
	emit_frame(id, buf, ssl, (__u32)ret, SSL_DIR_READ, &read_fault_count, &read_drop_count);
	return 0;
}

// probe_ssl_read_ex_entry attaches at SSL_read_ex(SSL *s, void *buf, size_t
// num, size_t *readbytes) for tls-openssl-ex (N-39): readbytes is RCX.
SEC("uprobe/ssl_read_ex")
int probe_ssl_read_ex_entry(struct pt_regs *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	if (!is_tracked(id >> 32))
		return 0;
	struct ssl_read_arg arg = {
		.buf = (__u64)PT_REGS_PARM2(ctx),
		.ssl = (__u64)PT_REGS_PARM1(ctx),
		.readbytes = (__u64)PT_REGS_PARM4(ctx),
	};
	bpf_map_update_elem(&ssl_read_args, &id, &arg, BPF_ANY);
	return 0;
}

// probe_ssl_read_ex_return: a return of 1 has *readbytes bytes in the
// buffer; anything else carries no data. A fault reading the count is
// counted once the read offset validated, as for SSL_write_ex.
SEC("uretprobe/ssl_read_ex")
int probe_ssl_read_ex_return(struct pt_regs *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	if (!is_tracked(id >> 32))
		return 0;
	struct ssl_read_arg *arg = bpf_map_lookup_elem(&ssl_read_args, &id);
	if (!arg)
		return 0;
	struct ssl_read_arg a = *arg;
	bpf_map_delete_elem(&ssl_read_args, &id);

	if ((int)PT_REGS_RC(ctx) != 1)
		return 0;
	__u64 n = 0;
	if (bpf_probe_read_user(&n, sizeof(n), (void *)a.readbytes)) {
		if (flag_on(&ssl_read_counting))
			count_percpu(&read_fault_count);
		return 0;
	}
	if (n == 0)
		return 0;
	__u32 total = n > 0xffffffffULL ? 0xffffffff : (__u32)n;
	emit_frame(id, (void *)a.buf, a.ssl, total, SSL_DIR_READ, &read_fault_count, &read_drop_count);
	return 0;
}

// --- tls-rustls-aead (N-39, N-40) ------------------------------------------
//
// rustls encrypts each record through MessageEncrypter::encrypt(&self,
// msg: OutboundPlainMessage, seq) and decrypts through
// MessageDecrypter::decrypt(&self, msg: InboundOpaqueMessage, seq), both
// returning a Result by hidden pointer, so RDI is the result, RSI self, RDX
// the message (by reference), RCX seq. pkg/tlsoffset finds the methods and
// checks the rustls version is 0.23, whose layouts these offsets are
// (measured, N-38): OutboundPlainMessage holds OutboundChunks at 0 (Single:
// 0, slice pointer at 8, length at 16; Multiple: the chunk slice's pointer
// at 0, its count at 8, start at 16, end at 24) and the ContentType tag at
// 0x20; InboundOpaqueMessage the payload pointer at 0 and length at 8; the
// Ok result the discriminant at 0, the plaintext slice at 8 and 16 and the
// ContentType tag at 0x18. Only application data (tag 3) is captured.

#define AEAD_CT_APPDATA 3
#define AEAD_CHUNKS_MAX 8

// aead_cfg: the Ok discriminant of decrypt's result, and whether the
// locator read one (ok_known); written by userspace before attaching.
struct aead_config {
	__u32 ok_tag;
	__u32 ok_known;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct aead_config);
} aead_cfg SEC(".maps");

// aead_events carries rustls frames and bind records, apart from ssl_events
// so its reader never waits for the SSL_write validation (N-39). 4 MiB;
// userspace shrinks it to one page when the method is not configured.
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22);
} aead_events SEC(".maps");

// aead_drop_count counts frames and bind records aead_events discarded.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} aead_drop_count SEC(".maps");

// aead_dec_args holds a decrypt call's result pointer, self and input
// record from entry to return, by pid and tid (LRU, as ssl_read_args).
struct aead_dec_arg {
	__u64 sret;
	__u64 self;
	__u64 in_ptr;
	__u64 in_len;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);
	__type(value, struct aead_dec_arg);
} aead_dec_args SEC(".maps");

// pending_enc: the encrypter of the latest application record a thread
// encrypted, until that thread's next send names the socket (N-40).
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);
	__type(value, __u64);
} pending_enc SEC(".maps");

// last_recv: the socket inode number of a thread's latest receive.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);
	__type(value, __u64);
} last_recv SEC(".maps");

// aead_bound: the socket each encrypter was last bound to, by tgid and
// encrypter, so a bind record is emitted only when it changes.
struct enc_key {
	__u64 self;
	__u32 tgid;
	__u32 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, struct enc_key);
	__type(value, __u64);
} aead_bound SEC(".maps");

static __always_inline void aead_output(struct ssl_frame *e, __u32 len)
{
	if (bpf_ringbuf_output(&aead_events, e, sizeof(e->hdr) + len, 0))
		count_percpu(&aead_drop_count);
}

static __always_inline void aead_fill(struct ssl_frame *e, __u64 id, __u64 self, __u64 sock, __u32 len, __u32 total, __u32 dir)
{
	e->hdr.tgid = id >> 32;
	e->hdr.tid = (__u32)id;
	e->hdr.ts_ns = bpf_ktime_get_ns();
	e->hdr.ssl = self;
	e->hdr.sock = sock;
	e->hdr.len = len;
	e->hdr.total = total;
	e->hdr.dir = dir;
	e->hdr.method = SSL_METHOD_AEAD;
}

struct outbound_plain {
	__u64 w[4];
	__u8 typ;
};

struct chunk {
	__u64 ptr;
	__u64 len;
};

// probe_aead_encrypt copies the plaintext of an application record at
// encrypt's entry: one slice, or up to AEAD_CHUNKS_MAX chunks of a
// Multiple payload (a vectored write), its [start, end) range. Fewer bytes
// copied than the record holds make a truncated frame. The thread's
// pending_enc names the encrypter for the bind at its next send.
SEC("uprobe/aead_encrypt")
int probe_aead_encrypt(struct pt_regs *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	if (!is_tracked(id >> 32))
		return 0;
	struct outbound_plain m;
	if (bpf_probe_read_user(&m, sizeof(m), (void *)PT_REGS_PARM3(ctx))) {
		count_percpu(&faulted_reads);
		return 0;
	}
	if (m.typ != AEAD_CT_APPDATA)
		return 0;
	__u64 self = (__u64)PT_REGS_PARM2(ctx);

	__u32 zero = 0;
	struct ssl_frame *e = bpf_map_lookup_elem(&ssl_heap, &zero);
	if (!e)
		return 0;

	__u64 total;
	__u32 off = 0;
	if (m.w[0] == 0) {
		total = m.w[2];
		__u32 len = total > SSL_CAP_LEN ? SSL_CAP_LEN : (__u32)total;
		if (bpf_probe_read_user(e->payload, len, (void *)m.w[1])) {
			count_percpu(&faulted_reads);
			return 0;
		}
		off = len;
	} else {
		__u64 chunks = m.w[0], n = m.w[1], start = m.w[2], end = m.w[3];
		total = end > start ? end - start : 0;
		__u64 pos = 0;
		for (int i = 0; i < AEAD_CHUNKS_MAX; i++) {
			if (i >= n || pos >= end || off >= SSL_CAP_LEN)
				break;
			struct chunk c;
			if (bpf_probe_read_user(&c, sizeof(c), (void *)(chunks + i * sizeof(c)))) {
				count_percpu(&faulted_reads);
				return 0;
			}
			__u64 lo = pos > start ? pos : start;
			__u64 hi = pos + c.len < end ? pos + c.len : end;
			pos += c.len;
			if (hi <= lo)
				continue;
			__u64 cnt = hi - lo;
			__u32 o = off & (SSL_CAP_LEN - 1);
			if (cnt > SSL_CAP_LEN - o)
				cnt = SSL_CAP_LEN - o;
			__u32 c32 = (__u32)cnt & (2 * SSL_CAP_LEN - 1);
			if (c32 > SSL_CAP_LEN)
				c32 = SSL_CAP_LEN;
			if (bpf_probe_read_user(&e->payload[o], c32, (void *)(c.ptr + (lo - (pos - c.len))))) {
				count_percpu(&faulted_reads);
				return 0;
			}
			off = o + c32;
		}
	}
	__u32 t32 = total > 0xffffffffULL ? 0xffffffff : (__u32)total;
	if (off > SSL_CAP_LEN)
		off = SSL_CAP_LEN;
	aead_fill(e, id, self, 0, off, t32, SSL_DIR_WRITE);
	aead_output(e, off);
	bpf_map_update_elem(&pending_enc, &id, &self, BPF_ANY);
	return 0;
}

struct inbound_opaque {
	__u64 ptr;
	__u64 len;
};

SEC("uprobe/aead_decrypt")
int probe_aead_decrypt_entry(struct pt_regs *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	if (!is_tracked(id >> 32))
		return 0;
	struct inbound_opaque in;
	if (bpf_probe_read_user(&in, sizeof(in), (void *)PT_REGS_PARM3(ctx)))
		return 0;
	struct aead_dec_arg a = {
		.sret = (__u64)PT_REGS_PARM1(ctx),
		.self = (__u64)PT_REGS_PARM2(ctx),
		.in_ptr = in.ptr,
		.in_len = in.len,
	};
	bpf_map_update_elem(&aead_dec_args, &id, &a, BPF_ANY);
	return 0;
}

struct plain_result {
	__u8 disc;
	__u8 pad[7];
	__u64 ptr;
	__u64 len;
	__u8 typ;
};

// probe_aead_decrypt_return reads decrypt's result: an Ok (when the
// locator read the discriminant) holding application data whose slice lies
// inside the record decrypted in place. Anything else (an error, a
// handshake or alert record) emits nothing. The frame carries the socket
// of the thread's latest receive, which read the record (N-40).
SEC("uretprobe/aead_decrypt")
int probe_aead_decrypt_return(struct pt_regs *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	if (!is_tracked(id >> 32))
		return 0;
	struct aead_dec_arg *ap = bpf_map_lookup_elem(&aead_dec_args, &id);
	if (!ap)
		return 0;
	struct aead_dec_arg a = *ap;
	bpf_map_delete_elem(&aead_dec_args, &id);

	struct plain_result r;
	if (bpf_probe_read_user(&r, sizeof(r), (void *)a.sret))
		return 0;
	__u32 zero = 0;
	struct aead_config *cfg = bpf_map_lookup_elem(&aead_cfg, &zero);
	if (cfg && cfg->ok_known && r.disc != cfg->ok_tag)
		return 0;
	if (r.typ != AEAD_CT_APPDATA || r.ptr < a.in_ptr || r.len > a.in_len || r.ptr - a.in_ptr > a.in_len - r.len)
		return 0;

	struct ssl_frame *e = bpf_map_lookup_elem(&ssl_heap, &zero);
	if (!e)
		return 0;
	__u32 len = r.len > SSL_CAP_LEN ? SSL_CAP_LEN : (__u32)r.len;
	if (bpf_probe_read_user(e->payload, len, (void *)r.ptr)) {
		count_percpu(&read_fault_count);
		return 0;
	}
	__u64 sock = 0;
	__u64 *s = bpf_map_lookup_elem(&last_recv, &id);
	if (s)
		sock = *s;
	aead_fill(e, id, a.self, sock, len, r.len > 0xffffffffULL ? 0xffffffff : (__u32)r.len, SSL_DIR_READ);
	aead_output(e, len);
	return 0;
}

// --- socket following for tls-rustls-aead (N-40) ---------------------------

#define S_IFMT   00170000
#define S_IFSOCK 0140000
#define TS_COMPAT 0x0002

#define NR_read 0
#define NR_write 1
#define NR_readv 19
#define NR_writev 20
#define NR_sendto 44
#define NR_recvfrom 45
#define NR_sendmsg 46
#define NR_recvmsg 47
#define NR_recvmmsg 299
#define NR_sendmmsg 307

// fd_sock_ino returns the socket inode number behind descriptor fd of the
// current task, or 0 when it is not a socket or cannot be read (as
// net.bpf.c's fd_socket, N-24).
static __always_inline __u64 fd_sock_ino(__u32 fd)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct fdtable *fdt = BPF_CORE_READ(task, files, fdt);
	if (!fdt || fd >= BPF_CORE_READ(fdt, max_fds))
		return 0;
	struct file **fds = BPF_CORE_READ(fdt, fd);
	struct file *f = NULL;
	if (!fds || bpf_probe_read_kernel(&f, sizeof(f), &fds[fd]) || !f)
		return 0;
	struct inode *inode = BPF_CORE_READ(f, f_inode);
	if (!inode || (BPF_CORE_READ(inode, i_mode) & S_IFMT) != S_IFSOCK)
		return 0;
	return BPF_CORE_READ(inode, i_ino);
}

// aead_sys_enter follows the receive and send syscalls of tracked threads:
// a receive on a socket becomes the thread's last_recv; the first send on a
// socket after the thread encrypted an application record binds that
// encrypter to the socket, emitted as a bind record when the binding is new
// or changed. Attached only with tls-rustls-aead.
SEC("raw_tracepoint/sys_enter")
int aead_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
	int send;
	switch (ctx->args[1]) {
	case NR_read: case NR_readv: case NR_recvfrom: case NR_recvmsg: case NR_recvmmsg:
		send = 0;
		break;
	case NR_write: case NR_writev: case NR_sendto: case NR_sendmsg: case NR_sendmmsg:
		send = 1;
		break;
	default:
		return 0;
	}
	__u64 id = bpf_get_current_pid_tgid();
	if (!is_tracked(id >> 32))
		return 0;
	if (send && !bpf_map_lookup_elem(&pending_enc, &id))
		return 0;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	if (BPF_CORE_READ(task, thread_info.status) & TS_COMPAT)
		return 0;
	struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
	__u64 ino = fd_sock_ino((__u32)BPF_CORE_READ(regs, di));
	if (!ino)
		return 0;
	if (!send) {
		bpf_map_update_elem(&last_recv, &id, &ino, BPF_ANY);
		return 0;
	}
	__u64 *self = bpf_map_lookup_elem(&pending_enc, &id);
	if (!self)
		return 0;
	struct enc_key k = {.self = *self, .tgid = id >> 32};
	bpf_map_delete_elem(&pending_enc, &id);
	__u64 *bound = bpf_map_lookup_elem(&aead_bound, &k);
	if (bound && *bound == ino)
		return 0;
	bpf_map_update_elem(&aead_bound, &k, &ino, BPF_ANY);

	__u32 zero = 0;
	struct ssl_frame *e = bpf_map_lookup_elem(&ssl_heap, &zero);
	if (!e)
		return 0;
	aead_fill(e, id, k.self, ino, 0, 0, SSL_DIR_BIND);
	aead_output(e, 0);
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
