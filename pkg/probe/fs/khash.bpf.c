// SPDX-License-Identifier: GPL-2.0
//go:build ignore

// Kernel copy of a written file's content at its last close (P-48).
//
// lsm/file_release runs in __fput after fsnotify_close has queued the
// fanotify close record and before the file gives up its write access. When
// the file is the only one holding write access to its inode, the program
// copies the content, read from the page cache through the file dynptr, into
// a ring buffer record; userspace hashes it. fentry/__fput counts the same
// closes before fsnotify_close, so userspace knows how many records to wait
// for after each fanotify read (P-49). fentry/security_file_open and
// fentry/security_path_truncate bump a counter per inode slot, which tells a
// copy that a new writer began during it.
//
// The file dynptr kfuncs exist from kernel 7.0 and need a trusted file
// pointer, which only the BPF LSM gives at close; userspace loads this object
// only when both are present.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define FMODE_WRITE_BIT  (1U << 1)
#define FMODE_OPENED_BIT (1U << 19)
#define S_IFMT_BITS  00170000
#define S_IFREG_BITS 0100000

// Record status values; mirrored by khashStatus* in khash.go.
#define KH_OK          0
#define KH_WRITER      1 // another file holds write access to the inode
#define KH_TOO_LARGE   2 // the file is larger than the cap
#define KH_NOT_CACHED  3 // a page is not in the page cache
#define KH_RACED       4 // a write access began during the copy
#define KH_NO_RESERVE  5 // the ring had no room for the content
#define KH_ERROR       6 // the file dynptr could not be made

#define EPOCH_SLOTS 4096

// Set by userspace before load.
volatile const __u64 content_cap = 4 << 20;

struct khash_hdr {
	__u64 dev; // super_block.s_dev, the kernel's encoding
	__u64 ino;
	__u64 size; // bytes of content after the header (0 unless KH_OK)
	__u32 tgid;
	__u32 status;
};

struct khash_counts {
	__u64 begun; // closes counted by fentry/__fput
	__u64 lost;  // closes whose record could not be reserved
};

// Keeps khash_hdr in the object's BTF for bpf2go.
const struct khash_hdr *khash_hdr_type __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 32 << 20); // userspace sets the size before load
} khash_ring SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct khash_counts);
} khash_count_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, EPOCH_SLOTS);
	__type(key, __u32);
	__type(value, __u64);
} khash_epoch SEC(".maps");

// The devices (s_dev) of the marked filesystems.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u32);
	__type(value, __u8);
} khash_devs SEC(".maps");

static __always_inline __u32 slot_of(struct inode *inode)
{
	__u64 p = (__u64)inode;
	return (__u32)((p >> 6) ^ (p >> 18)) & (EPOCH_SLOTS - 1);
}

static __always_inline void bump_epoch(struct inode *inode)
{
	__u32 slot = slot_of(inode);
	__u64 *e = bpf_map_lookup_elem(&khash_epoch, &slot);
	if (e)
		__sync_fetch_and_add(e, 1);
}

static __always_inline __u64 read_epoch(__u32 slot)
{
	__u64 *e = bpf_map_lookup_elem(&khash_epoch, &slot);
	if (!e)
		return 0;
	// A fetch-and-add of zero is a fully ordered load.
	return __sync_fetch_and_add(e, 0);
}

// wanted reports whether the close of file is one the probe hashes: an
// opened regular file with write access on a marked filesystem. fentry/__fput
// and lsm/file_release apply the same test, so every close one counts the
// other emits a record for.
static __always_inline struct inode *wanted(struct file *file)
{
	__u32 mode = BPF_CORE_READ(file, f_mode);
	if (!(mode & FMODE_OPENED_BIT) || !(mode & FMODE_WRITE_BIT))
		return NULL;
	struct inode *inode = BPF_CORE_READ(file, f_inode);
	if (!inode)
		return NULL;
	__u16 imode = BPF_CORE_READ(inode, i_mode);
	if ((imode & S_IFMT_BITS) != S_IFREG_BITS)
		return NULL;
	__u32 dev = BPF_CORE_READ(inode, i_sb, s_dev);
	if (!bpf_map_lookup_elem(&khash_devs, &dev))
		return NULL;
	return inode;
}

static __always_inline void count_lost(void)
{
	__u32 zero = 0;
	struct khash_counts *c = bpf_map_lookup_elem(&khash_count_map, &zero);
	if (c)
		__sync_fetch_and_add(&c->lost, 1);
}

// emit_status sends a record without content.
static __always_inline void emit_status(struct khash_hdr *h, __u32 status)
{
	struct khash_hdr *r = bpf_ringbuf_reserve(&khash_ring, sizeof(*r), 0);
	if (!r) {
		count_lost();
		return;
	}
	*r = *h;
	r->size = 0;
	r->status = status;
	bpf_ringbuf_submit(r, 0);
}

SEC("fentry/__fput")
int BPF_PROG(khash_begin, struct file *file)
{
	if (!wanted(file))
		return 0;
	__u32 zero = 0;
	struct khash_counts *c = bpf_map_lookup_elem(&khash_count_map, &zero);
	if (c)
		__sync_fetch_and_add(&c->begun, 1);
	return 0;
}

SEC("fentry/security_file_open")
int BPF_PROG(khash_write_open, struct file *file)
{
	if (!(BPF_CORE_READ(file, f_mode) & FMODE_WRITE_BIT))
		return 0;
	struct inode *inode = BPF_CORE_READ(file, f_inode);
	if (inode)
		bump_epoch(inode);
	return 0;
}

SEC("fentry/security_path_truncate")
int BPF_PROG(khash_truncate, const struct path *path)
{
	struct inode *inode = BPF_CORE_READ(path, dentry, d_inode);
	if (inode)
		bump_epoch(inode);
	return 0;
}

SEC("lsm/file_release")
int BPF_PROG(khash_release, struct file *file)
{
	struct inode *inode = wanted(file);
	if (!inode)
		return 0;

	struct khash_hdr h = {};
	h.dev = BPF_CORE_READ(inode, i_sb, s_dev);
	h.ino = BPF_CORE_READ(inode, i_ino);
	h.tgid = bpf_get_current_pid_tgid() >> 32;

	// The epoch is read before the writer count: a writer whose hook ran
	// before this read already holds write access, which the count sees.
	__u32 slot = slot_of(inode);
	__u64 e0 = read_epoch(slot);
	if (BPF_CORE_READ(inode, i_writecount.counter) != 1) {
		emit_status(&h, KH_WRITER);
		return 0;
	}
	__s64 size = BPF_CORE_READ(inode, i_size);
	if (size < 0 || (__u64)size > content_cap) {
		emit_status(&h, KH_TOO_LARGE);
		return 0;
	}
	if (size == 0) {
		emit_status(&h, KH_OK);
		return 0;
	}

	struct bpf_dynptr rec, src;
	__u32 total = sizeof(h) + (__u32)size;
	if (bpf_ringbuf_reserve_dynptr(&khash_ring, total, 0, &rec)) {
		bpf_ringbuf_discard_dynptr(&rec, 0);
		emit_status(&h, KH_NO_RESERVE);
		return 0;
	}
	__u32 status = KH_OK;
	if (bpf_dynptr_from_file(file, 0, &src))
		status = KH_ERROR;
	else if (bpf_dynptr_copy(&rec, sizeof(h), &src, 0, (__u64)size))
		status = KH_NOT_CACHED;
	bpf_dynptr_file_discard(&src);
	if (status == KH_OK && read_epoch(slot) != e0)
		status = KH_RACED;
	if (status != KH_OK) {
		bpf_ringbuf_discard_dynptr(&rec, 0);
		emit_status(&h, status);
		return 0;
	}
	h.size = (__u64)size;
	h.status = KH_OK;
	bpf_dynptr_write(&rec, 0, &h, sizeof(h), 0);
	bpf_ringbuf_submit_dynptr(&rec, 0);
	return 0;
}
