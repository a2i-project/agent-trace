// SPDX-License-Identifier: GPL-2.0
//go:build ignore

// Kernel time of the fs probe's fanotify records (P-55).
//
// fanotify queues a record for the first event of a process on an object and
// merges the later events of that process on that object into it while it is
// unread. fexit/fanotify_insert_event runs once per record the probe's group
// queues, under the group's notification lock and after the record joined the
// queue, so its calls come in queue order: the program numbers them, and the
// n-th record the probe reads is the n-th it numbered. fexit/
// fanotify_should_merge runs when an event merges into an unread record, and
// names the record by its address, which the insert hook mapped to its
// number. Each hook writes the kernel time, the event's mask bits and the
// caller's tgid to a ring buffer; userspace joins them to the records it reads
// by number and checks the bits and the process against the record.
//
// fentry/fanotify_read learns which group is the probe's: the probe makes one
// read of its fanotify descriptor, with the count calibration_count, while
// armed is set, before it marks anything, so every record the group queues is
// numbered. fentry/fanotify_free_event forgets a record once it is read.
//
// These are tracing programs on fanotify's own functions. They need no LSM,
// but the functions are static and a kernel built with them inlined cannot
// attach them; userspace then keeps the read-time clock.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// Record kinds; mirrored by kclockKind* in kclock.go.
#define KC_INSERT 1
#define KC_MERGE  2

// Set by userspace before load.
volatile const __u32 probe_tgid = 0;
volatile const __u64 calibration_count = 0;

struct kclock_rec {
	__u64 seq;  // the record's number, from 1, in queue order
	__u64 ts;   // bpf_ktime_get_ns() at the event
	__u32 mask; // the event's mask bits
	__u32 tgid; // the process the event's hook ran in
	__u32 kind; // KC_INSERT or KC_MERGE
	__u32 pad;
};

struct kclock_state {
	__u64 group; // the probe's struct fsnotify_group, 0 until calibrated
	__u64 seq;   // records numbered so far
	__u64 drops; // ring records that found no room
	__u64 armed; // set by userspace for the calibration read
};

// Keeps kclock_rec in the object's BTF for bpf2go.
const struct kclock_rec *kclock_rec_type __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4 << 20); // userspace may set the size before load
} kclock_ring SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct kclock_state);
} kclock_state_map SEC(".maps");

// The number of every unread record of the group, by its address. A record
// leaves it when fanotify frees it, after the read.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, __u64);
} kclock_seqs SEC(".maps");

static __always_inline struct kclock_state *state(void)
{
	__u32 zero = 0;
	return bpf_map_lookup_elem(&kclock_state_map, &zero);
}

static __always_inline void emit(struct kclock_state *s, __u64 seq, __u32 mask, __u32 kind)
{
	struct kclock_rec *r = bpf_ringbuf_reserve(&kclock_ring, sizeof(*r), 0);
	if (!r) {
		__sync_fetch_and_add(&s->drops, 1);
		return;
	}
	r->seq = seq;
	r->ts = bpf_ktime_get_ns();
	r->mask = mask;
	r->tgid = bpf_get_current_pid_tgid() >> 32;
	r->kind = kind;
	r->pad = 0;
	bpf_ringbuf_submit(r, 0);
}

SEC("fentry/fanotify_read")
int BPF_PROG(kclock_calibrate, struct file *file, char *buf, size_t count)
{
	if ((bpf_get_current_pid_tgid() >> 32) != probe_tgid || count != calibration_count)
		return 0;
	struct kclock_state *s = state();
	if (!s || !s->armed || s->group)
		return 0;
	s->group = (__u64)BPF_CORE_READ(file, private_data);
	s->armed = 0;
	return 0;
}

SEC("fexit/fanotify_insert_event")
int BPF_PROG(kclock_insert, struct fsnotify_group *group, struct fsnotify_event *fsn_event)
{
	struct kclock_state *s = state();
	if (!s || !s->group || s->group != (__u64)group)
		return 0;
	// Calls for the group are serialized by its notification lock, so a
	// plain increment numbers them in queue order.
	__u64 seq = s->seq + 1;
	s->seq = seq;
	__u64 key = (__u64)fsn_event;
	bpf_map_update_elem(&kclock_seqs, &key, &seq, BPF_ANY);
	struct fanotify_event *e = (struct fanotify_event *)fsn_event;
	emit(s, seq, BPF_CORE_READ(e, mask), KC_INSERT);
	return 0;
}

SEC("fexit/fanotify_should_merge")
int BPF_PROG(kclock_merge, struct fanotify_event *old, struct fanotify_event *new, bool ret)
{
	if (!ret)
		return 0;
	__u64 key = (__u64)old;
	__u64 *seq = bpf_map_lookup_elem(&kclock_seqs, &key);
	if (!seq)
		return 0; // another group's record
	struct kclock_state *s = state();
	if (!s)
		return 0;
	emit(s, *seq, BPF_CORE_READ(new, mask), KC_MERGE);
	return 0;
}

SEC("fentry/fanotify_free_event")
int BPF_PROG(kclock_free, struct fsnotify_group *group, struct fsnotify_event *fsn_event)
{
	struct kclock_state *s = state();
	if (!s || s->group != (__u64)group)
		return 0;
	__u64 key = (__u64)fsn_event;
	bpf_map_delete_elem(&kclock_seqs, &key);
	return 0;
}
