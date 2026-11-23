package fs

import (
	"encoding/binary"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"

	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/probe/ktime"
)

// Defaults and constants of the kernel clock of the fs records (P-55).
const (
	// DefaultKernelClockRing is the size of the ring that carries the
	// records' kernel times: 32 bytes per event and its ring header.
	DefaultKernelClockRing = 4 << 20
	// kclockCalibrationCount is the count of the one read that tells the
	// kernel program which fanotify group is the probe's. No other read of
	// a fanotify descriptor by the probe uses it.
	kclockCalibrationCount = 4099
	// kclockRingName names the ring in the coverage record's diagnostics.
	kclockRingName = "fs_clock"
)

// Record kinds; they mirror KC_* in kclock.bpf.c.
const (
	kclockInsert = 1
	kclockMerge  = 2
)

// recordStamps is what the kernel clock knows of one fanotify record: the
// event that queued it, and every event that merged into it, each with its
// kernel time.
type recordStamps struct {
	inserted bool
	tgid     uint32
	mask     uint64
	// first is the kernel time of the first event carrying each bit of
	// actionBits, 0 for none.
	first [len(actionBits)]uint64
}

// add records one event of the record.
func (r *recordStamps) add(rec kclockKclockRec) {
	if rec.Kind == kclockInsert {
		r.inserted, r.tgid = true, rec.Tgid
	}
	r.mask |= uint64(rec.Mask)
	for i, bit := range actionBits {
		if uint64(rec.Mask)&bit != 0 && (r.first[i] == 0 || rec.Ts < r.first[i]) {
			r.first[i] = rec.Ts
		}
	}
}

// at returns the kernel time of the first event of the record that action
// type a stands for, and false when no event of the record carries one of
// its bits.
func (r *recordStamps) at(a models.ActionType) (uint64, bool) {
	var t uint64
	for i, bit := range actionBits {
		if r.first[i] == 0 || !actionOf(bit, a) {
			continue
		}
		if t == 0 || r.first[i] < t {
			t = r.first[i]
		}
	}
	return t, t != 0
}

// actionOf reports whether mask bit bit expands to action type a
// (expandMask).
func actionOf(bit uint64, a models.ActionType) bool {
	for _, t := range actionTable[maskIndex(bit)] {
		if t == a {
			return true
		}
	}
	return false
}

// maskIndex is the index into actionTable of mask's actionBits.
func maskIndex(mask uint64) int {
	i := 0
	for b, bit := range actionBits {
		if mask&bit != 0 {
			i |= 1 << b
		}
	}
	return i
}

// stampTable holds the kernel times of the records not yet read, by number.
type stampTable struct {
	pending map[uint64]*recordStamps
	// next is the number of the last record read.
	next uint64
	// stamped counts the records joined to their kernel times; missing
	// those whose queueing event the ring did not deliver; mismatched those
	// whose kernel events did not agree with the record's bits or process.
	stamped, missing, mismatched uint64
}

// add files one ring record.
func (s *stampTable) add(rec kclockKclockRec) {
	if rec.Seq <= s.next {
		return // a record already read: its time was lost to a ring drop
	}
	if s.pending == nil {
		s.pending = map[uint64]*recordStamps{}
	}
	r := s.pending[rec.Seq]
	if r == nil {
		r = &recordStamps{}
		s.pending[rec.Seq] = r
	}
	r.add(rec)
}

// join gives each record of one fanotify read, in the order read, its kernel
// times. The n-th record read is the n-th the kernel numbered. A record
// whose queueing event is missing, or whose events disagree with its mask
// or its process, keeps the read-time clock; the check also catches a
// numbering that has lost its place, which then sends every later record
// to the read-time clock.
func (s *stampTable) join(raw []rawEvent) {
	for i := range raw {
		s.next++
		r := s.pending[s.next]
		delete(s.pending, s.next)
		switch {
		case r == nil || !r.inserted:
			s.missing++
		case r.mask&watchMask != raw[i].Mask&watchMask || (raw[i].PID > 0 && r.tgid != uint32(raw[i].PID)):
			s.mismatched++
		default:
			s.stamped++
			raw[i].Stamps = r
		}
	}
}

// kernelClock owns the loaded programs and the ring of kernel times.
type kernelClock struct {
	objs   kclockObjects
	links  []link.Link
	reader *ringbuf.Reader
	rec    ringbuf.Record
	offset int64
	size   uint64

	mu      sync.Mutex
	table   stampTable
	records uint64
	peak    uint64
}

// kernelClockSupport reports why the kernel clock cannot run on this
// kernel, or "" when it can be tried: the kernel BTF must describe the
// fanotify functions the programs attach to.
func kernelClockSupport() string {
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return "no kernel BTF: " + err.Error()
	}
	for _, fn := range []string{"fanotify_insert_event", "fanotify_should_merge", "fanotify_read", "fanotify_free_event"} {
		var f *btf.Func
		if err := spec.TypeByName(fn, &f); err != nil {
			return "kernel BTF has no " + fn
		}
	}
	return ""
}

// startKernelClock loads and attaches the kernel clock for fanotify group
// fd, which must not be marked yet, and finds the group with one read of
// fd. It returns the reason when it cannot.
func startKernelClock(fd int, ringSize uint64) (*kernelClock, string) {
	if why := kernelClockSupport(); why != "" {
		return nil, why
	}
	offset, err := ktime.BootOffsetNs()
	if err != nil {
		return nil, "boot offset: " + err.Error()
	}
	spec, err := loadKclock()
	if err != nil {
		return nil, "load spec: " + err.Error()
	}
	if err := spec.Variables["probe_tgid"].Set(uint32(os.Getpid())); err != nil {
		return nil, "set probe_tgid: " + err.Error()
	}
	if err := spec.Variables["calibration_count"].Set(uint64(kclockCalibrationCount)); err != nil {
		return nil, "set calibration_count: " + err.Error()
	}
	spec.Maps["kclock_ring"].MaxEntries = uint32(ringSize)
	k := &kernelClock{offset: offset, size: ringSize}
	if err := spec.LoadAndAssign(&k.objs, nil); err != nil {
		return nil, "load: " + err.Error()
	}
	if k.reader, err = ringbuf.NewReader(k.objs.KclockRing); err != nil {
		k.close()
		return nil, "ring reader: " + err.Error()
	}
	for _, p := range []*ebpf.Program{k.objs.KclockCalibrate, k.objs.KclockFree, k.objs.KclockMerge, k.objs.KclockInsert} {
		l, err := link.AttachTracing(link.TracingOptions{Program: p})
		if err != nil {
			k.close()
			return nil, "attach " + p.String() + ": " + err.Error()
		}
		k.links = append(k.links, l)
	}
	if why := k.calibrate(fd); why != "" {
		k.close()
		return nil, why
	}
	return k, ""
}

// calibrate arms the calibration and reads fd once, without blocking, with
// the calibration count; the group is empty, so the read returns EAGAIN
// after the kernel program has recorded which group fd is.
func (k *kernelClock) calibrate(fd int) string {
	var st kclockKclockState
	if err := k.objs.KclockStateMap.Lookup(uint32(0), &st); err != nil {
		return "calibration: " + err.Error()
	}
	st.Armed = 1
	if err := k.objs.KclockStateMap.Update(uint32(0), &st, ebpf.UpdateExist); err != nil {
		return "calibration: " + err.Error()
	}
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		return "calibration: " + err.Error()
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags|unix.O_NONBLOCK); err != nil {
		return "calibration: " + err.Error()
	}
	buf := make([]byte, kclockCalibrationCount)
	_, readErr := unix.Read(fd, buf)
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags); err != nil {
		return "calibration: " + err.Error()
	}
	if readErr != nil && !errors.Is(readErr, unix.EAGAIN) {
		return "calibration read: " + readErr.Error()
	}
	if err := k.objs.KclockStateMap.Lookup(uint32(0), &st); err != nil {
		return "calibration: " + err.Error()
	}
	if st.Group == 0 {
		return "calibration: the read did not reach the kernel program"
	}
	return ""
}

// sync consumes every ring record committed so far. The read loop calls it
// after each fanotify read: every event of the records read was written to
// the ring under the group's lock before the record could be read.
func (k *kernelClock) sync() {
	k.reader.SetDeadline(time.Now())
	for {
		if err := k.reader.ReadInto(&k.rec); err != nil {
			return
		}
		var rec kclockKclockRec
		if len(k.rec.RawSample) < 32 {
			continue
		}
		rec = decodeKclockRec(k.rec.RawSample)
		k.mu.Lock()
		k.records++
		if n := uint64(k.rec.Remaining) + 8 + (uint64(len(k.rec.RawSample))+7)&^7; n > k.peak {
			k.peak = n
		}
		k.table.add(rec)
		k.mu.Unlock()
	}
}

// decodeKclockRec decodes struct kclock_rec in the host's byte order.
func decodeKclockRec(raw []byte) kclockKclockRec {
	le := binary.NativeEndian
	return kclockKclockRec{
		Seq:  le.Uint64(raw[0:]),
		Ts:   le.Uint64(raw[8:]),
		Mask: le.Uint32(raw[16:]),
		Tgid: le.Uint32(raw[20:]),
		Kind: le.Uint32(raw[24:]),
	}
}

// join implements the join for one read (stampTable.join).
func (k *kernelClock) join(raw []rawEvent) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.table.join(raw)
}

// wall converts a kernel time.
func (k *kernelClock) wall(ns uint64) time.Time {
	return ktime.Wall(ns, k.offset)
}

// now reads CLOCK_MONOTONIC and converts it as a kernel time, so the
// read-time stamps of records the join could not time stay on the kernel
// timeline.
func (k *kernelClock) now() time.Time {
	var ts unix.Timespec
	if unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts) != nil {
		return time.Now()
	}
	return k.wall(uint64(ts.Nano()))
}

// stats returns the ring's diagnostics. Drops are kernel times lost, not
// events: their records keep the read-time clock.
func (k *kernelClock) stats() models.RingStats {
	var st kclockKclockState
	_ = k.objs.KclockStateMap.Lookup(uint32(0), &st)
	k.mu.Lock()
	defer k.mu.Unlock()
	return models.RingStats{SizeBytes: k.size, PeakBytes: k.peak, Records: k.records, Drops: st.Drops}
}

// close detaches the programs and releases the maps.
func (k *kernelClock) close() {
	for i := len(k.links) - 1; i >= 0; i-- {
		_ = k.links[i].Close()
	}
	k.links = nil
	if k.reader != nil {
		_ = k.reader.Close()
		k.reader = nil
	}
	_ = k.objs.Close()
}
