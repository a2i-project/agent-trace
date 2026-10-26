package net

import (
	"errors"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// ringbufHdrSize is the kernel's per-record ring buffer header
// (BPF_RINGBUF_HDR_SZ).
const ringbufHdrSize = 8

// ringMeter keeps a ring buffer's high-water mark as the reader sees it
// (P-34, N-33; the same as the proc probe's). The reader samples the ring at every record it takes, from what the
// read already returns, so the kernel does no extra work and userspace no
// extra load. One goroutine writes it; any may read it.
type ringMeter struct {
	peak    atomic.Uint64
	records atomic.Uint64
}

// observe samples the ring at a record just read. Remaining is what the ring
// held after the record, measured against the producer position read for
// it, so the occupancy before it adds the record's header and its length
// rounded up to 8, as the kernel lays it out. A record reserved and not yet
// committed counts, since it holds space the kernel cannot give to another.
func (m *ringMeter) observe(rec *ringbuf.Record) {
	m.records.Add(1)
	n := uint64(rec.Remaining) + ringbufHdrSize + (uint64(len(rec.RawSample))+7)&^7
	if n > m.peak.Load() {
		m.peak.Store(n)
	}
}

// trackedStat is the value of tracked_stat in net.bpf.c and tls.bpf.c.
type trackedStat struct {
	Live int64
	Peak int64
}

// trackedCounter reads the tracked_stat and tracked_seeded maps of one eBPF
// object and adds the pids userspace seeds (P-34). A copy of the proc
// probe's, since each probe package stands alone.
type trackedCounter struct {
	stat, seededMap *ebpf.Map
	capacity        uint32

	mu       sync.Mutex
	seeded   int64 // pids userspace inserted into tracked_pids
	seedPeak int64 // the highest occupancy read back after a seed
	final    *models.TrackedSetStats
}

// seed inserts key into pids and counts it when it is new. A key already
// present is updated in place, as UpdateAny did, and not counted again.
// The count is raised after the insert, so a fork racing with it can only
// read an occupancy one short.
func (c *trackedCounter) seed(pids *ebpf.Map, key, value any) error {
	err := pids.Update(key, value, ebpf.UpdateNoExist)
	if errors.Is(err, ebpf.ErrKeyExist) {
		return pids.Update(key, value, ebpf.UpdateAny)
	}
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seeded++
	var zero uint32
	if err := c.seededMap.Update(&zero, &c.seeded, ebpf.UpdateAny); err != nil {
		return err
	}
	if live, _, err := c.read(); err == nil && live+c.seeded > c.seedPeak {
		c.seedPeak = live + c.seeded
	}
	return nil
}

// read returns the kernel's live count and peak.
func (c *trackedCounter) read() (live, peak int64, err error) {
	var zero uint32
	var s trackedStat
	if err := c.stat.Lookup(&zero, &s); err != nil {
		return 0, 0, err
	}
	return s.Live, s.Peak, nil
}

// stats reports the tracked set: live from the maps while they are open, the
// snapshot after snapshot ran.
func (c *trackedCounter) stats() models.TrackedSetStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.final != nil {
		return *c.final
	}
	s := models.TrackedSetStats{Capacity: c.capacity}
	live, peak, err := c.read()
	if err != nil {
		return s
	}
	return c.combine(live, peak)
}

func (c *trackedCounter) combine(live, peak int64) models.TrackedSetStats {
	p := max(peak, c.seedPeak, 0)
	return models.TrackedSetStats{Capacity: c.capacity, Peak: uint64(p), AtStop: live + c.seeded}
}

// snapshot stores the final values; Stop calls it before closing the maps.
func (c *trackedCounter) snapshot() {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := models.TrackedSetStats{Capacity: c.capacity}
	if live, peak, err := c.read(); err == nil {
		s = c.combine(live, peak)
	}
	c.final = &s
}

// h2ClientPreface is the HTTP/2 client connection preface (RFC 9113, section
// 3.4): the first bytes a client writes on a connection that negotiated h2.
var h2ClientPreface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
