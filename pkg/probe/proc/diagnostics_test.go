package proc

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// The meter reads the occupancy before a record as what the ring held after
// it plus the record's header and padded length, and keeps the highest.
func TestRingMeter_ObserveKeepsTheHighWaterMark(t *testing.T) {
	var m ringMeter
	for _, tc := range []struct {
		remaining, length int
		want              uint64
	}{
		{remaining: 0, length: 48, want: 56},
		{remaining: 4096, length: 330, want: 4096 + 8 + 336},
		{remaining: 100, length: 1, want: 4096 + 8 + 336}, // lower: the mark stays
		{remaining: 8000, length: 56, want: 8000 + 8 + 56},
	} {
		m.observe(&ringbuf.Record{RawSample: make([]byte, tc.length), Remaining: tc.remaining})
		if got := m.peak.Load(); got != tc.want {
			t.Errorf("after remaining=%d length=%d: peak = %d, want %d", tc.remaining, tc.length, got, tc.want)
		}
	}
	if got := m.records.Load(); got != 4 {
		t.Errorf("records = %d, want 4", got)
	}
}

// A seeded pid counts in the occupancy at the stop and in the peak, also when
// no insert ever ran in the kernel; a seeded pid that exited leaves live
// below zero and the sum right.
func TestTrackedCounter_CombineAddsTheSeeds(t *testing.T) {
	for _, tc := range []struct {
		name             string
		seeded, seedPeak int64
		live, kernelPeak int64
		wantPeak         uint64
		wantAtStop       int64
	}{
		{name: "nothing", wantPeak: 0, wantAtStop: 0},
		{name: "root only", seeded: 1, seedPeak: 1, wantPeak: 1, wantAtStop: 1},
		{name: "root and children", seeded: 1, seedPeak: 1, live: 3, kernelPeak: 25, wantPeak: 25, wantAtStop: 4},
		{name: "root exited", seeded: 1, seedPeak: 1, live: -1, kernelPeak: 5, wantPeak: 5, wantAtStop: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &trackedCounter{capacity: 16384, seeded: tc.seeded, seedPeak: tc.seedPeak}
			got := c.combine(tc.live, tc.kernelPeak)
			want := models.TrackedSetStats{Capacity: 16384, Peak: tc.wantPeak, AtStop: tc.wantAtStop}
			if got != want {
				t.Errorf("combine = %+v, want %+v", got, want)
			}
		})
	}
}

// BenchmarkRingMeter_Observe is the userspace cost the meter adds to every
// record a probe reads.
func BenchmarkRingMeter_Observe(b *testing.B) {
	var m ringMeter
	rec := ringbuf.Record{RawSample: make([]byte, 330)}
	for i := 0; b.Loop(); i++ {
		rec.Remaining = i & 0xffff
		m.observe(&rec)
	}
}

// execRecordBytes is the ring space of an exec record with argv: the header,
// the 256-byte filename area and the argv strings, padded to 8, plus the
// ring's own header.
func execRecordBytes(argv ...string) uint64 {
	n := binary.Size(bpfEventHdr{}) + 256
	for _, a := range argv {
		n += len(a) + 1
	}
	return ringbufHdrSize + uint64(n+7)&^7
}

// headerRecordBytes is the ring space of a header-only record (fork, exec
// success, exit).
func headerRecordBytes() uint64 {
	return ringbufHdrSize + uint64(binary.Size(bpfEventHdr{})+7)&^7
}

// TestObserver_RingHighWaterMark fills the ring with a known set of records
// before the reader starts, so the first read sees them all: the mark must
// cover at least their bytes. Each run of /bin/true by this process is a
// fork, an exec, an exec success and an exit record (P-34).
func TestObserver_RingHighWaterMark(t *testing.T) {
	skipUnprivileged(t)

	const runs = 10
	nonce := fmt.Sprintf("agenttrace-hwm-%d", time.Now().UnixNano())
	obs, err := New(Config{EventBufSize: 256, DeferRootPID: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := obs.SetRootPID(int32(os.Getpid())); err != nil {
		t.Fatalf("SetRootPID: %v", err)
	}
	for i := 0; i < runs; i++ {
		if err := exec.Command("/bin/true", nonce).Run(); err != nil {
			t.Fatalf("spawn true: %v", err)
		}
	}
	obs.Start()
	if err := obs.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	for range obs.Events() {
	}

	ring := obs.CaptureCoverage().Diagnostics.Rings["events"]
	want := runs * (execRecordBytes("/bin/true", nonce) + 3*headerRecordBytes())
	t.Logf("events ring: %+v, %d bytes of known records", ring, want)
	if ring.PeakBytes < want {
		t.Errorf("PeakBytes = %d, want at least the %d bytes written before the reader started", ring.PeakBytes, want)
	}
	if ring.PeakBytes > ring.SizeBytes {
		t.Errorf("PeakBytes = %d exceeds the ring's %d bytes", ring.PeakBytes, ring.SizeBytes)
	}
	if ring.Records < 4*runs {
		t.Errorf("Records = %d, want at least %d", ring.Records, 4*runs)
	}
	if ring.SizeBytes != 8<<20 || ring.Drops != 0 {
		t.Errorf("SizeBytes = %d, Drops = %d, want 8 MiB and 0", ring.SizeBytes, ring.Drops)
	}
}

// TestObserver_FullRingHighWaterMark overflows a 16 KiB ring before the
// reader starts: the kernel drops records once the ring is full, so the mark
// must sit within one record of the size.
func TestObserver_FullRingHighWaterMark(t *testing.T) {
	skipUnprivileged(t)

	const size = 16 << 10
	nonce := fmt.Sprintf("agenttrace-full-%d", time.Now().UnixNano())
	obs, err := New(Config{EventBufSize: 512, DeferRootPID: true, RingbufBytes: size})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := obs.SetRootPID(int32(os.Getpid())); err != nil {
		t.Fatalf("SetRootPID: %v", err)
	}
	for i := 0; i < 64; i++ {
		if err := exec.Command("/bin/true", nonce).Run(); err != nil {
			t.Fatalf("spawn true: %v", err)
		}
	}
	obs.Start()
	if err := obs.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	for range obs.Events() {
	}

	cov := obs.CaptureCoverage()
	ring := cov.Diagnostics.Rings["events"]
	t.Logf("events ring: %+v", ring)
	if ring.Drops == 0 || ring.Drops != cov.RingbufDrops {
		t.Errorf("Drops = %d, RingbufDrops = %d, want the same non-zero count", ring.Drops, cov.RingbufDrops)
	}
	largest := execRecordBytes("/bin/true", nonce)
	if ring.PeakBytes+largest < size || ring.PeakBytes > size {
		t.Errorf("PeakBytes = %d, want within %d bytes below the ring's %d", ring.PeakBytes, largest, size)
	}
}

// TestObserver_TrackedSetPeak keeps a known number of children alive at once
// and checks the kernel's count against the map itself: the root and 24
// children make a peak of 25, and once they are reaped only the root is left
// (P-34).
func TestObserver_TrackedSetPeak(t *testing.T) {
	skipUnprivileged(t)

	const children = 24
	obs, err := New(Config{EventBufSize: 512, DeferRootPID: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := obs.SetRootPID(int32(os.Getpid())); err != nil {
		t.Fatalf("SetRootPID: %v", err)
	}
	obs.Start()

	var procs []*exec.Cmd
	for i := 0; i < children; i++ {
		c := exec.Command("/bin/sleep", "5")
		if err := c.Start(); err != nil {
			t.Fatalf("spawn sleep: %v", err)
		}
		procs = append(procs, c)
	}
	running := obs.tracked.stats()
	inMap := len(trackedKeys(t, obs))
	for _, c := range procs {
		_ = c.Process.Kill()
		_ = c.Wait()
	}
	// The exit hook runs before the parent's wait returns.
	if err := obs.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	for range obs.Events() {
	}

	if running.AtStop != int64(inMap) || inMap != children+1 {
		t.Errorf("while running: counted %d entries, the map holds %d, want %d", running.AtStop, inMap, children+1)
	}
	got := obs.CaptureCoverage().Diagnostics.TrackedSets["proc"]
	want := models.TrackedSetStats{Capacity: 16384, Peak: children + 1, AtStop: 1}
	if got != want {
		t.Errorf("tracked set = %+v, want %+v", got, want)
	}
}

// BenchmarkObserver_TrackedSpawn times a fork, exec and exit of a tracked
// child with the probe loaded, the path the tracked-set counter adds to.
// Privileged; compare with the same benchmark at an earlier commit.
func BenchmarkObserver_TrackedSpawn(b *testing.B) {
	if os.Getuid() != 0 {
		b.Skip("requires root or CAP_BPF+CAP_PERFMON")
	}
	obs, err := New(Config{EventBufSize: 1 << 16, DeferRootPID: true})
	if err != nil {
		b.Fatalf("New: %v", err)
	}
	if err := obs.SetRootPID(int32(os.Getpid())); err != nil {
		b.Fatalf("SetRootPID: %v", err)
	}
	obs.Start()
	go func() {
		for range obs.Events() {
		}
	}()
	for b.Loop() {
		if err := exec.Command("/bin/true").Run(); err != nil {
			b.Fatalf("spawn true: %v", err)
		}
	}
	b.StopTimer()
	_ = obs.Stop()
}
