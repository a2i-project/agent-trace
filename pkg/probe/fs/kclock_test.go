package fs

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/probe/ktime"
	"golang.org/x/sys/unix"
)

// P-55: the n-th record read is the n-th the kernel numbered. Each record
// takes the events numbered with it, the one that queued it and those that
// merged into it, and an action type takes the time of the first event
// carrying one of its bits.
func TestStampTable_JoinsRecordsByNumber(t *testing.T) {
	var s stampTable
	for _, r := range []kclockKclockRec{
		{Seq: 1, Ts: 100, Mask: unix.FAN_OPEN, Tgid: 7, Kind: kclockInsert},
		{Seq: 2, Ts: 120, Mask: unix.FAN_OPEN, Tgid: 8, Kind: kclockInsert},
		{Seq: 1, Ts: 150, Mask: unix.FAN_MODIFY, Tgid: 7, Kind: kclockMerge},
		{Seq: 1, Ts: 140, Mask: unix.FAN_MODIFY, Tgid: 7, Kind: kclockMerge},
		{Seq: 1, Ts: 200, Mask: unix.FAN_CLOSE_WRITE, Tgid: 7, Kind: kclockMerge},
		{Seq: 3, Ts: 300, Mask: unix.FAN_OPEN, Tgid: 9, Kind: kclockInsert}, // a record not read yet
	} {
		s.add(r)
	}
	raw := []rawEvent{
		{Mask: unix.FAN_OPEN | unix.FAN_MODIFY | unix.FAN_CLOSE_WRITE, PID: 7},
		{Mask: unix.FAN_OPEN, PID: 8},
	}
	s.join(raw)
	if raw[0].Stamps == nil || raw[1].Stamps == nil {
		t.Fatalf("stamps = %v, %v, want both", raw[0].Stamps, raw[1].Stamps)
	}
	for _, c := range []struct {
		a    models.ActionType
		want uint64
	}{{models.FileOpen, 100}, {models.FileWrite, 140}, {models.FileClose, 200}} {
		if got, ok := raw[0].Stamps.at(c.a); !ok || got != c.want {
			t.Errorf("%s at %d (%v), want %d", c.a, got, ok, c.want)
		}
	}
	if _, ok := raw[0].Stamps.at(models.FileDelete); ok {
		t.Error("a delete has a time in a record without one")
	}
	if got, _ := raw[1].Stamps.at(models.FileOpen); got != 120 {
		t.Errorf("the second record's open at %d, want 120", got)
	}
	if s.stamped != 2 || s.missing != 0 || s.mismatched != 0 || len(s.pending) != 1 {
		t.Errorf("stamped %d missing %d mismatched %d pending %d, want 2 0 0 1", s.stamped, s.missing, s.mismatched, len(s.pending))
	}
	// A late event of a record already read was a ring drop's survivor.
	s.add(kclockKclockRec{Seq: 1, Ts: 500, Mask: unix.FAN_MODIFY, Tgid: 7, Kind: kclockMerge})
	if _, ok := s.pending[1]; ok {
		t.Error("an event of a record already read was kept")
	}
}

// A record without the event that queued it (the ring dropped it), or whose
// events disagree with it, keeps the read-time clock. A numbering that lost
// its place disagrees from there on, so it cannot attach another record's
// times.
func TestStampTable_ARecordItsEventsDoNotMatchKeepsTheReadTime(t *testing.T) {
	for _, c := range []struct {
		name                string
		recs                []kclockKclockRec
		raw                 rawEvent
		missing, mismatched uint64
	}{
		{"no queueing event", []kclockKclockRec{{Seq: 1, Ts: 1, Mask: unix.FAN_MODIFY, Tgid: 7, Kind: kclockMerge}},
			rawEvent{Mask: unix.FAN_MODIFY, PID: 7}, 1, 0},
		{"other bits", []kclockKclockRec{{Seq: 1, Ts: 1, Mask: unix.FAN_OPEN, Tgid: 7, Kind: kclockInsert}},
			rawEvent{Mask: unix.FAN_OPEN | unix.FAN_MODIFY, PID: 7}, 0, 1},
		{"another process", []kclockKclockRec{{Seq: 1, Ts: 1, Mask: unix.FAN_OPEN, Tgid: 7, Kind: kclockInsert}},
			rawEvent{Mask: unix.FAN_OPEN, PID: 8}, 0, 1},
		{"no event at all", nil, rawEvent{Mask: unix.FAN_OPEN, PID: 7}, 1, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			var s stampTable
			for _, r := range c.recs {
				s.add(r)
			}
			raw := []rawEvent{c.raw}
			s.join(raw)
			if raw[0].Stamps != nil || s.missing != c.missing || s.mismatched != c.mismatched {
				t.Errorf("stamps %v, missing %d, mismatched %d; want none, %d, %d", raw[0].Stamps, s.missing, s.mismatched, c.missing, c.mismatched)
			}
		})
	}
	// A record whose process the kernel did not name (pid 0) is checked by
	// its bits alone.
	var s stampTable
	s.add(kclockKclockRec{Seq: 1, Ts: 1, Mask: unix.FAN_OPEN, Tgid: 7, Kind: kclockInsert})
	raw := []rawEvent{{Mask: unix.FAN_OPEN}}
	s.join(raw)
	if raw[0].Stamps == nil {
		t.Error("a record with pid 0 was not stamped")
	}
}

// The events of a stamped record carry its kernel times on the shared
// timeline, as points, in causal order (P-13): an open merged after the
// write still comes first, and the write after it by a nanosecond. A close
// goes through the settle window with its kernel time, and a removal held
// for its place keeps its own (P-27). A record without stamps keeps the
// read-time stamp and the batch's bound.
func TestProcessRawEvent_KernelTimesArePointsInCausalOrder(t *testing.T) {
	dir := t.TempDir()
	obs := newHashSeamObserver(t, dir, func(int) (string, error) { return "sha256:x", nil })
	obs.kclockOffset = 1_000_000_000
	bound := time.Unix(5, 0)
	obs.batchNotBefore = bound
	wall := func(k uint64) time.Time { return ktime.Wall(k, obs.kclockOffset) }

	target := filepath.Join(dir, "f.txt")
	r := &recordStamps{}
	r.add(kclockKclockRec{Ts: 300, Mask: unix.FAN_OPEN, Kind: kclockMerge})
	r.add(kclockKclockRec{Ts: 150, Mask: unix.FAN_MODIFY, Kind: kclockInsert})
	r.add(kclockKclockRec{Ts: 400, Mask: unix.FAN_CLOSE_WRITE, Kind: kclockMerge})
	readAt := time.Unix(9, 0)
	obs.processRawEvent(&rawEvent{Mask: unix.FAN_OPEN | unix.FAN_MODIFY | unix.FAN_CLOSE_WRITE, PID: 7, Path: target, Stamps: r}, readAt)
	obs.resolveSettled(obs.settleSnapshot(), hashSeamBuf(), true)

	created := filepath.Join(dir, "gone.txt")
	h := &recordStamps{}
	h.add(kclockKclockRec{Ts: 500, Mask: unix.FAN_CREATE, Kind: kclockInsert})
	h.add(kclockKclockRec{Ts: 900, Mask: unix.FAN_DELETE, Kind: kclockMerge})
	obs.processRawEvent(&rawEvent{Mask: unix.FAN_CREATE | unix.FAN_DELETE, PID: 7, Path: created, Stamps: h}, readAt)
	obs.releaseHeld()

	obs.processRawEvent(&rawEvent{Mask: unix.FAN_OPEN, PID: 8, Path: filepath.Join(dir, "plain.txt")}, readAt)

	got := map[string]models.GroundTruthEvent{}
	for _, e := range drainEvents(obs) {
		got[string(e.ActionType)+" "+filepath.Base(e.Target)] = e
	}
	for key, want := range map[string]time.Time{
		"file_open f.txt":      wall(300),
		"file_write f.txt":     wall(300).Add(time.Nanosecond),
		"file_close f.txt":     wall(400),
		"file_write gone.txt":  wall(500),
		"file_delete gone.txt": wall(900),
	} {
		e, ok := got[key]
		if !ok {
			t.Errorf("no %s among %v", key, keys(got))
			continue
		}
		if !e.Timestamp.Equal(want) || e.NotBefore == nil || !e.NotBefore.Equal(want) {
			t.Errorf("%s at [%v, %v], want the point %v", key, e.NotBefore, e.Timestamp, want)
		}
	}
	plain := got["file_open plain.txt"]
	if !plain.Timestamp.Equal(readAt) || plain.NotBefore == nil || !plain.NotBefore.Equal(bound) {
		t.Errorf("unstamped open at [%v, %v], want [%v, %v]", plain.NotBefore, plain.Timestamp, bound, readAt)
	}
}

func keys(m map[string]models.GroundTruthEvent) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// P-55 as root on a kernel that attaches the kernel clock: every record of a
// rewrite loop, merged or not, is joined to the kernel events numbered with
// it, none is missing or disagrees, and every event of the capture is a
// point. This checks the premise the join rests on, that the probe reads
// the records in the order fanotify_insert_event numbered them.
func TestKernelClock_EveryRecordIsJoined(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	dir := t.TempDir()
	obs, err := New(Config{Path: dir, PathFilter: dir, PIDFilter: int32(os.Getpid()), EventBufSize: 8192, KernelClock: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	obs.Start()
	if running, why := obs.KernelClockState(); !running {
		_ = obs.Stop()
		t.Skipf("the kernel clock cannot run here: %s", why)
	}
	time.Sleep(200 * time.Millisecond)
	for i := 0; i < 200; i++ {
		target := filepath.Join(dir, fmt.Sprintf("f%d", i%7))
		if err := os.WriteFile(target, []byte(fmt.Sprintf("rev %d\n", i)), 0o644); err != nil {
			t.Fatal(err)
		}
		if i%10 == 0 {
			_ = os.Rename(target, target+".moved")
			_ = os.Remove(target + ".moved")
		}
	}
	time.Sleep(500 * time.Millisecond)
	if err := obs.Stop(); err != nil {
		t.Fatal(err)
	}
	n := 0
	for e := range obs.Events() {
		n++
		if e.NotBefore == nil || !e.NotBefore.Equal(e.Timestamp) {
			t.Errorf("%s %s at [%v, %v], want a point", e.ActionType, e.Target, e.NotBefore, e.Timestamp)
		}
	}
	tab := obs.kclock.table
	t.Logf("%d events; records stamped %d, missing %d, mismatched %d", n, tab.stamped, tab.missing, tab.mismatched)
	if tab.stamped == 0 || tab.missing != 0 || tab.mismatched != 0 {
		t.Errorf("records stamped %d, missing %d, mismatched %d; want all stamped", tab.stamped, tab.missing, tab.mismatched)
	}
	if ring := obs.CaptureCoverage().Diagnostics.Rings[kclockRingName]; ring.Records == 0 || ring.Drops != 0 {
		t.Errorf("ring %+v, want records and no drops", ring)
	}
}

// Without the kernel clock the coverage record has no ring for it and the
// probe says so; asked for on a host that cannot run it, the probe runs as
// without it and says why.
func TestObserver_KernelClockOffLeavesTheCoverageAsBefore(t *testing.T) {
	obs := newHashSeamObserver(t, t.TempDir(), nil)
	if cov := obs.CaptureCoverage(); cov.Diagnostics != nil {
		t.Errorf("Diagnostics = %+v, want nil", cov.Diagnostics)
	}
	if running, why := obs.KernelClockState(); running || why != "" {
		t.Errorf("KernelClockState = %v, %q", running, why)
	}
}
