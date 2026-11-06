package fs

import (
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// Every event of a record carries the bound that stood when the record was
// read, also a close emitted after its settle window and a removal held for
// its place (P-52).
func TestProcessRawEvent_EventsCarryTheirRecordsBound(t *testing.T) {
	obs := &Observer{events: make(chan models.GroundTruthEvent, 32), cfg: Config{PathFilter: "/mock"}}
	first := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	later := first.Add(time.Second)
	now := later.Add(time.Second)

	obs.emptyAt = first
	obs.batchNotBefore = obs.emptyAt
	raws := []rawEvent{
		{Mask: unix.FAN_CREATE | unix.FAN_DELETE, PID: 1, Path: "/mock/gone"}, // delete held for its place
		{Mask: unix.FAN_OPEN | unix.FAN_MODIFY | unix.FAN_CLOSE_WRITE, PID: 1, Path: "/mock/a"},
	}
	for i := range raws {
		obs.processRawEvent(&raws[i], now.Add(time.Duration(i)))
	}
	// The queue was found empty again; the next batch has the later bound.
	obs.queueEmpty(later)
	obs.batchNotBefore = obs.emptyAt
	next := rawEvent{Mask: unix.FAN_OPEN, PID: 1, Path: "/mock/b"}
	obs.processRawEvent(&next, now.Add(10))
	obs.releaseHeld()
	obs.resolveSettled(obs.settleSnapshot(), nil, true)
	close(obs.events)

	want := map[string]time.Time{"/mock/gone": first, "/mock/a": first, "/mock/b": later}
	n := 0
	for e := range obs.events {
		n++
		w, ok := want[e.Target]
		if !ok {
			t.Fatalf("unexpected event %s %s", e.ActionType, e.Target)
		}
		if e.NotBefore == nil || !e.NotBefore.Equal(w) {
			t.Errorf("%s %s: NotBefore %v, want %v", e.ActionType, e.Target, e.NotBefore, w)
		}
	}
	if n < 5 {
		t.Errorf("got %d events, want the delete, a's open, write and close, and b's open", n)
	}
}

// An observer built without New holds no bound and claims none.
func TestProcessRawEvent_NoBoundWithoutOne(t *testing.T) {
	obs := &Observer{events: make(chan models.GroundTruthEvent, 4), cfg: Config{PathFilter: "/mock"}}
	obs.queueEmpty(time.Now())
	r := rawEvent{Mask: unix.FAN_OPEN, PID: 1, Path: "/mock/a"}
	obs.processRawEvent(&r, time.Now())
	close(obs.events)
	for e := range obs.events {
		if e.NotBefore != nil {
			t.Errorf("NotBefore %v on an observer with no bound", e.NotBefore)
		}
	}
}

// A slew within the kernel's limit is no step; a larger change is.
func TestClockStep(t *testing.T) {
	cases := []struct {
		mono, wall time.Duration
		step       bool
	}{
		{time.Second, time.Second, false},
		{time.Second, time.Second + 400*time.Microsecond, false}, // 400 ppm slew
		{time.Second, time.Second - 400*time.Microsecond, false},
		{time.Hour, time.Hour + time.Second, false}, // 278 ppm over an hour
		{time.Second, time.Second + 2*time.Millisecond, true},
		{time.Second, time.Second - 2*time.Millisecond, true},
		{time.Millisecond, time.Millisecond + 500*time.Nanosecond, false}, // read jitter
		{time.Minute, 0, true},                                            // stepped back a minute
	}
	for _, c := range cases {
		if got := clockStep(c.mono, c.wall); got != c.step {
			t.Errorf("clockStep(%v, %v) = %v, want %v", c.mono, c.wall, got, c.step)
		}
	}
}
