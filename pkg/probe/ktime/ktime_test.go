package ktime

import (
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Every call returns the offset of the first, so probes created at
// different times convert on one timeline.
func TestBootOffsetIsTakenOnce(t *testing.T) {
	first, err := BootOffsetNs()
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond)
	for i := 0; i < 3; i++ {
		if got, _ := BootOffsetNs(); got != first {
			t.Fatalf("call %d returned %d, want the first offset %d", i, got, first)
		}
	}
}

// A CLOCK_MONOTONIC reading converts to the wall clock read next to it,
// within the gap between the reads.
func TestWallMatchesTheWallClock(t *testing.T) {
	offset, err := BootOffsetNs()
	if err != nil {
		t.Fatal(err)
	}
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	got := Wall(uint64(ts.Nano()), offset)
	// Generous: the offset is fixed, so slew since the first call shows here.
	if d := now.Sub(got); d < -50*time.Millisecond || d > 50*time.Millisecond {
		t.Errorf("Wall = %v, the wall clock read next to it %v (difference %v)", got, now, d)
	}
	if Wall(10, offset).Sub(Wall(9, offset)) != time.Nanosecond {
		t.Error("readings one nanosecond apart convert more than a nanosecond apart")
	}
}
