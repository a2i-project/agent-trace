// Package ktime converts the kernel's bpf_ktime_get_ns() readings to wall
// time on one timeline shared by every probe of the process.
//
// bpf_ktime_get_ns() counts CLOCK_MONOTONIC. The offset to the wall clock is
// taken once per process, from a CLOCK_MONOTONIC read and the wall-clock
// read that follows it, and every probe converts with the same offset, so
// two kernel readings keep their order after conversion whichever probe
// made them. A later step of the wall clock is not followed.
package ktime

import (
	"fmt"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

var (
	once      sync.Once
	offsetNs  int64
	offsetErr error
)

// BootOffsetNs returns the constant such that wallNs = monotonicNs +
// BootOffsetNs for any CLOCK_MONOTONIC reading of this boot. The first call
// measures it; every later call returns the same value.
func BootOffsetNs() (int64, error) {
	once.Do(func() { offsetNs, offsetErr = measure() })
	return offsetNs, offsetErr
}

// measure pairs a CLOCK_MONOTONIC read with a wall-clock read taken
// immediately after.
func measure() (int64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, fmt.Errorf("clock_gettime CLOCK_MONOTONIC: %w", err)
	}
	monoNs := ts.Nano()
	wallNs := time.Now().UnixNano()
	return wallNs - monoNs, nil
}

// Wall converts a kernel reading with an offset BootOffsetNs returned.
func Wall(kernelNs uint64, offsetNs int64) time.Time {
	return time.Unix(0, int64(kernelNs)+offsetNs)
}
