package fs

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/content"
	"golang.org/x/sys/unix"
)

// The premise of P-53, on a real kernel and without root: an open with
// O_TRUNC empties the file before its FAN_MODIFY is queued and before the
// open returns its descriptor. The kernel queues the modify at the end of
// the truncation, so for as long as the truncation runs a reader sees an
// empty file, the queue holds no modify, and the opener holds no descriptor
// a writer check could find. A large cached file makes the truncation long
// enough to observe: on kernel 7.0 a 64 MiB file kept the window open for 4
// ms on ext4 and 13 to 19 ms on tmpfs. Each poll reads the size before the
// queue, so a poll that sees the file empty and then no modify in the queue
// saw the window. A short window on a loaded host can be missed, so the test
// tries five times before it fails.
func TestKernelATruncationEmptiesTheFileBeforeItsModifyIsQueued(t *testing.T) {
	if testing.Short() {
		t.Skip("writes a 64 MiB file")
	}
	fd, err := unix.FanotifyInit(uint(unix.FAN_CLASS_NOTIF|reportFlags|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK), unix.O_RDONLY)
	if err != nil {
		t.Skipf("fanotify_init with the probe's flags: %v", err)
	}
	defer func() { _ = unix.Close(fd) }()
	dir := t.TempDir()
	target := filepath.Join(dir, "big")
	if err := unix.FanotifyMark(fd, unix.FAN_MARK_ADD, watchMask|unix.FAN_EVENT_ON_CHILD, unix.AT_FDCWD, dir); err != nil {
		t.Skipf("fanotify_mark: %v", err)
	}
	buf := make([]byte, 64*1024)
	// queued reports whether a record read now carries FAN_MODIFY.
	queued := func() bool {
		modify := false
		for {
			n, err := unix.Read(fd, buf)
			if errors.Is(err, unix.EAGAIN) || n <= 0 {
				return modify
			}
			for _, r := range parseEvents(buf, n, func(fsID, int32, []byte) string { return "" }, nil) {
				modify = modify || r.Mask&unix.FAN_MODIFY != 0
			}
		}
	}
	chunk := make([]byte, 1<<20)
	for i := range chunk {
		chunk[i] = 'x'
	}

	for attempt := 1; attempt <= 5; attempt++ {
		f, err := os.Create(target)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 64; i++ {
			if _, err := f.Write(chunk); err != nil {
				t.Fatal(err)
			}
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		reader, err := unix.Open(target, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		queued()

		var returned atomic.Bool
		go func() {
			if w, err := unix.Open(target, unix.O_WRONLY|unix.O_TRUNC|unix.O_CLOEXEC, 0); err == nil {
				returned.Store(true)
				_ = unix.Close(w)
			}
			returned.Store(true)
		}()
		runtime.LockOSThread()
		window := 0
		modified := false
		for deadline := time.Now().Add(5 * time.Second); !returned.Load() && time.Now().Before(deadline); {
			var st unix.Stat_t
			if unix.Fstat(reader, &st) != nil {
				break
			}
			modified = queued() || modified
			if st.Size == 0 && !modified && !returned.Load() {
				window++
			}
		}
		runtime.UnlockOSThread()
		_ = unix.Close(reader)
		for !returned.Load() {
			time.Sleep(time.Millisecond)
		}
		if window > 0 {
			t.Logf("attempt %d: %d polls saw the file empty with no FAN_MODIFY queued and the open not returned", attempt, window)
			return
		}
	}
	t.Fatal("no poll saw the truncated file before its FAN_MODIFY was queued; P-53's premise does not hold on this kernel")
}

// P-53: the state the window leaves for the settle code. The close's record
// also holds the closing process's next open (P-26), whose truncation has
// emptied the file but has not returned: no descriptor holds the file, no
// later record exists, and the path is quiet. Before P-53 the settle code
// read the empty file and published sha256:e3b0c4..., the hash CI saw. An
// empty read is now never trusted. A non-empty read in the same state keeps
// its hash.
func TestObserver_AnEmptyReadIsNotTrusted(t *testing.T) {
	for _, c := range []struct {
		name     string
		content  string
		wantHash bool
	}{
		{"a truncation in progress", "", false},
		{"content the close left", "rev-1\n", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "rewritten.txt")
			reads := 0
			obs := newHashSeamObserver(t, dir, func(fd int) (string, error) {
				reads++
				return content.SHA256FD(fd)
			})
			obs.writerHolds = openForWriteBy
			if err := os.WriteFile(target, []byte("rev-1\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			obs.processRawEvent(&rawEvent{Mask: unix.FAN_OPEN | unix.FAN_MODIFY | unix.FAN_CLOSE_WRITE, PID: int32(os.Getpid()), Path: target}, time.Now())
			if err := os.Truncate(target, int64(len(c.content))); err != nil {
				t.Fatal(err)
			}
			obs.resolveSettled(obs.settleSnapshot(), hashSeamBuf(), false)
			closes := closeEvents(obs)
			if len(closes) != 1 || (closes[0].OutputHash != nil) != c.wantHash {
				t.Fatalf("closes = %s, want one with a hash: %v", describeCloses(closes), c.wantHash)
			}
			if reads != 1 {
				t.Errorf("the content was read %d time(s), want 1: nothing the probe can see says a write is pending", reads)
			}
			if got, want := obs.CaptureCoverage().HashlessCloses, uint64(map[bool]int{true: 0, false: 1}[c.wantHash]); got != want {
				t.Errorf("HashlessCloses = %d, want %d", got, want)
			}
			if _, ok := obs.shadowHashes[target]; ok != c.wantHash {
				t.Errorf("settled hash kept for later opens: %v, want %v", ok, c.wantHash)
			}
		})
	}
}
