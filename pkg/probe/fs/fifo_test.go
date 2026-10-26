package fs

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
	"golang.org/x/sys/unix"
)

// isRegularFD tells a regular file from a named pipe and a directory through
// an O_PATH descriptor, the kind the settle path holds.
func TestIsRegularFD(t *testing.T) {
	dir := t.TempDir()
	reg := filepath.Join(dir, "file")
	if err := os.WriteFile(reg, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "pipe")
	if err := unix.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		path string
		want bool
	}{{reg, true}, {fifo, false}, {dir, false}} {
		fd, err := unix.Open(c.path, unix.O_RDONLY|unix.O_PATH, 0)
		if err != nil {
			t.Fatal(err)
		}
		if got := isRegularFD(fd); got != c.want {
			t.Errorf("isRegularFD(%s) = %v, want %v", c.path, got, c.want)
		}
		_ = unix.Close(fd)
	}
}

// A named pipe written and closed, with no writer left, used to block the
// settle path's reopen for reading, and Stop with it, forever: the pilot of
// 2026-10-26 hung for two hours on a logind inhibitor pipe (P-35). The close
// is recorded without a hash and Stop returns.
func TestObserver_ClosedNamedPipeDoesNotBlockStop(t *testing.T) {
	skipUnprivileged(t)
	dir := t.TempDir()
	fifo := filepath.Join(dir, "pipe")
	if err := unix.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}
	obs := startObserver(t, dir)
	events := make(chan []models.GroundTruthEvent, 1)
	go func() {
		var got []models.GroundTruthEvent
		for e := range obs.Events() {
			got = append(got, e)
		}
		events <- got
	}()

	// A reader holds the pipe open so the writer's open does not block; both
	// close, leaving no writer for a later reopen to wait for.
	r, err := unix.Open(fifo, unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	w, err := os.OpenFile(fifo, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	_ = unix.Close(r)
	time.Sleep(500 * time.Millisecond) // past the settle time

	stopped := make(chan error, 1)
	go func() { stopped <- obs.Stop() }()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatalf("Stop: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Stop did not return within 10 s: the settle path is blocked on the named pipe")
	}
	for _, e := range <-events {
		if e.ActionType == models.FileClose && e.Target == fifo && e.OutputHash != nil {
			t.Errorf("the named pipe's close carries a hash %s, want none", *e.OutputHash)
		}
	}
}
