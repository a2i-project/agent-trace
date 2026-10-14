package fs

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// Item 9 of the security review of 2026-10-08, the close-order half of P-18
// (commit 55bd1da): a close is emitted only after its settle window, and it
// was stamped with its batch's time, so under the verifier's stable sort it
// fell behind every later record of the same batch. An honest write of two
// files back to back then paired the first file's close in the wrong place.
// Each record of a batch is now stamped with the batch's time plus its index,
// in drainNonBlocking. TestProcessRawEvent_RepeatedWritesAndRenamesCollapse
// stamps its records itself, so only a test through the read loop checks the
// stamping. Both files are written after the mark and before Start, so the
// kernel queues every notification and the first read takes them as one batch.
func TestObserver_ACloseKeepsItsPlaceInItsBatch(t *testing.T) {
	skipUnprivileged(t)
	root := t.TempDir()
	ws, files := filepath.Join(root, "ws"), filepath.Join(root, "files")
	for _, d := range []string{ws, files} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	obs, err := New(Config{Path: ws, PIDFilter: int32(os.Getpid()), EventBufSize: 256})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = obs.Stop() }()

	first, second := filepath.Join(files, "first.txt"), filepath.Join(files, "second.txt")
	if err := os.WriteFile(first, []byte("first\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("second\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	obs.Start()
	// CI sets the bound: the closes wait out the settle window on a slow runner.
	events := collectEvents(obs, time.Second)

	sort.SliceStable(events, func(i, j int) bool { return events[i].Timestamp.Before(events[j].Timestamp) })
	closeFirst, firstOfSecond := -1, -1
	for i, e := range events {
		if closeFirst < 0 && e.ActionType == models.FileClose && e.Target == first {
			closeFirst = i
		}
		if firstOfSecond < 0 && e.Target == second {
			firstOfSecond = i
		}
	}
	if closeFirst < 0 || firstOfSecond < 0 {
		t.Fatalf("close of %s at %d, first event of %s at %d: both must be observed", first, closeFirst, second, firstOfSecond)
	}
	if closeFirst > firstOfSecond {
		t.Errorf("after the stable sort by time the close of %s is at %d, behind the first event of %s at %d: a deferred close lost its place in the batch", first, closeFirst, second, firstOfSecond)
		for _, e := range events {
			t.Logf("  %s %s %s", e.Timestamp.Format("15:04:05.000000000"), e.ActionType, e.Target)
		}
	}
}
