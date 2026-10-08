package fs

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/content"
	"github.com/agent-trace/agent-trace/pkg/models"
	"golang.org/x/sys/unix"
)

func skipUnprivileged(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("requires root or CAP_SYS_ADMIN")
	}
}

// startObserver creates and starts an observer filtered to dir and our PID.
func startObserver(t *testing.T, dir string) *Observer {
	t.Helper()
	obs, err := New(Config{
		Path:         dir,
		PathFilter:   dir,
		PIDFilter:    int32(os.Getpid()),
		EventBufSize: 256,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	obs.Start()
	return obs
}

// collectEvents drains the observer's event channel for the given duration,
// returning all events whose target starts with the given prefix.
func collectEvents(obs *Observer, d time.Duration) []models.GroundTruthEvent {
	var events []models.GroundTruthEvent
	deadline := time.After(d)
	for {
		select {
		case e := <-obs.Events():
			events = append(events, e)
		case <-deadline:
			return events
		}
	}
}

// assertHasEvent checks that at least one event with the given action type
// and target path exists in the slice.
func assertHasEvent(t *testing.T, events []models.GroundTruthEvent, action models.ActionType, target string) {
	t.Helper()
	for _, e := range events {
		if e.ActionType == action && e.Target == target {
			return
		}
	}
	t.Errorf("expected event %s on %s, got %d events:", action, target, len(events))
	for _, e := range events {
		t.Logf("  %s %s", e.ActionType, e.Target)
	}
}

// assertHasEventInDir checks that at least one event with the given action
// type exists and its target is either the exact path or its parent directory.
// On some filesystems (tmpfs), directory events (DELETE, RENAME) resolve
// only to the parent directory because DFID_NAME info records lack the
// filename. On ext4/xfs this resolves to the full path.
//
// It also pins Fix 6 against a real kernel, not a mock: resolveEventPath
// guarantees PathIsAmbiguous is true exactly when the DFID-only fallback (no
// filename) produced the target, and false whenever DFID_NAME or FID
// resolved the full path. Whichever branch this filesystem actually took,
// the flag must agree with it.
func assertHasEventInDir(t *testing.T, events []models.GroundTruthEvent, action models.ActionType, target string) {
	t.Helper()
	dir := filepath.Dir(target)
	for _, e := range events {
		if e.ActionType != action {
			continue
		}
		switch e.Target {
		case target:
			if e.PathIsAmbiguous {
				t.Errorf("%s on %s resolved to the full path but PathIsAmbiguous was true", action, target)
			}
			return
		case dir:
			if !e.PathIsAmbiguous {
				t.Errorf("%s on %s resolved only to parent dir %s but PathIsAmbiguous was false", action, target, dir)
			}
			return
		}
	}
	t.Errorf("expected event %s on %s (or dir %s), got %d events:", action, target, dir, len(events))
	for _, e := range events {
		t.Logf("  %s %s (ambiguous=%v)", e.ActionType, e.Target, e.PathIsAmbiguous)
	}
}

func TestObserver_CreateFile(t *testing.T) {
	skipUnprivileged(t)
	dir := t.TempDir()
	obs := startObserver(t, dir)

	target := filepath.Join(dir, "created.txt")
	if err := os.WriteFile(target, []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}

	events := collectEvents(obs, 500*time.Millisecond)
	_ = obs.Stop()

	assertHasEvent(t, events, models.FileWrite, target)
}

func TestObserver_ModifyFile(t *testing.T) {
	skipUnprivileged(t)
	dir := t.TempDir()

	// Pre-create the file before starting the observer so we only see the modify.
	target := filepath.Join(dir, "modify.txt")
	if err := os.WriteFile(target, []byte("initial"), 0644); err != nil {
		t.Fatal(err)
	}

	obs := startObserver(t, dir)

	if err := os.WriteFile(target, []byte("modified"), 0644); err != nil {
		t.Fatal(err)
	}

	events := collectEvents(obs, 500*time.Millisecond)
	_ = obs.Stop()

	assertHasEvent(t, events, models.FileWrite, target)
}

func TestObserver_CloseWriteIncludesContentHash(t *testing.T) {
	skipUnprivileged(t)
	dir := t.TempDir()
	obs := startObserver(t, dir)

	target := filepath.Join(dir, "hashed.txt")
	if err := os.WriteFile(target, []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	events := collectEvents(obs, 500*time.Millisecond)
	_ = obs.Stop()

	const want = "sha256:5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
	for _, event := range events {
		if event.ActionType != models.FileClose || event.Target != target {
			continue
		}
		if event.OutputHash == nil {
			t.Fatal("FileClose event has no output hash")
		}
		if *event.OutputHash != want {
			t.Errorf("FileClose hash = %q, want %q", *event.OutputHash, want)
		}
		return
	}
	t.Fatalf("no FileClose event for %s", target)
}

// TestObserver_CloseHashSurvivesQuickRename is a regression guard for Fix 5
// round 4's settleQuietWindow: a lone write's FileClose must still capture
// the correct content hash even when the same path is renamed away shortly
// afterward. This is the real shape of cmd/simagent's Tier 4 fixture (write,
// wait 50ms, rename) and the exact scenario that regressed when the settle
// window was widened too far -- the settle window of docs/architecture/12_probe_fs.md. It pins settleQuietWindow's upper bound: window + polling
// latency must stay comfortably under the gap between an agent's distinct
// operations on a path, or the observer never gets a chance to hash before
// the file it was about to hash disappears out from under it.
func TestObserver_CloseHashSurvivesQuickRename(t *testing.T) {
	skipUnprivileged(t)
	dir := t.TempDir()
	obs := startObserver(t, dir)

	target := filepath.Join(dir, "quick.txt")
	data := []byte("hello\n")
	if err := os.WriteFile(target, data, 0o644); err != nil {
		t.Fatal(err)
	}
	want := content.SHA256Bytes(data)

	// The same gap cmd/simagent uses between writing a file and renaming it
	// away (see delay() in cmd/simagent/main.go); the observer must have
	// already hashed the close well before this elapses.
	time.Sleep(40 * time.Millisecond)
	if err := os.Rename(target, filepath.Join(dir, "quick-renamed.txt")); err != nil {
		t.Fatal(err)
	}

	events := collectEvents(obs, 500*time.Millisecond)
	_ = obs.Stop()

	for _, e := range events {
		if e.ActionType != models.FileClose || e.Target != target {
			continue
		}
		if e.OutputHash == nil {
			t.Fatalf("FileClose for %s lost its hash before the rename", target)
		}
		if *e.OutputHash != want {
			t.Errorf("FileClose hash = %q, want %q", *e.OutputHash, want)
		}
		return
	}
	t.Fatalf("no FileClose event for %s", target)
}

func TestObserverIgnoresHashReadOpen(t *testing.T) {
	path := "/mock/dir/hashed.txt"
	observer := &Observer{
		events: make(chan models.GroundTruthEvent, 1),
		cfg: Config{
			PathFilter: "/mock",
		},
		pendingHashOpens: map[string]int{path: 1},
	}

	observer.processRawEvent(&rawEvent{
		Mask: unix.FAN_OPEN,
		PID:  int32(os.Getpid()),
		Path: path,
	}, time.Now())

	if len(observer.pendingHashOpens) != 0 {
		t.Errorf("pending hash opens = %v, want none", observer.pendingHashOpens)
	}
	select {
	case event := <-observer.events:
		t.Errorf("unexpected self-generated event: %#v", event)
	default:
	}
}

// newHashSeamObserver builds an Observer wired for the pure-Go processRawEvent
// path (no kernel), with a controllable content-hash function. hashSettled
// still polls fanotifyFD/stopR (as part of its catch-up drain) even in this
// seam, so those get real, inert pipe fds -- never written to, so poll on
// them always reports "nothing ready" -- rather than the zero value (fd 0,
// i.e. stdin, whose poll behavior isn't something a test should depend on).
func newHashSeamObserver(t *testing.T, dir string, hashFD func(int) (string, error)) *Observer {
	t.Helper()
	var pipeFDs [2]int
	if err := unix.Pipe2(pipeFDs[:], unix.O_CLOEXEC); err != nil {
		t.Fatalf("pipe2: %v", err)
	}
	t.Cleanup(func() {
		_ = unix.Close(pipeFDs[0])
		_ = unix.Close(pipeFDs[1])
	})
	return &Observer{
		fanotifyFD:          pipeFDs[0],
		mountFD:             -1,
		stopR:               pipeFDs[0],
		events:              make(chan models.GroundTruthEvent, 16),
		cfg:                 Config{PathFilter: dir},
		pendingHashOpens:    map[string]int{},
		pathGeneration:      map[string]uint64{},
		shadowHashes:        map[string]string{},
		shadowHashesByInode: map[inodeKey]string{},
		lastWriteAt:         map[string]time.Time{},
		hashFD:              hashFD,
		// settleDelay left zero: these tests drive settleSnapshot/
		// resolveSettled directly and want an immediate resolve.
	}
}

// hashSeamBuf is a scratch read buffer big enough for these tests' synthetic
// drains, which never actually have data to read (see newHashSeamObserver).
func hashSeamBuf() []byte { return make([]byte, 4096) }

func drainEvents(obs *Observer) []models.GroundTruthEvent {
	var out []models.GroundTruthEvent
	for {
		select {
		case e := <-obs.events:
			out = append(out, e)
		default:
			return out
		}
	}
}

// TestObserver_RacedCloseDropsHash pins the Fix 5 TOCTOU behavior: if a second
// write-class event for a path lands while the close's content is being read,
// the digest can't be trusted to reflect the observed close, so the FileClose
// event is emitted with no OutputHash rather than a maybe-wrong one. Hashing
// is synchronous now (see hashSettled), so the mock hashFile itself stands in
// for "a write landed during the read" by bumping the generation as a side
// effect, exactly like a concurrent write's fanotify event would. This
// exercises hashSettled's own narrower check; the close is driven through a
// settle cycle first, exactly as resolveSettled would.
func TestObserver_RacedCloseDropsHash(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "raced.txt")

	var obs *Observer
	obs = newHashSeamObserver(t, dir, func(int) (string, error) {
		obs.processRawEvent(&rawEvent{Mask: unix.FAN_MODIFY, PID: int32(os.Getpid()), Path: target}, time.Now())
		return "sha256:stalehash", nil
	})

	// FAN_CLOSE_WRITE: generation -> 1. The mock hashFile bumps it to 2
	// mid-read, simulating the second write-class event landing while the
	// content was being read.
	obs.processRawEvent(&rawEvent{Mask: unix.FAN_CLOSE_WRITE, PID: int32(os.Getpid()), Path: target}, time.Now())
	before := obs.settleSnapshot()
	obs.resolveSettled(before, hashSeamBuf(), false)

	var closes int
	for _, e := range drainEvents(obs) {
		if e.ActionType != models.FileClose {
			continue
		}
		closes++
		if e.OutputHash != nil {
			t.Errorf("raced FileClose should have no OutputHash, got %q", *e.OutputHash)
		}
	}
	if closes != 1 {
		t.Fatalf("expected exactly 1 FileClose event, got %d", closes)
	}
}

// TestObserver_UnracedCloseKeepsHash is the companion: with nothing writing the
// path again during the hash read, the digest is attached as before.
func TestObserver_UnracedCloseKeepsHash(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "clean.txt")

	obs := newHashSeamObserver(t, dir, func(int) (string, error) {
		return "sha256:goodhash", nil
	})

	obs.processRawEvent(&rawEvent{Mask: unix.FAN_CLOSE_WRITE, PID: int32(os.Getpid()), Path: target}, time.Now())
	before := obs.settleSnapshot()
	obs.resolveSettled(before, hashSeamBuf(), false)

	var got *models.GroundTruthEvent
	for _, e := range drainEvents(obs) {
		if e.ActionType == models.FileClose {
			ev := e
			got = &ev
		}
	}
	if got == nil {
		t.Fatal("no FileClose event emitted")
	}
	if got.OutputHash == nil || *got.OutputHash != "sha256:goodhash" {
		t.Fatalf("unraced FileClose should carry the digest, got %v", got.OutputHash)
	}
}

// TestObserver_BatchedCloseFollowedByWriteHasNoHash covers a close and a bare
// write-class event (no intervening close) for the same path read in one batch,
// both processed before the settle cycle resolves the close. An earlier version
// of the observer folded such an event into the close's generation snapshot and
// hashed the content the file had by then. That content is not what the close
// described, and when the later event is an open the file may be mid-truncate
// (TestObserver_OpenAfterCloseDropsHash), so the close now settles without a
// hash and without a read.
func TestObserver_BatchedCloseFollowedByWriteHasNoHash(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "batched.txt")

	hashCalls := 0
	obs := newHashSeamObserver(t, dir, func(int) (string, error) {
		hashCalls++
		return "sha256:final", nil
	})

	now := time.Now()
	obs.processRawEvent(&rawEvent{Mask: unix.FAN_CLOSE_WRITE, PID: int32(os.Getpid()), Path: target}, now)
	obs.processRawEvent(&rawEvent{Mask: unix.FAN_MODIFY, PID: int32(os.Getpid()), Path: target}, now)

	before := obs.settleSnapshot()
	obs.resolveSettled(before, hashSeamBuf(), false)

	closes := closeEvents(obs)
	if len(closes) != 1 {
		t.Fatalf("expected 1 FileClose, got %d", len(closes))
	}
	if closes[0].OutputHash != nil || hashCalls != 0 {
		t.Fatalf("a close followed by a write in the same batch must settle without a hash or a read, got hash %v after %d read(s)", closes[0].OutputHash, hashCalls)
	}
}

// TestObserver_SupersededCloseNeverHashed pins the actual guarantee behind
// Fix 5's second round: a close is never hashed until it has survived a full
// settle cycle unchanged. If a newer close for the same path arrives first,
// the older one is superseded immediately -- emitted with no hash, without
// ever calling hashFile -- because it provably cannot be the file's final
// content. This is the scenario pathGeneration alone cannot catch: nothing
// races "during" the first close's read because it is never read at all.
func TestObserver_SupersededCloseNeverHashed(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "superseded.txt")

	var hashCalls int
	obs := newHashSeamObserver(t, dir, func(int) (string, error) {
		hashCalls++
		return "sha256:final", nil
	})

	obs.processRawEvent(&rawEvent{Mask: unix.FAN_CLOSE_WRITE, PID: int32(os.Getpid()), Path: target}, time.Now())
	// A second close for the same path arrives before the first is ever
	// judged settled -- superseding it right here, immediately.
	obs.processRawEvent(&rawEvent{Mask: unix.FAN_CLOSE_WRITE, PID: int32(os.Getpid()), Path: target}, time.Now())

	var closes int
	for _, e := range drainEvents(obs) {
		if e.ActionType != models.FileClose {
			continue
		}
		closes++
		if e.OutputHash != nil {
			t.Errorf("superseded FileClose should have no OutputHash, got %q", *e.OutputHash)
		}
	}
	if closes != 1 {
		t.Fatalf("expected exactly 1 (superseded) FileClose event before settling, got %d", closes)
	}
	if hashCalls != 0 {
		t.Errorf("superseded close should never be hashed, got %d hashFile calls", hashCalls)
	}

	// The surviving (second) close settles normally on the next cycle.
	before := obs.settleSnapshot()
	obs.resolveSettled(before, hashSeamBuf(), false)

	var got *models.GroundTruthEvent
	for _, e := range drainEvents(obs) {
		if e.ActionType == models.FileClose {
			ev := e
			got = &ev
		}
	}
	if got == nil {
		t.Fatal("no FileClose event emitted for the surviving close")
	}
	if got.OutputHash == nil || *got.OutputHash != "sha256:final" {
		t.Fatalf("surviving close should carry the digest, got %v", got.OutputHash)
	}
	if hashCalls != 1 {
		t.Errorf("expected exactly 1 hashFile call, got %d", hashCalls)
	}
}

// TestObserver_SupersededCloseAmbiguityFlag pins Fix 6's other half: when a
// close is superseded before it ever settles, the emitted (unhashed) event
// must carry the SUPERSEDED close's own PathIsAmbiguous value, not the
// superseding one's. registerClose reads it off the old pendingClose entry
// before overwriting the map, so a change in ambiguity between the two
// closes must not leak across the supersession in either direction.
func TestObserver_SupersededCloseAmbiguityFlag(t *testing.T) {
	for _, tc := range []struct {
		name            string
		firstAmbiguous  bool
		secondAmbiguous bool
	}{
		{name: "exact superseded by ambiguous", firstAmbiguous: false, secondAmbiguous: true},
		{name: "ambiguous superseded by exact", firstAmbiguous: true, secondAmbiguous: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "superseded.txt")

			obs := newHashSeamObserver(t, dir, func(int) (string, error) {
				return "sha256:final", nil
			})

			obs.processRawEvent(&rawEvent{Mask: unix.FAN_CLOSE_WRITE, PID: int32(os.Getpid()), Path: target, Ambiguous: tc.firstAmbiguous}, time.Now())
			obs.processRawEvent(&rawEvent{Mask: unix.FAN_CLOSE_WRITE, PID: int32(os.Getpid()), Path: target, Ambiguous: tc.secondAmbiguous}, time.Now())

			var got *models.GroundTruthEvent
			for _, e := range drainEvents(obs) {
				if e.ActionType == models.FileClose {
					ev := e
					got = &ev
				}
			}
			if got == nil {
				t.Fatal("expected a superseded FileClose event")
			}
			if got.OutputHash != nil {
				t.Errorf("superseded close should have no OutputHash, got %q", *got.OutputHash)
			}
			if got.PathIsAmbiguous != tc.firstAmbiguous {
				t.Errorf("superseded event PathIsAmbiguous = %v, want %v (the superseded close's own value, not the superseding one's)", got.PathIsAmbiguous, tc.firstAmbiguous)
			}

			// The surviving (second) close settles normally and must carry
			// its own ambiguous value, not the superseded one's.
			before := obs.settleSnapshot()
			obs.resolveSettled(before, hashSeamBuf(), false)

			got = nil
			for _, e := range drainEvents(obs) {
				if e.ActionType == models.FileClose {
					ev := e
					got = &ev
				}
			}
			if got == nil {
				t.Fatal("expected the surviving close to settle")
			}
			if got.PathIsAmbiguous != tc.secondAmbiguous {
				t.Errorf("settled event PathIsAmbiguous = %v, want %v (the surviving close's own value)", got.PathIsAmbiguous, tc.secondAmbiguous)
			}
		})
	}
}

// TestObserver_CloseHeldUntilPathQuiet pins Fix 5 round 4: a FileClose is not
// hashed until its path has gone settleDelay with no further write-class
// event. Surviving one settle cycle is not sufficient -- an intermediate
// close in a write burst kept surviving cycles in round 3 and got hashed
// against content the next write immediately truncated (the CI failure).
// Here the close survives every cycle (nothing supersedes it), yet must not
// be hashed while write-class events keep arriving; only once the path is
// quiet does it settle, and then exactly once. Since the close was followed by
// write-class events the content it described may be gone, so it settles
// without a hash and without a read (see TestObserver_OpenAfterCloseDropsHash);
// the positive case, a quiet path whose close is hashed, is
// TestObserver_CloseOfAQuietPathIsHashedAfterTheWindow.
func TestObserver_CloseHeldUntilPathQuiet(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "burst.txt")

	var hashCalls int
	obs := newHashSeamObserver(t, dir, func(int) (string, error) {
		hashCalls++
		return "sha256:final", nil
	})
	obs.settleDelay = 50 * time.Millisecond

	obs.processRawEvent(&rawEvent{Mask: unix.FAN_CLOSE_WRITE, PID: int32(os.Getpid()), Path: target}, time.Now())

	// Keep the path "busy": each write-class event pushes the quiet deadline
	// out, so no settle cycle in the burst may hash the (still un-superseded)
	// close. Re-stamp immediately before each resolveSettled so a scheduling
	// hiccup can't let settleDelay elapse between them.
	for i := 0; i < 6; i++ {
		obs.processRawEvent(&rawEvent{Mask: unix.FAN_MODIFY, PID: int32(os.Getpid()), Path: target}, time.Now())
		obs.resolveSettled(obs.settleSnapshot(), hashSeamBuf(), false)
		if hashCalls != 0 {
			t.Fatalf("close hashed mid-burst on cycle %d (%d hashFile calls)", i, hashCalls)
		}
	}
	// The FAN_MODIFY events surface as FileWrite; the point is that no
	// FileClose has been emitted yet -- the close is still pending.
	for _, e := range drainEvents(obs) {
		if e.ActionType == models.FileClose {
			t.Fatalf("FileClose emitted during the burst: %#v", e)
		}
	}

	// Path goes quiet: after settleDelay with no new write, the close settles.
	time.Sleep(2 * obs.settleDelay)
	obs.resolveSettled(obs.settleSnapshot(), hashSeamBuf(), false)

	var got *models.GroundTruthEvent
	for _, e := range drainEvents(obs) {
		if e.ActionType == models.FileClose {
			ev := e
			got = &ev
		}
	}
	if got == nil {
		t.Fatal("no FileClose emitted after the path went quiet")
	}
	if got.OutputHash != nil {
		t.Fatalf("a close followed by write-class events must settle without a hash, got %v", *got.OutputHash)
	}
	if hashCalls != 0 {
		t.Errorf("expected no hashFile call, got %d", hashCalls)
	}
}

// The quiet gate on its own: a close with nothing after it is not published
// until its path has been quiet for settleDelay, and then it carries the
// digest, read exactly once.
func TestObserver_CloseOfAQuietPathIsHashedAfterTheWindow(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "quiet.txt")
	var hashCalls int
	obs := newHashSeamObserver(t, dir, func(int) (string, error) {
		hashCalls++
		return "sha256:final", nil
	})
	obs.settleDelay = 50 * time.Millisecond

	obs.processRawEvent(&rawEvent{Mask: unix.FAN_CLOSE_WRITE, PID: int32(os.Getpid()), Path: target}, time.Now())
	obs.resolveSettled(obs.settleSnapshot(), hashSeamBuf(), false)
	if got := closeEvents(obs); len(got) != 0 || hashCalls != 0 {
		t.Fatalf("a close published before its path was quiet: %d event(s), %d read(s)", len(got), hashCalls)
	}

	time.Sleep(2 * obs.settleDelay)
	obs.resolveSettled(obs.settleSnapshot(), hashSeamBuf(), false)
	got := closeEvents(obs)
	if len(got) != 1 || got[0].OutputHash == nil || *got[0].OutputHash != "sha256:final" || hashCalls != 1 {
		t.Fatalf("after the window: events %+v, reads %d, want one hashed close read once", got, hashCalls)
	}
}

func TestObserver_DeleteFile(t *testing.T) {
	skipUnprivileged(t)
	dir := t.TempDir()

	target := filepath.Join(dir, "delete-me.txt")
	if err := os.WriteFile(target, []byte("bye"), 0644); err != nil {
		t.Fatal(err)
	}

	obs := startObserver(t, dir)

	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}

	events := collectEvents(obs, 500*time.Millisecond)
	_ = obs.Stop()

	// On tmpfs, DELETE resolves to the parent directory only (DFID without
	// filename). On ext4/xfs, DFID_NAME provides the full path.
	assertHasEventInDir(t, events, models.FileDelete, target)
}

func TestObserver_RenameFile(t *testing.T) {
	skipUnprivileged(t)
	dir := t.TempDir()

	src := filepath.Join(dir, "old-name.txt")
	dst := filepath.Join(dir, "new-name.txt")
	if err := os.WriteFile(src, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	obs := startObserver(t, dir)

	if err := os.Rename(src, dst); err != nil {
		t.Fatal(err)
	}

	events := collectEvents(obs, 500*time.Millisecond)
	_ = obs.Stop()

	// Rename produces MOVED_FROM (source) and MOVED_TO (destination),
	// both mapped to FileRename. On tmpfs, these resolve to the parent
	// directory only; on ext4/xfs, DFID_NAME gives the full path.
	assertHasEventInDir(t, events, models.FileRename, src)
	assertHasEventInDir(t, events, models.FileRename, dst)
}

// TestObserver_OpenAfterRenameCarriesShadowHash pins the F4.2 rename fix: a
// FAN_OPEN on a file right after it was renamed must still carry the file's
// real content as InputHash, not the empty-file fallback. shadowHashes alone
// can't survive the rename -- it's keyed by the path the file had when it
// was last hashed (here, at Start's pre-cache walk), and the rename's
// FAN_MOVED_FROM/FAN_MOVED_TO events aren't reliably resolvable back to that
// same path (see rawEvent.Ambiguous) -- so this exercises the
// shadowHashesByInode fallback keyed on the file's (device, inode) instead.
func TestObserver_OpenAfterRenameCarriesShadowHash(t *testing.T) {
	skipUnprivileged(t)
	dir := t.TempDir()

	src := filepath.Join(dir, "before-rename.txt")
	dst := filepath.Join(dir, "after-rename.txt")
	data := []byte("carried across rename")
	if err := os.WriteFile(src, data, 0644); err != nil {
		t.Fatal(err)
	}

	// Started only after the file exists, so its hash is populated via
	// Start's pre-cache walk rather than a FAN_CLOSE_WRITE settle -- the
	// same shadowHashes entry a longer-running observer would already have
	// for any file it saw close before this rename.
	obs := startObserver(t, dir)

	if err := os.Rename(src, dst); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(dst)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_, _ = f.Read(buf)
	_ = f.Close()

	events := collectEvents(obs, 500*time.Millisecond)
	_ = obs.Stop()

	wantHash := content.SHA256Bytes(data)
	var found bool
	for _, e := range events {
		if e.ActionType == models.FileOpen && e.Target == dst {
			found = true
			if e.InputHash == nil || *e.InputHash != wantHash {
				t.Errorf("FileOpen InputHash = %v, want %s", e.InputHash, wantHash)
			}
		}
	}
	if !found {
		for _, e := range events {
			t.Logf("  %s %s", e.ActionType, e.Target)
		}
		t.Fatalf("no FileOpen event for %s", dst)
	}
}

func TestObserver_OpenFile(t *testing.T) {
	skipUnprivileged(t)
	dir := t.TempDir()

	target := filepath.Join(dir, "read-me.txt")
	if err := os.WriteFile(target, []byte("contents"), 0644); err != nil {
		t.Fatal(err)
	}

	obs := startObserver(t, dir)

	// Open and read the file (no write).
	f, err := os.Open(target)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_, _ = f.Read(buf)
	_ = f.Close()

	events := collectEvents(obs, 500*time.Millisecond)
	_ = obs.Stop()

	assertHasEvent(t, events, models.FileOpen, target)
}

func TestObserver_StopIsClean(t *testing.T) {
	skipUnprivileged(t)
	dir := t.TempDir()
	obs := startObserver(t, dir)

	// Stop without any file operations.
	if err := obs.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	// Channel should be closed.
	_, ok := <-obs.Events()
	if ok {
		t.Error("expected events channel to be closed")
	}
}

func TestObserver_NoOverflow(t *testing.T) {
	skipUnprivileged(t)
	dir := t.TempDir()
	obs := startObserver(t, dir)

	// Small burst of operations.
	for i := 0; i < 10; i++ {
		_ = os.WriteFile(filepath.Join(dir, "burst.txt"), []byte("x"), 0644)
	}

	collectEvents(obs, 500*time.Millisecond)
	_ = obs.Stop()

	if obs.Overflow() {
		t.Error("unexpected queue overflow on a small burst")
	}
}

// TestDiag_RawFanotify bypasses the Observer to check whether fanotify
// events arrive at all and what their raw contents look like.
func TestDiag_RawFanotify(t *testing.T) {
	skipUnprivileged(t)

	dir := t.TempDir()

	fd, err := initFanotify()
	if err != nil {
		t.Fatalf("initFanotify: %v", err)
	}
	defer func() { _ = unix.Close(fd) }()

	t.Logf("fanotify fd=%d", fd)
	t.Logf("watchMask=0x%x", watchMask)

	if err := markFilesystem(fd, dir, watchMask); err != nil {
		t.Fatalf("markFilesystem: %v", err)
	}

	mountFD, err := openMountFD(dir)
	if err != nil {
		t.Fatalf("openMountFD: %v", err)
	}
	defer func() { _ = unix.Close(mountFD) }()
	t.Logf("mountFD=%d", mountFD)
	// Verify mountFD is valid.
	var st unix.Stat_t
	if err := unix.Fstat(mountFD, &st); err != nil {
		t.Fatalf("mountFD %d fstat failed: %v", mountFD, err)
	}

	// Perform a file operation.
	target := filepath.Join(dir, "diag.txt")
	if err := os.WriteFile(target, []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s, our PID=%d", target, os.Getpid())

	// Give the kernel a moment to queue events.
	time.Sleep(100 * time.Millisecond)

	// Non-blocking read.
	if err := unix.SetNonblock(fd, true); err != nil {
		t.Fatalf("SetNonblock: %v", err)
	}

	buf := make([]byte, 64*1024)
	n, err := unix.Read(fd, buf)
	if err != nil {
		t.Logf("Read error: %v (n=%d)", err, n)
		if n <= 0 {
			t.Fatal("no data from fanotify fd")
		}
	}
	t.Logf("Read %d bytes from fanotify fd", n)

	// Parse and dump raw events.
	offset := 0
	count := 0
	for offset+metadataSize <= n {
		meta := readMetadata(buf[offset:])
		if meta.EventLen < metadataSize || offset+int(meta.EventLen) > n {
			break
		}

		infoStart := offset + int(meta.MetadataLen)
		infoEnd := offset + int(meta.EventLen)
		infoData := buf[infoStart:infoEnd]

		t.Logf("event[%d]: event_len=%d mask=0x%x fd=%d pid=%d info_bytes=%d",
			count, meta.EventLen, meta.Mask, meta.FD, meta.PID, len(infoData))
		if len(infoData) > 0 {
			t.Logf("  info hex: %s", hex.EncodeToString(infoData))
		}

		// Try path resolution.
		path, ambiguous := resolveEventPath(infoData, newKernelResolver(mountsOf(mountFD)))
		t.Logf("  resolved path: %q (ambiguous=%v)", path, ambiguous)

		// Detailed handle resolution debugging for each info record.
		ioff := 0
		for ioff+4 <= len(infoData) {
			iType := infoData[ioff]
			iLen := int(binary.LittleEndian.Uint16(infoData[ioff+2 : ioff+4]))
			if iLen < 4 || ioff+iLen > len(infoData) {
				break
			}
			rec := infoData[ioff : ioff+iLen]
			if len(rec) >= 20 {
				hBytes := int(binary.LittleEndian.Uint32(rec[12:16]))
				hType := int32(binary.LittleEndian.Uint32(rec[16:20]))
				hEnd := 20 + hBytes
				if hEnd <= len(rec) {
					hData := make([]byte, hBytes)
					copy(hData, rec[20:hEnd])
					fh := unix.NewFileHandle(hType, hData)
					rfd, rerr := unix.OpenByHandleAt(mountFD, fh, unix.O_RDONLY|unix.O_PATH)
					if rerr != nil {
						t.Logf("  info[type=%d]: OpenByHandleAt failed: %v", iType, rerr)
					} else {
						link, lerr := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", rfd))
						t.Logf("  info[type=%d]: OpenByHandleAt fd=%d, readlink=%q err=%v", iType, rfd, link, lerr)
						_ = unix.Close(rfd)
					}
				}
			}
			ioff += iLen
		}

		offset += int(meta.EventLen)
		count++
	}
	t.Logf("total events parsed: %d", count)
}

const unixOpenModifyClose = 0x20 | 0x2 | 0x8 // FAN_OPEN | FAN_MODIFY | FAN_CLOSE_WRITE

func TestMaskToActionTypes(t *testing.T) {
	tests := []struct {
		name string
		mask uint64
		want []models.ActionType
	}{
		{"create", 0x100, []models.ActionType{models.FileWrite}},  // FAN_CREATE
		{"delete", 0x200, []models.ActionType{models.FileDelete}}, // FAN_DELETE
		{"modify+close_write merges FileWrite", 0x2 | 0x8, []models.ActionType{models.FileWrite, models.FileClose}},
		// The kernel merges consecutive events on one object. A merged mask has
		// no order, so the expansion must be the causal one: open, write, close.
		{"merged open+modify+close is open, write, close", unixOpenModifyClose, []models.ActionType{models.FileOpen, models.FileWrite, models.FileClose}},
		{"merged open+close is open, close", 0x20 | 0x8, []models.ActionType{models.FileOpen, models.FileClose}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := maskToActionTypes(tt.mask)
			if len(got) != len(tt.want) {
				t.Fatalf("len = %d, want %d; got %v", len(got), len(tt.want), got)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("[%d] = %s, want %s", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestPidOf(t *testing.T) {
	tests := []struct {
		pid  int32
		want uint32
	}{{4242, 4242}, {1, 1}, {0, 0}, {-1, 0}}
	for _, tc := range tests {
		if got := pidOf(&rawEvent{PID: tc.pid}); got != tc.want {
			t.Errorf("pidOf(%d) = %d, want %d (zero means not recorded)", tc.pid, got, tc.want)
		}
	}
}

// Every event the probe emits must carry its own causing PID (V1),
// including a close that is superseded by another process's close: the older
// close keeps the pid that caused it, not the pid of whoever superseded it.
func TestObserver_EventsCarryTheirOwnPID(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "shared.txt")
	obs := newHashSeamObserver(t, dir, func(int) (string, error) { return "sha256:final", nil })

	const pidA, pidB, pidC = 1111, 2222, 3333
	obs.processRawEvent(&rawEvent{Mask: unix.FAN_MODIFY, PID: pidA, Path: target}, time.Now())
	obs.processRawEvent(&rawEvent{Mask: unix.FAN_CLOSE_WRITE, PID: pidA, Path: target}, time.Now())
	obs.processRawEvent(&rawEvent{Mask: unix.FAN_CLOSE_WRITE, PID: pidB, Path: target}, time.Now()) // supersedes A's close
	obs.processRawEvent(&rawEvent{Mask: unix.FAN_DELETE, PID: pidC, Path: target}, time.Now())
	obs.processRawEvent(&rawEvent{Mask: unix.FAN_MODIFY, PID: 0, Path: target}, time.Now()) // kernel-caused
	obs.resolveSettled(obs.settleSnapshot(), hashSeamBuf(), true)

	type seen struct {
		action models.ActionType
		pid    uint32
	}
	var got []seen
	for _, e := range drainEvents(obs) {
		got = append(got, seen{e.ActionType, e.PID})
	}
	want := []seen{
		{models.FileWrite, pidA},
		{models.FileClose, pidA}, // A's close, superseded by B
		{models.FileDelete, pidC},
		{models.FileWrite, 0},
		{models.FileClose, pidB}, // B's close, settled at the end
	}
	if len(got) != len(want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("event %d = %v, want %v", i, got[i], want[i])
		}
	}
}

// A file written by a child process must carry the child's PID, which is what
// lets the verifier attribute the write to the command that caused it. No
// PIDFilter is set, as for a real agent.
func TestObserver_ChildProcessWriteCarriesChildPID(t *testing.T) {
	skipUnprivileged(t)

	dir := t.TempDir()
	obs, err := New(Config{Path: dir, PathFilter: dir, EventBufSize: 256})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	obs.Start()
	time.Sleep(200 * time.Millisecond)

	target := filepath.Join(dir, "child.txt")
	// The shell opens the redirection itself, so the shell's pid causes it.
	cmd := exec.Command("sh", "-c", "echo hi > "+target)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	childPID := uint32(cmd.Process.Pid)
	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait: %v", err)
	}
	events := collectEvents(obs, 1500*time.Millisecond)
	_ = obs.Stop()

	var sawChild bool
	for _, e := range events {
		if e.Target != target {
			continue
		}
		if e.PID == 0 {
			t.Errorf("event %s on %s has no PID", e.ActionType, e.Target)
		}
		if e.PID == childPID {
			sawChild = true
		}
		if e.PID == uint32(os.Getpid()) {
			t.Errorf("event %s on %s attributed to the test process, not the child that wrote it", e.ActionType, e.Target)
		}
	}
	if !sawChild {
		t.Errorf("no event for %s carried the child's pid %d; events: %v", target, childPID, events)
	}
}

// closeEvents returns the FileClose events an observer has emitted.
func closeEvents(obs *Observer) []models.GroundTruthEvent {
	var out []models.GroundTruthEvent
	for _, e := range drainEvents(obs) {
		if e.ActionType == models.FileClose {
			out = append(out, e)
		}
	}
	return out
}

// The hole behind the intermittent empty-content hash: a close is registered,
// then the writer's next iteration opens the file (open with O_TRUNC truncates
// it, and fanotify cannot say which flags an open had), and the writer stalls
// before writing. The path then looks quiet for the whole settle window while
// the file sits empty. The open was seen before the hash read began, so the
// generation did not change during the read, and the empty digest was trusted.
// A write-class event after a close was registered means the content the close
// described may be gone, so the close must be published without a hash.
func TestObserver_OpenAfterCloseDropsHash(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "rewritten.txt")

	hashed := 0
	obs := newHashSeamObserver(t, dir, func(int) (string, error) {
		hashed++
		return "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", nil // the empty file
	})

	obs.processRawEvent(&rawEvent{Mask: unix.FAN_CLOSE_WRITE, PID: 4242, Path: target}, time.Now())
	// The next iteration of the writer opens the file. No close follows yet.
	obs.processRawEvent(&rawEvent{Mask: unix.FAN_OPEN, PID: 4242, Path: target}, time.Now())

	obs.resolveSettled(obs.settleSnapshot(), hashSeamBuf(), false)

	closes := closeEvents(obs)
	if len(closes) != 1 {
		t.Fatalf("expected 1 FileClose, got %d", len(closes))
	}
	if closes[0].OutputHash != nil {
		t.Errorf("a close followed by an open of the same path carried a hash %q: the content it described may have been truncated", *closes[0].OutputHash)
	}
	if hashed != 0 {
		t.Errorf("hashFD ran %d time(s): a read that cannot be trusted should not be made", hashed)
	}
}

// The same holds for a modify after the close.
func TestObserver_ModifyAfterCloseDropsHash(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "f.txt")
	obs := newHashSeamObserver(t, dir, func(int) (string, error) { return "sha256:x", nil })
	obs.processRawEvent(&rawEvent{Mask: unix.FAN_CLOSE_WRITE, PID: 1, Path: target}, time.Now())
	obs.processRawEvent(&rawEvent{Mask: unix.FAN_MODIFY, PID: 1, Path: target}, time.Now())
	obs.resolveSettled(obs.settleSnapshot(), hashSeamBuf(), false)
	closes := closeEvents(obs)
	if len(closes) != 1 || closes[0].OutputHash != nil {
		t.Errorf("closes = %+v, want one without a hash", closes)
	}
}

// What must not change: events on other paths, and events that are not content
// changes (a rename), leave the hash alone, and a close that registers after
// the last write-class event keeps its digest.
func TestObserver_UnrelatedEventsKeepTheHash(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "kept.txt")
	other := filepath.Join(dir, "other.txt")

	obs := newHashSeamObserver(t, dir, func(int) (string, error) { return "sha256:good", nil })
	obs.processRawEvent(&rawEvent{Mask: unix.FAN_CLOSE_WRITE, PID: 1, Path: target}, time.Now())
	obs.processRawEvent(&rawEvent{Mask: unix.FAN_OPEN | unix.FAN_MODIFY, PID: 1, Path: other}, time.Now())
	obs.processRawEvent(&rawEvent{Mask: unix.FAN_MOVED_FROM, PID: 1, Path: target}, time.Now())
	obs.resolveSettled(obs.settleSnapshot(), hashSeamBuf(), false)

	var got *models.GroundTruthEvent
	for _, c := range closeEvents(obs) {
		if c.Target == target {
			ev := c
			got = &ev
		}
	}
	if got == nil || got.OutputHash == nil || *got.OutputHash != "sha256:good" {
		t.Fatalf("close of %s = %+v, want the digest kept", target, got)
	}
}

// A rewrite loop: each iteration is open, write, close. The earlier closes are
// superseded and carry no hash, and the last close, with nothing after it,
// keeps its digest. This is the shape of the e2e raced-rewrite test.
func TestObserver_RewriteLoopHashesOnlyTheLastClose(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "loop.txt")
	obs := newHashSeamObserver(t, dir, func(int) (string, error) { return "sha256:final", nil })
	for i := 0; i < 5; i++ {
		obs.processRawEvent(&rawEvent{Mask: unix.FAN_OPEN, PID: 1, Path: target}, time.Now())
		obs.processRawEvent(&rawEvent{Mask: unix.FAN_MODIFY, PID: 1, Path: target}, time.Now())
		obs.processRawEvent(&rawEvent{Mask: unix.FAN_CLOSE_WRITE, PID: 1, Path: target}, time.Now())
	}
	obs.resolveSettled(obs.settleSnapshot(), hashSeamBuf(), false)

	closes := closeEvents(obs)
	if len(closes) != 5 {
		t.Fatalf("expected 5 FileClose events, got %d", len(closes))
	}
	hashes := 0
	for i, c := range closes {
		if c.OutputHash != nil {
			hashes++
			if i != len(closes)-1 {
				t.Errorf("close %d carried a hash but was not the last", i)
			}
		}
	}
	if hashes != 1 {
		t.Errorf("%d closes carried a hash, want only the last", hashes)
	}
}

func TestParseMountInfo_KeepsRealFilesystemsOnly(t *testing.T) {
	const sample = `25 1 0:23 / /sys rw,nosuid - sysfs sysfs rw
26 1 0:5 / /proc rw - proc proc rw
28 1 259:7 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p7 rw
40 28 0:35 / /tmp rw,nosuid - tmpfs tmpfs rw
41 28 0:36 / /mnt/my\040disk rw - ext4 /dev/sdb1 rw
42 28 0:40 / /snap/core/1 ro - squashfs /dev/loop0 ro
43 28 0:41 / /run/user/1000/gvfs rw - fuse.gvfsd-fuse gvfsd-fuse rw
44 28 0:42 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw
garbage line
`
	got := parseMountInfo(strings.NewReader(sample))
	want := []mountEntry{{"/", "ext4"}, {"/tmp", "tmpfs"}, {"/mnt/my disk", "ext4"}}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %v, want %v", i, got[i], want[i])
		}
	}
}

// With AllFilesystems the observer sees a write on a filesystem other than the
// one holding Config.Path, and resolves its path through that filesystem's
// own mount fd. The test needs a second writable filesystem; it uses the
// first mount point the probe marked whose id differs from the workspace's.
func TestObserver_AllFilesystemsSeesASecondMount(t *testing.T) {
	skipUnprivileged(t)
	dir := t.TempDir()
	obs, err := New(Config{Path: dir, AllFilesystems: true, PIDFilter: int32(os.Getpid()), EventBufSize: 256})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = obs.Stop() }()
	marked, _ := obs.Scope()
	if len(marked) < 2 {
		t.Skipf("only one filesystem marked (%v), need a second one", marked)
	}
	home, _ := fsidOf(dir)
	var other string
	for _, point := range marked {
		id, err := fsidOf(point)
		if err != nil || id == home {
			continue
		}
		if f, err := os.CreateTemp(point, "agent-trace-second-mount-*"); err == nil {
			other = f.Name()
			_ = f.Close()
			break
		}
	}
	if other == "" {
		t.Skip("no writable second filesystem among the marked ones")
	}
	defer func() { _ = os.Remove(other) }()
	obs.Start()
	time.Sleep(50 * time.Millisecond)

	if err := os.WriteFile(other, []byte("elsewhere\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	events := collectEvents(obs, 300*time.Millisecond)
	assertHasEvent(t, events, models.FileWrite, other)
	assertHasEvent(t, events, models.FileClose, other)
	// The file was created after the mark, so its creation yields a first
	// close hashed as empty content; the close of the write carries the
	// content hash, which proves the hash read went through the second
	// filesystem's own mount fd.
	want := content.SHA256Bytes([]byte("elsewhere\n"))
	var hashes []string
	for _, e := range events {
		if e.ActionType == models.FileClose && e.Target == other {
			if e.OutputHash != nil && *e.OutputHash == want {
				return
			}
			if e.OutputHash != nil {
				hashes = append(hashes, *e.OutputHash)
			} else {
				hashes = append(hashes, "<nil>")
			}
		}
	}
	t.Errorf("no close on the second filesystem carries the content hash %s; closes had %v", want, hashes)
}

// mountsOf is the resolver input for a single mount fd: its filesystem id.
func mountsOf(mountFD int) map[fsID]int {
	var st unix.Statfs_t
	if err := unix.Fstatfs(mountFD, &st); err != nil {
		return nil
	}
	return map[fsID]int{{st.Fsid.Val[0], st.Fsid.Val[1]}: mountFD}
}
