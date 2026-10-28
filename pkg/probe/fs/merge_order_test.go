package fs

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
	"golang.org/x/sys/unix"
)

// emittedOrder processes raws as one batch, as drainNonBlocking does, ends
// the drain, flushes the pending closes, and returns the events in the order
// cmd/watch writes them: stably sorted by timestamp.
func emittedOrder(t *testing.T, obs *Observer, raws []rawEvent, prefix string) []string {
	t.Helper()
	base := time.Now()
	for i := range raws {
		obs.processRawEvent(&raws[i], base.Add(time.Duration(i)))
	}
	obs.releaseHeld()
	obs.flushPendingCloses(hashSeamBuf())
	events := drainEvents(obs)
	sort.SliceStable(events, func(i, j int) bool { return events[i].Timestamp.Before(events[j].Timestamp) })
	var out []string
	for _, e := range events {
		out = append(out, fmt.Sprintf("%s %s", e.ActionType, strings.TrimPrefix(e.Target, prefix)))
	}
	return out
}

// The kernel's records for operations read late, on a real kernel and
// without root (an inode mark on a directory the test owns), go through the
// probe and come out in the order the operations ran (P-27). Before P-27 a
// write then a rename read late came out as the write, the rename's source,
// the open, write and close, then the destination: the kernel merges the
// moved-from into the unread record of the file's creation, ahead of the
// file's content record. A delete merges the same way. What merging loses
// stays lost: a second moved-to on one name, a creation merged into an
// earlier record of its name.
func TestKernelMergedRemovalsComeOutInOrder(t *testing.T) {
	for _, c := range []struct {
		name string
		run  func(p func(string) string) error
		want []string
	}{
		{"write then rename", func(p func(string) string) error {
			if err := os.WriteFile(p("f1"), []byte("x"), 0o644); err != nil {
				return err
			}
			return os.Rename(p("f1"), p("f2"))
		}, []string{"file_write f1", "file_open f1", "file_write f1", "file_close f1", "file_rename f1", "file_rename f2"}},
		{"two files written then renamed", func(p func(string) string) error {
			for _, step := range []func() error{
				func() error { return os.WriteFile(p("a"), []byte("x"), 0o644) },
				func() error { return os.WriteFile(p("b"), []byte("x"), 0o644) },
				func() error { return os.Rename(p("a"), p("a2")) },
				func() error { return os.Rename(p("b"), p("b2")) },
			} {
				if err := step(); err != nil {
					return err
				}
			}
			return nil
		}, []string{
			"file_write a", "file_open a", "file_write a", "file_close a",
			"file_write b", "file_open b", "file_write b", "file_close b",
			"file_rename a", "file_rename a2", "file_rename b", "file_rename b2",
		}},
		{"write then delete", func(p func(string) string) error {
			if err := os.WriteFile(p("t"), []byte("x"), 0o644); err != nil {
				return err
			}
			return os.Remove(p("t"))
		}, []string{"file_write t", "file_open t", "file_write t", "file_close t", "file_delete t"}},
		{"two replaces of one target", func(p func(string) string) error {
			for _, step := range []func() error{
				func() error { return os.WriteFile(p("t1"), []byte("x"), 0o644) },
				func() error { return os.Rename(p("t1"), p("T")) },
				func() error { return os.WriteFile(p("t2"), []byte("y"), 0o644) },
				func() error { return os.Rename(p("t2"), p("T")) },
			} {
				if err := step(); err != nil {
					return err
				}
			}
			return nil
		}, []string{
			"file_write t1", "file_open t1", "file_write t1", "file_close t1", "file_rename t1", "file_rename T",
			"file_write t2", "file_open t2", "file_write t2", "file_close t2", "file_rename t2",
		}},
		{"a name renamed away and created again", func(p func(string) string) error {
			for _, step := range []func() error{
				func() error { return os.WriteFile(p("P"), []byte("x"), 0o644) },
				func() error { return os.Rename(p("P"), p("Q")) },
				func() error { return os.WriteFile(p("P"), []byte("y"), 0o644) },
			} {
				if err := step(); err != nil {
					return err
				}
			}
			return nil
		}, []string{
			"file_write P", "file_open P", "file_write P", "file_close P", "file_rename P", "file_rename Q",
			"file_open P", "file_write P", "file_close P",
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir, raws := readKernelBatch(t, nil, c.run)
			for _, r := range raws {
				t.Logf("record %#x %s", r.Mask, strings.TrimPrefix(r.Path, dir+"/"))
			}
			obs := newHashSeamObserver(t, dir, func(int) (string, error) { return "sha256:x", nil })
			obs.events = make(chan models.GroundTruthEvent, 64)
			obs.fileAt = func(e *rawEvent) string { return fileByHandle(dir, e) }
			got := emittedOrder(t, obs, raws, dir+"/")
			if strings.Join(got, "|") != strings.Join(c.want, "|") {
				t.Errorf("emitted\n  %v\nwant\n  %v\nfrom %d records", got, c.want, len(raws))
			}
		})
	}
}

// The rules on synthetic records (P-27): a moved-from emitted in place takes
// the next moved-to of its process, so a held one waits for the one after; a
// held delete floats only past content records of a file that has left its
// name; a held removal with no record to mark its place is emitted at the end
// of the drain; a moved-from or delete that is not merged with a creation is
// emitted in place, as before.
func TestProcessRawEvent_HeldRemovals(t *testing.T) {
	const (
		create  = unix.FAN_CREATE
		from    = unix.FAN_MOVED_FROM
		to      = unix.FAN_MOVED_TO
		del     = unix.FAN_DELETE
		content = unix.FAN_OPEN | unix.FAN_MODIFY
	)
	for _, c := range []struct {
		name       string
		raws       []rawEvent
		stillThere bool
		want       []string
	}{
		{"a rename in place between", []rawEvent{
			{Mask: create | from, PID: 1, Path: "/mock/P"},
			{Mask: content, PID: 1, Path: "/mock/P"},
			{Mask: from, PID: 1, Path: "/mock/x"},
			{Mask: to, PID: 1, Path: "/mock/y"},
			{Mask: to, PID: 1, Path: "/mock/Q"},
		}, false, []string{"file_write P", "file_open P", "file_write P", "file_rename x", "file_rename y", "file_rename P", "file_rename Q"}},
		{"another process's moved-to does not place it", []rawEvent{
			{Mask: create | from, PID: 1, Path: "/mock/P"},
			{Mask: content, PID: 1, Path: "/mock/P"},
			{Mask: to, PID: 2, Path: "/mock/z"},
			{Mask: to, PID: 1, Path: "/mock/Q"},
		}, false, []string{"file_write P", "file_open P", "file_write P", "file_rename z", "file_rename P", "file_rename Q"}},
		{"a delete of a file created again", []rawEvent{
			{Mask: create | del, PID: 1, Path: "/mock/t"},
			{Mask: content, PID: 1, Path: "/mock/t"},
		}, true, []string{"file_write t", "file_delete t", "file_open t", "file_write t"}},
		{"a delete before another file's record", []rawEvent{
			{Mask: create | del, PID: 1, Path: "/mock/t"},
			{Mask: content, PID: 1, Path: "/mock/t"},
			{Mask: content, PID: 1, Path: "/mock/u"},
		}, false, []string{"file_write t", "file_open t", "file_write t", "file_delete t", "file_open u", "file_write u"}},
		{"a rename whose moved-to merged away", []rawEvent{
			{Mask: create | from, PID: 1, Path: "/mock/t2"},
			{Mask: content, PID: 1, Path: "/mock/t2"},
			{Mask: content, PID: 1, Path: "/mock/u"},
		}, false, []string{"file_write t2", "file_open t2", "file_write t2", "file_open u", "file_write u", "file_rename t2"}},
		{"removals not merged with a creation", []rawEvent{
			{Mask: from, PID: 1, Path: "/mock/a"},
			{Mask: to, PID: 1, Path: "/mock/b"},
			{Mask: del, PID: 1, Path: "/mock/b"},
			{Mask: from | to, PID: 1, Path: "/mock/i"},
		}, false, []string{"file_rename a", "file_rename b", "file_delete b", "file_rename i"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			obs := newHashSeamObserver(t, "/mock", func(int) (string, error) { return "sha256:x", nil })
			obs.events = make(chan models.GroundTruthEvent, 64)
			obs.fileNamed = func(*rawEvent) bool { return c.stillThere }
			got := emittedOrder(t, obs, c.raws, "/mock/")
			if strings.Join(got, "|") != strings.Join(c.want, "|") {
				t.Errorf("emitted\n  %v\nwant\n  %v", got, c.want)
			}
		})
	}
}

// readKernelBatch marks a fresh directory with an unprivileged inode mark,
// creates the files named by existing in it unobserved, runs run with a
// function that names a file in it, and parses every record queued, as one
// late batch of the probe's read loop. It resolves only the directory's
// handle.
func readKernelBatch(t *testing.T, existing []string, run func(p func(string) string) error) (string, []rawEvent) {
	t.Helper()
	fd, err := unix.FanotifyInit(uint(unix.FAN_CLASS_NOTIF|reportFlags|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK), unix.O_RDONLY)
	if err != nil {
		t.Skipf("fanotify_init with the probe's flags: %v", err)
	}
	defer func() { _ = unix.Close(fd) }()
	dir := t.TempDir()
	for _, name := range existing {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("0"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := unix.FanotifyMark(fd, unix.FAN_MARK_ADD, watchMask|unix.FAN_EVENT_ON_CHILD, unix.AT_FDCWD, dir); err != nil {
		t.Skipf("fanotify_mark: %v", err)
	}
	dirHandle, _, err := unix.NameToHandleAt(unix.AT_FDCWD, dir, 0)
	if err != nil {
		t.Skipf("name_to_handle_at: %v", err)
	}
	resolve := func(_ fsID, handleType int32, handleData []byte) string {
		if handleType == dirHandle.Type() && bytes.Equal(handleData, dirHandle.Bytes()) {
			return dir
		}
		return ""
	}
	if err := run(func(name string) string { return filepath.Join(dir, name) }); err != nil {
		t.Fatal(err)
	}
	var raws []rawEvent
	buf := make([]byte, 64*1024)
	for {
		n, err := unix.Read(fd, buf)
		if errors.Is(err, unix.EAGAIN) || n <= 0 {
			break
		}
		raws = append(raws, parseEvents(buf, n, resolve, nil)...)
	}
	return dir, raws
}

// Claude Code 2.1.306 saving ~/.claude.json twice while the read loop paused
// (P-38): each save reads the target, writes a temporary and renames it onto
// the target. Read late, the kernel merges the second rename's moved-to into
// the first rename's unread moved-to record, so the queue holds one moved-to
// for two renames, and before P-38 the second save ended at its source.
// The probe completes the rename from where the temporary's file is.
func TestKernelASecondSaveMergedIntoTheFirstIsCompleted(t *testing.T) {
	dir, raws := readKernelBatch(t, []string{"T"}, func(p func(string) string) error {
		for i, tmp := range []string{"t1", "t2"} {
			if _, err := os.ReadFile(p("T")); err != nil {
				return err
			}
			if err := os.WriteFile(p(tmp), []byte{byte('1' + i)}, 0o644); err != nil {
				return err
			}
			if err := os.Rename(p(tmp), p("T")); err != nil {
				return err
			}
		}
		return nil
	})
	var shape []string
	for _, r := range raws {
		shape = append(shape, fmt.Sprintf("%#x %s", r.Mask, strings.TrimPrefix(r.Path, dir+"/")))
	}
	// The measured records: the second moved-to is in the first's record.
	wantShape := []string{
		"0x20 T", "0x140 t1", "0x2a t1", "0x80 T", "0x20 T", "0x140 t2", "0x2a t2",
	}
	if strings.Join(shape, "|") != strings.Join(wantShape, "|") {
		t.Errorf("records\n  %v\nwant\n  %v", shape, wantShape)
	}
	want := []string{
		"file_open T",
		"file_write t1", "file_open t1", "file_write t1", "file_close t1", "file_rename t1", "file_rename T",
		"file_open T",
		"file_write t2", "file_open t2", "file_write t2", "file_close t2", "file_rename t2", "file_rename T",
	}
	for _, c := range []struct {
		name   string
		fileAt func(*rawEvent) string
		want   []string
	}{
		{"completed", func(e *rawEvent) string { return fileByHandle(dir, e) }, want},
		// Without a resolution the probe emits what it did before P-38.
		{"file not found", func(*rawEvent) string { return "" }, want[:len(want)-1]},
	} {
		t.Run(c.name, func(t *testing.T) {
			obs := newHashSeamObserver(t, dir, func(int) (string, error) { return "sha256:x", nil })
			obs.events = make(chan models.GroundTruthEvent, 64)
			obs.fileAt = c.fileAt
			got := emittedOrder(t, obs, raws, dir+"/")
			if strings.Join(got, "|") != strings.Join(c.want, "|") {
				t.Errorf("emitted\n  %v\nwant\n  %v", got, c.want)
			}
		})
	}
}

// fileByHandle stands in for open_by_handle_at, which needs privilege: the
// path of the file in dir whose handle is e's, or "".
func fileByHandle(dir string, e *rawEvent) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, d := range entries {
		p := filepath.Join(dir, d.Name())
		if h, _, err := unix.NameToHandleAt(unix.AT_FDCWD, p, 0); err == nil && h.Type() == e.HandleType && bytes.Equal(h.Bytes(), e.HandleData) {
			return p
		}
	}
	return ""
}

// The rule of P-38 on synthetic records: a held moved-from whose file is now
// at a path is followed at the end of the drain by a moved-to on that path
// only when a moved-to record of its process named that path in the drain,
// the record the kernel can have merged it into.
func TestProcessRawEvent_MergedMovedToIsCompleted(t *testing.T) {
	const (
		create  = unix.FAN_CREATE
		from    = unix.FAN_MOVED_FROM
		to      = unix.FAN_MOVED_TO
		content = unix.FAN_OPEN | unix.FAN_MODIFY
	)
	handle := []byte{1}
	for _, c := range []struct {
		name string
		raws []rawEvent
		want []string
	}{
		{"merged into an earlier moved-to of its process", []rawEvent{
			{Mask: from, PID: 1, Path: "/mock/t1"},
			{Mask: to, PID: 1, Path: "/mock/T"},
			{Mask: unix.FAN_OPEN, PID: 1, Path: "/mock/T", HandleData: []byte{2}},
			{Mask: create | from, PID: 1, Path: "/mock/t2"},
			{Mask: content, PID: 1, Path: "/mock/t2", HandleData: handle},
		}, []string{"file_rename t1", "file_rename T", "file_open T", "file_write t2", "file_open t2", "file_write t2", "file_rename t2", "file_rename T"}},
		{"no moved-to of that path in the drain", []rawEvent{
			{Mask: create | from, PID: 1, Path: "/mock/t2"},
			{Mask: content, PID: 1, Path: "/mock/t2", HandleData: handle},
		}, []string{"file_write t2", "file_open t2", "file_write t2", "file_rename t2"}},
		{"the moved-to was another process's", []rawEvent{
			{Mask: to, PID: 2, Path: "/mock/T"},
			{Mask: create | from, PID: 1, Path: "/mock/t2"},
			{Mask: content, PID: 1, Path: "/mock/t2", HandleData: handle},
		}, []string{"file_rename T", "file_write t2", "file_open t2", "file_write t2", "file_rename t2"}},
		{"a content record with no handle", []rawEvent{
			{Mask: to, PID: 1, Path: "/mock/T"},
			{Mask: create | from, PID: 1, Path: "/mock/t2"},
			{Mask: content, PID: 1, Path: "/mock/t2"},
		}, []string{"file_rename T", "file_write t2", "file_open t2", "file_write t2", "file_rename t2"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			obs := newHashSeamObserver(t, "/mock", func(int) (string, error) { return "sha256:x", nil })
			obs.events = make(chan models.GroundTruthEvent, 64)
			obs.fileAt = func(e *rawEvent) string {
				if bytes.Equal(e.HandleData, handle) {
					return "/mock/T"
				}
				return ""
			}
			got := emittedOrder(t, obs, c.raws, "/mock/")
			if strings.Join(got, "|") != strings.Join(c.want, "|") {
				t.Errorf("emitted\n  %v\nwant\n  %v", got, c.want)
			}
		})
	}
}

// saveTwiceEnv names the target TestHelperSaveTwice saves in a child process.
const saveTwiceEnv = "AGENT_TRACE_SAVE_TWICE"

// TestHelperSaveTwice is not a test: run as a child with saveTwiceEnv set, it
// saves the target twice from one process, as Claude Code saves its state
// file, so that the kernel can merge the two renames' records (it merges only
// records of one process), and the probe, which drops its own records, sees
// them.
func TestHelperSaveTwice(t *testing.T) {
	target := os.Getenv(saveTwiceEnv)
	if target == "" {
		return
	}
	for i := range 2 {
		tmp := fmt.Sprintf("%s.tmp.%d", target, i)
		if _, err := os.ReadFile(target); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(tmp, []byte{byte('1' + i)}, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, target); err != nil {
			t.Fatal(err)
		}
	}
}

// As root, on the probe's filesystem-wide marks: two saves of one file by one
// process while the read loop is blocked, so the kernel merges the second
// rename's moved-to into the first's record, give both renames' both halves,
// the second save's after its temporary's close (P-38).
func TestObserver_ASecondSaveReadLateHasItsDestination(t *testing.T) {
	skipUnprivileged(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "state.json")
	if err := os.WriteFile(target, []byte("0"), 0o644); err != nil {
		t.Fatal(err)
	}
	obs := startBlockedObserver(t, dir)
	for _, f := range []string{"a", "b"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(200 * time.Millisecond) // the read loop reads the writes, then blocks
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperSaveTwice$")
	cmd.Env = append(os.Environ(), saveTwiceEnv+"="+target)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("helper: %v\n%s", err, out)
	}
	events := drainAll(t, obs)
	sort.SliceStable(events, func(i, j int) bool { return events[i].Timestamp.Before(events[j].Timestamp) })
	var got []string
	for _, e := range events {
		if e.PID != uint32(cmd.Process.Pid) {
			continue
		}
		got = append(got, fmt.Sprintf("%s %s", e.ActionType, strings.TrimPrefix(e.Target, dir+"/")))
	}
	want := []string{
		"file_open state.json",
		"file_write state.json.tmp.0", "file_open state.json.tmp.0", "file_write state.json.tmp.0", "file_close state.json.tmp.0",
		"file_rename state.json.tmp.0", "file_rename state.json",
		"file_open state.json",
		"file_write state.json.tmp.1", "file_open state.json.tmp.1", "file_write state.json.tmp.1", "file_close state.json.tmp.1",
		"file_rename state.json.tmp.1", "file_rename state.json",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("emitted\n  %v\nwant\n  %v", got, want)
	}
}
