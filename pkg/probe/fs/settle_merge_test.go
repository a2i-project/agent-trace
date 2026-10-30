package fs

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/content"
	"github.com/agent-trace/agent-trace/pkg/models"
	"golang.org/x/sys/unix"
)

// The kernel record behind the empty hash of P-26, on a real kernel and
// without root: an inode mark on a directory the test owns. A process writes
// a file and closes it, then opens it again with O_TRUNC, and nothing reads
// the queue between. The open and the truncation merge into the unread
// record of the close, so the reader gets one record, open, modify and
// close, while the file is empty and still open for writing, and no record
// of its own says the rewrite began. The write and close that follow are a
// new record once the first was read.
func TestKernelMergesATruncatingOpenIntoTheUnreadClose(t *testing.T) {
	fd, err := unix.FanotifyInit(uint(unix.FAN_CLASS_NOTIF|reportFlags|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK), unix.O_RDONLY)
	if err != nil {
		t.Skipf("fanotify_init with the probe's flags: %v", err)
	}
	defer func() { _ = unix.Close(fd) }()
	dir := t.TempDir()
	if err := unix.FanotifyMark(fd, unix.FAN_MARK_ADD, watchMask|unix.FAN_EVENT_ON_CHILD, unix.AT_FDCWD, dir); err != nil {
		t.Skipf("fanotify_mark: %v", err)
	}
	masks := func() []uint64 {
		var out []uint64
		buf := make([]byte, 64*1024)
		for {
			n, err := unix.Read(fd, buf)
			if errors.Is(err, unix.EAGAIN) || n <= 0 {
				return out
			}
			for _, r := range parseEvents(buf, n, func(fsID, int32, []byte) string { return "" }, nil) {
				out = append(out, r.Mask)
			}
		}
	}
	target := filepath.Join(dir, "f")
	if err := os.WriteFile(target, []byte("rev-1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	masks() // the creation

	if err := os.WriteFile(target, []byte("rev-2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(target, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		t.Fatal(err)
	}
	merged := masks()
	want := []uint64{unix.FAN_OPEN | unix.FAN_MODIFY | unix.FAN_CLOSE_WRITE}
	if fmt.Sprint(merged) != fmt.Sprint(want) {
		t.Errorf("a close then a truncating open read late gave records %#x, want %#x", merged, want)
	}
	if _, err := f.Write([]byte("rev-3\n")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if got, want := masks(), []uint64{unix.FAN_MODIFY | unix.FAN_CLOSE_WRITE}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("the write and close after the read gave records %#x, want %#x", got, want)
	}
}

// The premise of P-39, on a real kernel and without root: an open by another
// process that truncates the file is reported with FAN_MODIFY, whether or
// not the file was already empty and whether or not it writes, while an open
// that does not truncate carries no FAN_MODIFY. So an open record without a
// modify changed no content. Each child exits before the queue is read, so
// its open, truncation and close are merged into one record.
func TestKernelATruncatingOpenByAnotherProcessIsAModify(t *testing.T) {
	fd, err := unix.FanotifyInit(uint(unix.FAN_CLASS_NOTIF|reportFlags|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK), unix.O_RDONLY)
	if err != nil {
		t.Skipf("fanotify_init with the probe's flags: %v", err)
	}
	defer func() { _ = unix.Close(fd) }()
	dir := t.TempDir()
	if err := unix.FanotifyMark(fd, unix.FAN_MARK_ADD, watchMask|unix.FAN_EVENT_ON_CHILD, unix.AT_FDCWD, dir); err != nil {
		t.Skipf("fanotify_mark: %v", err)
	}
	contentBits := uint64(unix.FAN_OPEN | unix.FAN_MODIFY | unix.FAN_CLOSE_WRITE)
	masks := func() []uint64 {
		var out []uint64
		buf := make([]byte, 64*1024)
		for {
			n, err := unix.Read(fd, buf)
			if errors.Is(err, unix.EAGAIN) || n <= 0 {
				return out
			}
			for _, r := range parseEvents(buf, n, func(fsID, int32, []byte) string { return "" }, nil) {
				if r.Mask&contentBits != 0 {
					out = append(out, r.Mask&contentBits)
				}
			}
		}
	}
	target := filepath.Join(dir, "f")
	if err := os.WriteFile(target, []byte("written\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	masks()

	for _, c := range []struct {
		name   string
		script string
		want   uint64
	}{
		{"a read", `cat "$1" >/dev/null`, unix.FAN_OPEN},
		{"an open for writing that writes nothing", `exec 3<>"$1"`, unix.FAN_OPEN | unix.FAN_CLOSE_WRITE},
		{"a truncating open of a file with content", `: >"$1"`, unix.FAN_OPEN | unix.FAN_MODIFY | unix.FAN_CLOSE_WRITE},
		{"a truncating open of an empty file", `: >"$1"`, unix.FAN_OPEN | unix.FAN_MODIFY | unix.FAN_CLOSE_WRITE},
		{"a truncating open that writes", `echo x >"$1"`, unix.FAN_OPEN | unix.FAN_MODIFY | unix.FAN_CLOSE_WRITE},
	} {
		cmd := exec.Command("sh", "-c", c.script, "sh", target)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s: %v: %s", c.name, err, out)
		}
		got := masks()
		if fmt.Sprint(got) != fmt.Sprint([]uint64{c.want}) {
			t.Errorf("%s by another process gave records %#x, want one %#x", c.name, got, c.want)
		}
	}
}

// P-26: the close's record also holds the next rewrite's open and
// truncation, the writer still holds the file and has not written, and the
// path is quiet. Before P-26 the settle code read the empty file and
// published its hash, sha256:e3b0c4..., the hash CI saw. The close is now
// published without a hash and without a read. Once the writer has written
// and closed, its own close is hashed with the content it left.
func TestObserver_MergedTruncatingOpenDropsTheHash(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "rewritten.txt")
	reads := 0
	obs := newHashSeamObserver(t, dir, func(fd int) (string, error) {
		reads++
		return content.SHA256FD(fd)
	})
	obs.writerHolds = openForWriteBy
	self := int32(os.Getpid())

	if err := os.WriteFile(target, []byte("rev-1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(target, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	obs.processRawEvent(&rawEvent{Mask: unix.FAN_OPEN | unix.FAN_MODIFY | unix.FAN_CLOSE_WRITE, PID: self, Path: target}, time.Now())
	obs.resolveSettled(obs.settleSnapshot(), hashSeamBuf(), false)
	closes := closeEvents(obs)
	if len(closes) != 1 || closes[0].OutputHash != nil {
		t.Fatalf("closes = %s, want one without a hash: the file was truncated by an open that is still writing", describeCloses(closes))
	}
	if reads != 0 {
		t.Errorf("the content was read %d time(s); a read that cannot be trusted should not be made", reads)
	}

	if _, err := f.Write([]byte("rev-2\n")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	obs.processRawEvent(&rawEvent{Mask: unix.FAN_MODIFY | unix.FAN_CLOSE_WRITE, PID: self, Path: target}, time.Now())
	obs.resolveSettled(obs.settleSnapshot(), hashSeamBuf(), false)
	closes = closeEvents(obs)
	want := content.SHA256Bytes([]byte("rev-2\n"))
	if len(closes) != 1 || closes[0].OutputHash == nil || *closes[0].OutputHash != want {
		t.Fatalf("closes = %s, want one with %s", describeCloses(closes), want)
	}
}

// Since P-25 a record names the entry as it was named when the event
// happened. The close of a temporary renamed onto its target names the
// temporary, and a later record on the target names the target, so the
// path's generation does not see it. The file's handle is the same under
// both names, and its generations do (P-26). An open there by the closing
// process drops the hash, and so does a modify by any process; an open by
// another process changes no content and leaves it (P-39).
func TestObserver_AnOpenUnderAnotherNameDropsTheHash(t *testing.T) {
	for _, c := range []struct {
		name     string
		mask     uint64
		pid      int32
		wantHash bool
	}{
		{"the closer's open", unix.FAN_OPEN, 7, false},
		{"an open the record names no process for", unix.FAN_OPEN, 0, false},
		{"another process's modify", unix.FAN_MODIFY, 8, false},
		{"another process's open", unix.FAN_OPEN, 8, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			tmp := filepath.Join(dir, "notes.txt.tmp")
			target := filepath.Join(dir, "notes.txt")
			reads := 0
			obs := newHashSeamObserver(t, dir, func(int) (string, error) {
				reads++
				return "sha256:x", nil
			})
			handle := []byte("file-handle-1")
			obs.processRawEvent(&rawEvent{Mask: unix.FAN_CLOSE_WRITE, PID: 7, Path: tmp, HandleType: 1, HandleData: handle}, time.Now())
			obs.processRawEvent(&rawEvent{Mask: unix.FAN_MOVED_FROM, PID: 7, Path: tmp}, time.Now())
			obs.processRawEvent(&rawEvent{Mask: unix.FAN_MOVED_TO, PID: 7, Path: target}, time.Now())
			obs.processRawEvent(&rawEvent{Mask: c.mask, PID: c.pid, Path: target, HandleType: 1, HandleData: handle}, time.Now())
			obs.resolveSettled(obs.settleSnapshot(), hashSeamBuf(), false)
			closes := closeEvents(obs)
			if len(closes) != 1 || (closes[0].OutputHash != nil) != c.wantHash {
				t.Fatalf("closes = %s after %d read(s), want one with a hash: %v", describeCloses(closes), reads, c.wantHash)
			}
			if !c.wantHash && reads != 0 {
				t.Errorf("the content was read %d time(s); a read that cannot be trusted should not be made", reads)
			}
		})
	}

	// Another file's handle leaves the hash alone.
	dir := t.TempDir()
	tmp := filepath.Join(dir, "notes.txt.tmp")
	target := filepath.Join(dir, "notes.txt")
	obs := newHashSeamObserver(t, dir, func(int) (string, error) { return "sha256:x", nil })
	obs.processRawEvent(&rawEvent{Mask: unix.FAN_CLOSE_WRITE, PID: 7, Path: tmp, HandleType: 1, HandleData: []byte("file-handle-1")}, time.Now())
	obs.processRawEvent(&rawEvent{Mask: unix.FAN_OPEN, PID: 7, Path: target, HandleType: 1, HandleData: []byte("file-handle-2")}, time.Now())
	obs.resolveSettled(obs.settleSnapshot(), hashSeamBuf(), false)
	closes := closeEvents(obs)
	if len(closes) != 1 || closes[0].OutputHash == nil {
		t.Fatalf("closes = %s, want one with a hash", describeCloses(closes))
	}
}

// At Stop the drain after the read returns on the stop pipe. With records
// still queued it cannot say nothing touched the file during the read, so
// the close is published without a hash; with the queue empty the hash
// stands (P-26).
func TestObserver_AHashReadAtStopNeedsAnEmptyQueue(t *testing.T) {
	for _, c := range []struct {
		name     string
		queued   bool
		wantHash bool
	}{
		{"queue empty", false, true},
		{"records queued", true, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "f.txt")
			obs := newHashSeamObserver(t, dir, func(int) (string, error) { return "sha256:x", nil })
			var queue, stop [2]int
			for _, p := range []*[2]int{&queue, &stop} {
				if err := unix.Pipe2(p[:], unix.O_CLOEXEC); err != nil {
					t.Fatal(err)
				}
				fds := *p
				t.Cleanup(func() { _ = unix.Close(fds[0]); _ = unix.Close(fds[1]) })
			}
			obs.fanotifyFD, obs.stopR = queue[0], stop[0]
			if _, err := unix.Write(stop[1], []byte{0}); err != nil {
				t.Fatal(err)
			}
			if c.queued {
				if _, err := unix.Write(queue[1], []byte{0}); err != nil {
					t.Fatal(err)
				}
			}
			obs.processRawEvent(&rawEvent{Mask: unix.FAN_CLOSE_WRITE, PID: 1, Path: target}, time.Now())
			obs.flushPendingCloses(hashSeamBuf())
			closes := closeEvents(obs)
			if len(closes) != 1 || (closes[0].OutputHash != nil) != c.wantHash {
				t.Fatalf("closes = %s, want a hash: %v", describeCloses(closes), c.wantHash)
			}
		})
	}
}

// openForWriteBy answers for the descriptors of the process it names, and
// errs towards "held" when it cannot tell.
func TestOpenForWriteBy(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "f")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	pathFD, err := unix.Open(target, unix.O_PATH, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(pathFD) }()
	self := uint32(os.Getpid())

	if openForWriteBy(self, pathFD) {
		t.Error("held for writing with only an O_PATH descriptor")
	}
	r, err := os.Open(target)
	if err != nil {
		t.Fatal(err)
	}
	if openForWriteBy(self, pathFD) {
		t.Error("held for writing with a read-only descriptor")
	}
	_ = r.Close()
	for _, flag := range []int{os.O_WRONLY, os.O_RDWR, os.O_WRONLY | os.O_APPEND} {
		w, err := os.OpenFile(target, flag, 0)
		if err != nil {
			t.Fatal(err)
		}
		if !openForWriteBy(self, pathFD) {
			t.Errorf("not held for writing with a descriptor opened %#o", flag)
		}
		_ = w.Close()
	}
	if openForWriteBy(self, pathFD) {
		t.Error("held for writing after every writing descriptor was closed")
	}

	// A process that has exited holds nothing; the kernel, pid 0, cannot be asked.
	cmd := exec.Command("true")
	if err := cmd.Run(); err != nil {
		t.Skipf("true: %v", err)
	}
	if openForWriteBy(uint32(cmd.Process.Pid), pathFD) {
		t.Error("an exited process holds the file")
	}
	if !openForWriteBy(0, pathFD) {
		t.Error("pid 0 must count as held: its descriptors cannot be read")
	}
}

// The probe end to end, root only (CI): a writer that rewrites a file with a
// truncating open right after closing it, then stalls longer than the settle
// window before writing, the shape that published the empty hash. Every hash
// a close carries must be content the file had at a close.
func TestObserver_StalledRewriteNeverPublishesAnIntermediateHash(t *testing.T) {
	skipUnprivileged(t)
	dir := t.TempDir()
	obs := startObserver(t, dir)
	time.Sleep(200 * time.Millisecond)

	target := filepath.Join(dir, "stalled.txt")
	const iterations = 20
	valid := map[string]bool{}
	for i := 0; i < iterations; i++ {
		first := []byte(fmt.Sprintf("revision-%02d-a\n", i))
		second := []byte(fmt.Sprintf("revision-%02d-b\n", i))
		valid[content.SHA256Bytes(first)] = true
		valid[content.SHA256Bytes(second)] = true
		if err := os.WriteFile(target, first, 0o644); err != nil {
			t.Fatal(err)
		}
		f, err := os.OpenFile(target, os.O_WRONLY|os.O_TRUNC, 0)
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(3 * settleQuietWindow)
		if _, err := f.Write(second); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	events := collectEvents(obs, 500*time.Millisecond)
	if err := obs.Stop(); err != nil {
		t.Fatal(err)
	}
	for e := range obs.Events() {
		events = append(events, e)
	}
	var with, without int
	for _, e := range events {
		if e.ActionType != models.FileClose || e.Target != target {
			continue
		}
		if e.OutputHash == nil {
			without++
			continue
		}
		with++
		if !valid[*e.OutputHash] {
			t.Errorf("a close carried %s, the content of no close", *e.OutputHash)
		}
	}
	t.Logf("%d closes with a hash, %d without", with, without)
	if with+without == 0 {
		t.Fatal("no close of the target was observed")
	}
}

// The probe end to end, root only (CI): a file read back by another process
// within the settle window keeps its hash, the content of the close (P-39);
// a file the closing process opens again within the window is published
// without one, as before. The settle window is lengthened to two seconds so
// both opens land inside it on a slow runner. The reader is another process,
// so its open is a record of its own and never merges into the close's.
func TestObserver_AReaderWithinTheSettleWindowKeepsTheHash(t *testing.T) {
	skipUnprivileged(t)
	if _, err := exec.LookPath("cat"); err != nil {
		t.Skipf("cat: %v", err)
	}
	dir := t.TempDir()
	obs, err := New(Config{Path: dir, PathFilter: dir, EventBufSize: 256})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	obs.settleDelay = 2 * time.Second
	obs.Start()
	time.Sleep(200 * time.Millisecond)

	readBack := filepath.Join(dir, "read-back.txt")
	reopened := filepath.Join(dir, "reopened.txt")
	written := []byte("the content at the close\n")
	if err := os.WriteFile(readBack, written, 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cat", readBack).CombinedOutput(); err != nil {
		t.Fatalf("cat: %v: %s", err, out)
	}
	if err := os.WriteFile(reopened, written, 0o644); err != nil {
		t.Fatal(err)
	}
	// Left unread, the writer's next open would merge into its close's
	// record (P-26) and no open record would follow the close. Give the
	// read loop time to read the close first; the window is far longer.
	time.Sleep(200 * time.Millisecond)
	f, err := os.Open(reopened)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	events := collectEvents(obs, 3*time.Second)
	if err := obs.Stop(); err != nil {
		t.Fatal(err)
	}
	for e := range obs.Events() {
		events = append(events, e)
	}
	self := uint32(os.Getpid())
	var readerOpened bool
	closes := map[string][]models.GroundTruthEvent{}
	for _, e := range events {
		if e.ActionType == models.FileOpen && e.Target == readBack && e.PID != self {
			readerOpened = true
		}
		if e.ActionType == models.FileClose {
			closes[e.Target] = append(closes[e.Target], e)
		}
	}
	if !readerOpened {
		t.Fatalf("no open of %s by another process was observed; events: %v", readBack, events)
	}
	want := content.SHA256Bytes(written)
	if c := closes[readBack]; len(c) != 1 || c[0].OutputHash == nil || *c[0].OutputHash != want {
		t.Errorf("closes of the file read back = %s, want one with %s", describeCloses(c), want)
	}
	if c := closes[reopened]; len(c) != 1 || c[0].OutputHash != nil {
		t.Errorf("closes of the file its writer reopened = %s, want one without a hash", describeCloses(c))
	}
}

func describeCloses(closes []models.GroundTruthEvent) string {
	out := "["
	for i, c := range closes {
		if i > 0 {
			out += " "
		}
		if c.OutputHash == nil {
			out += c.Target + ":nohash"
		} else {
			out += c.Target + ":" + *c.OutputHash
		}
	}
	return out + "]"
}
