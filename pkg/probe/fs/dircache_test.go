package fs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
	"golang.org/x/sys/unix"
)

// pipeWatch returns a rename watch that reads the records a test writes to
// the returned descriptor, guarding the given filesystems.
func pipeWatch(t testing.TB, guarded ...fsID) (*renameWatch, int) {
	t.Helper()
	var p [2]int
	if err := unix.Pipe2(p[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		t.Fatalf("pipe2: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(p[0]); _ = unix.Close(p[1]) })
	w := &renameWatch{fd: p[0], guarded: map[fsID]bool{}, buf: make([]byte, 4096)}
	for _, id := range guarded {
		w.guarded[id] = true
	}
	return w, p[1]
}

// moveRecord is a rename watch record: a move of a file or, with dir set, of a
// directory, on filesystem fsid.
func moveRecord(fsid fsID, dir bool) []byte {
	info := buildFidInfo(1, []byte("handle"))
	binary.LittleEndian.PutUint32(info[4:8], uint32(fsid[0]))
	binary.LittleEndian.PutUint32(info[8:12], uint32(fsid[1]))
	mask := uint64(unix.FAN_MOVE_SELF)
	if dir {
		mask |= unix.FAN_ONDIR
	}
	return append(buildMetadata(mask, 1, uint16(len(info))), info...)
}

// The cache keeps at most its bound, evicting the directory resolved least
// recently, and counts what it evicts.
func TestDirCache_EvictsTheLeastRecentlyResolvedDirectory(t *testing.T) {
	w, _ := pipeWatch(t, fsID{})
	c := newDirCache(2, w)
	c.fill(fsID{}, 1, []byte("a"), "/a")
	c.fill(fsID{}, 1, []byte("b"), "/b")
	c.fill(fsID{}, 1, []byte("a"), "/a") // a is now the most recent
	c.fill(fsID{}, 1, []byte("c"), "/c")
	if _, ok := c.lookup(fsID{}, 1, []byte("b")); ok {
		t.Error("b survived although it was resolved least recently")
	}
	for _, k := range []string{"a", "c"} {
		if p, ok := c.lookup(fsID{}, 1, []byte(k)); !ok || p != "/"+k {
			t.Errorf("lookup %s = %q, %v", k, p, ok)
		}
	}
	if s := c.snapshot(); s.Evicted != 1 || s.Resolved != 2 || !s.Watching {
		t.Errorf("stats = %+v, want 1 evicted, 2 resolved, watching", s)
	}
}

// A directory renamed on a filesystem drops every entry of that filesystem; a
// file renamed drops nothing; a lost record drops everything. A cached path
// can then never be one a directory rename made stale.
func TestDirCache_ARenamedDirectoryDropsItsFilesystem(t *testing.T) {
	a, b := fsID{1, 1}, fsID{2, 2}
	for _, c := range []struct {
		name   string
		record []byte
		keepA  bool
		keepB  bool
	}{
		{"a file moved", moveRecord(a, false), true, true},
		{"a directory moved on a", moveRecord(a, true), false, true},
		{"the watch overflowed", buildMetadata(unix.FAN_Q_OVERFLOW, 0, 0), false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			w, records := pipeWatch(t, a, b)
			dirs := newDirCache(16, w)
			dirs.fill(a, 1, []byte("d"), "/a/d")
			dirs.fill(b, 1, []byte("d"), "/b/d")
			if _, err := unix.Write(records, c.record); err != nil {
				t.Fatal(err)
			}
			if _, ok := dirs.lookup(a, 1, []byte("d")); ok != c.keepA {
				t.Errorf("entry on a kept = %v, want %v", ok, c.keepA)
			}
			if _, ok := dirs.lookup(b, 1, []byte("d")); ok != c.keepB {
				t.Errorf("entry on b kept = %v, want %v", ok, c.keepB)
			}
		})
	}
}

// Without a rename watch, or on a filesystem the watch did not mark, nothing
// is named from the cache: a rename there would go unseen.
func TestDirCache_NoLookupWithoutARenameWatch(t *testing.T) {
	c := newDirCache(16, nil)
	c.fill(fsID{}, 1, []byte("d"), "/d")
	if _, ok := c.lookup(fsID{}, 1, []byte("d")); ok {
		t.Error("looked up without a rename watch")
	}
	w, _ := pipeWatch(t, fsID{1, 1})
	c = newDirCache(16, w)
	c.fill(fsID{}, 1, []byte("d"), "/d")
	if _, ok := c.lookup(fsID{}, 1, []byte("d")); ok {
		t.Error("looked up on a filesystem the watch does not guard")
	}
	var none *dirCache
	none.fill(fsID{}, 1, []byte("d"), "/d")
	if _, ok := none.lookup(fsID{}, 1, []byte("d")); ok {
		t.Error("a nil cache named a directory")
	}
}

// A DFID_NAME record whose directory no longer resolves is named from the
// cache when an earlier record resolved that directory, and stays unresolved
// otherwise.
func TestParseEvents_RemovedDirectoryIsNamedFromTheCache(t *testing.T) {
	w, _ := pipeWatch(t, fsID{})
	dirs := newDirCache(16, w)
	live := map[string]string{"dir123": "/mock/dir"}
	resolve := func(_ fsID, _ int32, h []byte) string { return live[string(h)] }
	record := func(mask uint64, dir, name string) []byte {
		info := buildDfidNameInfo(1, []byte(dir), name)
		return append(buildMetadata(mask, 1, uint16(len(info))), info...)
	}

	buf := record(unix.FAN_CREATE, "dir123", "probe")
	if ev := parseEvents(buf, len(buf), resolve, dirs); ev[0].Path != "/mock/dir/probe" {
		t.Fatalf("live path = %q", ev[0].Path)
	}
	delete(live, "dir123") // the directory is removed
	buf = append(record(unix.FAN_DELETE, "dir123", "probe"), record(unix.FAN_DELETE, "never-seen", "x")...)
	ev := parseEvents(buf, len(buf), resolve, dirs)
	if len(ev) != 2 || ev[0].Path != "/mock/dir/probe" || ev[0].Ambiguous {
		t.Errorf("delete in the removed directory = %+v, want /mock/dir/probe, exact", ev)
	}
	if len(ev) == 2 && ev[1].Path != "" {
		t.Errorf("delete in a directory never resolved = %q, want no path", ev[1].Path)
	}
	if st := dirs.snapshot(); st.Hits != 1 || st.Resolved != 0 {
		t.Errorf("stats = %+v, want the removed directory named from its resolved entry", st)
	}
}

// A directory the probe resolved once is named from the cache afterwards
// without resolving its handle again (P-29); an entry of the start walk is
// used only once the handle no longer resolves, since the walk's path can
// name the directory through another alias.
func TestParseEvents_ResolvedDirectoryIsNotResolvedAgain(t *testing.T) {
	w, _ := pipeWatch(t, fsID{})
	dirs := newDirCache(16, w)
	live := map[string]string{"dir123": "/mock/dir", "walked": "/mock/alias"}
	calls := map[string]int{}
	resolve := func(_ fsID, _ int32, h []byte) string {
		calls[string(h)]++
		return live[string(h)]
	}
	record := func(mask uint64, dir, name string) []byte {
		info := buildDfidNameInfo(1, []byte(dir), name)
		return append(buildMetadata(mask, 1, uint16(len(info))), info...)
	}
	dirs.put(fsID{}, 1, []byte("walked"), "/mock/walked", false)

	var buf []byte
	for _, name := range []string{"a", "b", "c"} {
		buf = append(buf, record(unix.FAN_CREATE, "dir123", name)...)
		buf = append(buf, record(unix.FAN_CREATE, "walked", name)...)
	}
	ev := parseEvents(buf, len(buf), resolve, dirs)
	if len(ev) != 6 || ev[4].Path != "/mock/dir/c" || ev[5].Path != "/mock/alias/c" {
		t.Fatalf("paths = %+v", ev)
	}
	if calls["dir123"] != 1 || calls["walked"] != 1 {
		t.Errorf("resolutions = %v, want one per directory", calls)
	}
	if st := dirs.snapshot(); st.Hits != 4 || st.Resolved != 0 {
		t.Errorf("stats = %+v, want 4 hits", st)
	}

	// A walk entry for a directory no record resolved names it once it is
	// gone.
	dirs.put(fsID{}, 1, []byte("gone"), "/mock/gone", false)
	buf = record(unix.FAN_DELETE, "gone", "x")
	if ev := parseEvents(buf, len(buf), resolve, dirs); ev[0].Path != "/mock/gone/x" {
		t.Errorf("delete in a walked, removed directory = %q", ev[0].Path)
	}
	if st := dirs.snapshot(); st.Resolved != 1 {
		t.Errorf("stats = %+v, want 1 resolved", st)
	}
}

// kernelRig reads real records from an unprivileged inode mark on one
// directory (the probe's filesystem-wide mark needs root) and resolves
// handles as open_by_handle_at would, by name_to_handle_at of every directory
// that exists under root when the record is read: a removed directory
// resolves to nothing, a renamed one to its new path.
type kernelRig struct {
	t    *testing.T
	fd   int
	root string
	dirs *dirCache
	raws []rawEvent
}

func newKernelRig(t *testing.T, sub string) *kernelRig {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, sub)
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.FanotifyInit(uint(unix.FAN_CLASS_NOTIF|reportFlags|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK), unix.O_RDONLY)
	if err != nil {
		t.Skipf("fanotify_init with the probe's flags: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	if err := unix.FanotifyMark(fd, unix.FAN_MARK_ADD, watchMask|unix.FAN_EVENT_ON_CHILD, unix.AT_FDCWD, dir); err != nil {
		t.Skipf("fanotify_mark: %v", err)
	}
	watch := openRenameWatch([]string{dir}, 0)
	if watch == nil {
		t.Skip("rename watch: the kernel refused an inode mark for FAN_MOVE_SELF | FAN_ONDIR")
	}
	dirs := newDirCache(dirCacheSize, watch)
	t.Cleanup(dirs.close)
	return &kernelRig{t: t, fd: fd, root: root, dirs: dirs}
}

func (k *kernelRig) resolve(_ fsID, handleType int32, handleData []byte) string {
	found := ""
	_ = filepath.Walk(k.root, func(p string, info os.FileInfo, err error) error {
		if err != nil || !info.IsDir() || found != "" {
			return nil
		}
		if h, _, err := unix.NameToHandleAt(unix.AT_FDCWD, p, 0); err == nil && h.Type() == handleType && bytes.Equal(h.Bytes(), handleData) {
			found = p
		}
		return nil
	})
	return found
}

// read parses every queued record, as one batch of the probe's read loop.
func (k *kernelRig) read() {
	buf := make([]byte, 64*1024)
	for {
		n, err := unix.Read(k.fd, buf)
		if errors.Is(err, unix.EAGAIN) || n <= 0 {
			return
		}
		k.raws = append(k.raws, parseEvents(buf, n, k.resolve, k.dirs)...)
	}
}

func (k *kernelRig) do(steps ...func() error) {
	for _, s := range steps {
		if err := s(); err != nil {
			k.t.Fatal(err)
		}
	}
}

// deletes returns the paths of the delete records read, "" for one with no
// path.
func (k *kernelRig) deletes() []string {
	var out []string
	for _, r := range k.raws {
		if r.Mask&unix.FAN_DELETE != 0 {
			out = append(out, strings.TrimPrefix(r.Path, k.root+"/"))
		}
	}
	return out
}

// The shape of the unresolved delete in every Claude Code run of the first
// capture with names (P-28): a file created in a fresh directory, read while
// the directory exists, then deleted with its directory before the next read.
// The delete names the file through the cache.
func TestKernelDeleteInARemovedDirectoryIsNamedFromTheCache(t *testing.T) {
	k := newKernelRig(t, "fswatch-probe-X")
	dir := filepath.Join(k.root, "fswatch-probe-X")
	k.do(func() error { return os.WriteFile(filepath.Join(dir, "probe"), []byte("x"), 0o644) })
	k.read()
	k.do(
		func() error { return os.Remove(filepath.Join(dir, "probe")) },
		func() error { return os.Remove(dir) },
	)
	k.read()
	if got := k.deletes(); strings.Join(got, "|") != "fswatch-probe-X/probe" {
		t.Errorf("deletes = %q, want the file named through the cache", got)
	}
	if s := k.dirs.snapshot(); s.Resolved+s.Hits == 0 {
		t.Errorf("stats = %+v, want the delete named from the cache", s)
	}
}

// A directory renamed after it was cached: removed before the next read, its
// delete stays unresolved rather than named under the old path; read once
// under its new name first, the cache follows the rename.
func TestKernelRenamedDirectoryIsNeverNamedByItsOldPath(t *testing.T) {
	for _, c := range []struct {
		name     string
		readMove bool
		want     string
	}{
		{"removed before a read", false, ""},
		{"read under its new name, then removed", true, "t/g"},
	} {
		t.Run(c.name, func(t *testing.T) {
			k := newKernelRig(t, "s")
			s, d := filepath.Join(k.root, "s"), filepath.Join(k.root, "t")
			k.do(func() error { return os.WriteFile(filepath.Join(s, "g"), []byte("x"), 0o644) })
			k.read()
			k.do(func() error { return os.Rename(s, d) })
			if c.readMove {
				k.do(func() error { return os.WriteFile(filepath.Join(d, "h"), []byte("y"), 0o644) })
				k.read()
				k.do(func() error { return os.Remove(filepath.Join(d, "h")) })
				k.read()
			}
			k.do(
				func() error { return os.Remove(filepath.Join(d, "g")) },
				func() error { return os.Remove(d) },
			)
			k.read()
			got := k.deletes()
			if len(got) == 0 || got[len(got)-1] != c.want {
				t.Errorf("deletes = %q, want the last one %q", got, c.want)
			}
			for _, p := range got {
				if strings.HasPrefix(p, "s/") {
					t.Errorf("a delete is named by the directory's old path: %q", p)
				}
			}
			if st := k.dirs.snapshot(); st.Invalidated == 0 {
				t.Errorf("stats = %+v, want the rename to invalidate", st)
			}
		})
	}
}

// A directory whose handle never resolved before its removal stays
// unresolved, and its records are counted (V-35).
func TestKernelDirectoryNeverResolvedStaysUnresolved(t *testing.T) {
	k := newKernelRig(t, "tree")
	dir := filepath.Join(k.root, "tree")
	k.do(
		func() error { return os.WriteFile(filepath.Join(dir, "leaf"), []byte("x"), 0o644) },
		func() error { return os.Remove(filepath.Join(dir, "leaf")) },
		func() error { return os.Remove(dir) },
	)
	k.read()
	if len(k.raws) == 0 {
		t.Fatal("no records")
	}
	obs := &Observer{events: make(chan models.GroundTruthEvent, 64), mountFD: -1}
	for i := range k.raws {
		if k.raws[i].Path != "" {
			t.Errorf("record %#x named %q", k.raws[i].Mask, k.raws[i].Path)
		}
		k.raws[i].PID = 1 // not the recorder's own
		obs.processRawEvent(&k.raws[i], time.Now())
	}
	if got := obs.CaptureCoverage().UnresolvedPaths; got == 0 {
		t.Error("UnresolvedPaths = 0")
	}
	if s := k.dirs.snapshot(); s.Resolved != 0 || s.Hits != 0 {
		t.Errorf("stats = %+v, want nothing named from the cache", s)
	}
}

// startBlockedObserver starts an observer on dir with an events channel of
// one, so the read loop stops reading once it has two events to emit: the
// records queued after that wait in the kernel until the test reads.
func startBlockedObserver(t *testing.T, dir string) *Observer {
	t.Helper()
	obs, err := New(Config{Path: dir, PathFilter: dir, EventBufSize: 1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	obs.Start()
	return obs
}

// drainAll stops the observer and returns every event it emitted.
func drainAll(t *testing.T, obs *Observer) []models.GroundTruthEvent {
	t.Helper()
	var events []models.GroundTruthEvent
	done := make(chan struct{})
	go func() {
		for e := range obs.Events() {
			events = append(events, e)
		}
		close(done)
	}()
	// CI sets this bound, not the dev box: the read loop must catch up with
	// the records queued while it was blocked.
	time.Sleep(500 * time.Millisecond)
	if err := obs.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	<-done
	return events
}

// As root, on the probe's filesystem-wide mark: a file seen in a directory,
// then removed with the directory by another process while the read loop is
// blocked, is named by its delete (P-28).
func TestObserver_DeleteInADirectoryRemovedAfterItWasSeenIsNamed(t *testing.T) {
	skipUnprivileged(t)
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	obs := startBlockedObserver(t, dir)
	if !obs.DirCache().Watching {
		t.Fatal("the rename watch marked nothing")
	}
	if err := os.WriteFile(filepath.Join(sub, "leaf"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond) // the read loop reads the write, then blocks
	if out, err := exec.Command("rm", "-rf", sub).CombinedOutput(); err != nil {
		t.Fatalf("rm: %v\n%s", err, out)
	}
	events := drainAll(t, obs)
	assertHasNamedEvent(t, events, models.FileDelete, filepath.Join(sub, "leaf"))
	t.Logf("dir cache %+v, unresolved %d", obs.DirCache(), obs.CaptureCoverage().UnresolvedPaths)
}

// As root: a directory renamed and removed while the read loop is blocked
// is never named by its old path; its delete stays unresolved and counted.
func TestObserver_RenamedThenRemovedDirectoryIsNotNamedByItsOldPath(t *testing.T) {
	skipUnprivileged(t)
	dir := t.TempDir()
	sub, moved := filepath.Join(dir, "sub"), filepath.Join(dir, "moved")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	obs := startBlockedObserver(t, dir)
	if err := os.WriteFile(filepath.Join(sub, "leaf"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if out, err := exec.Command("sh", "-c", `mv "$1" "$2" && rm -rf "$2"`, "sh", sub, moved).CombinedOutput(); err != nil {
		t.Fatalf("mv, rm: %v\n%s", err, out)
	}
	events := drainAll(t, obs)
	for _, e := range events {
		if e.ActionType == models.FileDelete && e.Target == filepath.Join(sub, "leaf") {
			t.Errorf("the delete is named by the directory's old path %s", e.Target)
		}
	}
	if obs.DirCache().Invalidated == 0 {
		t.Errorf("dir cache %+v: the rename invalidated nothing", obs.DirCache())
	}
	t.Logf("dir cache %+v, unresolved %d", obs.DirCache(), obs.CaptureCoverage().UnresolvedPaths)
}

// The start walk caches a directory under the name resolving its handle
// gives, which every record of the directory carries, and not under the path
// the walk reached it by, which can be another mount's (P-30). Only a handle
// that does not resolve keeps the walk's path, for a removed directory alone.
func TestDirCache_TheStartWalkCachesTheResolvedName(t *testing.T) {
	dir := t.TempDir()
	id, err := fsidOf(dir)
	if err != nil {
		t.Fatal(err)
	}
	fh, _, err := unix.NameToHandleAt(unix.AT_FDCWD, dir, 0)
	if err != nil {
		t.Skipf("name_to_handle_at: %v", err)
	}
	w, _ := pipeWatch(t, id)

	c := newDirCache(16, w)
	c.fillPath(dir, func(fsID, int32, []byte) string { return "/through/the/probe/mount" })
	if p, ok := c.hit(id, fh.Type(), fh.Bytes()); !ok || p != "/through/the/probe/mount" {
		t.Errorf("hit = %q, %v, want the resolved name", p, ok)
	}

	c = newDirCache(16, w)
	c.fillPath(dir, func(fsID, int32, []byte) string { return "" })
	if p, ok := c.hit(id, fh.Type(), fh.Bytes()); ok {
		t.Errorf("an unresolved walk entry named a record without resolving: %q", p)
	}
	if p, ok := c.lookup(id, fh.Type(), fh.Bytes()); !ok || p != dir {
		t.Errorf("lookup = %q, %v, want the walk's path %q", p, ok, dir)
	}
}

// createRecord is a rename watch record of the creation of directory child
// as name in directory parent, on filesystem fsid, as a group with
// renameFlags reports it: the parent's DFID_NAME record, then the child's
// FID record.
func createRecord(fsid fsID, parent, name, child string) []byte {
	dn := buildDfidNameInfo(1, []byte(parent), name)
	fid := buildFidInfo(1, []byte(child))
	for _, r := range [][]byte{dn, fid} {
		binary.LittleEndian.PutUint32(r[4:8], uint32(fsid[0]))
		binary.LittleEndian.PutUint32(r[8:12], uint32(fsid[1]))
	}
	info := append(dn, fid...)
	return append(buildMetadata(unix.FAN_CREATE|unix.FAN_ONDIR, 1, uint16(len(info))), info...)
}

// A directory never cached is named through its creation: its parent's path,
// from the cache, from resolving its handle, or through the parent's own
// creation, joined to its name (P-37). A directory move on the filesystem
// after the creation drops it, as it drops the cache; a creation of a file,
// a malformed record or a parent that cannot be named names nothing.
func TestDirCache_ADirectoryNeverCachedIsNamedThroughItsCreation(t *testing.T) {
	a := fsID{1, 1}
	live := func(_ fsID, _ int32, h []byte) string {
		if string(h) == "tmp" {
			return "/tmp/claude-1000"
		}
		return ""
	}
	fileCreate := createRecord(a, "tmp", "probe", "f")
	binary.LittleEndian.PutUint64(fileCreate[8:16], unix.FAN_CREATE)
	short := buildMetadata(unix.FAN_CREATE|unix.FAN_ONDIR, 1, 0)
	for _, c := range []struct {
		name    string
		records [][]byte
		cached  map[string]string
		resolve handleResolver
		lookup  string
		want    string
	}{
		{"the parent resolves", [][]byte{createRecord(a, "tmp", "fswatch-probe-X", "d")}, nil, live, "d", "/tmp/claude-1000/fswatch-probe-X"},
		{"the parent is cached", [][]byte{createRecord(a, "p", "x", "d")}, map[string]string{"p": "/cached"}, nil, "d", "/cached/x"},
		{"through the parent's creation", [][]byte{createRecord(a, "tmp", "outer", "o"), createRecord(a, "o", "inner", "i")}, nil, live, "i", "/tmp/claude-1000/outer/inner"},
		{"a directory moved after", [][]byte{createRecord(a, "tmp", "x", "d"), moveRecord(a, true)}, nil, live, "d", ""},
		{"a directory moved before", [][]byte{moveRecord(a, true), createRecord(a, "tmp", "x", "d")}, nil, live, "d", "/tmp/claude-1000/x"},
		{"a file moved after", [][]byte{createRecord(a, "tmp", "x", "d"), moveRecord(a, false)}, nil, live, "d", "/tmp/claude-1000/x"},
		{"a file created", [][]byte{fileCreate}, nil, live, "f", ""},
		{"a record without handles", [][]byte{short}, nil, live, "d", ""},
		{"the parent cannot be named", [][]byte{createRecord(a, "gone", "x", "d")}, nil, live, "d", ""},
		{"another directory", [][]byte{createRecord(a, "tmp", "x", "d")}, nil, live, "e", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			w, records := pipeWatch(t, a)
			dirs := newDirCache(16, w)
			for k, p := range c.cached {
				dirs.fill(a, 1, []byte(k), p)
			}
			for _, r := range c.records {
				if _, err := unix.Write(records, r); err != nil {
					t.Fatal(err)
				}
			}
			got, ok := dirs.lookupResolving(a, 1, []byte(c.lookup), c.resolve)
			if got != c.want || ok != (c.want != "") {
				t.Errorf("lookup = %q, %v, want %q", got, ok, c.want)
			}
			if s := dirs.snapshot(); (s.Linked == 1) != (c.want != "") {
				t.Errorf("stats = %+v", s)
			}
		})
	}
}

// The recorded creations are bounded apart from the cache: the oldest is
// dropped, and no creation evicts a directory the probe resolved.
func TestDirCache_CreationsAreBoundedApartFromTheCache(t *testing.T) {
	a := fsID{1, 1}
	w, records := pipeWatch(t, a)
	dirs := newDirCache(2, w)
	dirs.fill(a, 1, []byte("r"), "/r")
	for _, d := range []string{"d1", "d2", "d3"} {
		if _, err := unix.Write(records, createRecord(a, "r", d, d)); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := dirs.lookup(a, 1, []byte("d1")); ok {
		t.Error("the oldest creation survived")
	}
	for _, d := range []string{"d2", "d3", "r"} {
		if _, ok := dirs.lookup(a, 1, []byte(d)); !ok {
			t.Errorf("%s was dropped", d)
		}
	}
	if s := dirs.snapshot(); s.Created != 3 || s.Evicted != 0 {
		t.Errorf("stats = %+v, want 3 created, none evicted", s)
	}
}

// The shape of the five unresolved events of the agent's tree in a capture of
// Claude Code 2.1.306 (P-37): the harness creates a directory under its
// temporary directory, writes a probe file in it twice and removes both, and
// the probe reads none of it until the directory is gone. Every record is
// named through the directory's creation. Unprivileged: inode marks, the
// main one placed on the new directory as the test creates it.
func TestKernelDirectoryCreatedAndRemovedBetweenReadsIsNamed(t *testing.T) {
	root := t.TempDir()
	watch := openRenameWatch([]string{root}, 0)
	if watch == nil || !watch.creates {
		t.Skip("rename watch: the kernel refused FAN_REPORT_TARGET_FID or an inode mark for FAN_CREATE | FAN_ONDIR")
	}
	dirs := newDirCache(dirCacheSize, watch)
	t.Cleanup(dirs.close)
	fd, err := unix.FanotifyInit(uint(unix.FAN_CLASS_NOTIF|reportFlags|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK), unix.O_RDONLY)
	if err != nil {
		t.Skipf("fanotify_init with the probe's flags: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	k := &kernelRig{t: t, fd: fd, root: root, dirs: dirs}
	dir := filepath.Join(root, "fswatch-probe-X")
	probe := filepath.Join(dir, "probe")
	k.do(
		func() error { return os.Mkdir(dir, 0o700) },
		func() error {
			return unix.FanotifyMark(fd, unix.FAN_MARK_ADD, watchMask|unix.FAN_EVENT_ON_CHILD, unix.AT_FDCWD, dir)
		},
		func() error { return os.WriteFile(probe, []byte("x"), 0o644) },
		func() error { return os.WriteFile(probe, []byte("y"), 0o644) },
		func() error { return os.Remove(probe) },
		func() error { return os.Remove(dir) },
	)
	k.read()
	if len(k.raws) == 0 {
		t.Fatal("no records")
	}
	obs := &Observer{events: make(chan models.GroundTruthEvent, 64), mountFD: -1}
	for i := range k.raws {
		if k.raws[i].Path != probe && k.raws[i].Path != dir {
			t.Errorf("record %#x named %q, want %s", k.raws[i].Mask, k.raws[i].Path, probe)
		}
		k.raws[i].PID = 1 // not the recorder's own
		obs.processRawEvent(&k.raws[i], time.Now())
	}
	if got := obs.CaptureCoverage().UnresolvedPaths; got != 0 {
		t.Errorf("UnresolvedPaths = %d, want 0", got)
	}
	if got := k.deletes(); strings.Join(got, "|") != "fswatch-probe-X/probe" {
		t.Errorf("deletes = %q", got)
	}
	if s := k.dirs.snapshot(); s.Linked == 0 || s.Created == 0 {
		t.Errorf("stats = %+v, want the records named through the creation", s)
	}
}

// As root, on the probe's filesystem-wide marks: a directory created, written
// in and removed by another process while the read loop is blocked, so that
// no record of it is read while it exists, has every file event named, the
// shape of Claude Code's file-watch probe directory in a capture whose read
// loop paused for a second (P-37).
func TestObserver_ADirectoryCreatedAndRemovedWhileTheReadLoopIsBlockedIsNamed(t *testing.T) {
	skipUnprivileged(t)
	dir := t.TempDir()
	obs := startBlockedObserver(t, dir)
	if !obs.DirCache().Watching {
		t.Fatal("the rename watch marked nothing")
	}
	for _, f := range []string{"a", "b"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(200 * time.Millisecond) // the read loop reads the writes, then blocks
	sub := filepath.Join(dir, "fswatch-probe-X")
	probe := filepath.Join(sub, "probe")
	script := `mkdir "$1" && printf x > "$1/probe" && printf y >> "$1/probe" && rm "$1/probe" && rmdir "$1"`
	if out, err := exec.Command("sh", "-c", script, "sh", sub).CombinedOutput(); err != nil {
		t.Fatalf("sh: %v\n%s", err, out)
	}
	events := drainAll(t, obs)
	for _, a := range []models.ActionType{models.FileWrite, models.FileOpen, models.FileClose, models.FileDelete} {
		assertHasNamedEvent(t, events, a, probe)
	}
	if obs.DirCache().Linked == 0 {
		t.Errorf("dir cache %+v: nothing was named through a creation", obs.DirCache())
	}
	t.Logf("dir cache %+v, unresolved %d", obs.DirCache(), obs.CaptureCoverage().UnresolvedPaths)
}
