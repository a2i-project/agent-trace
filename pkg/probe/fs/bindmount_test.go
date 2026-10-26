package fs

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/agent-trace/agent-trace/pkg/matching"
	"github.com/agent-trace/agent-trace/pkg/models"
)

// A file reached through a bind mount and through its source path (P-30).
// The filesystem mark covers every mount of the filesystem, and a record
// carries the filesystem id, the directory's handle and the entry's name,
// which are the same whichever path a process used, so nothing in it says
// which path that was. The probe names both writes through the one mount it
// resolves the filesystem's handles with, the first one marked: here the
// tmpfs's own mount, whose path holds the source. The workspace is given as
// the alias, as an agent running inside the bind would see it, and the start
// walk caches the alias under the same name. A claim naming the alias does
// not match the event by path, but it does through the mount table the probe
// recorded (P-33, V-46), and a claim naming another file through the alias
// does not.
func TestObserver_ABindMountAliasIsNamedThroughTheProbesMount(t *testing.T) {
	skipUnprivileged(t)
	root := t.TempDir()
	fsDir, alias := filepath.Join(root, "fs"), filepath.Join(root, "alias")
	for _, d := range []string{fsDir, alias} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// A filesystem of its own, so that the mount marked first for it is
	// known whatever the host's mount table holds.
	if err := unix.Mount("agent-trace-bind", fsDir, "tmpfs", 0, "size=1m"); err != nil {
		t.Skipf("mount tmpfs: %v", err)
	}
	t.Cleanup(func() { _ = unix.Unmount(fsDir, unix.MNT_DETACH) })
	src := filepath.Join(fsDir, "src")
	if err := os.Mkdir(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(src, alias, "", unix.MS_BIND, ""); err != nil {
		t.Skipf("bind mount: %v", err)
	}
	t.Cleanup(func() { _ = unix.Unmount(alias, unix.MNT_DETACH) })

	obs, err := New(Config{Path: alias, AllFilesystems: true, PIDFilter: int32(os.Getpid()), EventBufSize: 256})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	marked, _ := obs.Scope()
	t.Logf("marked %v", marked)
	if !slices.Contains(marked, fsDir) || slices.Contains(marked, alias) {
		t.Errorf("marked %v, want the filesystem marked once, by %s", marked, fsDir)
	}
	obs.Start()
	time.Sleep(50 * time.Millisecond)

	viaAlias, viaSource := filepath.Join(alias, "via-alias.txt"), filepath.Join(src, "via-source.txt")
	if err := os.WriteFile(viaAlias, []byte("a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(viaSource, []byte("s\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	events := collectEvents(obs, 300*time.Millisecond)
	if err := obs.Stop(); err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		t.Logf("%s %s", e.ActionType, e.Target)
	}

	assertHasNamedEvent(t, events, models.FileWrite, filepath.Join(src, "via-alias.txt"))
	assertHasNamedEvent(t, events, models.FileWrite, viaSource)
	for _, e := range events {
		if strings.HasPrefix(e.Target, alias+"/") {
			t.Errorf("%s %s is named through the alias", e.ActionType, e.Target)
		}
	}
	claim := models.TrajectoryEntry{ActionType: models.FileWrite, Target: viaAlias}
	for _, e := range events {
		if e.ActionType == models.FileWrite && matching.TargetsMatch(claim, e) {
			t.Errorf("a claim through the alias matched %s by path alone", e.Target)
		}
	}

	table, changed := obs.MountTable()
	if table == nil || changed == nil {
		t.Fatalf("mount table %v, changed %v: want both recorded", table != nil, changed)
	}
	var fsMounts *models.FSMounts
	for i := range table {
		for _, m := range table[i].Mounts {
			if m.Point == fsDir {
				fsMounts = &table[i]
			}
		}
	}
	if fsMounts == nil {
		t.Fatalf("no filesystem in the table is mounted at %s", fsDir)
	}
	for _, m := range fsMounts.Mounts {
		t.Logf("table: %s id %d parent %d root %s at %s names %v", fsMounts.Device, m.ID, m.Parent, m.Root, m.Point, m.Names)
		switch m.Point {
		case fsDir:
			if m.Root != "/" || !m.Names {
				t.Errorf("tmpfs mount recorded as %+v, want root / and names", m)
			}
		case alias:
			if m.Root != "/src" || m.Names {
				t.Errorf("alias recorded as %+v, want root /src and not names", m)
			}
		}
	}
	if *changed {
		// Another process changed the namespace's mount table while the
		// capture ran; the table is then not trusted (V-46).
		if matching.NewMounts(&models.FSScope{Filesystems: table, MountTableChanged: changed}) != nil {
			t.Error("a table that changed during the capture was trusted")
		}
		t.Skip("the mount table changed during the capture; the alias match is not checked")
	}
	mounts := matching.NewMounts(&models.FSScope{Filesystems: table, MountTableChanged: changed})
	if mounts == nil {
		t.Fatal("the recorded table was not usable")
	}
	corroborated := false
	for _, e := range events {
		if e.ActionType == models.FileWrite && mounts.TargetsMatch(claim, e) {
			corroborated = true
			if e.Target != filepath.Join(src, "via-alias.txt") {
				t.Errorf("the alias claim matched %s", e.Target)
			}
		}
	}
	if !corroborated {
		t.Error("the claim naming the alias was not matched through the mount table")
	}
	other := models.TrajectoryEntry{ActionType: models.FileWrite, Target: filepath.Join(alias, "via-source.txt.other")}
	sameSuffix := models.TrajectoryEntry{ActionType: models.FileWrite, Target: filepath.Join(alias, "sub", "via-source.txt")}
	for _, e := range events {
		for _, c := range []models.TrajectoryEntry{other, sameSuffix} {
			if mounts.TargetsMatch(c, e) {
				t.Errorf("claim %s matched %s %s", c.Target, e.ActionType, e.Target)
			}
		}
	}
}

// A file outside the bind of a subdirectory the probe names its filesystem
// through has no name through that mount: readlink of its handle opened
// there gives "/" (P-33). The probe must leave it unnamed, not name it "/"
// or a directory entry under "/", which would be the name of another file.
// The filesystem's own mount is detached after a directory outside the bind
// is opened, so the bind is the only mount of the filesystem and the probe's.
func TestObserver_AFileOutsideTheProbesBindIsNotNamed(t *testing.T) {
	skipUnprivileged(t)
	root := t.TempDir()
	fsDir, ws := filepath.Join(root, "fs"), filepath.Join(root, "ws")
	for _, d := range []string{fsDir, ws} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := unix.Mount("agent-trace-escape", fsDir, "tmpfs", 0, "size=1m"); err != nil {
		t.Skipf("mount tmpfs: %v", err)
	}
	detached := false
	t.Cleanup(func() {
		if !detached {
			_ = unix.Unmount(fsDir, unix.MNT_DETACH)
		}
	})
	for _, d := range []string{"src", "other"} {
		if err := os.Mkdir(filepath.Join(fsDir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := unix.Mount(filepath.Join(fsDir, "src"), ws, "", unix.MS_BIND, ""); err != nil {
		t.Skipf("bind mount: %v", err)
	}
	t.Cleanup(func() { _ = unix.Unmount(ws, unix.MNT_DETACH) })
	outside, err := unix.Open(filepath.Join(fsDir, "other"), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(outside) }()
	if err := unix.Unmount(fsDir, unix.MNT_DETACH); err != nil {
		t.Fatalf("detach the tmpfs mount: %v", err)
	}
	detached = true

	obs, err := New(Config{Path: ws, PIDFilter: int32(os.Getpid()), EventBufSize: 256})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	obs.Start()
	time.Sleep(50 * time.Millisecond)

	inside := filepath.Join(ws, "inside.txt")
	if err := os.WriteFile(inside, []byte("i\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Openat(outside, "outside.txt", unix.O_CREAT|unix.O_WRONLY|unix.O_CLOEXEC, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unix.Write(fd, []byte("o\n")); err != nil {
		t.Fatal(err)
	}
	_ = unix.Close(fd)
	events := collectEvents(obs, 300*time.Millisecond)
	if err := obs.Stop(); err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		t.Logf("%s %q", e.ActionType, e.Target)
	}

	assertHasNamedEvent(t, events, models.FileWrite, inside)
	for _, e := range events {
		if e.Target != "" && e.Target != ws && !strings.HasPrefix(e.Target, ws+"/") {
			t.Errorf("%s named %q, outside the probe's mount %s", e.ActionType, e.Target, ws)
		}
	}
}
