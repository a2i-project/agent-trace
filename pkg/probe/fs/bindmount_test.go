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
// which are the same whichever path the process used, so nothing in it says
// which path that was. The probe names both writes through the one mount it
// resolves the filesystem's handles with, the first one marked: here the
// tmpfs's own mount, whose path holds the source. The workspace is given as
// the alias, as an agent running inside the bind would see it, and the start
// walk caches the alias under the same name. A claim naming the alias does
// not match the event, which is the known limit this pins.
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
			t.Errorf("a claim through the alias matched %s; the known limit in 12_probe_fs.md no longer holds", e.Target)
		}
	}
}
