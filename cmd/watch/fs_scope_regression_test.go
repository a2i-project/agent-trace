package main

import (
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/probe/fs"
)

// Item 5 of the security review of 2026-10-08: watch marked only the filesystem
// holding the workspace and filtered file events to the workspace prefix, so
// an agent's write anywhere else (a dotfile in the home directory, a separate
// tmpfs /tmp) was never observed. P-17 (commit 78abc12) made the fs probe mark
// every real filesystem and filter nothing by path, leaving the tree-or-
// workspace rule to scopeFSEvents. TestScopeFSEvents_KeepsTheTreeAnywhereAndTheWorkspaceForEveryone
// checks the rule and TestObserver_AllFilesystemsSeesASecondMount the probe;
// this test checks that the probe watch actually builds is configured that
// way: it marks more than the workspace's filesystem, and it reports a write
// outside the workspace.
func TestFSProbeBuilderSeesWritesOutsideTheWorkspace(t *testing.T) {
	skipUnprivileged(t)
	ws, elsewhere := t.TempDir(), t.TempDir()
	o, err := probeBuilders["fs"](watchConfig{Workspace: ws, EventBufSize: 4096})
	if err != nil {
		t.Fatalf("fs builder: %v", err)
	}
	obs, ok := o.(*fs.Observer)
	if !ok {
		t.Fatalf("fs builder returned %T", o)
	}
	if marked, _ := obs.Scope(); len(marked) == 0 || slices.Equal(marked, []string{ws}) {
		t.Errorf("marked = %v: only the workspace's filesystem, want every real filesystem (P-17)", marked)
	}

	// The probe filters nothing, so it reports the whole host; drain it all,
	// since its sends block, and note the one write the test makes.
	target := filepath.Join(elsewhere, "outside-the-workspace.txt")
	seen := make(chan struct{})
	var once sync.Once
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for e := range o.Events() {
			if e.Target == target && e.ActionType == models.FileWrite {
				once.Do(func() { close(seen) })
			}
		}
	}()
	o.Start()
	time.Sleep(100 * time.Millisecond)
	if err := os.WriteFile(target, []byte("outside\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// CI sets the bound, not the dev box: a contended runner reads the queue late.
	select {
	case <-seen:
	case <-time.After(5 * time.Second):
		t.Errorf("no file_write of %s, outside the workspace %s: the probe watch builds does not observe the agent there", target, ws)
	}
	if err := o.Stop(); err != nil {
		t.Errorf("Stop: %v", err)
	}
	<-drained
}
