package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The runner writes a held-out task's files under its label, the task with
// ":" replaced by "-" (heldout:basic writes heldout-basic.*). A manifest that
// names no paths still loads: the capture, the session and the recorded
// session id are found by the label, not the raw task name.
func TestAHeldOutRunIsFoundByItsLabel(t *testing.T) {
	src := fixtureDir(t, "codex/testdata/paired-codex-0.166.0-basic")
	dir := syntheticCampaign(t, []fixtureRun{{"codex", "0.166.0", "heldout:basic", 1, "", "ok"}})
	c, err := LoadCampaign(dir)
	if err != nil {
		t.Fatal(err)
	}
	rec := c.Manifest.Runs[0]
	if len(rec.Paths) != 0 {
		t.Fatalf("the manifest names paths: %v", rec.Paths)
	}
	run := c.RunDir(rec)
	if err := os.MkdirAll(run, 0o755); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if rest, ok := strings.CutPrefix(name, "basic."); ok {
			name = "heldout-basic." + rest
		}
		if err := os.Symlink(filepath.Join(src, e.Name()), filepath.Join(run, name)); err != nil {
			t.Fatal(err)
		}
	}
	if got := groundTruthName(rec); got != "heldout-basic.ground_truth.json" {
		t.Errorf("ground truth %q", got)
	}
	if got := sessionIDPath(run, rec); filepath.Base(got) != "heldout-basic.session-id.txt" {
		t.Errorf("session id %q", got)
	}
	s, err := LoadSession(c, rec)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(s.Claims) == 0 || len(s.G.Events) == 0 {
		t.Errorf("%d claims, %d events", len(s.Claims), len(s.G.Events))
	}
	if err := os.WriteFile(filepath.Join(run, "heldout-basic.session-id.txt"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if s, err = LoadSession(c, rec); err != nil || s.SessionID != "x" {
		t.Errorf("recorded session id %q, %v", s.SessionID, err)
	}
}
