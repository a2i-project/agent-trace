package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The session id the capture recorded (<label>.session-id.txt, I-110)
// decides the trace in the analysis as in the capture script's own verify
// runs (I-127): the manifest's path first, else the file in the run
// directory; a run without the file keeps the id the record states. On the
// Codex fixture the declared main file is the recorded session's rollout.
func TestTheRecordedSessionIDDecidesTheTrace(t *testing.T) {
	const thread = "01a19455-d74e-72a2-99d3-367c07be5a85"
	const other = "00000000-0000-0000-0000-000000000001"
	src := fixtureDir(t, "codex/testdata/paired-codex-0.166.0-basic")
	dir := syntheticCampaign(t, []fixtureRun{{"codex", "0.166.0", "basic", 1, "", "ok"}})
	run := filepath.Join(dir, "codex-0.166.0", "basic", "run-01")
	if err := os.MkdirAll(run, 0o755); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(src)
	for _, e := range entries {
		if err := os.Symlink(filepath.Join(src, e.Name()), filepath.Join(run, e.Name())); err != nil {
			t.Fatal(err)
		}
	}
	c, err := LoadCampaign(dir)
	if err != nil {
		t.Fatal(err)
	}
	load := func(rec RunRecord) *Session {
		t.Helper()
		s, err := LoadSession(c, rec)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	rec := c.Manifest.Runs[0]
	s := load(rec)
	if s.SessionID != "" || s.Report.TraceSession != thread {
		t.Fatalf("without the file: recorded %q, stated %q", s.SessionID, s.Report.TraceSession)
	}
	var rollout string
	for _, e := range s.G.Events {
		if strings.Contains(e.Target, "/rollout-") && strings.HasSuffix(e.Target, thread+".jsonl") {
			rollout = e.Target
			break
		}
	}
	if rollout == "" {
		t.Fatal("the capture names no rollout of the session")
	}
	main := func(s *Session) bool { return s.input(s.Claims, nil).Trace.Decl.Main(rollout) }
	if !main(s) {
		t.Errorf("without the file the stated session's rollout is not the main file")
	}

	write := func(name, id string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(run, name), []byte(id+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("basic.session-id.txt", other)
	if s = load(rec); s.SessionID != other || main(s) {
		t.Errorf("the run directory's file: recorded %q, the stated session's rollout still main %v", s.SessionID, main(s))
	}
	write("basic.session-id.txt", thread)
	if s = load(rec); s.SessionID != thread || !main(s) {
		t.Errorf("the record's own id: recorded %q, main %v", s.SessionID, main(s))
	}

	// The manifest's path wins over the default name.
	write("named.session-id.txt", other)
	named := filepath.Join(run, "named.session-id.txt")
	rec.Paths = map[string]*string{"session_id": &named}
	if s = load(rec); s.SessionID != other {
		t.Errorf("the manifest's path: recorded %q", s.SessionID)
	}
}
