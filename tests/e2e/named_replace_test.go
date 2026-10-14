package e2e

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/agent/claudecode"
	"github.com/agent-trace/agent-trace/pkg/content"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/probe"
	"github.com/agent-trace/agent-trace/pkg/probe/fs"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// A Write over an existing file as Claude Code makes it (I-22): read the file,
// write a temporary named <path>.tmp.<pid>.<12 hex>, rename it over the file.
// Under the real fs probe every event names the temporary or the target
// (P-25), and the adapter folds them into the claim's shape (I-56): one open
// and one write of the target carrying the new content's hash. The claims of
// an honest Write verify FAITHFUL, and a Write claimed with other content is
// NOT FAITHFUL. This test process plays the harness, so its pid is the root.
func TestNamedReplaceFoldsUnderTheProbe(t *testing.T) {
	skipUnprivileged(t)
	ws := t.TempDir()
	target := filepath.Join(ws, "report.txt")
	if err := os.WriteFile(target, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	obs, err := fs.New(fs.Config{Path: ws, PathFilter: ws, PIDFilter: int32(os.Getpid()), EventBufSize: 4096})
	if err != nil {
		t.Fatalf("fs.New: %v", err)
	}
	obs.Start()
	time.Sleep(200 * time.Millisecond)
	begin := time.Now()

	if _, err := os.ReadFile(target); err != nil {
		t.Fatal(err)
	}
	tmp := target + ".tmp." + "4242.0123456789ab"
	if err := os.WriteFile(tmp, []byte("new\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, target); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if err := obs.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	var g models.GroundTruth
	for e := range obs.Events() {
		if !e.Timestamp.Before(begin) {
			g = append(g, e)
		}
	}
	sort.SliceStable(g, func(i, j int) bool { return g[i].Timestamp.Before(g[j].Timestamp) })
	logAmbiguous(t, g)
	var raw []string
	for _, e := range g {
		raw = append(raw, string(e.ActionType)+" "+strings.TrimPrefix(e.Target, ws+"/"))
	}
	t.Logf("probe: %v", raw)

	folded := claudecode.Adapter{}.NormalizeStream(g)
	var got []string
	for _, e := range folded {
		got = append(got, string(e.ActionType)+" "+strings.TrimPrefix(e.Target, ws+"/"))
	}
	if strings.Join(got, "|") != "file_open report.txt|file_write report.txt" {
		t.Fatalf("folded: %v, want one open and one write of report.txt", got)
	}
	want := content.SHA256Bytes([]byte("new\n"))
	if w := folded[1]; w.OutputHash == nil || *w.OutputHash != want {
		t.Errorf("folded write carries %v, want %s", w.OutputHash, want)
	}

	claims := func(hash string) models.Trajectory {
		return models.Trajectory{
			{Timestamp: begin, ActionType: models.FileOpen, Target: target, Tool: "Write"},
			{Timestamp: begin, ActionType: models.FileWrite, Target: target, OutputHash: &hash, Tool: "Write"},
		}
	}
	file := models.GroundTruthFile{Events: g, RootPID: uint32(os.Getpid()),
		Coverage: coverageOf(map[string]probe.CoverageReporter{"fs": obs})}
	if v := verification.Verify(agent.Prepare(claudecode.Adapter{}, claims(want), file, nil, verification.Options{})); v.Outcome != verification.OutcomeFaithful {
		t.Errorf("honest Write: outcome %s", v.Outcome)
		logVerdict(t, v)
	}
	if v := verification.Verify(agent.Prepare(claudecode.Adapter{}, claims(content.SHA256Bytes([]byte("benign\n"))), file, nil, verification.Options{})); v.Outcome != verification.OutcomeNotFaithful {
		t.Errorf("Write claimed with other content: outcome %s, want NOT FAITHFUL", v.Outcome)
		logVerdict(t, v)
	}
}
