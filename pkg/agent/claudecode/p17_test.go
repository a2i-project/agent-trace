package claudecode

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// The P-17 capture of Claude Code 2.1.286 (2026-10-09) is the basic task recorded
// after the fs probe began marking every real filesystem (P-17), with five
// control runs: the capture script's default, and the only checked-in capture
// with that many. It is the evidence behind V-24's defaults: a baseline at an
// agreement of 1/N (0.2 here) explains the harness's own activity across the
// whole filesystem, and the task verifies FAITHFUL. It predates N-20 to N-22, so
// it holds address rules where a capture taken now records net_dial and net_dns.
// Reduced by scripts/make-capture-fixture.py, which also redacted the account's
// organisation id.
const p17Dir = "testdata/paired-2.1.286-p17"

func p17Run(t *testing.T, label string) models.GroundTruthFile {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(p17Dir, label+".ground_truth.json"))
	if err != nil {
		t.Fatal(err)
	}
	f, err := models.ParseGroundTruthFile(data)
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	return f
}

func p17Controls(t *testing.T) []models.GroundTruthFile {
	t.Helper()
	paths, _ := filepath.Glob(filepath.Join(p17Dir, "control-*.ground_truth.json"))
	var runs []models.GroundTruthFile
	for _, p := range paths {
		runs = append(runs, p17Run(t, strings.TrimSuffix(filepath.Base(p), ".ground_truth.json")))
	}
	return runs
}

func p17Verdict(t *testing.T, agreement float64) (verification.Verdict, models.Trajectory, agent.Baseline) {
	t.Helper()
	tr, rep, err := Adapter{}.Parse(filepath.Join(p17Dir, "basic.session.jsonl"))
	if err != nil || len(rep.ParseErrors) != 0 || len(rep.UnknownTools) != 0 {
		t.Fatalf("parse: %v %+v", err, rep)
	}
	b, err := agent.Capture(Adapter{}, "2.1.286", p17Controls(t), time.Now(), agent.CaptureOptions{Exclude: []string{controlCommand}, MinAgreement: agreement})
	if err != nil {
		t.Fatal(err)
	}
	g := p17Run(t, "basic")
	return verification.Verify(agent.Prepare(Adapter{}, tr, g, b.Predicate(g.Workspace), verification.Options{IntervalSlack: 500 * time.Millisecond})), tr, b
}

func TestP17CaptureHasFiveControlsAndNoEventLoss(t *testing.T) {
	runs := p17Controls(t)
	if len(runs) != 5 {
		t.Fatalf("%d controls, want five", len(runs))
	}
	for i, r := range append(runs, p17Run(t, "basic")) {
		if c := verification.Assess(r.Coverage); !c.Complete {
			t.Errorf("run %d: %v", i, c.Reasons)
		}
		if r.FSScope == nil || r.FSScope.Rule != "tree-or-workspace" {
			t.Errorf("run %d: fs scope %+v, want the P-17 rule", i, r.FSScope)
		}
	}
}

// V-24's default: with five controls and an agreement of 1/5, the basic task
// verifies FAITHFUL, every claim corroborated and the harness's activity across
// the filesystem explained by the baseline.
func TestP17TaskVerifiesFaithfulAtTheDefaultAgreement(t *testing.T) {
	v, tr, b := p17Verdict(t, 0.2)
	if v.Outcome != verification.OutcomeFaithful {
		t.Fatalf("outcome = %s\nunwitnessed=%v\nunrecorded=%v\nmismatched=%v\nunexplained subtrees=%d harness=%d reasons=%v",
			v.Outcome, v.Unwitnessed, v.Unrecorded, v.Mismatched, len(v.Coverage.UnexplainedSubtrees), len(v.UnexplainedHarness), v.Reasons)
	}
	if len(v.Corroborated) != len(tr) || len(tr) != 7 {
		t.Errorf("corroborated %d of %d claims, want all 7", len(v.Corroborated), len(tr))
	}
	if v.Coverage.Baselined < 300 {
		t.Errorf("only %d events explained by the baseline: a P-17 capture sees the harness across the filesystem", v.Coverage.Baselined)
	}
	if b.Runs != 5 || b.MinAgreement != 0.2 {
		t.Errorf("baseline from %d runs at %v", b.Runs, b.MinAgreement)
	}
}

// At full agreement the baseline keeps only what all five controls did. The
// task then shows two directory-level renames of the home directory as
// unrecorded: the harness rewrites ~/.claude.json through a temporary and a
// rename, which the kernel reports on the directory, outside the directories the
// adapter declares as the harness's own (V-24), so they are not set aside. An
// honest run reads NOT FAITHFUL. This pins the behaviour exactly, so a change is
// seen: every claim agrees, and the only findings are those renames. Open as
// ADP-13 (local todo); the capture script's default of 1/N avoids it.
func TestP17TaskAtFullAgreementFlagsOnlyTheHomeDirectoryRenames(t *testing.T) {
	v, tr, _ := p17Verdict(t, 1)
	if len(v.Corroborated) != len(tr) || len(v.Mismatched) != 0 || len(v.Unwitnessed) != 0 || len(v.Coverage.UnexplainedSubtrees) != 0 {
		t.Fatalf("corroborated=%d mismatched=%d unwitnessed=%d subtrees=%d: something other than the known renames changed",
			len(v.Corroborated), len(v.Mismatched), len(v.Unwitnessed), len(v.Coverage.UnexplainedSubtrees))
	}
	for _, e := range v.Unrecorded {
		if e.ActionType != models.FileRename || e.Target != "/home/user" || !e.PathIsAmbiguous {
			t.Errorf("unexpected unrecorded event %s %s (ambiguous %v)", e.ActionType, e.Target, e.PathIsAmbiguous)
		}
	}
	t.Logf("full agreement: %s, %d unrecorded home-directory rename(s)", v.Outcome, len(v.Unrecorded))
}
