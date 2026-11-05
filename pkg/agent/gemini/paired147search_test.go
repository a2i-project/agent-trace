package gemini

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

// The search task of the first parity campaign with agy 1.4.7 (2026-11-05),
// recorded by scripts/capture-campaign.sh with request content, model
// gemini-3.8-flash-high and five controls, and reduced by
// scripts/make-capture-fixture.py (I-133). Its six calls are those of
// paired-agy-1.3.4-search: list_dir, grep_search of seed, find_by_name,
// write_to_file of m.txt, multi_replace_file_content (refused as an unknown
// tool, status 4) and run_command cat m.txt. The grep_search ran the
// embedded ripgrep, whose exec failed and which has no exit record (P-31),
// then the fallback grep; the task run lasted over a minute, so the flag
// client's metrics POST at 60 s is in it and in no control (V-93).
const paired147SearchDir = "testdata/paired-agy-1.4.7-search"

func paired147SearchRun(t *testing.T, label string) models.GroundTruthFile {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(paired147SearchDir, label+".ground_truth.json"))
	if err != nil {
		t.Fatal(err)
	}
	f, err := models.ParseGroundTruthFile(data)
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	return f
}

func paired147SearchControls(t *testing.T) []models.GroundTruthFile {
	t.Helper()
	paths, _ := filepath.Glob(filepath.Join(paired147SearchDir, "control-*.ground_truth.json"))
	var runs []models.GroundTruthFile
	for _, p := range paths {
		runs = append(runs, paired147SearchRun(t, strings.TrimSuffix(filepath.Base(p), ".ground_truth.json")))
	}
	return runs
}

func paired147SearchClaims(t *testing.T) (models.Trajectory, agent.Report) {
	t.Helper()
	tr, rep, err := Adapter{}.Parse(filepath.Join(paired147SearchDir, "search.conversation.db"))
	if err != nil || len(rep.ParseErrors) != 0 || len(rep.UnknownTools) != 0 {
		t.Fatalf("parse: %v %+v", err, rep)
	}
	return tr, rep
}

// paired147SearchVerdict verifies as cmd/verify does, with the version
// given (--agent-version) or not, and a baseline from the five controls at
// the agreement (none at 0).
func paired147SearchVerdict(t *testing.T, a agent.Adapter, version string, tr models.Trajectory, agreement float64) (verification.Verdict, int) {
	t.Helper()
	g := paired147SearchRun(t, "search")
	var measured verification.Baseline
	rules := 0
	if agreement > 0 {
		b, err := agent.Capture(Adapter{}, "1.4.7", paired147SearchControls(t), time.Now(), agent.CaptureOptions{Exclude: []string{controlCommand}, MinAgreement: agreement})
		if err != nil {
			t.Fatal(err)
		}
		measured, rules = b.Predicate(g.Workspace), len(b.Rules)
	}
	in := agent.Prepare(a, tr, g, measured, verification.Options{IntervalSlack: 500 * time.Millisecond})
	v := agent.DeclarationVersion("", version)
	in.Options.HarnessHousekeeping = agent.HarnessHousekeeping(a, v)
	in.Options.HarnessBookkeeping = agent.HarnessBookkeeping(a, v, g)
	return verification.Verify(in), rules
}

func TestPaired147SearchHasFiveControlsAndNoEventLoss(t *testing.T) {
	runs := paired147SearchControls(t)
	if len(runs) != 5 {
		t.Fatalf("%d controls, want five", len(runs))
	}
	for i, r := range append(runs, paired147SearchRun(t, "search")) {
		if c := verification.Assess(r.Coverage); !c.Complete {
			t.Errorf("run %d: %v", i, c.Reasons)
		}
	}
}

// At every agreement the five controls give 279 rules, the five claims are
// corroborated, the search on its folder, and with the capture's version
// the flag metrics are declared housekeeping, so the run is FAITHFUL. This
// pins the counts, so a change is seen.
func TestPaired147SearchAtEachAgreement(t *testing.T) {
	tr, rep := paired147SearchClaims(t)
	if len(tr) != 5 || rep.ToolCalls != 6 {
		t.Fatalf("%d claims of %d calls, want 5 of 6", len(tr), rep.ToolCalls)
	}
	for _, a := range []float64{0.2, 0.4, 0.6, 0.8, 1} {
		v, rules := paired147SearchVerdict(t, Adapter{}, "1.4.7", tr, a)
		if rules != 279 {
			t.Errorf("agreement %v: %d rules, want 279", a, rules)
		}
		var search string
		for _, p := range v.Corroborated {
			if p.Entry.Tool == toolGrepSearch {
				search = p.Event.Target
			}
		}
		if len(v.Corroborated) != 5 || search != SearchGrep+" /ws/search" {
			t.Errorf("agreement %v: corroborated %d, the search on %q", a, len(v.Corroborated), search)
		}
		if got := renderNet(v.HarnessHousekeeping); got != "net_request POST https://antigravity-unleash.goog/api/client/metrics" {
			t.Errorf("agreement %v: declared housekeeping %q, want the flag metrics", a, got)
		}
		if v.Findings() != 0 || len(v.UnexplainedHarness) != 0 || len(v.UnexplainedHarnessNet) != 0 || len(v.Coverage.UnexplainedSubtrees) != 0 || v.Outcome != verification.OutcomeFaithful {
			t.Errorf("agreement %v: %d findings, unrecorded %v, %d harness events, %d unexplained subtrees, outcome %s; want FAITHFUL",
				a, v.Findings(), v.Unrecorded, len(v.UnexplainedHarness), len(v.Coverage.UnexplainedSubtrees), v.Outcome)
		}
	}
	// Without the version nothing is declared and the POST is Unrecorded.
	v, _ := paired147SearchVerdict(t, Adapter{}, "", tr, 0.2)
	if v.Outcome != verification.OutcomeNotFaithful || len(v.Unrecorded) != 1 || v.Unrecorded[0].Target != flagMetrics.Target {
		t.Errorf("no version: outcome %s, unrecorded %v", v.Outcome, v.Unrecorded)
	}
}

// The ripgrep's process takes the claim, and the fallback grep is beneath
// it; without the stream normalization the grep is an unclaimed command and
// the claim a mismatch, and a trajectory that leaves the search out is
// caught at the ripgrep's exec.
func TestPaired147SearchFoldsTheGrepUnderTheRipgrep(t *testing.T) {
	g := paired147SearchRun(t, "search")
	var rgs int
	for _, e := range g.Events {
		if e.ActionType == models.ProcessExec && searchOf(e.Target).form == ripgrepSearch {
			rgs++
			if e.Image != nil {
				t.Errorf("the ripgrep's exec took effect: %+v", e.Image)
			}
		}
		if e.ActionType == models.ProcessExit && searchOf(e.Target).form == ripgrepSearch {
			t.Error("the ripgrep has an exit record")
		}
	}
	if rgs != 1 {
		t.Fatalf("%d ripgrep execs, want 1", rgs)
	}
	tr, _ := paired147SearchClaims(t)
	f := verification.BuildForest(agent.NormalizeCapture(Adapter{}, g), g.RootPID)
	var under int
	for _, e := range g.Events {
		if e.ActionType == models.ProcessExec && searchOf(e.Target).form == grepSearch {
			if a := f.Attribute(e); a.Level == 2 && a.Command != nil && a.Command.Exec != nil && a.Command.Exec.Target == SearchGrep+" /ws/search" {
				under++
			}
		}
	}
	if under != 1 {
		t.Errorf("the grep is beneath the search %d times, want 1", under)
	}
	if v, _ := paired147SearchVerdict(t, rawAdapter{}, "1.4.7", tr, 0.2); v.Outcome != verification.OutcomeNotFaithful || len(v.Mismatched) != 1 {
		t.Errorf("without the fold: outcome %s, mismatched %v", v.Outcome, v.Mismatched)
	}
	var omitted models.Trajectory
	for _, e := range tr {
		if e.Tool != toolGrepSearch {
			omitted = append(omitted, e)
		}
	}
	if v, _ := paired147SearchVerdict(t, Adapter{}, "1.4.7", omitted, 0.2); v.Outcome != verification.OutcomeNotFaithful || len(v.Unrecorded) != 1 || v.Unrecorded[0].Target != SearchGrep+" /ws/search" {
		t.Errorf("omitting the search: outcome %s, unrecorded %v", v.Outcome, v.Unrecorded)
	}
}
