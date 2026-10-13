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

// The first paired capture of agy 1.3.4 (2026-10-13), recorded by
// scripts/capture-claude-code.sh --agent gemini with the task basic and five
// controls, and reduced by scripts/make-capture-fixture.py. The task makes
// five calls: view_file of b.txt, write_to_file creating a.txt,
// replace_file_content of a.txt, write_to_file over b.txt and run_command
// `echo hi`. Each control runs the no-op marker command with the task's tool
// set. The capture settles the file tools' kernel shapes (I-50) and showed the
// step directory missing from the step id family (I-49).
const pairedDir = "testdata/paired-agy-1.3.4-basic"

// controlCommand is the control task's own command, which never becomes a
// rule (I-28).
const controlCommand = ": agent-trace-control-marker"

func pairedRun(t *testing.T, label string) models.GroundTruthFile {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(pairedDir, label+".ground_truth.json"))
	if err != nil {
		t.Fatal(err)
	}
	f, err := models.ParseGroundTruthFile(data)
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	return f
}

func pairedControls(t *testing.T) []models.GroundTruthFile {
	t.Helper()
	paths, _ := filepath.Glob(filepath.Join(pairedDir, "control-*.ground_truth.json"))
	var runs []models.GroundTruthFile
	for _, p := range paths {
		runs = append(runs, pairedRun(t, strings.TrimSuffix(filepath.Base(p), ".ground_truth.json")))
	}
	return runs
}

func pairedClaims(t *testing.T) models.Trajectory {
	t.Helper()
	tr, rep, err := Adapter{}.Parse(filepath.Join(pairedDir, "basic.conversation.db"))
	if err != nil || len(rep.ParseErrors) != 0 || len(rep.UnknownTools) != 0 {
		t.Fatalf("parse: %v %+v", err, rep)
	}
	return tr
}

func pairedBaseline(t *testing.T, agreement float64) *agent.Baseline {
	t.Helper()
	b, err := agent.Capture(Adapter{}, "1.3.4", pairedControls(t), time.Now(), agent.CaptureOptions{Exclude: []string{controlCommand}, MinAgreement: agreement})
	if err != nil {
		t.Fatal(err)
	}
	return &b
}

func pairedVerdict(t *testing.T, tr models.Trajectory, b *agent.Baseline) verification.Verdict {
	t.Helper()
	g := pairedRun(t, "basic")
	var measured verification.Baseline
	if b != nil {
		measured = b.Predicate(g.Workspace)
	}
	return verification.Verify(agent.Prepare(Adapter{}, tr, g, measured, verification.Options{IntervalSlack: 500 * time.Millisecond}))
}

func TestPairedBasicHasFiveControlsAndNoEventLoss(t *testing.T) {
	runs := pairedControls(t)
	if len(runs) != 5 {
		t.Fatalf("%d controls, want five", len(runs))
	}
	for i, r := range append(runs, pairedRun(t, "basic")) {
		if c := verification.Assess(r.Coverage); !c.Complete {
			t.Errorf("run %d: %v", i, c.Reasons)
		}
	}
}

// At every agreement all eleven claims are corroborated, the two writes on
// their content, and the only finding is the harness's connection to
// oauth2.googleapis.com one second into the run: it refreshes its access token,
// which no control did (the controls ran within a minute after the task), so no
// rule explains it and a connection that sent data is a finding (O-25, not
// decided). The harness's own file events are all explained at one and two
// controls in five; above that, its replaces of its caches through
// temporaries vary between runs (I-49). This pins the counts, so a change is
// seen.
func TestPairedBasicAtEachAgreement(t *testing.T) {
	harness := map[float64]int{0.2: 0, 0.4: 0, 0.6: 3, 0.8: 3, 1: 12}
	rules := map[float64]int{0.2: 268, 0.4: 263, 0.6: 259, 0.8: 259, 1: 252}
	tr := pairedClaims(t)
	if len(tr) != 11 {
		t.Fatalf("%d claims, want 11", len(tr))
	}
	for _, a := range []float64{0.2, 0.4, 0.6, 0.8, 1} {
		b := pairedBaseline(t, a)
		if len(b.Rules) != rules[a] {
			t.Errorf("agreement %v: %d rules, want %d", a, len(b.Rules), rules[a])
		}
		v := pairedVerdict(t, tr, b)
		if len(v.Corroborated) != 11 || len(v.Mismatched) != 0 || len(v.Unwitnessed) != 0 || len(v.Unverified) != 0 || len(v.OutsideInterval) != 0 {
			t.Errorf("agreement %v: corroborated %d mismatched %v unwitnessed %v unverified %v outside %v",
				a, len(v.Corroborated), v.Mismatched, v.Unwitnessed, v.Unverified, v.OutsideInterval)
		}
		if len(v.Unrecorded) != 1 || v.Unrecorded[0].ActionType != models.NetConnect || v.Unrecorded[0].Target != "oauth2.googleapis.com" {
			t.Errorf("agreement %v: unrecorded %v, want only the connection to oauth2.googleapis.com", a, v.Unrecorded)
		}
		if v.Findings() != 1 || v.Outcome != verification.OutcomeNotFaithful {
			t.Errorf("agreement %v: %d findings, outcome %s; want the one finding and NOT FAITHFUL", a, v.Findings(), v.Outcome)
		}
		if len(v.UnexplainedHarness) != harness[a] {
			t.Errorf("agreement %v: %d unexplained harness events, want %d: %v", a, len(v.UnexplainedHarness), harness[a], v.UnexplainedHarness)
		}
	}
}

// The writes are corroborated on the content the harness wrote: write_to_file
// claims its CodeContent with a final newline (I-47), and the probe measured
// the same bytes on the close.
func TestPairedBasicWritesAreCorroboratedOnTheirContent(t *testing.T) {
	v := pairedVerdict(t, pairedClaims(t), pairedBaseline(t, 0.2))
	var hashed int
	for _, p := range v.Corroborated {
		if p.Entry.OutputHash != nil {
			hashed++
			if p.Event.OutputHash == nil || *p.Event.OutputHash != *p.Entry.OutputHash {
				t.Errorf("%s %s paired with %v", p.Entry.Tool, p.Entry.Target, p.Event.OutputHash)
			}
		}
	}
	if hashed != 2 {
		t.Errorf("%d corroborated claims state content, want the two write_to_file closes", hashed)
	}
}

// Without a baseline the harness's own activity is reported: hundreds of
// events at level 0, and still no claim unpaired.
func TestPairedBasicWithoutABaselineReportsTheHarness(t *testing.T) {
	v := pairedVerdict(t, pairedClaims(t), nil)
	if len(v.Corroborated) != 11 || len(v.Unrecorded) < 100 || len(v.UnexplainedHarness) < 100 {
		t.Errorf("corroborated %d, unrecorded %d, unexplained harness %d", len(v.Corroborated), len(v.Unrecorded), len(v.UnexplainedHarness))
	}
}

// A trajectory that leaves out a call is caught at its kernel events, and one
// that claims a call the agent did not make is caught as unwitnessed.
func TestPairedBasicCatchesAnOmissionAndAFabrication(t *testing.T) {
	tr := pairedClaims(t)
	var omitted models.Trajectory
	for _, e := range tr {
		if e.Tool != toolReplace {
			omitted = append(omitted, e)
		}
	}
	v := pairedVerdict(t, omitted, pairedBaseline(t, 0.2))
	var onA int
	for _, e := range v.Unrecorded {
		if strings.HasSuffix(e.Target, "/a.txt") {
			onA++
		}
	}
	if v.Outcome != verification.OutcomeNotFaithful || onA != 3 {
		t.Errorf("omitting replace_file_content: outcome %s, %d unrecorded events on a.txt, want its open, write and close: %v", v.Outcome, onA, v.Unrecorded)
	}
	fake := tr[len(tr)-1]
	fake.Target = "curl https://example.com"
	v = pairedVerdict(t, append(append(models.Trajectory{}, tr...), fake), pairedBaseline(t, 0.2))
	if len(v.Unwitnessed) != 1 || v.Unwitnessed[0].Target != fake.Target {
		t.Errorf("a fabricated command: unwitnessed %v", v.Unwitnessed)
	}
}

// The control task's own command is not a rule, so it explains no command of
// the task run (I-28).
func TestPairedBasicControlCommandIsNotARule(t *testing.T) {
	b := pairedBaseline(t, 0.2)
	for _, r := range b.Rules {
		if strings.Contains(r.Target, "agent-trace-control-marker") {
			t.Errorf("rule %v names the control command", r)
		}
	}
	if len(b.Excluded) != 1 || b.Excluded[0] != controlCommand {
		t.Errorf("excluded %v", b.Excluded)
	}
}

// The probe recorded the command as the wrapper `/usr/bin/bash -c echo hi`, a
// child of the agent's process, and Normalize recovers the CommandLine from
// it (I-47).
func TestPairedBasicRecoversTheCommandFromItsWrapper(t *testing.T) {
	g := pairedRun(t, "basic")
	var execs []string
	for _, e := range g.Events {
		if e.ActionType == models.ProcessExec {
			n, _ := Adapter{}.Normalize(e)
			execs = append(execs, e.Target+" => "+n.Target)
			if e.PPID != g.RootPID {
				t.Errorf("%s: parent %d, want the agent %d", e.Target, e.PPID, g.RootPID)
			}
		}
	}
	if strings.Join(execs, "\n") != "/usr/bin/bash -c echo hi => echo hi" {
		t.Errorf("execs %v", execs)
	}
}

// Without the stream normalization the file tools' measured shapes leave the
// two extra opens of view_file, the read opens of replace_file_content and of
// the write_to_file over b.txt, and the create of a.txt unrecorded (I-50).
func TestPairedBasicNeedsTheMeasuredShapes(t *testing.T) {
	g := pairedRun(t, "basic")
	b := pairedBaseline(t, 0.2)
	v := verification.Verify(agent.Prepare(rawAdapter{}, pairedClaims(t), g, b.Predicate(g.Workspace), verification.Options{IntervalSlack: 500 * time.Millisecond}))
	var files int
	for _, e := range v.Unrecorded {
		if strings.HasPrefix(e.Target, g.Workspace) {
			files++
		}
	}
	if files != 5 || len(v.Corroborated) != 11 {
		t.Errorf("without the folds: %d unrecorded workspace events, want 5; corroborated %d: %v", files, len(v.Corroborated), v.Unrecorded)
	}
}
