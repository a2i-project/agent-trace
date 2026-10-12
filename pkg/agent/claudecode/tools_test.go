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

// The tools capture of Claude Code 2.1.296 (2026-10-12) exercises what the
// other captures do not: a background Bash whose output file the agent reads
// later, three Reads in one message, two Edits of one file (the version offers
// no MultiEdit), a NotebookEdit loaded through ToolSearch, a Write that creates
// a file and one that overwrites it, and a subagent that writes a file. Its
// five controls also run a background Bash and a subagent, so the baseline
// covers the harness's activity around both. It is the evidence behind I-34 to
// I-43, V-30 and V-31. Reduced by scripts/make-capture-fixture.py, which keeps
// the Read and Write results the adapter reads.
const toolsDir = "testdata/paired-2.1.296-tools"

func toolsRun(t *testing.T, label string) models.GroundTruthFile {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(toolsDir, label+".ground_truth.json"))
	if err != nil {
		t.Fatal(err)
	}
	f, err := models.ParseGroundTruthFile(data)
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	return f
}

func toolsControls(t *testing.T) []models.GroundTruthFile {
	t.Helper()
	paths, _ := filepath.Glob(filepath.Join(toolsDir, "control-*.ground_truth.json"))
	var runs []models.GroundTruthFile
	for _, p := range paths {
		runs = append(runs, toolsRun(t, strings.TrimSuffix(filepath.Base(p), ".ground_truth.json")))
	}
	return runs
}

func toolsVerdict(t *testing.T, agreement float64) (verification.Verdict, models.Trajectory) {
	t.Helper()
	tr, rep, err := Adapter{}.Parse(filepath.Join(toolsDir, "tools.session.jsonl"))
	if err != nil || len(rep.ParseErrors) != 0 || len(rep.UnknownTools) != 0 {
		t.Fatalf("parse: %v %+v", err, rep)
	}
	g := toolsRun(t, "tools")
	b, err := agent.Capture(Adapter{}, "2.1.296", toolsControls(t), time.Now(), agent.CaptureOptions{Exclude: []string{controlCommand}, MinAgreement: agreement})
	if err != nil {
		t.Fatal(err)
	}
	return verification.Verify(agent.Prepare(Adapter{}, tr, g, b.Predicate(g.Workspace), verification.Options{IntervalSlack: 500 * time.Millisecond})), tr
}

func TestToolsCaptureHasFiveControlsAndNoEventLoss(t *testing.T) {
	runs := toolsControls(t)
	if len(runs) != 5 {
		t.Fatalf("%d controls, want five", len(runs))
	}
	for i, r := range append(runs, toolsRun(t, "tools")) {
		if c := verification.Assess(r.Coverage); !c.Complete {
			t.Errorf("run %d: %v", i, c.Reasons)
		}
	}
}

// Every tool the task used is mapped, the subagent's Write is claimed from its
// own transcript, and every whole-file Read states the content it read (I-40).
func TestToolsTaskClaimsEveryToolItUsed(t *testing.T) {
	tr, rep, err := Adapter{}.Parse(filepath.Join(toolsDir, "tools.session.jsonl"))
	if err != nil || len(rep.UnknownTools) != 0 {
		t.Fatalf("parse: %v unknown tools %v", err, rep.UnknownTools)
	}
	var notebook, subagentWrite, readsWithContent int
	for _, e := range tr {
		switch {
		case e.Tool == "NotebookEdit" && e.ActionType == models.FileWrite:
			notebook++
		case e.Tool == "Write" && e.ThreadID != "" && strings.HasSuffix(e.Target, "/subagent.txt"):
			subagentWrite++
		case e.Tool == "Read" && e.InputHash != nil:
			readsWithContent++
		}
	}
	if notebook != 1 || subagentWrite != 1 || readsWithContent != 3 {
		t.Errorf("NotebookEdit writes %d, subagent Writes %d, Reads with content %d; want 1, 1, 3", notebook, subagentWrite, readsWithContent)
	}
}

// At the capture script's default agreement (1/5) every claim is corroborated
// and nothing is a finding. The run is INCONCLUSIVE, not FAITHFUL, on four
// file events in the harness's own directories that no control made: a
// rewrite of its version lock that no fold shape takes, and the deletion of
// its fswatch probe directory (V-24). This pins both, so a change is seen.
func TestToolsTaskCorroboratesEveryClaimAtTheDefaultAgreement(t *testing.T) {
	v, tr := toolsVerdict(t, 0.2)
	if v.Findings() != 0 || len(v.Unverified) != 0 {
		t.Fatalf("findings %d unverified %d\nunwitnessed=%v\nunrecorded=%v\nmismatched=%v\noutside=%v",
			v.Findings(), len(v.Unverified), v.Unwitnessed, v.Unrecorded, v.Mismatched, v.OutsideInterval)
	}
	if len(v.Corroborated) != len(tr) || len(tr) != 16 {
		t.Errorf("corroborated %d of %d claims, want all 16", len(v.Corroborated), len(tr))
	}
	if v.Outcome != verification.OutcomeInconclusive || len(v.UnexplainedHarness) != 4 {
		t.Errorf("outcome %s with %d unexplained harness events, want INCONCLUSIVE with 4: %v", v.Outcome, len(v.UnexplainedHarness), v.UnexplainedHarness)
	}
}

// The harness reads and deletes its cwd file after each Bash call. In the
// task run and in two of the five controls the read merged into the batch of
// the delete and reached the probe as an ambiguous open of /tmp; in the other
// three it names the file. The fold reads the first as the second (I-43), so
// the run has no finding at any agreement: it is INCONCLUSIVE only on harness
// events in the harness's own directories that too few controls made, and
// every claim stays corroborated. This pins the count at each agreement.
func TestToolsTaskHasNoFindingAtAnyAgreement(t *testing.T) {
	run := toolsRun(t, "tools")
	var cwdReads int
	for _, e := range agent.NormalizeGround(Adapter{}, run.Events) {
		// The wrapper's shell writes the cwd file; when that batch merges, its
		// open of /tmp is followed by a write and keeps its target.
		if e.ActionType == models.FileOpen && e.Target == "/tmp" && e.PID == run.RootPID {
			t.Errorf("an open of /tmp by the agent's process is left: %+v", e)
		}
		if e.Target == cwdFileRead && e.PID == run.RootPID {
			cwdReads++
		}
	}
	if cwdReads != 1 {
		t.Errorf("%d folded reads of the cwd file, want 1", cwdReads)
	}
	for _, c := range []struct {
		agreement float64
		harness   int
	}{{0.2, 4}, {0.4, 6}, {0.6, 7}, {0.8, 10}, {1, 10}} {
		v, tr := toolsVerdict(t, c.agreement)
		if len(v.Corroborated) != len(tr) || v.Findings() != 0 || len(v.Unverified) != 0 {
			t.Errorf("agreement %v: corroborated %d of %d claims, findings %d, unverified %d\nunrecorded=%v",
				c.agreement, len(v.Corroborated), len(tr), v.Findings(), len(v.Unverified), v.Unrecorded)
		}
		if v.Outcome != verification.OutcomeInconclusive || len(v.UnexplainedHarness) != c.harness {
			t.Errorf("agreement %v: outcome %s with %d unexplained harness events, want INCONCLUSIVE with %d: %v",
				c.agreement, v.Outcome, len(v.UnexplainedHarness), c.harness, v.UnexplainedHarness)
		}
		for _, e := range v.UnexplainedHarness {
			if e.Target == cwdFileRead {
				t.Errorf("agreement %v: the folded read of the cwd file is unexplained", c.agreement)
			}
		}
	}
}

// The fold leaves the agent's own events in /tmp alone: an ambiguous open of
// /tmp that no delete of /tmp follows, and an open of a file in /tmp, by the
// agent's process, stay unrecorded at every agreement (I-43).
func TestAnAgentOpenInTmpIsStillAFinding(t *testing.T) {
	tr, _, err := Adapter{}.Parse(filepath.Join(toolsDir, "tools.session.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	g := toolsRun(t, "tools")
	// Halfway through the run, between two events, by the agent's process.
	mid := len(g.Events) / 2
	at := g.Events[mid].Timestamp.Add(time.Microsecond)
	injected := models.GroundTruth{
		{Timestamp: at, ActionType: models.FileOpen, Target: "/tmp", PID: g.RootPID, PathIsAmbiguous: true},
		{Timestamp: at.Add(time.Nanosecond), ActionType: models.FileOpen, Target: "/tmp/x", PID: g.RootPID},
	}
	events := append(append(append(models.GroundTruth(nil), g.Events[:mid+1]...), injected...), g.Events[mid+1:]...)
	g.Events = events
	for _, a := range []float64{0.2, 0.6, 1} {
		b, err := agent.Capture(Adapter{}, "2.1.296", toolsControls(t), time.Now(), agent.CaptureOptions{Exclude: []string{controlCommand}, MinAgreement: a})
		if err != nil {
			t.Fatal(err)
		}
		v := verification.Verify(agent.Prepare(Adapter{}, tr, g, b.Predicate(g.Workspace), verification.Options{IntervalSlack: 500 * time.Millisecond}))
		var got []string
		for _, e := range v.Unrecorded {
			got = append(got, string(e.ActionType)+" "+e.Target)
		}
		if v.Outcome != verification.OutcomeNotFaithful || v.Findings() != 2 || strings.Join(got, "|") != "file_open /tmp|file_open /tmp/x" {
			t.Errorf("agreement %v: outcome %s, findings %d, unrecorded %v; want NOT FAITHFUL on the two opens", a, v.Outcome, v.Findings(), got)
		}
	}
}
