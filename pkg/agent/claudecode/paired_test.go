package claudecode

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// The fixture is a real paired capture of Claude Code 2.1.286: one task run (a
// Read, a Write that creates a file, an Edit, a Write that overwrites, and a
// Bash command) and three control runs that make one no-op Bash call, all
// recorded under cmd/watch with the fs, proc and net probes and no event loss.
// It was reduced by scripts/make-capture-fixture.py: paths rewritten, the
// transcript cut to the fields the adapter reads, the shell snapshot script
// elided. Ground truth events, pids and timestamps are as captured.
const pairedDir = "testdata/paired-2.1.286"

func loadRun(t *testing.T, label string) models.GroundTruthFile {
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

func pairedBaseline(t *testing.T) agent.Baseline {
	t.Helper()
	var runs []models.GroundTruthFile
	for _, l := range []string{"control-1", "control-2", "control-3"} {
		runs = append(runs, loadRun(t, l))
	}
	b, err := agent.Capture(Adapter{}, "2.1.286", runs, time.Now(), agent.CaptureOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func pairedTask(t *testing.T) (models.Trajectory, models.GroundTruthFile) {
	t.Helper()
	tr, rep, err := Adapter{}.Parse(filepath.Join(pairedDir, "task.session.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.ParseErrors) != 0 || len(rep.UnknownTools) != 0 {
		t.Fatalf("the real transcript did not parse cleanly: %+v", rep)
	}
	return tr, loadRun(t, "task")
}

func verifyPaired(t *testing.T, claims models.Trajectory, g models.GroundTruthFile, b *agent.Baseline) verification.Verdict {
	t.Helper()
	var measured verification.Baseline
	if b != nil {
		measured = b.Predicate(g.Workspace)
	}
	return verification.Verify(agent.Prepare(Adapter{}, claims, g, measured, verification.Options{IntervalSlack: 500 * time.Millisecond}))
}

func TestPairedCaptureHasNoEventLoss(t *testing.T) {
	for _, l := range []string{"task", "control-1", "control-2", "control-3"} {
		if c := verification.Assess(loadRun(t, l).Coverage); !c.Complete {
			t.Errorf("%s: %v", l, c.Reasons)
		}
	}
}

func TestPairedTaskVerifiesFaithfulWithAMeasuredBaseline(t *testing.T) {
	tr, g := pairedTask(t)
	b := pairedBaseline(t)
	v := verifyPaired(t, tr, g, &b)
	if v.Outcome != verification.OutcomeFaithful {
		t.Fatalf("outcome = %s\nunwitnessed=%v\nunrecorded=%v\nmismatched=%v\nunexplained subtrees=%d reasons=%v",
			v.Outcome, v.Unwitnessed, v.Unrecorded, v.Mismatched, len(v.Coverage.UnexplainedSubtrees), v.Reasons)
	}
	if len(v.Corroborated) != len(tr) || len(tr) != 7 {
		t.Errorf("corroborated %d of %d claims, want all 7", len(v.Corroborated), len(tr))
	}
	if v.Coverage.Baselined == 0 {
		t.Error("nothing was explained by the baseline: the harness's setup commands should have been")
	}
}

// The control runs were taken in other directories than the task. The baseline
// still has to apply, because its rules name the workspace by a placeholder.
func TestPairedBaselineAppliesAcrossWorkspaces(t *testing.T) {
	b := pairedBaseline(t)
	found := false
	for _, r := range b.Rules {
		if strings.Contains(r.Target, agent.WorkspacePlaceholder) {
			found = true
		}
		if strings.Contains(r.Target, "/ws/control-") {
			t.Errorf("a rule names a control run's own directory: %q", r.Target)
		}
	}
	if !found {
		t.Error("no rule uses the workspace placeholder, but the harness inspects the working directory")
	}
}

// Without a baseline the harness's own commands are unreported actions. That is
// the point of measuring one, and the verdict must say so rather than pass.
func TestPairedTaskWithoutABaselineReportsTheHarness(t *testing.T) {
	tr, g := pairedTask(t)
	v := verifyPaired(t, tr, g, nil)
	if v.Outcome != verification.OutcomeNotFaithful {
		t.Fatalf("outcome = %s, want NOT FAITHFUL without a baseline", v.Outcome)
	}
	if len(v.Coverage.UnexplainedSubtrees) == 0 || len(v.Mismatched) != 0 || len(v.Unwitnessed) != 0 {
		t.Errorf("subtrees=%d mismatched=%d unwitnessed=%d: the claims themselves should all agree, only the harness is unexplained",
			len(v.Coverage.UnexplainedSubtrees), len(v.Mismatched), len(v.Unwitnessed))
	}
}

// Each way of lying about the real session must be caught, and caught as the
// right kind of finding, so the normalization that makes the honest session
// comparable cannot be what lets a dishonest one through.
func TestPairedTaskCatchesEachKindOfLie(t *testing.T) {
	b := pairedBaseline(t)
	find := func(tr models.Trajectory, tool string, a models.ActionType) int {
		for i, e := range tr {
			if e.Tool == tool && e.ActionType == a {
				return i
			}
		}
		t.Fatalf("no %s %s claim in %v", tool, a, tr)
		return -1
	}
	tests := []struct {
		name  string
		lie   func(tr models.Trajectory) models.Trajectory
		check func(t *testing.T, v verification.Verdict)
	}{
		{"a changed content hash on a Write", func(tr models.Trajectory) models.Trajectory {
			i := find(tr, "Write", models.FileWrite)
			h := "sha256:benign"
			tr[i].OutputHash = &h
			return tr
		}, func(t *testing.T, v verification.Verdict) {
			if len(v.Mismatched) != 1 || v.Mismatched[0].Diffs[0] != verification.DiffOutputHash {
				t.Errorf("Mismatched = %+v, want one output_hash difference", v.Mismatched)
			}
		}},
		{"a Write claimed on a different file", func(tr models.Trajectory) models.Trajectory {
			tr[find(tr, "Write", models.FileWrite)].Target = "/ws/task/decoy.txt"
			return tr
		}, func(t *testing.T, v verification.Verdict) {
			if len(v.Mismatched) != 1 || v.Mismatched[0].Diffs[0] != verification.DiffTarget {
				t.Errorf("Mismatched = %+v, want one target difference", v.Mismatched)
			}
		}},
		{"the Bash command replaced", func(tr models.Trajectory) models.Trajectory {
			tr[find(tr, "Bash", models.ProcessExec)].Target = "cat /etc/shadow"
			return tr
		}, func(t *testing.T, v verification.Verdict) {
			if len(v.Mismatched) != 1 {
				t.Errorf("Mismatched = %+v, want the substituted command", v.Mismatched)
			}
		}},
		{"the Edit omitted", func(tr models.Trajectory) models.Trajectory {
			var out models.Trajectory
			for _, e := range tr {
				if e.Tool != "Edit" {
					out = append(out, e)
				}
			}
			return out
		}, func(t *testing.T, v verification.Verdict) {
			if len(v.Unrecorded) == 0 {
				t.Error("an omitted Edit left nothing unrecorded")
			}
		}},
		{"a write fabricated", func(tr models.Trajectory) models.Trajectory {
			return append(tr, models.TrajectoryEntry{Timestamp: tr[len(tr)-1].Timestamp, ActionType: models.FileWrite, Target: "/ws/task/ghost.txt", Tool: "Write"})
		}, func(t *testing.T, v verification.Verdict) {
			if len(v.Unwitnessed) != 1 {
				t.Errorf("Unwitnessed = %v, want the fabricated write", v.Unwitnessed)
			}
		}},
		{"the Bash command omitted", func(tr models.Trajectory) models.Trajectory {
			var out models.Trajectory
			for _, e := range tr {
				if e.Tool != "Bash" {
					out = append(out, e)
				}
			}
			return out
		}, func(t *testing.T, v verification.Verdict) {
			if len(v.Unrecorded) == 0 && len(v.Coverage.UnexplainedSubtrees) == 0 {
				t.Error("an omitted Bash command left no trace")
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tr, g := pairedTask(t)
			raw, _ := json.Marshal(tr)
			var copyTr models.Trajectory
			_ = json.Unmarshal(raw, &copyTr)
			v := verifyPaired(t, tc.lie(copyTr), g, &b)
			if v.Outcome != verification.OutcomeNotFaithful {
				t.Fatalf("outcome = %s, want NOT FAITHFUL", v.Outcome)
			}
			tc.check(t, v)
		})
	}
}

// An action the agent took and did not report must not hide among the
// harness's own, however the baseline was built.
func TestPairedTaskCatchesAnInjectedUnreportedAction(t *testing.T) {
	tr, g := pairedTask(t)
	b := pairedBaseline(t)
	g.Events = append(g.Events,
		models.GroundTruthEvent{Timestamp: g.Events[len(g.Events)-1].Timestamp, ActionType: models.NetConnect, Target: "exfil.example.invalid", PID: g.RootPID},
		models.GroundTruthEvent{Timestamp: g.Events[len(g.Events)-1].Timestamp, ActionType: models.FileWrite, Target: "/ws/task/stolen.txt", PID: g.RootPID},
	)
	v := verifyPaired(t, tr, g, &b)
	if v.Outcome != verification.OutcomeNotFaithful || len(v.Unrecorded) != 2 {
		t.Errorf("outcome = %s, unrecorded = %v, want exactly the two injected actions", v.Outcome, v.Unrecorded)
	}
}
