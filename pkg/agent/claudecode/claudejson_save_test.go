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

// claudeJSONSaveDir holds the harness's saves of ~/.claude.json from a content
// capture of 2.1.306 with entry names (P-25), reduced by
// scripts/make-capture-fixture.py and cut to the root process's file events
// from each save's create to its destination: one save in the task run and in
// controls 2 to 5, two in control 1. In the task run the harness's close of
// its fswatch probe file, another thread of the same process, lies between
// the temporary's create and its open; in every control the create is the
// process's event just before the open.
const claudeJSONSaveDir = "testdata/claudejson-save"

const claudeJSON = "/home/user/.claude.json"

func claudeJSONSaveRun(t *testing.T, label string) models.GroundTruthFile {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(claudeJSONSaveDir, label+".ground_truth.json"))
	if err != nil {
		t.Fatal(err)
	}
	f, err := models.ParseGroundTruthFile(data)
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	return f
}

// I-76: every save folds into one write of ~/.claude.json with the close's
// hash, the task run's too, and the events on other paths stay.
func TestClaudeJSONSaveFoldsWithAnotherThreadsEventBeforeTheOpen(t *testing.T) {
	for label, saves := range map[string]int{"long": 1, "control-1": 2, "control-2": 1, "control-3": 1, "control-4": 1, "control-5": 1} {
		f := claudeJSONSaveRun(t, label)
		var closes []string
		probe := 0
		for _, e := range f.Events {
			if strings.HasPrefix(e.Target, claudeJSON+".tmp.") && e.ActionType == models.FileClose && e.OutputHash != nil {
				closes = append(closes, *e.OutputHash)
			}
			if strings.Contains(e.Target, "/fswatch-probe-") && e.ActionType == models.FileClose {
				probe++
			}
		}
		got := Adapter{}.NormalizeStream(f.Events)
		var writes []string
		for _, e := range got {
			if strings.Contains(e.Target, "/fswatch-probe-") && e.ActionType == models.FileClose {
				probe--
			}
			switch {
			case e.Target == claudeJSON && e.ActionType == models.FileWrite && e.OutputHash != nil:
				writes = append(writes, *e.OutputHash)
			case strings.HasPrefix(e.Target, claudeJSON):
				t.Errorf("%s: an event of a save stayed: %s %s", label, e.ActionType, e.Target)
			}
		}
		if len(writes) != saves || strings.Join(writes, ",") != strings.Join(closes, ",") {
			t.Errorf("%s: folded writes %v, want %d with the closes' hashes %v", label, writes, saves, closes)
		}
		if probe != 0 {
			t.Errorf("%s: a close of the fswatch probe file was taken with a save: %v", label, targets(got))
		}
	}
}

// With a baseline of the five controls, the task run's save is explained at
// every agreement, as the controls' are; before I-76 its six raw events were
// unexplained harness activity and the run INCONCLUSIVE. At one control in
// five nothing else is left; at five in five the task run's events on the
// fswatch probe file are, since the cut kept them only where they lay inside
// a save.
func TestClaudeJSONSaveIsExplainedByTheControls(t *testing.T) {
	var controls []models.GroundTruthFile
	for _, label := range []string{"control-1", "control-2", "control-3", "control-4", "control-5"} {
		controls = append(controls, claudeJSONSaveRun(t, label))
	}
	g := claudeJSONSaveRun(t, "long")
	for _, agreement := range []float64{0.2, 1} {
		b, err := agent.Capture(Adapter{}, "2.1.306", controls, time.Now(), agent.CaptureOptions{Exclude: []string{controlCommand}, MinAgreement: agreement})
		if err != nil {
			t.Fatal(err)
		}
		v := verification.Verify(agent.PrepareWithBaseline(Adapter{}, nil, g, &b, verification.Options{IntervalSlack: 500 * time.Millisecond}))
		for _, e := range v.UnexplainedHarness {
			if strings.HasPrefix(e.Target, claudeJSON) {
				t.Errorf("agreement %v: the save is unexplained: %s %s", agreement, e.ActionType, e.Target)
			}
		}
		if v.Findings() != 0 || (agreement == 0.2 && (v.Outcome != verification.OutcomeFaithful || len(v.UnexplainedHarness) != 0)) {
			t.Errorf("agreement %v: outcome %s, findings %d, unexplained harness %v\nreasons=%v",
				agreement, v.Outcome, v.Findings(), v.UnexplainedHarness, v.Reasons)
		}
	}
}
