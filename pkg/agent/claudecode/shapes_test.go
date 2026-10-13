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

// The shapes capture of Claude Code 2.1.296 (2026-10-13) holds the two shapes
// no earlier capture showed. A message with a slow and a fast read-only Bash
// call and a Read, where the harness exec'd the fast call before the slow one
// (V-32 pairs them). A Write and an Edit of a file in a directory without
// write permission, which the harness rewrote in place, with no temporary file
// and no rename (I-45). And the harness's own read of the file a lone
// `cat FILE` named, which the adapter derives as a harness-implied open
// (I-46, V-33). Reduced by scripts/make-capture-fixture.py, which keeps each
// record's cwd and a Bash result's states for I-46.
const shapesDir = "testdata/paired-2.1.296-shapes"

func shapesRun(t *testing.T, label string) models.GroundTruthFile {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(shapesDir, label+".ground_truth.json"))
	if err != nil {
		t.Fatal(err)
	}
	f, err := models.ParseGroundTruthFile(data)
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	return f
}

func shapesControls(t *testing.T) []models.GroundTruthFile {
	t.Helper()
	paths, _ := filepath.Glob(filepath.Join(shapesDir, "control-*.ground_truth.json"))
	var runs []models.GroundTruthFile
	for _, p := range paths {
		runs = append(runs, shapesRun(t, strings.TrimSuffix(filepath.Base(p), ".ground_truth.json")))
	}
	return runs
}

func shapesVerdict(t *testing.T, agreement float64) (verification.Verdict, models.Trajectory) {
	t.Helper()
	tr, rep, err := Adapter{}.Parse(filepath.Join(shapesDir, "shapes.session.jsonl"))
	if err != nil || len(rep.ParseErrors) != 0 || len(rep.UnknownTools) != 0 {
		t.Fatalf("parse: %v %+v", err, rep)
	}
	g := shapesRun(t, "shapes")
	b, err := agent.Capture(Adapter{}, "2.1.296", shapesControls(t), time.Now(), agent.CaptureOptions{Exclude: []string{controlCommand}, MinAgreement: agreement})
	if err != nil {
		t.Fatal(err)
	}
	return verification.Verify(agent.Prepare(Adapter{}, tr, g, b.Predicate(g.Workspace), verification.Options{IntervalSlack: 500 * time.Millisecond})), tr
}

func TestShapesCaptureHasFiveControlsAndNoEventLoss(t *testing.T) {
	runs := shapesControls(t)
	if len(runs) != 5 {
		t.Fatalf("%d controls, want five", len(runs))
	}
	for i, r := range append(runs, shapesRun(t, "shapes")) {
		if c := verification.Assess(r.Coverage); !c.Complete {
			t.Errorf("run %d: %v", i, c.Reasons)
		}
	}
}

// At every agreement every claim of the agent is corroborated, the swapped
// Bash calls of one message and the in-place Write and Edit included, and the
// harness's read of fast.txt is explained as harness-implied. Nothing is a
// finding. The run is INCONCLUSIVE, not FAITHFUL, on a backup of the
// harness's configuration that no control made (V-24); at three controls in
// five and above the fswatch probe directory's deletion joins it. This pins
// the counts, so a change is seen.
func TestShapesTaskHasNoFindingAtAnyAgreement(t *testing.T) {
	harness := map[float64]int{0.2: 5, 0.4: 5, 0.6: 6, 0.8: 6, 1: 6}
	for _, a := range []float64{0.2, 0.4, 0.6, 0.8, 1} {
		v, tr := shapesVerdict(t, a)
		var own int
		for _, e := range tr {
			if e.ImpliedBy == "" {
				own++
			}
		}
		if v.Findings() != 0 || len(v.Unverified) != 0 {
			t.Errorf("agreement %v: findings %d unverified %d\nunwitnessed=%v\nunrecorded=%v\nmismatched=%v",
				a, v.Findings(), len(v.Unverified), v.Unwitnessed, v.Unrecorded, v.Mismatched)
		}
		if len(v.Corroborated) != own || own != 10 {
			t.Errorf("agreement %v: corroborated %d of %d claims, want all 10", a, len(v.Corroborated), own)
		}
		if len(v.HarnessImplied) != 1 || !strings.HasSuffix(v.HarnessImplied[0].Event.Target, "/fast.txt") {
			t.Errorf("agreement %v: harness implied %v, want the read of fast.txt", a, v.HarnessImplied)
		}
		if v.Outcome != verification.OutcomeInconclusive || len(v.UnexplainedHarness) != harness[a] {
			t.Errorf("agreement %v: outcome %s with %d unexplained harness events, want INCONCLUSIVE with %d", a, v.Outcome, len(v.UnexplainedHarness), harness[a])
		}
	}
}
