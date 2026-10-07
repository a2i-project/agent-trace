package claudecode

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// The third paired capture of Claude Code 2.1.286 is a realistic coding task in
// a seeded Python package (scripts/seed/project): run the tests, fix a bug, add a
// function and a command-line option with tests, update the README, run the tests
// again. The model chose its own tools: it read the files with Bash, rewrote three
// of them with Write over their existing contents, made four Edits and ran the
// tests twice. The three control runs enabled the same tools (Read, Write, Edit,
// Bash, Grep, Glob) in the same seeded project. No event was lost. Reduced by
// scripts/make-capture-fixture.py.
const projectDir = "testdata/paired-2.1.286-project"

func projectRun(t *testing.T, label string) models.GroundTruthFile {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(projectDir, label+".ground_truth.json"))
	if err != nil {
		t.Fatal(err)
	}
	f, err := models.ParseGroundTruthFile(data)
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	return f
}

func TestProjectCaptureHasNoEventLoss(t *testing.T) {
	for _, l := range []string{"project", "control-1", "control-2", "control-3"} {
		if c := verification.Assess(projectRun(t, l).Coverage); !c.Complete {
			t.Errorf("%s: %v", l, c.Reasons)
		}
	}
}

func TestProjectTaskVerifiesFaithful(t *testing.T) {
	tr, rep, err := Adapter{}.Parse(filepath.Join(projectDir, "project.session.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.ParseErrors) != 0 || len(rep.UnknownTools) != 0 {
		t.Fatalf("the real transcript did not parse cleanly: %+v", rep)
	}
	var runs []models.GroundTruthFile
	for _, l := range []string{"control-1", "control-2", "control-3"} {
		runs = append(runs, projectRun(t, l))
	}
	b, err := agent.Capture(Adapter{}, "2.1.286", runs, time.Now(), agent.CaptureOptions{})
	if err != nil {
		t.Fatal(err)
	}
	g := projectRun(t, "project")
	v := verification.Verify(agent.Prepare(Adapter{}, tr, g, b.Predicate(g.Workspace), verification.Options{IntervalSlack: 500 * time.Millisecond}))
	if v.Outcome != verification.OutcomeFaithful {
		t.Fatalf("outcome = %s\nunwitnessed=%v\nunrecorded=%v\nmismatched=%v\nunexplained subtrees=%d reasons=%v",
			v.Outcome, v.Unwitnessed, v.Unrecorded, v.Mismatched, len(v.Coverage.UnexplainedSubtrees), v.Reasons)
	}
	if len(v.Corroborated) != len(tr) || len(tr) < 15 {
		t.Errorf("corroborated %d of %d claims, want all of them and a session of real size", len(v.Corroborated), len(tr))
	}
	// The three Bash calls ran python3 and cat, whose files and children are the
	// claimed commands' subtrees, not claims of their own.
	if v.Coverage.Explained < 20 {
		t.Errorf("only %d events explained by claimed commands", v.Coverage.Explained)
	}
	tools := map[string]int{}
	for _, e := range tr {
		tools[e.Tool]++
	}
	if tools["Write"] == 0 || tools["Edit"] == 0 || tools["Bash"] == 0 {
		t.Errorf("tool mix = %v, want Write, Edit and Bash all present", tools)
	}
}
