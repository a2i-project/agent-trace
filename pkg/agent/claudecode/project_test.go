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
	b, err := agent.Capture(Adapter{}, "2.1.286", runs, time.Now(), agent.CaptureOptions{Exclude: []string{controlCommand}})
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

// A second project session of 2.1.286 (2026-10-11), in which the model wrote
// the files with Bash heredocs instead of the Write tool. Its wrapper has no
// stdin redirection, which the strict shape of I-26 refused at first: an
// honest 3.9 KB heredoc command was a mismatch. Kept as the regression
// fixture for that shape, with two of its five controls.
func TestProjectHeredocSessionVerifies(t *testing.T) {
	const dir = "testdata/paired-2.1.286-project-heredoc"
	tr, rep, err := Adapter{}.Parse(filepath.Join(dir, "project.session.jsonl"))
	if err != nil || len(rep.ParseErrors) != 0 {
		t.Fatalf("parse: %v %+v", err, rep.ParseErrors)
	}
	if len(tr) != 3 {
		t.Fatalf("claims = %d, want the three Bash calls", len(tr))
	}
	load := func(name string) models.GroundTruthFile {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		f, err := models.ParseGroundTruthFile(data)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	runs := []models.GroundTruthFile{load("control-1.ground_truth.json"), load("control-2.ground_truth.json")}
	b, err := agent.Capture(Adapter{}, "2.1.286", runs, time.Now(), agent.CaptureOptions{Exclude: []string{controlCommand}, MinAgreement: 0.5})
	if err != nil {
		t.Fatal(err)
	}
	g := load("project.ground_truth.json")
	v := verification.Verify(agent.Prepare(Adapter{}, tr, g, b.Predicate(g.Workspace), verification.Options{IntervalSlack: 500 * time.Millisecond}))
	if v.Findings() != 0 || len(v.Corroborated) != 3 {
		t.Fatalf("findings=%d corroborated=%d mismatched=%v unrecorded=%v", v.Findings(), len(v.Corroborated), v.Mismatched, v.Unrecorded)
	}
	// The run backed up its configuration, which no control did: unexplained
	// harness activity, INCONCLUSIVE, not a finding (V-24).
	if v.Outcome == verification.OutcomeNotFaithful {
		t.Errorf("outcome = %s", v.Outcome)
	}
}

// The pre-registered gate of I-31. On a capture whose transcript kept the Edit
// results, every Edit claim states the file's content before and after, and
// every one of those pairs must be corroborated with no content diff: the
// harness's replacement is a plain string replace of the applied strings, or
// the hashes are wrong and the claim must not be made. A fixture whose Edits
// carry no hash predates the fields and is skipped, saying so. The fixture
// directories are listed so a new project capture joins the gate by being
// added here.
func TestProjectEditsClaimTheirContentAndAreCorroborated(t *testing.T) {
	for _, dir := range []string{projectDir, "testdata/paired-2.1.296-edits"} {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			label := filepath.Base(dir)[strings.LastIndex(filepath.Base(dir), "-")+1:] // the task label
			session := filepath.Join(dir, label+".session.jsonl")
			if _, err := os.Stat(session); err != nil {
				t.Skipf("no fixture at %s", dir)
			}
			tr, rep, err := Adapter{}.Parse(session)
			if err != nil || len(rep.ParseErrors) != 0 {
				t.Fatalf("parse: %v %+v", err, rep.ParseErrors)
			}
			edits, hashed := 0, 0
			for _, e := range tr {
				if e.Tool == toolEdit && e.ActionType == models.FileWrite {
					edits++
					if e.OutputHash != nil {
						hashed++
					}
				}
			}
			if edits == 0 {
				t.Skip("no Edit in the fixture")
			}
			if hashed == 0 {
				t.Skipf("the fixture's %d Edit result(s) carry no originalFile: it predates I-31 and measures nothing", edits)
			}
			if hashed != edits {
				t.Fatalf("%d of %d Edit claims carry a hash: the result fields are present for some calls only", hashed, edits)
			}
			controls, _ := filepath.Glob(filepath.Join(dir, "control-*.ground_truth.json"))
			var runs []models.GroundTruthFile
			for _, c := range controls {
				data, err := os.ReadFile(c)
				if err != nil {
					t.Fatal(err)
				}
				f, err := models.ParseGroundTruthFile(data)
				if err != nil {
					t.Fatal(err)
				}
				runs = append(runs, f)
			}
			b, err := agent.Capture(Adapter{}, rep.AgentVersion, runs, time.Now(), agent.CaptureOptions{Exclude: []string{controlCommand}, MinAgreement: 1 / float64(len(runs))})
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(filepath.Join(dir, label+".ground_truth.json"))
			if err != nil {
				t.Fatal(err)
			}
			g, err := models.ParseGroundTruthFile(data)
			if err != nil {
				t.Fatal(err)
			}
			v := verification.Verify(agent.Prepare(Adapter{}, tr, g, b.Predicate(g.Workspace), verification.Options{IntervalSlack: 500 * time.Millisecond}))
			for _, m := range v.Mismatched {
				if m.Entry.Tool == toolEdit {
					t.Errorf("STOP: Edit claim on %s differs in %v: claimed in=%s out=%s, observed in=%s out=%s", m.Entry.Target, m.Diffs, deref(m.Entry.InputHash), deref(m.Entry.OutputHash), deref(m.Event.InputHash), deref(m.Event.OutputHash))
				}
			}
			for _, u := range v.Unverified {
				if u.Entry.Tool == toolEdit {
					t.Logf("Edit on %s unverified in %v (the probe published no hash)", u.Entry.Target, u.Diffs)
				}
			}
			// The gate is about content: no finding, every Edit pair corroborated.
			// Occasional harness activity makes the run INCONCLUSIVE (V-24) and
			// says nothing about the hashes.
			if v.Findings() != 0 || v.Outcome == verification.OutcomeNotFaithful {
				t.Errorf("outcome = %s with %d finding(s); reasons %v", v.Outcome, v.Findings(), v.Reasons)
			}
			if v.Outcome == verification.OutcomeInconclusive {
				t.Logf("INCONCLUSIVE for reasons unrelated to content: %v", v.Reasons)
			}
			t.Logf("GO: %d Edit claims corroborated on their content (harness %s, %d claims, %d corroborated)", hashed, rep.AgentVersion, len(tr), len(v.Corroborated))
		})
	}
}

// O-28 on a real session, decided as V-29: the edits capture with the opens of
// the first Edit's file carrying no input hash, as the fs probe now leaves the
// open of a pre-existing file it never hashed (P-22). The Edit states the real
// content before it, which the probe could not check: the honest run is
// INCONCLUSIVE with that input_hash unverified, not NOT FAITHFUL.
func TestAnEditOfAFileTheProbeNeverHashedIsUnverified(t *testing.T) {
	const dir = "testdata/paired-2.1.296-edits"
	tr, rep, err := Adapter{}.Parse(filepath.Join(dir, "edits.session.jsonl"))
	if err != nil || len(rep.ParseErrors) != 0 {
		t.Fatalf("parse: %v %+v", err, rep.ParseErrors)
	}
	// The first Edit's stated input, and the file it edits.
	var target, stated string
	for _, e := range tr {
		if e.Tool == toolEdit && e.ActionType == models.FileOpen && e.InputHash != nil {
			target, stated = e.Target, *e.InputHash
			break
		}
	}
	if target == "" {
		t.Fatal("no Edit with a stated input hash in the fixture")
	}
	load := func(name string) models.GroundTruthFile {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		f, err := models.ParseGroundTruthFile(data)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	g := load("edits.ground_truth.json")
	stamped := 0
	for i, e := range g.Events {
		if e.ActionType == models.FileOpen && e.Target == target && e.InputHash != nil && *e.InputHash == stated {
			g.Events[i].InputHash = nil
			stamped++
		}
	}
	if stamped == 0 {
		t.Fatalf("no observed open of %s carries the stated input %s", target, stated)
	}
	runs := []models.GroundTruthFile{load("control-1.ground_truth.json"), load("control-2.ground_truth.json")}
	b, err := agent.Capture(Adapter{}, rep.AgentVersion, runs, time.Now(), agent.CaptureOptions{Exclude: []string{controlCommand}, MinAgreement: 0.5})
	if err != nil {
		t.Fatal(err)
	}
	v := verification.Verify(agent.Prepare(Adapter{}, tr, g, b.Predicate(g.Workspace), verification.Options{IntervalSlack: 500 * time.Millisecond}))
	if v.Outcome == verification.OutcomeNotFaithful || len(v.Mismatched) != 0 {
		t.Fatalf("outcome = %s, mismatched = %v: an Edit of a file the probe never measured must not be a finding", v.Outcome, v.Mismatched)
	}
	found := false
	for _, u := range v.Unverified {
		if u.Entry.Target == target && len(u.Diffs) == 1 && u.Diffs[0] == verification.DiffInputHash {
			found = true
		}
	}
	if !found || v.Outcome != verification.OutcomeInconclusive {
		t.Errorf("outcome = %s, unverified = %+v, want INCONCLUSIVE with the Edit's input_hash unverified", v.Outcome, v.Unverified)
	}
}
