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

// The first content capture of agy 1.4.7 (2026-11-03), recorded by
// scripts/capture-agent.sh --agent gemini --content with the task basic
// (the same five calls as paired-agy-1.3.4-basic) and five controls, model
// gemini-3.8-flash-high, and reduced by scripts/make-capture-fixture.py
// (I-119). The net probe read the TLS content of agy's Go crypto/tls, so
// the ground truth holds its requests and responses.
const paired147Dir = "testdata/paired-agy-1.4.7-basic"

func paired147Run(t *testing.T, label string) models.GroundTruthFile {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(paired147Dir, label+".ground_truth.json"))
	if err != nil {
		t.Fatal(err)
	}
	f, err := models.ParseGroundTruthFile(data)
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	return f
}

func paired147Controls(t *testing.T) []models.GroundTruthFile {
	t.Helper()
	paths, _ := filepath.Glob(filepath.Join(paired147Dir, "control-*.ground_truth.json"))
	var runs []models.GroundTruthFile
	for _, p := range paths {
		runs = append(runs, paired147Run(t, strings.TrimSuffix(filepath.Base(p), ".ground_truth.json")))
	}
	return runs
}

func paired147Claims(t *testing.T) models.Trajectory {
	t.Helper()
	tr, rep, err := Adapter{}.Parse(filepath.Join(paired147Dir, "basic.conversation.db"))
	if err != nil || len(rep.ParseErrors) != 0 || len(rep.UnknownTools) != 0 {
		t.Fatalf("parse: %v %+v", err, rep)
	}
	return tr
}

func paired147Verdict(t *testing.T, tr models.Trajectory, agreement float64) (verification.Verdict, int) {
	t.Helper()
	g := paired147Run(t, "basic")
	var measured verification.Baseline
	rules := 0
	if agreement > 0 {
		b, err := agent.Capture(Adapter{}, "1.4.7", paired147Controls(t), time.Now(), agent.CaptureOptions{Exclude: []string{controlCommand}, MinAgreement: agreement})
		if err != nil {
			t.Fatal(err)
		}
		measured, rules = b.Predicate(g.Workspace), len(b.Rules)
	}
	return verification.Verify(agent.Prepare(Adapter{}, tr, g, measured, verification.Options{IntervalSlack: 500 * time.Millisecond})), rules
}

func TestPaired147HasFiveControlsAndNoEventLoss(t *testing.T) {
	runs := paired147Controls(t)
	if len(runs) != 5 {
		t.Fatalf("%d controls, want five", len(runs))
	}
	for i, r := range append(runs, paired147Run(t, "basic")) {
		if c := verification.Assess(r.Coverage); !c.Complete {
			t.Errorf("run %d: %v", i, c.Reasons)
		}
	}
}

// At every agreement the five controls give the same 279 rules, all eleven
// claims are corroborated and the harness's own file events are explained.
// What is left is agy's renewal of its access token at the start of the
// task run, which no control made: the connection to oauth2.googleapis.com,
// reported apart as unexplained harness network activity (V-34), and, read
// with content, its POST of the token endpoint, which is Unrecorded, so the
// run is NOT FAITHFUL. No declaration explains the renewal of 1.4.7: an
// agy session states no version (I-57), and V-54 takes a declaration's
// version from the session only. This pins the counts, so a change is seen.
func TestPaired147AtEachAgreement(t *testing.T) {
	tr := paired147Claims(t)
	if len(tr) != 11 {
		t.Fatalf("%d claims, want 11", len(tr))
	}
	for _, a := range []float64{0.2, 0.4, 0.6, 0.8, 1} {
		v, rules := paired147Verdict(t, tr, a)
		if rules != 279 {
			t.Errorf("agreement %v: %d rules, want 279", a, rules)
		}
		if len(v.Corroborated) != 11 || len(v.Mismatched) != 0 || len(v.Unwitnessed) != 0 || len(v.Unverified) != 0 || len(v.OutsideInterval) != 0 {
			t.Errorf("agreement %v: corroborated %d mismatched %v unwitnessed %v unverified %v outside %v",
				a, len(v.Corroborated), v.Mismatched, v.Unwitnessed, v.Unverified, v.OutsideInterval)
		}
		if len(v.Unrecorded) != 1 || v.Unrecorded[0].ActionType != models.NetRequest || v.Unrecorded[0].Target != "POST https://oauth2.googleapis.com/token" || v.Unrecorded[0].RequestHash == nil {
			t.Errorf("agreement %v: unrecorded %v, want only the token renewal's POST with its body", a, v.Unrecorded)
		}
		if len(v.UnexplainedHarnessNet) != 1 || v.UnexplainedHarnessNet[0].ActionType != models.NetConnect || v.UnexplainedHarnessNet[0].Target != "oauth2.googleapis.com" {
			t.Errorf("agreement %v: unexplained harness network activity %v, want only the connection to oauth2.googleapis.com", a, v.UnexplainedHarnessNet)
		}
		if len(v.UnexplainedHarness) != 0 || v.Outcome != verification.OutcomeNotFaithful {
			t.Errorf("agreement %v: %d unexplained harness events, outcome %s; want none and NOT FAITHFUL", a, len(v.UnexplainedHarness), v.Outcome)
		}
	}
}

// view_file's three opens of b.txt are interleaved with the harness's open
// of its project configuration in the raw capture (I-118): the fold keeps
// the first open of b.txt only, which the claim pairs with.
func TestPaired147ViewFileRunPassesOverTheProjectConfig(t *testing.T) {
	var view models.TrajectoryEntry
	for _, e := range paired147Claims(t) {
		if e.Tool == toolViewFile {
			view = e
		}
	}
	if view.End == nil {
		t.Fatal("no view_file claim with an end")
	}
	g := paired147Run(t, "basic")
	in := func(e models.GroundTruthEvent) bool {
		return e.PID == g.RootPID && !e.Timestamp.Before(view.Timestamp) && !e.Timestamp.After(*view.End)
	}
	shape := func(events models.GroundTruth) string {
		var s []string
		for _, e := range events {
			if in(e) && e.ActionType == models.FileOpen && (e.Target == view.Target || projectConfig.MatchString(e.Target)) {
				s = append(s, filepath.Base(e.Target))
			}
		}
		return strings.Join(s, " ")
	}
	if got, want := shape(g.Events), "b.txt default-cli-project.json b.txt b.txt"; got != want {
		t.Errorf("raw opens in view_file's interval: %q, want %q", got, want)
	}
	if got, want := shape(Adapter{}.NormalizeStream(g.Events)), "b.txt default-cli-project.json"; got != want {
		t.Errorf("normalized opens in view_file's interval: %q, want %q", got, want)
	}
}

// The writes are corroborated on the content the harness wrote, as on 1.3.4
// (I-47).
func TestPaired147WritesAreCorroboratedOnTheirContent(t *testing.T) {
	v, _ := paired147Verdict(t, paired147Claims(t), 0.2)
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

// The fixture holds the account's profile picture under its placeholder
// only (I-119): the requests are kept, the account's id is not.
func TestPaired147KeepsNoProfilePictureID(t *testing.T) {
	var n int
	for _, label := range []string{"basic", "control-1", "control-2", "control-3", "control-4", "control-5"} {
		for _, e := range paired147Run(t, label).Events {
			if strings.Contains(e.Target, "googleusercontent.com/a/") {
				n++
				if !strings.HasSuffix(e.Target, "/a/account-picture") {
					t.Errorf("%s: %s", label, e.Target)
				}
			}
		}
	}
	if n == 0 {
		t.Error("no request of the profile picture: the fixture no longer shows the rewrite")
	}
}
