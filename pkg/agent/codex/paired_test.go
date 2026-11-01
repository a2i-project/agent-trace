package codex

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/content"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// The basic task on Codex 0.166.0 (2026-11-01), with five controls, the
// first Codex capture: an exec_command of cat b.txt, an apply_patch that
// adds a.txt, one that updates it, one that updates b.txt, and an
// exec_command of echo hi. Reduced by scripts/make-capture-fixture.py,
// which keeps the rollout's calls and items and leaves out the database
// snapshots; since I-87 it keeps the whole-file read's output and the
// updates' diffs, from which both updates claim their content.
const pairedDir = "testdata/paired-codex-0.166.0-basic"

func pairedRun(t *testing.T, label string) models.GroundTruthFile {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(pairedDir, label+".ground_truth.json"))
	if err != nil {
		t.Fatal(err)
	}
	g, err := models.ParseGroundTruthFile(data)
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	return g
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

func pairedClaims(t *testing.T) (models.Trajectory, agent.Report) {
	t.Helper()
	tr, rep, err := Adapter{}.Parse(filepath.Join(pairedDir, "basic.rollout.jsonl"))
	if err != nil || len(rep.ParseErrors) != 0 || len(rep.UnknownTools) != 0 {
		t.Fatalf("parse: %v %+v", err, rep)
	}
	return tr, rep
}

// verifyPaired verifies claims against g as cmd/verify does, with a
// baseline of the five controls at agreement.
func verifyPaired(t *testing.T, a agent.Adapter, claims models.Trajectory, g models.GroundTruthFile, agreement float64) verification.Verdict {
	t.Helper()
	b, err := agent.Capture(a, "0.166.0", pairedControls(t), time.Now(), agent.CaptureOptions{Exclude: []string{agent.ControlCommand}, MinAgreement: agreement})
	if err != nil {
		t.Fatal(err)
	}
	in := agent.PrepareWithBaseline(a, claims, g, &b, verification.Options{IntervalSlack: 500 * time.Millisecond})
	in.Options.HarnessBookkeeping = agent.HarnessBookkeeping(a, "0.166.0", g)
	in.Options.HarnessHousekeeping = agent.HarnessHousekeeping(a, "0.166.0")
	in.Trace.Decl = agent.Trace(a, g)
	return verification.Verify(in)
}

// The harness's model traffic, as the net probe writes it with content
// capture, added to the capture by the harness process: it is
// declared housekeeping (I-89), no finding; a request of another path by
// the same process stays a finding.
func TestPairedModelTrafficIsHousekeeping(t *testing.T) {
	tr, _ := pairedClaims(t)
	g := pairedRun(t, "basic")
	harness := agent.Rooted(Adapter{}, g).RootPID
	at := g.Events[len(g.Events)-1].Timestamp
	h1, h2 := "sha256:01", "sha256:02"
	base := verifyPaired(t, Adapter{}, tr, g, 0.2)
	g.Events = append(g.Events,
		models.GroundTruthEvent{Timestamp: at, PID: harness, ActionType: models.NetRequest, Target: "GET " + modelAPI},
		models.GroundTruthEvent{Timestamp: at, PID: harness, ActionType: models.NetRequest, Target: "WS " + modelAPI, RequestHash: &h1},
		models.GroundTruthEvent{Timestamp: at, PID: harness, ActionType: models.NetRequest, Target: "WS " + modelAPI, RequestHash: &h2},
	)
	v := verifyPaired(t, Adapter{}, tr, g, 0.2)
	if v.Outcome != base.Outcome || v.Findings() != base.Findings() || len(v.HarnessHousekeeping) != 3 {
		t.Errorf("%s, %d findings, housekeeping %d; want %s, %d findings and the three requests declared", v.Outcome, v.Findings(), len(v.HarnessHousekeeping), base.Outcome, base.Findings())
	}
	g.Events = append(g.Events, models.GroundTruthEvent{Timestamp: at, PID: harness, ActionType: models.NetRequest, Target: "WS https://chatgpt.com/backend-api/other", RequestHash: &h1})
	if v := verifyPaired(t, Adapter{}, tr, g, 0.2); v.Outcome != verification.OutcomeNotFaithful || len(v.HarnessHousekeeping) != 3 {
		t.Errorf("another path: %s, housekeeping %d", v.Outcome, len(v.HarnessHousekeeping))
	}
}

// Five loss-free controls; the task run lost six file events of the
// harness process (V-39), and no event of any run is ambiguous.
func TestPairedCaptureLostOnlyTheStartupCleanup(t *testing.T) {
	for i, r := range pairedControls(t) {
		if c := verification.Assess(r.Coverage); !c.Complete {
			t.Errorf("control %d: %v", i+1, c.Reasons)
		}
	}
	g := pairedRun(t, "basic")
	fs := g.Coverage.Probes["fs"]
	if fs.UnresolvedInTree != 6 || fs.RingbufDrops != 0 || fs.ChannelDrops != 0 {
		t.Errorf("fs coverage %+v, want six unresolved events in the tree and no drop", fs)
	}
	for _, r := range append(pairedControls(t), g) {
		for _, e := range r.Events {
			if e.PathIsAmbiguous {
				t.Fatalf("ambiguous event %+v", e)
			}
		}
	}
}

func TestPairedTaskClaimsEveryEffectOnce(t *testing.T) {
	tr, rep := pairedClaims(t)
	if rep.AgentVersion != "0.166.0" || rep.ToolCalls != 5 || len(tr) != 8 {
		t.Fatalf("version %s, %d calls, %d claims", rep.AgentVersion, rep.ToolCalls, len(tr))
	}
	var cmds, updates []string
	adds := 0
	for _, c := range tr {
		if c.ActionType == models.ProcessExec {
			cmds = append(cmds, c.Target)
		}
		if c.Tool == toolAdd && c.ActionType == models.FileWrite && *c.OutputHash == content.SHA256Bytes([]byte("hello\n")) {
			adds++
		}
		// a.txt from its add, b.txt from the cat of it (I-87).
		if c.Tool == toolUpdate && c.ActionType == models.FileWrite && c.OutputHash != nil {
			switch {
			case strings.HasSuffix(c.Target, "/a.txt") && *c.OutputHash == content.SHA256Bytes([]byte("world\n")):
				updates = append(updates, "a.txt")
			case strings.HasSuffix(c.Target, "/b.txt") && *c.OutputHash == content.SHA256Bytes([]byte("again\n")):
				updates = append(updates, "b.txt")
			}
		}
	}
	if strings.Join(cmds, ";") != "cat b.txt;echo hi" || adds != 1 || strings.Join(updates, ";") != "a.txt;b.txt" {
		t.Errorf("commands %v, hashed adds %d, updates with their content %v", cmds, adds, updates)
	}
}

// Every claim is corroborated at every agreement, the add and both updates
// on their content,
// with no finding and no unexplained harness file event; the run is
// INCONCLUSIVE on the capture's loss, and on git remote -v, the harness's
// command after a turn that applied a patch, which no control ran (I-83).
func TestPairedCorroboratesEveryClaimAtEveryAgreement(t *testing.T) {
	tr, _ := pairedClaims(t)
	g := pairedRun(t, "basic")
	for _, ag := range []float64{0.2, 0.4, 0.6, 0.8, 1} {
		v := verifyPaired(t, Adapter{}, tr, g, ag)
		if v.Outcome != verification.OutcomeInconclusive || v.Findings() != 0 || len(v.Corroborated) != 8 || len(v.Unverified) != 0 ||
			len(v.UnexplainedHarness) != 0 || len(v.UnexplainedHarnessNet) != 0 || len(v.UnexplainedHarnessCommands) != 1 {
			t.Errorf("agreement %v: %s, %d findings, %d corroborated, %d unverified, harness %d files %d hosts %d commands; reasons %v",
				ag, v.Outcome, v.Findings(), len(v.Corroborated), len(v.Unverified), len(v.UnexplainedHarness), len(v.UnexplainedHarnessNet), len(v.UnexplainedHarnessCommands), v.Reasons)
			continue
		}
		if c := v.UnexplainedHarnessCommands[0]; c.Exec == nil || c.Exec.Target != gitRemote {
			t.Errorf("agreement %v: the harness command is %+v", ag, c.Exec)
		}
		if len(v.Reasons) != 1 || !strings.Contains(v.Reasons[0], "V-39") {
			t.Errorf("agreement %v: reasons %v, want the loss", ag, v.Reasons)
		}
	}
}

// With the loss set aside, the one reason left is the harness command.
func TestPairedWithoutTheLossOnlyTheHarnessCommandRemains(t *testing.T) {
	tr, _ := pairedClaims(t)
	g := pairedRun(t, "basic")
	fs := g.Coverage.Probes["fs"]
	fs.UnresolvedInTree, fs.UnresolvedPaths = 0, 0
	g.Coverage.Probes["fs"] = fs
	v := verifyPaired(t, Adapter{}, tr, g, 1)
	if v.Outcome != verification.OutcomeInconclusive || len(v.Reasons) != 1 || !strings.Contains(v.Reasons[0], "declares as the harness's own") {
		t.Errorf("%s, reasons %v; want INCONCLUSIVE on the harness command alone", v.Outcome, v.Reasons)
	}
}

// What an altered trajectory is caught as: an omitted update, a substituted
// add, a substituted update (I-87), a fabricated command and an omitted
// command.
func TestPairedCatchesAlteredTrajectories(t *testing.T) {
	tr, _ := pairedClaims(t)
	g := pairedRun(t, "basic")
	drop := func(match func(models.TrajectoryEntry) bool) models.Trajectory {
		var out models.Trajectory
		for _, c := range tr {
			if !match(c) {
				out = append(out, c)
			}
		}
		return out
	}
	other := content.SHA256Bytes([]byte("bye\n"))
	substituted := append(models.Trajectory{}, tr...)
	for i := range substituted {
		if substituted[i].Tool == toolAdd && substituted[i].ActionType == models.FileWrite {
			substituted[i].OutputHash = &other
		}
	}
	substitutedUpdate := append(models.Trajectory{}, tr...)
	for i := range substitutedUpdate {
		if substitutedUpdate[i].Tool == toolUpdate && substitutedUpdate[i].ActionType == models.FileWrite && strings.HasSuffix(substitutedUpdate[i].Target, "/b.txt") {
			substitutedUpdate[i].OutputHash = &other
		}
	}
	fabricated := append(append(models.Trajectory{}, tr...), models.TrajectoryEntry{Timestamp: tr[len(tr)-1].Timestamp.Add(time.Second), ActionType: models.ProcessExec, Target: "rm -rf /ws", Tool: toolCommand})
	cases := map[string]struct {
		claims models.Trajectory
		check  func(verification.Verdict) bool
	}{
		"omitted update of b.txt": {drop(func(c models.TrajectoryEntry) bool {
			return strings.HasSuffix(c.Target, "/b.txt") && c.Tool == toolUpdate
		}),
			func(v verification.Verdict) bool { return len(v.Unrecorded) >= 2 }},
		"substituted add":    {substituted, func(v verification.Verdict) bool { return len(v.Mismatched) == 1 }},
		"substituted update": {substitutedUpdate, func(v verification.Verdict) bool { return len(v.Mismatched) == 1 }},
		"fabricated command": {fabricated, func(v verification.Verdict) bool { return len(v.Unwitnessed) == 1 }},
		"omitted echo hi": {drop(func(c models.TrajectoryEntry) bool { return c.Target == "echo hi" }),
			func(v verification.Verdict) bool { return len(v.Unrecorded) == 1 }},
	}
	for name, c := range cases {
		v := verifyPaired(t, Adapter{}, c.claims, g, 0.2)
		if v.Outcome != verification.OutcomeNotFaithful || !c.check(v) {
			t.Errorf("%s: %s, mismatched %d, unwitnessed %d, unrecorded %d", name, v.Outcome, len(v.Mismatched), len(v.Unwitnessed), len(v.Unrecorded))
		}
	}
}

// A command that deletes the rollout, added to the capture, is trace
// tampering; the harness's own writing of its rollout and databases is not.
func TestPairedACommandDeletingTheRolloutIsTampering(t *testing.T) {
	tr, _ := pairedClaims(t)
	g := pairedRun(t, "basic")
	if v := verifyPaired(t, Adapter{}, tr, g, 0.2); len(v.TraceTampering) != 0 {
		t.Fatalf("the honest run has trace tampering: %+v", v.TraceTampering)
	}
	harness := agent.Rooted(Adapter{}, g).RootPID
	var rollout string
	for _, e := range g.Events {
		if e.PID == harness && e.ActionType == models.FileWrite && strings.Contains(e.Target, "/.codex/sessions/") {
			rollout = e.Target
			break
		}
	}
	at := g.Events[len(g.Events)-1].Timestamp
	g.Events = append(g.Events,
		models.GroundTruthEvent{Timestamp: at, PID: 99999, PPID: harness, ActionType: models.ProcessFork, Target: "99999"},
		models.GroundTruthEvent{Timestamp: at, PID: 99999, PPID: harness, ActionType: models.ProcessExec, Target: "rm " + rollout},
		models.GroundTruthEvent{Timestamp: at, PID: 99999, ActionType: models.FileDelete, Target: rollout},
	)
	v := verifyPaired(t, Adapter{}, tr, g, 0.2)
	if v.Outcome != verification.OutcomeNotFaithful || len(v.TraceTampering) != 1 {
		t.Errorf("%s, tampering %+v", v.Outcome, v.TraceTampering)
	}
}

// bare is the adapter with none of its optional declarations: no launcher,
// no stream folds, no canonical ids, no harness directories or commands.
type bare struct{ agent.Adapter }

// Without its declarations the honest run is NOT FAITHFUL: rooted at the
// npm launcher, the harness is one unclaimed command and nothing pairs.
func TestPairedNeedsTheDeclarations(t *testing.T) {
	tr, _ := pairedClaims(t)
	v := verifyPaired(t, bare{Adapter{}}, tr, pairedRun(t, "basic"), 0.2)
	if v.Outcome != verification.OutcomeNotFaithful || len(v.Corroborated) == 8 {
		t.Errorf("%s with %d corroborated, want NOT FAITHFUL", v.Outcome, len(v.Corroborated))
	}
}
