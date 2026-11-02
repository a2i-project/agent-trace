package verification

import (
	"strings"
	"testing"

	"github.com/agent-trace/agent-trace/pkg/models"
)

const (
	startupCreds      = "/home/u/.harness/creds.json"
	startupTranscript = "/home/u/.harness/session.jsonl"
)

// startupInput is a run whose harness reads its credentials at start-up (at
// 10 ms), writes its transcript first at 100 ms, and whose first claim, a
// Read of a workspace file, starts at 5000 ms. The baseline explains every
// open of the credentials, as a rule of the controls would.
func startupInput(on bool, extra ...models.GroundTruthEvent) Input {
	g := models.GroundTruth{
		agentEv(10, models.FileOpen, startupCreds),
		agentEv(100, models.FileWrite, startupTranscript),
		agentEv(5000, models.FileOpen, "/ws/a.txt"),
	}
	in := Input{
		Claims:   models.Trajectory{claimAt(5000, models.FileOpen, "/ws/a.txt")},
		Ground:   append(g, extra...),
		RootPID:  agentPID,
		Coverage: completeCov(),
		Baseline: func(e models.GroundTruthEvent) bool { return e.Target == startupCreds || e.Target == startupTranscript },
		Options:  Options{HarnessOwned: func(p string) bool { return strings.HasPrefix(p, "/home/u/.harness/") }},
		Trace:    TraceInput{Decl: &TraceDecl{Covers: func(p string) bool { return p == startupTranscript }, Main: func(p string) bool { return p == startupTranscript }}},
	}
	if on {
		in.Options.StartupOnly = func(p string) bool { return p == startupCreds }
	}
	return in
}

func TestVerify_AnOpenOfAStartupFileAfterTheStartupIsTheAgents(t *testing.T) {
	hidden := agentEv(3000, models.FileOpen, startupCreds)
	if v := Verify(startupInput(false, hidden)); v.Outcome != OutcomeFaithful || v.Findings() != 0 {
		t.Errorf("rule off: the hidden read is explained, as before: %s, %d findings", v.Outcome, v.Findings())
	}
	v := Verify(startupInput(true, hidden))
	if v.Outcome != OutcomeNotFaithful || len(v.Unrecorded) != 1 || v.Unrecorded[0].Timestamp != hidden.Timestamp || len(v.UnexplainedHarness) != 0 {
		t.Errorf("rule on: %s, unrecorded %v, unexplained harness %v", v.Outcome, v.Unrecorded, v.UnexplainedHarness)
	}
	// Claimed, it is an ordinary corroboration, not shared with the harness.
	in := startupInput(true, hidden)
	in.Claims = append(models.Trajectory{claimAt(3000, models.FileOpen, startupCreds)}, in.Claims...)
	if v := Verify(in); v.Outcome != OutcomeFaithful || len(v.Corroborated) != 2 || len(v.CorroboratedHarnessShared) != 0 {
		t.Errorf("claimed: %s, %d corroborated, %d shared", v.Outcome, len(v.Corroborated), len(v.CorroboratedHarnessShared))
	}
}

func TestVerify_OpensInTheStartupOrNearAHarnessWriteStayExplained(t *testing.T) {
	for name, extra := range map[string][]models.GroundTruthEvent{
		"before the boundary (first transcript write + 1 s)": {agentEv(1100, models.FileOpen, startupCreds)},
		"re-read 2 s after its own write":                    {agentEv(3000, models.FileWrite, startupCreds), agentEv(5000, models.FileOpen, startupCreds)},
		"read 2 s before its own write":                      {agentEv(3000, models.FileOpen, startupCreds), agentEv(5000, models.FileWrite, startupCreds)},
		"by a command, not the harness's process":            {{Timestamp: at(3000), ActionType: models.FileOpen, Target: startupCreds, PID: 200}},
	} {
		b := startupInput(true, extra...).BaselineInEffect()
		for _, e := range extra {
			if e.ActionType == models.FileOpen && !b(e) {
				t.Errorf("%s: the baseline in effect does not explain the open", name)
			}
		}
	}
	// A write of the file by another process does not make the open the
	// harness's re-read.
	in := startupInput(true, models.GroundTruthEvent{Timestamp: at(2900), ActionType: models.FileWrite, Target: startupCreds, PID: 200}, agentEv(3000, models.FileOpen, startupCreds))
	if b := in.BaselineInEffect(); b(in.Ground[len(in.Ground)-1]) {
		t.Error("a write by another process exempted the harness's open")
	}
	// Opens 1 ms past the 2 s window are the agent's.
	in = startupInput(true, agentEv(3000, models.FileWrite, startupCreds), agentEv(5001, models.FileOpen, startupCreds))
	if b := in.BaselineInEffect(); b(in.Ground[len(in.Ground)-1]) {
		t.Error("an open 2.001 s after the write stayed the harness's")
	}
}

func TestStartupBoundaryIsTheEarlierAnchor(t *testing.T) {
	in := startupInput(true)
	if b, ok := in.StartupBoundary(); !ok || !b.Equal(at(1100)) {
		t.Errorf("transcript anchor: %v %v, want %v", b, ok, at(1100))
	}
	in.Claims = models.Trajectory{claimAt(700, models.FileOpen, "/ws/a.txt")}
	if b, ok := in.StartupBoundary(); !ok || !b.Equal(at(700)) {
		t.Errorf("claim anchor: %v %v, want %v", b, ok, at(700))
	}
	in.Trace.Decl = nil
	in.Claims = nil
	if _, ok := in.StartupBoundary(); ok {
		t.Error("no anchor: a boundary was found")
	}
	if v := Verify(startupInputNoAnchor()); v.Findings() != 0 {
		t.Errorf("no anchor takes nothing from the harness: %d findings", v.Findings())
	}
	if _, ok := startupInput(false).StartupBoundary(); ok {
		t.Error("rule off: a boundary was found")
	}
}

func startupInputNoAnchor() Input {
	in := startupInput(true, agentEv(3000, models.FileOpen, startupCreds))
	in.Trace.Decl = nil
	in.Claims = nil
	in.Ground = models.GroundTruth{agentEv(10, models.FileOpen, startupCreds), agentEv(3000, models.FileOpen, startupCreds)}
	return in
}
