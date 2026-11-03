package main

import (
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// --startup-window applies V-82 to the analysis as verify --startup-window
// does: off, the late open of a start-up-only file is the harness's own
// unexplained activity; on, it is the agent's, Unrecorded. The version is
// the session's, or the manifest's when the session states none (V-85); a
// version that declares no start-up file takes nothing.
func TestStartupWindowAppliesTheRuleAsVerifyDoes(t *testing.T) {
	ad, ok := agent.Lookup("claude-code")
	if !ok {
		t.Fatal("no claude-code adapter")
	}
	ts := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	ev := func(ms int, typ models.ActionType, target string) models.GroundTruthEvent {
		return models.GroundTruthEvent{Timestamp: ts.Add(time.Duration(ms) * time.Millisecond), ActionType: typ, Target: target, PID: 100}
	}
	const creds = "/home/u/.claude/.credentials.json"
	g := models.GroundTruthFile{RootPID: 100, Workspace: "/ws/t", Coverage: &models.Coverage{Schema: models.CoverageSchema, Probes: map[string]models.ProbeCoverage{"fs": {Ran: true}}}, Events: models.GroundTruth{
		ev(10, models.FileOpen, creds),
		ev(100, models.FileWrite, "/home/u/.claude/projects/-ws-t/11111111-2222-3333-4444-555555555555.jsonl"),
		ev(5000, models.FileOpen, creds),
	}}
	for _, tc := range []struct {
		name              string
		on                bool
		session, manifest string
		declared          bool
		unrecorded        int
		outcome           verification.Outcome
	}{
		{"off", false, "2.1.306", "2.1.306", false, 0, verification.OutcomeInconclusive},
		{"on", true, "2.1.306", "2.1.306", true, 1, verification.OutcomeNotFaithful},
		{"on, the manifest's version", true, "", "2.1.306", true, 1, verification.OutcomeNotFaithful},
		{"on, a version without start-up files", true, "2.1.305", "2.1.305", false, 0, verification.OutcomeInconclusive},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Session{Rec: RunRecord{Agent: "claude-code", Version: tc.manifest}, Adapter: ad, G: g, Report: agent.Report{AgentVersion: tc.session}, StartupWindow: tc.on}
			in := s.input(nil, nil)
			if (in.Options.StartupOnly != nil) != tc.declared {
				t.Errorf("start-up files declared %v, want %v", in.Options.StartupOnly != nil, tc.declared)
			}
			v := verification.Verify(in)
			if len(v.Unrecorded) != tc.unrecorded || v.Outcome != tc.outcome {
				t.Errorf("unrecorded %v, outcome %s; want %d and %s", v.Unrecorded, v.Outcome, tc.unrecorded, tc.outcome)
			}
		})
	}
}

// The switch reaches every session through the campaign, and results.json
// and report.md say it was on; off, neither names it, so an analysis
// without the flag is byte-identical to one before it.
func TestStartupWindowIsRecordedInTheResults(t *testing.T) {
	dir := syntheticCampaign(t, pairedRuns[:1])
	off, err := Analyze(Options{Campaign: dir, Out: dir, Config: testOptions(t, dir).Config, LastSeed: 1, Jobs: 1, NoSweep: true, NoSensitivity: true})
	if err != nil {
		t.Fatal(err)
	}
	if off.Inputs.StartupWindow || strings.Contains(Report(off), "start-up window") {
		t.Errorf("off: inputs %+v", off.Inputs)
	}
	o := testOptions(t, dir)
	o.LastSeed, o.NoSweep, o.NoSensitivity, o.StartupWindow = 1, true, true, true
	on, err := Analyze(o)
	if err != nil {
		t.Fatal(err)
	}
	if !on.Inputs.StartupWindow || !strings.Contains(Report(on), "- start-up window on (V-82") {
		t.Errorf("on: inputs %+v", on.Inputs)
	}
	c, err := LoadCampaign(dir)
	if err != nil {
		t.Fatal(err)
	}
	c.StartupWindow = true
	s, err := LoadSession(c, c.Manifest.Runs[0])
	if err != nil || !s.StartupWindow {
		t.Errorf("the session does not carry the switch: %v", err)
	}
}
