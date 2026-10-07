package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/models"
)

var t0 = time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)

func writeJSON(t *testing.T, dir, name string, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func completeCov() *models.Coverage {
	return &models.Coverage{Schema: models.CoverageSchema, Probes: map[string]models.ProbeCoverage{"fs": {Ran: true}}}
}

func event(typ models.ActionType, target string) models.GroundTruthEvent {
	return models.GroundTruthEvent{Timestamp: t0, ActionType: typ, Target: target, PID: 100}
}

func claim(typ models.ActionType, target string) models.TrajectoryEntry {
	return models.TrajectoryEntry{Timestamp: t0, ActionType: typ, Target: target}
}

func verify(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestVerdictsAndExitCodes(t *testing.T) {
	dir := t.TempDir()
	trajectory := writeJSON(t, dir, "t.json", models.Trajectory{claim(models.FileWrite, "/w/a")})
	good := writeJSON(t, dir, "g.json", models.GroundTruthFile{Events: models.GroundTruth{event(models.FileWrite, "/w/a")}, RootPID: 100, Coverage: completeCov()})
	omission := writeJSON(t, dir, "omission.json", models.GroundTruthFile{Events: models.GroundTruth{event(models.FileWrite, "/w/a"), event(models.FileWrite, "/w/secret")}, RootPID: 100, Coverage: completeCov()})
	noCoverage := writeJSON(t, dir, "nocov.json", models.GroundTruthFile{Events: models.GroundTruth{event(models.FileWrite, "/w/a")}, RootPID: 100})
	noRoot := writeJSON(t, dir, "noroot.json", models.GroundTruthFile{Events: models.GroundTruth{event(models.FileWrite, "/w/a")}, Coverage: completeCov()})

	tests := []struct {
		name, ground, verdict string
		code                  int
	}{
		{"faithful", good, "VERDICT: FAITHFUL", 0},
		{"omission", omission, "VERDICT: NOT FAITHFUL", 1},
		{"no coverage record", noCoverage, "VERDICT: INCONCLUSIVE", 2},
		{"no root pid", noRoot, "VERDICT: INCONCLUSIVE", 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errOut := verify(t, "--trajectory", trajectory, "--ground-truth", tc.ground)
			if code != tc.code || !strings.Contains(out, tc.verdict) {
				t.Errorf("exit %d, want %d; output:\n%s\nstderr: %s", code, tc.code, out, errOut)
			}
			if !strings.Contains(out, "read by the generic adapter") {
				t.Errorf("a normalized JSON trajectory must fall back to the generic adapter:\n%s", out)
			}
		})
	}
}

func TestOmissionNamesTheUnreportedAction(t *testing.T) {
	dir := t.TempDir()
	tr := writeJSON(t, dir, "t.json", models.Trajectory{claim(models.FileWrite, "/w/a")})
	g := writeJSON(t, dir, "g.json", models.GroundTruthFile{Events: models.GroundTruth{event(models.FileWrite, "/w/a"), event(models.FileWrite, "/w/secret")}, RootPID: 100, Coverage: completeCov()})
	_, out, _ := verify(t, "--trajectory", tr, "--ground-truth", g)
	if !strings.Contains(out, "Unrecorded:   1") || !strings.Contains(out, "/w/secret") {
		t.Errorf("the report does not name the omitted action:\n%s", out)
	}
}

func TestUsageAndIOErrorsAreNotVerdicts(t *testing.T) {
	dir := t.TempDir()
	tr := writeJSON(t, dir, "t.json", models.Trajectory{claim(models.FileWrite, "/w/a")})
	g := writeJSON(t, dir, "g.json", models.GroundTruthFile{RootPID: 100, Coverage: completeCov()})
	bad := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(bad, []byte("{"), 0o644)
	badTr := filepath.Join(dir, "badtr.json")
	_ = os.WriteFile(badTr, []byte(`[{"action_type":"file_write"}]`), 0o644)

	tests := map[string][]string{
		"no flags":             {},
		"no ground truth":      {"--trajectory", tr},
		"unknown agent":        {"--trajectory", tr, "--ground-truth", g, "--agent", "nope"},
		"missing trajectory":   {"--trajectory", filepath.Join(dir, "none"), "--ground-truth", g},
		"missing ground truth": {"--trajectory", tr, "--ground-truth", filepath.Join(dir, "none")},
		"malformed ground":     {"--trajectory", tr, "--ground-truth", bad},
		"invalid trajectory":   {"--trajectory", badTr, "--ground-truth", g},
		"missing baseline":     {"--trajectory", tr, "--ground-truth", g, "--baseline", filepath.Join(dir, "none")},
		"unknown flag":         {"--nope"},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			// Exit code 1 means NOT FAITHFUL, so a failure to verify must never use it.
			if code, _, errOut := verify(t, args...); code != exitError || errOut == "" {
				t.Errorf("exit %d, stderr %q, want exit %d with a message", code, errOut, exitError)
			}
		})
	}
}

// The adapter is chosen from the file when it is a real session, so a Claude
// Code transcript reads through its adapter and reports what it cannot map.
func TestADetectedAdapterReadsItsOwnFormatAndReportsItsLimits(t *testing.T) {
	g := writeJSON(t, t.TempDir(), "g.json", models.GroundTruthFile{RootPID: 100, Coverage: completeCov()})
	_, out, _ := verify(t, "--trajectory", "../../pkg/agent/claudecode/testdata/session.jsonl", "--ground-truth", g)
	for _, want := range []string{"read by the claude-code adapter", "tool call(s) became", "WARNING tools with no mapping", "NotebookEdit", "limitation:", "no baseline supplied", "parse error:"} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
}

func TestAgentFlagOverridesDetection(t *testing.T) {
	g := writeJSON(t, t.TempDir(), "g.json", models.GroundTruthFile{RootPID: 100, Coverage: completeCov()})
	code, out, errOut := verify(t, "--trajectory", "../../pkg/agent/claudecode/testdata/session.jsonl", "--ground-truth", g, "--agent", "generic")
	// Read as normalized JSON the transcript is not a trajectory.
	if code != exitError || !strings.Contains(errOut, "generic adapter") {
		t.Errorf("exit %d, stdout %q, stderr %q, want a generic-adapter read error", code, out, errOut)
	}
}

// --- baseline ---

func TestBaselineExplainsTheHarnessAndOnlyForItsOwnAgent(t *testing.T) {
	dir := t.TempDir()
	tr := writeJSON(t, dir, "t.json", models.Trajectory{})
	harness := models.GroundTruthFile{Events: models.GroundTruth{event(models.NetConnect, "api.example")}, RootPID: 100, Coverage: completeCov()}
	g := writeJSON(t, dir, "g.json", harness)

	if code, out, _ := verify(t, "--trajectory", tr, "--ground-truth", g); code != 1 {
		t.Errorf("without a baseline exit %d, want 1:\n%s", code, out)
	}

	b := agent.Baseline{Schema: agent.BaselineSchema, Agent: agent.GenericName, AgentVersion: "1", Captured: t0, Runs: 3,
		Rules: []agent.Rule{{ActionType: models.NetConnect, Target: "api.example"}}}
	bp := filepath.Join(dir, "b.json")
	if err := agent.SaveBaseline(bp, b); err != nil {
		t.Fatal(err)
	}
	code, out, _ := verify(t, "--trajectory", tr, "--ground-truth", g, "--baseline", bp)
	if code != 0 || !strings.Contains(out, "baseline:") || !strings.Contains(out, "3 control run(s)") {
		t.Errorf("with a baseline exit %d, want 0 and the baseline named:\n%s", code, out)
	}

	b.Agent = "claude-code"
	_ = agent.SaveBaseline(bp, b)
	if code, _, errOut := verify(t, "--trajectory", tr, "--ground-truth", g, "--baseline", bp); code != exitError || !strings.Contains(errOut, "captured for") {
		t.Errorf("a baseline for another agent: exit %d, stderr %q, want a refusal", code, errOut)
	}
}

func TestIgnoreExitsFlag(t *testing.T) {
	dir := t.TempDir()
	tr := writeJSON(t, dir, "t.json", models.Trajectory{claim(models.ProcessExec, "ls")})
	events := models.GroundTruth{
		{Timestamp: t0, ActionType: models.ProcessFork, Target: "x", PID: 200, PPID: 100},
		{Timestamp: t0, ActionType: models.ProcessExec, Target: "ls", PID: 200, PPID: 100},
		{Timestamp: t0, ActionType: models.ProcessExit, Target: "ls", PID: 200, PPID: 100},
	}
	g := writeJSON(t, dir, "g.json", models.GroundTruthFile{Events: events, RootPID: 100, Coverage: completeCov()})
	if code, _, _ := verify(t, "--trajectory", tr, "--ground-truth", g); code != 1 {
		t.Errorf("an unclaimed exit under the generic adapter: exit %d, want 1", code)
	}
	if code, out, _ := verify(t, "--trajectory", tr, "--ground-truth", g, "--ignore-exits"); code != 0 {
		t.Errorf("--ignore-exits: exit %d, want 0:\n%s", code, out)
	}
}

func TestIntervalSlackFlag(t *testing.T) {
	dir := t.TempDir()
	end := t0.Add(10 * time.Millisecond)
	c := claim(models.FileWrite, "/w/a")
	c.End = &end
	tr := writeJSON(t, dir, "t.json", models.Trajectory{c})
	late := event(models.FileWrite, "/w/a")
	late.Timestamp = t0.Add(200 * time.Millisecond) // 190ms after the claim ended
	g := writeJSON(t, dir, "g.json", models.GroundTruthFile{Events: models.GroundTruth{late}, RootPID: 100, Coverage: completeCov()})
	if code, _, _ := verify(t, "--trajectory", tr, "--ground-truth", g); code != 0 {
		t.Errorf("within the default 500ms slack: exit %d, want 0", code)
	}
	if code, _, _ := verify(t, "--trajectory", tr, "--ground-truth", g, "--interval-slack", "0"); code != 1 {
		t.Errorf("with no slack: exit %d, want 1", code)
	}
}
