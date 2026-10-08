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

func cov(p models.ProbeCoverage) *models.Coverage {
	return &models.Coverage{Schema: models.CoverageSchema, Probes: map[string]models.ProbeCoverage{"fs": p}}
}

func ev(typ models.ActionType, target string) models.GroundTruthEvent {
	return models.GroundTruthEvent{Timestamp: t0, ActionType: typ, Target: target, PID: 100}
}

func write(t *testing.T, dir, name string, f models.GroundTruthFile) string {
	t.Helper()
	data, _ := json.Marshal(f)
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func baseline(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestWritesARuleForWhatEveryRunDid(t *testing.T) {
	dir := t.TempDir()
	r1 := write(t, dir, "r1.json", models.GroundTruthFile{RootPID: 100, Coverage: cov(models.ProbeCoverage{Ran: true}),
		Events: models.GroundTruth{ev(models.NetConnect, "api.example"), ev(models.NetConnect, "once.example")}})
	r2 := write(t, dir, "r2.json", models.GroundTruthFile{RootPID: 100, Coverage: cov(models.ProbeCoverage{Ran: true}),
		Events: models.GroundTruth{ev(models.NetConnect, "api.example")}})
	outPath := filepath.Join(dir, "b.json")

	code, out, errOut := baseline(t, "--agent", "generic", "--agent-version", "9.9", "--out", outPath, r1, r2)
	if code != 0 {
		t.Fatalf("exit %d: %s %s", code, out, errOut)
	}
	b, err := agent.LoadBaseline(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if b.Agent != "generic" || b.AgentVersion != "9.9" || b.Runs != 2 || len(b.Rules) != 1 || b.Rules[0].Target != "api.example" || len(b.Unstable) != 1 {
		t.Errorf("baseline = %+v", b)
	}
	if !strings.Contains(out, "1 rule(s)") || !strings.Contains(out, "100% agreement") || !strings.Contains(out, "1 unstable") {
		t.Errorf("summary = %q", out)
	}
	if strings.Contains(out, "capture at least three") {
		t.Error("two runs must not get the single-run note")
	}
}

func TestExcludeFlagKeepsTheControlCommandOutOfTheRules(t *testing.T) {
	dir := t.TempDir()
	marker := models.GroundTruth{
		{Timestamp: t0, ActionType: models.ProcessFork, Target: "x", PID: 200, PPID: 100},
		{Timestamp: t0, ActionType: models.ProcessExec, Target: ": marker", PID: 200, PPID: 100},
		{Timestamp: t0, ActionType: models.ProcessExit, Target: ": marker", PID: 200, PPID: 100},
		ev(models.NetConnect, "api.example"),
	}
	r1 := write(t, dir, "r1.json", models.GroundTruthFile{RootPID: 100, Coverage: cov(models.ProbeCoverage{Ran: true}), Events: marker})
	outPath := filepath.Join(dir, "b.json")
	code, out, errOut := baseline(t, "--agent", "generic", "--agent-version", "9.9", "--out", outPath, "--exclude", ": marker", "--exclude", "other", r1)
	if code != 0 {
		t.Fatalf("exit %d: %s %s", code, out, errOut)
	}
	b, err := agent.LoadBaseline(outPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range b.Rules {
		if r.Target == ": marker" {
			t.Errorf("the excluded command is a rule: %+v", b.Rules)
		}
	}
	if len(b.Rules) != 1 || b.Rules[0].Target != "api.example" {
		t.Errorf("rules = %+v, want only the connection", b.Rules)
	}
	if len(b.Excluded) != 2 || b.Excluded[0] != ": marker" || b.Excluded[1] != "other" {
		t.Errorf("excluded = %v", b.Excluded)
	}
}

func TestWarnsThatOneRunCannotTellStableFromIncidental(t *testing.T) {
	dir := t.TempDir()
	r := write(t, dir, "r.json", models.GroundTruthFile{RootPID: 100, Coverage: cov(models.ProbeCoverage{Ran: true}), Events: models.GroundTruth{ev(models.NetConnect, "h")}})
	_, out, _ := baseline(t, "--agent", "generic", "--agent-version", "1", "--out", filepath.Join(dir, "b.json"), r)
	if !strings.Contains(out, "capture at least three") {
		t.Errorf("no single-run warning: %q", out)
	}
}

// A control run that lost events would leave the baseline short, which later
// reads as false omissions, so it is refused rather than used.
func TestRefusesControlRunsItCannotTrust(t *testing.T) {
	dir := t.TempDir()
	lossy := write(t, dir, "lossy.json", models.GroundTruthFile{RootPID: 100, Coverage: cov(models.ProbeCoverage{Ran: true, RingbufDrops: 2}), Events: models.GroundTruth{ev(models.NetConnect, "h")}})
	nocov := write(t, dir, "nocov.json", models.GroundTruthFile{RootPID: 100, Events: models.GroundTruth{ev(models.NetConnect, "h")}})
	noroot := write(t, dir, "noroot.json", models.GroundTruthFile{Coverage: cov(models.ProbeCoverage{Ran: true}), Events: models.GroundTruth{ev(models.NetConnect, "h")}})
	for name, p := range map[string]string{"lost events": lossy, "no coverage record": nocov, "no root pid": noroot} {
		out := filepath.Join(dir, name+".out")
		code, _, errOut := baseline(t, "--agent", "generic", "--agent-version", "1", "--out", out, p)
		if code != 3 || errOut == "" {
			t.Errorf("%s: exit %d, stderr %q, want a refusal", name, code, errOut)
		}
		if _, err := os.Stat(out); err == nil {
			t.Errorf("%s: a baseline was written anyway", name)
		}
	}
}

func TestUsageErrors(t *testing.T) {
	dir := t.TempDir()
	good := write(t, dir, "g.json", models.GroundTruthFile{RootPID: 100, Coverage: cov(models.ProbeCoverage{Ran: true})})
	bad := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(bad, []byte("{"), 0o644)
	for name, args := range map[string][]string{
		"no arguments":      {},
		"no version":        {"--agent", "generic", good},
		"no agent":          {"--agent-version", "1", good},
		"no runs":           {"--agent", "generic", "--agent-version", "1"},
		"unknown agent":     {"--agent", "nope", "--agent-version", "1", good},
		"missing run":       {"--agent", "generic", "--agent-version", "1", filepath.Join(dir, "none")},
		"malformed run":     {"--agent", "generic", "--agent-version", "1", bad},
		"unwritable output": {"--agent", "generic", "--agent-version", "1", "--out", filepath.Join(dir, "no", "such", "dir", "b.json"), good},
	} {
		if code, _, _ := baseline(t, args...); code != 3 {
			t.Errorf("%s: exit %d, want 3", name, code)
		}
	}
}

func TestMinAgreementFlag(t *testing.T) {
	dir := t.TempDir()
	mk := func(name string, targets ...string) string {
		var g models.GroundTruth
		for _, tg := range targets {
			g = append(g, ev(models.NetConnect, tg))
		}
		return write(t, dir, name, models.GroundTruthFile{RootPID: 100, Coverage: cov(models.ProbeCoverage{Ran: true}), Events: g})
	}
	runs := []string{mk("1.json", "a", "b"), mk("2.json", "a", "b"), mk("3.json", "a")}
	outPath := filepath.Join(dir, "b.json")
	if code, out, errOut := baseline(t, append([]string{"--agent", "generic", "--agent-version", "1", "--min-agreement", "0.6", "--out", outPath}, runs...)...); code != 0 || !strings.Contains(out, "2 rule(s)") || !strings.Contains(out, "60% agreement") {
		t.Fatalf("exit %d, out %q, err %q", code, out, errOut)
	}
	if code, _, _ := baseline(t, append([]string{"--agent", "generic", "--agent-version", "1", "--min-agreement", "2", "--out", outPath}, runs...)...); code != 3 {
		t.Errorf("an agreement above 1: exit %d, want 3", code)
	}
}
