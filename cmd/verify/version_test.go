package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agent-trace/agent-trace/pkg/config"
)

const (
	ccFixture     = "../../pkg/agent/claudecode/testdata/paired-2.1.286"
	geminiFixture = "../../pkg/agent/gemini/testdata/paired-agy-1.3.4-basic"
)

// sessionOfVersion copies the 2.1.286 task transcript with its version
// replaced, so the session states a version the config does not list.
func sessionOfVersion(t *testing.T, version string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(ccFixture, "task.session.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "task.session.jsonl")
	out := strings.ReplaceAll(string(data), `"version": "2.1.286"`, `"version": "`+version+`"`)
	if out == string(data) {
		t.Fatal("the fixture's version field was not found")
	}
	if err := os.WriteFile(p, []byte(out), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func readVersionJSON(t *testing.T, path string) versionJSON {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var j versionJSON
	if err := json.Unmarshal(data, &j); err != nil {
		t.Fatal(err)
	}
	return j
}

func secondLine(out string) string {
	lines := strings.SplitN(out, "\n", 3)
	if len(lines) < 2 {
		return ""
	}
	return lines[1]
}

func TestAgentVersionCheck(t *testing.T) {
	ccGround := filepath.Join(ccFixture, "task.ground_truth.json")
	geminiDB := filepath.Join(geminiFixture, "basic.conversation.db")
	geminiGround := filepath.Join(geminiFixture, "basic.ground_truth.json")
	unconfigured := sessionOfVersion(t, "2.1.300")
	ccSession := filepath.Join(ccFixture, "task.session.jsonl")

	// The exit code each fixture gives without a baseline, which the check
	// must not change by default.
	ccCode, _, _ := verify(t, "--trajectory", ccSession, "--ground-truth", ccGround)
	geminiCode, _, _ := verify(t, "--agent", "gemini", "--trajectory", geminiDB, "--ground-truth", geminiGround)

	tf, ff := true, false
	tests := []struct {
		name       string
		args       []string
		code       int
		warning    string // the report's second line starts with it; "" means no WARNING line
		reason     string // a verdict reason containing it
		version    string
		source     string
		configured *bool
		check      string
	}{
		{"configured version", []string{"--trajectory", ccSession, "--ground-truth", ccGround},
			ccCode, "", "", "2.1.286", "session", &tf, "configured"},
		{"configured version, strict", []string{"--trajectory", ccSession, "--ground-truth", ccGround, "--strict-version"},
			ccCode, "", "", "2.1.286", "session", &tf, "configured"},
		{"unconfigured version warns, verdict unchanged", []string{"--trajectory", unconfigured, "--ground-truth", ccGround},
			ccCode, "WARNING: claude-code version 2.1.300 is not configured", "", "2.1.300", "session", &ff, "not configured"},
		{"unconfigured version, strict", []string{"--trajectory", unconfigured, "--ground-truth", ccGround, "--strict-version"},
			2, "WARNING: claude-code version 2.1.300 is not configured", "the session was recorded by claude-code version 2.1.300", "2.1.300", "session", &ff, "not configured"},
		{"gemini states no version", []string{"--agent", "gemini", "--trajectory", geminiDB, "--ground-truth", geminiGround},
			geminiCode, "", "", "", "", nil, "unknown"},
		{"gemini states no version, strict", []string{"--agent", "gemini", "--trajectory", geminiDB, "--ground-truth", geminiGround, "--strict-version"},
			2, "", "the session does not state the gemini version", "", "", nil, "unknown"},
		{"gemini version given", []string{"--agent", "gemini", "--trajectory", geminiDB, "--ground-truth", geminiGround, "--strict-version", "--agent-version", "1.3.4"},
			geminiCode, "", "", "1.3.4", "--agent-version", &tf, "configured"},
		{"gemini version given, unconfigured", []string{"--agent", "gemini", "--trajectory", geminiDB, "--ground-truth", geminiGround, "--agent-version", "1.3.5"},
			geminiCode, "WARNING: gemini version 1.3.5 is not configured", "", "1.3.5", "--agent-version", &ff, "not configured"},
		{"flag agreeing with the session", []string{"--trajectory", ccSession, "--ground-truth", ccGround, "--agent-version", "2.1.286"},
			ccCode, "", "", "2.1.286", "session", &tf, "configured"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			jsonPath := filepath.Join(t.TempDir(), "report.json")
			code, out, errOut := verify(t, append(tc.args, "--json", jsonPath)...)
			if code != tc.code {
				t.Errorf("exit %d, want %d\n%s%s", code, tc.code, out, errOut)
			}
			second := secondLine(out)
			if tc.warning == "" && strings.HasPrefix(second, "WARNING") {
				t.Errorf("unexpected warning: %s", second)
			}
			if tc.warning != "" && !strings.HasPrefix(second, tc.warning) {
				t.Errorf("second line %q, want it to start with %q", second, tc.warning)
			}
			if tc.reason != "" && !strings.Contains(out, "FAITHFUL cannot be asserted:\n  - "+tc.reason) {
				t.Errorf("the first reason does not start with %q:\n%s", tc.reason, out)
			}
			j := readVersionJSON(t, jsonPath)
			if j.AgentVersion != tc.version || j.AgentVersionSource != tc.source || j.AgentVersionCheck != tc.check ||
				(j.AgentVersionConfigured == nil) != (tc.configured == nil) ||
				(j.AgentVersionConfigured != nil && *j.AgentVersionConfigured != *tc.configured) {
				t.Errorf("JSON %+v (configured %v), want version %q source %q check %q configured %v", j, j.AgentVersionConfigured, tc.version, tc.source, tc.check, tc.configured)
			}
		})
	}
}

// TestStrictVersionKeepsFindingsListed: a run with findings on an
// unconfigured version is INCONCLUSIVE under --strict-version, and the reason
// says the findings may come from the version.
func TestStrictVersionKeepsFindingsListed(t *testing.T) {
	unconfigured := sessionOfVersion(t, "2.1.300")
	ground := filepath.Join(ccFixture, "task.ground_truth.json")
	code, out, _ := verify(t, "--trajectory", unconfigured, "--ground-truth", ground)
	if code != 1 {
		t.Fatalf("the fixture without a baseline should be NOT FAITHFUL, got exit %d", code)
	}
	code, out2, _ := verify(t, "--trajectory", unconfigured, "--ground-truth", ground, "--strict-version")
	if code != 2 || !strings.Contains(out2, "VERDICT: INCONCLUSIVE") || !strings.Contains(out2, "finding(s) above may come from that") {
		t.Errorf("exit %d\n%s", code, out2)
	}
	// Everything above the verdict but the WARNING line's tail is the same.
	cut := func(s string) string {
		s = s[strings.Index(s, "\n")+1:]
		s = s[strings.Index(s, "\n")+1:]
		return s[:strings.Index(s, "\nVERDICT:")]
	}
	if cut(out) != cut(out2) {
		t.Error("--strict-version changed the report above the verdict")
	}
}

func TestAgentVersionErrors(t *testing.T) {
	ccSession := filepath.Join(ccFixture, "task.session.jsonl")
	ccGround := filepath.Join(ccFixture, "task.ground_truth.json")
	dir := t.TempDir()

	code, _, errOut := verify(t, "--trajectory", ccSession, "--ground-truth", ccGround, "--agent-version", "2.1.296")
	if code != exitError || !strings.Contains(errOut, "recorded by claude-code version 2.1.286") {
		t.Errorf("a contradicting --agent-version: exit %d, %s", code, errOut)
	}
	code, _, errOut = verify(t, "--trajectory", ccSession, "--ground-truth", ccGround, "--config", filepath.Join(dir, "missing.json"))
	if code != exitError || !strings.Contains(errOut, "agent config") {
		t.Errorf("a missing explicit config: exit %d, %s", code, errOut)
	}
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"schema":9}`), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errOut = verify(t, "--trajectory", ccSession, "--ground-truth", ccGround, "--config", bad)
	if code != exitError || !strings.Contains(errOut, "schema 9") {
		t.Errorf("an invalid config: exit %d, %s", code, errOut)
	}
}

// TestNoConfigFound: outside a checkout, with nothing beside the binary and
// no override, the report warns and the verdict stands; under
// --strict-version it is an error.
func TestNoConfigFound(t *testing.T) {
	ccSession, _ := filepath.Abs(filepath.Join(ccFixture, "task.session.jsonl"))
	ccGround, _ := filepath.Abs(filepath.Join(ccFixture, "task.ground_truth.json"))
	t.Setenv(config.EnvVar, "")
	t.Chdir(t.TempDir())
	// Without a baseline the fixture is NOT FAITHFUL, as in the checkout.
	code, out, _ := verify(t, "--trajectory", ccSession, "--ground-truth", ccGround)
	if code != 1 || !strings.HasPrefix(secondLine(out), "WARNING: no config/agents.json found") {
		t.Errorf("exit %d\n%s", code, out)
	}
	code, _, errOut := verify(t, "--trajectory", ccSession, "--ground-truth", ccGround, "--strict-version")
	if code != exitError || !strings.Contains(errOut, "no config/agents.json found") {
		t.Errorf("strict without a config: exit %d, %s", code, errOut)
	}
}

// TestAdapterWithoutAnEntry: a config that lists no version of the adapter
// warns, and under --strict-version makes the run INCONCLUSIVE.
func TestAdapterWithoutAnEntry(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "agents.json")
	if err := os.WriteFile(cfg, []byte(`{"schema":1,"adapters":{"gemini":{"binary":"agy","versions":[{"version":"1.3.4","verified":"2026-10-13","fixtures":["x"]}]}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	ccSession := filepath.Join(ccFixture, "task.session.jsonl")
	ccGround := filepath.Join(ccFixture, "task.ground_truth.json")
	_, out, _ := verify(t, "--trajectory", ccSession, "--ground-truth", ccGround, "--config", cfg)
	if !strings.HasPrefix(secondLine(out), "WARNING: "+cfg+" has no entry for the claude-code adapter") {
		t.Errorf("second line: %s", secondLine(out))
	}
	code, out, _ := verify(t, "--trajectory", ccSession, "--ground-truth", ccGround, "--config", cfg, "--strict-version")
	if code != 2 || !strings.Contains(out, "has no entry for the claude-code adapter") {
		t.Errorf("exit %d\n%s", code, out)
	}
}

// TestGenericAdapterHasNoVersion: the generic adapter stands for no agent,
// so there is nothing to check, also under --strict-version.
func TestGenericAdapterHasNoVersion(t *testing.T) {
	dir := "testdata/p5"
	args := []string{"--trajectory", filepath.Join(dir, "honest.json"), "--ground-truth", filepath.Join(dir, "ground_truth.json"), "--baseline", filepath.Join(dir, "baseline.json")}
	code, out, _ := verify(t, args...)
	code2, out2, _ := verify(t, append(args, "--strict-version")...)
	if code != 0 || code2 != 0 || out != out2 {
		t.Errorf("exit %d and %d under --strict-version", code, code2)
	}
}
