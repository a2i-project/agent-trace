package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// The fixtures' agents, as their manifests record them. Only the tests name
// agents; the command reads them from the protocol file.
const (
	AgentClaudeCode = "claude-code"
	AgentGemini     = "gemini"
	AgentCodex      = "codex"
	AgentOpenCode   = "opencode"
)

var (
	repoProtocolOnce sync.Once
	repoProtocolVal  *Protocol
)

// repoProtocol is the repository's config/protocol.json.
func repoProtocol() *Protocol {
	repoProtocolOnce.Do(func() {
		p, err := LoadProtocol(filepath.Join("..", "..", "config", ProtocolFileName))
		if err != nil {
			panic(err)
		}
		repoProtocolVal = p
	})
	return repoProtocolVal
}

func TestRepositoryProtocolHoldsTheRegisteredTargets(t *testing.T) {
	p := repoProtocol()
	cc, ok := p.Targets(AgentClaudeCode)
	if !ok || cc.FaithfulBar.MinRate == nil || *cc.FaithfulBar.MinRate != 0.50 || cc.FaithfulBar.Basis != "D2" {
		t.Fatalf("claude-code FAITHFUL bar: %+v", cc)
	}
	if r := cc.InconclusiveRange; r.Low == nil || *r.Low != 0.30 || *r.High != 0.70 {
		t.Errorf("claude-code pilot range: %+v", r)
	}
	agy, ok := p.Targets(AgentGemini)
	if !ok || agy.FaithfulBar.MinRate != nil || agy.FaithfulBar.None == "" || agy.InconclusiveRange.None == "" {
		t.Errorf("gemini declares no bar and no range: %+v", agy)
	}
	// Codex and OpenCode: no bar and no range (D2 registers Claude Code
	// only), no held-out task (D8 names none), and no tool-heavy task, since
	// neither harness makes a read of a background command's output file
	// that the agent's read shares (I-131).
	for _, name := range []string{AgentCodex, AgentOpenCode} {
		a, ok := p.Targets(name)
		if !ok || a.FaithfulBar.MinRate != nil || a.FaithfulBar.None == "" || a.InconclusiveRange.None == "" ||
			len(*a.ToolHeavyTasks) != 0 || len(*a.D8HeldOutTasks) != 0 {
			t.Errorf("%s: %+v", name, a)
		}
	}
	if err := p.Require([]string{AgentClaudeCode, AgentGemini, AgentCodex, AgentOpenCode}); err != nil {
		t.Errorf("every adapter with a profile has targets: %v", err)
	}
	for _, c := range []struct {
		agent, task string
		want        bool
	}{
		{AgentClaudeCode, "tools", true}, {AgentClaudeCode, "long", true}, {AgentClaudeCode, "long-cc", true}, {AgentClaudeCode, "heldout:long-cc", true},
		{AgentClaudeCode, "edits", false}, {AgentClaudeCode, "long-agy", false},
		{AgentGemini, "long", true}, {AgentGemini, "heldout:long-agy", true}, {AgentGemini, "tools", false},
		{AgentCodex, "tools", false}, {AgentCodex, "long", false}, {AgentOpenCode, "tools", false}, {AgentOpenCode, "long", false},
		{"unlisted", "long", false},
	} {
		if got := p.IsToolHeavy(c.agent, c.task); got != c.want {
			t.Errorf("IsToolHeavy(%s, %s) = %v", c.agent, c.task, got)
		}
	}
	if got := p.heldOutLine(); got != "Claude Code `long`, agy `long` and `subagent`" {
		t.Errorf("held-out line: %q", got)
	}
	if u := p.CaptureUser; u == nil || !u.RequireOtherUser || u.Basis != "I-139" {
		t.Errorf("capture_user: %+v", u)
	}
}

const validAgent = `{"agent": "claude-code", "label": "CC", "faithful_bar": {"min_rate": 0.5, "basis": "D2"}, "inconclusive_pilot_range": {"low": 0.3, "high": 0.7}, "tool_heavy_tasks": ["tools"], "d8_held_out_tasks": []}`

func writeProtocol(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), ProtocolFileName)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func protocolWith(agents ...string) string {
	return `{"schema": 1, "protocol": "test registration", "capture_user": {"none": "a test registration"}, "agents": [` + strings.Join(agents, ", ") + `]}`
}

// The loader refuses unknown fields, a target left out and malformed values,
// so an agent is never analysed against a default.
func TestLoadProtocolRefusesWhatItCannotRead(t *testing.T) {
	if _, err := LoadProtocol(writeProtocol(t, protocolWith(validAgent))); err != nil {
		t.Fatalf("a valid file: %v", err)
	}
	drop := func(field string) string {
		var m map[string]any
		if err := json.Unmarshal([]byte(validAgent), &m); err != nil {
			t.Fatal(err)
		}
		delete(m, field)
		b, _ := json.Marshal(m)
		return string(b)
	}
	with := func(old, new string) string { return strings.Replace(validAgent, old, new, 1) }
	for _, c := range []struct{ name, body, want string }{
		{"unknown top-level field", `{"schema": 1, "protocol": "x", "capture_user": {"none": "x"}, "agents": [` + validAgent + `], "extra": 1}`, "unknown field"},
		{"no capture user", strings.Replace(protocolWith(validAgent), `"capture_user": {"none": "a test registration"}, `, ``, 1), "no capture_user"},
		{"capture user both", strings.Replace(protocolWith(validAgent), `{"none": "a test registration"}`, `{"none": "x", "require_other_user": true, "basis": "I-139"}`, 1), "either require_other_user"},
		{"capture user neither", strings.Replace(protocolWith(validAgent), `{"none": "a test registration"}`, `{}`, 1), "either require_other_user"},
		{"capture user without basis", strings.Replace(protocolWith(validAgent), `{"none": "a test registration"}`, `{"require_other_user": true}`, 1), "without the basis"},
		{"capture user basis with none", strings.Replace(protocolWith(validAgent), `{"none": "a test registration"}`, `{"none": "x", "basis": "I-139"}`, 1), "basis without"},
		{"unknown agent field", protocolWith(with(`"label"`, `"colour": 1, "label"`)), "unknown field"},
		{"trailing data", protocolWith(validAgent) + `{}`, "after the top-level object"},
		{"wrong schema", strings.Replace(protocolWith(validAgent), `"schema": 1`, `"schema": 2`, 1), "schema 2"},
		{"no registration", strings.Replace(protocolWith(validAgent), `"test registration"`, `""`, 1), "no protocol"},
		{"no agents", protocolWith(), "no agents"},
		{"unregistered adapter", protocolWith(with(`"claude-code"`, `"nobody"`)), "no adapter is registered"},
		{"duplicate agent", protocolWith(validAgent, validAgent), "listed twice"},
		{"no label", protocolWith(with(`"CC"`, `""`)), "no label"},
		{"no faithful bar", protocolWith(drop("faithful_bar")), "no faithful_bar"},
		{"bar and none", protocolWith(with(`"basis": "D2"`, `"basis": "D2", "none": "x"`)), "either min_rate"},
		{"bar without basis", protocolWith(with(`, "basis": "D2"`, ``)), "without the basis"},
		{"bar out of range", protocolWith(with(`0.5`, `1.5`)), "not in (0, 1]"},
		{"no pilot range", protocolWith(drop("inconclusive_pilot_range")), "no inconclusive_pilot_range"},
		{"half a range", protocolWith(with(`"low": 0.3, `, ``)), "both low and high"},
		{"inverted range", protocolWith(with(`"low": 0.3`, `"low": 0.8`)), "low <= high"},
		{"no tool-heavy list", protocolWith(drop("tool_heavy_tasks")), "no tool_heavy_tasks"},
		{"no held-out list", protocolWith(drop("d8_held_out_tasks")), "no d8_held_out_tasks"},
		{"prefixed task", protocolWith(with(`["tools"]`, `["heldout:tools"]`)), "without the heldout: prefix"},
		{"duplicate task", protocolWith(with(`["tools"]`, `["tools", "tools"]`)), "listed twice"},
	} {
		_, err := LoadProtocol(writeProtocol(t, c.body))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.want)
		}
	}
}

// A protocol that requires the capture user (I-139) stops the analysis of a
// campaign whose runs did not run the agent as another user, naming the
// runs and the file; the same campaign is analysed under a protocol file
// that declares the requirement absent.
func TestACampaignWithoutTheCaptureUserStopsTheAnalysis(t *testing.T) {
	uid := func(n int) *int { return &n }
	for _, c := range []struct {
		name  string
		runAs *RunAsRecord
		want  string
	}{
		{"no run_as", nil, "claude-code-2.1.296/edits/run-01 (no run_as)"},
		{"the operator", &RunAsRecord{User: "carmine", UID: uid(1000), OperatorUID: uid(1000)}, "(ran as the operator)"},
		{"no operator uid", &RunAsRecord{User: "agenttrace", UID: uid(4242)}, "(no operator uid)"},
	} {
		dir := syntheticCampaign(t, pairedRuns[:1])
		setRunAs(t, dir, c.runAs)
		o := testOptions(t, dir)
		o.NoSweep, o.NoSensitivity = true, true
		var errOut bytes.Buffer
		if code := run(append(runArgs(o), "--no-sweep", "--no-sensitivity"), &bytes.Buffer{}, &errOut); code != exitError {
			t.Fatalf("%s: exit %d, want %d; stderr %s", c.name, code, exitError, errOut.String())
		}
		if msg := errOut.String(); !strings.Contains(msg, c.want) || !strings.Contains(msg, ProtocolFileName+" requires every run") || !strings.Contains(msg, "1 of 1 run(s)") {
			t.Errorf("%s: stderr: %s", c.name, msg)
		}
		o.Protocol = writeProtocol(t, protocolWith(validAgent))
		o.Out = t.TempDir()
		if _, err := Analyze(o); err != nil {
			t.Errorf("%s: with capture_user none: %v", c.name, err)
		}
	}
}

// setRunAs rewrites every run of a synthetic campaign's manifest with the
// given run-as record (nil removes it).
func setRunAs(t *testing.T, dir string, a *RunAsRecord) {
	t.Helper()
	c, err := LoadCampaign(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := range c.Manifest.Runs {
		c.Manifest.Runs[i].RunAs = a
	}
	if err := writeJSON(filepath.Join(dir, "manifest.json"), c.Manifest); err != nil {
		t.Fatal(err)
	}
}

// An agent of the campaign the protocol file does not list stops the
// analysis with a message naming it and the file.
func TestAnAgentWithNoTargetsStopsTheAnalysis(t *testing.T) {
	dir := syntheticCampaign(t, pairedRuns[:3])
	o := testOptions(t, dir)
	o.Protocol = writeProtocol(t, protocolWith(validAgent))
	o.Out = t.TempDir()
	var errOut bytes.Buffer
	args := append(runArgs(o), "--protocol", o.Protocol, "--no-sweep", "--no-sensitivity")
	if code := run(args, &bytes.Buffer{}, &errOut); code != exitError {
		t.Fatalf("exit %d, want %d; stderr %s", code, exitError, errOut.String())
	}
	if msg := errOut.String(); !strings.Contains(msg, "no targets for agent(s) gemini") || !strings.Contains(msg, ProtocolFileName) {
		t.Errorf("stderr: %s", msg)
	}
}

// The targets come from the file: a changed bar, range and label change the
// verdicts, and results.json records the file by name and hash, with the bar
// under the key the registration fixed.
func TestTargetsComeFromTheProtocolFile(t *testing.T) {
	dir := syntheticCampaign(t, pairedRuns[:2])
	o := testOptions(t, dir)
	o.Protocol = writeProtocol(t, protocolWith(strings.Replace(strings.Replace(validAgent, `0.5`, `0.25`, 1), `"low": 0.3`, `"low": 0.0`, 1)))
	o.NoSweep, o.NoSensitivity = true, true
	res, err := Analyze(o)
	if err != nil {
		t.Fatal(err)
	}
	if res.Inputs.ProtocolFile != ProtocolFileName || len(res.Inputs.ProtocolSHA256) != 64 || res.Inputs.ProtocolSHA256 != fileSHA256(o.Protocol) {
		t.Errorf("inputs: %+v", res.Inputs)
	}
	if res.Constants.Protocol != "test registration" {
		t.Errorf("registration: %q", res.Constants.Protocol)
	}
	d := verdictOf(res, "H3d", AgentClaudeCode)
	if !strings.Contains(d.Threshold, "at least 25% of honest runs (D2, CC only)") {
		t.Errorf("H3d threshold: %q", d.Threshold)
	}
	data, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if !strings.Contains(s, `"h3a_near_zero":0.05,"h3d_claude_code_bar":0.25,"h4a_max_wall_ratio":1.15`) {
		t.Errorf("the bar is not where the registration's key was: %s", s[strings.Index(s, `"h3a_near_zero"`):][:120])
	}
	if !strings.Contains(s, `"protocol_sha256":"`+res.Inputs.ProtocolSHA256+`"`) {
		t.Error("results.json lacks the protocol file's hash")
	}
	if !strings.Contains(Report(res), "protocol file `protocol.json`, sha256 `"+res.Inputs.ProtocolSHA256+"`") {
		t.Error("report.md lacks the protocol file's hash")
	}
}
