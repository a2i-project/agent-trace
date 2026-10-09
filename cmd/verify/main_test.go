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

// --- normalized claims (what cmd/attack writes) ---

const pairedDir = "../../pkg/agent/claudecode/testdata/paired-2.1.286"

// pairedFiles writes the checked-in real capture's honest claims as normalized
// JSON, and a baseline from its own control runs, so a test can verify them.
func pairedFiles(t *testing.T) (claims, baseline string, tr models.Trajectory) {
	t.Helper()
	ca, ok := agent.Lookup("claude-code")
	if !ok {
		t.Fatal("claude-code adapter is not registered")
	}
	tr, _, err := ca.Parse(filepath.Join(pairedDir, "task.session.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var runs []models.GroundTruthFile
	for _, l := range []string{"control-1", "control-2", "control-3"} {
		data, err := os.ReadFile(filepath.Join(pairedDir, l+".ground_truth.json"))
		if err != nil {
			t.Fatal(err)
		}
		f, err := models.ParseGroundTruthFile(data)
		if err != nil {
			t.Fatal(err)
		}
		runs = append(runs, f)
	}
	b, err := agent.Capture(ca, "2.1.286", runs, t0, agent.CaptureOptions{})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	baseline = filepath.Join(dir, "b.json")
	if err := agent.SaveBaseline(baseline, b); err != nil {
		t.Fatal(err)
	}
	return writeJSON(t, dir, "claims.json", tr), baseline, tr
}

func TestNormalizedClaimsVerifyAgainstARealCapture(t *testing.T) {
	claims, baseline, tr := pairedFiles(t)
	gt := filepath.Join(pairedDir, "task.ground_truth.json")

	code, out, errOut := verify(t, "--normalized", "--agent", "claude-code", "--trajectory", claims, "--ground-truth", gt, "--baseline", baseline)
	if code != 0 || !strings.Contains(out, "VERDICT: FAITHFUL") || !strings.Contains(out, "read as normalized JSON, ground truth normalized by the claude-code adapter") {
		t.Fatalf("honest claims: exit %d\n%s\n%s", code, out, errOut)
	}

	// A claim whose content hash is not what the file ended up holding.
	tampered := append(models.Trajectory{}, tr...)
	for i := range tampered {
		if tampered[i].OutputHash != nil {
			h := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
			tampered[i].OutputHash = &h
			break
		}
	}
	bad := writeJSON(t, t.TempDir(), "tampered.json", tampered)
	code, out, _ = verify(t, "--normalized", "--agent", "claude-code", "--trajectory", bad, "--ground-truth", gt, "--baseline", baseline)
	if code != 1 || !strings.Contains(out, "VERDICT: NOT FAITHFUL") || !strings.Contains(out, "output_hash") {
		t.Errorf("tampered hash: exit %d\n%s", code, out)
	}
}

// Without --agent the ground truth is not normalized by the claude-code adapter,
// so the real capture's wrapped commands do not match their claims. This is why
// the flag exists: normalized claims still need the adapter for the observed side.
func TestNormalizedClaimsNeedTheAdapterForTheGroundTruth(t *testing.T) {
	claims, _, _ := pairedFiles(t)
	code, _, _ := verify(t, "--normalized", "--trajectory", claims, "--ground-truth", filepath.Join(pairedDir, "task.ground_truth.json"))
	if code != 1 {
		t.Errorf("exit %d, want NOT FAITHFUL without the adapter's normalization", code)
	}
}

func TestNormalizedErrors(t *testing.T) {
	dir := t.TempDir()
	g := writeJSON(t, dir, "g.json", models.GroundTruthFile{RootPID: 100, Coverage: completeCov()})
	notJSON := filepath.Join(dir, "x.jsonl")
	_ = os.WriteFile(notJSON, []byte("not a trajectory"), 0o644)
	for name, args := range map[string][]string{
		"unknown agent":    {"--normalized", "--agent", "nope", "--trajectory", notJSON, "--ground-truth", g},
		"not a trajectory": {"--normalized", "--trajectory", notJSON, "--ground-truth", g},
	} {
		if code, _, errOut := verify(t, args...); code != exitError || errOut == "" {
			t.Errorf("%s: exit %d, stderr %q", name, code, errOut)
		}
	}
}

// The forensic view: what a claimed command did beneath it is listed per
// command in the text report and in full in the JSON report, and none of it
// is a finding (D3).
func TestForensicViewListsWhatEachCommandDid(t *testing.T) {
	dir := t.TempDir()
	const root, sh, child = 100, 200, 300
	ev := func(ms int, typ models.ActionType, target string, pid, ppid uint32) models.GroundTruthEvent {
		return models.GroundTruthEvent{Timestamp: t0.Add(time.Duration(ms) * time.Millisecond), ActionType: typ, Target: target, PID: pid, PPID: ppid}
	}
	code := int32(0)
	exit := ev(9, models.ProcessExit, "/bin/sh -c deploy.sh", sh, root)
	exit.ExitCode = &code
	g := models.GroundTruthFile{RootPID: root, Coverage: completeCov(), Workspace: "/w", Events: models.GroundTruth{
		ev(0, models.ProcessFork, "200", sh, root),
		ev(1, models.ProcessExec, "/bin/sh -c deploy.sh", sh, root),
		ev(2, models.ProcessFork, "300", child, sh),
		ev(3, models.ProcessExec, "/usr/bin/curl https://updates.example/pkg", child, sh),
		ev(4, models.NetConnect, "updates.example", child, 0),
		ev(5, models.FileWrite, "/w/pkg.tar", child, 0),
		ev(6, models.FileOpen, "/etc/ssl/certs/ca.pem", child, 0),
		ev(7, models.NetListen, "0.0.0.0:8080", sh, 0),
		ev(8, models.NetUnixConnect, "unix:/var/run/docker.sock", sh, 0),
		exit,
	}}
	tr := models.Trajectory{{Timestamp: t0, ActionType: models.ProcessExec, Target: "/bin/sh -c deploy.sh"}}
	trajectory := writeJSON(t, dir, "t.json", tr)
	ground := writeJSON(t, dir, "g.json", g)
	jsonOut := filepath.Join(dir, "report.json")

	exitCode, out, errOut := verify(t, "--trajectory", trajectory, "--ground-truth", ground, "--json", jsonOut, "--ignore-exits")
	if exitCode != 0 {
		t.Fatalf("exit %d, stderr %s\n%s", exitCode, errOut, out)
	}
	for _, want := range []string{
		"Commands (forensic view",
		"pid 200 [claimed, exit 0] /bin/sh -c deploy.sh",
		"programs run (1): /usr/bin/curl https://updates.example/pkg",
		"files written (1): /w/pkg.tar",
		"files opened (1): /etc/ssl/certs/ca.pem",
		"connections (1): updates.example",
		"listeners (1): 0.0.0.0:8080",
		"unix sockets (1): unix:/var/run/docker.sock",
		"VERDICT: FAITHFUL",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q\n%s", want, out)
		}
	}

	data, err := os.ReadFile(jsonOut)
	if err != nil {
		t.Fatal(err)
	}
	var rep jsonReport
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatalf("JSON report does not parse: %v", err)
	}
	if rep.Outcome != "FAITHFUL" || rep.ExitCode != 0 || rep.Findings != 0 || rep.RootPID != root || rep.Workspace != "/w" {
		t.Errorf("header = %+v", rep)
	}
	if len(rep.Commands) != 1 || rep.Commands[0].PID != sh || rep.Commands[0].Status != "claimed" || rep.Commands[0].Exec == nil || rep.Commands[0].Exit == nil {
		t.Fatalf("commands = %+v", rep.Commands)
	}
	if n := len(rep.Commands[0].Events); n != 4 {
		t.Errorf("the command's events = %d, want the child's exec, connect, write and open; the command's own exit is in exit, not here", n)
	}
	if n := len(rep.Commands[0].Capability); n != 2 {
		t.Errorf("the command's capability events = %d, want the listener and the socket", n)
	}
	if len(rep.Alignment.Corroborated) != 1 || len(rep.Capability) != 2 || !rep.Coverage.Complete || rep.Coverage.Explained != 4 {
		t.Errorf("lists = %+v", rep)
	}
}

func TestJSONReportWriteErrorIsAnError(t *testing.T) {
	dir := t.TempDir()
	trajectory := writeJSON(t, dir, "t.json", models.Trajectory{claim(models.FileWrite, "/w/a")})
	ground := writeJSON(t, dir, "g.json", models.GroundTruthFile{Events: models.GroundTruth{event(models.FileWrite, "/w/a")}, RootPID: 100, Coverage: completeCov()})
	code, _, errOut := verify(t, "--trajectory", trajectory, "--ground-truth", ground, "--json", filepath.Join(dir, "missing", "r.json"))
	if code != exitError || !strings.Contains(errOut, "JSON report") {
		t.Errorf("exit %d, stderr %q", code, errOut)
	}
}

// A baseline holds for one harness version. The Claude Code session states
// its version, and a baseline captured for another is refused as an error,
// not read as a verdict.
func TestBaselineForAnotherVersionIsRefused(t *testing.T) {
	dir := t.TempDir()
	const fixture = "../../pkg/agent/claudecode/testdata/paired-2.1.286"
	ground := filepath.Join(fixture, "task.ground_truth.json")
	session := filepath.Join(fixture, "task.session.jsonl")
	stale := writeJSON(t, dir, "stale.json", agent.Baseline{Schema: agent.BaselineSchema, Agent: "claude-code", AgentVersion: "2.0.0", Runs: 1, MinAgreement: 1})
	code, _, errOut := verify(t, "--agent", "claude-code", "--trajectory", session, "--ground-truth", ground, "--baseline", stale)
	if code != exitError || !strings.Contains(errOut, "2.0.0") || !strings.Contains(errOut, "2.1.286") {
		t.Errorf("exit %d, stderr %q, want a refusal naming both versions", code, errOut)
	}
	matching := writeJSON(t, dir, "ok.json", agent.Baseline{Schema: agent.BaselineSchema, Agent: "claude-code", AgentVersion: "2.1.286", Runs: 1, MinAgreement: 1})
	if code, _, errOut := verify(t, "--agent", "claude-code", "--trajectory", session, "--ground-truth", ground, "--baseline", matching); code == exitError {
		t.Errorf("a baseline for the session's own version was refused: %s", errOut)
	}
}
