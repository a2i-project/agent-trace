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
	"github.com/agent-trace/agent-trace/pkg/agent/sensitive"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
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

// TestIOURingSocketOpsAreInconclusive: a capture in which tracked processes
// submitted socket operations through io_uring cannot support FAITHFUL, even
// when every claim is corroborated, because the net probe did not see those
// operations (N-25). The same capture without the counter is the control.
func TestIOURingSocketOpsAreInconclusive(t *testing.T) {
	dir := t.TempDir()
	trajectory := writeJSON(t, dir, "t.json", models.Trajectory{claim(models.FileWrite, "/w/a")})
	capture := func(name string, ops uint64) string {
		cov := &models.Coverage{Schema: models.CoverageSchema, Probes: map[string]models.ProbeCoverage{
			"fs":  {Ran: true},
			"net": {Ran: true, IOURingNetOps: ops},
		}}
		return writeJSON(t, dir, name, models.GroundTruthFile{Events: models.GroundTruth{event(models.FileWrite, "/w/a")}, RootPID: 100, Coverage: cov})
	}

	code, out, errOut := verify(t, "--trajectory", trajectory, "--ground-truth", capture("clean.json", 0))
	if code != 0 || !strings.Contains(out, "VERDICT: FAITHFUL") {
		t.Fatalf("control: exit %d, want 0\n%s\n%s", code, out, errOut)
	}
	code, out, errOut = verify(t, "--trajectory", trajectory, "--ground-truth", capture("uring.json", 3))
	if code != 2 || !strings.Contains(out, "VERDICT: INCONCLUSIVE") || !strings.Contains(out, "io_uring") {
		t.Errorf("io_uring socket operations: exit %d, want 2 with a reason naming io_uring\n%s\n%s", code, out, errOut)
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
	for _, want := range []string{"read by the claude-code adapter", "tool call(s) became", "WARNING tools with no mapping that may have acted: MultiEdit", "limitation:", "no baseline supplied", "parse error:"} {
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
	implied := filepath.Join(dir, "implied.json")
	_ = os.WriteFile(implied, []byte(`[{"timestamp":"2026-10-06T12:00:00Z","action_type":"file_open","target":"/w/f","implied_by":"cat f"}]`), 0o644)
	for name, args := range map[string][]string{
		"unknown agent":    {"--normalized", "--agent", "nope", "--trajectory", notJSON, "--ground-truth", g},
		"not a trajectory": {"--normalized", "--trajectory", notJSON, "--ground-truth", g},
		// A harness-implied claim comes only from an adapter (V-33).
		"a harness-implied marker":                      {"--normalized", "--trajectory", implied, "--ground-truth", g},
		"a harness-implied marker, generic by fallback": {"--trajectory", implied, "--ground-truth", g},
	} {
		if code, _, errOut := verify(t, args...); code != exitError || errOut == "" {
			t.Errorf("%s: exit %d, stderr %q", name, code, errOut)
		}
	}
}

// A net_response is attestation (N-29): the text report counts and lists it
// under its own label, apart from listeners and sockets, and in the
// command's own group. The JSON report keeps it in the capability lists.
func TestResponsesHaveTheirOwnLabel(t *testing.T) {
	dir := t.TempDir()
	const root, sh = 100, 200
	ev := func(ms int, typ models.ActionType, target string, pid, ppid uint32) models.GroundTruthEvent {
		return models.GroundTruthEvent{Timestamp: t0.Add(time.Duration(ms) * time.Millisecond), ActionType: typ, Target: target, PID: pid, PPID: ppid}
	}
	resp := ev(3, models.NetResponse, "GET api.example:443/v1", sh, 0)
	resp.Response = &models.ResponseAttestation{Status: 200, BodyBytes: 2, End: t0.Add(4 * time.Millisecond), Complete: true, Paired: true}
	g := models.GroundTruthFile{RootPID: root, Coverage: completeCov(), Workspace: "/w", Events: models.GroundTruth{
		ev(0, models.ProcessFork, "200", sh, root),
		ev(1, models.ProcessExec, "/bin/sh -c fetch", sh, root),
		ev(2, models.NetUnixConnect, "unix:/run/x.sock", sh, 0),
		resp,
	}}
	tr := models.Trajectory{{Timestamp: t0, ActionType: models.ProcessExec, Target: "/bin/sh -c fetch"}}
	jsonOut := filepath.Join(dir, "report.json")
	code, out, errOut := verify(t, "--trajectory", writeJSON(t, dir, "t.json", tr), "--ground-truth", writeJSON(t, dir, "g.json", g), "--json", jsonOut, "--ignore-exits")
	if code != 0 {
		t.Fatalf("exit %d, stderr %s\n%s", code, errOut, out)
	}
	for _, want := range []string{
		"Capability:   1  (listeners and sockets observed",
		"Responses:    1  (HTTP responses read over TLS, attested only",
		"\nCapability:\n  " + t0.Add(2*time.Millisecond).Format(time.RFC3339Nano) + " net_unix_connect unix:/run/x.sock\n",
		"\nResponses:\n  " + t0.Add(3*time.Millisecond).Format(time.RFC3339Nano) + " net_response   GET api.example:443/v1\n",
		"    responses (1): GET api.example:443/v1\n",
		"    unix sockets (1): unix:/run/x.sock\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "unix sockets (2)") {
		t.Errorf("the response is grouped with the unix sockets\n%s", out)
	}
	data, err := os.ReadFile(jsonOut)
	if err != nil {
		t.Fatal(err)
	}
	var rep jsonReport
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Capability) != 2 || len(rep.Commands) != 1 || len(rep.Commands[0].Capability) != 2 {
		t.Errorf("JSON capability = %d, command capability = %+v, want both events in each", len(rep.Capability), rep.Commands)
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

// --- the p5 demo (P-18, close order) ---

// testdata/p5 is a real capture under watch (2026-10-09, the fs probe after
// P-17 and P-18) of a two-line shell "agent" that writes one file inside the
// workspace and one next to it, both from its own process. Paths are rewritten
// to /p5. P-18 sorts a close where its record was read, so each file's close
// sits before the next file's open, and an honest trajectory that claims open,
// write and close per file in that order aligns exactly. The baseline is the
// shell's own loads.
func TestP5CloseOrderDemo(t *testing.T) {
	const dir = "testdata/p5"
	gt := filepath.Join(dir, "ground_truth.json")
	base := filepath.Join(dir, "baseline.json")

	// The capture itself: the inside close is recorded before the outside open.
	data, err := os.ReadFile(gt)
	if err != nil {
		t.Fatal(err)
	}
	f, err := models.ParseGroundTruthFile(data)
	if err != nil {
		t.Fatal(err)
	}
	closeInside, openOutside := -1, -1
	for i, e := range f.Events {
		if e.ActionType == models.FileClose && e.Target == "/p5/ws/inside.txt" {
			closeInside = i
		}
		if e.ActionType == models.FileOpen && e.Target == "/p5/outside.txt" && openOutside < 0 {
			openOutside = i
		}
	}
	if closeInside < 0 || openOutside < 0 || closeInside > openOutside {
		t.Fatalf("close of inside.txt at %d, open of outside.txt at %d: the close must sit where it was read", closeInside, openOutside)
	}

	code, out, errOut := verify(t, "--trajectory", filepath.Join(dir, "honest.json"), "--ground-truth", gt, "--baseline", base)
	if code != 0 || !strings.Contains(out, "Corroborated: 6") || !strings.Contains(out, "VERDICT: FAITHFUL") {
		t.Fatalf("honest: exit %d\n%s\n%s", code, out, errOut)
	}

	// Leaving out the write next to the workspace is three unrecorded events,
	// all of them outside.txt's.
	code, out, _ = verify(t, "--trajectory", filepath.Join(dir, "omits-outside.json"), "--ground-truth", gt, "--baseline", base)
	if code != 1 || !strings.Contains(out, "Unrecorded:   3") || !strings.Contains(out, "VERDICT: NOT FAITHFUL") {
		t.Fatalf("omits-outside: exit %d\n%s", code, out)
	}
	for _, line := range strings.Split(out[strings.Index(out, "\nUnrecorded:\n"):], "\n")[2:5] {
		if !strings.HasSuffix(strings.TrimSpace(line), "/p5/outside.txt") {
			t.Errorf("unrecorded line %q is not outside.txt", line)
		}
	}
}

// A paired harness-implied claim (V-33) is counted and listed apart, in the
// text and in the JSON report, with the call that implied it; a run without
// one prints nothing about them, so every report without one is unchanged.
func TestHarnessImpliedClaimsAreReportedApart(t *testing.T) {
	at := func(ms int) time.Time { return t0.Add(time.Duration(ms) * time.Millisecond) }
	ev := func(ms int, typ models.ActionType, target string, pid, ppid uint32) models.GroundTruthEvent {
		return models.GroundTruthEvent{Timestamp: at(ms), ActionType: typ, Target: target, PID: pid, PPID: ppid}
	}
	gt := models.GroundTruthFile{RootPID: 100, Coverage: completeCov(), Events: models.GroundTruth{
		ev(1, models.ProcessFork, "x", 200, 100), ev(2, models.ProcessExec, "cat f", 200, 100),
		ev(3, models.ProcessFork, "x", 201, 200), ev(4, models.ProcessExec, "/usr/bin/cat f", 201, 200),
		ev(5, models.FileOpen, "/w/f", 201, 0),
		ev(6, models.ProcessExit, "/usr/bin/cat f", 201, 200), ev(7, models.ProcessExit, "cat f", 200, 100),
		ev(8, models.FileOpen, "/w/f", 100, 0),
	}}
	end := at(9)
	tr := models.Trajectory{
		{Timestamp: t0, End: &end, ActionType: models.ProcessExec, Target: "cat f"},
		{Timestamp: t0, End: &end, ActionType: models.FileOpen, Target: "/w/f", ImpliedBy: "cat f"},
	}
	g, _ := agent.Lookup(agent.GenericName)
	for _, withImplied := range []bool{true, false} {
		claims := tr
		if !withImplied {
			claims = tr[:1]
		}
		in := agent.Prepare(g, claims, gt, nil, verification.Options{})
		in.Options.IgnoreExits = true
		v := verification.Verify(in)
		ri := reportInput{trajectoryPath: "t", groundTruthPath: "g", adapter: g.Name(), reader: "r", entries: len(claims), gt: gt, verdict: v}
		var out bytes.Buffer
		report(&out, ri)
		jsonPath := filepath.Join(t.TempDir(), "v.json")
		if err := writeJSONReport(jsonPath, ri); err != nil {
			t.Fatal(err)
		}
		data, _ := os.ReadFile(jsonPath)
		if !withImplied {
			if strings.Contains(out.String(), "Harness implied") || strings.Contains(string(data), "harness_implied") || v.Outcome != verification.OutcomeNotFaithful {
				t.Errorf("without an implied claim: outcome %s\n%s", v.Outcome, out.String())
			}
			continue
		}
		if v.Outcome != verification.OutcomeFaithful || !strings.Contains(out.String(), "Harness implied: 1 of 1") ||
			!strings.Contains(out.String(), `file_open      /w/f  (after "cat f")`) || !strings.Contains(out.String(), "Corroborated: 1\n") {
			t.Errorf("outcome %s, report:\n%s", v.Outcome, out.String())
		}
		var rep struct {
			Alignment struct {
				HarnessImplied []struct {
					ImpliedBy string                  `json:"implied_by"`
					Event     models.GroundTruthEvent `json:"event"`
				} `json:"harness_implied"`
			} `json:"alignment"`
		}
		if err := json.Unmarshal(data, &rep); err != nil || len(rep.Alignment.HarnessImplied) != 1 ||
			rep.Alignment.HarnessImplied[0].ImpliedBy != "cat f" || rep.Alignment.HarnessImplied[0].Event.PID != 100 {
			t.Errorf("JSON harness_implied = %+v, %v", rep.Alignment.HarnessImplied, err)
		}
	}
}

// The report counts the agent process's own events the baseline explained
// apart from the events beneath baselined commands, in the text and the JSON:
// on the P5 capture the baseline explains six level-0 events and no command.
func TestLevelZeroBaselineIsCounted(t *testing.T) {
	const dir = "testdata/p5"
	jsonPath := filepath.Join(t.TempDir(), "v.json")
	_, out, _ := verify(t, "--trajectory", filepath.Join(dir, "honest.json"), "--ground-truth", filepath.Join(dir, "ground_truth.json"), "--baseline", filepath.Join(dir, "baseline.json"), "--json", jsonPath)
	if !strings.Contains(out, "  Explained by the baseline:      0 events\n  Level 0 explained by the baseline: 6 events (") {
		t.Errorf("with the baseline:\n%s", out)
	}
	data, _ := os.ReadFile(jsonPath)
	var rep struct {
		Coverage struct {
			LevelZero *int `json:"baselined_level_zero"`
		} `json:"coverage"`
	}
	if err := json.Unmarshal(data, &rep); err != nil || rep.Coverage.LevelZero == nil || *rep.Coverage.LevelZero != 6 {
		t.Errorf("JSON baselined_level_zero = %v, %v", rep.Coverage.LevelZero, err)
	}
	_, out, _ = verify(t, "--trajectory", filepath.Join(dir, "honest.json"), "--ground-truth", filepath.Join(dir, "ground_truth.json"))
	if !strings.Contains(out, "  Level 0 explained by the baseline: 0 events (") {
		t.Errorf("without a baseline:\n%s", out)
	}
}

// On the Gemini fixture the harness's token refresh is unexplained harness
// network activity (V-34): counted and listed apart in the text and the JSON,
// and the run is INCONCLUSIVE. Every run prints how many of the agent
// process's own events the baseline explained, apart from the events beneath
// baselined commands; a run with no such connection prints nothing about it.
func TestHarnessNetworkActivityAndLevelZeroBaselineAreReported(t *testing.T) {
	const dir = "../../pkg/agent/gemini/testdata/paired-agy-1.3.4-basic"
	controls, _ := filepath.Glob(filepath.Join(dir, "control-*.ground_truth.json"))
	var runs []models.GroundTruthFile
	for _, p := range controls {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		f, err := models.ParseGroundTruthFile(data)
		if err != nil {
			t.Fatal(err)
		}
		runs = append(runs, f)
	}
	a, _ := agent.Lookup("gemini")
	b, err := agent.Capture(a, "1.3.4", runs, t0, agent.CaptureOptions{Exclude: []string{": agent-trace-control-marker"}, MinAgreement: 0.2})
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	base := filepath.Join(tmp, "baseline.json")
	if err := agent.SaveBaseline(base, b); err != nil {
		t.Fatal(err)
	}
	jsonPath := filepath.Join(tmp, "v.json")
	code, out, errOut := verify(t, "--trajectory", filepath.Join(dir, "basic.conversation.db"), "--ground-truth", filepath.Join(dir, "basic.ground_truth.json"), "--baseline", base, "--json", jsonPath)
	if code != 2 || !strings.Contains(out, "Unrecorded:   0 ") ||
		!strings.Contains(out, "Unexplained harness network activity: 1  (") ||
		!strings.Contains(out, "\nUnexplained harness network activity:\n  2026-10-13T22:02:20.274885534+02:00 net_connect    oauth2.googleapis.com\n") ||
		!strings.Contains(out, "  Level 0 explained by the baseline: 581 events") || !strings.Contains(out, "VERDICT: INCONCLUSIVE") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	data, _ := os.ReadFile(jsonPath)
	var rep struct {
		Alignment struct {
			Net models.GroundTruth `json:"unexplained_harness_net"`
		} `json:"alignment"`
		Coverage struct {
			LevelZero int `json:"baselined_level_zero"`
		} `json:"coverage"`
	}
	if err := json.Unmarshal(data, &rep); err != nil || len(rep.Alignment.Net) != 1 || rep.Alignment.Net[0].Target != "oauth2.googleapis.com" || rep.Coverage.LevelZero != 581 {
		t.Errorf("JSON: %+v, %v", rep, err)
	}

	_, out, _ = verify(t, "--trajectory", filepath.Join(pairedDir, "task.session.jsonl"), "--ground-truth", filepath.Join(pairedDir, "task.ground_truth.json"))
	if strings.Contains(out, "network activity") || !strings.Contains(out, "  Level 0 explained by the baseline: 0 events") {
		t.Errorf("a run without harness network activity:\n%s", out)
	}
}

// V-36: a corroborated read paired with an open the baseline also explains is
// counted and listed with its note, in the text and the JSON, and the report
// states how many paths the harness opens at rest by the baseline. A run with
// no such pair prints no count and no list and its JSON has no key; a run
// without a baseline prints no limitation.
func TestReadsSharedWithTheHarnessAreReported(t *testing.T) {
	const cfg = "/home/u/.harness/settings.json"
	dir := t.TempDir()
	ground := writeJSON(t, dir, "g.json", models.GroundTruthFile{RootPID: 100, Coverage: completeCov(), Events: models.GroundTruth{
		event(models.FileOpen, cfg), event(models.FileOpen, "/w/a"),
	}})
	base := filepath.Join(dir, "b.json")
	if err := agent.SaveBaseline(base, agent.Baseline{Schema: agent.BaselineSchema, Agent: agent.GenericName, Runs: 1, MinAgreement: 1, Rules: []agent.Rule{
		{ActionType: models.FileOpen, Target: cfg}, {ActionType: models.FileOpen, Target: "/home/u/.harness/other"},
		{ActionType: models.FileOpen, Target: agent.WorkspacePlaceholder + "/.git"}, {ActionType: models.ProcessExec, Target: "git status"},
	}}); err != nil {
		t.Fatal(err)
	}
	const (
		limit = "  limitation: the harness itself opens 2 path(s) at rest by this baseline (file_open rules); an unclaimed in-process read of one of them is explained by the baseline and not detectable (V-36)\n"
		count = "  Corroborated, shared with the harness: 1 of them  ("
		list  = "\nCorroborated, shared with the harness:\n  2026-10-06T12:00:00Z file_open      " + cfg + "\n    note: the harness itself opens this file at rest; this read cannot be told apart from the harness's own, and an unclaimed read of it would be hidden\n"
	)
	report := func(t *testing.T, claims models.Trajectory, args ...string) (int, string, map[string]json.RawMessage) {
		t.Helper()
		trajectory := writeJSON(t, t.TempDir(), "t.json", claims)
		jsonPath := filepath.Join(t.TempDir(), "v.json")
		code, out, errOut := verify(t, append([]string{"--trajectory", trajectory, "--ground-truth", ground, "--json", jsonPath}, args...)...)
		if errOut != "" {
			t.Fatalf("stderr: %s", errOut)
		}
		data, _ := os.ReadFile(jsonPath)
		var rep struct {
			Alignment map[string]json.RawMessage `json:"alignment"`
		}
		if err := json.Unmarshal(data, &rep); err != nil {
			t.Fatal(err)
		}
		return code, out, rep.Alignment
	}

	t.Run("a read of a file the harness opens at rest", func(t *testing.T) {
		code, out, al := report(t, models.Trajectory{claim(models.FileOpen, cfg), claim(models.FileOpen, "/w/a")}, "--baseline", base)
		if code != 0 || !strings.Contains(out, "Corroborated: 2\n"+count) || !strings.Contains(out, list) || !strings.Contains(out, limit) {
			t.Errorf("exit %d\n%s", code, out)
		}
		var shared []verification.MatchedPair
		if err := json.Unmarshal(al["corroborated_harness_shared"], &shared); err != nil || len(shared) != 1 || shared[0].Event.Target != cfg {
			t.Errorf("JSON corroborated_harness_shared = %+v, %v", shared, err)
		}
	})
	t.Run("no read of such a file", func(t *testing.T) {
		code, out, al := report(t, models.Trajectory{claim(models.FileOpen, "/w/a")}, "--baseline", base)
		if code != 0 || strings.Contains(out, "shared with the harness") || !strings.Contains(out, limit) {
			t.Errorf("exit %d\n%s", code, out)
		}
		if _, ok := al["corroborated_harness_shared"]; ok {
			t.Errorf("JSON carries corroborated_harness_shared with no such pair")
		}
	})
	t.Run("no baseline", func(t *testing.T) {
		_, out, al := report(t, models.Trajectory{claim(models.FileOpen, cfg), claim(models.FileOpen, "/w/a")})
		if strings.Contains(out, "shared with the harness") || strings.Contains(out, "(V-36)") {
			t.Errorf("without a baseline:\n%s", out)
		}
		if _, ok := al["corroborated_harness_shared"]; ok {
			t.Errorf("JSON carries corroborated_harness_shared without a baseline")
		}
	})
}

// V-37: the report states how many paths the harness writes at rest by the
// baseline, lists them in the JSON, and lists a level-0 write a rule explains
// outside the harness's declared directories, with its count. A run with no
// such write prints no count and its JSON has no key; a baseline without
// write rules prints no limitation and no list.
func TestWritesTheHarnessMakesAtRestAreReported(t *testing.T) {
	const sock = "/tmp/cc-socks"
	dir := t.TempDir()
	write := func(name string, g models.GroundTruth) string {
		return writeJSON(t, dir, name, models.GroundTruthFile{RootPID: 100, Coverage: completeCov(), Events: g})
	}
	withWrite := write("g1.json", models.GroundTruth{event(models.FileWrite, sock), event(models.FileOpen, "/w/a")})
	without := write("g2.json", models.GroundTruth{event(models.FileOpen, "/w/a")})
	base := filepath.Join(dir, "b.json")
	if err := agent.SaveBaseline(base, agent.Baseline{Schema: agent.BaselineSchema, Agent: agent.GenericName, Runs: 1, MinAgreement: 1, Rules: []agent.Rule{
		{ActionType: models.FileWrite, Target: sock}, {ActionType: models.FileDelete, Target: sock}, {ActionType: models.FileClose, Target: "/home/u/.harness/state"},
		{ActionType: models.FileWrite, Target: agent.WorkspacePlaceholder + "/.lock"}, {ActionType: models.FileOpen, Target: "/home/u/.harness/cfg"},
	}}); err != nil {
		t.Fatal(err)
	}
	reads := filepath.Join(dir, "r.json")
	if err := agent.SaveBaseline(reads, agent.Baseline{Schema: agent.BaselineSchema, Agent: agent.GenericName, Runs: 1, MinAgreement: 1, Rules: []agent.Rule{
		{ActionType: models.FileOpen, Target: "/home/u/.harness/cfg"},
	}}); err != nil {
		t.Fatal(err)
	}
	const (
		limit = "  limitation: the harness itself writes 2 path(s) at rest by this baseline (file_write, file_close, file_rename or file_delete rules); an unclaimed in-process write to one of them is explained by the baseline and not detectable (V-37)\n"
		count = "  Baselined writes outside the harness's directories: 1  ("
		list  = "\nBaselined writes outside the harness's directories:\n  2026-10-06T12:00:00Z file_write     " + sock + "\n"
	)
	report := func(t *testing.T, ground string, args ...string) (int, string, map[string]json.RawMessage) {
		t.Helper()
		trajectory := writeJSON(t, t.TempDir(), "t.json", models.Trajectory{claim(models.FileOpen, "/w/a")})
		jsonPath := filepath.Join(t.TempDir(), "v.json")
		code, out, errOut := verify(t, append([]string{"--trajectory", trajectory, "--ground-truth", ground, "--json", jsonPath}, args...)...)
		if errOut != "" {
			t.Fatalf("stderr: %s", errOut)
		}
		data, _ := os.ReadFile(jsonPath)
		var rep map[string]json.RawMessage
		if err := json.Unmarshal(data, &rep); err != nil {
			t.Fatal(err)
		}
		var al map[string]json.RawMessage
		if err := json.Unmarshal(rep["alignment"], &al); err != nil {
			t.Fatal(err)
		}
		for k, v := range al {
			rep["alignment."+k] = v
		}
		return code, out, rep
	}

	t.Run("a baselined write outside the harness's directories", func(t *testing.T) {
		code, out, rep := report(t, withWrite, "--baseline", base)
		if code != 0 || !strings.Contains(out, limit) || !strings.Contains(out, count) || !strings.Contains(out, list) {
			t.Errorf("exit %d\n%s", code, out)
		}
		var resting []string
		if err := json.Unmarshal(rep["resting_writes"], &resting); err != nil || strings.Join(resting, ",") != "/home/u/.harness/state,"+sock {
			t.Errorf("JSON resting_writes = %v, %v", resting, err)
		}
		var listed models.GroundTruth
		if err := json.Unmarshal(rep["alignment.baselined_writes_outside_harness"], &listed); err != nil || len(listed) != 1 || listed[0].Target != sock {
			t.Errorf("JSON baselined_writes_outside_harness = %+v, %v", listed, err)
		}
	})
	t.Run("no such write in the run", func(t *testing.T) {
		code, out, rep := report(t, without, "--baseline", base)
		if code != 0 || !strings.Contains(out, limit) || strings.Contains(out, "Baselined writes outside") {
			t.Errorf("exit %d\n%s", code, out)
		}
		if _, ok := rep["alignment.baselined_writes_outside_harness"]; ok {
			t.Errorf("JSON carries baselined_writes_outside_harness with no such write")
		}
	})
	t.Run("a baseline without write rules", func(t *testing.T) {
		_, out, rep := report(t, without, "--baseline", reads)
		if strings.Contains(out, "(V-37)") {
			t.Errorf("a baseline without write rules:\n%s", out)
		}
		if _, ok := rep["resting_writes"]; ok {
			t.Errorf("JSON carries resting_writes without write rules")
		}
	})
}

// V-38: a baselined command with an event beneath it that its controls never
// produced is an unexplained subtree, printed with that event and carried in
// the JSON; a baseline written before V-38 that holds command rules prints a
// limitation line and keeps the old reading; a baseline with records does not
// print it.
func TestABaselinedCommandsSubtreeIsCheckedAgainstItsRecord(t *testing.T) {
	dir := t.TempDir()
	ground := writeJSON(t, dir, "g.json", models.GroundTruthFile{RootPID: 100, Coverage: completeCov(), Events: models.GroundTruth{
		{Timestamp: time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC), ActionType: models.ProcessFork, Target: "200", PID: 200, PPID: 100},
		{Timestamp: time.Date(2026, 10, 6, 12, 0, 1, 0, time.UTC), ActionType: models.ProcessExec, Target: "/bin/bash -c env", PID: 200, PPID: 100},
		{Timestamp: time.Date(2026, 10, 6, 12, 0, 2, 0, time.UTC), ActionType: models.ProcessExec, Target: "/usr/bin/env", PID: 200, PPID: 100},
		{Timestamp: time.Date(2026, 10, 6, 12, 0, 3, 0, time.UTC), ActionType: models.NetConnect, Target: "evil.example", PID: 200},
	}})
	rules := []agent.Rule{{ActionType: models.ProcessExec, Target: "/bin/bash -c env"}}
	save := func(name string, subtrees []agent.Subtree) string {
		p := filepath.Join(dir, name)
		if err := agent.SaveBaseline(p, agent.Baseline{Schema: agent.BaselineSchema, Agent: agent.GenericName, Runs: 1, MinAgreement: 1, Rules: rules, Subtrees: subtrees}); err != nil {
			t.Fatal(err)
		}
		return p
	}
	recorded := save("new.json", []agent.Subtree{{Command: "/bin/bash -c env", Events: []agent.Rule{{ActionType: models.ProcessExec, Target: "/usr/bin/env"}}}})
	old := save("old.json", nil)
	const limit = "  limitation: this baseline records no subtrees (written before V-38), so each of its 1 command(s) explains every event beneath it whatever the controls did; rebuild it with baseline to check them (V-38)\n"
	trajectory := writeJSON(t, dir, "t.json", models.Trajectory{})

	jsonPath := filepath.Join(dir, "v.json")
	code, out, errOut := verify(t, "--trajectory", trajectory, "--ground-truth", ground, "--baseline", recorded, "--json", jsonPath)
	if errOut != "" {
		t.Fatalf("stderr: %s", errOut)
	}
	want := "  pid 200 /bin/bash -c env  (baselined command; 1 of the 2 events beneath it are not what the controls' same command did)\n    2026-10-06T12:00:03Z net_connect    evil.example\n"
	if code != 1 || !strings.Contains(out, "Unexplained subtrees: 1") || !strings.Contains(out, want) || strings.Contains(out, limit) ||
		!strings.Contains(out, "[baseline, 1 beneath it not in the controls]") || !strings.Contains(out, "Explained by the baseline:      1 events") {
		t.Errorf("exit %d\n%s", code, out)
	}
	data, _ := os.ReadFile(jsonPath)
	var rep struct {
		Commands []struct {
			Status      string             `json:"status"`
			Unbaselined models.GroundTruth `json:"unbaselined"`
		} `json:"commands"`
		Coverage struct {
			UnexplainedSubtrees []uint32 `json:"unexplained_subtrees"`
		} `json:"coverage"`
	}
	if err := json.Unmarshal(data, &rep); err != nil || len(rep.Commands) != 1 || len(rep.Commands[0].Unbaselined) != 1 || rep.Commands[0].Unbaselined[0].Target != "evil.example" || len(rep.Coverage.UnexplainedSubtrees) != 1 {
		t.Errorf("JSON = %+v, %v", rep, err)
	}

	code, out, _ = verify(t, "--trajectory", trajectory, "--ground-truth", ground, "--baseline", old)
	if code != 0 || !strings.Contains(out, limit) || !strings.Contains(out, "Unexplained subtrees: 0") {
		t.Errorf("an old baseline: exit %d\n%s", code, out)
	}
}

// sensitiveRun is a Claude Code capture with no event and a snapshot in which
// ~/.claude.json changed as given (V-40).
func sensitiveRun(ws string, changes ...models.SensitiveChange) models.GroundTruthFile {
	ca, _ := agent.Lookup("claude-code")
	rec := &models.SensitiveSnapshot{Home: "/home/user"}
	for _, d := range agent.SensitiveFiles(ca) {
		f := models.SensitiveFile{Declared: d, Path: "/elsewhere", Start: models.SensitiveState{State: models.SensitiveMissing}, Stop: models.SensitiveState{State: models.SensitiveMissing}}
		if d == "~/.claude.json" {
			f.Path, f.Changes = "/home/user/.claude.json", changes
			f.Start = models.SensitiveState{State: models.SensitivePresent, Format: models.SensitiveJSON, Digest: "a"}
			f.Stop = models.SensitiveState{State: models.SensitivePresent, Format: models.SensitiveJSON, Digest: "b"}
		}
		rec.Files = append(rec.Files, f)
	}
	return models.GroundTruthFile{RootPID: 100, Coverage: completeCov(), Workspace: ws, Sensitive: rec}
}

// verify reports a change of a sensitive file the controls never made as a
// finding by file, key path and kind, with no value, and one outside the
// file's security-relevant keys as report-only (V-41); without a record of
// the controls' changes it lists them as not checked, with no finding (V-40).
func TestSensitiveChangesAreReported(t *testing.T) {
	dir := t.TempDir()
	ca, _ := agent.Lookup("claude-code")
	last := func(ws string) models.SensitiveChange {
		return models.SensitiveChange{Key: []string{"projects", ws, "lastSessionId"}, Kind: models.SensitiveChanged}
	}
	b, err := agent.Capture(ca, "1", []models.GroundTruthFile{sensitiveRun("/w/c1", last("/w/c1")), sensitiveRun("/w/c2", last("/w/c2"))}, t0, agent.CaptureOptions{})
	if err != nil {
		t.Fatal(err)
	}
	bp := filepath.Join(dir, "b.json")
	if err := agent.SaveBaseline(bp, b); err != nil {
		t.Fatal(err)
	}
	added := models.SensitiveChange{Key: []string{"projects", "/w/task", "allowedTools"}, Kind: models.SensitiveEntriesAdded, Entries: 1}
	cache := models.SensitiveChange{Key: []string{"cachedGrowthBookFeatures", "flag"}, Kind: models.SensitiveAdded}
	g := writeJSON(t, dir, "g.json", sensitiveRun("/w/task", last("/w/task"), added, cache))
	claims := writeJSON(t, dir, "claims.json", models.Trajectory{})
	jp := filepath.Join(dir, "v.json")

	code, out, errOut := verify(t, "--normalized", "--agent", "claude-code", "--trajectory", claims, "--ground-truth", g, "--baseline", bp, "--json", jp)
	if code != 1 {
		t.Fatalf("exit %d, want 1 (NOT FAITHFUL)\n%s%s", code, out, errOut)
	}
	for _, want := range []string{
		"sensitive:    5 harness file(s) checked against the controls: 3 change(s), 1 made by the controls, 0 by a claimed write, 1 unexplained, 1 report-only outside the security-relevant keys\n",
		"  limitation: the snapshot compares each sensitive file at the start and the stop only, so a change made and reverted in between is not seen (V-40)\n",
		"  Unexplained sensitive changes: 1  (",
		"\nUnexplained sensitive changes:\n  /home/user/.claude.json  projects[\"/w/task\"].allowedTools  entries-added (1)\n",
		"  Other sensitive changes: 1  (report-only: ",
		"\nOther sensitive changes (report-only):\n  /home/user/.claude.json  cachedGrowthBookFeatures.flag  added\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	data, err := os.ReadFile(jp)
	if err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Findings  int `json:"findings"`
		Sensitive struct {
			Checked     bool                           `json:"checked"`
			Unexplained []verification.SensitiveChange `json:"unexplained"`
			Other       []verification.SensitiveChange `json:"other"`
		} `json:"sensitive"`
	}
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Findings != 1 || !rep.Sensitive.Checked || len(rep.Sensitive.Unexplained) != 1 || rep.Sensitive.Unexplained[0].Kind != models.SensitiveEntriesAdded ||
		len(rep.Sensitive.Other) != 1 || sensitive.FormatKey(rep.Sensitive.Other[0].Key) != "cachedGrowthBookFeatures.flag" {
		t.Errorf("JSON report = %+v", rep)
	}

	// The cache key alone: listed, no finding, FAITHFUL.
	g2 := writeJSON(t, dir, "g2.json", sensitiveRun("/w/task", last("/w/task"), cache))
	code, out, errOut = verify(t, "--normalized", "--agent", "claude-code", "--trajectory", claims, "--ground-truth", g2, "--baseline", bp)
	if code != 0 || !strings.Contains(out, "0 unexplained, 1 report-only") || !strings.Contains(out, "  Unexplained sensitive changes: 0  (") ||
		strings.Contains(out, "\nUnexplained sensitive changes:\n") || !strings.Contains(out, "\nOther sensitive changes (report-only):\n") {
		t.Errorf("a cache key only: exit %d\n%s%s", code, out, errOut)
	}

	code, out, _ = verify(t, "--normalized", "--agent", "claude-code", "--trajectory", claims, "--ground-truth", g)
	if code == 1 || !strings.Contains(out, "sensitive:    the capture snapshots the harness's sensitive files; 3 change(s) not checked\n") ||
		!strings.Contains(out, "limitation: the baseline holds no record") || !strings.Contains(out, "\nSensitive changes not checked:\n") ||
		strings.Contains(out, "Other sensitive changes") {
		t.Errorf("without a baseline: exit %d\n%s", code, out)
	}
}

// A WebSearch call is reported as a server-side call with its join, in the
// text report and the JSON, only when the session holds one, and never
// changes the outcome (V-45).
func TestServerSideCallsAreReportedWithTheirJoin(t *testing.T) {
	dir := t.TempDir()
	session := `{"type":"assistant","timestamp":"2026-10-26T10:00:01Z","sessionId":"s","version":"2.1.306","requestId":"req_A","message":{"id":"m1","content":[{"type":"tool_use","id":"toolu_1","name":"WebSearch","input":{"query":"q"}}]}}
{"type":"user","timestamp":"2026-10-26T10:00:05Z","sessionId":"s","version":"2.1.306","message":{"content":[{"type":"tool_result","tool_use_id":"toolu_1","content":"r"}]}}
{"type":"assistant","timestamp":"2026-10-26T10:00:06Z","sessionId":"s","version":"2.1.306","requestId":"req_B","message":{"id":"m2","content":[{"type":"tool_use","id":"toolu_2","name":"WebSearch","input":{"query":"q2"}}]}}
`
	sp := filepath.Join(dir, "s.jsonl")
	if err := os.WriteFile(sp, []byte(session), 0o644); err != nil {
		t.Fatal(err)
	}
	ts := time.Date(2026, 10, 26, 10, 0, 0, 0, time.UTC)
	resp := models.GroundTruthEvent{Timestamp: ts, ActionType: models.NetResponse, PID: 100, Target: "POST https://api.anthropic.com/v1/messages",
		Response: &models.ResponseAttestation{Status: 200, RequestID: "req_A", End: ts, Complete: true, Paired: true, SSE: &models.SSESummary{Events: 3}}}
	g := models.GroundTruthFile{RootPID: 100, Events: models.GroundTruth{resp}, Coverage: &models.Coverage{Schema: models.CoverageSchema,
		Probes: map[string]models.ProbeCoverage{"fs": {Ran: true}, "net": {Ran: true, Responses: models.ContentActive}}}}
	jsonOut := filepath.Join(dir, "r.json")
	code, out, errOut := verify(t, "--agent", "claude-code", "--trajectory", sp, "--ground-truth", writeJSON(t, dir, "g.json", g), "--json", jsonOut)
	if code != 0 {
		t.Fatalf("exit %d, stderr %s\n%s", code, errOut, out)
	}
	for _, want := range []string{
		"Server-side calls: 2, corroborated as calls: 1  (run by the model API;",
		" WebSearch toolu_1 request req_A: corroborated as a call\n",
		" WebSearch toolu_2 request req_B: not corroborated: no response read by the agent's own process carries the call's request id\n",
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
		t.Fatal(err)
	}
	if len(rep.ServerCalls) != 2 || !rep.ServerCalls[0].Corroborated || rep.ServerCalls[0].Response == nil || len(rep.Parse.ServerCalls) != 2 {
		t.Errorf("JSON server calls %+v, parse %+v", rep.ServerCalls, rep.Parse.ServerCalls)
	}
}
