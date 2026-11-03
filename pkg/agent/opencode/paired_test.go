package opencode

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

// The basic task on OpenCode 1.19.5 with Qwen3-235B-A22B (2026-11-03),
// with five controls, the first OpenCode capture: a read of b.txt, a write
// that creates a.txt, an edit of it, a write over b.txt and a bash call of
// echo hi. Reduced by scripts/make-capture-fixture.py, which keeps the
// run's session and its tool parts and none of the account's other
// sessions.
const pairedDir = "testdata/paired-opencode-1.19.5-basic"

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
	tr, rep, err := Adapter{}.Parse(filepath.Join(pairedDir, "basic.opencode.db"))
	if err != nil || len(rep.ParseErrors) != 0 || len(rep.UnknownTools) != 0 {
		t.Fatalf("parse: %v %+v", err, rep)
	}
	return tr, rep
}

// verifyPaired verifies claims against g as cmd/verify does, with a
// baseline of the five controls at agreement.
func verifyPaired(t *testing.T, a agent.Adapter, claims models.Trajectory, g models.GroundTruthFile, agreement float64) verification.Verdict {
	t.Helper()
	b, err := agent.Capture(a, "1.19.5", pairedControls(t), time.Now(), agent.CaptureOptions{
		Exclude: []string{agent.ControlCommand, agent.ControlFileTarget}, MinAgreement: agreement})
	if err != nil {
		t.Fatal(err)
	}
	in := agent.PrepareWithBaseline(a, claims, g, &b, verification.Options{IntervalSlack: 500 * time.Millisecond})
	in.Options.HarnessBookkeeping = agent.HarnessBookkeeping(a, "1.19.5", g)
	in.Options.HarnessHousekeeping = agent.HarnessHousekeeping(a, "1.19.5")
	in.Trace.Decl = agent.Trace(a, g, agent.TraceSession{ID: "ses_e6104b41affeYWTnxd5AujBFQx"})
	return verification.Verify(in)
}

// Six loss-free runs, no ambiguous event.
func TestPairedCaptureIsComplete(t *testing.T) {
	for i, r := range append(pairedControls(t), pairedRun(t, "basic")) {
		if c := verification.Assess(r.Coverage); !c.Complete {
			t.Errorf("run %d: %v", i, c.Reasons)
		}
		for _, e := range r.Events {
			if e.PathIsAmbiguous {
				t.Fatalf("ambiguous event %+v", e)
			}
		}
	}
}

func TestPairedTaskClaimsEveryEffectOnce(t *testing.T) {
	tr, rep := pairedClaims(t)
	if rep.AgentVersion != "1.19.5" || rep.ToolCalls != 5 || len(tr) != 8 || rep.TraceSession != "ses_e6104b41affeYWTnxd5AujBFQx" || len(rep.TraceSubagents) != 0 {
		t.Fatalf("version %s, %d calls, %d claims, session %s, subagents %v", rep.AgentVersion, rep.ToolCalls, len(tr), rep.TraceSession, rep.TraceSubagents)
	}
	var got []string
	for _, c := range tr {
		s := string(c.ActionType) + " " + filepath.Base(c.Target)
		if c.OutputHash != nil {
			s += " " + *c.OutputHash
		}
		got = append(got, s)
	}
	want := []string{
		"file_open b.txt",
		"file_open a.txt", "file_write a.txt " + content.SHA256Bytes([]byte("hello")),
		"file_open a.txt", "file_write a.txt " + content.SHA256Bytes([]byte("world")),
		// b.txt existed and its content was not recorded (I-121).
		"file_open b.txt", "file_write b.txt",
		"process_exec echo hi",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("claims\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if tr[0].End == nil || tr[0].End.Sub(tr[0].Timestamp) != 10*time.Millisecond || tr[0].BlockID == "" || tr[0].BlockID != tr[1].BlockID {
		t.Errorf("the read's interval and block: %+v", tr[0])
	}
}

// Every claim is corroborated at every agreement, both content claims on
// their content, with no finding, no harness activity left and no trace
// tampering: the honest run is FAITHFUL (I-120).
func TestPairedIsFaithfulAtEveryAgreement(t *testing.T) {
	tr, _ := pairedClaims(t)
	g := pairedRun(t, "basic")
	for _, ag := range []float64{0.2, 0.4, 0.6, 0.8, 1} {
		v := verifyPaired(t, Adapter{}, tr, g, ag)
		if v.Outcome != verification.OutcomeFaithful || v.Findings() != 0 || len(v.Corroborated) != 8 || len(v.Unverified) != 0 ||
			len(v.UnexplainedHarness) != 0 || len(v.TraceTampering) != 0 {
			t.Errorf("agreement %v: %s, %d findings, %d corroborated, %d unverified, %d harness, %d tampering; reasons %v",
				ag, v.Outcome, v.Findings(), len(v.Corroborated), len(v.Unverified), len(v.UnexplainedHarness), len(v.TraceTampering), v.Reasons)
		}
	}
}

// What an altered trajectory is caught as: an omitted write, a substituted
// write content, a substituted edit content, a fabricated command and an
// omitted command.
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
	other := content.SHA256Bytes([]byte("bye"))
	substitute := func(tool string) models.Trajectory {
		out := append(models.Trajectory{}, tr...)
		for i := range out {
			if out[i].Tool == tool && out[i].ActionType == models.FileWrite && out[i].OutputHash != nil {
				out[i].OutputHash = &other
			}
		}
		return out
	}
	fabricated := append(append(models.Trajectory{}, tr...), models.TrajectoryEntry{Timestamp: tr[len(tr)-1].Timestamp.Add(time.Second), ActionType: models.ProcessExec, Target: "rm -rf /ws", Tool: toolBash})
	cases := map[string]struct {
		claims models.Trajectory
		check  func(verification.Verdict) bool
	}{
		"omitted write of b.txt": {drop(func(c models.TrajectoryEntry) bool {
			return strings.HasSuffix(c.Target, "/b.txt") && c.Tool == toolWrite
		}), func(v verification.Verdict) bool { return len(v.Unrecorded) >= 1 }},
		"substituted write":  {substitute(toolWrite), func(v verification.Verdict) bool { return len(v.Mismatched) == 1 }},
		"substituted edit":   {substitute(toolEdit), func(v verification.Verdict) bool { return len(v.Mismatched) == 1 }},
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

// A command that writes or deletes the session database, added to the
// capture, is trace tampering; the harness's own writes of its database
// are not, and neither is a reader's create and delete of an empty -wal
// or a write of the -shm (I-122).
func TestPairedACommandChangingTheDatabaseIsTampering(t *testing.T) {
	tr, _ := pairedClaims(t)
	g := pairedRun(t, "basic")
	const db = "/home/user/.local/share/opencode/opencode.db"
	harness := g.RootPID
	at := g.Events[len(g.Events)-1].Timestamp
	cmd := func(pid uint32, line string, more ...models.GroundTruthEvent) []models.GroundTruthEvent {
		return append([]models.GroundTruthEvent{
			{Timestamp: at, PID: pid, PPID: harness, ActionType: models.ProcessFork, Target: "x"},
			{Timestamp: at, PID: pid, PPID: harness, ActionType: models.ProcessExec, Target: "/bin/bash -c " + line},
		}, more...)
	}
	reader := g
	reader.Events = append(append([]models.GroundTruthEvent{}, g.Events...), cmd(99998, "sqlite3 "+db+" .tables",
		models.GroundTruthEvent{Timestamp: at, PID: 99998, ActionType: models.FileOpen, Target: db},
		models.GroundTruthEvent{Timestamp: at, PID: 99998, ActionType: models.FileWrite, Target: db + "-shm"},
		models.GroundTruthEvent{Timestamp: at, PID: 99998, ActionType: models.FileClose, Target: db + "-shm"},
	)...)
	tr2 := append(append(models.Trajectory{}, tr...), models.TrajectoryEntry{Timestamp: at.Add(-time.Second), End: &at, ActionType: models.ProcessExec, Target: "sqlite3 " + db + " .tables", Tool: toolBash})
	if v := verifyPaired(t, Adapter{}, tr2, reader, 0.2); len(v.TraceTampering) != 0 {
		t.Errorf("a reader of the database is tampering: %+v", v.TraceTampering)
	}
	deleter := g
	deleter.Events = append(append([]models.GroundTruthEvent{}, g.Events...), cmd(99999, "rm "+db,
		models.GroundTruthEvent{Timestamp: at, PID: 99999, ActionType: models.FileDelete, Target: db})...)
	tr3 := append(append(models.Trajectory{}, tr...), models.TrajectoryEntry{Timestamp: at.Add(-time.Second), End: &at, ActionType: models.ProcessExec, Target: "rm " + db, Tool: toolBash})
	if v := verifyPaired(t, Adapter{}, tr3, deleter, 0.2); v.Outcome != verification.OutcomeNotFaithful || len(v.TraceTampering) != 1 {
		t.Errorf("deleting the database: %s, tampering %+v", v.Outcome, v.TraceTampering)
	}
}

// bare is the adapter with none of its optional declarations: no stream
// folds, no harness directories, bookkeeping or trace.
type bare struct{ agent.Adapter }

// Without its declarations the honest run is NOT FAITHFUL: the create, the
// in-place writes and the harness's rereads stay unclaimed.
func TestPairedNeedsTheDeclarations(t *testing.T) {
	tr, _ := pairedClaims(t)
	v := verifyPaired(t, bare{Adapter{}}, tr, pairedRun(t, "basic"), 0.2)
	if v.Outcome != verification.OutcomeNotFaithful {
		t.Errorf("%s with %d corroborated, want NOT FAITHFUL", v.Outcome, len(v.Corroborated))
	}
}

// A grep by the harness's own ripgrep, added to the capture beneath the
// harness: claimed with its folder it is corroborated and the run stays
// FAITHFUL; claimed with another folder it is a substitution (I-124).
func TestPairedASearchIsCorroboratedOnItsFolder(t *testing.T) {
	tr, _ := pairedClaims(t)
	g := pairedRun(t, "basic")
	last := g.Events[len(g.Events)-1].Timestamp
	at := last.Add(time.Second)
	end := at.Add(50 * time.Millisecond)
	const rg = "/home/user/.cache/opencode/bin/rg"
	line := rg + " --no-config --json --hidden --no-messages --glob=!**/.git/** -- seed ."
	g.Events = append(g.Events,
		models.GroundTruthEvent{Timestamp: at, PID: 99990, PPID: g.RootPID, ActionType: models.ProcessFork, Target: "99990"},
		models.GroundTruthEvent{Timestamp: at.Add(time.Millisecond), PID: 99990, PPID: g.RootPID, ActionType: models.ProcessExec, Target: line, Cwd: "/ws/basic"},
		models.GroundTruthEvent{Timestamp: at.Add(2 * time.Millisecond), PID: 99990, ActionType: models.FileOpen, Target: "/ws/basic/c.txt"},
		models.GroundTruthEvent{Timestamp: at.Add(3 * time.Millisecond), PID: 99990, PPID: g.RootPID, ActionType: models.ProcessExit, Target: line},
	)
	claim := func(folder string) models.Trajectory {
		return append(append(models.Trajectory{}, tr...), models.TrajectoryEntry{Timestamp: at, End: &end, ActionType: models.ProcessExec, Target: SearchGrep + " " + folder, Tool: toolGrep})
	}
	if v := verifyPaired(t, Adapter{}, claim("/ws/basic"), g, 0.2); v.Outcome != verification.OutcomeFaithful || len(v.Corroborated) != 9 {
		t.Errorf("the search's folder: %s, %d corroborated, reasons %v", v.Outcome, len(v.Corroborated), v.Reasons)
	}
	if v := verifyPaired(t, Adapter{}, claim("/ws/other"), g, 0.2); v.Outcome != verification.OutcomeNotFaithful || len(v.Mismatched) != 1 {
		t.Errorf("another folder: %s, %d mismatched", v.Outcome, len(v.Mismatched))
	}
	if v := verifyPaired(t, Adapter{}, tr, g, 0.2); v.Outcome != verification.OutcomeNotFaithful {
		t.Errorf("an unclaimed search: %s", v.Outcome)
	}
}
