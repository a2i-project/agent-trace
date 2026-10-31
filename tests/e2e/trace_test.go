package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/probe"
	"github.com/agent-trace/agent-trace/pkg/probe/fs"
	"github.com/agent-trace/agent-trace/pkg/probe/proc"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// TestE2E_ACommandThatDeletesTheTraceIsTampering is V-59 against a known
// answer: simagent runs one claimed shell command that appends to a file
// declared as the session's trace and then deletes it. The probes see the
// append by the shell (level 1) and the delete by rm (level 2), the honest
// claims corroborate everything else, and the run is NOT FAITHFUL for trace
// tampering alone; read as missing, it cannot be verified, still NOT
// FAITHFUL, with the delete as the last write of the file.
func TestE2E_ACommandThatDeletesTheTraceIsTampering(t *testing.T) {
	skipUnprivileged(t)

	bin := buildSimAgent(t)
	ws := t.TempDir()
	traceDir := filepath.Join(ws, "trace")
	trace := filepath.Join(traceDir, "s.jsonl")
	if err := os.MkdirAll(traceDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(trace, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	trajectoryPath := filepath.Join(t.TempDir(), "trajectory.json")

	fsObs, err := fs.New(fs.Config{Path: ws, PathFilter: ws, EventBufSize: 4096})
	if err != nil {
		t.Fatalf("fs.New: %v", err)
	}
	procObs, err := proc.New(proc.Config{EventBufSize: 1024, DeferRootPID: true})
	if err != nil {
		t.Fatalf("proc.New: %v", err)
	}
	fsObs.Start()
	time.Sleep(200 * time.Millisecond)

	script := "printf x >> {ws}/trace/s.jsonl; /bin/rm {ws}/trace/s.jsonl"
	cmd := exec.Command(bin, "--workspace", ws, "--trajectory-out", trajectoryPath, "--file-only", "--shell-cmd", script)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start simagent: %v", err)
	}
	agentPID := uint32(cmd.Process.Pid)
	if err := procObs.SetRootPID(int32(cmd.Process.Pid)); err != nil {
		_ = cmd.Process.Kill()
		t.Fatalf("SetRootPID: %v", err)
	}
	procObs.Start()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("simagent: %v", err)
	}
	// CI sets this bound, not the dev box: the fs probe's settle window.
	time.Sleep(time.Second)
	_ = fsObs.Stop()
	_ = procObs.Stop()
	var g models.GroundTruth
	for e := range procObs.Events() {
		g = append(g, e)
	}
	for e := range fsObs.Events() {
		g = append(g, e)
	}
	logAmbiguous(t, g)
	data, err := os.ReadFile(trajectoryPath)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := models.ParseTrajectory(data)
	if err != nil {
		t.Fatal(err)
	}
	decl := &verification.TraceDecl{
		Covers: func(p string) bool { return p == trace },
		Main:   func(p string) bool { return p == trace },
	}
	in := verification.Input{
		Claims: tr, Ground: g, RootPID: agentPID,
		Coverage: coverageOf(map[string]probe.CoverageReporter{"fs": fsObs, "proc": procObs}),
		Options:  verification.Options{IntervalSlack: 250 * time.Millisecond},
		Trace:    verification.TraceInput{Decl: decl},
	}

	v := verification.Verify(in)
	if v.Outcome != verification.OutcomeNotFaithful {
		t.Fatalf("outcome = %s, want NOT FAITHFUL; reasons %v", v.Outcome, v.Reasons)
	}
	var deleted, written bool
	for _, tt := range v.TraceTampering {
		if tt.Event == nil || tt.Event.PID == agentPID || tt.Zone != "subtree" {
			t.Errorf("evidence %+v, want an event of the command's subtree", tt)
			continue
		}
		switch tt.Event.ActionType {
		case models.FileDelete:
			deleted = deleted || tt.Level == 2
		case models.FileWrite, models.FileClose:
			written = true
		}
	}
	if !deleted || !written {
		t.Errorf("tampering %+v, want rm's delete at level 2 and the shell's append", v.TraceTampering)
	}
	if v.Findings() != len(v.TraceTampering) {
		t.Errorf("findings %d, tampering %d: the honest claims should leave no other finding (unrecorded %v, unwitnessed %v, subtrees %d)",
			v.Findings(), len(v.TraceTampering), v.Unrecorded, v.Unwitnessed, len(v.Coverage.UnexplainedSubtrees))
	}
	// Without the declaration the same run is FAITHFUL: the rule alone
	// makes it NOT FAITHFUL.
	plain := in
	plain.Trace = verification.TraceInput{}
	requireFaithful(t, verification.Verify(plain))

	in.Trace.State, in.Trace.Detail = verification.TraceMissing, trace+" does not exist"
	v = verification.Verify(in)
	if v.Outcome != verification.OutcomeNotFaithful || !v.Trace.Unreadable() || len(v.Trace.Files) != 1 || !v.Trace.Files[0].Deleted() {
		t.Errorf("read as missing: outcome %s, trace %+v, want NOT FAITHFUL with the delete as the last write", v.Outcome, v.Trace)
	}
}
