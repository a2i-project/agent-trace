package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/probe/fs"
	"github.com/agent-trace/agent-trace/pkg/probe/proc"
)

// runSimAgentShell runs simagent with --shell-cmd and no probes, returning its
// trajectory. It is the unprivileged half of Tier 6 step 4.
func runSimAgentShell(t *testing.T, script string) (models.Trajectory, string) {
	t.Helper()
	bin := buildSimAgent(t)
	ws := t.TempDir()
	out := filepath.Join(t.TempDir(), "trajectory.json")
	cmd := exec.Command(bin, "--workspace", ws, "--trajectory-out", out, "--file-only", "--shell-cmd", script)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("simagent: %v\n%s", err, b)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := models.ParseTrajectory(data)
	if err != nil {
		t.Fatalf("ParseTrajectory: %v", err)
	}
	return tr, ws
}

// The compound command must be claimed as one shell invocation, with the
// interval and exit code the run produced, and must claim nothing the script
// itself spawns or writes (D3: descendants are never claimed).
func TestSimAgentShellCmd_ClaimsOnlyTheShellInvocation(t *testing.T) {
	tr, ws := runSimAgentShell(t, "echo hi | tr a-z A-Z > {ws}/upper.txt; wc -l {ws}/upper.txt; exit 3")

	if got, err := os.ReadFile(filepath.Join(ws, "upper.txt")); err != nil || string(got) != "HI\n" {
		t.Fatalf("the script did not run: %q, %v", got, err)
	}

	wantTarget := "/bin/sh -c echo hi | tr a-z A-Z > " + ws + "/upper.txt; wc -l " + ws + "/upper.txt; exit 3"
	var execs, exits int
	for _, e := range tr {
		if !strings.HasPrefix(e.Target, "/bin/sh -c") {
			if strings.Contains(e.Target, "upper.txt") || strings.Contains(e.Target, "/wc") || strings.Contains(e.Target, "/tr") {
				t.Errorf("trajectory claims a descendant action: %s %q", e.ActionType, e.Target)
			}
			continue
		}
		if e.Target != wantTarget {
			t.Errorf("claimed target = %q, want %q ({ws} expanded, argv as the proc probe reports it)", e.Target, wantTarget)
		}
		switch e.ActionType {
		case models.ProcessExec:
			execs++
			if e.End == nil || e.End.Before(e.Timestamp) {
				t.Errorf("exec claim interval = [%v, %v], want an end not before the start", e.Timestamp, e.End)
			}
		case models.ProcessExit:
			exits++
			if e.ExitCode == nil || *e.ExitCode != 3 {
				t.Errorf("exit claim code = %v, want 3", e.ExitCode)
			}
		}
	}
	if execs != 1 || exits != 1 {
		t.Errorf("shell claims: %d exec, %d exit, want one of each", execs, exits)
	}
}

// Without the flag nothing changes: the existing tiers depend on it.
func TestSimAgentShellCmd_OffByDefault(t *testing.T) {
	bin := buildSimAgent(t)
	out := filepath.Join(t.TempDir(), "trajectory.json")
	if b, err := exec.Command(bin, "--workspace", t.TempDir(), "--trajectory-out", out, "--file-only").CombinedOutput(); err != nil {
		t.Fatalf("simagent: %v\n%s", err, b)
	}
	data, _ := os.ReadFile(out)
	tr, err := models.ParseTrajectory(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range tr {
		if strings.HasPrefix(e.Target, "/bin/sh") || e.End != nil {
			t.Errorf("default run produced a shell claim or interval: %+v", e)
		}
	}
}

// TestTier6_E2E_ShellCmdBuildsAForest is the spec test for F6.7 as far as the
// probes allow today. The ground truth for a compound command must contain a
// level-1 process (the shell, child of the agent) and level-2 processes (what
// the script runs, children of the shell), and a file written inside the
// script must carry the pid of a descendant, not of the agent or the shell
// claim itself. That tree is what Tier 6 step 5 attributes by. Attribution
// logic is not asserted here, because it does not exist yet.
func TestTier6_E2E_ShellCmdBuildsAForest(t *testing.T) {
	skipUnprivileged(t)

	bin := buildSimAgent(t)
	ws := t.TempDir()
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

	// The pipeline children open the redirection themselves, before exec, so
	// the file event's pid is a process that also has an exec record.
	// An external echo, not the shell builtin: a builtin in a pipeline runs in
	// a forked subshell that never execs, so it would leave no exec record and
	// no node in the tree (the open fork-record problem, 08 section 3.2).
	script := "/bin/echo hi | tr a-z A-Z > {ws}/upper.txt; wc -l {ws}/upper.txt"
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
	time.Sleep(time.Second)
	_ = fsObs.Stop()
	_ = procObs.Stop()

	var procEvents, fsEvents []models.GroundTruthEvent
	for e := range procObs.Events() {
		procEvents = append(procEvents, e)
	}
	for e := range fsObs.Events() {
		fsEvents = append(fsEvents, e)
	}

	// Build the tree from exec records alone, as the verifier will.
	parent := map[uint32]uint32{}
	var shellPID uint32
	for _, e := range procEvents {
		if e.ActionType != models.ProcessExec || e.PID == 0 {
			continue
		}
		parent[e.PID] = e.PPID
		if strings.HasPrefix(e.Target, "/bin/sh -c") && e.PPID == agentPID {
			shellPID = e.PID
		}
	}
	if shellPID == 0 {
		t.Fatalf("no level-1 shell exec whose parent is the agent (%d); proc events: %v", agentPID, procEvents)
	}
	level := func(pid uint32) int { // 1 = shell, 2+ = below it, 0 = not under the agent
		for depth := 1; pid != 0 && depth < 32; depth++ {
			if parent[pid] == agentPID {
				return depth
			}
			pid = parent[pid]
		}
		return 0
	}
	if level(shellPID) != 1 {
		t.Errorf("shell level = %d, want 1", level(shellPID))
	}
	var level2 int
	for pid := range parent {
		if parent[pid] == shellPID {
			level2++
			if level(pid) != 2 {
				t.Errorf("child %d of the shell has level %d, want 2", pid, level(pid))
			}
		}
	}
	if level2 < 3 { // tr, wc and echo or its subshell
		t.Errorf("only %d level-2 processes under the shell, want the script's children", level2)
	}

	// The redirected file was written by a descendant of the shell.
	target := filepath.Join(ws, "upper.txt")
	var writers int
	for _, e := range fsEvents {
		if e.Target != target || (e.ActionType != models.FileWrite && e.ActionType != models.FileClose) {
			continue
		}
		writers++
		if e.PID == agentPID || e.PID == shellPID {
			t.Errorf("%s on %s attributed to pid %d, which is the agent or the shell, not the descendant that wrote it", e.ActionType, target, e.PID)
		}
		if level(e.PID) != 2 {
			t.Errorf("%s on %s by pid %d at level %d, want a level-2 descendant of the shell", e.ActionType, target, e.PID, level(e.PID))
		}
	}
	if writers == 0 {
		t.Errorf("no write events for %s; fs events: %v", target, fsEvents)
	}
}
