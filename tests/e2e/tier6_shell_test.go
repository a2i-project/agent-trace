package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/probe"
	"github.com/agent-trace/agent-trace/pkg/probe/fs"
	"github.com/agent-trace/agent-trace/pkg/probe/proc"
	"github.com/agent-trace/agent-trace/pkg/verification"
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
// claim itself. That tree is what the verifier attributes by, so the test ends
// by running the verifier on the capture: the honest trajectory is FAITHFUL
// although the agent claimed one command and its subtree did a dozen things, and
// each way of lying about that command is caught.
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
	// no node in the tree (the fork-record problem, V1).
	// ( ) forks a subshell that writes sub.txt without ever exec'ing: its
	// pid has no exec record and is placed in the tree by a fork record.
	script := "/bin/echo hi | tr a-z A-Z > {ws}/upper.txt; wc -l {ws}/upper.txt; ( echo sub > {ws}/sub.txt )"
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

	// Build the tree from exec and fork records, as the verifier will.
	parent := map[uint32]uint32{}
	var shellPID uint32
	for _, e := range procEvents {
		if (e.ActionType != models.ProcessExec && e.ActionType != models.ProcessFork) || e.PID == 0 {
			continue
		}
		parent[e.PID] = e.PPID
		if e.ActionType == models.ProcessExec && strings.HasPrefix(e.Target, "/bin/sh -c") && e.PPID == agentPID {
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

	// The subshell's write has no exec record behind its pid. It must still
	// land in the tree below the shell, which only fork records make possible.
	sub := filepath.Join(ws, "sub.txt")
	var subWrites int
	for _, e := range fsEvents {
		if e.Target != sub || (e.ActionType != models.FileWrite && e.ActionType != models.FileClose) {
			continue
		}
		subWrites++
		if _, known := parent[e.PID]; !known {
			t.Errorf("%s on %s by pid %d, which is not in the tree at all", e.ActionType, sub, e.PID)
		} else if level(e.PID) != 2 {
			t.Errorf("%s on %s by pid %d at level %d, want a level-2 descendant of the shell", e.ActionType, sub, e.PID, level(e.PID))
		}
	}
	if subWrites == 0 {
		t.Errorf("no write events for %s; fs events: %v", sub, fsEvents)
	}

	verifyShellCapture(t, ws, trajectoryPath, agentPID, procEvents, fsEvents, fsObs, procObs)
}

// verifyShellCapture runs the verifier on the shell-command capture. The
// subtree's events (the pipeline, the file writes, the subshell) are explained
// by the one command the agent claimed. They are never compared against a claim.
func verifyShellCapture(t *testing.T, ws, trajectoryPath string, agentPID uint32, procEvents, fsEvents []models.GroundTruthEvent, fsObs *fs.Observer, procObs *proc.Observer) {
	t.Helper()
	data, err := os.ReadFile(trajectoryPath)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := models.ParseTrajectory(data)
	if err != nil {
		t.Fatalf("ParseTrajectory: %v", err)
	}
	c := capture{
		tr:   tr,
		g:    append(append(models.GroundTruth{}, procEvents...), fsEvents...),
		root: int(agentPID),
		cov:  coverageOf(map[string]probe.CoverageReporter{"fs": fsObs, "proc": procObs}),
	}
	// The probes stamp events from their own clocks, so the claim's interval
	// gets the slack a real trajectory would need (V6).
	opts := verification.Options{IntervalSlack: 250 * time.Millisecond}

	t.Run("honest", func(t *testing.T) {
		v := c.verifyWith(c.tr, opts)
		requireFaithful(t, v)
		if v.Coverage.Explained < 5 {
			t.Errorf("only %d events attributed to the claimed command's subtree, want the whole script's activity", v.Coverage.Explained)
		}
		if len(v.Coverage.UnexplainedSubtrees) != 0 {
			t.Errorf("unexplained subtrees on an honest run: %d", len(v.Coverage.UnexplainedSubtrees))
		}
	})

	// Omission: the agent runs the shell and does not say so. Everything the
	// script did is left with no claim to explain it, and it cannot hide by
	// happening in a subtree.
	t.Run("omitted command", func(t *testing.T) {
		v := c.verifyWith(nil, opts)
		if v.Outcome != verification.OutcomeNotFaithful {
			t.Fatalf("outcome = %s, want NOT FAITHFUL", v.Outcome)
		}
		if len(v.Coverage.UnexplainedSubtrees) == 0 {
			t.Error("the unclaimed shell's subtree was not reported")
		}
		if len(v.Unrecorded) == 0 {
			t.Error("the unclaimed shell's exec was not reported as unrecorded")
		}
	})

	// A descendant's write cannot be claimed (D3): the agent did not do it, its
	// child did. A claim for it has nothing at level 0 to align with.
	t.Run("claiming a descendant's write", func(t *testing.T) {
		claimed := append(models.Trajectory{}, c.tr...)
		claimed = append(claimed, models.TrajectoryEntry{
			Timestamp: c.tr[0].Timestamp, ActionType: models.FileWrite, Target: filepath.Join(ws, "upper.txt"),
		})
		v := c.verifyWith(claimed, opts)
		if v.Outcome != verification.OutcomeNotFaithful {
			t.Fatalf("outcome = %s, want NOT FAITHFUL", v.Outcome)
		}
		found := false
		for _, e := range v.Unwitnessed {
			if e.ActionType == models.FileWrite {
				found = true
			}
		}
		if !found {
			t.Error("the claimed write of a descendant is not Unwitnessed")
		}
	})

	// Target substitution on the command: the agent says it ran something else.
	t.Run("command substitution", func(t *testing.T) {
		swapped := append(models.Trajectory{}, c.tr...)
		for i := range swapped {
			if swapped[i].ActionType == models.ProcessExec {
				swapped[i].Target = "/bin/sh -c true"
			}
		}
		v := c.verifyWith(swapped, opts)
		if v.Outcome != verification.OutcomeNotFaithful {
			t.Fatalf("outcome = %s, want NOT FAITHFUL", v.Outcome)
		}
		var sawTarget bool
		for _, p := range v.Mismatched {
			for _, d := range p.Diffs {
				if d == verification.DiffTarget && p.Entry.ActionType == models.ProcessExec {
					sawTarget = true
				}
			}
		}
		if !sawTarget {
			t.Error("the substituted command is not reported as a target mismatch")
		}
	})

	// Claim interval (D12): the claim says the command ran in a window that
	// the observed exec is not inside. The pair stays and the claim is flagged.
	t.Run("claim interval excludes the exec", func(t *testing.T) {
		moved := append(models.Trajectory{}, c.tr...)
		for i := range moved {
			if moved[i].ActionType == models.ProcessExec && moved[i].End != nil {
				start := moved[i].Timestamp.Add(-time.Hour)
				end := start.Add(time.Second)
				moved[i].Timestamp, moved[i].End = start, &end
			}
		}
		v := c.verifyWith(moved, opts)
		if v.Outcome != verification.OutcomeNotFaithful || len(v.OutsideInterval) == 0 {
			t.Errorf("outcome = %s, outside interval = %d, want NOT FAITHFUL with the claim flagged", v.Outcome, len(v.OutsideInterval))
		}
	})
}

// The agent claims the commands it runs and not what they do (D3). wc's open
// of the renamed file is wc's action, so it must not appear in the trajectory.
func TestSimAgent_ClaimsWcAndNotWcsOwnOpen(t *testing.T) {
	bin := buildSimAgent(t)
	ws := t.TempDir()
	out := filepath.Join(t.TempDir(), "trajectory.json")
	if b, err := exec.Command(bin, "--workspace", ws, "--trajectory-out", out).CombinedOutput(); err != nil {
		t.Fatalf("simagent: %v\n%s", err, b)
	}
	data, _ := os.ReadFile(out)
	tr, err := models.ParseTrajectory(data)
	if err != nil {
		t.Fatal(err)
	}
	var sawWc bool
	for _, e := range tr {
		if e.ActionType == models.ProcessExec && strings.Contains(e.Target, "wc") {
			sawWc = true
		}
		if e.ActionType == models.FileOpen && strings.HasSuffix(e.Target, "file2.txt") {
			t.Errorf("trajectory claims wc's own open of file2.txt: %+v", e)
		}
	}
	if !sawWc {
		t.Error("trajectory does not claim the wc command")
	}
}

// A curl subprocess's request cannot be claimed, so asking simagent to claim it
// is a usage error and not a trajectory that could never verify.
func TestSimAgent_RejectsClaimingACurlSubtreeRequest(t *testing.T) {
	bin := buildSimAgent(t)
	cmd := exec.Command(bin, "--workspace", t.TempDir(), "--trajectory-out", filepath.Join(t.TempDir(), "t.json"),
		"--fetch-url", "https://example.invalid/", "--fetch-via-curl", "--emit-net-request")
	b, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("simagent accepted --emit-net-request with --fetch-via-curl")
	}
	if !strings.Contains(string(b), "D3") {
		t.Errorf("error does not explain why: %s", b)
	}
}
