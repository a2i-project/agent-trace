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

// A shell whose script ends in a simple command execs it in its own process
// (dash does), so the proc probe names the shell's exit by that command's
// image (P-31). simagent claims the exit under the shell's command line, the
// way any adapter that claims exits names what the agent ran. The verifier
// compares the exit with the exit of the process the shell's exec started
// (V-44), so the honest run is FAITHFUL; a wrong exit code is still a
// mismatch, and an exit claimed for a process that did not exit is still
// unwitnessed.
func TestE2E_AnExitClaimOfAShellThatExecsItsLastCommand(t *testing.T) {
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

	// The script ends in an explicit exec, since dash does not always exec a
	// list's last command on its own: the shell replaces itself, so its pid
	// runs two programs and exits under the second.
	cmd := exec.Command(bin, "--workspace", ws, "--trajectory-out", trajectoryPath, "--file-only", "--shell-cmd", "/bin/echo hi > {ws}/hi.txt; exec /bin/true")
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
	// CI sets this bound, not the dev box: the probes drain after the agent exits.
	time.Sleep(time.Second)
	_ = fsObs.Stop()
	_ = procObs.Stop()

	var events models.GroundTruth
	for e := range procObs.Events() {
		events = append(events, e)
	}
	for e := range fsObs.Events() {
		events = append(events, e)
	}
	logAmbiguous(t, events)

	// The premise: the shell's pid exec'd twice and its exit names /bin/true.
	var shellPID uint32
	execsOf := map[uint32]int{}
	var exitTarget string
	for _, e := range events {
		if e.ActionType == models.ProcessExec && e.PPID == agentPID && shellPID == 0 {
			shellPID = e.PID
		}
		if e.ActionType == models.ProcessExec {
			execsOf[e.PID]++
		}
	}
	for _, e := range events {
		if e.ActionType == models.ProcessExit && e.PID == shellPID {
			exitTarget = e.Target
		}
	}
	if shellPID == 0 || execsOf[shellPID] != 2 {
		t.Skipf("this /bin/sh did not exec its last command (shell pid %d, %d execs): the case does not arise here", shellPID, execsOf[shellPID])
	}
	if exitTarget != "/bin/true" {
		t.Fatalf("the shell's exit names %q, want the image of its last exec, /bin/true (P-31)", exitTarget)
	}

	data, err := os.ReadFile(trajectoryPath)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := models.ParseTrajectory(data)
	if err != nil {
		t.Fatalf("ParseTrajectory: %v", err)
	}
	c := capture{
		tr: tr, g: events, root: int(agentPID),
		cov: coverageOf(map[string]probe.CoverageReporter{"fs": fsObs, "proc": procObs}),
	}
	opts := verification.Options{IntervalSlack: 250 * time.Millisecond}

	t.Run("honest", func(t *testing.T) {
		v := c.verifyWith(c.tr, opts)
		requireFaithful(t, v)
		var exits int
		for _, p := range v.Corroborated {
			if p.Entry.ActionType == models.ProcessExit {
				exits++
			}
		}
		if exits != 1 {
			t.Errorf("%d exit claims corroborated, want the shell's", exits)
		}
	})

	t.Run("wrong exit code", func(t *testing.T) {
		wrong := append(models.Trajectory{}, c.tr...)
		for i := range wrong {
			if wrong[i].ActionType == models.ProcessExit && wrong[i].ExitCode != nil {
				code := *wrong[i].ExitCode + 1
				wrong[i].ExitCode = &code
			}
		}
		v := c.verifyWith(wrong, opts)
		if v.Outcome != verification.OutcomeNotFaithful || len(v.Mismatched) != 1 || v.Mismatched[0].Diffs[0] != verification.DiffExitCode {
			t.Errorf("outcome %s, mismatched %v; want NOT FAITHFUL on the exit code", v.Outcome, v.Mismatched)
		}
	})

	t.Run("exit of a process that did not exit", func(t *testing.T) {
		var g models.GroundTruth
		for _, e := range c.g {
			if e.ActionType != models.ProcessExit || e.PID != shellPID {
				g = append(g, e)
			}
		}
		v := capture{tr: c.tr, g: g, root: c.root, cov: c.cov}.verifyWith(c.tr, opts)
		if v.Outcome != verification.OutcomeNotFaithful || len(v.Unwitnessed) != 1 || v.Unwitnessed[0].ActionType != models.ProcessExit {
			t.Errorf("outcome %s, unwitnessed %v; want the exit claim unwitnessed", v.Outcome, v.Unwitnessed)
		}
	})
}
