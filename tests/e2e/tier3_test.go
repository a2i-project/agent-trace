package e2e

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/probe"
	"github.com/agent-trace/agent-trace/pkg/probe/fs"
	"github.com/agent-trace/agent-trace/pkg/probe/proc"
	probenet "github.com/agent-trace/agent-trace/pkg/probe/net"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

const tier3FetchURL = "https://example.com"

// runTier3Agent runs the simulated agent with filesystem, process, and network
// probes active. The agent performs its usual file + subprocess operations and
// additionally fetches https://example.com via curl (--fetch-url flag).
// It returns the agent's self-reported trajectory alongside the merged
// ground truth from all three probes.
func runTier3Agent(t *testing.T, extraArgs ...string) capture {
	t.Helper()

	binPath := buildSimAgent(t)
	workspace := t.TempDir()
	trajectoryPath := filepath.Join(t.TempDir(), "trajectory.json")

	fsObs, err := fs.New(fs.Config{
		Path:         workspace,
		PathFilter:   workspace,
		EventBufSize: 4096,
	})
	if err != nil {
		t.Fatalf("fs.New: %v", err)
	}

	procObs, err := proc.New(proc.Config{
		EventBufSize: 256,
		DeferRootPID: true,
	})
	if err != nil {
		t.Fatalf("proc.New: %v", err)
	}

	// Net probe runs identity-only (no ExePath) — SNI-level detection is
	// sufficient for the occurrence-level Tier 3 E2E test. TrackedPID is
	// set via TrackPID after the agent starts so the map is populated before
	// any traffic flows.
	netObs, err := probenet.New(probenet.Config{
		EventBufSize: 256,
	})
	if err != nil {
		t.Fatalf("probenet.New: %v", err)
	}

	// Start FS probe and give fanotify time to attach.
	fsObs.Start()
	time.Sleep(200 * time.Millisecond)

	args := []string{
		"--workspace", workspace,
		"--trajectory-out", trajectoryPath,
		"--fetch-url", tier3FetchURL,
	}
	args = append(args, extraArgs...)

	cmd := exec.Command(binPath, args...)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatalf("start simagent: %v", err)
	}

	// Wire all three probes to the agent PID.
	if err := procObs.SetRootPID(int32(cmd.Process.Pid)); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("procObs.SetRootPID: %v", err)
	}
	procObs.Start()

	// TrackPID before Start so the map is set before the agent's curl fires.
	if err := netObs.TrackPID(int32(cmd.Process.Pid)); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("netObs.TrackPID: %v", err)
	}
	// Start blocks only if ExePath is set (TLS validation). Since we run
	// identity-only, it returns immediately after spawning the correlator.
	netObs.Start()

	if err := cmd.Wait(); err != nil {
		t.Fatalf("simagent failed: %v\n%s", err, output.String())
	}

	// Let the kernel deliver, and all probes drain, the trailing events.
	// The network events (SNI capture) may arrive slightly later than file
	// events, so we use a generous drain window.
	time.Sleep(5 * time.Second)

	if err := fsObs.Stop(); err != nil {
		t.Fatalf("fsObs.Stop: %v", err)
	}
	if err := procObs.Stop(); err != nil {
		t.Fatalf("procObs.Stop: %v", err)
	}
	if err := netObs.Stop(); err != nil {
		t.Fatalf("netObs.Stop: %v", err)
	}

	var g models.GroundTruth
	for e := range fsObs.Events() {
		g = append(g, e)
	}
	for e := range procObs.Events() {
		g = append(g, e)
	}
	for e := range netObs.Events() {
		g = append(g, e)
	}

	data, err := os.ReadFile(trajectoryPath)
	if err != nil {
		t.Fatalf("read trajectory: %v", err)
	}
	tr, err := models.ParseTrajectory(data)
	if err != nil {
		t.Fatalf("ParseTrajectory: %v", err)
	}

	return capture{
		tr: tr, g: g, root: cmd.Process.Pid,
		cov: coverageOf(map[string]probe.CoverageReporter{"fs": fsObs, "proc": procObs, "net": netObs}),
	}
}

func TestTier3_E2E_Faithful(t *testing.T) {
	skipUnprivileged(t)

	c := runTier3Agent(t)

	// Verify that the run produced at least one NetConnect ground-truth event.
	var sawNetEvent bool
	for _, e := range c.g {
		if e.ActionType == models.NetConnect {
			sawNetEvent = true
			break
		}
	}
	if !sawNetEvent {
		t.Fatalf("expected at least one NetConnect ground-truth event from net probe (got %d total events)", len(c.g))
	}

	requireFaithful(t, c.verify(c.tr))
}

func TestTier3_E2E_NotFaithful_NetOmission(t *testing.T) {
	skipUnprivileged(t)

	c := runTier3Agent(t)

	// Drop the NetConnect entry from the trajectory.  The net probe still
	// recorded the connection, so it should surface as Unrecorded.
	filtered := c.tr[:0:0]
	dropped := false
	for _, e := range c.tr {
		if !dropped && e.ActionType == models.NetConnect {
			dropped = true
			continue
		}
		filtered = append(filtered, e)
	}
	if !dropped {
		t.Fatal("no NetConnect entry in trajectory to drop — ensure --fetch-url produced one")
	}

	verdict := c.verify(filtered)
	if verdict.Outcome != verification.OutcomeNotFaithful {
		t.Fatalf("outcome = %s, want NOT FAITHFUL after dropping the NetConnect trajectory entry", verdict.Outcome)
	}
	found := false
	for _, e := range verdict.Unrecorded {
		if e.ActionType == models.NetConnect {
			found = true
		}
	}
	if !found {
		t.Errorf("dropped NetConnect not surfaced in Unrecorded")
		logVerdict(t, verdict)
	}
}

func TestTier3_E2E_NotFaithful_NetFabrication(t *testing.T) {
	skipUnprivileged(t)

	c := runTier3Agent(t)

	// Add a NetConnect entry for a host we never contacted.  There is no
	// ground-truth counterpart, so it should surface as Unwitnessed.
	ghost := models.TrajectoryEntry{
		Timestamp:  time.Now(),
		ActionType: models.NetConnect,
		Target:     "ghost.example.invalid",
	}
	mutated := append(append(models.Trajectory{}, c.tr...), ghost)

	verdict := c.verify(mutated)
	if verdict.Outcome != verification.OutcomeNotFaithful {
		t.Fatalf("outcome = %s, want NOT FAITHFUL after fabricating a NetConnect entry", verdict.Outcome)
	}
	found := false
	for _, e := range verdict.Unwitnessed {
		if e.Target == ghost.Target {
			found = true
		}
	}
	if !found {
		t.Errorf("fabricated NetConnect entry %q not in Unwitnessed", ghost.Target)
		logVerdict(t, verdict)
	}
}
