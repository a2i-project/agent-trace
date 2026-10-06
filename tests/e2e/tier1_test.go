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
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// capture is one observed run: the agent's own trajectory, the ground truth the
// probes produced, the agent's root pid, and the loss record the probes gave
// when they stopped. It is what cmd/watch writes to disk, held in memory.
type capture struct {
	tr   models.Trajectory
	g    models.GroundTruth
	root int
	cov  *models.Coverage
}

// coverageOf reads each probe's real loss counters, so a run that lost events
// is INCONCLUSIVE here as it would be under cmd/watch. Call it after Stop,
// which is when the observers snapshot their counters.
func coverageOf(probes map[string]probe.CoverageReporter) *models.Coverage {
	cov := &models.Coverage{Schema: models.CoverageSchema, Probes: map[string]models.ProbeCoverage{}}
	for name, r := range probes {
		cov.Probes[name] = r.CaptureCoverage()
	}
	return cov
}

// verify runs the verifier on the capture with the given claims, which are the
// agent's own unless a test mutates them.
func (c capture) verify(claims models.Trajectory) verification.Verdict {
	return c.verifyWith(claims, verification.Options{})
}

func (c capture) verifyWith(claims models.Trajectory, opts verification.Options) verification.Verdict {
	return verification.Verify(verification.Input{
		Claims:   claims,
		Ground:   c.g,
		RootPID:  uint32(c.root),
		Coverage: c.cov,
		Options:  opts,
	})
}

// requireFaithful fails the test with the full findings when the run is not
// FAITHFUL. INCONCLUSIVE fails too: an honest run must be provably honest.
func requireFaithful(t *testing.T, v verification.Verdict) {
	t.Helper()
	if v.Outcome != verification.OutcomeFaithful {
		t.Errorf("outcome = %s, want FAITHFUL", v.Outcome)
		logVerdict(t, v)
	}
}

// runFileOnly runs simagent --file-only with the fs probe alone, the Tier 1 and
// Tier 4 setup. The agent is the root: every file event carries its pid.
func runFileOnly(t *testing.T) capture {
	t.Helper()
	binPath := buildSimAgent(t)
	workspace := t.TempDir()
	trajectoryPath := filepath.Join(t.TempDir(), "trajectory.json")

	obs, err := fs.New(fs.Config{Path: workspace, PathFilter: workspace, EventBufSize: 4096})
	if err != nil {
		t.Fatalf("fs.New: %v", err)
	}
	obs.Start()
	time.Sleep(200 * time.Millisecond)

	cmd := exec.Command(binPath, "--workspace", workspace, "--trajectory-out", trajectoryPath, "--file-only")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("simagent failed: %v\n%s", err, out)
	}
	root := cmd.Process.Pid

	// Give the kernel and probe a moment to queue and process events.
	time.Sleep(500 * time.Millisecond)
	if err := obs.Stop(); err != nil {
		t.Fatalf("obs.Stop: %v", err)
	}
	var g models.GroundTruth
	for e := range obs.Events() {
		g = append(g, e)
	}

	data, err := os.ReadFile(trajectoryPath)
	if err != nil {
		t.Fatalf("read trajectory: %v", err)
	}
	tr, err := models.ParseTrajectory(data)
	if err != nil {
		t.Fatalf("models.ParseTrajectory: %v", err)
	}
	return capture{tr: tr, g: g, root: root, cov: coverageOf(map[string]probe.CoverageReporter{"fs": obs})}
}

func skipUnprivileged(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("requires root or CAP_SYS_ADMIN")
	}
}

// buildSimAgent compiles the cmd/simagent binary and returns the path to it.
func buildSimAgent(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "simagent")

	cmd := exec.Command("go", "build", "-o", binPath, "../../cmd/simagent")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build simagent: %v\n%s", err, string(out))
	}
	return binPath
}

func TestTier1_E2E_Faithful(t *testing.T) {
	skipUnprivileged(t)
	c := runFileOnly(t)
	if len(c.g) == 0 {
		t.Fatal("the fs probe observed nothing")
	}
	requireFaithful(t, c.verify(c.tr))
}

func TestTier1_E2E_NotFaithful_Omission(t *testing.T) {
	skipUnprivileged(t)
	c := runFileOnly(t)

	// Drop the first claim: the agent did something it does not report.
	dropped := c.tr[0]
	verdict := c.verify(c.tr[1:])
	if verdict.Outcome != verification.OutcomeNotFaithful {
		t.Fatalf("outcome = %s, want NOT FAITHFUL due to omission", verdict.Outcome)
	}
	found := false
	for _, e := range verdict.Unrecorded {
		if e.ActionType == dropped.ActionType && e.Target == dropped.Target {
			found = true
		}
	}
	if !found {
		t.Errorf("dropped claim %s %s not among the Unrecorded events", dropped.ActionType, dropped.Target)
		logVerdict(t, verdict)
	}
}

func TestTier1_E2E_NotFaithful_Fabrication(t *testing.T) {
	skipUnprivileged(t)
	c := runFileOnly(t)

	// Fabrication: a claim for a file open that never happened. The path is
	// inside the watched workspace, so a real open would have been observed.
	ghost := models.TrajectoryEntry{
		Timestamp:  c.tr[0].Timestamp.Add(time.Millisecond),
		ActionType: models.FileOpen,
		Target:     "/nonexistent/ghost.txt",
	}
	for _, e := range c.tr {
		if e.ActionType == models.FileOpen {
			ghost.Target = filepath.Join(filepath.Dir(e.Target), "ghost.txt")
			break
		}
	}
	verdict := c.verify(append(append(models.Trajectory{}, c.tr...), ghost))
	if verdict.Outcome != verification.OutcomeNotFaithful {
		t.Fatalf("outcome = %s, want NOT FAITHFUL due to the fabricated entry", verdict.Outcome)
	}
	found := false
	for _, e := range verdict.Unwitnessed {
		if e.Target == ghost.Target && e.ActionType == ghost.ActionType {
			found = true
		}
	}
	if !found {
		t.Errorf("fabricated entry %s %s not among the Unwitnessed claims", ghost.ActionType, ghost.Target)
		logVerdict(t, verdict)
	}
}

// Filename swap is target substitution (P3). The alignment pairs the swapped
// claim with the event at the same position, so it is one Mismatched pair
// naming the target, and neither a fabrication nor an omission.
func TestTier1_E2E_NotFaithful_FilenameSwap(t *testing.T) {
	skipUnprivileged(t)
	c := runFileOnly(t)

	var realTarget string
	for _, e := range c.tr {
		if e.ActionType == models.FileOpen {
			realTarget = e.Target
			break
		}
	}
	if realTarget == "" {
		t.Fatal("no file_open claim to swap")
	}
	swapTarget := filepath.Join(filepath.Dir(realTarget), "decoy.txt")
	mutated := append(models.Trajectory{}, c.tr...)
	for i := range mutated {
		if mutated[i].ActionType == models.FileOpen && mutated[i].Target == realTarget {
			mutated[i].Target = swapTarget
			break
		}
	}

	verdict := c.verify(mutated)
	if verdict.Outcome != verification.OutcomeNotFaithful {
		t.Fatalf("outcome = %s, want NOT FAITHFUL due to the filename swap", verdict.Outcome)
	}
	found := false
	for _, p := range verdict.Mismatched {
		if p.Entry.Target == swapTarget && p.Event.Target == realTarget {
			for _, d := range p.Diffs {
				if d == verification.DiffTarget {
					found = true
				}
			}
		}
	}
	if !found {
		t.Errorf("swap of %s for %s not reported as a target mismatch", realTarget, swapTarget)
		logVerdict(t, verdict)
	}
	if len(verdict.Unwitnessed) != 0 || len(verdict.Unrecorded) != 0 {
		t.Errorf("a substitution must not also read as a fabrication and an omission: unwitnessed=%d unrecorded=%d",
			len(verdict.Unwitnessed), len(verdict.Unrecorded))
	}
}
