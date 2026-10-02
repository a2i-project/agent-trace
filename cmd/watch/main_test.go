package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/probe"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

func skipUnprivileged(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("requires root (fanotify + eBPF)")
	}
}

// TestRunWatch_ExecWrapSuppressesRootSeesChild exercises the Fix 3a wiring:
// runWatch launches the "agent" itself and records its PID as the proc
// probe's ancestry root. Two properties must hold:
//
//   - the agent process's own exec must NOT appear as a ground-truth event
//     (it is the controller, not an agent action), matching the suppression
//     tests/e2e/tier2_test.go's runTier2Agent already relies on;
//   - a child the agent spawns MUST appear, tagged top-level.
//
// The fake agent is a shell (the ancestry root) that forks one child,
// `/bin/echo <nonce>`, via `&` so the shell genuinely forks rather than
// exec-ing echo in place.
func TestRunWatch_ExecWrapSuppressesRootSeesChild(t *testing.T) {
	skipUnprivileged(t)

	ws := t.TempDir()
	out := filepath.Join(t.TempDir(), "ground_truth.json")
	nonce := fmt.Sprintf("watch-3a-%d", time.Now().UnixNano())
	// sleep 2 prevents a scheduler race where the child shell runs and forks
	// before the parent watch process has a chance to call SetRootPID.
	script := "sleep 2 && /bin/echo " + nonce + " & wait"

	opts := watchOptions{
		cfg:       watchConfig{Workspace: ws, EventBufSize: 256},
		probes:    "proc",
		out:       out,
		agentArgs: []string{"/bin/sh", "-c", script},
	}

	if err := runWatch(opts); err != nil {
		t.Fatalf("runWatch: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read %s: %v", out, err)
	}
	file, err := models.ParseGroundTruthFile(data)
	if err != nil {
		t.Fatalf("parse ground truth: %v", err)
	}
	if file.Coverage == nil {
		t.Fatal("watch wrote no coverage record")
	}
	if !file.Coverage.Probes["proc"].Ran {
		t.Errorf("proc probe not recorded as run: %+v", file.Coverage.Probes)
	}
	ground := file.Events

	var sawRoot, sawChild bool
	for _, e := range ground {
		if e.ActionType != models.ProcessExec {
			continue
		}
		if strings.HasPrefix(e.Target, "/bin/sh") && strings.Contains(e.Target, nonce) {
			// The root shell's own exec line (its argv carries the -c script).
			sawRoot = true
		}
		if strings.HasPrefix(e.Target, "/bin/echo") && strings.Contains(e.Target, nonce) {
			sawChild = true
			if e.IsTopLevel != nil && !*e.IsTopLevel {
				t.Errorf("child exec %q tagged forensic-only, want top-level", e.Target)
			}
		}
	}
	if sawRoot {
		t.Errorf("root agent exec leaked into ground truth; events: %+v", ground)
	}
	if !sawChild {
		t.Errorf("child exec (echo %s) missing from ground truth; events: %+v", nonce, ground)
	}
}

// TestRunWatch_RejectsRootPIDWithCommand is a pure-logic guard that needs no
// privileges: the two ancestry-root mechanisms are mutually exclusive.
func TestRunWatch_RejectsRootPIDWithCommand(t *testing.T) {
	err := runWatch(watchOptions{
		cfg:       watchConfig{Workspace: t.TempDir()},
		probes:    "proc",
		rootPID:   1234,
		agentArgs: []string{"/bin/true"},
	})
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected mutual-exclusion error, got %v", err)
	}
}

type fakeReporter struct{ cov models.ProbeCoverage }

func (f fakeReporter) CaptureCoverage() models.ProbeCoverage { return f.cov }

func TestBuildCoverage_RecordsEveryKnownProbe(t *testing.T) {
	cov := buildCoverage(map[string]probe.CoverageReporter{
		"proc": fakeReporter{models.ProbeCoverage{Ran: true, RingbufDrops: 5}},
	})
	if cov.Schema != models.CoverageSchema {
		t.Errorf("schema = %d, want %d", cov.Schema, models.CoverageSchema)
	}
	if len(cov.Probes) != len(probeBuilders) {
		t.Fatalf("recorded %d probes, want all %d known", len(cov.Probes), len(probeBuilders))
	}
	if got := cov.Probes["proc"]; !got.Ran || got.RingbufDrops != 5 {
		t.Errorf("proc = %+v, want ran with 5 drops", got)
	}
	for _, name := range []string{"fs", "net"} {
		if cov.Probes[name].Ran {
			t.Errorf("%s was not selected but is recorded as run", name)
		}
	}
}

// TestRunWatch_RecordsLossInCoverage forces the proc probe's kernel ring to
// overflow (one-page ring, an exec whose argv alone exceeds it) and checks the
// loss reaches the written file and makes the capture count as incomplete.
func TestRunWatch_RecordsLossInCoverage(t *testing.T) {
	skipUnprivileged(t)

	out := filepath.Join(t.TempDir(), "ground_truth.json")
	script := "sleep 2 && /bin/true " + strings.Repeat("x", 6000)

	opts := watchOptions{
		cfg:       watchConfig{Workspace: t.TempDir(), EventBufSize: 256, ProcRingbufBytes: 4096},
		probes:    "proc",
		out:       out,
		agentArgs: []string{"/bin/sh", "-c", script},
	}
	if err := runWatch(opts); err != nil {
		t.Fatalf("runWatch: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read %s: %v", out, err)
	}
	file, err := models.ParseGroundTruthFile(data)
	if err != nil {
		t.Fatalf("parse ground truth: %v", err)
	}
	if file.Coverage == nil {
		t.Fatal("no coverage record written")
	}
	if got := file.Coverage.Probes["proc"].RingbufDrops; got == 0 {
		t.Errorf("proc RingbufDrops = 0, want > 0 after forcing the ring to overflow")
	}
	if verification.Assess(file.Coverage).Complete {
		t.Error("Assess reported a capture with ring buffer drops as complete")
	}
}
