package e2e

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/probe"
	probenet "github.com/agent-trace/agent-trace/pkg/probe/net"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// TestTier3_E2E_ListenerIsCapabilityEvidence is the spec test for
// 09_observer_hardening_todo.md item 2. A command in the watched tree opens a
// wildcard listener. The net probe must record bind and listen with the
// address, the exposure must read as wildcard, and the verifier must count the
// listener as capability evidence without making the run unfaithful, because
// no trajectory can claim it (decision D3: level 2, never aligned).
func TestTier3_E2E_ListenerIsCapabilityEvidence(t *testing.T) {
	skipUnprivileged(t)
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}

	// Reserve the port before the observer starts, so the reservation itself
	// (a listener in the tracked process) does not appear in the events.
	l, err := listenTCP4()
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	port := l.port
	l.close()

	obs, err := probenet.New(probenet.Config{TrackedPID: int32(os.Getpid()), EventBufSize: 256})
	if err != nil {
		t.Fatalf("probenet.New: %v", err)
	}
	obs.Start()
	time.Sleep(200 * time.Millisecond)

	script := fmt.Sprintf("import socket; s=socket.socket(); s.bind(('0.0.0.0', %d)); s.listen(1); s.close()", port)
	if out, err := exec.Command(py, "-c", script).CombinedOutput(); err != nil {
		t.Fatalf("listener command: %v\n%s", err, out)
	}
	time.Sleep(500 * time.Millisecond)
	if err := obs.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	var g models.GroundTruth
	for e := range obs.Events() {
		g = append(g, e)
	}

	want := fmt.Sprintf("0.0.0.0:%d", port)
	var sawBind, sawListen bool
	for _, e := range g {
		if e.Target != want {
			continue
		}
		switch e.ActionType {
		case models.NetBind:
			sawBind = true
		case models.NetListen:
			sawListen = true
			if models.ClassifyBindTarget(e.Target) != models.ExposureWildcard {
				t.Errorf("exposure of %s = %s, want wildcard", e.Target, models.ClassifyBindTarget(e.Target))
			}
		}
	}
	if !sawBind || !sawListen {
		t.Fatalf("bind seen = %v, listen seen = %v for %s; events: %v", sawBind, sawListen, want, g)
	}

	// The agent reports nothing. The listener must not make that unfaithful,
	// and it must be counted.
	// The test process is the agent: the probe tracks it, and the listener
	// command is its child. No proc probe runs, so the child is outside the
	// forest, which does not matter for an unclaimable event.
	c := capture{g: g, root: os.Getpid(), cov: coverageOf(map[string]probe.CoverageReporter{"net": obs})}
	v := c.verify(models.Trajectory{})
	if v.Outcome != verification.OutcomeFaithful || len(v.Unrecorded) != 0 {
		t.Errorf("listener made the run unfaithful: outcome = %s, unrecorded = %v", v.Outcome, v.Unrecorded)
	}
	if len(v.Capability) < 2 {
		t.Errorf("Capability = %d, want the bind and the listen counted", len(v.Capability))
	}
}

type reservedPort struct {
	port  int
	close func()
}

func listenTCP4() (*reservedPort, error) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	return &reservedPort{port: ln.Addr().(*net.TCPAddr).Port, close: func() { _ = ln.Close() }}, nil
}

// TestTier3_E2E_UnixConnectIsCapabilityEvidence is the spec test for item 5
// part 2. A command in the watched tree connects to a Unix socket, the way an
// agent reaches the Docker daemon, which runs outside the tracked tree. The
// connect must be recorded with the socket path and counted as capability
// evidence, and it must not make an honest run unfaithful.
func TestTier3_E2E_UnixConnectIsCapabilityEvidence(t *testing.T) {
	skipUnprivileged(t)
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}

	sock := filepath.Join(t.TempDir(), "docker.sock")
	obs, err := probenet.New(probenet.Config{TrackedPID: int32(os.Getpid()), EventBufSize: 256})
	if err != nil {
		t.Fatalf("probenet.New: %v", err)
	}
	obs.Start()
	time.Sleep(200 * time.Millisecond)

	// The client connects to a socket nobody serves: a connect attempt is
	// evidence whether or not the daemon answers.
	script := fmt.Sprintf("import socket; s=socket.socket(socket.AF_UNIX)\ntry:\n s.connect(%q)\nexcept OSError:\n pass\n", sock)
	if out, err := exec.Command(py, "-c", script).CombinedOutput(); err != nil {
		t.Fatalf("client command: %v\n%s", err, out)
	}
	time.Sleep(500 * time.Millisecond)
	if err := obs.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	var g models.GroundTruth
	for e := range obs.Events() {
		g = append(g, e)
	}

	var seen bool
	for _, e := range g {
		if e.ActionType == models.NetUnixConnect && e.Target == "unix:"+sock {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("no net_unix_connect for %s; events: %v", sock, g)
	}
	c := capture{g: g, root: os.Getpid(), cov: coverageOf(map[string]probe.CoverageReporter{"net": obs})}
	v := c.verify(models.Trajectory{})
	if v.Outcome != verification.OutcomeFaithful || len(v.Unrecorded) != 0 {
		t.Errorf("a unix connect made the run unfaithful: outcome = %s, unrecorded = %v", v.Outcome, v.Unrecorded)
	}
	if len(v.Capability) == 0 {
		t.Error("the unix connect was not counted as capability evidence")
	}
}
