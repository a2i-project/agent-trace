package e2e

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/probe"
	probenet "github.com/agent-trace/agent-trace/pkg/probe/net"
	"github.com/agent-trace/agent-trace/pkg/probe/proc"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// TestTier3_E2E_ListenerIsCapabilityEvidence is the spec test for
// decision P-8 (docs/decisions/probes.md). A command in the watched tree opens a
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

// TestTier3_E2E_SocketEventsAreAttributedToTheCommand pins attribution of
// capability evidence. The agent (simagent, held until both probes track it)
// runs one shell command that execs python3, so the client keeps the shell's
// pid at level 1; it connects to a Unix socket and opens a listener. Each
// event must carry the command's pid, not the agent's, and land in that
// command's Capability in the verdict and in no other command's, while the
// honest run stays FAITHFUL. A probe that stamped the root's pid, or a
// verifier that left the events at the agent, fails here.
func TestTier3_E2E_SocketEventsAreAttributedToTheCommand(t *testing.T) {
	skipUnprivileged(t)
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	l, err := listenTCP4()
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	port := l.port
	l.close()

	bin := buildSimAgent(t)
	ws := t.TempDir()
	trajectoryPath := filepath.Join(t.TempDir(), "trajectory.json")
	sock := filepath.Join(t.TempDir(), "daemon.sock")
	listen := fmt.Sprintf("127.0.0.1:%d", port)

	procObs, err := proc.New(proc.Config{EventBufSize: 1024, DeferRootPID: true})
	if err != nil {
		t.Fatalf("proc.New: %v", err)
	}
	netObs, err := probenet.New(probenet.Config{EventBufSize: 256})
	if err != nil {
		t.Fatalf("probenet.New: %v", err)
	}

	// The client connects to a socket nobody serves: the attempt is the
	// evidence. connect_ex returns the error instead of raising it.
	client := fmt.Sprintf(`import socket; u=socket.socket(socket.AF_UNIX); u.connect_ex("%s"); s=socket.socket(); s.bind(("127.0.0.1", %d)); s.listen(1); s.close()`, sock, port)
	// The agent is held on its stdin until both probes track its pid, then
	// execs simagent in place, as watch starts an agent: no fork of the
	// shell command can come before the tracking. The probes drop the root's
	// own exec.
	cmd := exec.Command("/bin/sh", "-c", `read go; exec "$@"`, "sh",
		bin, "--workspace", ws, "--trajectory-out", trajectoryPath, "--file-only",
		"--shell-cmd", "exec "+py+" -c '"+client+"'")
	release, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start agent: %v", err)
	}
	agentPID := uint32(cmd.Process.Pid)
	if err := procObs.SetRootPID(int32(agentPID)); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("SetRootPID: %v", err)
	}
	procObs.Start()
	if err := netObs.TrackPID(int32(agentPID)); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("TrackPID: %v", err)
	}
	netObs.Start()
	if _, err := release.Write([]byte("go\n")); err != nil {
		t.Fatalf("release the agent: %v", err)
	}
	_ = release.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("simagent: %v", err)
	}
	// CI sets this bound, not a dev box: the probes drain after the agent exits.
	time.Sleep(time.Second)
	if err := procObs.Stop(); err != nil {
		t.Fatalf("procObs.Stop: %v", err)
	}
	if err := netObs.Stop(); err != nil {
		t.Fatalf("netObs.Stop: %v", err)
	}
	var g models.GroundTruth
	for e := range procObs.Events() {
		g = append(g, e)
	}
	for e := range netObs.Events() {
		g = append(g, e)
	}

	// The shell command is the agent's child, so its pid is level 1.
	var shellPID uint32
	for _, e := range g {
		if e.ActionType == models.ProcessExec && e.PPID == agentPID && strings.HasPrefix(e.Target, "/bin/sh -c") {
			shellPID = e.PID
		}
	}
	if shellPID == 0 || shellPID == agentPID {
		t.Fatalf("no level-1 shell exec under the agent %d; events: %v", agentPID, g)
	}

	type key struct {
		typ    models.ActionType
		target string
	}
	want := []key{
		{models.NetUnixConnect, models.UnixTargetPrefix + sock},
		{models.NetBind, listen},
		{models.NetListen, listen},
	}
	for _, w := range want {
		var n int
		for _, e := range g {
			if e.ActionType == w.typ && e.Target == w.target {
				n++
				if e.PID != shellPID {
					t.Errorf("%s %s by pid %d, want the command's pid %d (the agent is %d)", w.typ, w.target, e.PID, shellPID, agentPID)
				}
			}
		}
		if n != 1 {
			t.Errorf("%d %s events for %s, want 1; events: %v", n, w.typ, w.target, g)
		}
	}

	// simagent's file claims are left out: no fs probe runs. The shell's
	// exec and exit claims are what the agent says about the command.
	data, err := os.ReadFile(trajectoryPath)
	if err != nil {
		t.Fatal(err)
	}
	all, err := models.ParseTrajectory(data)
	if err != nil {
		t.Fatalf("ParseTrajectory: %v", err)
	}
	var tr models.Trajectory
	for _, e := range all {
		if strings.HasPrefix(e.Target, "/bin/sh -c") {
			tr = append(tr, e)
		}
	}
	if len(tr) != 2 {
		t.Fatalf("shell claims %v, want its exec and exit", tr)
	}
	c := capture{tr: tr, g: g, root: int(agentPID), cov: coverageOf(map[string]probe.CoverageReporter{"proc": procObs, "net": netObs})}
	v := c.verifyWith(tr, verification.Options{IntervalSlack: 250 * time.Millisecond})
	requireFaithful(t, v)

	held := func(evs models.GroundTruth, w key) bool {
		for _, e := range evs {
			if e.ActionType == w.typ && e.Target == w.target {
				return true
			}
		}
		return false
	}
	for _, w := range want {
		if !held(v.Capability, w) {
			t.Errorf("%s %s is not capability evidence in the verdict", w.typ, w.target)
		}
		var holders []uint32
		for _, cmd := range v.Commands {
			if held(cmd.Capability, w) {
				holders = append(holders, cmd.Process.PID)
			}
		}
		if len(holders) != 1 || holders[0] != shellPID {
			t.Errorf("%s %s held by commands %v, want only the shell command %d", w.typ, w.target, holders, shellPID)
		}
	}
}
