package net

import (
	"fmt"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// TestObserver_StopDrainsRingsPromptly: Stop called the moment a tracked
// process has exited still delivers every connection it made, since Stop
// detaches the producers and then reads the rings until they are empty
// instead of closing them (N-32); and Stop returns without a fixed wait.
//
// The bound is pre-registered: with one perf-event tracepoint per hook, Stop
// took about 1.1 s on the development machine (18 detaches of about 60 ms
// each, the overhead benchmark of commit da3e4f0); raw tracepoints detach
// without waiting for a grace period. One second is generous for a contended
// CI runner and still fails the old design.
func TestObserver_StopDrainsRingsPromptly(t *testing.T) {
	skipUnprivileged(t)

	ports := sinks(t, 20)
	obs := startObserver(t)

	pyPID := runPython(t, fmt.Sprintf(`
import socket
for port in %s:
    s = socket.socket()
    s.connect(("127.0.0.1", port))
    s.send(b"x")
    s.close()
`, pyList(ports)))

	start := time.Now()
	if err := obs.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	took := time.Since(start)
	events := collect(obs)
	t.Logf("Stop took %s", took)

	for _, port := range ports {
		target := fmt.Sprintf("127.0.0.1:%d", port)
		if at, pid := typeOf(t, events, target); at != models.NetConnect || pid != pyPID {
			t.Errorf("%s is %q from PID %d, want net_connect from %d", target, at, pid, pyPID)
		}
	}
	if took > time.Second {
		t.Errorf("Stop took %s, want under 1 s (no fixed wait, N-32)", took)
	}
}

// pyList renders ports as a Python list literal.
func pyList(ports []int) string {
	s := "["
	for i, p := range ports {
		if i > 0 {
			s += ", "
		}
		s += fmt.Sprint(p)
	}
	return s + "]"
}
