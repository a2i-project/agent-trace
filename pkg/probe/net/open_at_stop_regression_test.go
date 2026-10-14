package net

import (
	"fmt"
	stdnet "net"
	"os"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// One of the documented limits the security review of 2026-10-08 listed as
// still live evasions: a connection without an SNI name was emitted only at
// its close, so one held open past the end of the capture was never emitted
// and nothing counted it. N-21 (commit 497e306) emits every connection still
// open when both feeders close, from correlate.
// TestFlushOpenConnections_EmitsWhatNeverClosed calls flushOpenConnections
// directly, so only a test through a running observer checks that correlate
// calls it. The test process, the tracked root, connects to a local sink,
// writes, and keeps the connection open until the observer has stopped.
func TestObserver_AConnectionOpenAtStopIsEmitted(t *testing.T) {
	skipUnprivileged(t)
	ports := sinks(t, 1)
	obs := startObserver(t)

	target := fmt.Sprintf("127.0.0.1:%d", ports[0])
	c, err := stdnet.Dial("tcp4", target)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write([]byte("held open past the capture")); err != nil {
		t.Fatalf("write: %v", err)
	}
	time.Sleep(300 * time.Millisecond)

	events := drainEvents(t, obs) // stops the observer with the connection open
	at, pid := typeOf(t, events, target)
	if at != models.NetConnect {
		t.Errorf("%s is %q, want %q: a connection open when the capture stops is emitted (N-21)", target, at, models.NetConnect)
	}
	if at != "" && pid != uint32(os.Getpid()) {
		t.Errorf("%s has PID %d, want the test process %d", target, pid, os.Getpid())
	}
	if n := obs.Coverage().OpenAtStop; n < 1 {
		t.Errorf("OpenAtStop = %d, want at least the held connection", n)
	}
}
