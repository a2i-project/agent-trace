package net

import (
	"io"
	stdnet "net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// TestWriteWindowEnd checks when a write candidate's validation window ends
// (N-55): not before a tracked process's first ClientHello, then timeout
// after the later of the candidate's start and that ClientHello. A
// ClientHello before the candidate started gives the window of N-D4, counted
// from the candidate's start, unchanged.
func TestWriteWindowEnd(t *testing.T) {
	start := time.Unix(1000, 0)
	const timeout = 5 * time.Second
	for _, tc := range []struct {
		name    string
		hello   int64
		end     time.Time
		started bool
	}{
		{"no ClientHello yet", 0, time.Time{}, false},
		{"ClientHello before the candidate", start.Add(-2 * time.Second).UnixNano(), start.Add(timeout), true},
		{"ClientHello at the candidate's start", start.UnixNano(), start.Add(timeout), true},
		{"ClientHello 5.03 s after the start", start.Add(5030 * time.Millisecond).UnixNano(), start.Add(5030*time.Millisecond + timeout), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			end, started := writeWindowEnd(start, tc.hello, timeout)
			if started != tc.started || !end.Equal(tc.end) {
				t.Errorf("writeWindowEnd = %v, %v; want %v, %v", end, started, tc.end, tc.started)
			}
		})
	}
}

// TestIsClientHello checks the test that starts the window: a handshake
// record (22) of TLS major version 3 whose first message is a ClientHello (1).
func TestIsClientHello(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    []byte
		want bool
	}{
		{"ClientHello", []byte{0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00}, true},
		{"ServerHello", []byte{0x16, 0x03, 0x03, 0x00, 0x40, 0x02}, false},
		{"application data", []byte{0x17, 0x03, 0x03, 0x00, 0x20, 0x01}, false},
		{"HTTP request", []byte("GET / HTTP/1.1\r\n"), false},
		{"short", []byte{0x16, 0x03, 0x01}, false},
	} {
		if got := isClientHello(tc.p); got != tc.want {
			t.Errorf("%s: isClientHello = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// heldSClient starts a shell that waits for a line on its stdin and then
// execs openssl(1) s_client to addr, keeping the shell's pid, which the
// observer tracks before the release. The rest of stdin goes to s_client,
// which writes it through SSL_write once the handshake is done.
func heldSClient(t *testing.T, obs *Observer, addr, host string) (stdin io.WriteCloser) {
	t.Helper()
	serverHost, port, err := stdnet.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	cmd := exec.Command("sh", "-c", `read go; exec openssl s_client -connect "$1" -servername "$2" -quiet`,
		"sh", stdnet.JoinHostPort(serverHost, port), host)
	stdin, err = cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start shell: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	if err := obs.TrackPID(int32(cmd.Process.Pid)); err != nil {
		t.Fatalf("TrackPID: %v", err)
	}
	return stdin
}

// TestObserver_ValidationWindowStartsAtFirstClientHello is N-55's positive
// case: a tracked client that starts its TLS connection well after the
// probes started, later than ValidationTimeout, still validates the
// SSL_write offset and has its request captured. Under the window of N-D4,
// counted from Start, the same run fell back to identity only.
func TestObserver_ValidationWindowStartsAtFirstClientHello(t *testing.T) {
	skipUnprivileged(t)
	libssl := findLibSSL(t)
	const host = "agenttrace-late-start.internal"
	addr := startTLSServer(t, host)

	const timeout = time.Second
	obs, err := New(Config{ExePath: libssl, EventBufSize: 256, ValidationTimeout: timeout, CachePath: t.TempDir() + "/cache.json"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	stdin := heldSClient(t, obs, addr, host)
	var evs []models.GroundTruthEvent
	eventsDone := make(chan struct{})
	go func() {
		defer close(eventsDone)
		for ev := range obs.Events() {
			evs = append(evs, ev)
		}
	}()
	startDone := make(chan struct{})
	go func() { obs.Start(); close(startDone) }()

	// Well past the window counted from Start: the client has not connected.
	time.Sleep(3 * timeout)
	select {
	case <-startDone:
		t.Fatalf("Start returned before any ClientHello: %v", obs.TLSAttachError())
	default:
	}
	if _, err := io.WriteString(stdin, "go\nGET /v1/late HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("release the client: %v", err)
	}
	// CI sets this bound, not a dev box.
	select {
	case <-startDone:
	case <-time.After(15 * time.Second):
		t.Fatal("Start did not return after the client's request")
	}
	if err := obs.TLSAttachError(); err != nil {
		t.Fatalf("TLSAttachError: %v", err)
	}
	time.Sleep(500 * time.Millisecond)
	if err := obs.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	<-eventsDone
	want := "GET https://" + host + "/v1/late"
	for _, ev := range evs {
		if ev.ActionType == models.NetRequest && ev.Target == want {
			return
		}
	}
	t.Fatalf("no net_request %q among %d events; coverage %+v", want, len(evs), obs.Coverage())
}

// TestObserver_ValidationWindowEndsAfterClientHello is N-55's fail-closed
// case: a tracked client that completes its handshake but never writes
// leaves the candidate without a frame, and the window, started at its
// ClientHello, ends the validation with identity only.
func TestObserver_ValidationWindowEndsAfterClientHello(t *testing.T) {
	skipUnprivileged(t)
	libssl := findLibSSL(t)
	const host = "agenttrace-silent-client.internal"
	addr := startTLSServer(t, host)

	const timeout = time.Second
	obs, err := New(Config{ExePath: libssl, EventBufSize: 256, ValidationTimeout: timeout, CachePath: t.TempDir() + "/cache.json"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	stdin := heldSClient(t, obs, addr, host)
	go func() {
		for range obs.Events() {
		}
	}()
	startDone := make(chan struct{})
	go func() { obs.Start(); close(startDone) }()
	time.Sleep(2 * timeout)
	select {
	case <-startDone:
		t.Fatalf("Start returned before any ClientHello: %v", obs.TLSAttachError())
	default:
	}
	if _, err := io.WriteString(stdin, "go\n"); err != nil {
		t.Fatalf("release the client: %v", err)
	}
	select {
	case <-startDone:
	case <-time.After(15 * time.Second):
		t.Fatal("Start did not return after the client's ClientHello")
	}
	err = obs.TLSAttachError()
	if err == nil || !strings.Contains(err.Error(), "of the first TLS ClientHello") {
		t.Fatalf("TLSAttachError = %v, want the window's end after the ClientHello", err)
	}
	if err := obs.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if got := obs.CaptureCoverage().Content; got != models.ContentAttachFailed {
		t.Errorf("Content = %q, want %q", got, models.ContentAttachFailed)
	}
}

// TestObserver_ValidationWithoutClientHelloEndsAtStop: a tracked process that
// never begins a TLS connection keeps the candidate waiting, and Stop ends
// the validation with an error that says no ClientHello came (N-55).
func TestObserver_ValidationWithoutClientHelloEndsAtStop(t *testing.T) {
	skipUnprivileged(t)
	libssl := findLibSSL(t)
	obs, err := New(Config{ExePath: libssl, EventBufSize: 256, ValidationTimeout: 500 * time.Millisecond, CachePath: t.TempDir() + "/cache.json"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleep: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	if err := obs.TrackPID(int32(cmd.Process.Pid)); err != nil {
		t.Fatalf("TrackPID: %v", err)
	}
	go func() {
		for range obs.Events() {
		}
	}()
	startDone := make(chan struct{})
	go func() { obs.Start(); close(startDone) }()
	time.Sleep(2 * time.Second)
	select {
	case <-startDone:
		t.Fatalf("Start returned without a ClientHello: %v", obs.TLSAttachError())
	default:
	}
	if err := obs.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	select {
	case <-startDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after Stop")
	}
	if err := obs.TLSAttachError(); err == nil || !strings.Contains(err.Error(), "no tracked process sent a TLS ClientHello") {
		t.Fatalf("TLSAttachError = %v, want the stop without a ClientHello", err)
	}
}
