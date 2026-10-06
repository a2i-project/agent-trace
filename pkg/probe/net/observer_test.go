package net

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	stdnet "net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
)

func skipUnprivileged(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("requires root or CAP_BPF+CAP_PERFMON")
	}
}

// selfSignedCert generates a throwaway ECDSA certificate valid for the
// given hostname, for use by a local test-only TLS server. Not related to
// or reused by anything that talks to a real host.
func selfSignedCert(t *testing.T, host string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        cert,
	}
}

// startTLSServer starts a local TLS server on 127.0.0.1 that accepts
// connections, completes the handshake, and otherwise does nothing. It
// exists only to give an SNI-bearing ClientHello somewhere to be sent.
func startTLSServer(t *testing.T, host string) (addr string) {
	t.Helper()
	cert := selfSignedCert(t, host)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				tlsConn, ok := conn.(*tls.Conn)
				if !ok {
					return
				}
				_ = tlsConn.Handshake()
				buf := make([]byte, 4096)
				_, _ = tlsConn.Read(buf)
			}()
		}
	}()
	return ln.Addr().String()
}

func collect(obs *Observer) []models.GroundTruthEvent {
	var got []models.GroundTruthEvent
	for e := range obs.Events() {
		got = append(got, e)
	}
	return got
}

func TestObserver_CapturesSNIFromTrackedProcess(t *testing.T) {
	skipUnprivileged(t)

	const host = "agenttrace-test.internal"
	addr := startTLSServer(t, host)

	obs, err := New(Config{TrackedPID: int32(os.Getpid()), EventBufSize: 256})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	obs.Start()
	time.Sleep(150 * time.Millisecond) // let tracepoints attach

	start := time.Now()
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, //nolint:gosec // self-signed test cert, no real endpoint involved
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.Close()
	end := time.Now()

	time.Sleep(300 * time.Millisecond)
	if err := obs.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	got := collect(obs)

	var found *models.GroundTruthEvent
	for i := range got {
		if got[i].ActionType == models.NetConnect && got[i].Target == host {
			found = &got[i]
		}
	}
	if found == nil {
		t.Fatalf("no NetConnect event for host %q in %+v", host, got)
	}
	if found.Timestamp.Before(start.Add(-time.Second)) || found.Timestamp.After(end.Add(time.Second)) {
		t.Errorf("timestamp %v outside expected window [%v, %v]", found.Timestamp, start, end)
	}
}

func TestObserver_UntrackedProcessIsInvisible(t *testing.T) {
	skipUnprivileged(t)
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not available")
	}

	const host = "agenttrace-untracked.internal"
	addr := startTLSServer(t, host)

	// Track a decoy process, not our own PID -- the observer now propagates
	// tracked_pids to descendants on fork (task_newtask, for --fetch-via-curl
	// style subprocess tracking), so tracking our own PID would make the
	// openssl child below tracked too, defeating the point of this test.
	// The decoy has no relation to the openssl process spawned below, so
	// this still exercises the tracked_pids gate from the design doc
	// (section 4.1): a connection from a process outside the tracked set
	// and its descendants must never surface as a ground-truth event.
	decoy := exec.Command("sleep", "5")
	if err := decoy.Start(); err != nil {
		t.Fatalf("start decoy: %v", err)
	}
	t.Cleanup(func() { _ = decoy.Process.Kill() })

	obs, err := New(Config{TrackedPID: int32(decoy.Process.Pid), EventBufSize: 256})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	obs.Start()
	time.Sleep(150 * time.Millisecond)

	serverHost, port, err := stdnet.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	cmd := exec.Command("openssl", "s_client",
		"-connect", stdnet.JoinHostPort(serverHost, port),
		"-servername", host)
	cmd.Stdin = nil
	_ = cmd.Run() // exit status is irrelevant; we only care whether a connection was attempted

	time.Sleep(300 * time.Millisecond)
	if err := obs.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	got := collect(obs)
	for _, e := range got {
		if e.Target == host {
			t.Errorf("untracked process's connection to %q was observed: %+v", host, e)
		}
	}
}

// TestCoverage_UsesStopSnapshot checks that once Stop has snapshotted the
// kernel counters, Coverage reports the snapshot without touching the eBPF
// maps (which Stop has closed by then) and adds it to the userspace counts.
func TestCoverage_UsesStopSnapshot(t *testing.T) {
	o := &Observer{coverage: Coverage{Connections: 4, WithContent: 2}}
	o.finalFaulted.Store(3)
	o.finalRingbufDrops.Store(7)
	o.finalUntracked.Store(5)
	o.kernelCountersFinal.Store(true)

	got := o.Coverage()
	want := Coverage{Connections: 4, WithContent: 2, FaultedReads: 3, RingbufDrops: 7, UntrackedChildren: 5}
	if got != want {
		t.Errorf("Coverage() = %+v, want %+v", got, want)
	}
}

// TestObserver_CountsUntrackedChildren is the net probe's counterpart: a tiny
// tracked_pids map, more concurrently live children than it can hold, and the
// overflow must show in Coverage live and after Stop.
func TestObserver_CountsUntrackedChildren(t *testing.T) {
	skipUnprivileged(t)

	const capacity, children = 4, 24
	obs, err := New(Config{TrackedPID: int32(os.Getpid()), EventBufSize: 256, TrackedPIDsMax: capacity})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	obs.Start()
	time.Sleep(150 * time.Millisecond)

	var procs []*exec.Cmd
	for i := 0; i < children; i++ {
		c := exec.Command("/bin/sleep", "2")
		if err := c.Start(); err != nil {
			t.Fatalf("spawn sleep: %v", err)
		}
		procs = append(procs, c)
	}
	t.Cleanup(func() {
		for _, c := range procs {
			_ = c.Process.Kill()
			_ = c.Wait()
		}
	})
	time.Sleep(300 * time.Millisecond)

	live := obs.Coverage().UntrackedChildren
	if live < children-capacity+1 { // the root occupies one of the slots
		t.Errorf("UntrackedChildren while running = %d, want >= %d", live, children-capacity+1)
	}
	if err := obs.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if after := obs.Coverage().UntrackedChildren; after < live {
		t.Errorf("UntrackedChildren after Stop = %d, less than the %d read while running: the Stop snapshot was lost", after, live)
	}
	if got := obs.CaptureCoverage().UntrackedChildren; got == 0 {
		t.Error("CaptureCoverage().UntrackedChildren = 0, want the overflow reported")
	}
	for range obs.Events() {
	}
}

// TestObserver_NoUntrackedChildrenWhenMapFits is the control for the test
// above, against the default capacity.
func TestObserver_NoUntrackedChildrenWhenMapFits(t *testing.T) {
	skipUnprivileged(t)

	obs, err := New(Config{TrackedPID: int32(os.Getpid()), EventBufSize: 256})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	obs.Start()
	time.Sleep(150 * time.Millisecond)
	for i := 0; i < 24; i++ {
		if err := exec.Command("/bin/true").Run(); err != nil {
			t.Fatalf("spawn true: %v", err)
		}
	}
	time.Sleep(300 * time.Millisecond)
	if err := obs.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if got := obs.Coverage().UntrackedChildren; got != 0 {
		t.Errorf("UntrackedChildren = %d, want 0 with the default map capacity", got)
	}
	for range obs.Events() {
	}
}

func TestEmitListener(t *testing.T) {
	var v6 [16]byte
	v6[15] = 1
	tests := []struct {
		name    string
		typ     models.ActionType
		hdr     bpfNetEventHdr
		payload []byte
		target  string
	}{
		{"bind ipv4 loopback", models.NetBind, bpfNetEventHdr{Family: afInet, Port: 8080, Addr: [16]byte{127, 0, 0, 1}}, nil, "127.0.0.1:8080"},
		{"listen ipv4 wildcard", models.NetListen, bpfNetEventHdr{Family: afInet, Port: 9, Addr: [16]byte{}}, nil, "0.0.0.0:9"},
		{"listen ipv6 loopback", models.NetListen, bpfNetEventHdr{Family: afInet6, Port: 443, Addr: v6}, nil, "[::1]:443"},
		{"listen ipv6 wildcard", models.NetListen, bpfNetEventHdr{Family: afInet6, Port: 443}, nil, "[::]:443"},
		{"bind unix pathname", models.NetBind, bpfNetEventHdr{Family: afUnix}, []byte("/tmp/s.sock"), "unix:/tmp/s.sock"},
		{"listen unix abstract", models.NetListen, bpfNetEventHdr{Family: afUnix}, []byte("\x00agent"), "unix:@agent"},
		{"listen unix with unreadable name", models.NetListen, bpfNetEventHdr{Family: afUnix}, nil, "unix:<unknown>"},
		{"listen with no bound address", models.NetListen, bpfNetEventHdr{}, nil, models.UnboundListenTarget},
		{"bind port zero keeps the requested port", models.NetBind, bpfNetEventHdr{Family: afInet, Addr: [16]byte{10, 0, 0, 2}}, nil, "10.0.0.2:0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o := &Observer{events: make(chan models.GroundTruthEvent, 1)}
			ts := time.Unix(100, 0)
			o.emitListener(tc.typ, tc.hdr, tc.payload, ts)
			select {
			case e := <-o.events:
				if e.ActionType != tc.typ || e.Target != tc.target || !e.Timestamp.Equal(ts) {
					t.Errorf("event = %+v, want %s %q at %v", e, tc.typ, tc.target, ts)
				}
				if e.IsTopLevel != nil {
					t.Errorf("IsTopLevel = %v, want nil: the net probe assigns no level", *e.IsTopLevel)
				}
			default:
				t.Fatal("no event emitted")
			}
		})
	}
}

func TestEmitListener_FullChannelCountsDrop(t *testing.T) {
	o := &Observer{events: make(chan models.GroundTruthEvent)} // unbuffered, nobody reading
	o.emitListener(models.NetListen, bpfNetEventHdr{Family: afInet, Port: 1}, nil, time.Now())
	if got := o.Dropped(); got != 1 {
		t.Errorf("Dropped = %d, want 1: a lost listener event must be counted", got)
	}
}

// drainEvents stops the observer and returns every event it emitted.
func drainEvents(t *testing.T, obs *Observer) []models.GroundTruthEvent {
	t.Helper()
	if err := obs.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	return collect(obs)
}

// freePort returns a TCP port that was free a moment ago on 127.0.0.1.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := stdnet.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*stdnet.TCPAddr).Port
}

func listenerTargets(events []models.GroundTruthEvent, at models.ActionType) []string {
	var out []string
	for _, e := range events {
		if e.ActionType == at {
			out = append(out, e.Target)
		}
	}
	return out
}

// TestObserver_ObservesListeners checks bind and listen from the tracked
// process itself, with an exposure distinction between a loopback and a
// wildcard listener, and the bind-to-listen address join.
func TestObserver_ObservesListeners(t *testing.T) {
	skipUnprivileged(t)

	loPort, anyPort := freePort(t), freePort(t)
	obs, err := New(Config{TrackedPID: int32(os.Getpid()), EventBufSize: 256})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	obs.Start()
	time.Sleep(150 * time.Millisecond)

	lo, err := stdnet.Listen("tcp4", stdnet.JoinHostPort("127.0.0.1", strconv.Itoa(loPort)))
	if err != nil {
		t.Fatalf("listen loopback: %v", err)
	}
	defer func() { _ = lo.Close() }()
	wild, err := stdnet.Listen("tcp4", stdnet.JoinHostPort("0.0.0.0", strconv.Itoa(anyPort)))
	if err != nil {
		t.Fatalf("listen wildcard: %v", err)
	}
	defer func() { _ = wild.Close() }()
	time.Sleep(300 * time.Millisecond)

	events := drainEvents(t, obs)
	wantLo := "127.0.0.1:" + strconv.Itoa(loPort)
	wantAny := "0.0.0.0:" + strconv.Itoa(anyPort)
	for _, at := range []models.ActionType{models.NetBind, models.NetListen} {
		got := listenerTargets(events, at)
		for _, want := range []string{wantLo, wantAny} {
			if !slices.Contains(got, want) {
				t.Errorf("%s targets = %v, missing %s", at, got, want)
			}
		}
	}
	if models.ClassifyBindTarget(wantLo) == models.ClassifyBindTarget(wantAny) {
		t.Error("loopback and wildcard listeners classified identically")
	}
}

// TestObserver_ListenersFromChildAreVisible covers the acceptance case: a
// listener opened by a descendant of the tracked process. The script also
// closes a bound fd and then listens on a fresh unbound socket that reuses the
// fd number, which must report an unknown address: a stale bind record
// attributing the old address to the new socket would be a wrong event.
func TestObserver_ListenersFromChildAreVisible(t *testing.T) {
	skipUnprivileged(t)
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}

	// Reserved before the observer starts: the reservation is itself a
	// listener in the tracked process and would pollute the events.
	port := freePort(t)
	obs, err := New(Config{TrackedPID: int32(os.Getpid()), EventBufSize: 256})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	obs.Start()
	time.Sleep(150 * time.Millisecond)

	script := fmt.Sprintf(`
import socket
a = socket.socket()
a.bind(('127.0.0.1', %d))
a.listen(1)
fd = a.fileno()
a.close()
b = socket.socket()
assert b.fileno() == fd, 'fd was not reused, the test cannot check stale state'
b.listen(1)
b.close()
`, port)
	if out, err := exec.Command(py, "-c", script).CombinedOutput(); err != nil {
		t.Fatalf("python listener: %v\n%s", err, out)
	}
	time.Sleep(300 * time.Millisecond)

	events := drainEvents(t, obs)
	want := "127.0.0.1:" + strconv.Itoa(port)
	if got := listenerTargets(events, models.NetBind); !slices.Equal(got, []string{want}) {
		t.Errorf("bind targets = %v, want [%s]", got, want)
	}
	got := listenerTargets(events, models.NetListen)
	if !slices.Equal(got, []string{want, models.UnboundListenTarget}) {
		t.Errorf("listen targets = %v, want [%s %s] in order", got, want, models.UnboundListenTarget)
	}
}

// TestObserver_UntrackedListenerIsInvisible is the gate control: a listener
// outside the tracked set must not surface.
func TestObserver_UntrackedListenerIsInvisible(t *testing.T) {
	skipUnprivileged(t)

	decoy := exec.Command("sleep", "5")
	if err := decoy.Start(); err != nil {
		t.Fatalf("start decoy: %v", err)
	}
	t.Cleanup(func() { _ = decoy.Process.Kill(); _ = decoy.Wait() })

	obs, err := New(Config{TrackedPID: int32(decoy.Process.Pid), EventBufSize: 256})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	obs.Start()
	time.Sleep(150 * time.Millisecond)

	l, err := stdnet.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = l.Close() }()
	time.Sleep(300 * time.Millisecond)

	for _, e := range drainEvents(t, obs) {
		if e.ActionType == models.NetBind || e.ActionType == models.NetListen {
			t.Errorf("untracked process's listener was observed: %+v", e)
		}
	}
}

func TestUnixTarget(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		want    string
	}{
		{"pathname", []byte("/var/run/docker.sock"), "unix:/var/run/docker.sock"},
		{"relative pathname is kept as written", []byte("docker.sock"), "unix:docker.sock"},
		{"abstract", []byte("\x00systemd-private"), "unix:@systemd-private"},
		{"abstract with embedded NUL is escaped, not truncated", []byte("\x00a\x00b"), `unix:@a\x00b`},
		{"abstract with newline stays one line", []byte("\x00a\nb"), `unix:@a\nb`},
		{"lone NUL is the empty abstract name", []byte("\x00"), "unix:@"},
		{"unreadable name", nil, "unix:<unknown>"},
	}
	for _, tc := range tests {
		if got := unixTarget(tc.payload); got != tc.want {
			t.Errorf("%s: unixTarget(%q) = %q, want %q", tc.name, tc.payload, got, tc.want)
		}
	}
}

func TestEmitUnixConnect(t *testing.T) {
	o := &Observer{events: make(chan models.GroundTruthEvent, 2)}
	o.handleNetRecord(netRecord{hdr: bpfNetEventHdr{Type: netUnixConnect, Family: afUnix}, payload: []byte("/run/docker.sock")})
	e := <-o.events
	if e.ActionType != models.NetUnixConnect || e.Target != "unix:/run/docker.sock" {
		t.Errorf("event = %+v", e)
	}
	if e.ActionType.IsClaimable() {
		t.Error("a unix connect must not be claimable")
	}
	if o.coverage.Connections != 0 {
		t.Errorf("Connections = %d: a unix connect is not a TLS connection and must not skew the TLS coverage ratios", o.coverage.Connections)
	}
}

// runPython runs a script with python3, skipping the test when it is absent.
func runPython(t *testing.T, script string) {
	t.Helper()
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	if out, err := exec.Command(py, "-c", script).CombinedOutput(); err != nil {
		t.Fatalf("python: %v\n%s", err, out)
	}
}

// TestObserver_ObservesUnixSockets covers the acceptance cases of item 5 part
// 2: a command in the tracked tree connects to a Unix socket and the event
// carries the socket path, for a pathname socket, an abstract socket, and a
// connect that fails because nothing listens (an attempt, like execve). It
// also checks the AF_UNIX bind and listen events of a socket server.
func TestObserver_ObservesUnixSockets(t *testing.T) {
	skipUnprivileged(t)

	dir := t.TempDir()
	sock := filepath.Join(dir, "s.sock")
	missing := filepath.Join(dir, "no-daemon.sock")
	abstract := fmt.Sprintf("agenttrace-%d", time.Now().UnixNano())

	obs, err := New(Config{TrackedPID: int32(os.Getpid()), EventBufSize: 256})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	obs.Start()
	time.Sleep(150 * time.Millisecond)

	runPython(t, fmt.Sprintf(`
import socket
srv = socket.socket(socket.AF_UNIX)
srv.bind(%q)
srv.listen(1)
c = socket.socket(socket.AF_UNIX)
c.connect(%q)
c.close()
srv.close()
asrv = socket.socket(socket.AF_UNIX)
asrv.bind('\0' + %q)
asrv.listen(1)
ac = socket.socket(socket.AF_UNIX)
ac.connect('\0' + %q)
ac.close()
asrv.close()
m = socket.socket(socket.AF_UNIX)
try:
    m.connect(%q)
except OSError:
    pass
`, sock, sock, abstract, abstract, missing))
	time.Sleep(300 * time.Millisecond)

	events := drainEvents(t, obs)
	pathT, absT, missT := "unix:"+sock, "unix:@"+abstract, "unix:"+missing
	if got := listenerTargets(events, models.NetUnixConnect); !slices.Equal(got, []string{pathT, absT, missT}) {
		t.Errorf("unix connect targets = %v, want [%s %s %s] in order", got, pathT, absT, missT)
	}
	for _, at := range []models.ActionType{models.NetBind, models.NetListen} {
		if got := listenerTargets(events, at); !slices.Equal(got, []string{pathT, absT}) {
			t.Errorf("%s targets = %v, want [%s %s]", at, got, pathT, absT)
		}
	}
	if models.ClassifyBindTarget(pathT) != models.ExposureLocalSocket {
		t.Errorf("exposure of %s = %s", pathT, models.ClassifyBindTarget(pathT))
	}
}

// TestObserver_UntrackedUnixConnectIsInvisible is the gate control.
func TestObserver_UntrackedUnixConnectIsInvisible(t *testing.T) {
	skipUnprivileged(t)

	decoy := exec.Command("sleep", "5")
	if err := decoy.Start(); err != nil {
		t.Fatalf("start decoy: %v", err)
	}
	t.Cleanup(func() { _ = decoy.Process.Kill(); _ = decoy.Wait() })

	obs, err := New(Config{TrackedPID: int32(decoy.Process.Pid), EventBufSize: 256})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	obs.Start()
	time.Sleep(150 * time.Millisecond)

	runPython(t, `
import socket
s = socket.socket(socket.AF_UNIX)
try:
    s.connect('/run/agenttrace-nobody-listens.sock')
except OSError:
    pass
`)
	time.Sleep(300 * time.Millisecond)
	for _, e := range drainEvents(t, obs) {
		if e.ActionType == models.NetUnixConnect {
			t.Errorf("untracked process's unix connect was observed: %+v", e)
		}
	}
}
