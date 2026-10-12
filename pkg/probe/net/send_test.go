package net

import (
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	stdnet "net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/tlsparse"
)

// Tests for the send side of a connection (N-23) and its socket keying
// (N-24). The privileged ones run a scripted process in the tracked tree that
// sends only through one path, with a connection that sends nothing as the
// control in the same run.

// sinks starts n TCP listeners on 127.0.0.1 that accept and discard whatever
// they receive, and returns their ports.
func sinks(t *testing.T, n int) []int {
	t.Helper()
	var ports []int
	for i := 0; i < n; i++ {
		ln, err := stdnet.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer func() { _ = c.Close() }()
					_, _ = io.Copy(io.Discard, c)
				}()
			}
		}()
		ports = append(ports, ln.Addr().(*stdnet.TCPAddr).Port)
	}
	return ports
}

// startObserver tracks the test process, so every process the test starts is
// in the tracked tree.
func startObserver(t *testing.T) *Observer {
	t.Helper()
	obs, err := New(Config{TrackedPID: int32(os.Getpid()), EventBufSize: 256})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	obs.Start()
	time.Sleep(150 * time.Millisecond) // let tracepoints attach
	return obs
}

// typeOf returns the action type of the one event with the given target, or
// "" when there is none, and fails when there are several.
func typeOf(t *testing.T, events []models.GroundTruthEvent, target string) (models.ActionType, uint32) {
	t.Helper()
	var at models.ActionType
	var pid uint32
	n := 0
	for _, e := range events {
		if e.Target == target {
			at, pid = e.ActionType, e.PID
			n++
		}
	}
	if n > 1 {
		t.Errorf("%d events for %s, want one", n, target)
	}
	return at, pid
}

// expectTypes checks the action type and PID of the event for each port.
func expectTypes(t *testing.T, events []models.GroundTruthEvent, pid uint32, want map[int]models.ActionType, why map[int]string) {
	t.Helper()
	for port, at := range want {
		target := fmt.Sprintf("127.0.0.1:%d", port)
		got, gotPID := typeOf(t, events, target)
		if got != at {
			t.Errorf("%s (%s) is %q, want %q", target, why[port], got, at)
			continue
		}
		if gotPID != pid {
			t.Errorf("%s (%s) has PID %d, want the connecting process %d", target, why[port], gotPID, pid)
		}
	}
}

// TestObserver_SendsWithoutWriteAreConnections: a connection by address that
// sends only through writev, only through sendfile or only through splice
// carried data, so it is net_connect, not net_dial. A connection that sends
// nothing is the control and stays net_dial (N-22).
func TestObserver_SendsWithoutWriteAreConnections(t *testing.T) {
	skipUnprivileged(t)

	ports := sinks(t, 4)
	file := filepath.Join(t.TempDir(), "payload")
	if err := os.WriteFile(file, []byte("sent by sendfile"), 0o600); err != nil {
		t.Fatal(err)
	}
	obs := startObserver(t)

	pyPID := runPython(t, fmt.Sprintf(`
import os, socket
def conn(port):
    s = socket.socket()
    s.connect(("127.0.0.1", port))
    return s
s = conn(%d)
os.writev(s.fileno(), [b"only ", b"writev"])
s.close()
s = conn(%d)
with open(%q, "rb") as f:
    os.sendfile(s.fileno(), f.fileno(), 0, 16)
s.close()
r, w = os.pipe()
os.write(w, b"spliced")
s = conn(%d)
os.splice(r, s.fileno(), 7)
s.close()
s = conn(%d)
s.close()
`, ports[0], ports[1], file, ports[2], ports[3]))
	time.Sleep(300 * time.Millisecond)

	events := drainEvents(t, obs)
	expectTypes(t, events, pyPID,
		map[int]models.ActionType{ports[0]: models.NetConnect, ports[1]: models.NetConnect, ports[2]: models.NetConnect, ports[3]: models.NetDial},
		map[int]string{ports[0]: "writev", ports[1]: "sendfile", ports[2]: "splice", ports[3]: "nothing sent"})
}

// clientHello returns the first TLS record a Go client sends for host: a
// ClientHello with an SNI extension. X25519 alone keeps it small, so the
// whole extension block fits in the probe's 1024-byte capture.
func clientHello(t *testing.T, host string) []byte {
	t.Helper()
	c1, c2 := stdnet.Pipe()
	defer func() { _ = c1.Close(); _ = c2.Close() }()
	go func() {
		_ = tls.Client(c1, &tls.Config{
			ServerName:         host,
			CurvePreferences:   []tls.CurveID{tls.X25519},
			InsecureSkipVerify: true, //nolint:gosec // the handshake never completes; only its first record is used
		}).Handshake()
	}()
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(c2, hdr); err != nil {
		t.Fatalf("read record header: %v", err)
	}
	body := make([]byte, int(hdr[3])<<8|int(hdr[4]))
	if _, err := io.ReadFull(c2, body); err != nil {
		t.Fatalf("read record body: %v", err)
	}
	hello := append(hdr, body...)
	if len(hello) > 1024 {
		t.Fatalf("ClientHello is %d bytes, more than the 1024-byte capture", len(hello))
	}
	if h, err := tlsparse.ParseClientHello(hello); err != nil || h.ServerName != host {
		t.Fatalf("ParseClientHello = %+v, %v; want SNI %s", h, err, host)
	}
	return hello
}

// TestObserver_HelloAcrossIovecsYieldsSNI: a ClientHello split across the
// iovecs of a writev and of a two-iovec sendmsg yields its SNI name. The first
// iovec holds only the record header, so a capture of the first iovec alone
// has no name.
func TestObserver_HelloAcrossIovecsYieldsSNI(t *testing.T) {
	skipUnprivileged(t)

	const viaWritev, viaSendmsg = "writev.agenttrace-test.internal", "sendmsg.agenttrace-test.internal"
	hw, hs := clientHello(t, viaWritev), clientHello(t, viaSendmsg)
	ports := sinks(t, 2)
	obs := startObserver(t)

	pyPID := runPython(t, fmt.Sprintf(`
import os, socket
hw = bytes.fromhex(%q)
hs = bytes.fromhex(%q)
s = socket.socket()
s.connect(("127.0.0.1", %d))
os.writev(s.fileno(), [hw[:5], hw[5:40], hw[40:]])
s.close()
s = socket.socket()
s.connect(("127.0.0.1", %d))
s.sendmsg([hs[:5], hs[5:]])
s.close()
`, hex.EncodeToString(hw), hex.EncodeToString(hs), ports[0], ports[1]))
	time.Sleep(300 * time.Millisecond)

	events := drainEvents(t, obs)
	for _, host := range []string{viaWritev, viaSendmsg} {
		at, pid := typeOf(t, events, host)
		if at != models.NetConnect || pid != pyPID {
			t.Errorf("event for %s is %q from PID %d, want net_connect from %d; events %+v", host, at, pid, pyPID, events)
		}
	}
}

// TestObserver_ForkedChildWriteMarksConnection: a shell connects through
// /dev/tcp and a forked cat writes the data, so the process that connected
// never writes. The connection is net_connect, attributed to the shell. A
// second /dev/tcp connection that nothing writes is the control.
func TestObserver_ForkedChildWriteMarksConnection(t *testing.T) {
	skipUnprivileged(t)
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}

	ports := sinks(t, 2)
	file := filepath.Join(t.TempDir(), "payload")
	if err := os.WriteFile(file, []byte("written by the child\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	obs := startObserver(t)

	script := fmt.Sprintf(`exec 3<>/dev/tcp/127.0.0.1/%d
cat %q >&3
exec 3>&-
exec 4<>/dev/tcp/127.0.0.1/%d
exec 4>&-
`, ports[0], file, ports[1])
	cmd := exec.Command(bash, "-c", script)
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatalf("bash: %v", err)
	}
	shPID := uint32(cmd.Process.Pid)
	if err := cmd.Wait(); err != nil {
		t.Fatalf("bash: %v\n%s", err, out.String())
	}
	time.Sleep(300 * time.Millisecond)

	events := drainEvents(t, obs)
	expectTypes(t, events, shPID,
		map[int]models.ActionType{ports[0]: models.NetConnect, ports[1]: models.NetDial},
		map[int]string{ports[0]: "written by a forked cat", ports[1]: "nothing sent"})
}

// TestObserver_SCMRightsReceiverWriteMarksConnection: a process connects,
// passes the descriptor over a Unix socket to a process that did not inherit
// it, and closes its own copy before the receiver writes. The receiver's
// write marks the connection, which ends at the receiver's close and is
// net_connect, attributed to the process that connected. A second passed
// connection the receiver only closes is the control.
func TestObserver_SCMRightsReceiverWriteMarksConnection(t *testing.T) {
	skipUnprivileged(t)

	ports := sinks(t, 2)
	obs := startObserver(t)

	pyPID := runPython(t, fmt.Sprintf(`
import os, socket
parent, child = socket.socketpair()
pid = os.fork()
if pid == 0:
    parent.close()
    _, fds, _, _ = socket.recv_fds(child, 16, 2)
    child.recv(2)  # the sender has closed its copies
    os.write(fds[0], b"written by the receiver")
    os.close(fds[0])
    os.close(fds[1])
    os._exit(0)
child.close()
written = socket.socket()
written.connect(("127.0.0.1", %d))
idle = socket.socket()
idle.connect(("127.0.0.1", %d))
socket.send_fds(parent, [b"fd"], [written.fileno(), idle.fileno()])
written.close()
idle.close()
parent.send(b"go")
_, status = os.waitpid(pid, 0)
if status != 0:
    raise SystemExit("receiver failed")
`, ports[0], ports[1]))
	time.Sleep(300 * time.Millisecond)

	events := drainEvents(t, obs)
	expectTypes(t, events, pyPID,
		map[int]models.ActionType{ports[0]: models.NetConnect, ports[1]: models.NetDial},
		map[int]string{ports[0]: "written by the SCM_RIGHTS receiver", ports[1]: "passed, nothing sent"})
	if c := obs.Coverage(); c.OpenAtStop != 0 {
		t.Errorf("OpenAtStop = %d, want 0: both connections end at the receiver's close", c.OpenAtStop)
	}
}

// Userspace half: records about one socket may come from any process holding
// it. A NET_SEND or NET_HELLO from another tgid marks the connection written,
// a close from another tgid ends it, and the event carries the PID of the
// process that connected. A connection that only another process closed,
// with nothing sent, stays a dial.
func TestHandleNetRecord_RecordsFromAnotherProcessFollowTheSocket(t *testing.T) {
	const host = "child.agenttrace-test.internal"
	hello := clientHello(t, host)
	o := &Observer{events: make(chan models.GroundTruthEvent, 8), conns: map[uint64]*connection{}}
	v4 := [16]byte{192, 0, 2, 9}
	rec := func(typ uint8, tgid uint32, sock uint64, port uint16, payload []byte) netRecord {
		return netRecord{hdr: bpfNetEventHdr{Type: typ, Tgid: tgid, Fd: 1, Sock: sock, Family: afInet, Addr: v4, Port: port, TsNs: 1}, payload: payload}
	}
	o.handleNetRecord(rec(netConnect, 7, 100, 8080, nil))
	o.handleNetRecord(rec(netSend, 8, 100, 8080, nil)) // a child's sendfile
	o.handleNetRecord(rec(netClose, 8, 100, 8080, nil))
	o.handleNetRecord(rec(netConnect, 7, 200, 443, nil))
	o.handleNetRecord(rec(netHello, 9, 200, 443, hello)) // a receiver's write
	o.handleNetRecord(rec(netClose, 9, 200, 443, nil))
	o.handleNetRecord(rec(netConnect, 7, 300, 9090, nil))
	o.handleNetRecord(rec(netClose, 8, 300, 9090, nil)) // closed elsewhere, never written
	o.handleNetRecord(rec(netSend, 8, 999, 9090, nil))  // a socket never connected: ignored
	close(o.events)
	var got []string
	for e := range o.events {
		got = append(got, fmt.Sprintf("%s %s %d", e.ActionType, e.Target, e.PID))
	}
	want := []string{"net_connect 192.0.2.9:8080 7", "net_connect " + host + " 7", "net_dial 192.0.2.9:9090 7"}
	if !slices.Equal(got, want) {
		t.Errorf("emitted %v, want %v", got, want)
	}
	if o.coverage.Dials != 1 || o.coverage.WithHostname != 1 || len(o.conns) != 0 {
		t.Errorf("coverage = %+v, %d open, want Dials 1, WithHostname 1, none open", o.coverage, len(o.conns))
	}
}
