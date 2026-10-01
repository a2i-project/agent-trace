package net

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	stdnet "net"
	"os"
	"os/exec"
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
	o.kernelCountersFinal.Store(true)

	got := o.Coverage()
	want := Coverage{Connections: 4, WithContent: 2, FaultedReads: 3, RingbufDrops: 7}
	if got != want {
		t.Errorf("Coverage() = %+v, want %+v", got, want)
	}
}
