package net

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	stdnet "net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// wsExClient is a WebSocket client over the system libssl's SSL_write_ex
// and SSL_read_ex, loaded with dlopen so that no OpenSSL headers are
// needed. After a byte on stdin it connects, sends the upgrade request for
// the path given, reads the 101 head and the server's first frame, sends
// one masked text frame with the message given, reads the server's reply
// frame and close frame, and sends a masked close frame.
const wsExClient = `
#include <arpa/inet.h>
#include <dlfcn.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define SSL_CTRL_SET_TLSEXT_HOSTNAME 55

static void *sym(void *h, const char *name) {
	void *p = dlsym(h, name);
	if (!p) { fprintf(stderr, "dlsym %s: %s\n", name, dlerror()); exit(3); }
	return p;
}

static int (*rd)(void *, void *, size_t, size_t *);
static int (*wr)(void *, const void *, size_t, size_t *);

static void read_n(void *ssl, char *buf, size_t want, size_t *have) {
	while (*have < want) {
		size_t n = 0;
		if (rd(ssl, buf + *have, want - *have, &n) != 1) { fprintf(stderr, "SSL_read_ex failed\n"); exit(8); }
		*have += n;
	}
}

static void write_all(void *ssl, const char *p, size_t n) {
	while (n > 0) {
		size_t w = 0;
		if (wr(ssl, p, n, &w) != 1) { fprintf(stderr, "SSL_write_ex failed\n"); exit(7); }
		p += w; n -= w;
	}
}

int main(int argc, char **argv) {
	if (argc != 6) return 2;
	void *h = dlopen(argv[1], RTLD_NOW);
	if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 3; }
	const void *(*client_method)(void) = sym(h, "TLS_client_method");
	void *(*ctx_new)(const void *) = sym(h, "SSL_CTX_new");
	void *(*ssl_new)(void *) = sym(h, "SSL_new");
	int (*set_fd)(void *, int) = sym(h, "SSL_set_fd");
	int (*ssl_connect)(void *) = sym(h, "SSL_connect");
	long (*ssl_ctrl)(void *, int, long, void *) = sym(h, "SSL_ctrl");
	rd = sym(h, "SSL_read_ex");
	wr = sym(h, "SSL_write_ex");

	char c;
	if (read(0, &c, 1) != 1) return 4;
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	sa.sin_port = htons(atoi(argv[2]));
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (connect(fd, (struct sockaddr *)&sa, sizeof sa)) { perror("connect"); return 5; }
	void *ssl = ssl_new(ctx_new(client_method()));
	set_fd(ssl, fd);
	ssl_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, 0, argv[3]);
	if (ssl_connect(ssl) != 1) { fprintf(stderr, "SSL_connect failed\n"); return 6; }

	char req[1024];
	int n = snprintf(req, sizeof req, "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", argv[4], argv[3]);
	write_all(ssl, req, n);

	char buf[4096];
	size_t have = 0;
	char *end = NULL;
	while (!end) {
		read_n(ssl, buf, have + 1, &have);
		buf[have] = 0;
		end = strstr(buf, "\r\n\r\n");
	}
	size_t head = (end - buf) + 4;
	read_n(ssl, buf, head + 2, &have);
	read_n(ssl, buf, head + 2 + (unsigned char)buf[head + 1], &have);

	const char *msg = argv[5];
	size_t ml = strlen(msg);
	unsigned char frame[200];
	unsigned char key[4] = {1, 2, 3, 4};
	frame[0] = 0x81; frame[1] = 0x80 | (unsigned char)ml;
	memcpy(frame + 2, key, 4);
	for (size_t i = 0; i < ml; i++) frame[6 + i] = msg[i] ^ key[i % 4];
	write_all(ssl, (char *)frame, 6 + ml);

	have = 0;
	read_n(ssl, buf, 2, &have);
	read_n(ssl, buf, 2 + (unsigned char)buf[1] + 2, &have);
	unsigned char closef[6] = {0x88, 0x80, 1, 2, 3, 4};
	write_all(ssl, (char *)closef, 6);
	return 0;
}
`

// startWSTLSServer accepts one WebSocket client: it reads the upgrade
// request head, answers 101 with a first text frame in the same write,
// reads the client's masked frame, answers a text frame and a close frame,
// waits up to two seconds for the client's close frame and closes.
func startWSTLSServer(t *testing.T, host string) (port string) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t, host)}})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		r := bufio.NewReader(conn)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		_, _ = conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n\x81\x05hello"))
		hdr := make([]byte, 6)
		if _, err := io.ReadFull(r, hdr); err != nil {
			return
		}
		if _, err := io.ReadFull(r, make([]byte, int(hdr[1]&0x7f))); err != nil {
			return
		}
		_, _ = conn.Write([]byte("\x81\x05world\x88\x00"))
		// The client's close frame, if it sends one, then the close.
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = io.ReadFull(r, make([]byte, 6))
	}()
	_, port, _ = stdnet.SplitHostPort(ln.Addr().String())
	return port
}

// wsEventShape is what checkWSSession compares of each event.
type wsEventShape struct {
	Type   models.ActionType
	Target string
	Hash   string
	Status int
	WS     *models.WebSocketSummary
}

// checkWSSession requires the events of the session startWSTLSServer
// serves: the upgrade request and its 101, the server's first message as a
// turn, the client's message as a WS request with its hash, and the
// server's reply as a turn ended by the close.
func checkWSSession(t *testing.T, evs []models.GroundTruthEvent, hostPort, path, msg string) {
	t.Helper()
	var got []wsEventShape
	for _, e := range evs {
		if e.ActionType != models.NetRequest && e.ActionType != models.NetResponse {
			continue
		}
		s := wsEventShape{Type: e.ActionType, Target: e.Target}
		if e.RequestHash != nil {
			s.Hash = *e.RequestHash
		}
		if e.Response != nil {
			s.Status = e.Response.Status
			s.WS = e.Response.WebSocket
		}
		got = append(got, s)
	}
	host, port := hostPort, 0
	if h, p, err := stdnet.SplitHostPort(hostPort); err == nil {
		host = h
		if n, err := parsePort(p); err == nil {
			port = n
		}
	}
	p, q, _ := strings.Cut(path, "?")
	get := models.CanonicalNetTarget("GET", host, port, p, q)
	ws := models.CanonicalNetTarget("WS", host, port, p, q)
	one := func(name string) *models.WebSocketSummary {
		return &models.WebSocketSummary{Messages: 1, Types: map[string]int{name: 1}}
	}
	want := []wsEventShape{
		{Type: models.NetRequest, Target: get},
		{Type: models.NetResponse, Target: get, Status: 101},
		{Type: models.NetResponse, Target: ws, Status: 101, WS: one("(text)")},
		{Type: models.NetRequest, Target: ws, Hash: hashOf(msg)},
		{Type: models.NetResponse, Target: ws, Status: 101, WS: one("(text)")},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("events:\n%+v\nwant\n%+v", got, want)
	}
}

// runContentSession tracks the client cmd (which waits for a byte on
// stdin), starts the observer, lets the client run to its end, stops and
// returns the events.
func runContentSession(t *testing.T, obs *Observer, cmd *exec.Cmd) []models.GroundTruthEvent {
	t.Helper()
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start client: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	if err := obs.TrackPID(int32(cmd.Process.Pid)); err != nil {
		t.Fatalf("TrackPID: %v", err)
	}
	var evs []models.GroundTruthEvent
	done := make(chan struct{})
	go func() {
		defer close(done)
		for e := range obs.Events() {
			evs = append(evs, e)
		}
	}()
	if _, err := stdin.Write([]byte("a")); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	go func() { obs.Start(); close(started) }()
	select {
	case <-started:
	case <-time.After(30 * time.Second):
		t.Fatal("Observer.Start did not return")
	}
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	select {
	case err := <-waited:
		if err != nil {
			t.Fatalf("client: %v\n%s", err, stderr.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("client did not finish\n%s", stderr.String())
	}
	if err := obs.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	<-done
	return evs
}

// buildWSExClient compiles wsExClient, or skips the test when no C
// compiler is installed.
func buildWSExClient(t *testing.T) string {
	t.Helper()
	var cc string
	for _, c := range []string{"cc", "gcc", "clang"} {
		if p, err := exec.LookPath(c); err == nil {
			cc = p
			break
		}
	}
	if cc == "" {
		t.Skip("no C compiler to build the SSL_write_ex client")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "client.c")
	if err := os.WriteFile(src, []byte(wsExClient), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "client")
	if out, err := exec.Command(cc, "-O1", "-o", bin, src, "-ldl").CombinedOutput(); err != nil {
		t.Fatalf("build the client: %v\n%s", err, out)
	}
	return bin
}

// TestWSExClient_CompletesItsSession runs the SSL_write_ex client against
// the test server without the probe, unprivileged, so that a failure of
// the privileged test below is the probe's and not the session's.
func TestWSExClient_CompletesItsSession(t *testing.T) {
	libssl := findLibSSL(t)
	bin := buildWSExClient(t)
	const host = "agenttrace-ws-ex.internal"
	port := startWSTLSServer(t, host)
	cmd := exec.Command(bin, libssl, port, host, "/ws", "hi")
	cmd.Stdin = strings.NewReader("a")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("client: %v\n%s", err, out)
	}
}

// TestObserver_OpenSSLExWebSocket runs tls-openssl-ex (N-39) on the system
// libssl, located by its SSL_write_ex and SSL_read_ex symbols, with a
// client that writes and reads only through them, and requires the
// WebSocket session parsed from the captured plaintext (N-41).
func TestObserver_OpenSSLExWebSocket(t *testing.T) {
	skipUnprivileged(t)
	libssl := findLibSSL(t)
	bin := buildWSExClient(t)

	const host = "agenttrace-ws-ex.internal"
	port := startWSTLSServer(t, host)
	obs, err := New(Config{Content: []ContentMethod{{Method: MethodOpenSSLEx, Path: libssl}}, EventBufSize: 4096, ValidationTimeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const path, msg = "/ws?t=1", `{"type":"response.create"}`
	evs := runContentSession(t, obs, exec.Command(bin, libssl, port, host, path, msg))
	if err := obs.TLSAttachError(); err != nil {
		t.Fatalf("TLSAttachError: %v", err)
	}
	checkWSSession(t, evs, host, path, msg)
	cov := obs.CaptureCoverage()
	if cov.Content != models.ContentActive || cov.Responses != models.ContentActive {
		t.Errorf("content %s responses %s, want active", cov.Content, cov.Responses)
	}
	if c := obs.Coverage(); c.WSRequests != 1 || c.WSServerMessages != 2 || c.FaultedReads != 0 || c.ReadFaults != 0 {
		t.Errorf("coverage %+v", c)
	}
}

// TestRustlsClient_CompletesItsSession runs the client
// AGENT_TRACE_RUSTLS_CLIENT names against the test server without the
// probe, unprivileged; skipped without it.
func TestRustlsClient_CompletesItsSession(t *testing.T) {
	client := os.Getenv("AGENT_TRACE_RUSTLS_CLIENT")
	if client == "" {
		t.Skip("AGENT_TRACE_RUSTLS_CLIENT not set")
	}
	port := startWSTLSServer(t, "localhost")
	if out, err := exec.Command(client, port, "hello").CombinedOutput(); err != nil {
		t.Fatalf("client: %v\n%s", err, out)
	}
}

// TestObserver_RustlsAEADWebSocket runs tls-rustls-aead (N-39, N-40) on a
// rustls client named by AGENT_TRACE_RUSTLS_CLIENT, and is skipped without
// one. The client is testdata/rustls-client, which CI builds with cargo
// (its crates downloaded at the build, pinned by Cargo.lock). It takes the port and a message, connects to 127.0.0.1 with the name
// localhost, accepts any certificate, sends the upgrade request for /ws?x=1
// with Host localhost:PORT, reads the 101 head, sends one masked text frame
// with the message, and reads to the end of the connection.
func TestObserver_RustlsAEADWebSocket(t *testing.T) {
	skipUnprivileged(t)
	client := os.Getenv("AGENT_TRACE_RUSTLS_CLIENT")
	if client == "" {
		t.Skip("AGENT_TRACE_RUSTLS_CLIENT not set")
	}
	port := startWSTLSServer(t, "localhost")
	obs, err := New(Config{Content: []ContentMethod{{Method: MethodRustlsAEAD, Path: client}}, EventBufSize: 4096})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const msg = "hello"
	// The shell waits for the byte, then becomes the client (same pid).
	cmd := exec.Command("sh", "-c", `read x; exec "$0" "$1" "$2"`, client, port, msg)
	evs := runContentSession(t, obs, cmd)
	checkWSSession(t, evs, "localhost:"+port, "/ws?x=1", msg)
	cov := obs.CaptureCoverage()
	if cov.Content != models.ContentActive || cov.Responses != models.ContentActive {
		t.Errorf("content %s responses %s, want active", cov.Content, cov.Responses)
	}
	if c := obs.Coverage(); c.AEADUnbound != 0 || c.AEADUnpaired != 0 || c.AEADRebound != 0 || c.AEADUnvalidated != 0 || c.AEADRingDrops != 0 {
		t.Errorf("coverage %+v", c)
	}
}
