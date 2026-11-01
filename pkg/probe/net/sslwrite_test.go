package net

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	stdnet "net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// partialWriteClient is a TLS client against the system libssl, loaded with
// dlopen so that no OpenSSL headers are needed to build it. It waits for a
// byte on stdin, connects with a small send buffer and writes one HTTP/1.1
// request head (which validates the SSL_write offset), waits for a second
// byte, then writes a body: its first 100 bytes with one blocking call, the
// rest with SSL_MODE_ENABLE_PARTIAL_WRITE on a non-blocking socket to a peer
// that does not read yet, so calls return short or fail with WANT_WRITE and
// are retried with the remaining bytes, each call asking at most the chunk
// given (0: the whole rest). The body is bodyByte's sequence, so
// a byte captured twice shifts every byte after it. It prints its own tally
// of the calls after the second byte.
const partialWriteClient = `
#include <arpa/inet.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define SSL_CTRL_MODE 33
#define SSL_MODE_ENABLE_PARTIAL_WRITE 1L
#define SSL_CTRL_SET_TLSEXT_HOSTNAME 55
#define SSL_ERROR_WANT_READ 2
#define SSL_ERROR_WANT_WRITE 3

static void *sym(void *h, const char *name) {
	void *p = dlsym(h, name);
	if (!p) { fprintf(stderr, "dlsym %s: %s\n", name, dlerror()); exit(3); }
	return p;
}

static void wait_byte(void) {
	char c;
	if (read(0, &c, 1) != 1) exit(4);
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
	int (*ssl_write)(void *, const void *, int) = sym(h, "SSL_write");
	int (*get_error)(const void *, int) = sym(h, "SSL_get_error");
	long total = atol(argv[4]);
	long chunk = atol(argv[5]);

	wait_byte();
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	int small = 4096;
	setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &small, sizeof small);
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
	char head[512];
	int n = snprintf(head, sizeof head, "POST /upload HTTP/1.1\r\nHost: %s\r\nContent-Length: %ld\r\n\r\n", argv[3], total);
	if (ssl_write(ssl, head, n) != n) return 7;

	wait_byte();
	char *body = malloc(total);
	unsigned int s = 1;
	for (long i = 0; i < total; i++) {
		s = s * 1103515245u + 12345u;
		body[i] = (char)(s >> 16);
	}
	long calls = 0, partial = 0, failed = 0, requested = 0, written = 0;
	int r = ssl_write(ssl, body, 100);
	calls++; requested += 100;
	if (r != 100) return 8;
	written += r;
	ssl_ctrl(ssl, SSL_CTRL_MODE, SSL_MODE_ENABLE_PARTIAL_WRITE, NULL);
	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
	long off = 100;
	time_t start = time(NULL);
	while (off < total) {
		if (time(NULL) - start > 30) return 9;
		long want = total - off;
		if (chunk > 0 && want > chunk) want = chunk;
		r = ssl_write(ssl, body + off, (int)want);
		calls++; requested += want;
		if (r > 0) {
			written += r; off += r;
			if (r < want) partial++;
			continue;
		}
		failed++;
		int e = get_error(ssl, r);
		struct pollfd p = { .fd = fd, .events = e == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT };
		if (e != SSL_ERROR_WANT_WRITE && e != SSL_ERROR_WANT_READ) { fprintf(stderr, "SSL_write error %d\n", e); return 10; }
		poll(&p, 1, 1000);
	}
	printf("calls=%ld partial=%ld failed=%ld requested=%ld written=%ld head=%d\n", calls, partial, failed, requested, written, n);
	fflush(stdout);
	return 0;
}
`

// partialWriteBody is the body partialWriteClient writes: the high bytes of
// a linear congruential sequence, with no period a repeated record could
// line up with.
func partialWriteBody(n int) []byte {
	b := make([]byte, n)
	s := uint32(1)
	for i := range b {
		s = s*1103515245 + 12345
		b[i] = byte(s >> 16)
	}
	return b
}

// buildPartialWriteClient compiles partialWriteClient, or skips the test
// when no C compiler is installed.
func buildPartialWriteClient(t *testing.T) string {
	t.Helper()
	var cc string
	for _, c := range []string{"cc", "gcc", "clang"} {
		if p, err := exec.LookPath(c); err == nil {
			cc = p
			break
		}
	}
	if cc == "" {
		t.Skip("no C compiler to build the partial-write client")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "client.c")
	if err := os.WriteFile(src, []byte(partialWriteClient), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "client")
	if out, err := exec.Command(cc, "-O1", "-o", bin, src, "-ldl").CombinedOutput(); err != nil {
		t.Fatalf("build the partial-write client: %v\n%s", err, out)
	}
	return bin
}

// startStalledTLSServer accepts TLS connections on a listener with a small
// receive buffer and reads nothing from them until release is closed, then
// drains each to its end.
func startStalledTLSServer(t *testing.T, host string, release <-chan struct{}) (port string) {
	t.Helper()
	lc := stdnet.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4096)
		}); err != nil {
			return err
		}
		return serr
	}}
	raw, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ln := tls.NewListener(raw, &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t, host)}})
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				if tc, ok := conn.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
				<-release
				_, _ = io.Copy(io.Discard, conn)
			}()
		}
	}()
	_, port, _ = stdnet.SplitHostPort(raw.Addr().String())
	return port
}

// TestObserver_SSLWriteCountsPartialWrites drives SSL_write into short and
// failed returns and checks the uretprobe's counts (N-36) against the
// client's own tally: every call after the offset validated, its partial
// and failed returns, and the bytes asked and written. The first call, the
// request head that validated the offset, returned before counting was
// switched on and is not counted. It also checks the content captured at
// the return (N-37): the request parses, once, and its body hashes to the
// bytes the client sent, so no failed or partial call put a byte in the
// stream twice. The body's hash is checked when each call asks at most
// 16 KiB, the most a frame copies: asked for the whole rest, OpenSSL returns
// far more, and the request is then emitted cut, once, without a hash
// (N-44, checkCutRequest). Asked for one record at a time, the calls fail with WANT_WRITE and are retried with
// the same bytes, the pattern the Claude Code pilot showed (N-37).
func TestObserver_SSLWriteCountsPartialWrites(t *testing.T) {
	for _, tc := range []struct {
		name    string
		chunk   int
		content bool
	}{
		{"whole rest per call", 0, false},
		{"one record per call", 16384, true},
	} {
		t.Run(tc.name, func(t *testing.T) { testSSLWritePartial(t, tc.chunk, tc.content) })
	}
}

func testSSLWritePartial(t *testing.T, chunk int, checkContent bool) {
	skipUnprivileged(t)
	libssl := findLibSSL(t)
	client := buildPartialWriteClient(t)

	const host = "agenttrace-partial-write.internal"
	const total = 1 << 20
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseServer := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseServer)
	port := startStalledTLSServer(t, host, release)

	obs, err := New(Config{ExePath: libssl, EventBufSize: 4096, ValidationTimeout: 8 * time.Second})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cmd := exec.Command(client, libssl, port, host, strconv.Itoa(total), strconv.Itoa(chunk))
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start client: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	if err := obs.TrackPID(int32(cmd.Process.Pid)); err != nil {
		t.Fatalf("TrackPID: %v", err)
	}
	var requests []models.GroundTruthEvent
	eventsDone := make(chan struct{})
	go func() {
		defer close(eventsDone)
		for ev := range obs.Events() {
			if ev.ActionType == models.NetRequest {
				requests = append(requests, ev)
			}
		}
	}()

	// The client connects and writes the request head only once tracked.
	if _, err := stdin.Write([]byte("a")); err != nil {
		t.Fatal(err)
	}
	startDone := make(chan struct{})
	go func() { obs.Start(); close(startDone) }()
	select {
	case <-startDone:
	case <-time.After(20 * time.Second):
		t.Fatal("Observer.Start did not return")
	}
	if err := obs.TLSAttachError(); err != nil {
		t.Fatalf("TLSAttachError: %v", err)
	}

	// Start has attached the uretprobe at the validated offset: write the
	// body against a peer that reads nothing for half a second.
	if _, err := stdin.Write([]byte("b")); err != nil {
		t.Fatal(err)
	}
	time.AfterFunc(500*time.Millisecond, releaseServer)
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Fatalf("read the client's tally: %v", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("client: %v", err)
	}
	var want models.SSLWriteCounts
	var head uint64
	if _, err := fmt.Sscanf(line, "calls=%d partial=%d failed=%d requested=%d written=%d head=%d",
		&want.Calls, &want.Partial, &want.Failed, &want.BytesRequested, &want.BytesWritten, &head); err != nil {
		t.Fatalf("parse the client's tally %q: %v", line, err)
	}
	t.Logf("client: %+v (head %d bytes)", want, head)
	if want.Partial+want.Failed == 0 {
		t.Fatalf("the client's writes all completed in full, so nothing was forced: %+v", want)
	}

	if err := obs.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	d := obs.CaptureCoverage().Diagnostics
	if d == nil || d.SSLWrites == nil {
		t.Fatalf("SSLWrites not measured: %+v", d)
	}
	got := *d.SSLWrites
	t.Logf("probe:  %+v", got)
	if got != want {
		t.Errorf("SSLWrites = %+v, want the client's tally %+v", got, want)
	}

	<-eventsDone
	cov := obs.Coverage()
	if !checkContent {
		checkCutRequest(t, cov, requests, host, total)
		return
	}
	if cov.FramesTruncated != 0 || cov.FramesUnattributed != 0 || cov.FaultedReads != 0 || cov.TLSRingDrops != 0 {
		t.Errorf("content lost: truncated %d, unattributed %d, faulted %d, ring drops %d; want 0 (a write over %d bytes is truncated)",
			cov.FramesTruncated, cov.FramesUnattributed, cov.FaultedReads, cov.TLSRingDrops, 16384)
	}
	sum := sha256.Sum256(partialWriteBody(total))
	wantHash := "sha256:" + hex.EncodeToString(sum[:])
	wantTarget := models.CanonicalNetTarget("POST", host, 0, "/upload", "")
	if len(requests) != 1 {
		t.Fatalf("net_request events = %d (%+v), want 1: the request head and the body parse as one request", len(requests), requests)
	}
	r := requests[0]
	if r.Target != wantTarget {
		t.Errorf("request target = %q, want %q", r.Target, wantTarget)
	}
	if r.RequestHash == nil || *r.RequestHash != wantHash {
		t.Errorf("request body hash = %v, want %s: the captured stream does not hold each byte of the body once", r.RequestHash, wantHash)
	}
}

// checkCutRequest reads the requests of the run whose calls asked for the
// whole rest of the body (N-44). A call that returned more than the copy cuts
// the request: it is emitted once, with its target, cut and without a hash,
// and the body's Content-Length makes the stream pass over the rest of the
// body, so no frame is unattributed. A run in which no call returned more
// than the copy must hash the body whole instead.
func checkCutRequest(t *testing.T, cov Coverage, requests []models.GroundTruthEvent, host string, total int) {
	t.Helper()
	t.Logf("truncated frames %d, requests cut %d, unattributed %d", cov.FramesTruncated, cov.RequestsCut, cov.FramesUnattributed)
	wantTarget := models.CanonicalNetTarget("POST", host, 0, "/upload", "")
	if len(requests) != 1 || requests[0].Target != wantTarget {
		t.Fatalf("net_request events %+v, want one of %s", requests, wantTarget)
	}
	r := requests[0]
	if cov.FramesUnattributed != 0 || cov.FaultedReads != 0 || cov.TLSRingDrops != 0 {
		t.Errorf("unattributed %d, faulted %d, ring drops %d; want 0", cov.FramesUnattributed, cov.FaultedReads, cov.TLSRingDrops)
	}
	if cov.FramesTruncated == 0 {
		sum := sha256.Sum256(partialWriteBody(total))
		if want := "sha256:" + hex.EncodeToString(sum[:]); r.RequestCut || r.RequestHash == nil || *r.RequestHash != want {
			t.Errorf("no call was truncated, but the request is %+v, want the body hashed whole (%s)", r, want)
		}
		return
	}
	if !r.RequestCut || r.RequestHash != nil || cov.RequestsCut != 1 {
		t.Errorf("request %+v, requests cut %d: want one request, cut and without a hash", r, cov.RequestsCut)
	}
}
