package net

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/tlsoffset"
)

const testConn = 0xc000123000

func goRec(dir uint32, conn, sock uint64, payload []byte) sslRecord {
	return sslRecord{hdr: tlsbpfSslFrameHdr{Tgid: testTGID, Ssl: conn, Sock: sock, Len: uint32(len(payload)), Total: uint32(len(payload)), Dir: dir, Method: 2}, payload: payload}
}

// Go frames: frames before each direction validates are discarded and
// counted; the first preface write and SETTINGS read validate; an h2
// session on one *Conn yields its request and response; a frame with no
// socket is counted; the same *Conn with a new socket starts a new
// connection, emitting the old one's response in progress.
func TestGo_ValidationBindingAndReuse(t *testing.T) {
	o := newTestObserver()
	o.events = make(chan models.GroundTruthEvent, 64)
	o.conns[testSock] = &connection{tgid: testTGID, host: modelHost, port: 443}
	ts := time.Unix(4000, 0)

	o.handleGoRecord(goRec(sslDirWrite, testConn, testSock, []byte("\x00\x00\x00junk")), ts)
	o.handleGoRecord(goRec(sslDirRead, testConn, testSock, []byte("junk")), ts)
	if o.coverage.GoUnvalidated != 2 || o.goWriteValid || o.goReadValid {
		t.Fatalf("before validation: %+v", o.coverage)
	}
	w := append(append(append([]byte{}, h2ClientPreface...), settingsFrame()...), h2Post(1, modelPath+"?alt=sse")...)
	o.handleGoRecord(goRec(sslDirWrite, testConn, testSock, w), ts)
	o.handleGoRecord(goRec(sslDirWrite, testConn, testSock, h2F(0, h2EndStream, 1, []byte(`{"a":1}`))), ts)
	o.handleGoRecord(goRec(sslDirRead, testConn, testSock, settingsFrame()), ts)
	o.handleGoRecord(goRec(sslDirRead, testConn, testSock, h2F(1, h2EndHeaders, 1, h2Fields(":status", "200", "content-type", "text/event-stream"))), ts)
	o.handleGoRecord(goRec(sslDirRead, testConn, testSock, h2F(0, h2EndStream, 1, []byte("data: x\n\n"))), ts)
	if !o.goWriteValid || !o.goReadValid {
		t.Fatal("the preface and the SETTINGS frame did not validate")
	}
	// A response in progress, then the *Conn reused on another socket.
	o.handleGoRecord(goRec(sslDirWrite, testConn, testSock, h2Post(3, "/x")), ts)
	o.handleGoRecord(goRec(sslDirRead, testConn, testSock, h2F(1, h2EndHeaders, 3, h2Fields(":status", "200"))), ts)
	o.handleGoRecord(goRec(sslDirWrite, testConn, testSock+1, append(append([]byte{}, h2ClientPreface...), h2Post(1, "/after")...)), ts)
	o.handleGoRecord(goRec(sslDirWrite, testConn+0x100, 0, append(append([]byte{}, h2ClientPreface...), h2Post(1, "/nosock")...)), ts)
	o.flushResponses()

	var got []string
	for _, e := range drain(o) {
		s := string(e.ActionType) + " " + e.Target
		if e.RequestCut {
			s += " cut"
		}
		if e.Response != nil && !e.Response.Complete {
			s += " incomplete"
		}
		got = append(got, s)
	}
	want := []string{
		"net_request POST https://" + modelHost + modelPath + "?alt=sse",
		"net_response POST https://" + modelHost + modelPath + "?alt=sse",
		// The reuse closes the old connection: its open request cut, its
		// response incomplete.
		"net_request POST https://" + modelHost + "/x cut",
		"net_response POST https://" + modelHost + "/x incomplete",
		"net_request POST https://" + modelHost + "/after cut",
		"net_request POST https://" + modelHost + "/nosock cut",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("events:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if c := o.coverage; c.GoConnReused != 1 || c.GoUnbound != 1 || c.H2Preface != 3 {
		t.Errorf("coverage %+v", c)
	}
}

// goH2Server is a local HTTP/2 TLS server for the Go client: it records the
// SHA-256 of each request body, answers each with a fixed event stream, and
// writes its certificate where the client reads it.
type goH2Server struct {
	srv      *httptest.Server
	certPath string
	mu       sync.Mutex
	bodies   []string
	protos   []int
}

const goH2Events = "event: chunk\ndata: 1\n\nevent: chunk\ndata: 2\n\nevent: done\ndata: 3\n\n"

func startGoH2Server(t *testing.T) *goH2Server {
	t.Helper()
	g := &goH2Server{}
	g.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		sum := sha256.Sum256(b)
		g.mu.Lock()
		g.bodies = append(g.bodies, "sha256:"+hex.EncodeToString(sum[:]))
		g.protos = append(g.protos, r.ProtoMajor)
		g.mu.Unlock()
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("X-Request-Id", "rid-"+r.Method)
		_, _ = io.WriteString(w, goH2Events)
	}))
	g.srv.EnableHTTP2 = true
	g.srv.StartTLS()
	t.Cleanup(g.srv.Close)
	g.certPath = filepath.Join(t.TempDir(), "cert.pem")
	if err := os.WriteFile(g.certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: g.srv.Certificate().Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	return g
}

// buildGoH2Client builds testdata/goh2client with the toolchain running the
// tests (no download: standard library only).
func buildGoH2Client(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "goh2client")
	cmd := exec.Command("go", "build", "-o", out, "./testdata/goh2client")
	cmd.Env = append(os.Environ(), "GOFLAGS=")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}
	return out
}

// The Go client completes its session against the server unprivileged, in
// the time the privileged test allows, over HTTP/2, so a failure of the
// privileged test is the probe's.
func TestGoH2Client_CompletesItsSession(t *testing.T) {
	g := startGoH2Server(t)
	client := buildGoH2Client(t)
	cmd := exec.Command(client, g.srv.URL, g.certPath)
	cmd.Stdin = strings.NewReader(sessionGo)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("client: %v\n%s", err, out.String())
		}
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("client did not finish\n%s", out.String())
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.protos) != 3 || g.protos[0] != 2 || g.protos[1] != 2 || g.protos[2] != 2 {
		t.Errorf("requests by protocol %v, want three over HTTP/2", g.protos)
	}
}

// TestObserver_GoCryptoH2 runs tls-go-crypto (N-47, N-48) on a Go TLS
// client built from testdata/goh2client, which makes three HTTP/2 requests
// to a local server: two POSTs (one of 100000 bytes, written in calls
// larger than one frame's copy) and a GET. Every request and response must
// be recorded with its hash, paired by stream, with no frame unvalidated,
// unbound or dropped, and every entry the probes saw matched by a return
// but the reads still blocked when the client exited.
func TestObserver_GoCryptoH2(t *testing.T) {
	skipUnprivileged(t)
	g := startGoH2Server(t)
	client := buildGoH2Client(t)
	if _, err := tlsoffset.ScanGoTLS(client); err != nil {
		t.Fatalf("locator: %v", err)
	}
	obs, err := New(Config{Content: []ContentMethod{{Method: MethodGoCrypto, Path: client}}, EventBufSize: 4096})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	evs := runContentSession(t, obs, exec.Command(client, g.srv.URL, g.certPath))
	host := strings.TrimPrefix(g.srv.URL, "https://")
	gen := "POST https://" + host + "/v1internal:streamGenerateContent?alt=sse"
	load := "GET https://" + host + "/v1internal:loadCodeAssist"
	g.mu.Lock()
	bodies := append([]string(nil), g.bodies...)
	g.mu.Unlock()
	if len(bodies) != 3 {
		t.Fatalf("the server saw %d requests", len(bodies))
	}
	respHash := sha256.Sum256([]byte(goH2Events))
	var reqs, resps []models.GroundTruthEvent
	for _, e := range evs {
		switch e.ActionType {
		case models.NetRequest:
			reqs = append(reqs, e)
		case models.NetResponse:
			resps = append(resps, e)
		}
	}
	if len(reqs) != 3 || len(resps) != 3 {
		t.Fatalf("%d requests and %d responses, want 3 and 3: %+v", len(reqs), len(resps), evs)
	}
	for i, want := range []struct {
		target string
		hash   string
	}{{gen, bodies[0]}, {gen, bodies[1]}, {load, ""}} {
		r := reqs[i]
		h := ""
		if r.RequestHash != nil {
			h = *r.RequestHash
		}
		if r.Target != want.target || h != want.hash || r.RequestCut {
			t.Errorf("request %d: %s hash %s cut %v, want %s %s", i, r.Target, h, r.RequestCut, want.target, want.hash)
		}
		p := resps[i].Response
		if resps[i].Target != want.target || !p.Paired || !p.Complete || p.Status != 200 || p.BodyHash != "sha256:"+hex.EncodeToString(respHash[:]) || p.SSE == nil || p.SSE.Events != 3 {
			t.Errorf("response %d: %s %+v", i, resps[i].Target, p)
		}
	}
	cov := obs.CaptureCoverage()
	if req, resp := cov.MethodContent(MethodGoCrypto); req != models.ContentActive || resp != models.ContentActive {
		t.Errorf("method state %s %s, want active", req, resp)
	}
	c := obs.Coverage()
	if c.GoUnvalidated != 0 || c.GoUnbound != 0 || c.GoRingDrops != 0 || c.H2Unparsed != 0 || c.H2Requests != 3 || c.H2Responses != 3 || c.FaultedReads != 0 || c.ReadFaults != 0 || c.ReadDrops != 0 {
		t.Errorf("coverage %+v", c)
	}
	gc := cov.Diagnostics.GoTLS
	if gc == nil || gc.WriteCalls == 0 || gc.WriteCalls != gc.WriteReturns || gc.ReadCalls < gc.ReadReturns || gc.ReadCalls-gc.ReadReturns > 2 {
		t.Errorf("go_tls counts %+v", gc)
	}
}
