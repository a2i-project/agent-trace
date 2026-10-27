package net

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
)

func newTestObserver() *Observer {
	return &Observer{
		conns:    make(map[uint64]*connection),
		tlsConns: make(map[sslKey]*tlsConn),
		readOK:   make(chan struct{}),
		events:   make(chan models.GroundTruthEvent, 16),
	}
}

func TestHandleSSLFrame_EmitsNetRequestFromHostHeader(t *testing.T) {
	o := newTestObserver()
	ts := time.Now()

	req := "GET /v1/messages?x=1 HTTP/1.1\r\nHost: api.example.com\r\nConnection: close\r\n\r\n"
	o.handleSSLFrame(sslKey{tgid: 42, ssl: 7}, []byte(req), 0, ts)

	select {
	case ev := <-o.events:
		if ev.ActionType != models.NetRequest {
			t.Fatalf("ActionType = %v, want NetRequest", ev.ActionType)
		}
		want := "GET https://api.example.com/v1/messages?x=1"
		if ev.Target != want {
			t.Fatalf("Target = %q, want %q", ev.Target, want)
		}
		if ev.RequestHash != nil {
			t.Fatalf("RequestHash = %v, want nil for a bodyless GET", *ev.RequestHash)
		}
		if !ev.Timestamp.Equal(ts) {
			t.Fatalf("Timestamp = %v, want %v", ev.Timestamp, ts)
		}
	default:
		t.Fatal("no event emitted")
	}

	if o.coverage.WithContent != 1 {
		t.Errorf("coverage.WithContent = %d, want 1", o.coverage.WithContent)
	}
}

func TestHandleSSLFrame_RequestHashOfBody(t *testing.T) {
	o := newTestObserver()
	body := "{\"prompt\":\"hi\"}"
	req := "POST /v1/messages HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: " +
		strconv.Itoa(len(body)) + "\r\n\r\n" + body

	o.handleSSLFrame(sslKey{tgid: 1, ssl: 1}, []byte(req), 0, time.Now())

	ev := <-o.events
	if ev.RequestHash == nil {
		t.Fatal("RequestHash is nil, want a hash of the body")
	}
	sum := sha256.Sum256([]byte(body))
	want := "sha256:" + hex.EncodeToString(sum[:])
	if *ev.RequestHash != want {
		t.Errorf("RequestHash = %q, want %q", *ev.RequestHash, want)
	}
}

func TestHandleSSLFrame_SplitAcrossFrames(t *testing.T) {
	o := newTestObserver()
	full := "GET /a HTTP/1.1\r\nHost: split.example.com\r\n\r\n"
	mid := len(full) / 2

	o.handleSSLFrame(sslKey{tgid: 1, ssl: 1}, []byte(full[:mid]), 0, time.Now())
	select {
	case ev := <-o.events:
		t.Fatalf("emitted before the request was complete: %+v", ev)
	default:
	}

	o.handleSSLFrame(sslKey{tgid: 1, ssl: 1}, []byte(full[mid:]), 0, time.Now())
	select {
	case ev := <-o.events:
		if ev.Target != "GET https://split.example.com/a" {
			t.Errorf("Target = %q", ev.Target)
		}
	default:
		t.Fatal("no event emitted after the request completed")
	}
}

func TestHandleSSLFrame_NoHostFallsBackToConnectionSNI(t *testing.T) {
	o := newTestObserver()
	o.conns[3] = &connection{tgid: 9, host: "sni.example.com", openedAt: time.Now()}

	// HTTP/1.0 request with no Host header at all.
	req := "GET /root HTTP/1.0\r\n\r\n"
	o.handleSSLFrame(sslKey{tgid: 9, ssl: 1}, []byte(req), 0, time.Now())

	select {
	case ev := <-o.events:
		if ev.Target != "GET https://sni.example.com/root" {
			t.Errorf("Target = %q", ev.Target)
		}
	default:
		t.Fatal("no event emitted")
	}
}

func TestHandleSSLFrame_UnattributableRequestIsCounted(t *testing.T) {
	o := newTestObserver()
	req := "GET /root HTTP/1.0\r\n\r\n" // no Host header, no matching connection
	o.handleSSLFrame(sslKey{tgid: 9, ssl: 1}, []byte(req), 0, time.Now())

	select {
	case ev := <-o.events:
		t.Fatalf("unexpected event for an unattributable request: %+v", ev)
	default:
	}
	if o.coverage.FramesUnattributed != 1 {
		t.Errorf("coverage.FramesUnattributed = %d, want 1", o.coverage.FramesUnattributed)
	}
}

func TestHandleSSLFrame_MalformedRequestDropsPendingBytes(t *testing.T) {
	o := newTestObserver()
	o.handleSSLFrame(sslKey{tgid: 1, ssl: 1}, []byte("not an http request\r\n\r\n"), 0, time.Now())

	if o.coverage.FramesUnattributed != 1 {
		t.Errorf("coverage.FramesUnattributed = %d, want 1", o.coverage.FramesUnattributed)
	}
	if c := o.tlsConns[sslKey{tgid: 1, ssl: 1}]; c == nil || c.req.Len() != 0 {
		t.Error("malformed stream was not dropped")
	}
}

func TestHandleSSLFrame_HostHeaderWithNonDefaultPort(t *testing.T) {
	o := newTestObserver()
	req := "GET /a HTTP/1.1\r\nHost: api.example.com:8443\r\n\r\n"
	o.handleSSLFrame(sslKey{tgid: 1, ssl: 1}, []byte(req), 0, time.Now())

	ev := <-o.events
	want := "GET https://api.example.com:8443/a"
	if ev.Target != want {
		t.Errorf("Target = %q, want %q", ev.Target, want)
	}
}

// A connection whose stream holds bytes past a request's body, as a write
// captured twice would leave them, emits the first request and then no
// request with those bytes for its method (N-34): the next request line is
// malformed, the buffer is dropped and counted, and a later request on the
// connection parses again.
func TestHandleSSLFrame_ABodyTailIsNeverARequestMethod(t *testing.T) {
	o := newTestObserver()
	key := sslKey{tgid: 1, ssl: 1}
	body := `[{"message":"event_one","os":"linux"}]`
	head := "POST /api/v2/logs HTTP/1.1\r\nHost: intake.example.com\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n"
	o.handleSSLFrame(key, []byte(head), 0, time.Now())
	o.handleSSLFrame(key, []byte(body), 0, time.Now())
	o.handleSSLFrame(key, []byte(body[10:]), 0, time.Now())
	o.handleSSLFrame(key, []byte(head+body), 0, time.Now())
	o.handleSSLFrame(key, []byte("GET /next HTTP/1.1\r\nHost: intake.example.com\r\n\r\n"), 0, time.Now())

	var targets []string
	for len(o.events) > 0 {
		targets = append(targets, (<-o.events).Target)
	}
	want := []string{"POST https://intake.example.com/api/v2/logs", "GET https://intake.example.com/next"}
	if len(targets) != len(want) || targets[0] != want[0] || targets[1] != want[1] {
		t.Errorf("targets %q, want %q", targets, want)
	}
	if o.coverage.FramesUnattributed != 1 {
		t.Errorf("FramesUnattributed = %d, want 1", o.coverage.FramesUnattributed)
	}
}
