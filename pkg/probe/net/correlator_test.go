package net

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/tlsparse"
)

func newTestObserver() *Observer {
	return &Observer{
		conns:   make(map[uint64]*connection),
		pending: make(map[sslKey]*tlsparse.Stream),
		events:  make(chan models.GroundTruthEvent, 16),
	}
}

func TestHandleSSLFrame_EmitsNetRequestFromHostHeader(t *testing.T) {
	o := newTestObserver()
	ts := time.Now()

	req := "GET /v1/messages?x=1 HTTP/1.1\r\nHost: api.example.com\r\nConnection: close\r\n\r\n"
	o.handleSSLFrame(42, 7, []byte(req), ts)

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

	o.handleSSLFrame(1, 1, []byte(req), time.Now())

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

	o.handleSSLFrame(1, 1, []byte(full[:mid]), time.Now())
	select {
	case ev := <-o.events:
		t.Fatalf("emitted before the request was complete: %+v", ev)
	default:
	}

	o.handleSSLFrame(1, 1, []byte(full[mid:]), time.Now())
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
	o.handleSSLFrame(9, 1, []byte(req), time.Now())

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
	o.handleSSLFrame(9, 1, []byte(req), time.Now())

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
	o.handleSSLFrame(1, 1, []byte("not an http request\r\n\r\n"), time.Now())

	if o.coverage.FramesUnattributed != 1 {
		t.Errorf("coverage.FramesUnattributed = %d, want 1", o.coverage.FramesUnattributed)
	}
	if _, ok := o.pending[sslKey{tgid: 1, tid: 1}]; ok {
		t.Error("malformed stream was not dropped from pending")
	}
}

func TestHandleSSLFrame_HostHeaderWithNonDefaultPort(t *testing.T) {
	o := newTestObserver()
	req := "GET /a HTTP/1.1\r\nHost: api.example.com:8443\r\n\r\n"
	o.handleSSLFrame(1, 1, []byte(req), time.Now())

	ev := <-o.events
	want := "GET https://api.example.com:8443/a"
	if ev.Target != want {
		t.Errorf("Target = %q, want %q", ev.Target, want)
	}
}
