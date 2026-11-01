package net

import (
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// metricsHead is the head of a request whose body a single large write
// carries, as Codex 0.166.0 posts its metrics (N-44).
const metricsHead = "POST /otlp/v1/metrics HTTP/1.1\r\nHost: ab.example.com\r\nContent-Type: application/x-protobuf\r\nContent-Length: 30000\r\n\r\n"

func splitEvents(evs []models.GroundTruthEvent) (reqs, resps []models.GroundTruthEvent) {
	for _, ev := range evs {
		switch ev.ActionType {
		case models.NetRequest:
			reqs = append(reqs, ev)
		case models.NetResponse:
			resps = append(resps, ev)
		}
	}
	return reqs, resps
}

// TestHandleSSLFrame_TruncatedWriteEmitsACutRequest: a write larger than the
// copy whose copied bytes hold the request's head emits the request with its
// target, marked cut and without a hash, and its response pairs with it, so
// it is no response gap (N-44).
func TestHandleSSLFrame_TruncatedWriteEmitsACutRequest(t *testing.T) {
	o := newTestObserver()
	o.readValid = true
	k := sslKey{tgid: 7, ssl: 1}
	t0 := time.Unix(100, 0)
	copied := metricsHead + strings.Repeat("x", 16384-len(metricsHead))
	o.handleSSLFrame(k, []byte(copied), 30000-(16384-len(metricsHead)), t0)
	o.handleSSLRead(k, []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"), 0, t0.Add(time.Second))

	reqs, resps := splitEvents(drainNow(o))
	if len(reqs) != 1 || len(resps) != 1 {
		t.Fatalf("requests %+v, responses %+v", reqs, resps)
	}
	r := reqs[0]
	if r.Target != "POST https://ab.example.com/otlp/v1/metrics" || !r.RequestCut || r.RequestHash != nil || r.PID != 7 || !r.Timestamp.Equal(t0) {
		t.Errorf("request %+v", r)
	}
	if resps[0].Target != r.Target || !resps[0].Response.Paired || !resps[0].Response.Complete {
		t.Errorf("response %+v %+v", resps[0], resps[0].Response)
	}
	c := o.coverage
	if c.FramesTruncated != 1 || c.RequestsCut != 1 || c.WithContent != 1 || c.FramesUnattributed != 0 || c.ResponsesUnattributed != 0 || c.ResponsesUnpaired != 0 {
		t.Errorf("coverage %+v", c)
	}
	if cov := o.CaptureCoverage(); cov.RequestsCut != 1 || cov.ResponseGaps != 0 {
		t.Errorf("capture coverage: requests_cut %d, response_gaps %d", cov.RequestsCut, cov.ResponseGaps)
	}
}

// TestHandleSSLFrame_CutRequestOverSeveralWrites: the head in a write of its
// own and the body in large writes, as a partial-write loop sends it. The
// body's length says where the request ends, so the writes after the cut
// pass over and the next request on the connection is read whole.
func TestHandleSSLFrame_CutRequestOverSeveralWrites(t *testing.T) {
	o := newTestObserver()
	k := sslKey{tgid: 7, ssl: 1}
	t0 := time.Unix(100, 0)
	o.handleSSLFrame(k, []byte(metricsHead), 0, t0)
	// 16384 copied and 3616 missed, then the last 10000 bytes of the body
	// (9000 copied, 1000 missed) and a complete request.
	o.handleSSLFrame(k, []byte(strings.Repeat("x", 16384)), 3616, t0.Add(time.Millisecond))
	o.handleSSLFrame(k, []byte(strings.Repeat("x", 9000)), 1000, t0.Add(2*time.Millisecond))
	o.handleSSLFrame(k, []byte("POST /next HTTP/1.1\r\nHost: ab.example.com\r\nContent-Length: 2\r\n\r\n{}"), 0, t0.Add(3*time.Millisecond))

	reqs, _ := splitEvents(drainNow(o))
	if len(reqs) != 2 {
		t.Fatalf("requests %+v", reqs)
	}
	if !reqs[0].RequestCut || reqs[0].Target != "POST https://ab.example.com/otlp/v1/metrics" || !reqs[0].Timestamp.Equal(t0.Add(time.Millisecond)) {
		t.Errorf("cut request %+v", reqs[0])
	}
	if reqs[1].RequestCut || reqs[1].RequestHash == nil || reqs[1].Target != "POST https://ab.example.com/next" {
		t.Errorf("next request %+v", reqs[1])
	}
	if c := o.coverage; c.FramesTruncated != 2 || c.RequestsCut != 1 || c.FramesUnattributed != 0 || c.WithContent != 2 {
		t.Errorf("coverage %+v", c)
	}
}

// TestHandleSSLFrame_CutLeavesWhatItCannotRead covers the hole that cannot
// be read past or named.
func TestHandleSSLFrame_CutLeavesWhatItCannotRead(t *testing.T) {
	t0 := time.Unix(100, 0)
	k := sslKey{tgid: 7, ssl: 1}

	t.Run("no head in the bytes copied", func(t *testing.T) {
		o := newTestObserver()
		o.handleSSLFrame(k, []byte("POST /a HTTP/1.1\r\nHost: h.example.com\r\nX-Big: "+strings.Repeat("y", 100)), 20000, t0)
		if evs := drainNow(o); len(evs) != 0 {
			t.Fatalf("events %+v", evs)
		}
		if c := o.coverage; c.FramesTruncated != 1 || c.FramesUnattributed != 1 || c.RequestsCut != 0 || o.tlsConns[k].req.Len() != 0 {
			t.Errorf("coverage %+v", c)
		}
	})

	t.Run("chunked body: cut, then the stream restarts", func(t *testing.T) {
		o := newTestObserver()
		o.handleSSLFrame(k, []byte("POST /c HTTP/1.1\r\nHost: h.example.com\r\nTransfer-Encoding: chunked\r\n\r\n4000\r\nxx"), 20000, t0)
		reqs, _ := splitEvents(drainNow(o))
		if len(reqs) != 1 || !reqs[0].RequestCut || reqs[0].Target != "POST https://h.example.com/c" {
			t.Fatalf("requests %+v", reqs)
		}
		if tc := o.tlsConns[k]; tc.skip != 0 || tc.req.Len() != 0 {
			t.Errorf("skip %d, buffered %d", tc.skip, tc.req.Len())
		}
	})

	t.Run("a whole request before the hole is not cut", func(t *testing.T) {
		o := newTestObserver()
		o.handleSSLFrame(k, []byte("GET /whole HTTP/1.1\r\nHost: h.example.com\r\n\r\nPOST /cut HTTP/1.1\r\nHost: h.example.com\r\nContent-Length: 40000\r\n\r\nxx"), 30000, t0)
		reqs, _ := splitEvents(drainNow(o))
		if len(reqs) != 2 || reqs[0].RequestCut || reqs[0].Target != "GET https://h.example.com/whole" || !reqs[1].RequestCut {
			t.Fatalf("requests %+v", reqs)
		}
		if tc := o.tlsConns[k]; tc.skip != 40000-2-30000 {
			t.Errorf("skip %d", tc.skip)
		}
	})

	t.Run("a hole past the body's end loses the next request's start", func(t *testing.T) {
		o := newTestObserver()
		o.handleSSLFrame(k, []byte("POST /a HTTP/1.1\r\nHost: h.example.com\r\nContent-Length: 100\r\n\r\nxx"), 20000, t0)
		reqs, _ := splitEvents(drainNow(o))
		if len(reqs) != 1 || !reqs[0].RequestCut {
			t.Fatalf("requests %+v", reqs)
		}
		if tc := o.tlsConns[k]; tc.skip != 0 {
			t.Errorf("skip %d", tc.skip)
		}
	})

	t.Run("no host: counted unattributed, as its response is", func(t *testing.T) {
		o := newTestObserver()
		o.readValid = true
		o.handleSSLFrame(k, []byte("POST /a HTTP/1.1\r\nContent-Length: 30000\r\n\r\nxx"), 20000, t0)
		o.handleSSLRead(k, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), 0, t0.Add(time.Second))
		if evs := drainNow(o); len(evs) != 0 {
			t.Fatalf("events %+v", evs)
		}
		if c := o.coverage; c.FramesUnattributed != 1 || c.RequestsCut != 0 || c.ResponsesUnattributed != 1 {
			t.Errorf("coverage %+v", c)
		}
	})
}

// TestHandleSSLFrame_HoleAfterAnUpgrade: the upgrade request is read and the
// hole reaches the client's WebSocket frames, whose direction it ends.
func TestHandleSSLFrame_HoleAfterAnUpgrade(t *testing.T) {
	o := newTestObserver()
	k := sslKey{tgid: 7, ssl: 1}
	up := "GET /ws HTTP/1.1\r\nHost: h.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
	o.handleSSLFrame(k, []byte(up+"\x81\xfe"), 20000, time.Unix(100, 0))
	reqs, _ := splitEvents(drainNow(o))
	if len(reqs) != 1 || reqs[0].RequestCut || reqs[0].Target != "GET https://h.example.com/ws" {
		t.Fatalf("requests %+v", reqs)
	}
	if c := o.coverage; c.WebSockets != 1 || c.WSUnparsed != 1 || c.RequestsCut != 0 || c.FramesTruncated != 1 {
		t.Errorf("coverage %+v", c)
	}
}
