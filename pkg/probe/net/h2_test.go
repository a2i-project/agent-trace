package net

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
)

func h2F(typ, flags byte, stream uint32, payload []byte) []byte {
	out := []byte{byte(len(payload) >> 16), byte(len(payload) >> 8), byte(len(payload)), typ, flags}
	out = binary.BigEndian.AppendUint32(out, stream)
	return append(out, payload...)
}

// h2Fields encodes fields as HPACK literals without indexing, raw strings
// shorter than 127 bytes.
func h2Fields(kv ...string) []byte {
	var b []byte
	for i := 0; i+1 < len(kv); i += 2 {
		b = append(b, 0x00, byte(len(kv[i])))
		b = append(b, kv[i]...)
		b = append(b, byte(len(kv[i+1])))
		b = append(b, kv[i+1]...)
	}
	return b
}

const (
	h2EndStream  = 0x1
	h2EndHeaders = 0x4
	modelHost    = "daily-cloudcode-pa.googleapis.com"
	modelPath    = "/v1internal:streamGenerateContent"
)

func h2Post(stream uint32, path string) []byte {
	return h2F(1, h2EndHeaders, stream, h2Fields(":method", "POST", ":scheme", "https", ":authority", modelHost, ":path", path, "content-type", "application/json"))
}

func settingsFrame() []byte { return h2F(4, 0, 0, []byte{0, 3, 0, 0, 0, 100}) }

func evsOf(o *Observer) []models.GroundTruthEvent { return drain(o) }

// An h2 session on one connection: a model request whose body spans two
// writes, an event-stream response paired with it by stream, a second
// request whose response arrives first on the wire, and the counts.
func TestH2_SessionOverTheSSLSide(t *testing.T) {
	o := newTestObserver()
	o.events = make(chan models.GroundTruthEvent, 64)
	key := sslKey{tgid: 5, ssl: 0x99}
	t0 := time.Unix(2000, 0)
	at := func(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }

	w1 := append(append(append([]byte{}, h2ClientPreface...), settingsFrame()...), h2Post(1, modelPath+"?alt=sse")...)
	w1 = append(w1, h2F(0, 0, 1, []byte(`{"contents":`))...)
	o.handleSSLFrame(key, w1, 0, at(0))
	o.handleSSLFrame(key, h2F(0, h2EndStream, 1, []byte(`[]}`)), 0, at(1))
	r1 := append(settingsFrame(), h2F(1, h2EndHeaders, 1, h2Fields(":status", "200", "content-type", "text/event-stream", "x-request-id", "abc"))...)
	r1 = append(r1, h2F(0, 0, 1, []byte("data: {\"a\":1}\n\n"))...)
	o.feedRead(key, r1, 0, at(2))
	o.feedRead(key, h2F(0, h2EndStream, 1, []byte("data: {\"a\":2}\n\n")), 0, at(3))
	// Stream 3: its head, then its response ends before its body does.
	o.handleSSLFrame(key, h2Post(3, "/v1internal:loadCodeAssist"), 0, at(4))
	o.feedRead(key, h2F(1, h2EndHeaders|h2EndStream, 3, h2Fields(":status", "403")), 0, at(5))
	o.handleSSLFrame(key, h2F(0, h2EndStream, 3, []byte(`{}`)), 0, at(6))
	o.flushResponses()

	evs := evsOf(o)
	if len(evs) != 4 {
		t.Fatalf("%d events, want 4: %+v", len(evs), evs)
	}
	modelTarget := "POST https://" + modelHost + modelPath + "?alt=sse"
	if e := evs[0]; e.ActionType != models.NetRequest || e.Target != modelTarget || e.RequestHash == nil || *e.RequestHash != hashOf(`{"contents":[]}`) || e.RequestCut || !e.Timestamp.Equal(at(1)) || e.PID != 5 {
		t.Errorf("request 1: %+v", e)
	}
	if e := evs[1]; e.ActionType != models.NetResponse || e.Target != modelTarget || !e.Response.Paired || e.Response.Status != 200 || e.Response.RequestID != "abc" ||
		!e.Response.Complete || e.Response.SSE == nil || e.Response.SSE.Events != 2 || !e.Timestamp.Equal(at(2)) {
		t.Errorf("response 1: %+v %+v", e, e.Response)
	}
	other := "POST https://" + modelHost + "/v1internal:loadCodeAssist"
	if e := evs[2]; e.ActionType != models.NetResponse || e.Target != other || !e.Response.Paired || e.Response.Status != 403 {
		t.Errorf("response 3, paired with the request still streaming: %+v %+v", e, e.Response)
	}
	if e := evs[3]; e.ActionType != models.NetRequest || e.Target != other || *e.RequestHash != hashOf(`{}`) {
		t.Errorf("request 3: %+v", e)
	}
	c := o.coverage
	if c.H2Preface != 1 || c.H2Requests != 2 || c.H2Responses != 2 || c.WithContent != 2 || c.Responses != 2 || c.FramesH2 != 4 || c.H2Unparsed != 0 || c.SSEEvents != 2 {
		t.Errorf("coverage %+v", c)
	}
}

// The server's SETTINGS read before the client's preface (the server spoke
// first) starts the h2 read side; a write larger than the copy inside a
// DATA payload cuts that request and keeps the framing; a stream open at
// the end of the capture is emitted cut, its response incomplete.
func TestH2_ServerFirstCutAndOpenAtStop(t *testing.T) {
	o := newTestObserver()
	o.events = make(chan models.GroundTruthEvent, 64)
	key := sslKey{tgid: 5, ssl: 0x77}
	ts := time.Unix(3000, 0)
	o.feedRead(key, settingsFrame(), 0, ts)
	w := append(append(append([]byte{}, h2ClientPreface...), h2Post(1, "/big")...), h2F(0, h2EndStream, 1, []byte("0123456789"))[:9+4]...)
	o.handleSSLFrame(key, w, 6, ts)
	o.handleSSLFrame(key, h2Post(3, "/open"), 0, ts)
	o.feedRead(key, h2F(1, h2EndHeaders, 3, h2Fields(":status", "200")), 0, ts)
	o.flushResponses()
	evs := evsOf(o)
	if len(evs) != 3 {
		t.Fatalf("%d events, want 3: %+v", len(evs), evs)
	}
	if e := evs[0]; e.Target != "POST https://"+modelHost+"/big" || !e.RequestCut || e.RequestHash != nil {
		t.Errorf("cut request: %+v", e)
	}
	if e := evs[1]; e.Target != "POST https://"+modelHost+"/open" || !e.RequestCut {
		t.Errorf("open request: %+v", e)
	}
	if e := evs[2]; e.ActionType != models.NetResponse || e.Response.Complete || !e.Response.Paired {
		t.Errorf("open response: %+v %+v", e, e.Response)
	}
	if c := o.coverage; c.RequestsCut != 2 || c.FramesTruncated != 1 || c.ResponsesIncomplete != 1 {
		t.Errorf("coverage %+v", c)
	}
}

// A request stream that does not parse as HTTP/1.x and begins like an h2
// frame is an h2 connection older than the capture: refused and counted.
// A server direction that loses its framing counts as unparsed responses.
func TestH2_RefusalsAreCounted(t *testing.T) {
	o := newTestObserver()
	o.handleSSLFrame(sslKey{tgid: 1, ssl: 1}, h2Post(5, "/x"), 0, time.Now())
	if o.coverage.H2NoPreface != 1 || o.coverage.FramesUnattributed != 1 || o.coverage.WithContent != 0 {
		t.Errorf("coverage %+v", o.coverage)
	}
	o = newTestObserver()
	key := sslKey{tgid: 1, ssl: 2}
	o.handleSSLFrame(key, append(append([]byte{}, h2ClientPreface...), h2Post(1, "/x")...), 0, time.Now())
	o.feedRead(key, settingsFrame(), 40, time.Now())
	if o.coverage.H2Unparsed != 1 || o.coverage.ResponsesUnparsed != 1 {
		t.Errorf("coverage %+v", o.coverage)
	}
}

// The validators of every method accept the h2 preface on the write side
// and a server's SETTINGS frame on the read side (N-46).
func TestValidStarts(t *testing.T) {
	if !validRequestStart(append(append([]byte{}, h2ClientPreface...), settingsFrame()...)) || !validRequestStart([]byte("GET / HTTP/1.1\r\n")) {
		t.Error("a request start refused")
	}
	if validRequestStart(settingsFrame()) || validRequestStart([]byte("PRI * HTTP/2.0\r\n")) {
		t.Error("a frame or a partial preface accepted as a request start")
	}
	if !validResponseStart(settingsFrame()) || !validResponseStart([]byte("HTTP/1.1 200 OK\r\n")) {
		t.Error("a response start refused")
	}
	if validResponseStart(h2F(4, 1, 0, nil)) || validResponseStart(h2ClientPreface) {
		t.Error("a SETTINGS ack or a preface accepted as a response start")
	}
}
