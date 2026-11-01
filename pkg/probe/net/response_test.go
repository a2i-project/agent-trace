package net

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
)

func drainNow(o *Observer) []models.GroundTruthEvent {
	var out []models.GroundTruthEvent
	for {
		select {
		case ev := <-o.events:
			out = append(out, ev)
		default:
			return out
		}
	}
}

func chunk(s string) string { return fmt.Sprintf("%x\r\n%s\r\n", len(s), s) }

const testSSE = "event: message_start\ndata: {}\n\nevent: content_block_delta\ndata: {\"t\":\"hi\"}\n\nevent: message_stop\ndata: {}\n\n"

func sseResponse(reqID string) []string {
	head := "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nrequest-id: " + reqID + "\r\nTransfer-Encoding: chunked\r\n\r\n"
	parts := strings.SplitAfter(testSSE, "\n\n")
	out := []string{head}
	for _, p := range parts {
		if p != "" {
			out = append(out, chunk(p))
		}
	}
	return append(out, "0\r\n\r\n")
}

// TestResponses_PairedPerConnectionOnOneThread runs two connections on one
// thread, as an event loop does, with their requests and responses
// interleaved: each response pairs with the request of its own SSL object
// (N-30), not with the thread's latest request.
func TestResponses_PairedPerConnectionOnOneThread(t *testing.T) {
	o := newTestObserver()
	o.events = make(chan models.GroundTruthEvent, 64)
	a, b := sslKey{tgid: 5, ssl: 0xa000}, sslKey{tgid: 5, ssl: 0xb000}
	t0 := time.Unix(100, 0)

	o.handleSSLFrame(a, []byte("POST /v1/messages HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 2\r\n\r\n{}"), 0, t0)
	o.handleSSLFrame(b, []byte("GET /api/usage HTTP/1.1\r\nHost: other.example.com\r\n\r\n"), 0, t0.Add(time.Millisecond))
	at := t0.Add(time.Second)
	for i, part := range sseResponse("req_A") {
		if i == 1 {
			o.handleSSLRead(b, []byte("HTTP/1.1 200 OK\r\nRequest-Id: req_B\r\nContent-Length: 4\r\n\r\nus"), 0, at)
		}
		o.handleSSLRead(a, []byte(part), 0, at)
		at = at.Add(time.Millisecond)
	}
	o.handleSSLRead(b, []byte("ed"), 0, at)

	var resp []models.GroundTruthEvent
	for _, ev := range drainNow(o) {
		if ev.ActionType == models.NetResponse {
			resp = append(resp, ev)
		}
	}
	if len(resp) != 2 {
		t.Fatalf("got %d responses: %+v", len(resp), resp)
	}
	byID := map[string]models.GroundTruthEvent{}
	for _, ev := range resp {
		byID[ev.Response.RequestID] = ev
	}
	ra, rb := byID["req_A"], byID["req_B"]
	if ra.Target != "POST https://api.example.com/v1/messages" || rb.Target != "GET https://other.example.com/api/usage" {
		t.Errorf("targets %q, %q", ra.Target, rb.Target)
	}
	sum := sha256.Sum256([]byte(testSSE))
	if !ra.Response.Paired || !ra.Response.Complete || ra.Response.Status != 200 ||
		ra.Response.BodyHash != "sha256:"+hex.EncodeToString(sum[:]) || ra.Response.BodyBytes != int64(len(testSSE)) {
		t.Errorf("response A %+v", ra.Response)
	}
	if s := ra.Response.SSE; s == nil || s.Events != 3 || s.Types["message_start"] != 1 || s.Types["message_stop"] != 1 {
		t.Errorf("SSE %+v", ra.Response.SSE)
	}
	if !ra.Timestamp.Equal(t0.Add(time.Second)) || !ra.Response.End.After(ra.Timestamp) {
		t.Errorf("A stamped %v, ended %v", ra.Timestamp, ra.Response.End)
	}
	if rb.Response.SSE != nil || rb.Response.BodyBytes != 4 || rb.PID != 5 {
		t.Errorf("response B %+v pid %d", rb.Response, rb.PID)
	}
	if o.coverage.Responses != 2 || o.coverage.SSEEvents != 3 || o.coverage.ResponsesUnpaired != 0 {
		t.Errorf("coverage %+v", o.coverage)
	}
	if !ra.ActionType.IsValid() || ra.ActionType.IsClaimable() {
		t.Error("net_response must be valid ground truth and never claimable")
	}
	if err := ra.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

// TestResponses_ReadsBeforeAStatusLineAreUnvalidated checks that reads are
// discarded and counted until one begins with a status line, which
// validates the SSL_read offset and signals readOK.
func TestResponses_ReadsBeforeAStatusLineAreUnvalidated(t *testing.T) {
	o := newTestObserver()
	k := sslKey{tgid: 1, ssl: 1}
	o.handleSSLRead(k, []byte("tail of a body read before validation"), 0, time.Now())
	o.handleSSLRead(k, []byte{0x17, 0x03, 0x03}, 0, time.Now())
	select {
	case <-o.readOK:
		t.Fatal("readOK closed by reads that are no status line")
	default:
	}
	if o.coverage.ReadsUnvalidated != 2 {
		t.Errorf("ReadsUnvalidated = %d, want 2", o.coverage.ReadsUnvalidated)
	}
	o.handleSSLRead(k, []byte("HTTP/1.1 204 No Content\r\n\r\n"), 0, time.Now())
	select {
	case <-o.readOK:
	default:
		t.Fatal("readOK not closed by a status line")
	}
	// No request on the connection and no host: counted, not emitted.
	if evs := drainNow(o); len(evs) != 0 || o.coverage.ResponsesUnattributed != 1 {
		t.Errorf("events %+v, coverage %+v", evs, o.coverage)
	}
}

func TestResponses_UnpairedNamesTheHost(t *testing.T) {
	o := newTestObserver()
	o.readValid = true
	k := sslKey{tgid: 1, ssl: 1}
	o.handleSSLFrame(k, []byte("GET /a HTTP/1.1\r\nHost: api.example.com:8443\r\n\r\n"), 0, time.Now())
	o.handleSSLRead(k, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), 0, time.Now())
	var got []string
	for _, ev := range drainNow(o) {
		if ev.ActionType == models.NetResponse {
			got = append(got, fmt.Sprintf("%s paired=%v", ev.Target, ev.Response.Paired))
		}
	}
	want := []string{"GET https://api.example.com:8443/a paired=true", "https://api.example.com:8443 paired=false"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if o.coverage.ResponsesUnpaired != 1 {
		t.Errorf("ResponsesUnpaired = %d", o.coverage.ResponsesUnpaired)
	}
}

func TestResponses_HeadAnswerHasNoBody(t *testing.T) {
	o := newTestObserver()
	o.readValid = true
	k := sslKey{tgid: 1, ssl: 1}
	o.handleSSLFrame(k, []byte("HEAD /f HTTP/1.1\r\nHost: h.example.com\r\n\r\n"), 0, time.Now())
	o.handleSSLRead(k, []byte("HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n"), 0, time.Now())
	evs := drainNow(o)
	if len(evs) != 2 || evs[1].Response == nil || !evs[1].Response.Complete || evs[1].Response.BodyBytes != 0 {
		t.Fatalf("events %+v", evs)
	}
}

// TestResponses_GapsAndFlush covers the counted paths: a truncated read, a
// read that does not parse, and a response cut off by the end of the
// capture, which is emitted as incomplete and stamped at its last read.
func TestResponses_GapsAndFlush(t *testing.T) {
	o := newTestObserver()
	o.readValid = true
	k := sslKey{tgid: 1, ssl: 1}
	t0 := time.Unix(50, 0)
	o.handleSSLFrame(k, []byte("GET /a HTTP/1.1\r\nHost: h.example.com\r\n\r\n"), 0, t0)
	o.handleSSLRead(k, []byte("HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nabc"), 7, t0.Add(time.Second))
	o.handleSSLRead(k, []byte("0123456789"), 0, t0.Add(time.Second))
	o.handleSSLRead(k, []byte("HTTP/9 nonsense\r\n\r\n"), 0, t0.Add(2*time.Second))
	o.handleSSLFrame(k, []byte("GET /b HTTP/1.1\r\nHost: h.example.com\r\n\r\n"), 0, t0.Add(3*time.Second))
	o.handleSSLRead(k, []byte("HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nabc"), 0, t0.Add(4*time.Second))
	o.flushResponses()

	var resp []*models.ResponseAttestation
	for _, ev := range drainNow(o) {
		if ev.ActionType == models.NetResponse {
			resp = append(resp, ev.Response)
		}
	}
	if len(resp) != 2 {
		t.Fatalf("got %d responses", len(resp))
	}
	if !resp[0].Truncated || !resp[0].Complete || resp[0].BodyHash != "" || resp[0].BodyBytes != 20 {
		t.Errorf("truncated: %+v", resp[0])
	}
	if resp[1].Complete || resp[1].BodyHash != "" || !resp[1].End.Equal(t0.Add(4*time.Second)) {
		t.Errorf("flushed: %+v", resp[1])
	}
	c := o.coverage
	if c.ResponsesTruncated != 1 || c.ResponsesUnparsed != 1 || c.ResponsesIncomplete != 1 || len(o.tlsConns) != 0 {
		t.Errorf("coverage %+v, %d connections left", c, len(o.tlsConns))
	}
}

func TestHandleSSLFrame_TruncatedWriteDropsTheStream(t *testing.T) {
	o := newTestObserver()
	k := sslKey{tgid: 1, ssl: 1}
	o.handleSSLFrame(k, []byte("POST /a HTTP/1.1\r\nHost: h.example.com\r\nContent-Length: 30000\r\n\r\nxx"), 20000, time.Now())
	if evs := drainNow(o); len(evs) != 0 {
		t.Fatalf("events %+v", evs)
	}
	if o.coverage.FramesTruncated != 1 || o.coverage.FramesUnattributed != 1 || o.tlsConns[k].req.Len() != 0 {
		t.Errorf("coverage %+v", o.coverage)
	}
}

func TestTLSConns_Bounded(t *testing.T) {
	o := newTestObserver()
	o.readValid = true
	t0 := time.Unix(1, 0)
	for i := 0; i <= maxTLSConns; i++ {
		o.tlsConn(sslKey{tgid: 1, ssl: uint64(i + 1)}, t0.Add(time.Duration(i)))
	}
	if len(o.tlsConns) != maxTLSConns {
		t.Fatalf("%d connections kept", len(o.tlsConns))
	}
	if _, ok := o.tlsConns[sslKey{tgid: 1, ssl: 1}]; ok {
		t.Error("the connection seen least recently was kept")
	}
}

func TestCaptureCoverage_ResponseState(t *testing.T) {
	o := &Observer{}
	if got := o.CaptureCoverage().Responses; got != models.ContentIdentityOnly {
		t.Errorf("no content method: %q", got)
	}
	o.plan = contentPlan{sslMethod: MethodTLSSymbols, sslPath: "/x"}
	o.coverage = Coverage{ResponsesUnparsed: 1, ResponsesTruncated: 2, ResponsesUnattributed: 3}
	cov := o.CaptureCoverage()
	if cov.Responses != models.ContentAttachFailed || cov.ResponseGaps != 6 {
		t.Errorf("unvalidated: %+v", cov)
	}
	o.readActive.Store(true)
	if got := o.CaptureCoverage().Responses; got != models.ContentActive {
		t.Errorf("validated: %q", got)
	}
}
