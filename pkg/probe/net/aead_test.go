package net

import (
	"bytes"
	"compress/flate"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/tlsparse"
)

// wsFrameBytes encodes one WebSocket frame, masked with a fixed key when
// masked is set.
func wsFrameBytes(op byte, masked bool, payload string) []byte {
	out := []byte{0x80 | op}
	m := byte(0)
	if masked {
		m = 0x80
	}
	switch n := len(payload); {
	case n < 126:
		out = append(out, m|byte(n))
	default:
		out = append(out, m|126)
		out = binary.BigEndian.AppendUint16(out, uint16(n))
	}
	if !masked {
		return append(out, payload...)
	}
	key := []byte{9, 8, 7, 6}
	out = append(out, key...)
	for i := 0; i < len(payload); i++ {
		out = append(out, payload[i]^key[i%4])
	}
	return out
}

func hashOf(s string) string {
	h := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(h[:])
}

const (
	testEnc  = 0x7000
	testDec  = 0x8000
	testSock = 4242
	testTGID = 77
)

func aeadRec(dir uint32, self, sock uint64, payload []byte) sslRecord {
	return sslRecord{hdr: tlsbpfSslFrameHdr{Tgid: testTGID, Ssl: self, Sock: sock, Len: uint32(len(payload)), Total: uint32(len(payload)), Dir: dir, Method: 1}, payload: payload}
}

const upgradeReq = "GET /backend-api/codex/responses?v=2 HTTP/1.1\r\nHost: chatgpt.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: x\r\n\r\n"
const accept101 = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"

func drain(o *Observer) []models.GroundTruthEvent {
	var out []models.GroundTruthEvent
	for {
		select {
		case e := <-o.events:
			out = append(out, e)
		default:
			return out
		}
	}
}

// A rustls WebSocket session: the upgrade from an encrypter, its bind to a
// socket, the 101 and server frames read on that socket, client messages
// as net_request and the server's messages between them as one turn.
func TestAEAD_WebSocketSession(t *testing.T) {
	o := newTestObserver()
	o.events = make(chan models.GroundTruthEvent, 64)
	t0 := time.Unix(1000, 0)
	at := func(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }

	o.handleAEADRecord(aeadRec(sslDirWrite, testEnc, 0, []byte(upgradeReq)), at(0))
	o.handleAEADRecord(aeadRec(sslDirBind, testEnc, testSock, nil), at(0))
	// The 101 and the first server frame in one record.
	o.handleAEADRecord(aeadRec(sslDirRead, testDec, testSock, append([]byte(accept101), wsFrameBytes(0x1, false, `{"type":"hello"}`)...)), at(1))
	m1 := `{"type":"response.create","input":[{"role":"user"}]}`
	o.handleAEADRecord(aeadRec(sslDirWrite, testEnc, 0, wsFrameBytes(0x1, true, m1)), at(2))
	o.handleAEADRecord(aeadRec(sslDirRead, testDec, testSock, wsFrameBytes(0x1, false, `{"type":"response.output_text.delta","delta":"hi"}`)), at(3))
	o.handleAEADRecord(aeadRec(sslDirRead, testDec, testSock, append(wsFrameBytes(0x9, false, ""), wsFrameBytes(0x1, false, `{"type":"response.completed"}`)...)), at(4))
	m2 := `{"type":"response.create","previous_response_id":"r1"}`
	o.handleAEADRecord(aeadRec(sslDirWrite, testEnc, 0, wsFrameBytes(0x1, true, m2)), at(5))
	o.flushResponses()

	evs := drain(o)
	type ev struct {
		typ    models.ActionType
		target string
		hash   string
		status int
		ws     *models.WebSocketSummary
	}
	var got []ev
	for _, e := range evs {
		x := ev{typ: e.ActionType, target: e.Target}
		if e.RequestHash != nil {
			x.hash = *e.RequestHash
		}
		if e.Response != nil {
			x.status = e.Response.Status
			x.ws = e.Response.WebSocket
			if !e.Response.Paired {
				t.Errorf("response %s not paired", e.Target)
			}
		}
		got = append(got, x)
	}
	wsTarget := "WS https://chatgpt.com/backend-api/codex/responses?v=2"
	want := []ev{
		{typ: models.NetRequest, target: "GET https://chatgpt.com/backend-api/codex/responses?v=2"},
		{typ: models.NetResponse, target: "GET https://chatgpt.com/backend-api/codex/responses?v=2", status: 101},
		{typ: models.NetResponse, target: wsTarget, status: 101, ws: &models.WebSocketSummary{Messages: 1, Types: map[string]int{"hello": 1}}},
		{typ: models.NetRequest, target: wsTarget, hash: hashOf(m1)},
		{typ: models.NetResponse, target: wsTarget, status: 101, ws: &models.WebSocketSummary{Messages: 2, Types: map[string]int{"response.output_text.delta": 1, "response.completed": 1}}},
		{typ: models.NetRequest, target: wsTarget, hash: hashOf(m2)},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("events:\n%+v\nwant\n%+v", got, want)
	}
	turn := evs[4].Response
	wantHash := hashOf(`{"type":"response.output_text.delta","delta":"hi"}` + `{"type":"response.completed"}`)
	if !turn.Complete || turn.BodyHash != wantHash || !evs[4].Timestamp.Equal(at(3)) || !turn.End.Equal(at(4)) {
		t.Errorf("turn %+v at %v, want complete with hash %s from %v to %v", turn, evs[4].Timestamp, wantHash, at(3), at(4))
	}
	c := o.coverage
	if c.WebSockets != 1 || c.WSAccepted != 1 || c.WSRequests != 2 || c.WSServerMessages != 3 || c.Responses != 3 || c.AEADUnvalidated != 0 || c.AEADUnbound != 0 {
		t.Errorf("coverage %+v", c)
	}
	if len(o.tlsConns) != 0 {
		t.Errorf("%d connection keys left after the flush", len(o.tlsConns))
	}
}

// Frames before their direction validated are counted and dropped; a read
// with no socket is kept by its decrypter, unpaired; a rebind is ignored.
func TestAEAD_ValidationAndBinding(t *testing.T) {
	o := newTestObserver()
	o.events = make(chan models.GroundTruthEvent, 64)
	ts := time.Unix(1, 0)
	o.handleAEADRecord(aeadRec(sslDirRead, testDec, testSock, []byte("\x17garbage")), ts)
	o.handleAEADRecord(aeadRec(sslDirWrite, testEnc, 0, []byte("not http")), ts)
	if o.coverage.AEADUnvalidated != 2 || o.aeadWriteValid || o.aeadReadValid {
		t.Fatalf("unvalidated %d, valid %v/%v", o.coverage.AEADUnvalidated, o.aeadWriteValid, o.aeadReadValid)
	}
	o.handleAEADRecord(aeadRec(sslDirWrite, testEnc, 0, []byte("GET /x HTTP/1.1\r\nHost: h.example\r\n\r\n")), ts)
	o.handleAEADRecord(aeadRec(sslDirBind, testEnc, testSock, nil), ts)
	o.handleAEADRecord(aeadRec(sslDirBind, testEnc, testSock+1, nil), ts)
	if o.coverage.AEADRebound != 1 || o.aeadBound[sslKey{tgid: testTGID, kind: keyAEADEnc, ssl: testEnc}] != testSock {
		t.Errorf("rebound %d, bound %v", o.coverage.AEADRebound, o.aeadBound)
	}
	o.handleAEADRecord(aeadRec(sslDirRead, testDec, 0, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")), ts)
	if o.coverage.AEADUnbound != 1 || o.coverage.ResponsesUnattributed != 1 {
		t.Errorf("unbound %d unattributed %d: a read with no socket has no request", o.coverage.AEADUnbound, o.coverage.ResponsesUnattributed)
	}
	o.handleAEADRecord(aeadRec(sslDirRead, testDec, testSock, []byte("HTTP/1.1 204 No Content\r\n\r\n")), ts)
	evs := drain(o)
	if len(evs) != 2 || evs[1].ActionType != models.NetResponse || evs[1].Target != "GET https://h.example/x" || !evs[1].Response.Paired {
		t.Errorf("events %+v, want the request and its paired response", evs)
	}
}

// An accept that negotiates an extension the parser cannot decode refuses
// both directions: no WebSocket message is emitted, the refusal is counted
// once with its reason (N-43).
func TestWebSocket_ExtensionRefused(t *testing.T) {
	for _, tc := range []struct{ ext, reason string }{
		{"x-webkit-deflate-frame", `unsupported extension "x-webkit-deflate-frame"`},
		{"permessage-deflate; client_max_window_bits", `permessage-deflate parameter "client_max_window_bits" without a window size of 8 to 15`},
	} {
		o := newTestObserver()
		o.events = make(chan models.GroundTruthEvent, 64)
		o.readValid = true
		ts := time.Unix(1, 0)
		key := sslKey{tgid: 5, ssl: 9}
		o.handleSSLFrame(key, []byte(upgradeReq), 0, ts)
		o.handleSSLRead(key, []byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nSec-WebSocket-Extensions: "+tc.ext+"\r\n\r\n"), 0, ts)
		o.handleSSLFrame(key, wsFrameBytes(0x1, true, "compressed?"), 0, ts)
		o.handleSSLRead(key, wsFrameBytes(0x1, false, "x"), 0, ts)
		o.flushResponses()
		evs := drain(o)
		c := o.coverage
		if len(evs) != 2 || c.WSRefused != 1 || c.WSRequests != 0 || c.FramesUnattributed != 0 || c.ResponsesUnparsed != 0 || !reflect.DeepEqual(c.WSRefusedReasons, map[string]int{tc.reason: 1}) {
			t.Errorf("%s: events %d, coverage %+v", tc.ext, len(evs), c)
		}
	}
}

// deflateMessages compresses messages as one permessage-deflate sender
// with context takeover: each flushed, the trailing 0x00 0x00 0xff 0xff
// removed.
func deflateMessages(t *testing.T, msgs ...string) [][]byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	for _, m := range msgs {
		start := buf.Len()
		_, _ = w.Write([]byte(m))
		_ = w.Flush()
		z := buf.Bytes()[start:]
		out = append(out, append([]byte(nil), z[:len(z)-4]...))
	}
	return out
}

// compressed sets RSV1 on a single-frame message.
func compressed(frame []byte) []byte {
	frame[0] |= 0x40
	return frame
}

// A permessage-deflate session (N-43): the client's first message, written
// before the 101 was read, is held until the accept says what was agreed;
// both directions decode with context takeover; requests and turns hash
// the decompressed payloads, the model request digest included, and a
// turn starts at its first message's first frame.
func TestWebSocket_PermessageDeflate(t *testing.T) {
	o := newTestObserver()
	o.events = make(chan models.GroundTruthEvent, 64)
	o.readValid = true
	t0 := time.Unix(1, 0)
	at := func(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }
	key := sslKey{tgid: 5, ssl: 9}
	item := `{"type":"message","role":"user","content":[{"type":"input_text","text":"hello hello hello"}]}`
	m1 := `{"type":"response.create","input":[` + item + `]}`
	m2 := `{"type":"response.create","previous_response_id":"resp_1","input":[` + item + `]}`
	s1 := `{"type":"response.created","response":{"id":"resp_1"}}`
	s2 := `{"type":"response.completed","response":{"id":"resp_1","status":"completed"}}`
	cz := deflateMessages(t, m1, m2)
	sz := deflateMessages(t, s1, s2)
	req := strings.Replace(upgradeReq, "\r\n\r\n", "\r\nSec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n\r\n", 1)
	o.handleSSLFrame(key, []byte(req), 0, at(0))
	o.handleSSLFrame(key, compressed(wsFrameBytes(0x1, true, string(cz[0]))), 0, at(1))
	if o.coverage.WSRequests != 0 {
		t.Fatal("a client frame was parsed before the accept")
	}
	o.handleSSLRead(key, []byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nSec-WebSocket-Extensions: permessage-deflate; client_max_window_bits=15\r\n\r\n"), 0, at(2))
	// The first server message in two frames, the last read later.
	f := compressed(wsFrameBytes(0x1, false, string(sz[0][:2])))
	f[0] &^= 0x80
	o.handleSSLRead(key, f, 0, at(3))
	o.handleSSLRead(key, append(wsFrameBytes(0x0, false, string(sz[0][2:])), compressed(wsFrameBytes(0x1, false, string(sz[1])))...), 0, at(4))
	o.handleSSLFrame(key, compressed(wsFrameBytes(0x1, true, string(cz[1]))), 0, at(5))
	evs := drain(o)
	var wsReqs, turns []models.GroundTruthEvent
	for _, e := range evs {
		if !strings.HasPrefix(e.Target, "WS ") {
			continue
		}
		if e.ActionType == models.NetRequest {
			wsReqs = append(wsReqs, e)
		} else {
			turns = append(turns, e)
		}
	}
	if len(wsReqs) != 2 || *wsReqs[0].RequestHash != hashOf(m1) || *wsReqs[1].RequestHash != hashOf(m2) || !wsReqs[0].Timestamp.Equal(at(1)) {
		t.Fatalf("requests %+v, want the hashes of the decompressed messages", wsReqs)
	}
	h, _ := tlsparse.ResponsesItemHash([]byte(item))
	if d := wsReqs[1].ModelRequest; d == nil || d.PreviousResponseID != "resp_1" || len(d.Items) != 1 || d.Items[0].Hash != h {
		t.Errorf("digest %+v", d)
	}
	if len(turns) != 1 || turns[0].Response.BodyHash != hashOf(s1+s2) || turns[0].Response.BodyBytes != int64(len(s1+s2)) || !turns[0].Timestamp.Equal(at(3)) ||
		!reflect.DeepEqual(turns[0].Response.WebSocket.ResponseIDs, []string{"resp_1"}) {
		t.Errorf("turns %+v, want one of the decompressed server messages from %v", turns, at(3))
	}
	if c := o.coverage; c.WSDeflate != 1 || c.WSRefused != 0 || c.WSUnparsed != 0 || c.WSModelRequests != 2 {
		t.Errorf("coverage %+v", c)
	}
}

// The WebSocket layer runs on the SSL side's streams too, and a malformed
// client frame ends only that direction.
func TestWebSocket_SSLSideAndMalformedFrame(t *testing.T) {
	o := newTestObserver()
	o.events = make(chan models.GroundTruthEvent, 64)
	o.readValid = true
	ts := time.Unix(1, 0)
	key := sslKey{tgid: 5, ssl: 9}
	o.handleSSLFrame(key, append([]byte(upgradeReq), wsFrameBytes(0x2, true, "early")...), 0, ts)
	o.handleSSLRead(key, []byte(accept101), 0, ts)
	o.handleSSLRead(key, wsFrameBytes(0x2, false, "bin"), 0, ts)
	o.handleSSLFrame(key, wsFrameBytes(0x1, false, "unmasked client frame"), 0, ts)
	o.handleSSLRead(key, wsFrameBytes(0x8, false, ""), 0, ts)
	evs := drain(o)
	var kinds []string
	for _, e := range evs {
		kinds = append(kinds, string(e.ActionType)+" "+strings.SplitN(e.Target, " ", 2)[0])
	}
	want := []string{"net_request GET", "net_request WS", "net_response GET", "net_response WS"}
	if !reflect.DeepEqual(kinds, want) {
		t.Fatalf("events %v, want %v", kinds, want)
	}
	if r := evs[3].Response; r.WebSocket == nil || r.WebSocket.Messages != 1 || r.WebSocket.Types["(binary)"] != 1 || !r.Complete {
		t.Errorf("turn %+v", r)
	}
	if o.coverage.WSUnparsed != 1 {
		t.Errorf("WSUnparsed %d, want 1", o.coverage.WSUnparsed)
	}
}

func TestPlanContent(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
		want contentPlan
		err  string
	}{
		{"none", Config{}, contentPlan{}, ""},
		{"ExePath is tls-symbols", Config{ExePath: "/c"}, contentPlan{sslMethod: MethodTLSSymbols, sslPath: "/c"}, ""},
		{"openssl-ex and rustls", Config{Content: []ContentMethod{{MethodOpenSSLEx, "/x"}, {MethodRustlsAEAD, "/x"}}}, contentPlan{sslMethod: MethodOpenSSLEx, sslPath: "/x", aeadPath: "/x"}, ""},
		{"go and openssl-ex", Config{Content: []ContentMethod{{MethodGoCrypto, "/g"}, {MethodOpenSSLEx, "/x"}}}, contentPlan{sslMethod: MethodOpenSSLEx, sslPath: "/x", goPath: "/g"}, ""},
		{"go twice", Config{Content: []ContentMethod{{MethodGoCrypto, "/g"}, {MethodGoCrypto, "/g"}}}, contentPlan{}, "given twice"},
		{"two SSL-side methods", Config{ExePath: "/c", Content: []ContentMethod{{MethodOpenSSLEx, "/x"}}}, contentPlan{}, "both hook SSL calls"},
		{"unknown", Config{Content: []ContentMethod{{"tls-go", "/x"}}}, contentPlan{}, "unknown content method"},
		{"no path", Config{Content: []ContentMethod{{MethodRustlsAEAD, ""}}}, contentPlan{}, "names no file"},
	} {
		got, err := planContent(tc.cfg)
		if tc.err != "" {
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("%s: err %v, want %q", tc.name, err, tc.err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%s: %+v, %v; want %+v", tc.name, got, err, tc.want)
		}
	}
}

// The probe's content state is active when any configured method's is
// (N-42); each method's state is in the diagnostics and MethodContent reads
// it.
func TestCaptureCoverage_ContentMethods(t *testing.T) {
	o := &Observer{plan: contentPlan{sslMethod: MethodOpenSSLEx, sslPath: "/x", aeadPath: "/x"}}
	cov := o.CaptureCoverage()
	if cov.Content != models.ContentAttachFailed || cov.Responses != models.ContentAttachFailed {
		t.Errorf("no method validated: content %s responses %s", cov.Content, cov.Responses)
	}
	o.aeadWriteValid, o.aeadReadValid = true, true
	cov = o.CaptureCoverage()
	if cov.Content != models.ContentActive || cov.Responses != models.ContentActive {
		t.Errorf("the rustls side validated: content %s responses %s, want active", cov.Content, cov.Responses)
	}
	want := map[string]models.ContentMethodState{
		MethodOpenSSLEx:  {Requests: models.ContentAttachFailed, Responses: models.ContentAttachFailed},
		MethodRustlsAEAD: {Requests: models.ContentActive, Responses: models.ContentActive},
	}
	if !reflect.DeepEqual(cov.Diagnostics.ContentMethods, want) {
		t.Errorf("methods %+v", cov.Diagnostics.ContentMethods)
	}
	if req, resp := cov.MethodContent(MethodOpenSSLEx); req != models.ContentAttachFailed || resp != models.ContentAttachFailed {
		t.Errorf("MethodContent(%s) = %s, %s", MethodOpenSSLEx, req, resp)
	}
	if req, _ := cov.MethodContent(MethodTLSSymbols); req != models.ContentIdentityOnly {
		t.Errorf("a method not configured reads %s, want identity_only", req)
	}
}

// A client message holding a Responses API request carries its digest, and
// a turn the response ids its messages named (P-42).
func TestWebSocket_ModelRequestDigest(t *testing.T) {
	o := newTestObserver()
	o.events = make(chan models.GroundTruthEvent, 64)
	o.readValid = true
	ts := time.Unix(1, 0)
	key := sslKey{tgid: 5, ssl: 9}
	o.handleSSLFrame(key, []byte(upgradeReq), 0, ts)
	o.handleSSLRead(key, []byte(accept101), 0, ts)
	item := `{"type":"custom_tool_call_output","call_id":"call_1","output":"seed\n"}`
	o.handleSSLFrame(key, wsFrameBytes(0x1, true, `{"type":"response.create","previous_response_id":"resp_0","input":[`+item+`]}`), 0, ts)
	o.handleSSLRead(key, wsFrameBytes(0x1, false, `{"type":"response.created","response":{"id":"resp_1"}}`), 0, ts)
	o.handleSSLRead(key, wsFrameBytes(0x1, false, `{"type":"response.completed","response":{"id":"resp_1","status":"completed"}}`), 0, ts)
	o.handleSSLFrame(key, wsFrameBytes(0x1, true, `not json`), 0, ts)
	evs := drain(o)
	var reqs []*models.ModelRequestDigest
	var ids []string
	for _, e := range evs {
		if e.ActionType == models.NetRequest && strings.HasPrefix(e.Target, "WS ") {
			reqs = append(reqs, e.ModelRequest)
		}
		if e.Response != nil && e.Response.WebSocket != nil {
			ids = e.Response.WebSocket.ResponseIDs
		}
	}
	h, _ := tlsparse.ResponsesItemHash([]byte(item))
	want := &models.ModelRequestDigest{Type: "response.create", PreviousResponseID: "resp_0", Items: []models.ModelItemDigest{{Type: "custom_tool_call_output", CallID: "call_1", Hash: h}}}
	if len(reqs) != 2 || !reflect.DeepEqual(reqs[0], want) || reqs[1] != nil {
		t.Errorf("digests %+v, want %+v and none for a message that is not a request", reqs, want)
	}
	if !reflect.DeepEqual(ids, []string{"resp_1"}) || o.coverage.WSModelRequests != 1 {
		t.Errorf("response ids %v, model requests %d", ids, o.coverage.WSModelRequests)
	}
}
