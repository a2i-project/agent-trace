package tlsparse

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func h2Frame(typ, flags byte, stream uint32, payload []byte) []byte {
	out := []byte{byte(len(payload) >> 16), byte(len(payload) >> 8), byte(len(payload)), typ, flags}
	out = binary.BigEndian.AppendUint32(out, stream)
	return append(out, payload...)
}

func h2Block(fields ...string) []byte {
	var b []byte
	for i := 0; i+1 < len(fields); i += 2 {
		b = append(b, encodeLiteral(fields[i], fields[i+1], i%4 == 0)...)
	}
	return b
}

type h2Req struct {
	stream               uint32
	method, host, path   string
	query, hash          string
	bodyLen              int64
	cut                  bool
	contentType, traceID string
}

func shaS(s string) string {
	h := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(h[:])
}

func reqOf(r *H2Request) h2Req {
	return h2Req{r.Stream, r.Method, r.Headers.Get("Host"), r.Path, r.Query, r.BodyHash, r.BodyLen, r.Cut, r.Headers.Get("Content-Type"), ""}
}

// Requests from synthetic frames: a POST whose body spans padded DATA
// frames and a header block split by CONTINUATION, a GET ended by its
// HEADERS, trailers, a reset stream, and the stream left open at the close.
func TestH2Client_Synthetic(t *testing.T) {
	var w []byte
	w = append(w, H2ClientPreface...)
	w = append(w, h2Frame(h2Settings, 0, 0, []byte{0, 4, 0, 0, 0xff, 0xff})...)
	blk := h2Block(":method", "POST", ":scheme", "https", ":authority", "api.example.com", ":path", "/v1/x?alt=sse", "content-type", "application/json")
	w = append(w, h2Frame(h2Headers, h2FlagPriority, 1, append([]byte{0, 0, 0, 0, 16}, blk[:7]...))...)
	w = append(w, h2Frame(h2Continuation, h2FlagEndHeaders, 1, blk[7:])...)
	w = append(w, h2Frame(h2Data, h2FlagPadded, 1, append(append([]byte{3}, "hello "...), 0, 0, 0))...)
	w = append(w, h2Frame(h2WindowUpdate, 0, 0, []byte{0, 0, 1, 0})...)
	w = append(w, h2Frame(h2Data, h2FlagEndStream, 1, []byte("world"))...)
	// Stream 3: indexed fields from the table the first block filled.
	w = append(w, h2Frame(h2Headers, h2FlagEndHeaders|h2FlagEndStream, 3, append(append([]byte{0x82, 0x87}, encodeLiteral(":authority", "api.example.com", false)...), 0x84))...)
	// Stream 5: body, then trailers end it.
	w = append(w, h2Frame(h2Headers, h2FlagEndHeaders, 5, h2Block(":method", "PUT", ":scheme", "https", ":path", "/t", ":authority", "api.example.com"))...)
	w = append(w, h2Frame(h2Data, 0, 5, []byte("abc"))...)
	w = append(w, h2Frame(h2Headers, h2FlagEndHeaders|h2FlagEndStream, 5, h2Block("x-trailer", "1"))...)
	// Stream 7: reset after part of its body.
	w = append(w, h2Frame(h2Headers, h2FlagEndHeaders, 7, h2Block(":method", "POST", ":scheme", "https", ":path", "/r", ":authority", "api.example.com"))...)
	w = append(w, h2Frame(h2Data, 0, 7, []byte("partial"))...)
	w = append(w, h2Frame(h2RstStream, 0, 7, []byte{0, 0, 0, 8})...)
	// Stream 9: open at the close. Stream 11: no :path, malformed.
	w = append(w, h2Frame(h2Headers, h2FlagEndHeaders, 9, h2Block(":method", "POST", ":scheme", "https", ":path", "/open", ":authority", "api.example.com"))...)
	w = append(w, h2Frame(h2Headers, h2FlagEndHeaders|h2FlagEndStream, 11, h2Block(":method", "GET", ":scheme", "https"))...)

	want := []h2Req{
		{stream: 1, method: "POST", host: "api.example.com", path: "/v1/x", query: "alt=sse", hash: shaS("hello world"), bodyLen: 11, contentType: "application/json"},
		{stream: 3, method: "GET", host: "api.example.com", path: "/"},
		{stream: 5, method: "PUT", host: "api.example.com", path: "/t", hash: shaS("abc"), bodyLen: 3},
		{stream: 7, method: "POST", host: "api.example.com", path: "/r", bodyLen: 7, cut: true},
		{stream: 9, method: "POST", host: "api.example.com", path: "/open", cut: true},
	}
	// Fed whole, byte by byte, and in uneven pieces: the same requests.
	for _, size := range []int{len(w), 1, 7, 100} {
		c := NewH2Client()
		var got []h2Req
		emit := func(r *H2Request) { got = append(got, reqOf(r)) }
		for i := 0; i < len(w); i += size {
			if err := c.Feed(w[i:min(i+size, len(w))], 0, time.Time{}, emit); err != nil {
				t.Fatalf("size %d: %v", size, err)
			}
		}
		if c.Head(9) == nil || c.Head(1) != nil {
			t.Errorf("size %d: Head(9) %v, Head(1) %v", size, c.Head(9), c.Head(1))
		}
		c.Close(emit)
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("size %d:\n got %v\nwant %v", size, got, want)
		}
		if c.Malformed != 1 {
			t.Errorf("size %d: Malformed %d, want 1", size, c.Malformed)
		}
	}
}

// Bytes missed inside a DATA payload cut that request and keep the framing;
// bytes missed anywhere else end the direction, and the requests in
// progress are emitted cut.
func TestH2Client_MissedBytes(t *testing.T) {
	head := append(append([]byte{}, H2ClientPreface...), h2Frame(h2Headers, h2FlagEndHeaders, 1, h2Block(":method", "POST", ":scheme", "https", ":path", "/a", ":authority", "h"))...)
	data := h2Frame(h2Data, h2FlagEndStream, 1, []byte("0123456789"))
	next := h2Frame(h2Headers, h2FlagEndHeaders|h2FlagEndStream, 3, h2Block(":method", "GET", ":scheme", "https", ":path", "/b", ":authority", "h"))

	c := NewH2Client()
	var got []h2Req
	emit := func(r *H2Request) { got = append(got, reqOf(r)) }
	// The write holds the DATA header and 4 bytes; 6 were missed.
	if err := c.Feed(append(append([]byte{}, head...), data[:9+4]...), 6, time.Time{}, emit); err != nil {
		t.Fatal(err)
	}
	if err := c.Feed(next, 0, time.Time{}, emit); err != nil {
		t.Fatal(err)
	}
	want := []h2Req{{stream: 1, method: "POST", host: "h", path: "/a", bodyLen: 10, cut: true}, {stream: 3, method: "GET", host: "h", path: "/b"}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("got %v, want %v", got, want)
	}

	c = NewH2Client()
	got = nil
	if err := c.Feed(append(append([]byte{}, head...), data[:3]...), 20, time.Time{}, emit); !errors.Is(err, ErrH2Missing) {
		t.Fatalf("err %v, want ErrH2Missing", err)
	}
	if len(got) != 1 || !got[0].cut || got[0].path != "/a" {
		t.Errorf("got %v, want /a cut", got)
	}
	if err := c.Feed(next, 0, time.Time{}, emit); !errors.Is(err, ErrH2Missing) {
		t.Errorf("a later feed: %v", err)
	}
}

func TestH2Client_ProtocolErrors(t *testing.T) {
	p := H2ClientPreface
	hdr := func(stream uint32) []byte {
		return h2Frame(h2Headers, 0, stream, h2Block(":method", "GET", ":scheme", "https", ":path", "/", ":authority", "h"))
	}
	for name, b := range map[string][]byte{
		"no preface":                []byte("GET / HTTP/1.1\r\n\r\n"),
		"DATA on stream 0":          append(append([]byte{}, p...), h2Frame(h2Data, 0, 0, []byte("x"))...),
		"interrupted header block":  append(append(append([]byte{}, p...), hdr(1)...), h2Frame(h2Data, 0, 1, nil)...),
		"continuation of no block":  append(append([]byte{}, p...), h2Frame(h2Continuation, h2FlagEndHeaders, 1, nil)...),
		"padding longer than frame": append(append([]byte{}, p...), h2Frame(h2Data, h2FlagPadded, 1, []byte{5, 'a'})...),
		"bad HPACK":                 append(append([]byte{}, p...), h2Frame(h2Headers, h2FlagEndHeaders, 1, []byte{0x80})...),
		"frame over the bound":      append(append([]byte{}, p...), 0x7f, 0xff, 0xff, h2Settings, 0, 0, 0, 0, 0),
	} {
		err := NewH2Client().Feed(b, 0, time.Time{}, func(*H2Request) {})
		if err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

type h2Resp struct {
	stream   uint32
	status   int
	reqID    string
	ctype    string
	bytes    int64
	hash     string
	complete bool
	trunc    bool
	events   int
}

func respOf(stream uint32, r *Response) h2Resp {
	x := h2Resp{stream, r.Status, r.RequestID, r.ContentType, r.BodyBytes, r.BodyHash, r.Complete, r.Truncated, 0}
	if r.SSE != nil {
		x.events = r.SSE.Events
	}
	return x
}

// Responses from synthetic frames: an interim 100 skipped, an event stream
// counted, a gzip body, trailers, a reset stream, missed body bytes and the
// stream open at the close.
func TestH2Server_Synthetic(t *testing.T) {
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write([]byte("data: a\n\ndata: b\n\n"))
	_ = zw.Close()
	var r []byte
	r = append(r, h2Frame(h2Settings, 0, 0, []byte{0, 3, 0, 0, 0, 100})...)
	r = append(r, h2Frame(h2Settings, 1, 0, nil)...)
	r = append(r, h2Frame(h2Headers, h2FlagEndHeaders, 1, h2Block(":status", "100"))...)
	r = append(r, h2Frame(h2Headers, h2FlagEndHeaders, 1, h2Block(":status", "200", "content-type", "text/event-stream; charset=utf-8", "x-request-id", "req-1"))...)
	r = append(r, h2Frame(h2Data, 0, 1, []byte("event: ping\ndata: 1\n\nda"))...)
	r = append(r, h2Frame(h2Data, h2FlagEndStream, 1, []byte("ta: 2\n\n"))...)
	r = append(r, h2Frame(h2Headers, h2FlagEndHeaders, 3, h2Block(":status", "200", "content-type", "text/event-stream", "content-encoding", "gzip"))...)
	r = append(r, h2Frame(h2Data, h2FlagEndStream, 3, gz.Bytes())...)
	r = append(r, h2Frame(h2Headers, h2FlagEndHeaders, 5, h2Block(":status", "404"))...)
	r = append(r, h2Frame(h2Data, 0, 5, []byte("nope"))...)
	r = append(r, h2Frame(h2Headers, h2FlagEndHeaders|h2FlagEndStream, 5, h2Block("grpc-status", "0"))...)
	r = append(r, h2Frame(h2Headers, h2FlagEndHeaders, 7, h2Block(":status", "200"))...)
	r = append(r, h2Frame(h2RstStream, 0, 7, []byte{0, 0, 0, 2})...)
	r = append(r, h2Frame(h2Headers, h2FlagEndHeaders|h2FlagEndStream, 9, h2Block(":status", "204"))...)
	r = append(r, h2Frame(h2Headers, h2FlagEndHeaders, 11, h2Block(":status", "200"))...)
	r = append(r, h2Frame(h2Data, 0, 11, []byte("part"))...)

	s := NewH2Server()
	var got []h2Resp
	emit := func(id uint32, x *Response) { got = append(got, respOf(id, x)) }
	if err := s.Feed(r, 0, time.Time{}, emit); err != nil {
		t.Fatal(err)
	}
	// Stream 13: 10 body bytes, 6 of them missed.
	d := h2Frame(h2Data, h2FlagEndStream, 13, []byte("0123456789"))
	if err := s.Feed(append(h2Frame(h2Headers, h2FlagEndHeaders, 13, h2Block(":status", "200")), d[:13]...), 6, time.Time{}, emit); err != nil {
		t.Fatal(err)
	}
	s.Close(time.Time{}, emit)
	want := []h2Resp{
		{stream: 1, status: 200, reqID: "req-1", ctype: "text/event-stream", bytes: 30, hash: shaS("event: ping\ndata: 1\n\ndata: 2\n\n"), complete: true, events: 2},
		{stream: 3, status: 200, ctype: "text/event-stream", bytes: int64(gz.Len()), hash: shaS(gz.String()), complete: true, events: 2},
		{stream: 5, status: 404, bytes: 4, hash: shaS("nope"), complete: true},
		{stream: 7, status: 200},
		{stream: 9, status: 204, hash: shaS(""), complete: true},
		{stream: 13, status: 200, bytes: 10, complete: true, trunc: true},
		{stream: 11, status: 200, bytes: 4},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("\n got %v\nwant %v", got, want)
	}
}

func TestH2ServerPrefaceAndFrameShape(t *testing.T) {
	settings := h2Frame(h2Settings, 0, 0, []byte{0, 3, 0, 0, 0, 100})
	if !IsH2ServerPreface(settings) {
		t.Error("a SETTINGS frame is the server preface")
	}
	for name, b := range map[string][]byte{
		"ack":           h2Frame(h2Settings, 1, 0, nil),
		"stream 1":      h2Frame(h2Settings, 0, 1, nil),
		"odd length":    h2Frame(h2Settings, 0, 0, []byte{1, 2, 3}),
		"status line":   []byte("HTTP/1.1 200 OK\r\n"),
		"short":         settings[:5],
		"headers frame": h2Frame(h2Headers, 4, 1, nil),
	} {
		if IsH2ServerPreface(b) {
			t.Errorf("%s read as a server preface", name)
		}
	}
	if !LooksLikeH2Frame(h2Frame(h2Headers, 4, 1, []byte("x"))) || !LooksLikeH2Frame(h2Frame(h2WindowUpdate, 0, 0, []byte{0, 0, 0, 1})) {
		t.Error("an h2 frame header not recognised")
	}
	if LooksLikeH2Frame([]byte("POST /x HTTP/1.1\r\n")) || LooksLikeH2Frame(h2Frame(h2Data, 0, 0, []byte("x"))) {
		t.Error("bytes that are no h2 frame recognised as one")
	}
}

// recConn records the bytes a connection wrote and read, one chunk per call.
type recConn struct {
	net.Conn
	mu            sync.Mutex
	writes, reads [][]byte
}

func (c *recConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.mu.Lock()
	c.writes = append(c.writes, append([]byte(nil), b[:n]...))
	c.mu.Unlock()
	return n, err
}

func (c *recConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.mu.Lock()
	if n > 0 {
		c.reads = append(c.reads, append([]byte(nil), b[:n]...))
	}
	c.mu.Unlock()
	return n, err
}

// A stream Go's own HTTP/2 client and server generate (h2c on loopback, so
// the bytes are the plaintext a TLS hook sees): several requests on one
// connection, whose header blocks Go's encoder writes with its dynamic
// table and Huffman coding, a large POST body split over DATA frames, and
// event-stream responses. The parsers must read every request and response
// as the client and server saw them.
func TestH2_GoGeneratedStream(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]string{} // path -> body hash, as the server read it
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen[r.URL.Path] = shaS(string(body))
		mu.Unlock()
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("X-Request-Id", "id-"+strings.TrimPrefix(r.URL.Path, "/"))
		for i := 0; i < 3; i++ {
			_, _ = fmt.Fprintf(w, "event: chunk\ndata: %d %s\n\n", i, r.URL.Path)
			w.(http.Flusher).Flush()
		}
	})}
	srv.Protocols = new(http.Protocols)
	srv.Protocols.SetUnencryptedHTTP2(true)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	var rc *recConn
	tr := &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		rc = &recConn{Conn: c}
		return rc, nil
	}}
	tr.Protocols = new(http.Protocols)
	tr.Protocols.SetUnencryptedHTTP2(true)
	client := &http.Client{Transport: tr}
	base := "http://" + ln.Addr().String()
	big := strings.Repeat("0123456789abcdef", 6000) // 96000 bytes, several DATA frames
	type call struct{ method, path, body string }
	calls := []call{{"POST", "/one", `{"q":1}`}, {"GET", "/two", ""}, {"POST", "/three", big}, {"POST", "/four", `{"q":4}`}}
	wantBodies := map[string]string{}
	for _, c := range calls {
		req, _ := http.NewRequest(c.method, base+c.path+"?alt=sse", strings.NewReader(c.body))
		if c.body == "" {
			req.Body = nil
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Goog-Api-Client", "test/1.0")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.ProtoMajor != 2 {
			t.Fatalf("%s spoke %s, want HTTP/2", c.path, resp.Proto)
		}
		wantBodies[c.path] = shaS(string(b))
	}
	tr.CloseIdleConnections()
	rc.mu.Lock()
	writes, reads := rc.writes, rc.reads
	rc.mu.Unlock()

	cl := NewH2Client()
	var reqs []*H2Request
	for _, w := range writes {
		if err := cl.Feed(w, 0, time.Time{}, func(r *H2Request) { reqs = append(reqs, r) }); err != nil {
			t.Fatalf("client direction: %v", err)
		}
	}
	if len(reqs) != len(calls) {
		t.Fatalf("%d requests, want %d", len(reqs), len(calls))
	}
	for i, c := range calls {
		r := reqs[i]
		if r.Method != c.method || r.Path != c.path || r.Query != "alt=sse" || r.Headers.Get("Host") != ln.Addr().String() || r.Cut {
			t.Errorf("request %d: %s %s ? %s host %s cut %v", i, r.Method, r.Path, r.Query, r.Headers.Get("Host"), r.Cut)
		}
		if r.Headers.Get("X-Goog-Api-Client") != "test/1.0" || r.Headers.Get("Content-Type") != "application/json" {
			t.Errorf("request %d: headers %v", i, r.Headers)
		}
		wantHash := ""
		if c.body != "" {
			wantHash = seen[c.path]
		}
		if r.BodyHash != wantHash || r.BodyLen != int64(len(c.body)) {
			t.Errorf("request %d: body %d bytes %s, want %d %s", i, r.BodyLen, r.BodyHash, len(c.body), wantHash)
		}
	}
	sv := NewH2Server()
	var resps []*Response
	for _, b := range reads {
		if err := sv.Feed(b, 0, time.Time{}, func(_ uint32, r *Response) { resps = append(resps, r) }); err != nil {
			t.Fatalf("server direction: %v", err)
		}
	}
	if len(resps) != len(calls) {
		t.Fatalf("%d responses, want %d", len(resps), len(calls))
	}
	for i, c := range calls {
		r := resps[i]
		if r.Status != 200 || !r.Complete || r.BodyHash != wantBodies[c.path] || r.SSE == nil || r.SSE.Events != 3 || r.RequestID != "id-"+c.path[1:] {
			t.Errorf("response %d: %+v", i, r)
		}
	}
	if len(cl.f.hp.dyn) == 0 || len(sv.f.hp.dyn) == 0 {
		t.Errorf("the dynamic tables stayed empty (%d, %d): the stream did not exercise them", len(cl.f.hp.dyn), len(sv.f.hp.dyn))
	}
}

func FuzzH2Client(f *testing.F) {
	f.Add(append(append([]byte{}, H2ClientPreface...), h2Frame(h2Headers, h2FlagEndHeaders|h2FlagEndStream, 1, h2Block(":method", "GET", ":scheme", "https", ":path", "/", ":authority", "h"))...))
	// END_STREAM on a stream never opened (a fuzzer's find).
	f.Add(append(append([]byte{}, H2ClientPreface...), h2Frame(h2Data, h2FlagEndStream, 0x30303030, nil)...))
	f.Fuzz(func(t *testing.T, b []byte) {
		c := NewH2Client()
		_ = c.Feed(b, 0, time.Time{}, func(*H2Request) {})
		c.Close(func(*H2Request) {})
		s := NewH2Server()
		_ = s.Feed(b, 0, time.Time{}, func(uint32, *Response) {})
		s.Close(time.Time{}, func(uint32, *Response) {})
	})
}
