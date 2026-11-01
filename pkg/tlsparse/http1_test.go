package tlsparse

import (
	"strconv"
	"testing"
)

func parseOne(t *testing.T, s *Stream) *HTTPRequest {
	t.Helper()
	req, ok, err := ParseHTTP1(s)
	if err != nil {
		t.Fatalf("ParseHTTP1 error: %v", err)
	}
	if !ok {
		t.Fatalf("ParseHTTP1 reported incomplete, want complete")
	}
	return req
}

func TestParseHTTP1_SplitMidRequestLine(t *testing.T) {
	s := NewStream()
	s.Append([]byte("GET /v1/mess"))
	if _, ok, err := ParseHTTP1(s); err != nil || ok {
		t.Fatalf("ok=%v err=%v, want incomplete", ok, err)
	}
	s.Append([]byte("ages HTTP/1.1\r\nHost: api.example.com\r\n\r\n"))
	req := parseOne(t, s)
	if req.Method != "GET" || req.Path != "/v1/messages" {
		t.Errorf("got method=%q path=%q", req.Method, req.Path)
	}
}

func TestParseHTTP1_SplitMidHeaders(t *testing.T) {
	s := NewStream()
	s.Append([]byte("POST /v1/messages HTTP/1.1\r\nHost: api.example.com\r\nContent-Le"))
	if _, ok, err := ParseHTTP1(s); err != nil || ok {
		t.Fatalf("ok=%v err=%v, want incomplete", ok, err)
	}
	s.Append([]byte("ngth: 5\r\n\r\nhello"))
	req := parseOne(t, s)
	if req.Method != "POST" || string(req.Body) != "hello" {
		t.Errorf("got method=%q body=%q", req.Method, req.Body)
	}
}

func TestParseHTTP1_SplitMidBody(t *testing.T) {
	s := NewStream()
	s.Append([]byte("POST /v1/messages HTTP/1.1\r\nContent-Length: 11\r\n\r\nhello "))
	if _, ok, err := ParseHTTP1(s); err != nil || ok {
		t.Fatalf("ok=%v err=%v, want incomplete", ok, err)
	}
	s.Append([]byte("world"))
	req := parseOne(t, s)
	if string(req.Body) != "hello world" {
		t.Errorf("body = %q, want %q", req.Body, "hello world")
	}
}

func TestParseHTTP1_PipelinedRequestsInOneChunk(t *testing.T) {
	s := NewStream()
	s.Append([]byte(
		"GET /a HTTP/1.1\r\nHost: h\r\n\r\n" +
			"GET /b HTTP/1.1\r\nHost: h\r\n\r\n"))

	first := parseOne(t, s)
	if first.Path != "/a" {
		t.Errorf("first.Path = %q, want /a", first.Path)
	}
	second := parseOne(t, s)
	if second.Path != "/b" {
		t.Errorf("second.Path = %q, want /b", second.Path)
	}
	if s.Len() != 0 {
		t.Errorf("stream has %d leftover bytes, want 0", s.Len())
	}
}

func TestParseHTTP1_ChunkedTransferEncoding(t *testing.T) {
	s := NewStream()
	s.Append([]byte(
		"POST /upload HTTP/1.1\r\n" +
			"Transfer-Encoding: chunked\r\n\r\n" +
			"5\r\nhello\r\n" +
			"6\r\n world\r\n" +
			"0\r\n\r\n"))

	req := parseOne(t, s)
	if string(req.Body) != "hello world" {
		t.Errorf("body = %q, want %q", req.Body, "hello world")
	}
	if s.Len() != 0 {
		t.Errorf("stream has %d leftover bytes after chunked body, want 0", s.Len())
	}
}

func TestParseHTTP1_ChunkedThenPipelinedRequest(t *testing.T) {
	s := NewStream()
	s.Append([]byte(
		"POST /upload HTTP/1.1\r\n" +
			"Transfer-Encoding: chunked\r\n\r\n" +
			"5\r\nhello\r\n" +
			"0\r\n\r\n" +
			"GET /next HTTP/1.1\r\nHost: h\r\n\r\n"))

	first := parseOne(t, s)
	if string(first.Body) != "hello" {
		t.Errorf("body = %q, want hello", first.Body)
	}
	second := parseOne(t, s)
	if second.Path != "/next" {
		t.Errorf("second.Path = %q, want /next (chunked decode must not over-consume)", second.Path)
	}
}

func TestParseHTTP1_ChunkedIncomplete(t *testing.T) {
	s := NewStream()
	s.Append([]byte(
		"POST /upload HTTP/1.1\r\n" +
			"Transfer-Encoding: chunked\r\n\r\n" +
			"5\r\nhel"))
	if _, ok, err := ParseHTTP1(s); err != nil || ok {
		t.Fatalf("ok=%v err=%v, want incomplete", ok, err)
	}
}

func TestParseHTTP1_NoBody(t *testing.T) {
	s := NewStream()
	s.Append([]byte("GET /health HTTP/1.1\r\nHost: h\r\n\r\n"))
	req := parseOne(t, s)
	if len(req.Body) != 0 {
		t.Errorf("body = %q, want empty", req.Body)
	}
}

func TestParseHTTP1_MalformedRequestLine(t *testing.T) {
	s := NewStream()
	s.Append([]byte("NOTAREQUESTLINE\r\n\r\n"))
	_, _, err := ParseHTTP1(s)
	if err == nil {
		t.Fatal("want error for malformed request line")
	}
}

func TestParseHTTP1_QueryVerbatim(t *testing.T) {
	s := NewStream()
	s.Append([]byte("GET /search?q=a+b&x=1 HTTP/1.1\r\nHost: h\r\n\r\n"))
	req := parseOne(t, s)
	if req.Path != "/search" || req.Query != "q=a+b&x=1" {
		t.Errorf("path=%q query=%q", req.Path, req.Query)
	}
}

// A request line is a method of capital letters, a target in an RFC 9112
// form and HTTP/1.0 or HTTP/1.1, and nothing else (N-34). The shape that
// motivated it: the tail of an earlier JSON body left in the stream ahead of
// the next request, with no space or line break in it, so that the whole
// tail read as the method.
func TestParseHTTP1_OnlyARequestLineIsARequest(t *testing.T) {
	for line, ok := range map[string]bool{
		"GET / HTTP/1.1":                                      true,
		"POST /api/v2/logs HTTP/1.1":                          true,
		"GET http://h/x HTTP/1.0":                             true,
		"GET https://h/x?y=1 HTTP/1.1":                        true,
		"OPTIONS * HTTP/1.1":                                  true,
		"CONNECT example.com:443 HTTP/1.1":                    true,
		`444","os":"linux","n":1}]POST /api/v2/logs HTTP/1.1`: false,
		"abcPOST /x HTTP/1.1":                                 false,
		"post /x HTTP/1.1":                                    false,
		"P /x HTTP/1.1":                                       false,
		"VERYLONGMETHOD /x HTTP/1.1":                          false,
		"GET x HTTP/1.1":                                      false,
		"GET * HTTP/1.1":                                      false,
		"CONNECT /x HTTP/1.1":                                 true, // origin form, any method
		"GET example.com:443 HTTP/1.1":                        false,
		"CONNECT a/b:443 HTTP/1.1":                            false,
		"GET /x HTTP/2.0":                                     false,
		"GET /x HTTP/1.1 trailing":                            false,
		"GET /x\x01y HTTP/1.1":                                false,
		"GET  /x HTTP/1.1":                                    false,
	} {
		s := NewStream()
		s.Append([]byte(line + "\r\nHost: h\r\n\r\n"))
		req, complete, err := ParseHTTP1(s)
		if ok && (err != nil || !complete || req == nil) {
			t.Errorf("%q: %v, complete %v, want a request", line, err, complete)
		}
		if !ok && (err != ErrMalformedRequest || req != nil) {
			t.Errorf("%q: %+v, %v, want ErrMalformedRequest", line, req, err)
		}
	}
}

// The synthesized stream of a write whose body bytes reached the stream
// twice, as an SSL_write retried with bytes it had already been called with
// would leave them: the first request ends at its Content-Length, the
// repeated tail stays buffered, and the next request arrives behind it. The
// next request line is then malformed, never a request with the tail as its
// method.
func TestParseHTTP1_ABodyTailAheadOfTheNextRequestIsNotARequest(t *testing.T) {
	body := `[{"message":"event_one","id":"00000000-1111-2222-3333-444444444444","os":"linux"}]`
	next := "POST /api/v2/logs HTTP/1.1\r\nHost: intake.example.com\r\nContent-Length: 2\r\n\r\n[]"
	s := NewStream()
	s.Append([]byte("POST /api/v2/logs HTTP/1.1\r\nHost: intake.example.com\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body + body[40:]))
	if req := parseOne(t, s); string(req.Body) != body {
		t.Fatalf("first body %q", req.Body)
	}
	if req, ok, err := ParseHTTP1(s); req != nil || ok || err != nil {
		t.Fatalf("the tail alone: %+v %v %v, want need-more-data", req, ok, err)
	}
	s.Append([]byte(next))
	if req, _, err := ParseHTTP1(s); req != nil || err != ErrMalformedRequest {
		t.Fatalf("the tail and the next request: %+v %v, want ErrMalformedRequest", req, err)
	}
}

func TestCutHTTP1(t *testing.T) {
	head := "POST /m HTTP/1.1\r\nHost: h.example.com\r\nContent-Length: 100\r\n\r\n"
	cases := []struct {
		name     string
		buf      string
		missing  int
		ok       bool
		skip     int
		err      bool
		consumed bool
	}{
		{name: "head and part of the body, the rest to come", buf: head + "0123456789", missing: 40, ok: true, skip: 50, consumed: true},
		{name: "missed bytes end the body exactly", buf: head + "0123456789", missing: 90, ok: true, skip: 0, consumed: true},
		{name: "missed bytes run past the body", buf: head + "0123456789", missing: 91, ok: true, skip: -1, consumed: true},
		{name: "chunked body", buf: "POST /c HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n10\r\nab", missing: 5, ok: true, skip: -1, consumed: true},
		{name: "head incomplete", buf: "POST /m HTTP/1.1\r\nHost: h.exa", missing: 5},
		{name: "complete request is not cut", buf: "GET / HTTP/1.1\r\nHost: h\r\n\r\n", missing: 5},
		{name: "malformed head", buf: "xPOST /m HTTP/1.1\r\nHost: h\r\n\r\n", missing: 5, err: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := NewStream()
			s.Append([]byte(tc.buf))
			req, skip, ok, err := CutHTTP1(s, tc.missing)
			if (err != nil) != tc.err || ok != tc.ok {
				t.Fatalf("ok %v err %v", ok, err)
			}
			if (s.Len() == 0) != tc.consumed {
				t.Errorf("%d bytes left", s.Len())
			}
			if !ok {
				return
			}
			if skip != tc.skip || req.Body != nil || req.Method != "POST" || req.Headers.Get("Host") == "" {
				t.Errorf("skip %d, request %+v", skip, req)
			}
		})
	}
}
