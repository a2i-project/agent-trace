package tlsparse

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func sum(b string) string {
	h := sha256.Sum256([]byte(b))
	return "sha256:" + hex.EncodeToString(h[:])
}

// feedAll feeds the reads in order and returns every response emitted, then
// those Close emits, with the number of errors Feed returned.
func feedAll(p *ResponseParser, reads ...string) ([]*Response, int) {
	var out []*Response
	emit := func(r *Response) { out = append(out, r) }
	errs := 0
	at := time.Unix(1000, 0)
	for _, r := range reads {
		at = at.Add(time.Second)
		if err := p.Feed([]byte(r), 0, at, emit); err != nil {
			errs++
		}
	}
	p.Close(at.Add(time.Second), emit)
	return out, errs
}

const sseBody = "event: message_start\ndata: {\"a\":1}\n\n" +
	": keep-alive comment\n\n" +
	"event: content_block_delta\r\ndata: x\r\ndata: y\r\n\r\n" +
	"data: no event field\r\r" +
	"event: message_stop\ndata: {}\n\n" +
	"event: no_data\n\n"

func chunked(body string, sizes ...int) string {
	var b strings.Builder
	for len(body) > 0 {
		n := len(body)
		if len(sizes) > 0 {
			n, sizes = sizes[0], sizes[1:]
			if n > len(body) {
				n = len(body)
			}
		}
		fmt.Fprintf(&b, "%x\r\n%s\r\n", n, body[:n])
		body = body[n:]
	}
	b.WriteString("0\r\n\r\n")
	return b.String()
}

func TestResponseParser_Framings(t *testing.T) {
	sseHead := "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\nrequest-id: req_011abc\r\nTransfer-Encoding: chunked\r\n\r\n"
	wantSSE := map[string]int{"message_start": 1, "content_block_delta": 1, "message": 1, "message_stop": 1}

	tests := []struct {
		name      string
		reads     []string
		status    []int
		bodies    []string // body each response hashes; "-" for no hash
		complete  []bool
		requestID string
		sse       map[string]int
	}{
		{
			name:     "content length",
			reads:    []string{"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"},
			status:   []int{200},
			bodies:   []string{"hello"},
			complete: []bool{true},
		},
		{
			name:      "chunked sse",
			reads:     []string{sseHead + chunked(sseBody, 7, 30, 1, 100)},
			status:    []int{200},
			bodies:    []string{sseBody},
			complete:  []bool{true},
			requestID: "req_011abc",
			sse:       wantSSE,
		},
		{
			name:     "two responses on one connection, the second split across reads",
			reads:    []string{"HTTP/1.1 204 No Content\r\n\r\nHTTP/1.1 200 OK\r\nContent-Le", "ngth: 3\r\n\r\nab", "c"},
			status:   []int{204, 200},
			bodies:   []string{"", "abc"},
			complete: []bool{true, true},
		},
		{
			name:     "interim response is not a response",
			reads:    []string{"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok"},
			status:   []int{201},
			bodies:   []string{"ok"},
			complete: []bool{true},
		},
		{
			name:     "chunked with trailer",
			reads:    []string{"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n3;ext=1\r\nabc\r\n0\r\nX-Trailer: 1\r\n\r\n"},
			status:   []int{200},
			bodies:   []string{"abc"},
			complete: []bool{true},
		},
		{
			name:     "close-delimited body ends with the capture, unhashed",
			reads:    []string{"HTTP/1.0 200 OK\r\n\r\npart one ", "part two"},
			status:   []int{200},
			bodies:   []string{"-"},
			complete: []bool{false},
		},
		{
			name:     "close-delimited body ended by a new status line",
			reads:    []string{"HTTP/1.0 200 OK\r\n\r\nold", "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"},
			status:   []int{200, 404},
			bodies:   []string{"-", ""},
			complete: []bool{false, true},
		},
		{
			name:     "body cut off by the end of the capture",
			reads:    []string{"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc"},
			status:   []int{200},
			bodies:   []string{"-"},
			complete: []bool{false},
		},
		{
			name:     "upgrade ends parsing",
			reads:    []string{"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n\x81\x05hello", "HTTP/1.1 200 OK\r\n\r\n"},
			status:   []int{101},
			bodies:   []string{""},
			complete: []bool{true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, errs := feedAll(NewResponseParser(), tt.reads...)
			if errs != 0 {
				t.Fatalf("%d errors", errs)
			}
			if len(got) != len(tt.status) {
				t.Fatalf("got %d responses %+v, want %d", len(got), got, len(tt.status))
			}
			for i, r := range got {
				if r.Status != tt.status[i] || r.Complete != tt.complete[i] {
					t.Errorf("response %d: status %d complete %v, want %d %v", i, r.Status, r.Complete, tt.status[i], tt.complete[i])
				}
				switch want := tt.bodies[i]; want {
				case "-":
					if r.BodyHash != "" {
						t.Errorf("response %d: BodyHash %q, want none", i, r.BodyHash)
					}
				default:
					if r.BodyHash != sum(want) || r.BodyBytes != int64(len(want)) {
						t.Errorf("response %d: %d bytes hash %s, want %d bytes of %q", i, r.BodyBytes, r.BodyHash, len(want), want)
					}
				}
				if r.Start.IsZero() || r.End.Before(r.Start) {
					t.Errorf("response %d: Start %v End %v", i, r.Start, r.End)
				}
			}
			if got[0].RequestID != tt.requestID {
				t.Errorf("RequestID = %q, want %q", got[0].RequestID, tt.requestID)
			}
			if tt.sse == nil {
				if got[0].SSE != nil {
					t.Errorf("SSE = %+v, want nil", got[0].SSE)
				}
				return
			}
			s := got[0].SSE
			if s == nil || s.Events != 4 || s.Overflow || fmt.Sprint(s.Types) != fmt.Sprint(tt.sse) {
				t.Errorf("SSE = %+v, want 4 events %v", s, tt.sse)
			}
		})
	}
}

// TestResponseParser_EverySplit feeds a keep-alive pair of responses split
// at every byte boundary, and one byte per read, and requires the same
// result as a single read.
func TestResponseParser_EverySplit(t *testing.T) {
	stream := "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n" + chunked(sseBody, 5, 9) +
		"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nX-Request-Id: abc\r\n\r\nbody"
	check := func(t *testing.T, got []*Response, errs int) {
		t.Helper()
		if errs != 0 || len(got) != 2 {
			t.Fatalf("errs %d, %d responses", errs, len(got))
		}
		if got[0].BodyHash != sum(sseBody) || got[0].SSE == nil || got[0].SSE.Events != 4 {
			t.Errorf("first: %+v sse %+v", got[0], got[0].SSE)
		}
		if got[1].BodyHash != sum("body") || got[1].RequestID != "abc" {
			t.Errorf("second: %+v", got[1])
		}
	}
	for i := 0; i <= len(stream); i++ {
		got, errs := feedAll(NewResponseParser(), stream[:i], stream[i:])
		check(t, got, errs)
	}
	var bytesOne []string
	for i := range stream {
		bytesOne = append(bytesOne, stream[i:i+1])
	}
	got, errs := feedAll(NewResponseParser(), bytesOne...)
	check(t, got, errs)
}

func TestResponseParser_HeadAnswerHasNoBody(t *testing.T) {
	p := NewResponseParser()
	p.Bodyless = func() bool { return true }
	got, errs := feedAll(p, "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	if errs != 0 || len(got) != 2 || !got[0].Complete || got[0].BodyBytes != 0 {
		t.Fatalf("errs %d, got %+v", errs, got)
	}
}

// TestResponseParser_MissingBytes covers reads the capture copied only in
// part: inside a body of known length the response is truncated and keeps
// its framing, elsewhere the stream is lost until a status line.
func TestResponseParser_MissingBytes(t *testing.T) {
	at := time.Unix(1, 0)
	t.Run("inside a content-length body", func(t *testing.T) {
		p := NewResponseParser()
		var got []*Response
		emit := func(r *Response) { got = append(got, r) }
		if err := p.Feed([]byte("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc"), 4, at, emit); err != nil {
			t.Fatal(err)
		}
		if err := p.Feed([]byte("xyz"), 0, at, emit); err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || !got[0].Complete || !got[0].Truncated || got[0].BodyHash != "" || got[0].BodyBytes != 10 {
			t.Fatalf("got %+v", got)
		}
	})
	t.Run("inside an event stream", func(t *testing.T) {
		p := NewResponseParser()
		var got []*Response
		emit := func(r *Response) { got = append(got, r) }
		head := "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 40\r\n\r\ndata: 1\n\n"
		if err := p.Feed([]byte(head), 31, at, emit); err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].SSE == nil || got[0].SSE.Events != 1 || !got[0].SSE.Overflow || !got[0].Truncated {
			t.Fatalf("got %+v", got)
		}
	})
	t.Run("in a header block", func(t *testing.T) {
		p := NewResponseParser()
		var got []*Response
		emit := func(r *Response) { got = append(got, r) }
		if err := p.Feed([]byte("HTTP/1.1 200 OK\r\nCont"), 10, at, emit); !errors.Is(err, ErrMalformedResponse) {
			t.Fatalf("err = %v", err)
		}
		// Skipped until a read begins with a status line.
		if err := p.Feed([]byte("ent-Length: 0\r\n\r\n"), 0, at, emit); err != nil {
			t.Fatal(err)
		}
		if err := p.Feed([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), 0, at, emit); err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].BodyHash != sum("") {
			t.Fatalf("got %+v", got)
		}
	})
}

// TestResponseParser_Unparsed covers bytes that are not an HTTP/1.x response
// and the resynchronization on the next status line.
func TestResponseParser_Unparsed(t *testing.T) {
	tests := []struct {
		name  string
		reads []string
		errs  int
		got   int // responses emitted
	}{
		{"not http", []string{"\x00\x00\x12\x04 h2 frame"}, 1, 0},
		{"bad status code", []string{"HTTP/1.1 2x0 OK\r\n\r\n"}, 1, 0},
		{"conflicting lengths", []string{"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n"}, 1, 0},
		{"bad chunk size", []string{"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n"}, 1, 1},
		{"missing chunk CRLF", []string{"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\naXY"}, 1, 1},
		{"header block too large", []string{"HTTP/1.1 200 OK\r\nX: " + strings.Repeat("a", maxResponseHeader)}, 1, 0},
		{"chunk line too long", []string{"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + strings.Repeat("0", maxChunkLine+1)}, 1, 1},
		{"resync", []string{"garbage", "more garbage", "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx"}, 1, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, errs := feedAll(NewResponseParser(), tt.reads...)
			if errs != tt.errs || len(got) != tt.got {
				t.Fatalf("errs %d responses %d (%+v), want %d %d", errs, len(got), got, tt.errs, tt.got)
			}
			for _, r := range got {
				if tt.name != "resync" && (r.Complete || r.BodyHash != "") {
					t.Errorf("a response cut off by bytes that did not parse is complete: %+v", r)
				}
			}
		})
	}
}

func TestResponseParser_HeaderValues(t *testing.T) {
	long := strings.Repeat("r", maxRequestID+1)
	got, _ := feedAll(NewResponseParser(),
		"HTTP/1.1 200 OK\r\nRequest-Id: req_1\r\nX-Request-Id: other\r\nContent-Type: Application/JSON; charset=utf-8\r\nContent-Encoding: GZIP\r\nContent-Length: 0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nRequest-Id: "+long+"\r\nContent-Length: 0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nRequest-Id: bad\x01id\r\nContent-Length: 0\r\n\r\n")
	if len(got) != 3 {
		t.Fatalf("got %d", len(got))
	}
	if got[0].RequestID != "req_1" || got[0].ContentType != "application/json" || got[0].ContentEncoding != "gzip" {
		t.Errorf("first: %+v", got[0])
	}
	if got[1].RequestID != "" || got[2].RequestID != "" {
		t.Errorf("unbounded or unprintable request ids kept: %q %q", got[1].RequestID, got[2].RequestID)
	}
}

func TestResponseParser_CompressedEventStream(t *testing.T) {
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	_, _ = w.Write([]byte(sseBody))
	_ = w.Close()
	body := gz.String()
	head := "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n"
	got, errs := feedAll(NewResponseParser(), head+chunked(body, 10))
	if errs != 0 || len(got) != 1 {
		t.Fatalf("errs %d got %d", errs, len(got))
	}
	r := got[0]
	if r.BodyHash != sum(body) || r.SSE == nil || r.SSE.Events != 4 {
		t.Errorf("got %+v sse %+v; the hash is of the coded body, the events of the decoded one", r, r.SSE)
	}

	head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Encoding: br\r\nContent-Length: 3\r\n\r\nabc"
	got, _ = feedAll(NewResponseParser(), head)
	if len(got) != 1 || got[0].SSE != nil || got[0].BodyHash != sum("abc") {
		t.Errorf("an undecodable coding: %+v", got)
	}
}

func TestSSEParser_Bounds(t *testing.T) {
	s := newSSEParser()
	for i := 0; i < maxSSETypes+3; i++ {
		s.write([]byte(fmt.Sprintf("event: t%d\ndata: x\n\n", i)))
	}
	s.write([]byte("event: " + strings.Repeat("n", maxSSETypeLen+1) + "\ndata: x\n\n"))
	if s.stats.Events != maxSSETypes+4 || len(s.stats.Types) != maxSSETypes+1 || s.stats.Types[sseOtherType] != 4 {
		t.Errorf("stats %+v", s.stats)
	}
	s.write([]byte("data: " + strings.Repeat("x", maxSSELine)))
	if !s.stats.Overflow {
		t.Error("a line over the bound did not overflow")
	}
	s.write([]byte("\n\n"))
	if s.stats.Events != maxSSETypes+4 {
		t.Error("counting continued after overflow")
	}
}

func FuzzResponseParser(f *testing.F) {
	f.Add([]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/event-stream\r\n\r\n5\r\ndata:\r\n0\r\n\r\n"), 3, 0)
	f.Add([]byte("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabcdHTTP/1.1 204 x\r\n\r\n"), 10, 2)
	f.Fuzz(func(t *testing.T, data []byte, split int, missing int) {
		p := NewResponseParser()
		emit := func(r *Response) {
			if r.BodyHash != "" && (!r.Complete || r.Truncated) {
				t.Fatalf("hash on an incomplete response: %+v", r)
			}
		}
		if split < 0 || split > len(data) {
			split = len(data) / 2
		}
		if missing < 0 || missing > 1<<20 {
			missing = 0
		}
		_ = p.Feed(data[:split], 0, time.Unix(1, 0), emit)
		_ = p.Feed(data[split:], missing, time.Unix(2, 0), emit)
		p.Close(time.Unix(3, 0), emit)
	})
}
