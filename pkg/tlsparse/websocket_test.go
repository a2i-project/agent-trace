package tlsparse

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/textproto"
	"reflect"
	"testing"
	"time"
)

// wsFrame encodes one frame; a masked frame uses the key 0x37fa213d.
func wsFrame(fin bool, op byte, masked bool, payload []byte) []byte {
	b0 := op
	if fin {
		b0 |= 0x80
	}
	out := []byte{b0}
	m := byte(0)
	if masked {
		m = 0x80
	}
	switch n := len(payload); {
	case n < 126:
		out = append(out, m|byte(n))
	case n < 1<<16:
		out = append(out, m|126)
		out = binary.BigEndian.AppendUint16(out, uint16(n))
	default:
		out = append(out, m|127)
		out = binary.BigEndian.AppendUint64(out, uint64(n))
	}
	if !masked {
		return append(out, payload...)
	}
	key := []byte{0x37, 0xfa, 0x21, 0x3d}
	out = append(out, key...)
	for i, c := range payload {
		out = append(out, c^key[i%4])
	}
	return out
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

type wsResult struct {
	msgs []WSMessage
	ctl  []byte
	data []byte
	err  error
}

// feedWS feeds stream to a new parser in chunks of size step (0: whole).
func feedWS(client bool, stream []byte, step int) wsResult {
	var r wsResult
	s := NewWSStream(client)
	s.OnData = func(p []byte) { r.data = append(r.data, p...) }
	at := time.Unix(100, 0)
	if step <= 0 {
		step = len(stream) + 1
	}
	for i := 0; i < len(stream); i += step {
		chunk := stream[i:min(i+step, len(stream))]
		if err := s.Feed(chunk, 0, at, func(m *WSMessage) {
			c := *m
			c.Start, c.End = time.Time{}, time.Time{}
			r.msgs = append(r.msgs, c)
		}, func(op byte) { r.ctl = append(r.ctl, op) }); err != nil {
			r.err = err
		}
	}
	return r
}

func TestWSStream_Messages(t *testing.T) {
	long := bytes.Repeat([]byte("x"), 70000)
	mid := bytes.Repeat([]byte("y"), 200)
	cases := []struct {
		name   string
		client bool
		stream []byte
		want   []WSMessage
		ctl    []byte
		data   []byte
	}{
		{"masked client text", true, wsFrame(true, WSText, true, []byte("hello")),
			[]WSMessage{{Text: true, Bytes: 5, Hash: sha([]byte("hello")), Frames: 1}}, nil, []byte("hello")},
		{"JSON type first", true, wsFrame(true, WSText, true, []byte(`{"type":"response.create","input":[]}`)),
			[]WSMessage{{Text: true, Bytes: 37, Hash: sha([]byte(`{"type":"response.create","input":[]}`)), Frames: 1, Type: "response.create"}}, nil, nil},
		{"JSON type after nested members", false, wsFrame(true, WSText, false, []byte(`{"a":{"b":[1,{"type":"no"}]},"type":"done"}`)),
			[]WSMessage{{Text: true, Bytes: 43, Hash: sha([]byte(`{"a":{"b":[1,{"type":"no"}]},"type":"done"}`)), Frames: 1, Type: "done"}}, nil, nil},
		{"binary message has no type", false, wsFrame(true, WSBinary, false, []byte(`{"type":"x"}`)),
			[]WSMessage{{Bytes: 12, Hash: sha([]byte(`{"type":"x"}`)), Frames: 1}}, nil, nil},
		{"fragmented with a ping inside", true, append(append(wsFrame(false, WSText, true, []byte("hel")), wsFrame(true, WSPing, true, []byte("p"))...), wsFrame(true, WSContinuation, true, []byte("lo"))...),
			[]WSMessage{{Text: true, Bytes: 5, Hash: sha([]byte("hello")), Frames: 2}}, []byte{WSPing}, []byte("hello")},
		{"16-bit and 64-bit lengths", false, append(wsFrame(true, WSBinary, false, mid), wsFrame(true, WSBinary, false, long)...),
			[]WSMessage{{Bytes: 200, Hash: sha(mid), Frames: 1}, {Bytes: 70000, Hash: sha(long), Frames: 1}}, nil, nil},
		{"empty message", true, wsFrame(true, WSText, true, nil),
			[]WSMessage{{Text: true, Hash: sha(nil), Frames: 1}}, nil, nil},
		{"close ends the stream", false, append(append(wsFrame(true, WSPong, false, nil), wsFrame(true, WSClose, false, []byte{3, 232})...), wsFrame(true, WSText, false, []byte("after"))...),
			nil, []byte{WSPong, WSClose}, nil},
	}
	for _, tc := range cases {
		for _, step := range []int{0, 1, 3, 7} {
			r := feedWS(tc.client, tc.stream, step)
			if r.err != nil {
				t.Errorf("%s (step %d): %v", tc.name, step, r.err)
				continue
			}
			if !reflect.DeepEqual(r.msgs, tc.want) {
				t.Errorf("%s (step %d): messages %+v, want %+v", tc.name, step, r.msgs, tc.want)
			}
			if !bytes.Equal(r.ctl, tc.ctl) {
				t.Errorf("%s (step %d): control %v, want %v", tc.name, step, r.ctl, tc.ctl)
			}
			if tc.data != nil && !bytes.Equal(r.data, tc.data) {
				t.Errorf("%s (step %d): data %q, want %q", tc.name, step, r.data, tc.data)
			}
		}
	}
}

func TestWSStream_Refuses(t *testing.T) {
	rsv1 := wsFrame(true, WSText, true, []byte("z"))
	rsv1[0] |= 0x40
	rsv2 := wsFrame(true, WSText, false, []byte("z"))
	rsv2[0] |= 0x20
	huge := []byte{0x82, 127, 0x80, 0, 0, 0, 0, 0, 0, 0}
	cases := []struct {
		name   string
		client bool
		stream []byte
		want   error
	}{
		{"RSV1: compressed", true, rsv1, ErrWSCompressed},
		{"RSV2", false, rsv2, ErrWSProtocol},
		{"client frame not masked", true, wsFrame(true, WSText, false, []byte("a")), ErrWSProtocol},
		{"server frame masked", false, wsFrame(true, WSText, true, []byte("a")), ErrWSProtocol},
		{"continuation without a message", false, wsFrame(true, WSContinuation, false, []byte("a")), ErrWSProtocol},
		{"message inside a fragmented one", false, append(wsFrame(false, WSText, false, []byte("a")), wsFrame(true, WSText, false, []byte("b"))...), ErrWSProtocol},
		{"fragmented control frame", false, wsFrame(false, WSPing, false, nil), ErrWSProtocol},
		{"long control frame", false, wsFrame(true, WSPing, false, make([]byte, 126)), ErrWSProtocol},
		{"reserved opcode", false, wsFrame(true, 0x3, false, nil), ErrWSProtocol},
		{"length with the top bit set", false, huge, ErrWSProtocol},
	}
	for _, tc := range cases {
		r := feedWS(tc.client, tc.stream, 0)
		if !errors.Is(r.err, tc.want) {
			t.Errorf("%s: err %v, want %v", tc.name, r.err, tc.want)
		}
		if len(r.msgs) != 0 {
			t.Errorf("%s: messages %+v after the error", tc.name, r.msgs)
		}
	}
}

func TestWSStream_MissingBytesEndTheStream(t *testing.T) {
	s := NewWSStream(false)
	n := 0
	emit := func(*WSMessage) { n++ }
	if err := s.Feed(wsFrame(true, WSText, false, []byte("ok")), 0, time.Now(), emit, nil); err != nil || n != 1 {
		t.Fatalf("first frame: err %v, %d messages", err, n)
	}
	if err := s.Feed([]byte{0x81}, 10, time.Now(), emit, nil); !errors.Is(err, ErrWSMissing) {
		t.Fatalf("err %v, want ErrWSMissing", err)
	}
	if err := s.Feed(wsFrame(true, WSText, false, []byte("again")), 0, time.Now(), emit, nil); err != nil || n != 1 || s.Err() == nil {
		t.Errorf("after the hole: err %v, %d messages, Err %v; want nothing parsed", err, n, s.Err())
	}
}

func TestWSStream_Times(t *testing.T) {
	s := NewWSStream(true)
	t0, t1 := time.Unix(10, 0), time.Unix(11, 0)
	var got *WSMessage
	emit := func(m *WSMessage) { got = m }
	_ = s.Feed(wsFrame(false, WSBinary, true, []byte("a")), 0, t0, emit, nil)
	if !s.InMessage() {
		t.Fatal("InMessage false inside a fragmented message")
	}
	_ = s.Feed(wsFrame(true, WSContinuation, true, []byte("b")), 0, t1, emit, nil)
	if got == nil || !got.Start.Equal(t0) || !got.End.Equal(t1) || s.InMessage() {
		t.Errorf("message %+v, want Start %v End %v and no message in progress", got, t0, t1)
	}
}

func TestIsWebSocketUpgradeAndAccept(t *testing.T) {
	h := func(kv ...string) textproto.MIMEHeader {
		m := textproto.MIMEHeader{}
		for i := 0; i+1 < len(kv); i += 2 {
			m.Add(kv[i], kv[i+1])
		}
		return m
	}
	for _, tc := range []struct {
		name string
		req  *HTTPRequest
		want bool
	}{
		{"upgrade", &HTTPRequest{Method: "GET", Headers: h("Upgrade", "WebSocket", "Connection", "keep-alive, Upgrade")}, true},
		{"POST", &HTTPRequest{Method: "POST", Headers: h("Upgrade", "websocket", "Connection", "upgrade")}, false},
		{"h2c", &HTTPRequest{Method: "GET", Headers: h("Upgrade", "h2c", "Connection", "upgrade")}, false},
		{"no Connection token", &HTTPRequest{Method: "GET", Headers: h("Upgrade", "websocket", "Connection", "close")}, false},
		{"nil", nil, false},
	} {
		if got := IsWebSocketUpgrade(tc.req); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
	if !IsWebSocketAccept(&Response{Status: 101, Upgrade: "websocket"}) || IsWebSocketAccept(&Response{Status: 101, Upgrade: "h2c"}) || IsWebSocketAccept(&Response{Status: 200, Upgrade: "websocket"}) {
		t.Error("IsWebSocketAccept: wrong answer for 101 websocket, 101 h2c or 200")
	}
}

// A 101 response keeps its upgrade headers and the bytes after its head.
func TestResponseParser_UpgradeKeepsTheRest(t *testing.T) {
	p := NewResponseParser()
	frame := wsFrame(true, WSText, false, []byte("hi"))
	in := append([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: WebSocket\r\nConnection: Upgrade\r\nSec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n\r\n"), frame...)
	var got []*Response
	if err := p.Feed(in, 0, time.Now(), func(r *Response) { got = append(got, r) }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Status != 101 || got[0].Upgrade != "websocket" || got[0].Extensions != "permessage-deflate; client_max_window_bits" || !got[0].Complete {
		t.Fatalf("responses %+v", got)
	}
	if !p.Upgraded() || !bytes.Equal(p.TakeUpgraded(), frame) || p.TakeUpgraded() != nil {
		t.Error("the bytes after the head are not returned once")
	}
	if err := p.Feed([]byte("HTTP/1.1 200 OK\r\n\r\n"), 0, time.Now(), func(r *Response) { got = append(got, r) }); err != nil || len(got) != 1 {
		t.Error("an upgraded parser parsed more")
	}
}

func FuzzWSStream(f *testing.F) {
	f.Add(true, wsFrame(true, WSText, true, []byte(`{"type":"a"}`)), uint8(3))
	f.Add(false, append(wsFrame(false, WSText, false, []byte("x")), wsFrame(true, WSContinuation, false, []byte("y"))...), uint8(1))
	f.Fuzz(func(t *testing.T, client bool, stream []byte, step uint8) {
		whole := feedWS(client, stream, 0)
		parts := feedWS(client, stream, int(step%16)+1)
		if !reflect.DeepEqual(whole.msgs, parts.msgs) || !bytes.Equal(whole.ctl, parts.ctl) || !errors.Is(parts.err, whole.err) {
			t.Fatalf("chunked feed differs: %+v vs %+v", whole, parts)
		}
	})
}
