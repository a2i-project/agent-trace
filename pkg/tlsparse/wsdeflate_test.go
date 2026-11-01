package tlsparse

import (
	"bytes"
	"compress/flate"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// deflater compresses messages as a permessage-deflate sender does: each
// message flushed, the trailing 0x00 0x00 0xff 0xff removed, the window
// kept across messages unless noTakeover.
type deflater struct {
	t          *testing.T
	noTakeover bool
	buf        bytes.Buffer
	w          *flate.Writer
}

func (d *deflater) message(p []byte) []byte {
	if d.w == nil || d.noTakeover {
		d.buf.Reset()
		w, err := flate.NewWriter(&d.buf, flate.BestCompression)
		if err != nil {
			d.t.Fatal(err)
		}
		d.w = w
	}
	start := d.buf.Len()
	if _, err := d.w.Write(p); err != nil {
		d.t.Fatal(err)
	}
	if err := d.w.Flush(); err != nil {
		d.t.Fatal(err)
	}
	out := append([]byte(nil), d.buf.Bytes()[start:]...)
	if !bytes.HasSuffix(out, []byte{0, 0, 0xff, 0xff}) {
		d.t.Fatalf("flush did not end with an empty stored block: % x", out)
	}
	return out[:len(out)-4]
}

// compressedFrames frames one compressed message: RSV1 on the first frame
// only, split into frames of at most size bytes (0: one frame).
func compressedFrames(op byte, masked bool, z []byte, size int) []byte {
	if size <= 0 || size > len(z) {
		size = max(len(z), 1)
	}
	var out []byte
	for i := 0; i == 0 || i < len(z); i += size {
		part := z[i:min(i+size, len(z))]
		o := byte(WSContinuation)
		if i == 0 {
			o = op
		}
		f := wsFrame(i+size >= len(z), o, masked, part)
		if i == 0 {
			f[0] |= 0x40
		}
		out = append(out, f...)
	}
	return out
}

func feedInflating(client, noTakeover bool, stream []byte, step int) wsResult {
	var r wsResult
	s := NewWSStream(client)
	s.Inflate(noTakeover)
	s.KeepText = 1 << 20
	s.OnData = func(p []byte) { r.data = append(r.data, p...) }
	if step <= 0 {
		step = len(stream) + 1
	}
	for i := 0; i < len(stream); i += step {
		if err := s.Feed(stream[i:min(i+step, len(stream))], 0, time.Unix(1, 0), func(m *WSMessage) {
			c := *m
			c.Start, c.End = time.Time{}, time.Time{}
			c.Body = append([]byte(nil), m.Body...)
			r.msgs = append(r.msgs, c)
		}, func(op byte) { r.ctl = append(r.ctl, op) }); err != nil {
			r.err = err
		}
	}
	return r
}

// Compressed messages decode in both directions, with and without context
// takeover, fragmented or not, chunked any way, and their hash, length,
// type and body are those of the decompressed payload.
func TestWSStream_Inflate(t *testing.T) {
	m1 := []byte(`{"type":"response.create","input":[{"role":"user","content":"` + strings.Repeat("abc ", 300) + `"}]}`)
	m2 := []byte(`{"type":"response.create","previous_response_id":"r1","input":[{"role":"user","content":"` + strings.Repeat("abc ", 300) + `"}]}`)
	m3 := []byte("plain after compressed")
	for _, client := range []bool{true, false} {
		for _, noTakeover := range []bool{false, true} {
			for _, size := range []int{0, 5} {
				d := &deflater{t: t, noTakeover: noTakeover}
				z1, z2 := d.message(m1), d.message(m2)
				if !noTakeover && len(z2) >= len(z1) {
					t.Fatalf("the second message (%d bytes) does not refer back into the first (%d)", len(z2), len(z1))
				}
				stream := append(compressedFrames(WSText, client, z1, size), compressedFrames(WSText, client, z2, size)...)
				stream = append(stream, wsFrame(true, WSBinary, client, m3)...)
				want := []WSMessage{
					{Text: true, Bytes: int64(len(m1)), Hash: sha(m1), Type: "response.create", Compressed: true, WireBytes: int64(len(z1)), Body: m1},
					{Text: true, Bytes: int64(len(m2)), Hash: sha(m2), Type: "response.create", Compressed: true, WireBytes: int64(len(z2)), Body: m2},
					{Bytes: int64(len(m3)), Hash: sha(m3), Frames: 1},
				}
				for i, z := range [][]byte{z1, z2} {
					want[i].Frames = 1
					if size > 0 {
						want[i].Frames = (len(z) + size - 1) / size
					}
				}
				for _, step := range []int{0, 1, 13} {
					r := feedInflating(client, noTakeover, stream, step)
					if r.err != nil {
						t.Fatalf("client %v noTakeover %v size %d step %d: %v", client, noTakeover, size, step, r.err)
					}
					if !reflect.DeepEqual(r.msgs, want) {
						t.Errorf("client %v noTakeover %v size %d step %d: messages\n%+v\nwant\n%+v", client, noTakeover, size, step, r.msgs, want)
					}
					if wantData := append(append(append([]byte(nil), m1...), m2...), m3...); !bytes.Equal(r.data, wantData) {
						t.Errorf("client %v noTakeover %v size %d step %d: OnData got %d bytes, want the %d decompressed", client, noTakeover, size, step, len(r.data), len(wantData))
					}
				}
			}
		}
	}
}

// A message that refers back into an earlier one does not decode on a
// stream agreed without context takeover, and the stream ends there.
func TestWSStream_InflateNeedsTheAgreedTakeover(t *testing.T) {
	m := []byte(strings.Repeat("the same words again ", 50))
	d := &deflater{t: t}
	stream := append(compressedFrames(WSText, false, d.message(m), 0), compressedFrames(WSText, false, d.message(m), 0)...)
	if r := feedInflating(false, false, stream, 0); r.err != nil || len(r.msgs) != 2 {
		t.Fatalf("with takeover: err %v, %d messages", r.err, len(r.msgs))
	}
	r := feedInflating(false, true, stream, 0)
	if !errors.Is(r.err, ErrWSInflate) || len(r.msgs) != 1 {
		t.Errorf("without takeover: err %v, %d messages; want ErrWSInflate after the first", r.err, len(r.msgs))
	}
}

// Edge cases of RFC 7692: an empty compressed message, a message ended by
// a final block (a sender that closes its compressor), a control frame
// between the fragments of a compressed message; and RSV1 where it is not
// allowed.
func TestWSStream_InflateEdges(t *testing.T) {
	var final bytes.Buffer
	w, _ := flate.NewWriter(&final, flate.DefaultCompression)
	_, _ = w.Write([]byte("closed"))
	_ = w.Close()
	d := &deflater{t: t}
	frag := d.message([]byte("fragmented message"))
	ping := wsFrame(true, WSPing, false, nil)
	withPing := append(append(compressedFrames(WSText, false, frag[:3], 0)[:0:0], compressedFrames(WSText, false, frag[:3], 0)...), ping...)
	withPing[0] &^= 0x80 // not the last frame
	withPing = append(withPing, wsFrame(true, WSContinuation, false, frag[3:])...)
	for _, tc := range []struct {
		name   string
		stream []byte
		want   string
	}{
		{"empty compressed message", compressedFrames(WSText, false, nil, 0), ""},
		{"empty stored block only", compressedFrames(WSText, false, d.message(nil), 0), ""},
		{"final block", compressedFrames(WSText, false, final.Bytes(), 0), "closed"},
		{"ping between fragments", withPing, "fragmented message"},
	} {
		r := feedInflating(false, false, tc.stream, 1)
		if r.err != nil || len(r.msgs) != 1 || string(r.msgs[0].Body) != tc.want || r.msgs[0].Hash != sha([]byte(tc.want)) {
			t.Errorf("%s: err %v, messages %+v", tc.name, r.err, r.msgs)
		}
	}
	rsv1Cont := append(wsFrame(false, WSText, false, []byte("a")), wsFrame(true, WSContinuation, false, []byte("b"))...)
	rsv1Cont[3] |= 0x40
	rsv1Ping := wsFrame(true, WSPing, false, nil)
	rsv1Ping[0] |= 0x40
	for name, stream := range map[string][]byte{"RSV1 on a continuation": rsv1Cont, "RSV1 on a control frame": rsv1Ping} {
		if r := feedInflating(false, false, stream, 0); !errors.Is(r.err, ErrWSProtocol) {
			t.Errorf("%s: err %v, want ErrWSProtocol", name, r.err)
		}
	}
	if r := feedInflating(false, false, compressedFrames(WSText, false, []byte{0xff, 0xff, 0xff}, 0), 0); !errors.Is(r.err, ErrWSInflate) || len(r.msgs) != 0 {
		t.Errorf("corrupt data: err %v, messages %d", r.err, len(r.msgs))
	}
}

func TestParseWSExtensions(t *testing.T) {
	for _, tc := range []struct {
		h      string
		want   *WSDeflate
		reason string
	}{
		{"", nil, ""},
		{"permessage-deflate", &WSDeflate{}, ""},
		{"permessage-deflate; client_max_window_bits=15; server_no_context_takeover", &WSDeflate{ClientMaxWindowBits: 15, ServerNoContextTakeover: true}, ""},
		{`permessage-deflate;server_max_window_bits="10";client_no_context_takeover`, &WSDeflate{ServerMaxWindowBits: 10, ClientNoContextTakeover: true}, ""},
		{"permessage-deflate; server_max_window_bits=8", &WSDeflate{ServerMaxWindowBits: 8}, ""},
		{"?", nil, "the extensions header is longer than 128 bytes or not printable"},
		{"x-webkit-deflate-frame", nil, `unsupported extension "x-webkit-deflate-frame"`},
		{"permessage-deflate, permessage-deflate", nil, `2 extensions negotiated: "permessage-deflate, permessage-deflate"`},
		{"permessage-deflate; client_max_window_bits", nil, `permessage-deflate parameter "client_max_window_bits" without a window size of 8 to 15`},
		{"permessage-deflate; server_max_window_bits=16", nil, `permessage-deflate parameter "server_max_window_bits" without a window size of 8 to 15`},
		{"permessage-deflate; server_max_window_bits=09", nil, `permessage-deflate parameter "server_max_window_bits" without a window size of 8 to 15`},
		{"permessage-deflate; server_no_context_takeover=1", nil, `permessage-deflate parameter "server_no_context_takeover" with a value`},
		{"permessage-deflate; server_no_context_takeover; server_no_context_takeover", nil, `permessage-deflate parameter "server_no_context_takeover" stated twice`},
		{"permessage-deflate; foo", nil, `unsupported permessage-deflate parameter "foo"`},
	} {
		got, err := ParseWSExtensions(tc.h)
		var xe *WSExtensionError
		switch {
		case tc.reason != "":
			if !errors.As(err, &xe) || xe.Reason != tc.reason || got != nil {
				t.Errorf("%q: %+v, %v; want the reason %q", tc.h, got, err, tc.reason)
			}
		case err != nil || !reflect.DeepEqual(got, tc.want):
			t.Errorf("%q: %+v, %v; want %+v", tc.h, got, err, tc.want)
		}
	}
}

func FuzzWSStreamInflate(f *testing.F) {
	d := &deflater{t: &testing.T{}}
	f.Add(false, false, append(compressedFrames(WSText, false, d.message([]byte(`{"type":"a"}`)), 0), compressedFrames(WSText, false, d.message([]byte(`{"type":"a"}`)), 3)...), uint8(2))
	f.Fuzz(func(t *testing.T, client, noTakeover bool, stream []byte, step uint8) {
		whole := feedInflating(client, noTakeover, stream, 0)
		parts := feedInflating(client, noTakeover, stream, int(step%16)+1)
		if !reflect.DeepEqual(whole.msgs, parts.msgs) || !bytes.Equal(whole.ctl, parts.ctl) || !errors.Is(parts.err, whole.err) {
			t.Fatalf("chunked feed differs: %+v vs %+v", whole, parts)
		}
	})
}
