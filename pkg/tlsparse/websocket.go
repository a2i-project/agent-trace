package tlsparse

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"strings"
	"time"
)

// Errors that end the parsing of one direction of a WebSocket connection
// (RFC 6455). After one, the stream ignores what follows.
var (
	// ErrWSCompressed: a frame sets RSV1, which only an extension such as
	// permessage-deflate (RFC 7692) allows. Compressed payloads are not
	// decoded, so the stream is refused rather than hashed compressed.
	ErrWSCompressed = errors.New("tlsparse: compressed WebSocket frame (an extension is in use)")
	// ErrWSProtocol: bytes that are not a valid frame sequence for this
	// direction (reserved bits or opcodes, a client frame not masked or a
	// server frame masked, a fragmented or long control frame, a
	// continuation with no message, a new message inside a fragmented one).
	ErrWSProtocol = errors.New("tlsparse: malformed WebSocket frame")
	// ErrWSMissing: the capture missed bytes of the stream, after which no
	// frame boundary can be found again.
	ErrWSMissing = errors.New("tlsparse: WebSocket stream has missing bytes")
)

// WebSocket opcodes.
const (
	WSContinuation = 0x0
	WSText         = 0x1
	WSBinary       = 0x2
	WSClose        = 0x8
	WSPing         = 0x9
	WSPong         = 0xa
)

// Bounds of the WebSocket parser.
const (
	maxWSControl = 125     // payload of a control frame (RFC 6455, 5.5)
	wsTypePrefix = 4 << 10 // bytes of a text message kept to read its JSON "type"
	maxWSType    = 64
)

// WSMessage is one complete data message: a text or binary frame and its
// continuations. Its payload, unmasked, is hashed and counted as it streams;
// only the first 4 KiB of a text message are kept, until the message ends,
// to read its type.
type WSMessage struct {
	Text       bool   // opcode 1, else 2
	Bytes      int64  // payload length, all frames
	Hash       string // "sha256:<hex>" of the unmasked payload
	Frames     int
	Start, End time.Time // when its first and last frame were read
	// Type is the string value of the top-level "type" member when the
	// message is text holding a JSON object and the member, at most 64
	// printable bytes, is within its first 4 KiB; "" otherwise.
	Type string
	// ResponseID is the "id" of the top-level "response" object of such a
	// message, within its first 4 KiB (an OpenAI Responses API event names
	// its response so), at most 256 printable bytes; "" otherwise.
	ResponseID string
	// Body is the whole unmasked payload of a text message no longer than
	// the stream's KeepText, nil otherwise. It is valid only during the
	// onMessage call that receives the message, for a digest of it; the
	// plaintext is never kept (N-D3).
	Body []byte
}

// WSStream parses the frames of one direction of a WebSocket connection,
// from the bytes after the upgrade. Call Feed with each captured chunk.
type WSStream struct {
	// OnData, when set, receives the unmasked payload bytes of every data
	// frame, in order, as they are parsed.
	OnData func([]byte)
	// KeepText, when above zero, is the longest text message whose whole
	// payload is passed to onMessage as WSMessage.Body.
	KeepText int

	client bool // frames from the client, which must be masked
	err    error
	closed bool // a close frame was read; what follows is ignored

	hdr     []byte // the frame header read so far
	inFrame bool
	opcode  byte
	fin     bool
	masked  bool
	key     [4]byte
	left    int64 // payload bytes of the frame still to read
	pos     int64 // payload bytes of the frame read, for the mask

	msg    *WSMessage // message in progress, nil between messages
	hash   hash.Hash
	prefix []byte
	body   []byte // the whole text message while it fits KeepText
	over   bool   // the message outgrew KeepText
	ctl    []byte // control frame payload
}

// NewWSStream returns a parser for the client's frames (client true, which
// must be masked) or the server's (which must not be).
func NewWSStream(client bool) *WSStream {
	return &WSStream{client: client}
}

// Err is the error that ended the stream, or nil.
func (s *WSStream) Err() error { return s.err }

// Closed reports whether a close frame was read.
func (s *WSStream) Closed() bool { return s.closed }

// InMessage reports whether a data message has begun and not ended.
func (s *WSStream) InMessage() bool { return s.msg != nil }

// Feed consumes one chunk of the direction's bytes; missing is the number
// of bytes the capture did not copy after it. Each data message that ends
// is passed to onMessage, each control frame's opcode to onControl (either
// may be nil). It returns the error that ends the stream, once; later calls
// do nothing and return nil.
func (s *WSStream) Feed(data []byte, missing int, at time.Time, onMessage func(*WSMessage), onControl func(op byte)) error {
	if s.err != nil || s.closed {
		return nil
	}
	for len(data) > 0 && s.err == nil && !s.closed {
		if !s.inFrame {
			data = s.header(data)
			if s.inFrame && s.left == 0 {
				s.endFrame(at, onMessage, onControl)
			}
			continue
		}
		n := int64(len(data))
		if n > s.left {
			n = s.left
		}
		s.payload(data[:n], at)
		data = data[n:]
		s.left -= n
		if s.left == 0 {
			s.endFrame(at, onMessage, onControl)
		}
	}
	if s.err == nil && !s.closed && missing > 0 {
		s.err = ErrWSMissing
	}
	return s.err
}

// header reads frame header bytes and returns the bytes after them.
func (s *WSStream) header(data []byte) []byte {
	need := 2
	take := func() bool {
		for len(s.hdr) < need && len(data) > 0 {
			s.hdr = append(s.hdr, data[0])
			data = data[1:]
		}
		return len(s.hdr) >= need
	}
	if !take() {
		return data
	}
	b0, b1 := s.hdr[0], s.hdr[1]
	switch {
	case b0&0x40 != 0:
		s.err = ErrWSCompressed
		return nil
	case b0&0x30 != 0:
		s.err = ErrWSProtocol
		return nil
	}
	masked := b1&0x80 != 0
	if masked != s.client {
		s.err = ErrWSProtocol
		return nil
	}
	n7 := b1 & 0x7f
	switch n7 {
	case 126:
		need = 4
	case 127:
		need = 10
	}
	if masked {
		need += 4
	}
	if !take() {
		return data
	}
	var length uint64
	off := 2
	switch n7 {
	case 126:
		length = uint64(binary.BigEndian.Uint16(s.hdr[2:4]))
		off = 4
	case 127:
		length = binary.BigEndian.Uint64(s.hdr[2:10])
		off = 10
	default:
		length = uint64(n7)
	}
	if length>>63 != 0 {
		s.err = ErrWSProtocol
		return nil
	}
	op := b0 & 0x0f
	fin := b0&0x80 != 0
	switch op {
	case WSContinuation:
		if s.msg == nil {
			s.err = ErrWSProtocol
			return nil
		}
	case WSText, WSBinary:
		if s.msg != nil {
			s.err = ErrWSProtocol
			return nil
		}
	case WSClose, WSPing, WSPong:
		if !fin || length > maxWSControl {
			s.err = ErrWSProtocol
			return nil
		}
	default:
		s.err = ErrWSProtocol
		return nil
	}
	if masked {
		copy(s.key[:], s.hdr[off:off+4])
	}
	s.hdr = s.hdr[:0]
	s.inFrame, s.opcode, s.fin, s.masked, s.left, s.pos = true, op, fin, masked, int64(length), 0
	return data
}

// startMessage begins a data message at its first frame.
func (s *WSStream) startMessage(at time.Time) {
	s.msg = &WSMessage{Text: s.opcode == WSText, Start: at}
	s.hash = sha256.New()
	s.prefix = s.prefix[:0]
	s.body = s.body[:0]
	s.over = false
}

func (s *WSStream) payload(p []byte, at time.Time) {
	if s.masked {
		q := make([]byte, len(p))
		for i, b := range p {
			q[i] = b ^ s.key[(s.pos+int64(i))&3]
		}
		p = q
	}
	s.pos += int64(len(p))
	if s.opcode >= WSClose {
		s.ctl = append(s.ctl, p...)
		return
	}
	if s.msg == nil {
		s.startMessage(at)
	}
	s.msg.Bytes += int64(len(p))
	s.hash.Write(p)
	if s.msg.Text && len(s.prefix) < wsTypePrefix {
		s.prefix = append(s.prefix, p[:min(len(p), wsTypePrefix-len(s.prefix))]...)
	}
	if s.msg.Text && s.KeepText > 0 && !s.over {
		if len(s.body)+len(p) > s.KeepText {
			s.over, s.body = true, s.body[:0]
		} else {
			s.body = append(s.body, p...)
		}
	}
	if s.OnData != nil {
		s.OnData(p)
	}
}

func (s *WSStream) endFrame(at time.Time, onMessage func(*WSMessage), onControl func(op byte)) {
	s.inFrame = false
	if s.opcode >= WSClose {
		op := s.opcode
		s.ctl = s.ctl[:0]
		if op == WSClose {
			s.closed = true
		}
		if onControl != nil {
			onControl(op)
		}
		return
	}
	if s.msg == nil { // an empty first frame
		s.startMessage(at)
	}
	s.msg.Frames++
	s.msg.End = at
	if !s.fin {
		return
	}
	m := s.msg
	m.Hash = "sha256:" + hex.EncodeToString(s.hash.Sum(nil))
	if m.Text {
		m.Type = jsonType(s.prefix)
		m.ResponseID = jsonResponseID(s.prefix)
		if s.KeepText > 0 && !s.over {
			m.Body = s.body
		}
	}
	s.msg, s.hash = nil, nil
	if onMessage != nil {
		onMessage(m)
	}
	m.Body = nil
}

// jsonType returns the string value of the top-level "type" member of the
// JSON object b begins with (b may be a truncated prefix), or "" when there
// is none, it is not a string, or it is not at most 64 printable bytes.
func jsonType(b []byte) string {
	d := json.NewDecoder(bytes.NewReader(b))
	if t, err := d.Token(); err != nil || t != json.Delim('{') {
		return ""
	}
	for {
		k, err := d.Token()
		if err != nil {
			return ""
		}
		key, ok := k.(string)
		if !ok {
			return "" // the object's end
		}
		if key == "type" {
			v, err := d.Token()
			s, ok := v.(string)
			if err != nil || !ok || len(s) > maxWSType || !printable(s) {
				return ""
			}
			return s
		}
		if !skipJSONValue(d) {
			return ""
		}
	}
}

// jsonResponseID returns the "id" string of the top-level "response"
// object of the JSON object b begins with (b may be a truncated prefix), or
// "" when there is none or it is not at most 256 printable bytes.
func jsonResponseID(b []byte) string {
	d := json.NewDecoder(bytes.NewReader(b))
	if t, err := d.Token(); err != nil || t != json.Delim('{') {
		return ""
	}
	for {
		k, err := d.Token()
		key, ok := k.(string)
		if err != nil || !ok {
			return ""
		}
		if key != "response" {
			if !skipJSONValue(d) {
				return ""
			}
			continue
		}
		if t, err := d.Token(); err != nil || t != json.Delim('{') {
			return ""
		}
		for {
			k, err := d.Token()
			key, ok := k.(string)
			if err != nil || !ok {
				return ""
			}
			if key == "id" {
				v, err := d.Token()
				s, ok := v.(string)
				if err != nil || !ok || len(s) > maxRequestID || !printable(s) {
					return ""
				}
				return s
			}
			if !skipJSONValue(d) {
				return ""
			}
		}
	}
}

// skipJSONValue reads one value, nested ones whole.
func skipJSONValue(d *json.Decoder) bool {
	depth := 0
	for {
		t, err := d.Token()
		if err != nil {
			return false
		}
		switch t {
		case json.Delim('{'), json.Delim('['):
			depth++
		case json.Delim('}'), json.Delim(']'):
			depth--
		}
		if depth <= 0 {
			return true
		}
	}
}

// IsWebSocketUpgrade reports whether r asks to open a WebSocket (RFC 6455,
// 4.1): a GET whose Upgrade header names websocket and whose Connection
// header names upgrade, both as case-insensitive tokens.
func IsWebSocketUpgrade(r *HTTPRequest) bool {
	return r != nil && r.Method == "GET" && hasToken(r.Headers.Values("Upgrade"), "websocket") && hasToken(r.Headers.Values("Connection"), "upgrade")
}

// IsWebSocketAccept reports whether r accepts a WebSocket upgrade: status
// 101 with Upgrade naming websocket.
func IsWebSocketAccept(r *Response) bool {
	return r != nil && r.Status == 101 && hasToken([]string{r.Upgrade}, "websocket")
}

func hasToken(values []string, token string) bool {
	for _, v := range values {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), token) {
				return true
			}
		}
	}
	return false
}
