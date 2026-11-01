package tlsparse

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"net/textproto"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The HTTP/2 layer (RFC 9113, N-46). H2Client reads the client direction of
// a connection from its preface and yields its requests; H2Server reads the
// server direction and yields its responses, as HTTP/1.x requests and
// responses are. Each direction decodes its header blocks with its own HPACK
// table (hpack.go), so it must be read from the start of the connection: a
// direction that loses its framing or its table ends, and nothing more of
// it is parsed.

// Errors that end an HTTP/2 direction.
var (
	// ErrH2Protocol is a frame that breaks the protocol: no preface, a
	// header block interrupted, a frame on the wrong stream, padding longer
	// than its frame, a frame over the buffer bound.
	ErrH2Protocol = errors.New("tlsparse: HTTP/2 protocol error")
	// ErrH2Missing is bytes the capture missed outside a DATA payload,
	// which loses the framing or the header table.
	ErrH2Missing = errors.New("tlsparse: HTTP/2 bytes missed outside a DATA payload")
)

// H2ClientPreface is the client connection preface (RFC 9113, section 3.4).
var H2ClientPreface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

// Frame types and flags (RFC 9113, section 6).
const (
	h2Data         = 0x0
	h2Headers      = 0x1
	h2Priority     = 0x2
	h2RstStream    = 0x3
	h2Settings     = 0x4
	h2PushPromise  = 0x5
	h2Ping         = 0x6
	h2Goaway       = 0x7
	h2WindowUpdate = 0x8
	h2Continuation = 0x9

	h2FlagEndStream  = 0x1
	h2FlagEndHeaders = 0x4
	h2FlagPadded     = 0x8
	h2FlagPriority   = 0x20
)

// Bounds of the HTTP/2 layer.
const (
	h2HeaderLen = 9
	// h2MaxBuffered bounds the payload of a frame other than DATA, which is
	// buffered whole, and a header block with its continuations.
	h2MaxBuffered = 1 << 20
	// h2MaxStreams bounds the streams followed at once per direction; a
	// stream past it is not followed (counted by the caller).
	h2MaxStreams = 1024
)

// IsH2ServerPreface reports whether b begins with what an HTTP/2 server
// sends first: a SETTINGS frame on stream 0 without the ACK flag, whose
// length is a multiple of six (RFC 9113, sections 3.4 and 6.5).
func IsH2ServerPreface(b []byte) bool {
	if len(b) < h2HeaderLen {
		return false
	}
	n := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
	return b[3] == h2Settings && b[4]&0x1 == 0 && binary.BigEndian.Uint32(b[5:9])&0x7fffffff == 0 && n%6 == 0 && n <= 6*64
}

// LooksLikeH2Frame reports whether b begins with a plausible HTTP/2 frame
// header: a known type, a length no larger than the protocol allows by
// default, the reserved bit clear, and stream 0 exactly for the connection
// frames. It tells an h2 connection whose preface came before the capture
// from other bytes that do not parse, for counting only.
func LooksLikeH2Frame(b []byte) bool {
	if len(b) < h2HeaderLen || b[3] > h2Continuation || b[5]&0x80 != 0 {
		return false
	}
	n := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
	stream := binary.BigEndian.Uint32(b[5:9])
	switch b[3] {
	case h2Settings, h2Ping, h2Goaway:
		return stream == 0 && n <= 1<<14
	case h2WindowUpdate:
		return n == 4
	default:
		return stream != 0 && n <= 1<<14
	}
}

// h2Handler receives what a framer reads.
type h2Handler interface {
	// headers is a complete header block of a HEADERS frame and its
	// continuations, decoded; end is its END_STREAM flag.
	headers(stream uint32, fields []hpackField, end bool, at time.Time)
	// data is DATA payload bytes, padding removed.
	data(stream uint32, p []byte, at time.Time)
	// missed is DATA payload bytes the capture missed.
	missed(stream uint32, n int)
	// end is END_STREAM on a DATA frame.
	end(stream uint32, at time.Time)
	// reset is RST_STREAM.
	reset(stream uint32, at time.Time)
}

// Framer states.
const (
	h2fPreface = iota
	h2fHeader
	h2fPayload // a frame other than DATA, buffered
	h2fPadLen  // DATA's pad length byte
	h2fData    // DATA payload
	h2fPad     // DATA padding
	h2fDone
)

// h2Framer reads the frames of one direction.
type h2Framer struct {
	state   int
	pre     int // preface bytes matched
	hdr     [h2HeaderLen]byte
	nhdr    int
	length  int
	typ     byte
	flags   byte
	stream  uint32
	payload []byte
	left    int // bytes of the current DATA payload still to come
	pad     int // padding bytes after them
	hp      *hpackDecoder
	// The header block in progress: its stream, its END_STREAM flag, and
	// whether it is a PUSH_PROMISE's, which is decoded and dropped.
	block       []byte
	blockStream uint32
	blockEnd    bool
	blockPush   bool
	inBlock     bool
	err         error
	h           h2Handler
}

func newH2Framer(client bool, h h2Handler) *h2Framer {
	f := &h2Framer{state: h2fHeader, hp: newHPACKDecoder(), h: h}
	if client {
		f.state = h2fPreface
	}
	return f
}

// feed consumes bytes, then accounts for missing bytes after them. Once it
// returns an error the direction is done and later calls return it again.
func (f *h2Framer) feed(data []byte, missing int, at time.Time) error {
	if f.err != nil {
		return f.err
	}
	for len(data) > 0 && f.err == nil {
		data = f.step(data, at)
	}
	if f.err == nil && missing > 0 {
		f.miss(missing, at)
	}
	return f.err
}

func (f *h2Framer) fail(err error) {
	f.err = err
	f.state = h2fDone
	f.payload, f.block = nil, nil
}

func (f *h2Framer) step(data []byte, at time.Time) []byte {
	switch f.state {
	case h2fPreface:
		n := min(len(data), len(H2ClientPreface)-f.pre)
		if !bytes.Equal(data[:n], H2ClientPreface[f.pre:f.pre+n]) {
			f.fail(ErrH2Protocol)
			return nil
		}
		f.pre += n
		if f.pre == len(H2ClientPreface) {
			f.state = h2fHeader
		}
		return data[n:]
	case h2fHeader:
		n := copy(f.hdr[f.nhdr:], data)
		f.nhdr += n
		if f.nhdr < h2HeaderLen {
			return data[n:]
		}
		f.nhdr = 0
		f.length = int(f.hdr[0])<<16 | int(f.hdr[1])<<8 | int(f.hdr[2])
		f.typ, f.flags = f.hdr[3], f.hdr[4]
		f.stream = binary.BigEndian.Uint32(f.hdr[5:9]) & 0x7fffffff
		f.begin(at)
		return data[n:]
	case h2fPayload:
		n := min(len(data), f.length-len(f.payload))
		f.payload = append(f.payload, data[:n]...)
		if len(f.payload) == f.length {
			f.frame(at)
		}
		return data[n:]
	case h2fPadLen:
		f.pad = int(data[0])
		if f.pad > f.left-1 {
			f.fail(ErrH2Protocol)
			return nil
		}
		f.left -= 1 + f.pad
		f.state = h2fData
		f.dataDone(at)
		return data[1:]
	case h2fData:
		n := min(len(data), f.left)
		f.h.data(f.stream, data[:n], at)
		f.left -= n
		f.dataDone(at)
		return data[n:]
	case h2fPad:
		n := min(len(data), f.pad)
		f.pad -= n
		f.dataDone(at)
		return data[n:]
	}
	return nil
}

// begin starts the frame whose header was just read.
func (f *h2Framer) begin(at time.Time) {
	if f.inBlock && (f.typ != h2Continuation || f.stream != f.blockStream) {
		f.fail(ErrH2Protocol)
		return
	}
	if f.typ == h2Data {
		if f.stream == 0 {
			f.fail(ErrH2Protocol)
			return
		}
		f.left, f.pad = f.length, 0
		f.state = h2fData
		if f.flags&h2FlagPadded != 0 {
			if f.length == 0 {
				f.fail(ErrH2Protocol)
				return
			}
			f.state = h2fPadLen
			return
		}
		f.dataDone(at)
		return
	}
	if f.length > h2MaxBuffered {
		f.fail(ErrH2Protocol)
		return
	}
	f.payload = f.payload[:0]
	f.state = h2fPayload
	if f.length == 0 {
		f.frame(at)
	}
}

// dataDone ends the DATA frame once its payload and padding are read.
func (f *h2Framer) dataDone(at time.Time) {
	if f.state == h2fData && f.left == 0 {
		f.state = h2fPad
	}
	if f.state == h2fPad && f.pad == 0 {
		f.state = h2fHeader
		if f.flags&h2FlagEndStream != 0 {
			f.h.end(f.stream, at)
		}
	}
}

// frame handles a buffered frame other than DATA.
func (f *h2Framer) frame(at time.Time) {
	f.state = h2fHeader
	p := f.payload
	switch f.typ {
	case h2Headers, h2PushPromise:
		if f.stream == 0 {
			f.fail(ErrH2Protocol)
			return
		}
		if f.flags&h2FlagPadded != 0 {
			if len(p) == 0 || int(p[0]) > len(p)-1 {
				f.fail(ErrH2Protocol)
				return
			}
			p = p[1 : len(p)-int(p[0])]
		}
		if f.typ == h2Headers && f.flags&h2FlagPriority != 0 {
			if len(p) < 5 {
				f.fail(ErrH2Protocol)
				return
			}
			p = p[5:]
		}
		if f.typ == h2PushPromise {
			if len(p) < 4 {
				f.fail(ErrH2Protocol)
				return
			}
			p = p[4:]
		}
		f.block = append(f.block[:0], p...)
		f.blockStream, f.blockEnd, f.blockPush = f.stream, f.flags&h2FlagEndStream != 0, f.typ == h2PushPromise
		f.inBlock = true
	case h2Continuation:
		if !f.inBlock {
			f.fail(ErrH2Protocol)
			return
		}
		if len(f.block)+len(p) > h2MaxBuffered {
			f.fail(ErrH2Protocol)
			return
		}
		f.block = append(f.block, p...)
	case h2RstStream:
		if f.stream == 0 || len(p) != 4 {
			f.fail(ErrH2Protocol)
			return
		}
		f.h.reset(f.stream, at)
		return
	default:
		// SETTINGS, PING, GOAWAY, WINDOW_UPDATE, PRIORITY and unknown types
		// carry nothing this layer records.
		return
	}
	if f.flags&h2FlagEndHeaders == 0 {
		return
	}
	f.inBlock = false
	var fields []hpackField
	if err := f.hp.decode(f.block, func(n, v string) { fields = append(fields, hpackField{n, v}) }); err != nil {
		f.fail(err)
		return
	}
	if !f.blockPush {
		f.h.headers(f.blockStream, fields, f.blockEnd, at)
	}
}

// miss accounts for n bytes the capture missed: inside a DATA payload they
// are the stream's, inside its padding nothing; anywhere else, or past the
// frame, the framing is lost.
func (f *h2Framer) miss(n int, at time.Time) {
	for n > 0 && f.err == nil {
		switch f.state {
		case h2fData:
			k := min(n, f.left)
			f.h.missed(f.stream, k)
			f.left -= k
			n -= k
			f.dataDone(at)
		case h2fPad:
			k := min(n, f.pad)
			f.pad -= k
			n -= k
			f.dataDone(at)
		default:
			f.fail(ErrH2Missing)
		}
	}
}

// fieldsOf splits a decoded header block into its pseudo-header fields and
// its regular fields, the latter canonicalised. ok is false for a block
// that breaks the rules of RFC 9113, section 8.3: a pseudo-header after a
// regular field, an unknown or repeated pseudo-header, or a field name with
// an upper-case letter.
func fieldsOf(fields []hpackField) (pseudo map[string]string, h textproto.MIMEHeader, ok bool) {
	pseudo, h = map[string]string{}, textproto.MIMEHeader{}
	regular := false
	for _, f := range fields {
		if f.name != strings.ToLower(f.name) || f.name == "" {
			return nil, nil, false
		}
		if f.name[0] == ':' {
			if regular {
				return nil, nil, false
			}
			if _, dup := pseudo[f.name]; dup {
				return nil, nil, false
			}
			pseudo[f.name] = f.value
			continue
		}
		regular = true
		k := textproto.CanonicalMIMEHeaderKey(f.name)
		h[k] = append(h[k], f.value)
	}
	return pseudo, h, true
}

// H2Request is one request of an HTTP/2 connection. Its body is hashed as
// it streams and not kept: Body of the embedded request is nil, BodyHash
// holds the SHA-256 of the DATA payloads in order when the body has bytes
// and is whole.
type H2Request struct {
	*HTTPRequest
	Stream   uint32
	BodyLen  int64
	BodyHash string // "sha256:<hex>"; "" with no body or when Cut
	// Cut is set when bytes of the body were missed, or the stream ended
	// (reset, the direction lost, the capture closed) before END_STREAM.
	Cut bool
	// Reset is set when the client reset the stream (RST_STREAM).
	Reset bool
}

type h2ReqState struct {
	req  *H2Request
	hash hash.Hash
}

// H2Client reads the client direction of an HTTP/2 connection, from its
// preface, into requests.
type H2Client struct {
	f       *h2Framer
	streams map[uint32]*h2ReqState
	emit    func(*H2Request)
	// Malformed counts streams whose header block is not a request
	// (missing or invalid pseudo-headers) or that exceed h2MaxStreams; they
	// are not followed.
	Malformed int
}

// NewH2Client returns a parser expecting the client preface.
func NewH2Client() *H2Client {
	c := &H2Client{streams: map[uint32]*h2ReqState{}}
	c.f = newH2Framer(true, h2ClientHandler{c})
	return c
}

// Feed consumes the bytes of one write, then missing bytes the capture did
// not copy. Every request that ends here is passed to emit: at END_STREAM,
// or cut when its stream is reset. An error ends the direction: requests in
// progress are passed to emit cut, and every later Feed returns the error.
func (c *H2Client) Feed(data []byte, missing int, at time.Time, emit func(*H2Request)) error {
	c.emit = emit
	err := c.f.feed(data, missing, at)
	if err != nil {
		c.Close(emit)
	}
	c.emit = nil
	return err
}

// Err returns the error that ended the direction, or nil.
func (c *H2Client) Err() error { return c.f.err }

// Head returns the request whose head was read on stream and whose stream
// has not ended, or nil.
func (c *H2Client) Head(stream uint32) *H2Request {
	if s := c.streams[stream]; s != nil {
		return s.req
	}
	return nil
}

// Close passes every request in progress to emit, cut, in stream order.
func (c *H2Client) Close(emit func(*H2Request)) {
	ids := make([]uint32, 0, len(c.streams))
	for id := range c.streams {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		s := c.streams[id]
		delete(c.streams, id)
		s.req.Cut = true
		emit(s.req)
	}
}

type h2ClientHandler struct{ c *H2Client }

func (h h2ClientHandler) headers(stream uint32, fields []hpackField, end bool, at time.Time) {
	c := h.c
	if s := c.streams[stream]; s != nil {
		// Trailers: they end the request.
		if end {
			c.finish(stream)
		}
		return
	}
	if len(c.streams) >= h2MaxStreams {
		c.Malformed++
		return
	}
	req, ok := h2RequestOf(fields)
	if !ok {
		c.Malformed++
		return
	}
	c.streams[stream] = &h2ReqState{req: &H2Request{HTTPRequest: req, Stream: stream}, hash: sha256.New()}
	if end {
		c.finish(stream)
	}
}

func (h h2ClientHandler) data(stream uint32, p []byte, _ time.Time) {
	if s := h.c.streams[stream]; s != nil {
		s.req.BodyLen += int64(len(p))
		s.hash.Write(p)
	}
}

func (h h2ClientHandler) missed(stream uint32, n int) {
	if s := h.c.streams[stream]; s != nil {
		s.req.BodyLen += int64(n)
		s.req.Cut = true
	}
}

func (h h2ClientHandler) end(stream uint32, _ time.Time) {
	if h.c.streams[stream] != nil {
		h.c.finish(stream)
	}
}

func (h h2ClientHandler) reset(stream uint32, _ time.Time) {
	c := h.c
	if s := c.streams[stream]; s != nil {
		delete(c.streams, stream)
		s.req.Cut, s.req.Reset = true, true
		c.emit(s.req)
	}
}

func (c *H2Client) finish(stream uint32) {
	s := c.streams[stream]
	delete(c.streams, stream)
	if !s.req.Cut && s.req.BodyLen > 0 {
		s.req.BodyHash = "sha256:" + hex.EncodeToString(s.hash.Sum(nil))
	}
	c.emit(s.req)
}

// h2RequestOf builds the request a header block opens: :method, :scheme
// and :path (an origin-form path, or * for OPTIONS) are required, and
// :authority, else a host field, names the host, set as the Host header.
// CONNECT, which has no scheme or path, is a request for its authority.
func h2RequestOf(fields []hpackField) (*HTTPRequest, bool) {
	pseudo, h, ok := fieldsOf(fields)
	if !ok {
		return nil, false
	}
	method := pseudo[":method"]
	if !isMethodToken(method) {
		return nil, false
	}
	if auth := pseudo[":authority"]; auth != "" {
		h.Set("Host", auth)
	}
	if method == "CONNECT" {
		if _, has := pseudo[":path"]; has || h.Get("Host") == "" {
			return nil, false
		}
		return &HTTPRequest{Method: method, Path: h.Get("Host"), Headers: h}, true
	}
	path := pseudo[":path"]
	if pseudo[":scheme"] == "" || path == "" || strings.ContainsAny(path, " \t\r\n") {
		return nil, false
	}
	if path != "*" && path[0] != '/' || path == "*" && method != "OPTIONS" {
		return nil, false
	}
	p, q, _ := strings.Cut(path, "?")
	return &HTTPRequest{Method: method, Path: p, Query: q, Headers: h}, true
}

// isMethodToken reports whether m is an HTTP method token (RFC 9110,
// section 5.6.2); HTTP/2 does not restrict methods to capital letters.
func isMethodToken(m string) bool {
	if m == "" || len(m) > 32 {
		return false
	}
	for i := 0; i < len(m); i++ {
		c := m[i]
		if c <= ' ' || c >= 0x7f || strings.IndexByte(`"(),/:;<=>?@[\]{}`, c) >= 0 {
			return false
		}
	}
	return true
}

type h2RespState struct {
	r    *Response
	sink *bodySink
}

// H2Server reads the server direction of an HTTP/2 connection, from its
// first frame, into responses. Interim (1xx) responses are skipped; a
// response ends at END_STREAM, complete, or at RST_STREAM, incomplete.
type H2Server struct {
	f       *h2Framer
	streams map[uint32]*h2RespState
	emit    func(uint32, *Response)
	// Malformed counts streams whose first header block has no valid
	// :status, or that exceed h2MaxStreams; they are not followed.
	Malformed int
}

// NewH2Server returns a parser expecting the server's first frame.
func NewH2Server() *H2Server {
	s := &H2Server{streams: map[uint32]*h2RespState{}}
	s.f = newH2Framer(false, h2ServerHandler{s})
	return s
}

// Feed consumes the bytes of one read, then missing bytes the capture did
// not copy. Every response that ends here is passed to emit with its
// stream. An error ends the direction: responses in progress are emitted
// incomplete, and every later Feed returns the error.
func (s *H2Server) Feed(data []byte, missing int, at time.Time, emit func(uint32, *Response)) error {
	s.emit = emit
	err := s.f.feed(data, missing, at)
	if err != nil {
		s.Close(at, emit)
	}
	s.emit = nil
	return err
}

// Err returns the error that ended the direction, or nil.
func (s *H2Server) Err() error { return s.f.err }

// Reset ends the response on stream as incomplete: the client reset the
// stream, so no more of it comes.
func (s *H2Server) Reset(stream uint32, at time.Time, emit func(uint32, *Response)) {
	s.emit = emit
	h2ServerHandler{s}.reset(stream, at)
	s.emit = nil
}

// Close emits every response in progress, incomplete, in stream order.
func (s *H2Server) Close(at time.Time, emit func(uint32, *Response)) {
	ids := make([]uint32, 0, len(s.streams))
	for id := range s.streams {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		st := s.streams[id]
		delete(s.streams, id)
		if st.sink != nil {
			st.sink.finish(st.r, false, at)
			emit(id, st.r)
		}
	}
}

type h2ServerHandler struct{ s *H2Server }

func (h h2ServerHandler) headers(stream uint32, fields []hpackField, end bool, at time.Time) {
	s := h.s
	st := s.streams[stream]
	if st != nil && st.sink != nil {
		// Trailers: they end the response.
		if end {
			s.finish(stream, true, at)
		}
		return
	}
	pseudo, hdr, ok := fieldsOf(fields)
	status, err := strconv.Atoi(pseudo[":status"])
	if !ok || err != nil || len(pseudo[":status"]) != 3 || status < 100 || status > 599 {
		if st == nil {
			s.Malformed++
		}
		return
	}
	if status < 200 {
		// An interim response; the final one follows on the same stream.
		return
	}
	if st == nil {
		if len(s.streams) >= h2MaxStreams {
			s.Malformed++
			return
		}
		st = &h2RespState{}
		s.streams[stream] = st
	}
	r := &Response{Status: status, Start: at}
	r.RequestID = requestID(hdr)
	r.ContentType = mediaType(hdr.Get("Content-Type"))
	r.ContentEncoding = boundedLower(strings.TrimSpace(hdr.Get("Content-Encoding")))
	st.r, st.sink = r, newBodySink()
	if !end {
		st.sink.countEvents(r)
		return
	}
	s.finish(stream, true, at)
}

func (h h2ServerHandler) data(stream uint32, p []byte, _ time.Time) {
	if st := h.s.streams[stream]; st != nil && st.sink != nil {
		st.sink.consume(st.r, p)
	}
}

func (h h2ServerHandler) missed(stream uint32, n int) {
	if st := h.s.streams[stream]; st != nil && st.sink != nil {
		st.sink.miss(st.r, int64(n))
	}
}

func (h h2ServerHandler) end(stream uint32, at time.Time) {
	if st := h.s.streams[stream]; st != nil && st.sink != nil {
		h.s.finish(stream, true, at)
	}
}

func (h h2ServerHandler) reset(stream uint32, at time.Time) {
	if st := h.s.streams[stream]; st != nil && st.sink != nil {
		h.s.finish(stream, false, at)
	}
}

func (s *H2Server) finish(stream uint32, complete bool, at time.Time) {
	st := s.streams[stream]
	delete(s.streams, stream)
	st.sink.finish(st.r, complete, at)
	s.emit(stream, st.r)
}
