package tlsparse

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"mime"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

// ErrMalformedResponse means the bytes of a connection's read side did not
// parse as an HTTP/1.x response. The parser then skips the connection's
// reads until one begins with a status line.
var ErrMalformedResponse = errors.New("tlsparse: malformed HTTP/1.x response")

// Bounds of the response parser. Nothing it buffers grows past them.
const (
	maxResponseHeader = 64 << 10 // status line and header block
	maxChunkLine      = 4 << 10  // one chunk-size line
	maxTrailer        = 64 << 10 // the trailer section of a chunked body
	maxCompressedSSE  = 8 << 20  // a compressed event stream kept for decoding at its end
	maxDecodedSSE     = 64 << 20 // bytes decoded from it
	maxHeaderValue    = 128      // content type and content encoding
	maxRequestID      = 256
)

// Response is one HTTP/1.x response read from a connection. Its body is
// hashed and counted as it streams; no byte of it is kept, except a
// compressed event stream, buffered up to 8 MiB so it can be decoded and
// counted at its end.
type Response struct {
	Status          int
	RequestID       string // request-id, else x-request-id; "" if absent, too long or not printable
	ContentType     string // media type, lowercased, without parameters
	ContentEncoding string // lowercased
	BodyBytes       int64  // body length without transfer coding; includes bytes the capture missed
	BodyHash        string // "sha256:<hex>" of the body; "" unless Complete and not Truncated
	Start, End      time.Time
	Complete        bool // the body ended by its framing
	Truncated       bool // bytes of the response were missed
	SSE             *SSEStats
	// Upgrade and Extensions are the Upgrade and Sec-WebSocket-Extensions
	// headers of a 101 response, lowercased, at most 128 bytes; "" otherwise.
	// Extensions is "?" for a header present but longer or not printable.
	Upgrade, Extensions string
}

// ResponseParser reassembles the HTTP/1.x responses of one connection from
// the plaintext its reads return, in order. Call Feed with each read and
// Close when the connection's capture ends.
type ResponseParser struct {
	// Bodyless, when set, is called once per final response when its
	// header block has been read; true means it answers a HEAD request, so
	// it has no body whatever its headers say.
	Bodyless func() bool

	state     int
	hdr       []byte
	cur       *Response
	framing   int
	remaining int64
	chunk     int
	line      []byte
	trailer   int
	sink      *bodySink
	upgraded  []byte // bytes after a 101 response's head, for TakeUpgraded
}

// bodySink hashes a response body as it streams and counts its server-sent
// events, buffering a compressed event stream for decoding at its end. The
// HTTP/1.x parser and the HTTP/2 layer (N-46) share it.
type bodySink struct {
	hash    hash.Hash
	sse     *sseParser
	encoded []byte // compressed event stream, decoded at the end
	encOver bool
}

// newBodySink starts a body hash.
func newBodySink() *bodySink {
	return &bodySink{hash: sha256.New()}
}

// countEvents sets the sink up to count the events of r's body when r, whose
// content type and coding are set, is an event stream in a coding it reads.
func (b *bodySink) countEvents(r *Response) {
	if r.ContentType == "text/event-stream" {
		switch r.ContentEncoding {
		case "", "identity":
			b.sse = newSSEParser()
		case "gzip", "x-gzip", "deflate":
			b.sse = newSSEParser()
			b.encoded = []byte{}
		}
	}
}

// consume adds body bytes.
func (b *bodySink) consume(r *Response, p []byte) {
	if len(p) == 0 {
		return
	}
	r.BodyBytes += int64(len(p))
	b.hash.Write(p)
	switch {
	case b.encoded != nil:
		if len(b.encoded)+len(p) > maxCompressedSSE {
			b.encOver = true
			p = p[:maxCompressedSSE-len(b.encoded)]
		}
		b.encoded = append(b.encoded, p...)
	case b.sse != nil:
		b.sse.write(p)
	}
}

// miss counts n body bytes the capture missed: the response is truncated
// and its event count overflows.
func (b *bodySink) miss(r *Response, n int64) {
	r.BodyBytes += n
	r.Truncated = true
	if b.sse != nil {
		b.sse.overflow()
	}
}

// finish ends the body: the hash when it is complete and not truncated, and
// the event count.
func (b *bodySink) finish(r *Response, complete bool, at time.Time) {
	r.End = at
	r.Complete = complete
	if complete && !r.Truncated {
		r.BodyHash = "sha256:" + hex.EncodeToString(b.hash.Sum(nil))
	}
	if b.sse != nil && b.encoded != nil {
		if !b.decodeSSE(r.ContentEncoding) {
			b.sse = nil
		} else if b.encOver {
			b.sse.overflow()
		}
	}
	if b.sse != nil {
		r.SSE = &b.sse.stats
	}
}

const (
	stHeader = iota
	stBody
	stLost
	stUpgraded
)

const (
	frLength = iota
	frChunked
	frClose
)

const (
	chSize = iota
	chData
	chCR
	chLF
	chTrailer
)

// NewResponseParser returns a parser waiting for a status line.
func NewResponseParser() *ResponseParser {
	return &ResponseParser{}
}

var statusPrefix = []byte("HTTP/1.")

// Feed consumes the bytes one read returned. missing is the number of bytes
// the read returned beyond data, which the capture did not copy. Every
// response that ends here is passed to emit, in order. Feed returns
// ErrMalformedResponse when the stream stops parsing; reads are then
// skipped until one begins with a status line, and the response in
// progress, if any, is emitted as incomplete.
func (p *ResponseParser) Feed(data []byte, missing int, at time.Time, emit func(*Response)) error {
	switch p.state {
	case stUpgraded:
		return nil
	case stLost:
		if !bytes.HasPrefix(data, statusPrefix) {
			return nil
		}
		p.state = stHeader
		p.hdr = p.hdr[:0]
	case stBody:
		// A body delimited by the end of the connection never ends in a
		// capture that does not see the close. A read that begins with a
		// status line is taken as a new connection that reuses the SSL
		// object, and ends that body.
		if p.framing == frClose && bytes.HasPrefix(data, statusPrefix) {
			p.finish(false, at, emit)
		}
	}

	var err error
	for len(data) > 0 && err == nil {
		switch p.state {
		case stHeader:
			data, err = p.header(data, at, emit)
		case stBody:
			data, err = p.body(data, at, emit)
		default:
			data = nil
		}
	}
	if err == nil && missing > 0 {
		err = p.miss(int64(missing), at, emit)
	}
	if err != nil {
		p.lose(at, emit)
		return err
	}
	return nil
}

// Upgraded reports whether a 101 response switched the connection to
// another protocol; Feed then parses nothing more.
func (p *ResponseParser) Upgraded() bool { return p.state == stUpgraded }

// TakeUpgraded returns, once, the bytes that followed the 101 response's
// head in the read that held it: the first bytes of the new protocol.
func (p *ResponseParser) TakeUpgraded() []byte {
	b := p.upgraded
	p.upgraded = nil
	return b
}

// Close ends the connection's capture: a response whose header block was
// read is emitted as incomplete.
func (p *ResponseParser) Close(at time.Time, emit func(*Response)) {
	if p.state == stBody {
		p.finish(false, at, emit)
	}
}

func (p *ResponseParser) lose(at time.Time, emit func(*Response)) {
	if p.state == stBody {
		p.finish(false, at, emit)
	}
	p.cur = nil
	p.state = stLost
	p.hdr = p.hdr[:0]
}

func (p *ResponseParser) header(data []byte, at time.Time, emit func(*Response)) ([]byte, error) {
	if len(p.hdr) == 0 {
		p.cur = &Response{Start: at}
	}
	from := len(p.hdr) - 3
	if from < 0 {
		from = 0
	}
	p.hdr = append(p.hdr, data...)
	n := len(statusPrefix)
	if len(p.hdr) < n {
		n = len(p.hdr)
	}
	if !bytes.Equal(p.hdr[:n], statusPrefix[:n]) {
		return nil, ErrMalformedResponse
	}
	end := bytes.Index(p.hdr[from:], []byte("\r\n\r\n"))
	if end == -1 {
		if len(p.hdr) > maxResponseHeader {
			return nil, ErrMalformedResponse
		}
		return nil, nil
	}
	end += from
	if end+4 > maxResponseHeader {
		return nil, ErrMalformedResponse
	}
	block := p.hdr[:end]
	rest := append([]byte(nil), p.hdr[end+4:]...)
	p.hdr = p.hdr[:0]

	status, headers, err := parseResponseHead(block)
	if err != nil {
		return nil, err
	}
	r := p.cur
	r.Status = status
	if status >= 100 && status < 200 && status != 101 {
		// An interim response: the final one follows for the same request.
		p.cur = nil
		return rest, nil
	}
	r.RequestID = requestID(headers)
	r.ContentType = mediaType(headers.Get("Content-Type"))
	r.ContentEncoding = boundedLower(strings.TrimSpace(headers.Get("Content-Encoding")))
	p.sink = newBodySink()

	if status == 101 {
		r.Upgrade = boundedLower(strings.TrimSpace(headers.Get("Upgrade")))
		ext := strings.TrimSpace(strings.Join(headers.Values("Sec-WebSocket-Extensions"), ", "))
		if r.Extensions = boundedLower(ext); r.Extensions == "" && ext != "" {
			r.Extensions = "?" // present but too long or not printable: still an extension
		}
		p.state = stBody
		p.finish(true, at, emit)
		p.state = stUpgraded
		p.upgraded = rest
		return nil, nil
	}
	if status == 204 || status == 304 || (p.Bodyless != nil && p.Bodyless()) {
		p.state = stBody
		p.finish(true, at, emit)
		return rest, nil
	}

	chunked := isChunkedResponse(headers)
	length, hasLength, err := int64(0), false, error(nil)
	if !chunked {
		if length, hasLength, err = responseLength(headers); err != nil {
			p.cur = nil
			return nil, err
		}
	}

	p.sink.countEvents(r)
	p.state = stBody
	switch {
	case chunked:
		p.framing = frChunked
		p.chunk = chSize
		p.line = p.line[:0]
		p.trailer = 0
	case hasLength:
		p.framing = frLength
		p.remaining = length
		if length == 0 {
			p.finish(true, at, emit)
		}
	default:
		p.framing = frClose
	}
	return rest, nil
}

func (p *ResponseParser) body(data []byte, at time.Time, emit func(*Response)) ([]byte, error) {
	switch p.framing {
	case frLength:
		n := int64(len(data))
		if n > p.remaining {
			n = p.remaining
		}
		p.consume(data[:n])
		p.remaining -= n
		if p.remaining == 0 {
			p.finish(true, at, emit)
		}
		return data[n:], nil
	case frClose:
		p.consume(data)
		return nil, nil
	}

	for len(data) > 0 {
		switch p.chunk {
		case chSize:
			i := bytes.IndexByte(data, '\n')
			if i == -1 {
				p.line = append(p.line, data...)
				if len(p.line) > maxChunkLine {
					return nil, ErrMalformedResponse
				}
				return nil, nil
			}
			p.line = append(p.line, data[:i]...)
			data = data[i+1:]
			size, err := chunkSize(p.line)
			p.line = p.line[:0]
			if err != nil {
				return nil, err
			}
			if size == 0 {
				p.chunk = chTrailer
			} else {
				p.remaining = size
				p.chunk = chData
			}
		case chData:
			n := int64(len(data))
			if n > p.remaining {
				n = p.remaining
			}
			p.consume(data[:n])
			p.remaining -= n
			data = data[n:]
			if p.remaining == 0 {
				p.chunk = chCR
			}
		case chCR:
			if data[0] != '\r' {
				return nil, ErrMalformedResponse
			}
			data = data[1:]
			p.chunk = chLF
		case chLF:
			if data[0] != '\n' {
				return nil, ErrMalformedResponse
			}
			data = data[1:]
			p.chunk = chSize
		case chTrailer:
			i := bytes.IndexByte(data, '\n')
			if i == -1 {
				p.line = append(p.line, data...)
				p.trailer += len(data)
				if p.trailer > maxTrailer {
					return nil, ErrMalformedResponse
				}
				return nil, nil
			}
			p.line = append(p.line, data[:i]...)
			p.trailer += i + 1
			data = data[i+1:]
			empty := len(bytes.TrimSuffix(p.line, []byte("\r"))) == 0
			p.line = p.line[:0]
			if p.trailer > maxTrailer {
				return nil, ErrMalformedResponse
			}
			if empty {
				p.finish(true, at, emit)
				return data, nil
			}
		}
	}
	return nil, nil
}

// miss accounts for bytes a read returned that the capture did not copy.
// Inside a body of known length they are counted and the response is marked
// truncated; anywhere else the stream's framing is lost.
func (p *ResponseParser) miss(n int64, at time.Time, emit func(*Response)) error {
	if p.state != stBody {
		if p.state == stUpgraded {
			return nil
		}
		return ErrMalformedResponse
	}
	p.sink.miss(p.cur, 0)
	switch {
	case p.framing == frClose:
		p.cur.BodyBytes += n
		return nil
	case p.framing == frLength || (p.framing == frChunked && p.chunk == chData):
		if n > p.remaining {
			return ErrMalformedResponse
		}
		p.cur.BodyBytes += n
		p.remaining -= n
		if p.remaining == 0 {
			if p.framing == frLength {
				p.finish(true, at, emit)
			} else {
				p.chunk = chCR
			}
		}
		return nil
	}
	return ErrMalformedResponse
}

func (p *ResponseParser) consume(b []byte) {
	p.sink.consume(p.cur, b)
}

func (p *ResponseParser) finish(complete bool, at time.Time, emit func(*Response)) {
	r := p.cur
	if p.sink == nil {
		// A response that ended with its head (a 101, 204 or 304, an
		// answer to a HEAD) before its body was set up.
		p.sink = &bodySink{hash: sha256.New()}
	}
	p.sink.finish(r, complete, at)
	p.cur, p.sink = nil, nil
	p.state = stHeader
	emit(r)
}

// decodeSSE decodes the buffered compressed event stream into the SSE
// parser. A prefix that ends early still counts the events it holds. It
// reports false when the coding cannot be read at all.
func (b *bodySink) decodeSSE(coding string) bool {
	var r io.Reader
	var err error
	switch coding {
	case "gzip", "x-gzip":
		r, err = gzip.NewReader(bytes.NewReader(b.encoded))
	case "deflate":
		// "deflate" is zlib-wrapped by the standard, raw by some servers.
		r, err = zlib.NewReader(bytes.NewReader(b.encoded))
		if err != nil {
			r, err = flate.NewReader(bytes.NewReader(b.encoded)), nil
		}
	default:
		return false
	}
	if err != nil {
		return false
	}
	_, err = io.Copy(sseWriter{b.sse}, io.LimitReader(r, maxDecodedSSE))
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		b.sse.overflow()
	}
	return true
}

type sseWriter struct{ s *sseParser }

func (w sseWriter) Write(b []byte) (int, error) {
	w.s.write(b)
	return len(b), nil
}

// parseResponseHead reads the status line and the header fields of block,
// which excludes the blank line that ends it.
func parseResponseHead(block []byte) (int, textproto.MIMEHeader, error) {
	line, fields, _ := bytes.Cut(block, []byte("\r\n"))
	// HTTP/1.x SP 3DIGIT [SP reason]
	if len(line) < 12 || !bytes.HasPrefix(line, statusPrefix) || (line[7] != '0' && line[7] != '1') || line[8] != ' ' {
		return 0, nil, ErrMalformedResponse
	}
	code := line[9:12]
	if len(line) > 12 && line[12] != ' ' {
		return 0, nil, ErrMalformedResponse
	}
	status := 0
	for _, c := range code {
		if c < '0' || c > '9' {
			return 0, nil, ErrMalformedResponse
		}
		status = status*10 + int(c-'0')
	}
	if status < 100 {
		return 0, nil, ErrMalformedResponse
	}
	// The fields are split by hand rather than with textproto, which
	// rejects a whole header block for one value with a control byte: a
	// response is attested, so a field it cannot use is dropped, not the
	// response.
	headers := textproto.MIMEHeader{}
	var last string
	for len(fields) > 0 {
		var line []byte
		line, fields, _ = bytes.Cut(fields, []byte("\r\n"))
		if len(line) == 0 {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			// Obsolete line folding continues the previous field.
			if last == "" {
				return 0, nil, ErrMalformedResponse
			}
			vals := headers[last]
			vals[len(vals)-1] += " " + strings.TrimSpace(string(line))
			continue
		}
		name, value, ok := bytes.Cut(line, []byte(":"))
		if !ok || len(name) == 0 || bytes.ContainsAny(name, " \t") {
			return 0, nil, ErrMalformedResponse
		}
		last = textproto.CanonicalMIMEHeaderKey(string(name))
		headers[last] = append(headers[last], strings.TrimSpace(string(value)))
	}
	return status, headers, nil
}

// isChunkedResponse reports whether chunked is the last transfer coding.
func isChunkedResponse(h textproto.MIMEHeader) bool {
	v := h.Values("Transfer-Encoding")
	if len(v) == 0 {
		return false
	}
	codings := strings.Split(v[len(v)-1], ",")
	return strings.EqualFold(strings.TrimSpace(codings[len(codings)-1]), "chunked")
}

// responseLength reads Content-Length. Repeated values must agree.
func responseLength(h textproto.MIMEHeader) (int64, bool, error) {
	vals := h.Values("Content-Length")
	if len(vals) == 0 {
		return 0, false, nil
	}
	var n int64 = -1
	for _, v := range vals {
		for _, part := range strings.Split(v, ",") {
			m, err := strconv.ParseInt(strings.TrimSpace(part), 10, 63)
			if err != nil || m < 0 || (n >= 0 && m != n) {
				return 0, false, ErrMalformedResponse
			}
			n = m
		}
	}
	return n, true, nil
}

func chunkSize(line []byte) (int64, error) {
	line = bytes.TrimSuffix(line, []byte("\r"))
	if i := bytes.IndexByte(line, ';'); i != -1 {
		line = line[:i]
	}
	s := strings.TrimSpace(string(line))
	if s == "" || len(s) > 15 {
		return 0, ErrMalformedResponse
	}
	n, err := strconv.ParseInt(s, 16, 63)
	if err != nil || n < 0 {
		return 0, ErrMalformedResponse
	}
	return n, nil
}

func requestID(h textproto.MIMEHeader) string {
	v := h.Get("Request-Id")
	if v == "" {
		v = h.Get("X-Request-Id")
	}
	v = strings.TrimSpace(v)
	if len(v) > maxRequestID || !printable(v) {
		return ""
	}
	return v
}

func mediaType(v string) string {
	if v == "" {
		return ""
	}
	mt, _, err := mime.ParseMediaType(v)
	if err != nil {
		mt, _, _ = strings.Cut(v, ";")
		mt = strings.TrimSpace(mt)
	}
	return boundedLower(mt)
}

func boundedLower(v string) string {
	if len(v) > maxHeaderValue || !printable(v) {
		return ""
	}
	return strings.ToLower(v)
}

func printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
