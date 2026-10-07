package tlsparse

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net/textproto"
	"strconv"
	"strings"
)

// ErrMalformedRequest means a complete request line and header block were
// present but could not be parsed as HTTP/1.1. This is a genuine parse
// failure, not a need-more-data condition.
var ErrMalformedRequest = errors.New("tlsparse: malformed HTTP/1.1 request")

// HTTPRequest is one parsed HTTP/1.1 request. Path and Query are taken
// verbatim from the request line's target and are never decoded or
// normalized, per the anti-normalization discipline in
// docs/architecture/13_probe_net.md -- CanonicalNetTarget is
// the single place that assembles the comparable form.
type HTTPRequest struct {
	Method  string
	Path    string
	Query   string // everything after the first '?' in the target; "" if absent
	Headers textproto.MIMEHeader
	Body    []byte
}

// ParseHTTP1 attempts to parse one complete HTTP/1.1 request from the front
// of s. It returns (nil, false, nil) when s does not yet contain a complete
// request -- the caller should call again after the next Append. It returns
// a non-nil error only for a request line and header block that are fully
// present but malformed, which more data cannot fix.
//
// On success, exactly the bytes of that one request are consumed from s, so
// pipelined requests are read by calling ParseHTTP1 again on what remains.
func ParseHTTP1(s *Stream) (*HTTPRequest, bool, error) {
	headerEnd := bytes.Index(s.buf, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		return nil, false, nil
	}
	bodyStart := headerEnd + 4

	requestLineEnd := bytes.Index(s.buf[:headerEnd], []byte("\r\n"))
	var requestLine []byte
	var headerBlock []byte
	if requestLineEnd == -1 {
		// No headers at all, just a request line immediately followed by
		// the blank line.
		requestLine = s.buf[:headerEnd]
		headerBlock = nil
	} else {
		requestLine = s.buf[:requestLineEnd]
		headerBlock = s.buf[requestLineEnd+2 : headerEnd]
	}

	method, path, query, err := parseRequestLine(requestLine)
	if err != nil {
		return nil, false, err
	}

	var headers textproto.MIMEHeader
	if len(headerBlock) > 0 {
		tp := textproto.NewReader(bufio.NewReader(bytes.NewReader(append(append([]byte{}, headerBlock...), '\r', '\n'))))
		headers, err = tp.ReadMIMEHeader()
		// textproto.ReadMIMEHeader returns io.EOF-wrapped errors for a
		// clean end of input; the header block always terminates cleanly
		// here since we appended the closing CRLF ourselves, so any
		// non-nil, non-EOF error is a real malformed-header condition.
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, false, ErrMalformedRequest
		}
	} else {
		headers = textproto.MIMEHeader{}
	}

	body, consumedBody, ok, err := readBody(s.buf[bodyStart:], headers)
	if err != nil {
		return nil, false, err
	}
	if !ok {
		return nil, false, nil
	}

	req := &HTTPRequest{
		Method:  method,
		Path:    path,
		Query:   query,
		Headers: headers,
		Body:    body,
	}
	s.consume(bodyStart + consumedBody)
	return req, true, nil
}

// parseRequestLine splits "METHOD target HTTP/1.x" into its parts. target is
// split on the first '?' into Path and Query, both kept verbatim.
func parseRequestLine(line []byte) (method, path, query string, err error) {
	parts := bytes.SplitN(line, []byte(" "), 3)
	if len(parts) != 3 {
		return "", "", "", ErrMalformedRequest
	}
	if !bytes.HasPrefix(parts[2], []byte("HTTP/1.")) {
		return "", "", "", ErrMalformedRequest
	}
	if len(parts[0]) == 0 || len(parts[1]) == 0 {
		return "", "", "", ErrMalformedRequest
	}
	target := parts[1]
	if i := bytes.IndexByte(target, '?'); i != -1 {
		return string(parts[0]), string(target[:i]), string(target[i+1:]), nil
	}
	return string(parts[0]), string(target), "", nil
}

// readBody determines the request body from the bytes following the header
// block, based on Transfer-Encoding/Content-Length. It returns ok=false when
// the body is not yet fully buffered (more data needed), and consumed as
// the number of raw (still on-the-wire, i.e. still chunk-encoded where
// applicable) bytes to advance the stream past.
func readBody(after []byte, headers textproto.MIMEHeader) (body []byte, consumed int, ok bool, err error) {
	if isChunked(headers) {
		return readChunkedBody(after)
	}

	n, hasLen, err := contentLength(headers)
	if err != nil {
		return nil, 0, false, err
	}
	if !hasLen || n == 0 {
		return nil, 0, true, nil
	}
	if len(after) < n {
		return nil, 0, false, nil
	}
	return after[:n], n, true, nil
}

func isChunked(headers textproto.MIMEHeader) bool {
	return headers.Get("Transfer-Encoding") == "chunked"
}

func contentLength(headers textproto.MIMEHeader) (int, bool, error) {
	v := headers.Get("Content-Length")
	if v == "" {
		return 0, false, nil
	}
	n := 0
	for _, c := range []byte(v) {
		if c < '0' || c > '9' {
			return 0, false, ErrMalformedRequest
		}
		n = n*10 + int(c-'0')
	}
	return n, true, nil
}

// readChunkedBody decodes a chunked-transfer-encoded body directly against
// after's byte indices, rather than through a buffered io.Reader: a
// bufio-wrapped reader (as net/http/httputil.NewChunkedReader requires)
// reads ahead in fixed-size blocks internally, which would make "how many
// raw bytes did decoding consume" unrecoverable and risk eating into a
// pipelined request that immediately follows this one in the same buffer.
// Indexing directly keeps consumed exact.
//
// Returns ok=false, not an error, when the terminating zero-length chunk
// (and any trailer section) has not yet been fully observed in after --
// that is a need-more-data condition; the caller retries after the next
// Append.
func readChunkedBody(after []byte) (body []byte, consumed int, ok bool, err error) {
	pos := 0
	var out []byte
	for {
		lineEnd := bytes.Index(after[pos:], []byte("\r\n"))
		if lineEnd == -1 {
			return nil, 0, false, nil
		}
		sizeLine := after[pos : pos+lineEnd]
		if i := bytes.IndexByte(sizeLine, ';'); i != -1 { // chunk extensions, ignored
			sizeLine = sizeLine[:i]
		}
		size, perr := strconv.ParseUint(strings.TrimSpace(string(sizeLine)), 16, 32)
		if perr != nil {
			return nil, 0, false, ErrMalformedRequest
		}
		pos += lineEnd + 2

		if size == 0 {
			if len(after)-pos >= 2 && bytes.Equal(after[pos:pos+2], []byte("\r\n")) {
				return out, pos + 2, true, nil
			}
			trailerEnd := bytes.Index(after[pos:], []byte("\r\n\r\n"))
			if trailerEnd == -1 {
				return nil, 0, false, nil
			}
			return out, pos + trailerEnd + 4, true, nil
		}

		end := pos + int(size)
		if len(after) < end+2 {
			return nil, 0, false, nil
		}
		out = append(out, after[pos:end]...)
		if !bytes.Equal(after[end:end+2], []byte("\r\n")) {
			return nil, 0, false, ErrMalformedRequest
		}
		pos = end + 2
	}
}
