package tlsparse

// Stream reassembles plaintext bytes delivered in arbitrary-sized chunks
// (one per captured SSL_write call, in the real correlator) into a single
// ordered buffer that ParseHTTP1 consumes incrementally. A chunk boundary
// carries no framing significance: a request line, a header, or a body can
// be split across any number of Append calls, and a single Append can also
// carry more than one complete request (pipelining).
type Stream struct {
	buf []byte
}

// NewStream returns an empty Stream.
func NewStream() *Stream {
	return &Stream{}
}

// Append adds newly observed plaintext bytes to the end of the stream.
func (s *Stream) Append(data []byte) {
	s.buf = append(s.buf, data...)
}

// Len reports the number of buffered, unconsumed bytes.
func (s *Stream) Len() int {
	return len(s.buf)
}

// consume discards the first n bytes, called by a parser after it has
// successfully extracted one complete message from the front of the buffer.
func (s *Stream) consume(n int) {
	s.buf = s.buf[n:]
}

// Take returns the buffered, unconsumed bytes and empties the stream: what
// follows the last request on a connection that changes protocol.
func (s *Stream) Take() []byte {
	b := s.buf
	s.buf = nil
	return b
}
