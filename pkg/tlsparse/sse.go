package tlsparse

import "bytes"

// Bounds of the server-sent event parser.
const (
	maxSSELine    = 1 << 20
	maxSSETypes   = 16
	maxSSETypeLen = 64
	sseOtherType  = "(other)"
)

// SSEStats counts the events of a text/event-stream body.
type SSEStats struct {
	Events   int            // events dispatched: blocks with at least one data line
	Types    map[string]int // events by event field ("message" when absent); at most maxSSETypes names
	Overflow bool           // a line was too long or bytes were missed; counting stopped there
}

// sseParser splits an event stream into events as its bytes arrive, per the
// WHATWG event stream format: lines end in CRLF, LF or CR, a blank line
// dispatches the event, a line starting with ':' is a comment. It keeps
// only the line being read and the event field of the event being read.
type sseParser struct {
	stats   SSEStats
	line    []byte
	afterCR bool
	started bool
	event   string
	data    bool
	dead    bool
}

func newSSEParser() *sseParser {
	return &sseParser{stats: SSEStats{Types: map[string]int{}}}
}

var utf8BOM = []byte{0xef, 0xbb, 0xbf}

func (s *sseParser) write(p []byte) {
	if s.dead {
		return
	}
	if !s.started && len(p) > 0 {
		s.started = true
		p = bytes.TrimPrefix(p, utf8BOM)
	}
	for len(p) > 0 {
		if s.afterCR {
			s.afterCR = false
			if p[0] == '\n' {
				p = p[1:]
				continue
			}
		}
		i := bytes.IndexAny(p, "\r\n")
		if i == -1 {
			if len(s.line)+len(p) > maxSSELine {
				s.overflow()
				return
			}
			s.line = append(s.line, p...)
			return
		}
		if len(s.line)+i > maxSSELine {
			s.overflow()
			return
		}
		s.line = append(s.line, p[:i]...)
		s.afterCR = p[i] == '\r'
		p = p[i+1:]
		s.processLine(s.line)
		s.line = s.line[:0]
	}
}

func (s *sseParser) processLine(line []byte) {
	if len(line) == 0 {
		if s.data {
			s.stats.Events++
			s.tally(s.event)
		}
		s.event, s.data = "", false
		return
	}
	if line[0] == ':' {
		return
	}
	field, value, _ := bytes.Cut(line, []byte(":"))
	value = bytes.TrimPrefix(value, []byte(" "))
	switch string(field) {
	case "event":
		s.event = string(value)
	case "data":
		s.data = true
	}
}

func (s *sseParser) tally(name string) {
	if name == "" {
		name = "message"
	}
	if len(name) > maxSSETypeLen || !printable(name) {
		name = sseOtherType
	}
	if _, ok := s.stats.Types[name]; !ok && name != sseOtherType && len(s.stats.Types) >= maxSSETypes {
		name = sseOtherType
	}
	s.stats.Types[name]++
}

// overflow stops counting: the events read so far stand, the rest of the
// stream is not parsed.
func (s *sseParser) overflow() {
	s.stats.Overflow = true
	s.dead = true
	s.line = nil
}
