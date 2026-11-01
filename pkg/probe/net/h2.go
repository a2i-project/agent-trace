package net

import (
	"time"

	"github.com/agent-trace/agent-trace/pkg/tlsparse"
)

// HTTP/2 on the streams of any content method (N-46): a request stream that
// begins with the client preface is read by tlsparse.H2Client, and the read
// side of such a connection, or one that begins with a server's SETTINGS
// frame, by tlsparse.H2Server. Requests and responses become the same
// net_request and net_response records as HTTP/1.x ones, paired by stream.

// h2Conn is the HTTP/2 state of one connection.
type h2Conn struct {
	client *tlsparse.H2Client // nil until the preface was written
	server *tlsparse.H2Server // nil until the first read
	// sent holds the emitted requests by stream until their response.
	sent map[uint32]*sentRequest
	// clientLost and serverLost are set when the direction stopped
	// parsing, so each is counted once.
	clientLost, serverLost bool
	// refused marks a connection whose request stream began with h2 frames
	// and no preface: nothing of it is parsed.
	refused bool
}

// h2Start makes c an h2 connection whose client direction begins now. A
// connection whose previous client direction ended (the key reused) starts
// over: its responses in progress are emitted first.
func (o *Observer) h2Start(tgid uint32, c *tlsConn) {
	if c.h2 != nil && c.h2.client != nil {
		o.h2Close(tgid, c)
		c.h2 = nil
	}
	if c.h2 == nil {
		c.h2 = &h2Conn{sent: map[uint32]*sentRequest{}}
	}
	c.h2.client = tlsparse.NewH2Client()
	o.coverage.H2Preface++
}

// h2ClientBytes feeds one write to the client direction.
func (o *Observer) h2ClientBytes(tgid uint32, c *tlsConn, payload []byte, missing int, ts time.Time) {
	h := c.h2
	before := h.client.Malformed
	err := h.client.Feed(payload, missing, ts, func(r *tlsparse.H2Request) { o.emitH2Request(tgid, c, r, ts) })
	o.coverage.H2Malformed += h.client.Malformed - before
	if err != nil && !h.clientLost {
		h.clientLost = true
		o.coverage.H2Unparsed++
	}
}

// emitH2Request emits one request and keeps its target for the response on
// its stream. A cut request (bytes of its body missed, or its stream ended
// before END_STREAM) carries no hash (N-44). A request its client reset
// ends the response in progress on its stream.
func (o *Observer) emitH2Request(tgid uint32, c *tlsConn, r *tlsparse.H2Request, ts time.Time) {
	var hash *string
	if r.BodyHash != "" && !r.Cut {
		h := r.BodyHash
		hash = &h
	}
	sent := &sentRequest{method: r.Method}
	if target, host, port, ok := o.emitRequest(tgid, r.HTTPRequest, hash, r.Cut, ts); ok {
		sent.target = target
		c.host, c.port = host, port
		o.coverage.H2Requests++
	}
	c.h2.sent[r.Stream] = sent
	if r.Reset && c.h2.server != nil {
		c.h2.server.Reset(r.Stream, ts, func(id uint32, resp *tlsparse.Response) { o.emitH2Response(tgid, c, id, resp) })
	}
}

// h2ServerBytes feeds one read to the server direction, which starts with
// it. A direction that stops parsing loses its responses: ResponsesUnparsed.
func (o *Observer) h2ServerBytes(tgid uint32, c *tlsConn, payload []byte, missing int, ts time.Time) {
	if c.h2 == nil {
		c.h2 = &h2Conn{sent: map[uint32]*sentRequest{}}
	}
	h := c.h2
	if h.refused {
		if !h.serverLost {
			h.serverLost = true
			o.coverage.ResponsesUnparsed++
		}
		return
	}
	if h.server == nil {
		h.server = tlsparse.NewH2Server()
	}
	before := h.server.Malformed
	err := h.server.Feed(payload, missing, ts, func(id uint32, r *tlsparse.Response) { o.emitH2Response(tgid, c, id, r) })
	o.coverage.H2Malformed += h.server.Malformed - before
	if err != nil && !h.serverLost {
		h.serverLost = true
		o.coverage.H2Unparsed++
		o.coverage.ResponsesUnparsed++
	}
}

// emitH2Response emits the response on stream as the answer to the
// request emitted on it, or to the request whose head was read and whose
// body is still streaming (a response may end first); with neither, it
// names the connection's host.
func (o *Observer) emitH2Response(tgid uint32, c *tlsConn, stream uint32, r *tlsparse.Response) {
	sent := c.h2.sent[stream]
	delete(c.h2.sent, stream)
	if sent == nil && c.h2.client != nil {
		if head := c.h2.client.Head(stream); head != nil {
			sent = &sentRequest{method: head.Method}
			if target, _, _, ok := o.requestTarget(tgid, head.HTTPRequest); ok {
				sent.target = target
			}
		}
	}
	if o.emitResponse(tgid, c, r, sent) {
		o.coverage.H2Responses++
	}
}

// h2Close ends the capture of an h2 connection: the requests in progress
// are emitted cut, then the responses in progress incomplete, stamped at
// the connection's last frame.
func (o *Observer) h2Close(tgid uint32, c *tlsConn) {
	h := c.h2
	if h == nil {
		return
	}
	if h.client != nil {
		h.client.Close(func(r *tlsparse.H2Request) { o.emitH2Request(tgid, c, r, c.lastSeen) })
	}
	if h.server != nil {
		h.server.Close(c.lastSeen, func(id uint32, r *tlsparse.Response) { o.emitH2Response(tgid, c, id, r) })
	}
}
