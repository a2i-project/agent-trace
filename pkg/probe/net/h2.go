package net

import (
	"slices"
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
	// early holds, by stream, responses that ended on a client stream the
	// client direction has not shown yet (N-50): the read of the response
	// reached the correlator before the write that opened its stream. Each
	// is emitted when its request is, or unpaired when the connection's
	// state closes or a later stream shows the request will not come.
	early map[uint32]*tlsparse.Response
	// opened is the highest client stream whose request head was read.
	opened uint32
}

// h2MaxEarly bounds the responses held for their request per connection;
// past it a response is emitted unpaired at once.
const h2MaxEarly = 64

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
		o.flushEarly(tgid, c, false)
	}
}

// emitH2Request emits one request and keeps its target for the response on
// its stream, or emits the response held for it (N-50). A cut request
// (bytes of its body missed, or its stream ended before END_STREAM)
// carries no hash (N-44). A request its client reset ends the response in
// progress on its stream.
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
	h := c.h2
	h.noteOpened(r.Stream)
	if early := h.early[r.Stream]; early != nil {
		delete(h.early, r.Stream)
		if o.emitResponse(tgid, c, early, sent) {
			o.coverage.H2Responses++
		}
	} else {
		h.sent[r.Stream] = sent
		if r.Reset && h.server != nil {
			h.server.Reset(r.Stream, ts, func(id uint32, resp *tlsparse.Response) { o.emitH2Response(tgid, c, id, resp) })
		}
	}
	o.flushEarly(tgid, c, false)
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
// body is still streaming (a response may end first). With neither, a
// response on a stream the client direction may still open is held for
// its request (N-50), and any other names the connection's host.
func (o *Observer) emitH2Response(tgid uint32, c *tlsConn, stream uint32, r *tlsparse.Response) {
	h := c.h2
	sent := h.sent[stream]
	delete(h.sent, stream)
	if sent == nil && h.client != nil {
		if head := h.client.Head(stream); head != nil {
			h.noteOpened(stream)
			sent = &sentRequest{method: head.Method}
			if target, _, _, ok := o.requestTarget(tgid, head.HTTPRequest); ok {
				sent.target = target
			}
		}
	}
	if sent == nil && h.mayOpen(stream) && len(h.early) < h2MaxEarly {
		if h.early == nil {
			h.early = map[uint32]*tlsparse.Response{}
		}
		h.early[stream] = r
		return
	}
	if o.emitResponse(tgid, c, r, sent) {
		o.coverage.H2Responses++
	}
}

// noteOpened records that the client direction showed the head of stream.
func (h *h2Conn) noteOpened(stream uint32) { h.opened = max(h.opened, stream) }

// mayOpen reports whether the client direction may still show the request
// on stream: a client stream (odd) above every stream it has shown, on a
// client direction not ended. Client streams open in increasing order
// (RFC 9113, 5.1.1), so a request on a lower stream will not come.
func (h *h2Conn) mayOpen(stream uint32) bool {
	if stream%2 == 0 || stream <= h.opened || h.clientLost {
		return false
	}
	return h.client == nil || h.client.Err() == nil
}

// flushEarly emits unpaired the held responses whose request will not
// come, all of them when the connection's state closes, in stream order.
func (o *Observer) flushEarly(tgid uint32, c *tlsConn, all bool) {
	h := c.h2
	ids := make([]uint32, 0, len(h.early))
	for id := range h.early {
		if all || !h.mayOpen(id) {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	for _, id := range ids {
		r := h.early[id]
		delete(h.early, id)
		if o.emitResponse(tgid, c, r, nil) {
			o.coverage.H2Responses++
		}
	}
}

// h2Close ends the capture of an h2 connection: the requests in progress
// are emitted cut, then the responses held for a request that never came
// unpaired, then the responses in progress incomplete, stamped at the
// connection's last frame.
func (o *Observer) h2Close(tgid uint32, c *tlsConn) {
	h := c.h2
	if h == nil {
		return
	}
	if h.client != nil {
		h.client.Close(func(r *tlsparse.H2Request) { o.emitH2Request(tgid, c, r, c.lastSeen) })
	}
	o.flushEarly(tgid, c, true)
	if h.server != nil {
		h.server.Close(c.lastSeen, func(id uint32, r *tlsparse.Response) { o.emitH2Response(tgid, c, id, r) })
	}
}
