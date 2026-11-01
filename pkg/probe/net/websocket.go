package net

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"slices"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/tlsparse"
)

// WebSocket content (N-41), on the streams of any content method: after an
// upgrade request the client's direction is parsed as frames, and after a
// 101 that accepts a WebSocket the server's is. Each client message is a
// net_request whose target is the upgrade's with the method WS and whose
// hash is that of the message's unmasked payload; the server's messages
// between two client messages are one turn, a net_response attestation.

// maxWSPending bounds the client bytes held, when the upgrade request
// offered an extension, until the accept says which was agreed.
const maxWSPending = 1 << 20

// maxWSReasons bounds the distinct refusal reasons the coverage keeps; the
// rest count under "(other)".
const maxWSReasons = 16

// maxWSTypes bounds the type names a turn's summary keeps, and the
// response ids.
const maxWSTypes = 16

// maxModelRequest is the longest client text message kept whole, briefly,
// for its Responses API digest (P-42); a longer one gets none.
const maxModelRequest = 16 << 20

// wsConn is the WebSocket state of one connection.
type wsConn struct {
	// target is "WS https://host[:port]path[?query]" from the upgrade
	// request, or from the connection's host alone when no request was
	// seen; "" when neither names a host.
	target string
	// paired: the upgrade request was seen, so target names its path.
	paired bool
	// client and server parse the two directions; nil until the upgrade
	// request (client) or the accept (server) was seen.
	client, server *tlsparse.WSStream
	// refused: the accept negotiated an extension the parser cannot
	// decode, so neither direction is parsed.
	refused bool
	// offered: the upgrade request offered an extension, so the client's
	// frames may be compressed and are held in pending until the accept
	// says what was agreed (N-43).
	offered bool
	pending []wsChunk
	held    int
	turn    *wsTurn
	at      time.Time // the time of the read being parsed, for OnData
}

// wsChunk is client bytes held until the accept.
type wsChunk struct {
	p       []byte
	missing int
	at      time.Time
}

// wsTurn accumulates the server messages after a client message.
type wsTurn struct {
	start, end time.Time
	bytes      int64
	hash       hash.Hash
	messages   int
	types      map[string]int
	ids        []string
	truncated  bool
}

// wsUpgrade switches the request stream of c to WebSocket frames after the
// upgrade request req.
func (o *Observer) wsUpgrade(c *tlsConn, req *tlsparse.HTTPRequest) {
	o.coverage.WebSockets++
	w := &wsConn{client: tlsparse.NewWSStream(true)}
	w.client.KeepText = maxModelRequest
	w.offered = req.Headers.Get("Sec-WebSocket-Extensions") != ""
	if c.last != nil && c.last.target != "" {
		w.target = models.CanonicalNetTarget("WS", c.host, c.port, req.Path, req.Query)
		w.paired = true
	}
	c.ws = w
}

// wsAccept switches the read side of c to WebSocket frames after the 101
// response r, decoding both directions when r agreed to permessage-deflate
// (N-43), or refuses both when r negotiated an extension the parser cannot
// honour, counting the reason. The client bytes held for the accept are
// then parsed.
func (o *Observer) wsAccept(tgid uint32, c *tlsConn, r *tlsparse.Response) {
	o.coverage.WSAccepted++
	if c.ws == nil {
		c.ws = &wsConn{}
		if c.host != "" {
			c.ws.target = "WS " + hostTarget(c.host, c.port)
		}
	}
	w := c.ws
	deflate, err := tlsparse.ParseWSExtensions(r.Extensions)
	if err != nil {
		w.refused, w.pending = true, nil
		reason := err.Error()
		var xe *tlsparse.WSExtensionError
		if errors.As(err, &xe) {
			reason = xe.Reason
		}
		o.wsRefuse(reason)
		return
	}
	w.server = tlsparse.NewWSStream(false)
	w.server.OnData = func(p []byte) {
		// A compressed message's bytes arrive at its last frame; the turn
		// starts at its first.
		at := w.server.MessageStart()
		if at.IsZero() {
			at = w.at
		}
		t := w.turnAt(at)
		t.bytes += int64(len(p))
		t.hash.Write(p)
	}
	if deflate != nil {
		o.coverage.WSDeflate++
		w.server.Inflate(deflate.ServerNoContextTakeover)
		if w.client != nil {
			w.client.Inflate(deflate.ClientNoContextTakeover)
		}
	}
	held := w.pending
	w.pending, w.offered = nil, false
	for _, ch := range held {
		o.wsClientBytes(tgid, c, ch.p, ch.missing, ch.at)
	}
}

// wsRefuse counts one refused WebSocket direction and its reason.
func (o *Observer) wsRefuse(reason string) {
	o.coverage.WSRefused++
	if o.coverage.WSRefusedReasons == nil {
		o.coverage.WSRefusedReasons = map[string]int{}
	}
	if _, ok := o.coverage.WSRefusedReasons[reason]; !ok && len(o.coverage.WSRefusedReasons) >= maxWSReasons {
		reason = "(other)"
	}
	o.coverage.WSRefusedReasons[reason]++
}

func (w *wsConn) turnAt(at time.Time) *wsTurn {
	if w.turn == nil {
		w.turn = &wsTurn{start: at, end: at, hash: sha256.New(), types: map[string]int{}}
	}
	return w.turn
}

// wsFailed counts the error that ended one direction's parsing: a
// compressed frame with no agreed extension or a message over the
// decoder's bound is a refusal, with its reason; anything else (a
// malformed frame, data that does not decompress, missing bytes) leaves
// the direction unparsed.
func (o *Observer) wsFailed(err error) {
	switch {
	case errors.Is(err, tlsparse.ErrWSCompressed):
		o.wsRefuse("a compressed frame with no extension agreed")
	case errors.Is(err, tlsparse.ErrWSTooLarge):
		o.wsRefuse("a compressed message over the decoder's bound")
	default:
		o.coverage.WSUnparsed++
	}
}

// wsClientBytes parses client bytes of c: each message ends the server's
// turn before it and is emitted as a net_request.
func (o *Observer) wsClientBytes(tgid uint32, c *tlsConn, p []byte, missing int, ts time.Time) {
	w := c.ws
	if w.refused || w.client == nil {
		return
	}
	if w.offered && w.server == nil {
		if w.held+len(p) > maxWSPending {
			w.refused, w.pending = true, nil
			o.wsRefuse("client frames before the accept over 1 MiB")
			return
		}
		w.held += len(p)
		w.pending = append(w.pending, wsChunk{p: append([]byte(nil), p...), missing: missing, at: ts})
		return
	}
	err := w.client.Feed(p, missing, ts, func(m *tlsparse.WSMessage) {
		o.wsEndTurn(tgid, c, true)
		o.emitWSRequest(tgid, w, m)
	}, func(op byte) {
		if op == tlsparse.WSClose {
			o.wsEndTurn(tgid, c, true)
		}
	})
	if err != nil {
		o.wsFailed(err)
	}
}

// wsServerBytes parses server bytes of c into the current turn.
func (o *Observer) wsServerBytes(tgid uint32, c *tlsConn, p []byte, missing int, ts time.Time) {
	w := c.ws
	if w.refused || w.server == nil {
		return
	}
	w.at = ts
	err := w.server.Feed(p, missing, ts, func(m *tlsparse.WSMessage) {
		t := w.turnAt(m.Start)
		t.messages++
		t.end = m.End
		name := m.Type
		switch {
		case name != "":
		case m.Text:
			name = "(text)"
		default:
			name = "(binary)"
		}
		if _, ok := t.types[name]; !ok && len(t.types) >= maxWSTypes {
			name = "(other)"
		}
		t.types[name]++
		if id := m.ResponseID; id != "" && len(t.ids) < maxWSTypes && !slices.Contains(t.ids, id) {
			t.ids = append(t.ids, id)
		}
		o.coverage.WSServerMessages++
	}, func(op byte) {
		if op == tlsparse.WSClose {
			o.wsEndTurn(tgid, c, true)
		}
	})
	if err != nil {
		o.wsFailed(err)
		if errors.Is(err, tlsparse.ErrWSMissing) && w.turn != nil {
			w.turn.truncated = true
		}
		o.wsEndTurn(tgid, c, false)
	}
}

// emitWSRequest emits one client message as a net_request stamped at its
// first frame. A connection with no target counts FramesUnattributed.
func (o *Observer) emitWSRequest(tgid uint32, w *wsConn, m *tlsparse.WSMessage) {
	if w.target == "" {
		o.coverage.FramesUnattributed++
		return
	}
	h := m.Hash
	o.coverage.WSRequests++
	e := models.GroundTruthEvent{Timestamp: m.Start, ActionType: models.NetRequest, Target: w.target, RequestHash: &h, PID: tgid}
	if m.Body != nil {
		if r, ok := tlsparse.ParseResponsesRequest(m.Body); ok {
			d := &models.ModelRequestDigest{Type: r.Type, PreviousResponseID: r.PreviousResponseID, Truncated: r.Truncated, Items: []models.ModelItemDigest{}}
			for _, it := range r.Items {
				d.Items = append(d.Items, models.ModelItemDigest{Type: it.Type, Role: it.Role, CallID: it.CallID, Hash: it.Hash})
			}
			e.ModelRequest = d
			o.coverage.WSModelRequests++
		}
	}
	o.send(e)
}

// wsEndTurn emits the turn in progress on c, if any, as a net_response
// stamped at its first server byte: complete when it ended at a client
// message or a close with no server message cut off, its hash then that of
// the concatenated payloads of its messages.
func (o *Observer) wsEndTurn(tgid uint32, c *tlsConn, complete bool) {
	if c.ws == nil || c.ws.turn == nil {
		return
	}
	w, t := c.ws, c.ws.turn
	w.turn = nil
	if w.server != nil && w.server.InMessage() {
		complete = false
	}
	if t.truncated {
		complete = false
		o.coverage.ResponsesTruncated++
	}
	if w.target == "" {
		o.coverage.ResponsesUnattributed++
		return
	}
	end := t.end
	if !complete && c.lastSeen.After(end) {
		end = c.lastSeen
	}
	att := &models.ResponseAttestation{
		Status:    101,
		BodyBytes: t.bytes,
		End:       end,
		Complete:  complete,
		Truncated: t.truncated,
		Paired:    w.paired,
		WebSocket: &models.WebSocketSummary{Messages: t.messages, Types: t.types, ResponseIDs: t.ids},
	}
	if len(t.types) == 0 {
		att.WebSocket.Types = nil
	}
	if complete {
		att.BodyHash = "sha256:" + hex.EncodeToString(t.hash.Sum(nil))
	} else {
		o.coverage.ResponsesIncomplete++
	}
	if !w.paired {
		o.coverage.ResponsesUnpaired++
	}
	o.coverage.Responses++
	o.send(models.GroundTruthEvent{Timestamp: t.start, ActionType: models.NetResponse, Target: w.target, PID: tgid, Response: att})
}

// send delivers one event, counting it as dropped when the channel is full.
func (o *Observer) send(e models.GroundTruthEvent) {
	select {
	case o.events <- e:
	default:
		o.dropped.Add(1)
	}
}
