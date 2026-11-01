package models

import "time"

// ResponseAttestation is what the net probe records of one HTTP response it
// read over TLS (N-29): enough to identify the response, join it to its
// request and to the transcript entry that names its request id, and say
// how much arrived and when. The plaintext itself is never kept (N-D3).
// Nothing in it is compared with a trajectory (N-11).
type ResponseAttestation struct {
	// Status is the status code of the status line.
	Status int `json:"status"`
	// RequestID is the value of the response's request-id header, or of
	// x-request-id when it has none. Empty when neither is present or the
	// value is longer than 256 bytes or not printable ASCII.
	RequestID string `json:"request_id,omitempty"`
	// ContentType is the media type of the Content-Type header, lowercased,
	// without parameters. ContentEncoding is the Content-Encoding header,
	// lowercased. Each is at most 128 bytes, empty otherwise.
	ContentType     string `json:"content_type,omitempty"`
	ContentEncoding string `json:"content_encoding,omitempty"`
	// BodyBytes is the length of the body with the transfer coding
	// (chunked) removed and the content coding kept: the bytes received, or
	// stated by the framing for bytes the capture missed.
	BodyBytes int64 `json:"body_bytes"`
	// BodyHash is "sha256:<hex>" of those bytes. Empty when the body did not
	// end by its framing within the capture, or bytes of it were missed, so
	// an empty hash means not measured, never an empty body (whose hash is
	// that of zero bytes).
	BodyHash string `json:"body_hash,omitempty"`
	// End is when the last byte of the response was read, or when the
	// capture gave up on it (see Complete). The event's Timestamp is when
	// the status line was read.
	End time.Time `json:"end"`
	// Complete is true when the body ended by its framing (Content-Length,
	// the last chunk, or a status that has no body). False for a body cut
	// off by the end of the capture, by a connection reused before it
	// ended, or by bytes that did not parse.
	Complete bool `json:"complete"`
	// Truncated is true when bytes of the response were not captured: a
	// read larger than the probe copies.
	Truncated bool `json:"truncated,omitempty"`
	// Paired is true when the request this response answers was seen on
	// the same connection; the event's Target is then that request's
	// target. False: the target names only the connection's host.
	Paired bool `json:"paired"`
	// SSE summarizes a text/event-stream body. Nil for any other body, and
	// for a stream whose content coding the probe cannot decode.
	SSE *SSESummary `json:"sse,omitempty"`
	// WebSocket summarizes the server messages of a WebSocket turn: the
	// messages a server sent on an upgraded connection between two client
	// messages (N-41). Nil for an HTTP response.
	WebSocket *WebSocketSummary `json:"websocket,omitempty"`
}

// WebSocketSummary counts the server messages of one WebSocket turn.
type WebSocketSummary struct {
	// Messages is the number of complete data messages.
	Messages int `json:"messages"`
	// Types counts them by the top-level JSON "type" of a text message,
	// "(text)" or "(binary)" without one. At most 16 names are kept; the
	// others are counted under "(other)".
	Types map[string]int `json:"types,omitempty"`
}

// SSESummary counts the events of a server-sent event stream.
type SSESummary struct {
	// Events is the number of events dispatched: blocks that carried at
	// least one data line.
	Events int `json:"events"`
	// Types counts the events by their event field ("message" when absent).
	// At most 16 names, of at most 64 bytes each, are kept; the others are
	// counted under "(other)".
	Types map[string]int `json:"types,omitempty"`
	// Overflow is true when a line exceeded 1 MiB or bytes were missed, and
	// counting stopped there; Events then counts the events before it.
	Overflow bool `json:"overflow,omitempty"`
}
