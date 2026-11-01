package net

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/tlsparse"
)

var errNotAPort = errors.New("net: not a port")

// Coverage reports how much of the network activity seen by the kernel-side
// program was successfully attributed to content, per
// docs/architecture/13_probe_net.md.
type Coverage struct {
	Connections        int    // NET_CONNECT seen
	DNS                int    // net_dns events: DNS queries with their question, and port-53 connections that sent bytes no query was read from (N-20, N-27)
	DNSNamed           int    // net_dns events that carry the question (N-27)
	DNSUnparsed        int    // sends to port 53 whose bytes did not parse as a DNS query; counted, not trusted (N-27)
	Datagrams          int    // datagrams to an explicit address recorded: every one to port 53, one per socket and destination otherwise (N-28)
	AddressProbes      int    // connections to port 0: the resolver's source-address selection, not emitted
	OpenAtStop         int    // connections still open when the capture stopped, emitted then with their connect time (N-21)
	Replaced           int    // connections replaced by a new connect on the same socket before they were emitted, emitted then with their connect time (N-24)
	Dials              int    // connections closed with no name and nothing written, emitted as net_dial capability evidence (N-22)
	WithHostname       int    // SNI parsed from a ClientHello
	HellosFollowed     int    // ClientHellos whose first send did not hold them whole, followed into later sends (N-31)
	WithContent        int    // at least one HTTP request attributed to a connection
	FramesUnattributed int    // ssl_frame whose request could not be joined to a connection or parsed
	ContentUnsupported int    // no longer counted (N-46): before it, connections whose ClientHello offered h2 in ALPN
	FaultedReads       uint64 // SSL_write calls whose plaintext read faulted in-kernel (see D5)
	RingbufDrops       uint64 // records the net, TLS and rustls ring buffers discarded because they were full: NetRingDrops plus TLSRingDrops plus AEADRingDrops
	NetRingDrops       uint64 // records the net ring buffer discarded (N-33)
	TLSRingDrops       uint64 // write frames the TLS ring buffer discarded (N-33)
	UntrackedChildren  uint64 // descendants left untracked because a tracked_pids map was full (lower bound)
	StateMapFull       uint64 // connections lost because the kernel conns map was full (lower bound)
	IOURingNetOps      uint64 // io_uring operations on sockets by tracked processes, which no hook records (N-25); event loss
	IOURingOps         uint64 // io_uring operations of any kind by tracked processes; diagnostic
	IOURingRings       uint64 // io_uring rings set up by tracked processes; diagnostic
	HelloFaults        uint64 // hello reads that faulted on a connection still waiting for its hello; content gap (no hostname), not event loss
	FramesTruncated    int    // SSL_write calls larger than the capture copies; a request whose head the copied bytes hold is emitted cut (RequestsCut), otherwise the request stream is dropped and counted in FramesUnattributed too
	RequestsCut        int    // requests emitted cut: their head was copied and bytes of their body were not (N-44); counted in WithContent too

	// HTTP/2 (N-33, N-46): the connections whose request stream begins with
	// the client preface are parsed by the HTTP/2 layer.
	H2Preface            int // TLS connections whose request stream began with the HTTP/2 client preface
	H2PrefaceUnvalidated int // write frames that began with the preface while offset validation read them, before content capture was active
	FramesH2             int // write frames on connections counted in H2Preface, the preface's included
	H2Requests           int // requests emitted from HTTP/2 streams; counted in WithContent too
	H2Responses          int // responses emitted from HTTP/2 streams; counted in Responses too
	H2Unparsed           int // HTTP/2 directions that stopped parsing: a protocol or HPACK error, or bytes missed outside a DATA payload; a lost server direction counts in ResponsesUnparsed too
	H2Malformed          int // HTTP/2 streams not followed: a header block that is no request or response, or a stream past the bound
	H2NoPreface          int // request streams that did not parse as HTTP/1.x and began like an HTTP/2 frame: an h2 connection whose preface came before the capture

	// Response capture (N-29). All diagnostic; ResponseGaps in
	// ProbeCoverage sums the ones that mean missing response data.
	Responses             int    // net_response events emitted
	ResponsesUnpaired     int    // emitted with no request seen on the connection; the target names the host only
	ResponsesUnattributed int    // parsed but not emitted: no request, so no host, on the connection
	ResponsesIncomplete   int    // emitted before their body ended: end of capture, connection reused, or bytes that did not parse
	ResponsesTruncated    int    // responses with bytes the capture missed (a read larger than it copies)
	ResponsesUnparsed     int    // times a connection's reads stopped parsing as HTTP/1.x responses and were skipped up to the next status line
	SSEEvents             int    // server-sent events counted across all responses
	ReadsUnvalidated      int    // SSL_read frames discarded before a read began with a status line, which validates the SSL_read offset
	ReadFaults            uint64 // SSL_read buffers whose read faulted in-kernel
	ReadDrops             uint64 // SSL_read frames the TLS ring buffer discarded because it was full

	// WebSocket (N-41), on any content method's streams.
	WebSockets       int // request streams switched to WebSocket frames by an upgrade request
	WSAccepted       int // 101 responses accepting a WebSocket
	WSRequests       int // client messages emitted as net_request
	WSServerMessages int // server messages counted into net_response turns
	WSModelRequests  int // client messages that parsed as a Responses API request and carry its digest (P-42)
	WSRefused        int // WebSocket directions not parsed: an extension the parser cannot decode, a compressed frame with none agreed, a compressed message over the decoder's bound, client frames before the accept over 1 MiB
	// WSRefusedReasons counts each refusal by its reason (at most 16, the
	// rest under "(other)").
	WSRefusedReasons map[string]int
	WSDeflate        int // accepts that agreed to permessage-deflate, decoded (N-43)
	WSUnparsed       int // WebSocket directions ended by a malformed frame or missing bytes

	// rustls (tls-rustls-aead, N-39, N-40).
	AEADUnvalidated int    // rustls frames discarded before a frame of their direction began with an HTTP/1.x request or status line
	AEADUnbound     int    // rustls read frames with no socket (no receive seen on their thread), kept per decrypter
	AEADRebound     int    // binds of an encrypter to a socket other than its first, ignored
	AEADUnpaired    int    // encrypters bound to a socket whose reads had begun a state of their own
	AEADRingDrops   uint64 // rustls frames and bind records the aead_events ring discarded because it was full
}

// sslKey identifies the connection a run of ssl_frames belongs to: the
// process and the SSL object the call was made on (N-30). Since the
// write-bracket join is abandoned (N-D1), the SSL* pointer is the only
// connection identity the uprobes see; it keeps apart the streams of
// connections one thread serves in turn, as an event loop does. A pointer
// the allocator reuses for a later connection continues the earlier key.
//
// kind keeps apart the identities of the rustls side (N-40): keyAEADEnc and
// keyAEADDec are its encrypter and decrypter objects, keySock a socket inode
// number its records were bound to; keySSL, the zero value, is an SSL*.
type sslKey struct {
	tgid uint32
	kind uint8
	ssl  uint64
}

// tlsConn is the content state of one TLS connection: the request stream
// being reassembled, the response parser, and the latest request still
// waiting for its response.
type tlsConn struct {
	req      *tlsparse.Stream
	resp     *tlsparse.ResponseParser
	last     *sentRequest
	host     string // host and port of the latest attributed request
	port     int
	lastSeen time.Time
	// h2 is the HTTP/2 state once the request stream began with the client
	// preface, or the read side with a server's SETTINGS frame (N-46).
	h2 *h2Conn
	// readStarted is set once a read was fed to the HTTP/1.x response
	// parser, after which a SETTINGS frame no longer starts the h2 side.
	readStarted bool
	// keys are the keys o.tlsConns holds this state under: its own, and the
	// socket a rustls encrypter was bound to (N-40).
	keys []sslKey
	// ws is the WebSocket state once an upgrade request or accept was seen
	// on the connection (N-41).
	ws *wsConn
	// skip is the number of bytes of a cut request's body still to come
	// after the bytes the capture missed (N-44): the stream passes over
	// them before it parses the next request.
	skip int
}

// sentRequest is what a response needs of the request it answers.
type sentRequest struct {
	target string // "" when the request could not be attributed to a host
	method string
}

// maxTLSConns bounds the connections whose content state is kept. Past it,
// the connection seen least recently is dropped (and its response in
// progress emitted as incomplete) to make room.
const maxTLSConns = 4096

func (o *Observer) tlsConn(key sslKey, ts time.Time) *tlsConn {
	c := o.tlsConns[key]
	if c == nil {
		if len(o.tlsConns) >= maxTLSConns {
			o.evictTLSConn()
		}
		c = &tlsConn{req: tlsparse.NewStream(), resp: tlsparse.NewResponseParser(), keys: []sslKey{key}}
		c.resp.Bodyless = func() bool { return c.last != nil && c.last.method == "HEAD" }
		o.tlsConns[key] = c
	}
	c.lastSeen = ts
	return c
}

func (o *Observer) evictTLSConn() {
	var oldest sslKey
	var at time.Time
	first := true
	for k, c := range o.tlsConns {
		if first || c.lastSeen.Before(at) {
			oldest, at, first = k, c.lastSeen, false
		}
	}
	o.closeTLSConn(oldest)
}

// handleSSLFrame feeds one captured SSL_write payload into its connection's
// reassembly stream and emits a models.NetRequest GroundTruthEvent for every
// complete HTTP/1.1 request it yields. Per N-D3, the
// raw plaintext never leaves this function: only RequestHash and the fields
// CanonicalNetTarget needs are retained in the emitted event. missing is the
// number of bytes the call wrote beyond the captured payload.
func (o *Observer) handleSSLFrame(key sslKey, payload []byte, missing int, ts time.Time) {
	c := o.tlsConn(key, ts)
	if c.ws != nil && (c.ws.client != nil || c.ws.refused) {
		o.wsClientBytes(key.tgid, c, payload, missing, ts)
		return
	}
	if c.h2 != nil && c.h2.refused {
		if !validRequestStart(payload) {
			return
		}
		// A request line or preface: the key was reused for a new
		// connection.
		o.h2Close(key.tgid, c)
		c.h2 = nil
	}
	if c.req.Len() == 0 && c.skip == 0 && bytes.HasPrefix(payload, h2ClientPreface) && (c.h2 == nil || c.h2.client == nil || c.h2.client.Err() != nil) {
		// A new h2 connection: the first, or one that reuses the key after
		// the previous one's client direction ended.
		o.h2Start(key.tgid, c)
	}
	if c.h2 == nil && c.req.Len() == 0 && c.skip == 0 && !httpRequestLineRE.Match(payload) && tlsparse.LooksLikeH2Frame(payload) {
		// An h2 connection whose preface came before the capture: its
		// header tables are unknown, so both directions are refused.
		c.h2 = &h2Conn{refused: true}
		o.coverage.H2NoPreface++
		o.coverage.FramesUnattributed++
		return
	}
	if missing > 0 {
		o.coverage.FramesTruncated++
	}
	if c.h2 != nil && c.h2.client != nil {
		if c.h2.client.Err() == nil || !httpRequestLineRE.Match(payload) {
			o.coverage.FramesH2++
			o.h2ClientBytes(key.tgid, c, payload, missing, ts)
			return
		}
		// An HTTP/1.x request after the h2 connection ended: the key was
		// reused for HTTP/1.1.
		c.h2 = nil
	}
	if c.skip > 0 {
		// The rest of a cut request's body (N-44): bytes the call wrote
		// first, then the bytes it wrote beyond the copy.
		n := min(len(payload), c.skip)
		payload, c.skip = payload[n:], c.skip-n
		if len(payload) == 0 {
			n = min(missing, c.skip)
			missing, c.skip = missing-n, c.skip-n
		}
		if len(payload) == 0 && missing == 0 {
			return
		}
	}
	c.req.Append(payload)
	if !o.parseRequests(key, c, ts) {
		if missing > 0 && c.ws != nil {
			// The hole follows the client frames after an upgrade.
			o.wsClientBytes(key.tgid, c, nil, missing, ts)
		}
		return
	}
	if missing == 0 {
		return
	}
	// The request stream has a hole: a body hashed across it would be
	// wrong. A request whose head was copied is emitted cut, with no hash,
	// and answers the response that follows (N-44); its framing goes on past
	// the hole only when its length says where it ends.
	req, skip, ok, err := tlsparse.CutHTTP1(c.req, missing)
	if err != nil || !ok {
		c.req = tlsparse.NewStream()
		o.coverage.FramesUnattributed++
		return
	}
	sent := &sentRequest{method: req.Method}
	if target, host, port, ok := o.emitNetRequest(key.tgid, req, true, ts); ok {
		sent.target = target
		c.host, c.port = host, port
	}
	c.last = sent
	c.req = tlsparse.NewStream()
	c.skip = max(skip, 0)
}

// parseRequests emits every complete request the connection's stream holds.
// It reports false when the stream is done with: its bytes did not parse and
// were discarded, or the connection switched to WebSocket frames.
func (o *Observer) parseRequests(key sslKey, c *tlsConn, ts time.Time) bool {
	for {
		req, ok, err := tlsparse.ParseHTTP1(c.req)
		if err != nil {
			// Not an HTTP/1.1 request (h2 ciphertext-looking-like-plaintext
			// never happens post-decryption, but a partial/aliased capture
			// or an ALPN-negotiated h2 connection produces bytes this
			// parser can't make sense of). Drop the rest of this
			// connection's buffered bytes rather than retrying forever
			// against the same malformed prefix.
			c.req = tlsparse.NewStream()
			o.coverage.FramesUnattributed++
			return false
		}
		if !ok {
			return true // need more bytes; wait for the next ssl_frame
		}
		sent := &sentRequest{method: req.Method}
		if target, host, port, ok := o.emitNetRequest(key.tgid, req, false, ts); ok {
			sent.target = target
			c.host, c.port = host, port
		}
		c.last = sent
		if tlsparse.IsWebSocketUpgrade(req) {
			// What follows on this stream is the client's frames (N-41).
			o.wsUpgrade(c, req)
			if rest := c.req.Take(); len(rest) > 0 {
				o.wsClientBytes(key.tgid, c, rest, 0, ts)
			}
			return false
		}
	}
}

// emitNetRequest turns one parsed HTTP/1.1 request into a models.NetRequest
// GroundTruthEvent. The host comes from the request's own Host header per
// the D1 resolution -- this is the join key back to a connection, not
// connection state itself, so a request line's target host need not equal
// any (tgid, fd) tracked in o.conns for the event to be emitted.
//
// A cut request (N-44) is emitted with RequestCut set and no RequestHash:
// bytes of its body were not captured.
//
// It returns the target, host and port, with ok false when the request
// could not be attributed to a host and nothing was emitted.
func (o *Observer) emitNetRequest(tgid uint32, req *tlsparse.HTTPRequest, cut bool, ts time.Time) (target, host string, port int, ok bool) {
	var reqHash *string
	if len(req.Body) > 0 && !cut {
		sum := sha256.Sum256(req.Body)
		h := "sha256:" + hex.EncodeToString(sum[:])
		reqHash = &h
	}
	return o.emitRequest(tgid, req, reqHash, cut, ts)
}

// requestTarget attributes a request to a host and builds its target, as
// emitNetRequest does, without emitting anything. ok is false when the
// request names no host and its process has no connection with an SNI name.
func (o *Observer) requestTarget(tgid uint32, req *tlsparse.HTTPRequest) (target, host string, port int, ok bool) {
	host = req.Headers.Get("Host")
	if host == "" {
		host = o.newestHostForTGID(tgid)
	}
	if host == "" {
		return "", "", 0, false
	}
	if i := strings.LastIndexByte(host, ':'); i != -1 && !strings.Contains(host[i:], "]") {
		if p, err := parsePort(host[i+1:]); err == nil {
			port = p
			host = host[:i]
		}
	}
	return models.CanonicalNetTarget(req.Method, host, port, req.Path, req.Query), host, port, true
}

// emitRequest emits a request whose body hash is computed: nil with no body
// or a cut one. An HTTP/1.x request's comes from its body, an HTTP/2
// request's from its stream (N-46).
func (o *Observer) emitRequest(tgid uint32, req *tlsparse.HTTPRequest, reqHash *string, cut bool, ts time.Time) (target, host string, port int, ok bool) {
	target, host, port, ok = o.requestTarget(tgid, req)
	if !ok {
		o.coverage.FramesUnattributed++
		return "", "", 0, false
	}

	event := models.GroundTruthEvent{
		Timestamp:   ts,
		ActionType:  models.NetRequest,
		Target:      target,
		RequestHash: reqHash,
		RequestCut:  cut,
		PID:         tgid,
	}

	o.coverage.WithContent++
	if cut {
		o.coverage.RequestsCut++
	}
	select {
	case o.events <- event:
	default:
		o.dropped.Add(1)
	}
	return target, host, port, true
}

// newestHostForTGID falls back to the most recently opened tracked
// connection's SNI hostname for tgid, for the rare case a captured request
// has no Host header (HTTP/1.0, or a client that omits it). Best effort:
// with no Host header and no SNI on any open connection for this tgid,
// there is nothing left to attribute the request to.
func (o *Observer) newestHostForTGID(tgid uint32) string {
	var best string
	var bestAt time.Time
	for _, c := range o.conns {
		if c.tgid != tgid || c.host == "" {
			continue
		}
		if best == "" || c.openedAt.After(bestAt) {
			best = c.host
			bestAt = c.openedAt
		}
	}
	return best
}

func parsePort(s string) (int, error) {
	n := 0
	if s == "" {
		return 0, errNotAPort
	}
	for _, c := range []byte(s) {
		if c < '0' || c > '9' {
			return 0, errNotAPort
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}
