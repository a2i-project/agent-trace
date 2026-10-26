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
	ContentUnsupported int    // connections whose ClientHello offered h2 in ALPN, whatever was negotiated
	FaultedReads       uint64 // SSL_write calls whose plaintext read faulted in-kernel (see D5)
	RingbufDrops       uint64 // records the net and TLS ring buffers discarded because they were full: NetRingDrops plus TLSRingDrops
	NetRingDrops       uint64 // records the net ring buffer discarded (N-33)
	TLSRingDrops       uint64 // write frames the TLS ring buffer discarded (N-33)
	UntrackedChildren  uint64 // descendants left untracked because a tracked_pids map was full (lower bound)
	StateMapFull       uint64 // connections lost because the kernel conns map was full (lower bound)
	IOURingNetOps      uint64 // io_uring operations on sockets by tracked processes, which no hook records (N-25); event loss
	IOURingOps         uint64 // io_uring operations of any kind by tracked processes; diagnostic
	IOURingRings       uint64 // io_uring rings set up by tracked processes; diagnostic
	HelloFaults        uint64 // hello reads that faulted on a connection still waiting for its hello; content gap (no hostname), not event loss
	FramesTruncated    int    // SSL_write calls larger than the capture copies; the request stream is dropped and counted in FramesUnattributed too

	// HTTP/2 (N-33). Diagnostic: the frames are handled as before.
	H2Preface            int // TLS connections whose request stream began with the HTTP/2 client preface
	H2PrefaceUnvalidated int // write frames that began with the preface while offset validation read them, before content capture was active
	FramesH2             int // write frames on connections counted in H2Preface, the preface's included

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
}

// sslKey identifies the connection a run of ssl_frames belongs to: the
// process and the SSL object the call was made on (N-30). Since the
// write-bracket join is abandoned (N-D1), the SSL* pointer is the only
// connection identity the uprobes see; it keeps apart the streams of
// connections one thread serves in turn, as an event loop does. A pointer
// the allocator reuses for a later connection continues the earlier key.
type sslKey struct {
	tgid uint32
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
	// h2 is set when the request stream began with the HTTP/2 preface and
	// cleared when a request parses on it (an SSL* reused for HTTP/1.1).
	h2 bool
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
		c = &tlsConn{req: tlsparse.NewStream(), resp: tlsparse.NewResponseParser()}
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
	if c.req.Len() == 0 && bytes.HasPrefix(payload, h2ClientPreface) {
		c.h2 = true
		o.coverage.H2Preface++
	}
	if c.h2 {
		o.coverage.FramesH2++
	}
	if missing > 0 {
		// The request stream has a hole: a body hashed across it would be
		// wrong, and its framing cannot be trusted past it.
		c.req = tlsparse.NewStream()
		o.coverage.FramesTruncated++
		o.coverage.FramesUnattributed++
		return
	}
	c.req.Append(payload)

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
			return
		}
		if !ok {
			return // need more bytes; wait for the next ssl_frame
		}
		c.h2 = false
		sent := &sentRequest{method: req.Method}
		if target, host, port, ok := o.emitNetRequest(key.tgid, req, ts); ok {
			sent.target = target
			c.host, c.port = host, port
		}
		c.last = sent
	}
}

// emitNetRequest turns one parsed HTTP/1.1 request into a models.NetRequest
// GroundTruthEvent. The host comes from the request's own Host header per
// the D1 resolution -- this is the join key back to a connection, not
// connection state itself, so a request line's target host need not equal
// any (tgid, fd) tracked in o.conns for the event to be emitted.
//
// It returns the target, host and port, with ok false when the request
// could not be attributed to a host and nothing was emitted.
func (o *Observer) emitNetRequest(tgid uint32, req *tlsparse.HTTPRequest, ts time.Time) (target, host string, port int, ok bool) {
	host = req.Headers.Get("Host")
	if host == "" {
		host = o.newestHostForTGID(tgid)
	}
	if host == "" {
		o.coverage.FramesUnattributed++
		return "", "", 0, false
	}

	if i := strings.LastIndexByte(host, ':'); i != -1 && !strings.Contains(host[i:], "]") {
		if p, err := parsePort(host[i+1:]); err == nil {
			port = p
			host = host[:i]
		}
	}

	target = models.CanonicalNetTarget(req.Method, host, port, req.Path, req.Query)

	var reqHash *string
	if len(req.Body) > 0 {
		sum := sha256.Sum256(req.Body)
		h := "sha256:" + hex.EncodeToString(sum[:])
		reqHash = &h
	}

	isTopLevel := true
	event := models.GroundTruthEvent{
		Timestamp:   ts,
		ActionType:  models.NetRequest,
		Target:      target,
		RequestHash: reqHash,
		IsTopLevel:  &isTopLevel,
		PID:         tgid,
	}

	o.coverage.WithContent++
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
