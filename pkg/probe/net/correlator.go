package net

import (
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
// docs/plan/06_tier3_network_design.md section 8.
type Coverage struct {
	Connections        int    // NET_CONNECT seen
	WithHostname       int    // SNI parsed from a ClientHello
	WithContent        int    // at least one HTTP request attributed to a connection
	FramesUnattributed int    // ssl_frame whose request could not be joined to a connection or parsed
	ContentUnsupported int    // h2 connections (ALPN negotiated h2; content parsing skipped)
	FaultedReads       uint64 // SSL_write calls whose plaintext read faulted in-kernel (see D5)
	RingbufDrops       uint64 // records the net and TLS ring buffers discarded because they were full
	UntrackedChildren  uint64 // descendants left untracked because a tracked_pids map was full (lower bound)
	StateMapFull       uint64 // connections lost because the kernel conns map was full (lower bound)
}

// sslKey identifies the (tgid, tid) pair a run of ssl_frames belongs to.
// Frames from the same thread are assumed to belong to one logical
// request/response stream at a time -- see the design doc D1 resolution
// (section 13): since the write-bracket join is abandoned, this is the only
// correlation signal available short of parsing BoringSSL's SSL* internals.
type sslKey struct {
	tgid uint32
	tid  uint32
}

// handleSSLFrame feeds one captured SSL_write payload into the per-thread
// reassembly stream and emits a models.NetRequest GroundTruthEvent for every
// complete HTTP/1.1 request it yields. Per D3 (design doc section 13), the
// raw plaintext never leaves this function: only RequestHash and the fields
// CanonicalNetTarget needs are retained in the emitted event.
func (o *Observer) handleSSLFrame(tgid, tid uint32, payload []byte, ts time.Time) {
	key := sslKey{tgid: tgid, tid: tid}
	stream := o.pending[key]
	if stream == nil {
		stream = tlsparse.NewStream()
		o.pending[key] = stream
	}
	stream.Append(payload)

	for {
		req, ok, err := tlsparse.ParseHTTP1(stream)
		if err != nil {
			// Not an HTTP/1.1 request (h2 ciphertext-looking-like-plaintext
			// never happens post-decryption, but a partial/aliased capture
			// or an ALPN-negotiated h2 connection produces bytes this
			// parser can't make sense of). Drop the rest of this thread's
			// buffered bytes rather than retrying forever against the same
			// malformed prefix.
			delete(o.pending, key)
			o.coverage.FramesUnattributed++
			return
		}
		if !ok {
			return // need more bytes; wait for the next ssl_frame
		}
		o.emitNetRequest(tgid, req, ts)
	}
}

// emitNetRequest turns one parsed HTTP/1.1 request into a models.NetRequest
// GroundTruthEvent. The host comes from the request's own Host header per
// the D1 resolution -- this is the join key back to a connection, not
// connection state itself, so a request line's target host need not equal
// any (tgid, fd) tracked in o.conns for the event to be emitted.
func (o *Observer) emitNetRequest(tgid uint32, req *tlsparse.HTTPRequest, ts time.Time) {
	host := req.Headers.Get("Host")
	if host == "" {
		host = o.newestHostForTGID(tgid)
	}
	if host == "" {
		o.coverage.FramesUnattributed++
		return
	}

	port := 0
	if i := strings.LastIndexByte(host, ':'); i != -1 && !strings.Contains(host[i:], "]") {
		if p, err := parsePort(host[i+1:]); err == nil {
			port = p
			host = host[:i]
		}
	}

	target := models.CanonicalNetTarget(req.Method, host, port, req.Path, req.Query)

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
	}

	o.coverage.WithContent++
	select {
	case o.events <- event:
	default:
		o.dropped.Add(1)
	}
}

// newestHostForTGID falls back to the most recently opened tracked
// connection's SNI hostname for tgid, for the rare case a captured request
// has no Host header (HTTP/1.0, or a client that omits it). Best effort:
// with no Host header and no SNI on any open connection for this tgid,
// there is nothing left to attribute the request to.
func (o *Observer) newestHostForTGID(tgid uint32) string {
	var best string
	var bestAt time.Time
	for k, c := range o.conns {
		if k.tgid != tgid || c.host == "" {
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
