package net

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/tlsoffset"
	"github.com/agent-trace/agent-trace/pkg/tlsparse"
)

// Response capture (N-29): the SSL_read side of N1. tls.bpf.c stashes the
// buffer at SSL_read's entry and emits what the call returned at its return,
// on the same ring as the writes, so a response is never read before the
// request it answers. This file validates the SSL_read offset, parses the
// responses of each connection with tlsparse.ResponseParser and emits each
// as a models.NetResponse event carrying a models.ResponseAttestation.

// sslDirRead is the dir field of a frame captured at SSL_read's return.
const sslDirRead = 1

// maxHeldReads bounds the read frames the write validation holds for
// replay. More are counted in ReadsUnvalidated and dropped.
const maxHeldReads = 256

// httpStatusLineRE recognizes an HTTP/1.x status line at the start of a
// read. The first read that matches validates the SSL_read offset (N-D4,
// N-29), as a request line validates the SSL_write offset.
var httpStatusLineRE = regexp.MustCompile(`^HTTP/1\.[01] [1-5][0-9]{2}[ \r]`)

// attachWrite attaches the SSL side's write entry and return probes
// (SSL_write's, or SSL_write_ex's for tls-openssl-ex) at off; the return
// emits the write frame (N-37). Both or neither.
func (o *Observer) attachWrite(off uint64) ([]link.Link, error) {
	entry, err := o.exe.Uprobe("", o.writeProgs[0], &link.UprobeOptions{Address: off})
	if err != nil {
		return nil, err
	}
	ret, err := o.exe.Uretprobe("", o.writeProgs[1], &link.UprobeOptions{Address: off})
	if err != nil {
		_ = entry.Close()
		return nil, err
	}
	return []link.Link{entry, ret}, nil
}

// attachRead attaches the SSL side's read entry and return probes
// (SSL_read's, or SSL_read_ex's) at a file offset of the executable.
func (o *Observer) attachRead(off uint64) ([]link.Link, error) {
	entry, err := o.exe.Uprobe("", o.readProgs[0], &link.UprobeOptions{Address: off})
	if err != nil {
		return nil, err
	}
	ret, err := o.exe.Uretprobe("", o.readProgs[1], &link.UprobeOptions{Address: off})
	if err != nil {
		_ = entry.Close()
		return nil, err
	}
	return []link.Link{entry, ret}, nil
}

func closeLinks(ls []link.Link) {
	for _, l := range ls {
		_ = l.Close()
	}
}

// dedupCandidates drops repeated offsets, keeping the first (the cached
// one, when the cache named a candidate the scan also found).
func dedupCandidates(cs []tlsoffset.Candidate) []tlsoffset.Candidate {
	seen := map[uint64]bool{}
	out := cs[:0:0]
	for _, c := range cs {
		if !seen[c.FileOff] {
			seen[c.FileOff] = true
			out = append(out, c)
		}
	}
	return out
}

// startRead runs in Start after the write validation and before tlsReady
// closes. With content capture active it removes the validated SSL_write
// offset from the read candidates (with the read frames held from probes
// at that offset, which were writes read back) and starts validateRead;
// otherwise it releases the read probes and records why responses are not
// captured.
func (o *Observer) startRead() {
	if o.exe == nil {
		close(o.readDone)
		return
	}
	if !o.tlsActive {
		closeLinks(o.firstReadLinks)
		o.firstReadLinks = nil
		o.readAttachErr = errors.New("SSL_read not attached: SSL_write content capture did not validate")
		close(o.readDone)
		return
	}
	if len(o.readCands) > 0 && o.readCands[0].FileOff == o.writeOffset {
		closeLinks(o.firstReadLinks)
		o.firstReadLinks = nil
		kept := o.replay[:0]
		for _, rec := range o.replay {
			if rec.hdr.Dir != sslDirRead {
				kept = append(kept, rec)
			}
		}
		o.replay = kept
	}
	var cands []tlsoffset.Candidate
	for _, c := range o.readCands {
		if c.FileOff != o.writeOffset {
			cands = append(cands, c)
		}
	}
	o.readCands = cands
	if len(cands) == 0 {
		o.readAttachErr = fmt.Errorf("no SSL_read candidate in %s", o.plan.sslPath)
		close(o.readDone)
		return
	}
	timeout := o.cfg.ValidationTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	go o.validateRead(timeout)
}

// validateRead tries the SSL_read candidates in turn, each for up to
// timeout, and keeps the first during whose window correlate saw a read
// that begins with an HTTP/1.x status line (readOK). The window starts when
// the candidate is attached, or, for the first candidate, when New attached
// it. A candidate whose window passes is detached. The accepted offset is
// cached with the SSL_write offset. It returns, closing readDone, when a
// candidate is accepted, every one has failed, or Stop closes readStop.
func (o *Observer) validateRead(timeout time.Duration) {
	defer close(o.readDone)
	for i, cand := range o.readCands {
		var links []link.Link
		if i == 0 && o.firstReadLinks != nil {
			links, o.firstReadLinks = o.firstReadLinks, nil
		} else {
			var err error
			if links, err = o.attachRead(cand.FileOff); err != nil {
				continue
			}
		}
		accept := func() {
			o.readLinks = links
			o.readActive.Store(true)
			// From here a fault reading SSL_read_ex's byte count is a
			// lost response, counted (tls-openssl-ex).
			var zero, on uint32 = 0, 1
			_ = o.tlsObjs.SslReadCounting.Update(&zero, &on, ebpf.UpdateAny)
			_ = o.tlsCache.Store(o.tlsBuildID, tlsoffset.Target{Path: o.plan.sslPath, BuildID: o.tlsBuildID, SSLWrite: o.writeOffset, SSLRead: cand.FileOff})
		}
		timer := time.NewTimer(timeout)
		select {
		case <-o.readOK:
			timer.Stop()
			accept()
			return
		case <-o.readStop:
			timer.Stop()
			// Stop closes readStop after correlate has drained the rings
			// (N-32), so a status line read in the drain has closed readOK
			// already; it wins over the stop.
			select {
			case <-o.readOK:
				accept()
				return
			default:
			}
			closeLinks(links)
			o.readAttachErr = fmt.Errorf("no SSL_read candidate validated in %s before the capture stopped: no read of a tracked process began with an HTTP/1.x status line", o.plan.sslPath)
			return
		case <-timer.C:
			closeLinks(links)
		}
	}
	o.readAttachErr = fmt.Errorf("no SSL_read candidate validated in %s (%d tried): no read of a tracked process began with an HTTP/1.x status line within %s each", o.plan.sslPath, len(o.readCands), timeout)
}

// ResponseAttachError reports why response capture is inactive: content
// capture is unconfigured or failed, or no SSL_read candidate validated.
// Nil when it is active or ExePath was never set. Read it after Stop.
func (o *Observer) ResponseAttachError() error {
	return o.readAttachErr
}

// handleSSLRead feeds one captured SSL_read payload to its connection's
// response parser. Until a read has begun with a status line the SSL_read
// offset is unvalidated, and reads are discarded.
func (o *Observer) handleSSLRead(key sslKey, payload []byte, missing int, ts time.Time) {
	if !o.readValid {
		if !httpStatusLineRE.Match(payload) {
			o.coverage.ReadsUnvalidated++
			return
		}
		o.readValid = true
		close(o.readOK)
	}
	o.feedRead(key, payload, missing, ts)
}

// feedRead feeds one validated read to its connection: the server's
// WebSocket frames once a 101 accepted a WebSocket (N-41), the response
// parser otherwise.
func (o *Observer) feedRead(key sslKey, payload []byte, missing int, ts time.Time) {
	c := o.tlsConn(key, ts)
	if c.ws != nil && (c.ws.server != nil || c.ws.refused) {
		o.wsServerBytes(key.tgid, c, payload, missing, ts)
		return
	}
	if err := c.resp.Feed(payload, missing, ts, func(r *tlsparse.Response) {
		o.emitNetResponse(key.tgid, c, r)
		if tlsparse.IsWebSocketAccept(r) {
			o.wsAccept(key.tgid, c, r)
		}
	}); err != nil {
		o.coverage.ResponsesUnparsed++
	}
	if c.ws != nil && c.ws.server != nil && c.resp.Upgraded() {
		if rest := c.resp.TakeUpgraded(); len(rest) > 0 {
			o.wsServerBytes(key.tgid, c, rest, 0, ts)
		}
	}
}

// emitNetResponse emits one parsed response as a models.NetResponse event
// stamped when its status line was read. Its target is that of the latest
// request on the same connection, which it answers (HTTP/1.1 without
// pipelining); with none, the connection's host as https://host[:port];
// with no host either, nothing is emitted and the response is counted.
func (o *Observer) emitNetResponse(tgid uint32, c *tlsConn, r *tlsparse.Response) {
	paired := c.last != nil && c.last.target != ""
	var target string
	switch {
	case paired:
		target = c.last.target
	case c.host != "":
		target = hostTarget(c.host, c.port)
		o.coverage.ResponsesUnpaired++
	}
	c.last = nil
	if r.Truncated {
		o.coverage.ResponsesTruncated++
	}
	if target == "" {
		o.coverage.ResponsesUnattributed++
		return
	}
	if !r.Complete {
		o.coverage.ResponsesIncomplete++
	}
	att := &models.ResponseAttestation{
		Status:          r.Status,
		RequestID:       r.RequestID,
		ContentType:     r.ContentType,
		ContentEncoding: r.ContentEncoding,
		BodyBytes:       r.BodyBytes,
		BodyHash:        r.BodyHash,
		End:             r.End,
		Complete:        r.Complete,
		Truncated:       r.Truncated,
		Paired:          paired,
	}
	if r.SSE != nil {
		att.SSE = &models.SSESummary{Events: r.SSE.Events, Types: r.SSE.Types, Overflow: r.SSE.Overflow}
		o.coverage.SSEEvents += r.SSE.Events
	}
	o.coverage.Responses++
	event := models.GroundTruthEvent{
		Timestamp:  r.Start,
		ActionType: models.NetResponse,
		Target:     target,
		PID:        tgid,
		Response:   att,
	}
	select {
	case o.events <- event:
	default:
		o.dropped.Add(1)
	}
}

// hostTarget names a connection by host alone, in the form of a request
// target without method and path.
func hostTarget(host string, port int) string {
	return models.CanonicalNetTarget("", host, port, "", "")[1:]
}

// closeTLSConn ends the capture of one connection: its response in
// progress, or its WebSocket turn, is emitted as incomplete, stamped at its
// last read, and every key it is held under is released.
func (o *Observer) closeTLSConn(key sslKey) {
	c := o.tlsConns[key]
	if c == nil {
		return
	}
	c.resp.Close(c.lastSeen, func(r *tlsparse.Response) { o.emitNetResponse(key.tgid, c, r) })
	o.wsEndTurn(key.tgid, c, false)
	for _, k := range c.keys {
		delete(o.tlsConns, k)
		delete(o.aeadBound, k)
	}
}

// flushResponses emits every response still in progress when the capture
// stops, oldest connection first. Runs once, from correlate, after both
// feeders have closed.
func (o *Observer) flushResponses() {
	keys := make([]sslKey, 0, len(o.tlsConns))
	for k := range o.tlsConns {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := o.tlsConns[keys[i]], o.tlsConns[keys[j]]
		if !a.lastSeen.Equal(b.lastSeen) {
			return a.lastSeen.Before(b.lastSeen)
		}
		if keys[i].tgid != keys[j].tgid {
			return keys[i].tgid < keys[j].tgid
		}
		if keys[i].kind != keys[j].kind {
			return keys[i].kind < keys[j].kind
		}
		return keys[i].ssl < keys[j].ssl
	})
	for _, k := range keys {
		o.closeTLSConn(k)
	}
}
