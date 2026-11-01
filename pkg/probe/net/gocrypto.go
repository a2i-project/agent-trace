package net

import (
	"fmt"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/tlsoffset"
)

// The Go side of content capture (tls-go-crypto, N-47, N-48): tls.bpf.c
// stashes the arguments of crypto/tls.(*Conn).Write and Read at their entry
// by goroutine and copies what the call wrote or read at each of their RET
// instructions, on the go_events ring, with the socket the *Conn holds.
// This file locates and attaches the probes, feeds the ring to correlate
// and runs the frames through the streams the other methods use, keyed by
// *Conn.

// keyGoConn is the sslKey kind of a Go *Conn.
const keyGoConn uint8 = 4

// prepareGo locates the two functions and their returns in o.plan.goPath,
// attaches an entry probe at each function and a return probe at each RET,
// and opens the go_events reader. It refuses (an error, which fails New)
// when the locator finds no anchor.
func (o *Observer) prepareGo() error {
	path := o.plan.goPath
	res, err := tlsoffset.ScanGoTLS(path)
	if err != nil {
		return fmt.Errorf("scan %s: %w", path, err)
	}
	o.goScan = res
	exe, err := link.OpenExecutable(path)
	if err != nil {
		return fmt.Errorf("open executable %s: %w", path, err)
	}
	reader, err := ringbuf.NewReader(o.tlsObjs.GoEvents)
	if err != nil {
		return fmt.Errorf("open go ring buffer: %w", err)
	}
	o.goReader = reader
	o.goRingSize = uint64(o.tlsObjs.GoEvents.MaxEntries())
	for _, side := range []struct {
		fn         tlsoffset.GoFunc
		entry, ret *ebpf.Program
	}{
		{res.Write, o.tlsObjs.ProbeGoWrite, o.tlsObjs.ProbeGoWriteRet},
		{res.Read, o.tlsObjs.ProbeGoRead, o.tlsObjs.ProbeGoReadRet},
	} {
		// The returns go first, so a call whose entry is seen always finds
		// its return probes in place.
		for _, r := range side.fn.Returns {
			l, err := exe.Uprobe("", side.ret, &link.UprobeOptions{Address: r.FileOff})
			if err != nil {
				return fmt.Errorf("attach %s return at %#x: %w", side.fn.Name, r.FileOff, err)
			}
			o.goLinks = append(o.goLinks, l)
		}
		l, err := exe.Uprobe("", side.entry, &link.UprobeOptions{Address: side.fn.Entry.FileOff})
		if err != nil {
			return fmt.Errorf("attach %s at %#x: %w", side.fn.Name, side.fn.Entry.FileOff, err)
		}
		o.goLinks = append(o.goLinks, l)
	}
	o.goCounts = &goCountsMeter{stat: o.tlsObjs.GoStat}
	return nil
}

// goFeed decodes go_events records for correlate from the start, as
// aeadFeed does: the method has no offset to validate before its frames
// are read. It drains the ring at Stop (N-32).
func (o *Observer) goFeed(out chan<- sslRecord) {
	defer close(out)
	for {
		record, err := o.goReader.Read()
		if err != nil {
			if drainRead(o.goReader, err, o.goDraining.Load()) {
				return
			}
			continue
		}
		o.goRing.observe(&record)
		if rec, ok := decodeSSLRecord(record.RawSample); ok {
			out <- rec
		}
	}
}

// handleGoRecord runs one Go frame through the streams of its *Conn. Until
// a write frame has begun with an HTTP/1.x request line or the HTTP/2
// preface, write frames are discarded, and until a read frame has begun
// with a status line or a server's SETTINGS frame, read frames are: the
// first frame of each direction validates the located functions and the
// registers the probes read (N-D4); frames before it count in
// GoUnvalidated. A frame names its *Conn's socket: a *Conn seen with
// another socket than before was freed and reused for a new connection, so
// the old one's state is closed (GoConnReused); a frame with no socket
// counts in GoUnbound and keeps to its *Conn.
func (o *Observer) handleGoRecord(rec sslRecord, ts time.Time) {
	h := rec.hdr
	missing := max(int(h.Total)-len(rec.payload), 0)
	if h.Dir == sslDirRead {
		if !o.goReadValid {
			if !validResponseStart(rec.payload) {
				o.coverage.GoUnvalidated++
				return
			}
			o.goReadValid = true
		}
	} else if !o.goWriteValid {
		if !validRequestStart(rec.payload) {
			o.coverage.GoUnvalidated++
			return
		}
		o.goWriteValid = true
	}
	key := sslKey{tgid: h.Tgid, kind: keyGoConn, ssl: h.Ssl}
	o.goBind(key, h.Sock, ts)
	if h.Dir == sslDirRead {
		o.feedRead(key, rec.payload, missing, ts)
		return
	}
	o.handleSSLFrame(key, rec.payload, missing, ts)
}

// goBind ties the connection state of a *Conn to the socket its frame
// named. A known host of that socket (its SNI) names the connection until a
// request does, so an unpaired response still has a host.
func (o *Observer) goBind(key sslKey, sock uint64, ts time.Time) {
	if sock == 0 {
		o.coverage.GoUnbound++
		return
	}
	if c := o.tlsConns[key]; c != nil && c.sock != 0 && c.sock != sock {
		o.coverage.GoConnReused++
		o.closeTLSConn(key)
	}
	c := o.tlsConn(key, ts)
	if c.sock == sock {
		return
	}
	c.sock = sock
	if conn := o.conns[sock]; conn != nil && c.host == "" && conn.host != "" {
		c.host, c.port = conn.host, int(conn.port)
	}
}

// goCountsMeter reads tls.bpf.c's go_stat, the calls whose entry and whose
// return the Go probes saw (N-47): live while the map is open, and the
// snapshot Stop takes before it closes the map.
type goCountsMeter struct {
	stat *ebpf.Map

	mu      sync.Mutex
	snapped bool
	final   *models.GoTLSCounts
}

func (m *goCountsMeter) read() (*models.GoTLSCounts, error) {
	var perCPU []tlsbpfGoCounts
	var zero uint32
	if err := m.stat.Lookup(&zero, &perCPU); err != nil {
		return nil, err
	}
	c := &models.GoTLSCounts{}
	for _, v := range perCPU {
		c.WriteCalls += v.WriteCalls
		c.WriteReturns += v.WriteReturns
		c.ReadCalls += v.ReadCalls
		c.ReadReturns += v.ReadReturns
	}
	return c, nil
}

// counts returns the counts, or nil when they could not be read.
func (m *goCountsMeter) counts() *models.GoTLSCounts {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.snapped {
		return m.final
	}
	c, err := m.read()
	if err != nil {
		return nil
	}
	return c
}

// snapshot stores the final counts; Stop calls it before closing the maps.
func (m *goCountsMeter) snapshot() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.final, _ = m.read()
	m.snapped = true
}
