package net

import (
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/agent-trace/agent-trace/pkg/tlsoffset"
)

// The rustls side of content capture (tls-rustls-aead, N-39, N-40):
// tls.bpf.c copies each application record's plaintext at the AEAD encrypt
// method's entry and its decrypted plaintext at decrypt's return, on the
// aead_events ring, and binds each encrypter to the socket its thread sends
// on next. This file locates and attaches the methods, feeds the ring to
// correlate and turns frames into the per-connection streams the SSL side
// uses, keyed by socket once an encrypter is bound.

// Frame header values mirroring tls.bpf.c.
const (
	sslDirWrite    = 0
	sslDirBind     = 2
	aeadOkUnknown  = -1
	aeadUprobeKind = "rustls AEAD"
)

// Kinds of sslKey: an SSL*, a rustls encrypter or decrypter object, or a
// socket inode number (a rustls connection whose records are bound to it).
const (
	keySSL uint8 = iota
	keyAEADEnc
	keyAEADDec
	keySock
)

// prepareAEAD locates the rustls AEAD methods in o.plan.aeadPath, writes the
// decrypt result's Ok discriminant to aead_cfg, attaches encrypt's entry
// probe and decrypt's entry and return probes at every method, attaches the
// socket-following sys_enter hook and opens the aead_events reader. It
// refuses (an error, which fails New) when the locator finds no anchor.
func (o *Observer) prepareAEAD() error {
	path := o.plan.aeadPath
	res, err := tlsoffset.ScanRustlsAEAD(path)
	if err != nil {
		return fmt.Errorf("scan %s: %w", path, err)
	}
	o.aeadScan = res
	cfg := tlsbpfAeadConfig{}
	if res.OkTag != aeadOkUnknown {
		cfg.OkTag, cfg.OkKnown = uint32(res.OkTag), 1
	}
	var zero uint32
	if err := o.tlsObjs.AeadCfg.Update(&zero, &cfg, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("write aead_cfg: %w", err)
	}
	exe, err := link.OpenExecutable(path)
	if err != nil {
		return fmt.Errorf("open executable %s: %w", path, err)
	}
	o.aeadExe = exe
	reader, err := ringbuf.NewReader(o.tlsObjs.AeadEvents)
	if err != nil {
		return fmt.Errorf("open aead ring buffer: %w", err)
	}
	o.aeadReader = reader
	o.aeadRingSize = uint64(o.tlsObjs.AeadEvents.MaxEntries())
	// The hook goes first, so a record encrypted once the uprobes are in
	// place is always followed to its socket.
	l, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: "sys_enter", Program: o.tlsObjs.AeadSysEnter})
	if err != nil {
		return fmt.Errorf("attach aead sys_enter: %w", err)
	}
	o.aeadLinks = append(o.aeadLinks, l)
	for _, m := range res.Methods {
		opts := &link.UprobeOptions{Address: m.FileOff}
		if m.Encrypt {
			l, err := exe.Uprobe("", o.tlsObjs.ProbeAeadEncrypt, opts)
			if err != nil {
				return fmt.Errorf("attach %s encrypt at %#x: %w", aeadUprobeKind, m.FileOff, err)
			}
			o.aeadLinks = append(o.aeadLinks, l)
			continue
		}
		entry, err := exe.Uprobe("", o.tlsObjs.ProbeAeadDecryptEntry, opts)
		if err != nil {
			return fmt.Errorf("attach %s decrypt at %#x: %w", aeadUprobeKind, m.FileOff, err)
		}
		o.aeadLinks = append(o.aeadLinks, entry)
		ret, err := exe.Uretprobe("", o.tlsObjs.ProbeAeadDecryptReturn, opts)
		if err != nil {
			return fmt.Errorf("attach %s decrypt return at %#x: %w", aeadUprobeKind, m.FileOff, err)
		}
		o.aeadLinks = append(o.aeadLinks, ret)
	}
	return nil
}

// aeadFeed decodes aead_events records for correlate from the start: the
// rustls side has no offset to validate before its frames are read, so it
// never waits on tlsReady. It drains the ring at Stop like sslFeed (N-32).
func (o *Observer) aeadFeed(out chan<- sslRecord) {
	defer close(out)
	for {
		record, err := o.aeadReader.Read()
		if err != nil {
			if drainRead(o.aeadReader, err, o.aeadDraining.Load()) {
				return
			}
			continue
		}
		o.aeadRing.observe(&record)
		if rec, ok := decodeSSLRecord(record.RawSample); ok {
			out <- rec
		}
	}
}

// handleAEADRecord runs one rustls record or bind record through the
// streams. A write frame is keyed by its encrypter, which a bind aliases to
// the socket; a read frame by the socket of its thread's last receive, or by
// its decrypter when there was none. Until a write frame has begun with an
// HTTP/1.x request line, write frames are discarded, and until a read frame
// has begun with a status line, read frames are: the first frame of each
// direction validates the located methods and their layouts (N-D4), and
// frames before it are counted in AEADUnvalidated.
func (o *Observer) handleAEADRecord(rec sslRecord, ts time.Time) {
	h := rec.hdr
	missing := max(int(h.Total)-len(rec.payload), 0)
	switch h.Dir {
	case sslDirBind:
		o.aeadBind(sslKey{tgid: h.Tgid, kind: keyAEADEnc, ssl: h.Ssl}, h.Sock, ts)
	case sslDirRead:
		if !o.aeadReadValid {
			if !httpStatusLineRE.Match(rec.payload) {
				o.coverage.AEADUnvalidated++
				return
			}
			o.aeadReadValid = true
		}
		key := sslKey{tgid: h.Tgid, kind: keySock, ssl: h.Sock}
		if h.Sock == 0 {
			key = sslKey{tgid: h.Tgid, kind: keyAEADDec, ssl: h.Ssl}
			o.coverage.AEADUnbound++
		}
		o.feedRead(key, rec.payload, missing, ts)
	default:
		if !o.aeadWriteValid {
			if !httpRequestLineRE.Match(rec.payload) {
				o.coverage.AEADUnvalidated++
				return
			}
			o.aeadWriteValid = true
		}
		o.handleSSLFrame(sslKey{tgid: h.Tgid, kind: keyAEADEnc, ssl: h.Ssl}, rec.payload, missing, ts)
	}
}

// aeadBind records that encrypter enc sent its records on socket sock. The
// first binding stands: the connection state of the encrypter becomes that
// of the socket, so the socket's read frames find the requests they answer.
// A later bind to another socket (the thread sent elsewhere before this
// encrypter's records left, as a task moved between threads can) is
// counted in AEADRebound and ignored. When the socket already has its own
// state (reads came first), the two cannot be joined: AEADUnpaired.
func (o *Observer) aeadBind(enc sslKey, sock uint64, ts time.Time) {
	if prev, ok := o.aeadBound[enc]; ok {
		if prev != sock {
			o.coverage.AEADRebound++
		}
		return
	}
	o.aeadBound[enc] = sock
	sk := sslKey{tgid: enc.tgid, kind: keySock, ssl: sock}
	c := o.tlsConn(enc, ts)
	if other, ok := o.tlsConns[sk]; ok {
		if other != c {
			o.coverage.AEADUnpaired++
		}
		return
	}
	o.tlsConns[sk] = c
	c.keys = append(c.keys, sk)
}
