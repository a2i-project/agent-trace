// Package net is the network probe. It has two layers. The kernel side
// (net.bpf.c) records identity: connect, listener and Unix-socket tracepoints,
// the first bytes of each connection, and the TLS SNI hostname that
// pkg/tlsparse extracts from them. The content side (tls.bpf.c) is a uprobe on
// SSL_write that captures request plaintext before encryption, and a uprobe
// and uretprobe pair on SSL_read that captures response plaintext after
// decryption, located in the target's TLS library by pkg/tlsoffset and
// validated at run time; correlator.go parses HTTP out of it and attributes
// each request to a connection by Host header. A connection with no captured
// content is emitted as models.NetConnect, a request as models.NetRequest
// with a body hash, a response as models.NetResponse with its attestation
// record (response.go).
// docs/architecture/13_probe_net.md describes the workflow and its limits, and
// docs/decisions/network.md the reasons (N-D1 to N-D5).
package net

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	stdnet "net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/tlsoffset"
	"github.com/agent-trace/agent-trace/pkg/tlsparse"
)

// Event type values mirror the NET_* constants in net.bpf.c.
const (
	netConnect uint8 = 1
	netHello   uint8 = 2
	netBind    uint8 = 3 // unused until tls.bpf.c exists (S5)
	netClose   uint8 = 4

	// Listener evidence, mirroring NET_SOCK_BIND and NET_SOCK_LISTEN. Distinct
	// from netBind above, which is the reserved, never-emitted write join.
	netSockBind    uint8 = 5
	netSockListen  uint8 = 6
	netUnixConnect uint8 = 7

	// netSend marks a connection as having carried data through a send whose
	// bytes were not read (N-23).
	netSend uint8 = 8

	// netDgram is a datagram sent to an explicit address on a datagram or
	// raw socket, connected or not (N-28).
	netDgram uint8 = 9

	// netHelloMore continues a ClientHello the connection's first send did
	// not hold whole (N-31).
	netHelloMore uint8 = 10
)

// netFlagHelloMore, in a NET_HELLO or NET_HELLO_MORE header's flags, says
// that further sends of the same ClientHello follow (NET_FLAG_HELLO_MORE).
const netFlagHelloMore uint16 = 1

// maxHelloBytes bounds the ClientHello bytes kept per connection, the
// kernel's HELLO_FOLLOW_MAX: one full TLS record.
const maxHelloBytes = 5 + 16384

const (
	afUnix  = 1
	afInet  = 2
	afInet6 = 10
)

// Config controls the observer's behavior.
type Config struct {
	// TrackedPID, if > 0, is seeded into tracked_pids at New so this single
	// process's connections are observed. Additional PIDs can be added
	// later via TrackPID. There is no global (untracked) mode: net.bpf.c
	// gates every program on tracked_pids membership unconditionally (see
	// docs/architecture/13_probe_net.md), so an Observer with no tracked PID at all
	// sees nothing until TrackPID is called, and its CaptureCoverage reports
	// Ran=false (N-26).
	TrackedPID int32

	// EventBufSize is the channel buffer size for emitted events. Defaults
	// to 4096 if zero.
	EventBufSize int

	// TrackedPIDsMax overrides the capacity of the kernel tracked_pids maps
	// (net and TLS). Zero keeps the compiled-in 4096. It exists so tests can
	// force an overflow and exercise UntrackedChildren; production callers
	// should leave it zero.
	TrackedPIDsMax uint32

	// ConnsMax overrides the capacity of the kernel conns map, which holds
	// one entry per open tracked connection. Zero keeps the compiled-in 8192.
	// Test only, to force StateMapFull.
	ConnsMax uint32

	// ExePath, if set, is the executable to attach the SSL_write uprobe to
	// for content capture (S5). Without it, Observer runs identity-only,
	// exactly as in S3: NetConnect events with a resolved hostname, no
	// NetRequest events. Required for TrackedPID's process to yield
	// request-level content.
	ExePath string

	// CachePath is the tlsoffset JSON cache file. Defaults to
	// $TMPDIR/agent-trace-tlsoffset-cache.json. Only used when ExePath is
	// set.
	CachePath string

	// ValidationTimeout bounds how long Observer.New waits for a candidate
	// SSL_write offset to produce a parseable HTTP request before trying
	// the next candidate (N-D4). Defaults to 5s.
	ValidationTimeout time.Duration
}

// connection is per-connection correlator state, keyed by the socket inode
// number the kernel records carry (N-24).
type connection struct {
	tgid     uint32 // the process that connected; every event of the connection carries it
	family   uint8
	addr     [16]byte
	port     uint16
	openedAt time.Time
	host     string
	alpn     []string
	emitted  bool
	// wrote is set at the first send on the connection by any tracked
	// process holding it, whatever it carried. A connection closed without
	// one sent nothing (N-22, N-23).
	wrote bool
	// sotype is the socket's type as the kernel reported it (sockStream,
	// sockDgram, ...), 0 when unknown or in a record from before N-27.
	sotype uint16
	// datagram marks a destination of an addressed datagram (N-28), not a
	// connect(): it has no close, and port 0 is not address selection.
	datagram bool
	// hello holds the ClientHello bytes captured so far while helloPending:
	// the first send did not hold the whole hello and the kernel follows it
	// into later sends (N-31). helloAt is when the first of them was sent.
	hello        []byte
	helloAt      time.Time
	helloPending bool
}

// dgramKey names one destination of one socket. A datagram destination is
// recorded once (N-28); the kernel's LRU map can evict and repeat one.
type dgramKey struct {
	sock   uint64
	family uint8
	addr   [16]byte
	port   uint16
}

// Observer watches network connections via eBPF and emits
// models.GroundTruthEvent values. See the package doc comment for what this
// slice does and does not cover.
type Observer struct {
	objs     bpfObjects
	links    []link.Link // net.bpf.c tracepoints, in attach order
	reader   *ringbuf.Reader
	events   chan models.GroundTruthEvent
	stopped  chan struct{}
	cfg      Config
	dropped  atomic.Uint64
	stopOnce sync.Once

	// tracking is raised once a pid is in tracked_pids, by New or TrackPID.
	// Until then the probe watches nothing (N-26).
	tracking atomic.Bool

	// Kernel-side counters snapshotted by Stop, before it closes the maps
	// they live in. kernelCountersFinal is raised after the values are set.
	finalFaulted        atomic.Uint64
	finalRingbufDrops   atomic.Uint64
	finalUntracked      atomic.Uint64
	finalStateFull      atomic.Uint64
	finalIOURingNet     atomic.Uint64
	finalIOURingOps     atomic.Uint64
	finalIOURingRings   atomic.Uint64
	finalHelloFaults    atomic.Uint64
	finalReadFaults     atomic.Uint64
	finalReadDrops      atomic.Uint64
	kernelCountersFinal atomic.Bool

	// iouringSubmitUnseen is set when the kernel has no io_uring_submit_req
	// tracepoint, so io_uring operations cannot be classified; every ring a
	// tracked process sets up then counts as network activity (N-25).
	iouringSubmitUnseen bool

	bootOffsetNs int64

	conns  map[uint64]*connection // by socket inode number
	dgrams map[dgramKey]bool      // datagram destinations already emitted (N-28)

	// Content-capture (S5) state. tlsObjs and sslWriteLink are zero/nil
	// when cfg.ExePath is unset -- Observer then runs identity-only, as it
	// did before this slice existed.
	tlsObjs      tlsbpfObjects
	sslWriteLink link.Link
	// firstLink is the uprobe New attaches at the first candidate, so a
	// tracked process's SSL_write between New and Start is captured and
	// waits in ssl_events for validation. attachAndValidateTLS takes it
	// over (and clears the field) when it tries that candidate.
	firstLink   link.Link
	tlsForkLink link.Link
	tlsExitLink link.Link
	exe         *link.Executable
	sslReader   *ringbuf.Reader

	tlsCandidates []tlsoffset.Candidate
	tlsBuildID    string
	tlsCache      *tlsoffset.Cache
	tlsAttachErr  error
	// replay holds, in ring order, the frames the write validation read
	// that correlate must not lose: the read frames it passed over and the
	// write frame that validated the chosen candidate. sslFeed sends them
	// before it reads the ring.
	replay []sslRecord
	// heldDropped counts read frames the write validation could not hold
	// (beyond maxHeldReads); added to ReadsUnvalidated.
	heldDropped atomic.Uint64

	// Response capture (N-29): the SSL_read side. readCands are the
	// candidates, firstReadLinks the entry and return probes New attached
	// at the first of them. validateRead (response.go) owns the links
	// until it closes readDone; correlate closes readOK on the first read
	// frame that begins with a status line.
	readCands      []tlsoffset.Candidate
	firstReadLinks []link.Link
	readLinks      []link.Link
	readOK         chan struct{}
	readStop       chan struct{}
	readDone       chan struct{}
	readActive     atomic.Bool
	readAttachErr  error // written before readDone closes
	readValid      bool  // owned by correlate

	// tlsReady is closed by Start once attachAndValidateTLS has finished (or
	// immediately, when content capture was never configured). It exists to
	// keep exactly one goroutine reading o.sslReader at a time: ringbuf.Reader
	// holds its internal mutex for the whole of a blocking Read, so a feeder
	// goroutine parked in Read starves the validator -- which then reports
	// "no candidate validated" even though the offset was right and the
	// feeder was receiving its frames. The ssl feeder waits here; the
	// validator owns the reader until it closes.
	tlsReady    chan struct{}
	tlsActive   bool   // content capture validated and attached; read only after <-tlsReady
	writeOffset uint64 // the validated SSL_write offset

	tlsConns map[sslKey]*tlsConn
	coverage Coverage
}

// netTracepoint is one net.bpf.c program and the tracepoint it attaches to.
type netTracepoint struct {
	group, name string
	prog        *ebpf.Program
}

// netTracepoints lists the programs New attaches, in attach order. The send
// hooks beyond write, sendto and sendmsg, and dup2 and dup3, complete the
// send side of a connection (N-23, N-24).
func netTracepoints(objs *bpfObjects) []netTracepoint {
	return []netTracepoint{
		{"syscalls", "sys_enter_connect", objs.TraceConnect},
		{"syscalls", "sys_enter_write", objs.TraceWrite},
		{"syscalls", "sys_enter_sendto", objs.TraceSendto},
		{"syscalls", "sys_enter_sendmsg", objs.TraceSendmsg},
		{"syscalls", "sys_enter_sendmmsg", objs.TraceSendmmsg},
		{"syscalls", "sys_enter_writev", objs.TraceWritev},
		{"syscalls", "sys_enter_pwritev2", objs.TracePwritev2},
		{"syscalls", "sys_enter_sendfile64", objs.TraceSendfile},
		{"syscalls", "sys_enter_splice", objs.TraceSplice},
		{"syscalls", "sys_enter_close", objs.TraceClose},
		{"syscalls", "sys_enter_dup2", objs.TraceDup2},
		{"syscalls", "sys_enter_dup3", objs.TraceDup3},
		{"task", "task_newtask", objs.HandleFork},
		{"sched", "sched_process_exit", objs.HandleExit},
		{"syscalls", "sys_enter_bind", objs.TraceBind},
		{"syscalls", "sys_enter_listen", objs.TraceListen},
	}
}

// iouringTracepoints lists the io_uring counters' programs (N-25). Unlike the
// programs above, a missing tracepoint is not an error: a kernel built
// without io_uring has neither, and New handles a kernel that has the
// syscall but not io_uring_submit_req.
func iouringTracepoints(objs *bpfObjects) (submit, setup netTracepoint) {
	return netTracepoint{"io_uring", "io_uring_submit_req", objs.TraceIouringSubmit},
		netTracepoint{"syscalls", "sys_enter_io_uring_setup", objs.TraceIouringSetup}
}

// New loads the eBPF programs, attaches the tracepoints, and opens the ring
// buffer. The caller must call Start to begin receiving events and Stop to
// release resources. Requires CAP_BPF + CAP_PERFMON (or root).
func New(cfg Config) (*Observer, error) {
	if cfg.EventBufSize <= 0 {
		cfg.EventBufSize = 4096
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock rlimit: %w", err)
	}

	bootOffsetNs, err := computeBootOffsetNs()
	if err != nil {
		return nil, fmt.Errorf("compute boot offset: %w", err)
	}

	var objs bpfObjects
	spec, err := loadBpf()
	if err != nil {
		return nil, fmt.Errorf("load bpf spec: %w", err)
	}
	if cfg.TrackedPIDsMax != 0 {
		spec.Maps["tracked_pids"].MaxEntries = cfg.TrackedPIDsMax
	}
	if cfg.ConnsMax != 0 {
		spec.Maps["conns"].MaxEntries = cfg.ConnsMax
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("load eBPF objects: %w", err)
	}

	if cfg.TrackedPID > 0 {
		p := uint32(cfg.TrackedPID)
		one := uint8(1)
		if err := objs.TrackedPids.Update(&p, &one, ebpf.UpdateAny); err != nil {
			_ = objs.Close()
			return nil, fmt.Errorf("update tracked_pids: %w", err)
		}
	}

	var links []link.Link
	closeAll := func() {
		for i := len(links) - 1; i >= 0; i-- {
			_ = links[i].Close()
		}
		_ = objs.Close()
	}
	for _, tp := range netTracepoints(&objs) {
		l, err := link.Tracepoint(tp.group, tp.name, tp.prog, nil)
		if err != nil {
			closeAll()
			return nil, fmt.Errorf("attach %s: %w", tp.name, err)
		}
		links = append(links, l)
	}
	submitTP, setupTP := iouringTracepoints(&objs)
	attached := map[string]bool{}
	for _, tp := range []netTracepoint{submitTP, setupTP} {
		l, err := link.Tracepoint(tp.group, tp.name, tp.prog, nil)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			closeAll()
			return nil, fmt.Errorf("attach %s: %w", tp.name, err)
		}
		links = append(links, l)
		attached[tp.name] = true
	}

	reader, err := ringbuf.NewReader(objs.NetEvents)
	if err != nil {
		closeAll()
		return nil, fmt.Errorf("open ring buffer: %w", err)
	}

	o := &Observer{
		objs:         objs,
		links:        links,
		reader:       reader,
		events:       make(chan models.GroundTruthEvent, cfg.EventBufSize),
		stopped:      make(chan struct{}),
		tlsReady:     make(chan struct{}),
		cfg:          cfg,
		bootOffsetNs: bootOffsetNs,
		conns:        make(map[uint64]*connection),
		dgrams:       make(map[dgramKey]bool),
		tlsConns:     make(map[sslKey]*tlsConn),
		readOK:       make(chan struct{}),
		readStop:     make(chan struct{}),
		readDone:     make(chan struct{}),

		iouringSubmitUnseen: !attached[submitTP.name] && attached[setupTP.name],
	}
	o.tracking.Store(cfg.TrackedPID > 0)

	if cfg.ExePath != "" {
		if err := o.prepareTLS(cfg); err != nil {
			_ = reader.Close()
			closeAll()
			return nil, fmt.Errorf("prepare SSL_write content capture: %w", err)
		}
	}

	return o, nil
}

// httpRequestLineRE recognizes an HTTP/1.x request line at the start of a
// captured buffer, for offset validation only (N-D4): "does this candidate's first captured write look like a real
// SSL_write(request_bytes) call, not some other BoringSSL internal buffer".
// It is deliberately looser than tlsparse.ParseHTTP1, which needs a
// complete header block; validation only needs the request line.
var httpRequestLineRE = regexp.MustCompile(`^[A-Z]{2,10} \S+ HTTP/1\.[01]\r\n`)

// prepareTLS loads tls.bpf.c's objects, seeds its tracked_pids, opens the
// executable and the ssl_events ring buffer, resolves SSL_write candidates
// in cfg.ExePath, and attaches the uprobe at the first (highest-ranked)
// candidate. Validation is a separate mandatory step performed by
// net.Observer.Start, not New, because the process(es) whose traffic will
// validate a candidate may not exist yet at New time. The first candidate
// is attached here all the same: a process started after New and tracked
// before Start (an agent started by watch) can send its first
// request before Start runs, and a uprobe attached only in Start missed
// that frame, so validation then waited for a second request that may
// never come. The frame waits in ssl_events until validation reads it.
func (o *Observer) prepareTLS(cfg Config) (err error) {
	scan, err := tlsoffset.Scan(cfg.ExePath)
	if err != nil {
		return fmt.Errorf("scan ELF for SSL_write: %w", err)
	}
	candidates, buildID, readCands := scan.Write, scan.BuildID, scan.Read

	cachePath := cfg.CachePath
	if cachePath == "" {
		cachePath = filepath.Join(os.TempDir(), "agent-trace-tlsoffset-cache.json")
	}
	cache := tlsoffset.NewCache(cachePath)
	if cached := cache.Lookup(buildID); cached != nil {
		candidates = append([]tlsoffset.Candidate{{FileOff: cached.SSLWrite, Score: 1 << 30}}, candidates...)
		if cached.SSLRead != 0 {
			readCands = append([]tlsoffset.Candidate{{FileOff: cached.SSLRead, Score: 1 << 30}}, readCands...)
		}
	}
	if len(candidates) == 0 {
		return fmt.Errorf("no SSL_write candidates found in %s", cfg.ExePath)
	}

	tlsSpec, err := loadTlsbpf()
	if err != nil {
		return fmt.Errorf("load tls bpf spec: %w", err)
	}
	if cfg.TrackedPIDsMax != 0 {
		tlsSpec.Maps["tracked_pids"].MaxEntries = cfg.TrackedPIDsMax
	}
	if err := tlsSpec.LoadAndAssign(&o.tlsObjs, nil); err != nil {
		return fmt.Errorf("load tls eBPF objects: %w", err)
	}
	defer func() {
		if err != nil {
			_ = o.tlsObjs.Close()
		}
	}()

	if cfg.TrackedPID > 0 {
		p := uint32(cfg.TrackedPID)
		one := uint8(1)
		if err := o.tlsObjs.TrackedPids.Update(&p, &one, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update tls tracked_pids: %w", err)
		}
	}

	exe, err := link.OpenExecutable(cfg.ExePath)
	if err != nil {
		return fmt.Errorf("open executable %s: %w", cfg.ExePath, err)
	}

	sslReader, err := ringbuf.NewReader(o.tlsObjs.SslEvents)
	if err != nil {
		return fmt.Errorf("open ssl ring buffer: %w", err)
	}

	tlsForkLink, err := link.Tracepoint("task", "task_newtask", o.tlsObjs.HandleFork, nil)
	if err != nil {
		_ = sslReader.Close()
		return fmt.Errorf("attach tls task_newtask: %w", err)
	}

	tlsExitLink, err := link.Tracepoint("sched", "sched_process_exit", o.tlsObjs.HandleExit, nil)
	if err != nil {
		_ = tlsForkLink.Close()
		_ = sslReader.Close()
		return fmt.Errorf("attach tls sched_process_exit: %w", err)
	}

	o.tlsForkLink = tlsForkLink
	o.tlsExitLink = tlsExitLink
	o.exe = exe
	o.sslReader = sslReader
	o.tlsCache = cache
	o.tlsBuildID = buildID
	o.tlsCandidates = candidates
	o.readCands = dedupCandidates(readCands)
	// A failed attach is not fatal here: attachAndValidateTLS tries the
	// candidate again and reports the outcome.
	if l, err := exe.Uprobe("", o.tlsObjs.ProbeSslWrite, &link.UprobeOptions{Address: candidates[0].FileOff}); err == nil {
		o.firstLink = l
	}
	// The SSL_read probes at the first read candidate, for the same reason:
	// the response to a request sent before Start must not be missed.
	if len(o.readCands) > 0 {
		if ls, err := o.attachRead(o.readCands[0].FileOff); err == nil {
			o.firstReadLinks = ls
		}
	}
	return nil
}

// attachAndValidateTLS is the validation step (N-D4): attach
// probe_ssl_write at each candidate in turn and require its first captured
// frame from a tracked process to look like an HTTP/1.x request line (D4:
// runtime validation is authoritative, the ELF scan's score is only a
// sorting hint). Called from Start, which blocks on it -- see Start's doc
// comment for why that's acceptable despite Start having no error return.
//
// On success the validated offset is cached by build ID, o.sslWriteLink is
// set and o.tlsActive becomes true. On failure (no candidate validates
// within its timeout) it leaves o.sslWriteLink nil, closes o.sslReader, and
// records the error in o.tlsAttachErr: Observer falls back to identity-only
// operation exactly as if cfg.ExePath had never been set, rather than
// failing the whole probe.
//
// It must run while it is the only reader of o.sslReader -- see the tlsReady
// field comment.
func (o *Observer) attachAndValidateTLS(cfg Config) {
	timeout := cfg.ValidationTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	var chosen tlsoffset.Candidate
	var framesSeen int
	var validated bool
	for i, cand := range o.tlsCandidates {
		var l link.Link
		if i == 0 && o.firstLink != nil {
			l, o.firstLink = o.firstLink, nil // attached in New (prepareTLS)
		} else {
			var err error
			l, err = o.exe.Uprobe("", o.tlsObjs.ProbeSslWrite, &link.UprobeOptions{Address: cand.FileOff})
			if err != nil {
				continue
			}
		}
		rec, seen, ok := o.validateSSLWriteCandidate(timeout)
		framesSeen += seen
		if ok {
			o.sslWriteLink = l
			o.replay = append(o.replay, rec)
			chosen = cand
			validated = true
			break
		}
		_ = l.Close()
	}
	if !validated {
		// Distinguish "the offset is wrong / nothing wrote" from "the
		// offset is fine but the plaintext isn't HTTP/1.x". The second case
		// is what an ALPN-negotiated h2 connection looks like from here, and
		// reporting it as a failed offset search sends the reader hunting
		// for a symbol-resolution bug that isn't there.
		if framesSeen > 0 {
			o.tlsAttachErr = fmt.Errorf("no SSL_write candidate validated in %s (%d tried): captured %d frame(s), none began with an HTTP/1.x request line -- HTTP/2 plaintext cannot validate an offset, and its content is not parsed",
				cfg.ExePath, len(o.tlsCandidates), framesSeen)
		} else {
			o.tlsAttachErr = fmt.Errorf("no SSL_write candidate validated in %s (%d tried): no frame was captured from a tracked process within %s",
				cfg.ExePath, len(o.tlsCandidates), timeout)
		}
		_ = o.sslReader.Close()
		return
	}

	o.sslReader.SetDeadline(time.Time{}) // clear the validation deadline for normal operation
	o.tlsActive = true
	o.writeOffset = chosen.FileOff
	target := tlsoffset.Target{Path: cfg.ExePath, BuildID: o.tlsBuildID, SSLWrite: chosen.FileOff}
	if prev := o.tlsCache.Lookup(o.tlsBuildID); prev != nil && prev.SSLWrite == chosen.FileOff {
		target.SSLRead = prev.SSLRead // kept until a validation replaces it
	}
	_ = o.tlsCache.Store(o.tlsBuildID, target)
}

// validateSSLWriteCandidate blocks for up to timeout waiting for one write
// frame on o.sslReader and, if it looks like an HTTP/1.x request line,
// decodes and returns it (ok=true) so the caller can feed it to the
// correlator instead of discarding it -- a short-lived tracked process may
// never call SSL_write again after the one write that validated the offset,
// so dropping this frame would silently lose its content.
//
// Read frames (the SSL_read probes New attached) are not evidence about
// the write candidate: they are held for replay, up to maxHeldReads, and
// the wait goes on.
//
// seen reports whether a write frame arrived at all (1) or the read timed
// out / the reader was closed (0), which is what lets the caller tell a
// wrong offset apart from non-HTTP/1.x plaintext.
func (o *Observer) validateSSLWriteCandidate(timeout time.Duration) (rec sslRecord, seen int, ok bool) {
	o.sslReader.SetDeadline(time.Now().Add(timeout))
	for {
		record, err := o.sslReader.Read()
		if err != nil {
			return sslRecord{}, 0, false
		}
		rec, ok := decodeSSLRecord(record.RawSample)
		if !ok {
			return sslRecord{}, 1, false
		}
		if rec.hdr.Dir == sslDirRead {
			if len(o.replay) < maxHeldReads {
				o.replay = append(o.replay, rec)
			} else {
				o.heldDropped.Add(1)
			}
			continue
		}
		if !httpRequestLineRE.Match(rec.payload) {
			return sslRecord{}, 1, false
		}
		return rec, 1, true
	}
}

// decodeSSLRecord decodes one ssl_events record. ok is false for a record
// shorter than its header or than the payload length it states.
func decodeSSLRecord(raw []byte) (sslRecord, bool) {
	var hdr tlsbpfSslFrameHdr
	hdrSize := binary.Size(hdr)
	if len(raw) < hdrSize {
		return sslRecord{}, false
	}
	if err := binary.Read(bytes.NewReader(raw), binary.NativeEndian, &hdr); err != nil {
		return sslRecord{}, false
	}
	payloadEnd := hdrSize + int(hdr.Len)
	if payloadEnd > len(raw) {
		return sslRecord{}, false
	}
	return sslRecord{hdr: hdr, payload: append([]byte(nil), raw[hdrSize:payloadEnd]...)}, true
}

// computeBootOffsetNs pairs a CLOCK_MONOTONIC read with a wall-clock read
// taken immediately after, so any later bpf_ktime_get_ns() reading can be
// converted to wall-clock time. Identical in method to pkg/probe/proc's
// helper of the same name; kept as a separate copy since each probe package
// is self-contained and independently attachable.
func computeBootOffsetNs() (int64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, fmt.Errorf("clock_gettime CLOCK_MONOTONIC: %w", err)
	}
	monoNs := ts.Nano()
	wallNs := time.Now().UnixNano()
	return wallNs - monoNs, nil
}

// TrackPID adds a PID to tracked_pids so its connections are observed. Safe
// to call after Start. It updates both net.bpf.c's and, when content
// capture is active, tls.bpf.c's copy of the map -- see the "gating role"
// comment on tls.bpf.c's tracked_pids for why there are two.
func (o *Observer) TrackPID(pid int32) error {
	p := uint32(pid)
	one := uint8(1)
	if err := o.objs.TrackedPids.Update(&p, &one, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update tracked_pids: %w", err)
	}
	o.tracking.Store(true)
	if o.tlsObjs.TrackedPids != nil {
		if err := o.tlsObjs.TrackedPids.Update(&p, &one, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update tls tracked_pids: %w", err)
		}
	}
	return nil
}

// Coverage reports how much of the observed network activity was
// attributed to content (docs/architecture/13_probe_net.md). FaultedReads and
// RingbufDrops come from eBPF maps: they are read live while the observer
// runs and from the snapshot Stop took before closing the maps afterwards.
// Both are zero for the TLS side when content capture (cfg.ExePath) was
// never configured.
func (o *Observer) Coverage() Coverage {
	cov := o.coverage
	snapshot := func() kernelCounts {
		return kernelCounts{
			faulted:    o.finalFaulted.Load(),
			drops:      o.finalRingbufDrops.Load(),
			untracked:  o.finalUntracked.Load(),
			stateFull:  o.finalStateFull.Load(),
			uringNet:   o.finalIOURingNet.Load(),
			uringOps:   o.finalIOURingOps.Load(),
			uringRing:  o.finalIOURingRings.Load(),
			helloFault: o.finalHelloFaults.Load(),
			readFault:  o.finalReadFaults.Load(),
			readDrop:   o.finalReadDrops.Load(),
		}
	}
	var k kernelCounts
	if o.kernelCountersFinal.Load() {
		k = snapshot() // Stop closed the maps, so they cannot be read again
	} else {
		var err error
		if k, err = o.kernelCounters(); err != nil && o.kernelCountersFinal.Load() {
			// Stop closed the maps between the check above and the lookup.
			k = snapshot()
		}
	}
	cov.FaultedReads += k.faulted
	cov.RingbufDrops += k.drops
	cov.UntrackedChildren += k.untracked
	cov.StateMapFull += k.stateFull
	cov.IOURingNetOps += k.uringNet
	cov.IOURingOps += k.uringOps
	cov.IOURingRings += k.uringRing
	cov.HelloFaults += k.helloFault
	cov.ReadFaults += k.readFault
	cov.ReadDrops += k.readDrop
	cov.ReadsUnvalidated += int(o.heldDropped.Load())
	if o.iouringSubmitUnseen {
		cov.IOURingNetOps += k.uringRing
	}
	return cov
}

// kernelCounts are the percpu counters the eBPF programs maintain, summed.
type kernelCounts struct {
	faulted    uint64 // SSL reads that faulted
	drops      uint64 // records the net and TLS ring buffers discarded because they were full
	untracked  uint64 // descendants that could not be added to a tracked_pids map
	stateFull  uint64 // connections lost because the conns map was full
	uringNet   uint64 // io_uring operations on sockets by tracked processes (N-25)
	uringOps   uint64 // io_uring operations of any kind by tracked processes
	uringRing  uint64 // io_uring rings set up by tracked processes
	helloFault uint64 // hello reads that faulted on a connection still waiting for its hello
	readFault  uint64 // SSL_read buffers that faulted
	readDrop   uint64 // SSL_read frames the TLS ring buffer discarded
}

// kernelCounters sums the counters above. An error means a map could not be
// read, which in practice means Stop has already closed it.
func (o *Observer) kernelCounters() (k kernelCounts, err error) {
	add := func(dst *uint64, m *ebpf.Map) {
		if m == nil {
			return
		}
		if v, e := sumPerCPU(m); e != nil {
			err = e
		} else {
			*dst += v
		}
	}
	add(&k.drops, o.objs.DropCount)
	add(&k.untracked, o.objs.UntrackedCount)
	add(&k.stateFull, o.objs.StateLostCount)
	add(&k.uringNet, o.objs.IouringNetCount)
	add(&k.uringOps, o.objs.IouringOpsCount)
	add(&k.uringRing, o.objs.IouringSetupCount)
	add(&k.helloFault, o.objs.HelloFaultCount)
	add(&k.faulted, o.tlsObjs.FaultedReads)
	add(&k.drops, o.tlsObjs.DropCount)
	add(&k.untracked, o.tlsObjs.UntrackedCount)
	add(&k.readFault, o.tlsObjs.ReadFaultCount)
	add(&k.readDrop, o.tlsObjs.ReadDropCount)
	return k, err
}

// sumPerCPU returns the sum of a one-slot percpu uint64 array across CPUs.
func sumPerCPU(m *ebpf.Map) (uint64, error) {
	var perCPU []uint64
	var zero uint32
	if err := m.Lookup(&zero, &perCPU); err != nil {
		return 0, err
	}
	var sum uint64
	for _, v := range perCPU {
		sum += v
	}
	return sum, nil
}

// Events returns the channel on which GroundTruthEvents are delivered. The
// channel is closed when Stop returns.
func (o *Observer) Events() <-chan models.GroundTruthEvent {
	return o.events
}

// CaptureCoverage reports the loss counters for this capture. Call after Stop.
//
// Ran is false when no pid was ever tracked: every program is gated on
// tracked_pids, so such a probe observed nothing, and an empty capture with
// Ran=true would read as a complete record of no network activity. Ran=false
// says what a probe that was not started says: its silence is no evidence
// (N-26).
func (o *Observer) CaptureCoverage() models.ProbeCoverage {
	cov := o.Coverage()
	content := models.ContentActive
	switch {
	case o.cfg.ExePath == "":
		content = models.ContentIdentityOnly
	case o.tlsAttachErr != nil:
		content = models.ContentAttachFailed
	}
	responses := models.ContentActive
	switch {
	case o.cfg.ExePath == "":
		responses = models.ContentIdentityOnly
	case !o.readActive.Load():
		responses = models.ContentAttachFailed
	}
	return models.ProbeCoverage{
		Ran:               o.tracking.Load(),
		RingbufDrops:      cov.RingbufDrops,
		ChannelDrops:      o.Dropped(),
		UntrackedChildren: cov.UntrackedChildren,
		StateMapFull:      cov.StateMapFull,
		FaultedReads:      cov.FaultedReads,
		IOURingNetOps:     cov.IOURingNetOps,
		Content:           content,
		HelloFaults:       cov.HelloFaults,
		Responses:         responses,
		ResponseGaps:      cov.ReadFaults + cov.ReadDrops + uint64(cov.ResponsesUnparsed+cov.ResponsesTruncated+cov.ResponsesUnattributed),
	}
}

// Dropped reports how many events were discarded because the events channel
// was full. Check after Stop returns.
func (o *Observer) Dropped() uint64 {
	return o.dropped.Load()
}

// Start begins reading ring-buffer records in background goroutines and, if
// content capture was configured, validates and attaches the SSL_write
// uprobe (see attachAndValidateTLS). The validation step blocks Start for up
// to cfg.ValidationTimeout per SSL_write candidate; the probe.Observer
// interface gives Start no error return, so a validation failure is
// recorded (see TLSAttachError) and Observer degrades to identity-only
// operation rather than failing the whole probe.
//
// The net ring buffer is drained throughout, including during validation, so
// a slow or failing validation cannot cost us connection events. The ssl
// ring buffer is not: its feeder waits on tlsReady so that the validator is
// its only reader until validation is done.
//
// Response capture is validated after Start returns (validateRead, in
// response.go): SSL_read cannot be validated before a request has gone out,
// and Start does not wait for the response.
func (o *Observer) Start() {
	go o.correlate()
	if o.exe != nil {
		o.attachAndValidateTLS(o.cfg)
	}
	o.startRead()
	close(o.tlsReady)
}

// TLSAttachError reports why content capture is inactive, or nil if it
// never failed (either it's working, or cfg.ExePath was never set). Safe to
// call after Start returns.
func (o *Observer) TLSAttachError() error {
	return o.tlsAttachErr
}

// Stop unblocks both ring-buffer reads, waits for the correlator goroutine
// to finish, and releases all resources. The events channel is closed by
// correlate itself once both feeders have drained, which happens before it
// signals o.stopped, so Stop can safely wait on o.stopped alone and must
// not close o.events again. Safe to call once.
func (o *Observer) Stop() error {
	o.stopOnce.Do(func() {
		_ = o.reader.Close() // unblocks netFeed's Read with ErrClosed
		if o.sslReader != nil {
			// Unblocks whichever of attachAndValidateTLS or sslFeed is
			// reading, with ErrClosed. A failed validation has already
			// closed it; ringbuf.Reader.Close is idempotent.
			_ = o.sslReader.Close()
		}
		<-o.stopped
		// correlate has returned, so Start has decided whether
		// validateRead runs; stop it and wait for it to release its links.
		close(o.readStop)
		<-o.readDone
		// Snapshot the kernel counters before the maps are closed below;
		// Coverage reads this snapshot afterwards. Order matters: the
		// values are stored before the final flag is raised.
		k, _ := o.kernelCounters()
		o.finalFaulted.Store(k.faulted)
		o.finalRingbufDrops.Store(k.drops)
		o.finalUntracked.Store(k.untracked)
		o.finalStateFull.Store(k.stateFull)
		o.finalIOURingNet.Store(k.uringNet)
		o.finalIOURingOps.Store(k.uringOps)
		o.finalIOURingRings.Store(k.uringRing)
		o.finalHelloFaults.Store(k.helloFault)
		o.finalReadFaults.Store(k.readFault)
		o.finalReadDrops.Store(k.readDrop)
		o.kernelCountersFinal.Store(true)
		if o.sslWriteLink != nil {
			_ = o.sslWriteLink.Close()
		}
		if o.firstLink != nil {
			_ = o.firstLink.Close() // never taken over by a validation
		}
		closeLinks(o.readLinks)
		if o.tlsForkLink != nil {
			_ = o.tlsForkLink.Close()
		}
		if o.tlsExitLink != nil {
			_ = o.tlsExitLink.Close()
		}
		_ = o.tlsObjs.Close()
		for i := len(o.links) - 1; i >= 0; i-- {
			_ = o.links[i].Close()
		}
		_ = o.objs.Close()
	})
	return nil
}

// netRecord is one decoded net_events ring-buffer record.
type netRecord struct {
	hdr     bpfNetEventHdr
	payload []byte
}

// sslRecord is one decoded ssl_events ring-buffer record.
type sslRecord struct {
	hdr     tlsbpfSslFrameHdr
	payload []byte
}

// correlate is the single goroutine that owns all correlator state (o.conns,
// o.pending, o.coverage): it drives both ring buffers via one select loop.
// The two feeder goroutines below exist only
// because cilium/ebpf's ringbuf.Reader.Read is a blocking call with no
// select-able primitive of its own; they decode records and hand them to
// this goroutine, doing no correlation themselves.
func (o *Observer) correlate() {
	defer close(o.stopped)
	defer close(o.events)

	netCh := make(chan netRecord, 64)
	go o.netFeed(netCh)

	sslCh := make(chan sslRecord, 64)
	go o.sslFeed(sslCh)

	// Each feeder's channel is set to nil once it closes: a closed channel is
	// always ready, so leaving it in the select would spin this goroutine at
	// 100% CPU until the other feeder finished. A nil channel blocks forever
	// and drops out of the select instead.
	defer o.flushOpenConnections()
	defer o.flushResponses()
	for netCh != nil || sslCh != nil {
		select {
		case rec, ok := <-netCh:
			if !ok {
				netCh = nil
				continue
			}
			o.handleNetRecord(rec)

		case rec, ok := <-sslCh:
			if !ok {
				sslCh = nil
				continue
			}
			ts := time.Unix(0, int64(rec.hdr.TsNs)+o.bootOffsetNs)
			missing := int(rec.hdr.Total) - len(rec.payload)
			if missing < 0 {
				missing = 0
			}
			key := sslKey{tgid: rec.hdr.Tgid, ssl: rec.hdr.Ssl}
			if rec.hdr.Dir == sslDirRead {
				o.handleSSLRead(key, rec.payload, missing, ts)
			} else {
				o.handleSSLFrame(key, rec.payload, missing, ts)
			}
		}
	}
}

func (o *Observer) netFeed(out chan<- netRecord) {
	defer close(out)

	var hdr bpfNetEventHdr
	hdrSize := binary.Size(hdr)

	for {
		record, err := o.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		if len(record.RawSample) < hdrSize {
			continue
		}
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.NativeEndian, &hdr); err != nil {
			continue
		}
		payloadEnd := hdrSize + int(hdr.PayloadLen)
		var payload []byte
		if hdr.PayloadLen > 0 && payloadEnd <= len(record.RawSample) {
			payload = append([]byte(nil), record.RawSample[hdrSize:payloadEnd]...)
		}
		out <- netRecord{hdr: hdr, payload: payload}
	}
}

// sslFeed decodes ssl_events records for correlate. It does not touch
// o.sslReader until tlsReady is closed: until then the reader belongs to
// attachAndValidateTLS, and a second goroutine blocking in Read would hold
// ringbuf.Reader's mutex and starve the validator (which would then reject
// a perfectly good offset). Closing tlsReady also publishes o.tlsActive,
// o.sslReader and o.replay to this goroutine.
func (o *Observer) sslFeed(out chan<- sslRecord) {
	defer close(out)

	<-o.tlsReady
	if !o.tlsActive {
		return // content capture unconfigured, or validation failed
	}

	// The frames validation consumed straight off the ring buffer before
	// this goroutine started reading: the write frame that validated the
	// chosen SSL_write candidate, so a tracked process that calls SSL_write
	// only once still gets its content correlated, and the read frames
	// before it, in ring order.
	for _, rec := range o.replay {
		out <- rec
	}
	o.replay = nil

	for {
		record, err := o.sslReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		if rec, ok := decodeSSLRecord(record.RawSample); ok {
			out <- rec
		}
	}
}

// flushOpenConnections emits every connection still open when the capture
// stops: one without an SNI name is otherwise emitted only on its close, so
// a connection held open until the process exits, or past the end of the
// capture, was never emitted and nothing counted it (N-21). Each is stamped
// with its connect time, which is when it happened; the order among the
// probe's events is by that stamp. Runs once, from correlate, after both
// feeders have closed.
func (o *Observer) flushOpenConnections() {
	keys := make([]uint64, 0, len(o.conns))
	for k, c := range o.conns {
		if !c.emitted {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool { return o.conns[keys[i]].openedAt.Before(o.conns[keys[j]].openedAt) })
	for _, k := range keys {
		c := o.conns[k]
		o.coverage.OpenAtStop++
		o.emit(c, c.openedAt)
	}
}

func (o *Observer) handleNetRecord(rec netRecord) {
	hdr := rec.hdr
	// Connection records are keyed by socket, not by the caller's tgid and
	// fd: a send or close may come from another process holding the socket,
	// a child after fork or a receiver of SCM_RIGHTS (N-24).
	key := hdr.Sock
	ts := time.Unix(0, int64(hdr.TsNs)+o.bootOffsetNs)

	switch hdr.Type {
	case netConnect:
		// A socket connected again (a datagram socket pointed at a new
		// peer) starts a new connection on the same key. The old one
		// happened and its target is known, so it is emitted now, stamped
		// with its connect time, like one still open at the stop.
		if prev, ok := o.conns[key]; ok && !prev.emitted {
			o.coverage.Replaced++
			o.emit(prev, prev.openedAt)
		}
		o.conns[key] = &connection{
			tgid:     hdr.Tgid,
			family:   hdr.Family,
			addr:     hdr.Addr,
			port:     hdr.Port,
			openedAt: ts,
			sotype:   hdr.Sotype,
		}
		o.coverage.Connections++

	case netHello:
		conn, ok := o.conns[key]
		if !ok {
			return
		}
		conn.wrote = true
		if conn.port == 53 {
			// A DNS query, one per datagram on a datagram socket (N-27).
			o.dnsQuery(conn, rec.payload, ts)
			return
		}
		conn.hello = append(conn.hello[:0], rec.payload...)
		conn.helloAt = ts
		conn.helloPending = true
		if hdr.Flags&netFlagHelloMore != 0 && !tlsparse.ClientHelloComplete(conn.hello) {
			// The rest of the hello follows in NET_HELLO_MORE (N-31).
			o.coverage.HellosFollowed++
			return
		}
		if o.resolveHello(conn) {
			o.emit(conn, conn.helloAt)
		}

	case netHelloMore:
		conn, ok := o.conns[key]
		if !ok || !conn.helloPending {
			return // the hello was already complete, or its connection is gone
		}
		conn.hello = append(conn.hello, rec.payload...)
		if hdr.Flags&netFlagHelloMore != 0 && len(conn.hello) < maxHelloBytes && !tlsparse.ClientHelloComplete(conn.hello) {
			return
		}
		if o.resolveHello(conn) {
			o.emit(conn, conn.helloAt)
		}

	case netSend:
		// A send whose bytes were not read (sendfile, splice, a faulted
		// read, which the kernel also counts in hello_fault_count): the
		// connection carried data, with no hello to parse.
		if conn, ok := o.conns[key]; ok {
			conn.wrote = true
		}

	case netDgram:
		o.handleDatagram(hdr, rec.payload, ts)

	case netSockBind:
		o.emitListener(models.NetBind, hdr, rec.payload, ts)

	case netSockListen:
		o.emitListener(models.NetListen, hdr, rec.payload, ts)

	case netUnixConnect:
		o.emitGroundTruthOnly(models.NetUnixConnect, hdr.Tgid, unixTarget(rec.payload), ts)

	case netBind:
		// No-op: the write-bracket join this event existed for is
		// abandoned (N-D1); net.bpf.c never emits it.
		return

	case netClose:
		// The kernel sends it when the last tracked descriptor of the socket
		// closes, whichever process held it.
		conn, ok := o.conns[key]
		if ok {
			o.emit(conn, ts)
		}
		delete(o.conns, key)
	}
}

// resolveHello parses the ClientHello captured for conn and reports whether
// it named a host. With one, it stores host and ALPN and counts the hostname.
// It runs once per connection: when the hello is whole, or, for one still
// being followed, when the connection is emitted without the rest.
func (o *Observer) resolveHello(conn *connection) bool {
	conn.helloPending = false
	hello, err := tlsparse.ParseClientHello(conn.hello)
	conn.hello = nil
	if err != nil || hello.ServerName == "" {
		return false
	}
	conn.host = hello.ServerName
	conn.alpn = hello.ALPN
	o.coverage.WithHostname++
	for _, proto := range hello.ALPN {
		if proto == "h2" {
			o.coverage.ContentUnsupported++
			break
		}
	}
	return true
}

// emitListener sends a NetBind or NetListen event. They carry no hostname and
// need no connection state, so they bypass the connection correlator. They
// are ground truth only, never claimable (models.ActionType.IsClaimable), and
// the net probe assigns no level, so IsTopLevel stays nil and the verifier
// keys on the action type instead.
func (o *Observer) emitListener(t models.ActionType, hdr bpfNetEventHdr, payload []byte, ts time.Time) {
	var target string
	if hdr.Family == afUnix {
		target = unixTarget(payload)
	} else if target = peerAddrPort(hdr.Family, hdr.Addr, hdr.Port); target == "" {
		target = models.UnboundListenTarget
	}
	o.emitGroundTruthOnly(t, hdr.Tgid, target, ts)
}

// emitGroundTruthOnly sends an event of an unclaimable type.
func (o *Observer) emitGroundTruthOnly(t models.ActionType, pid uint32, target string, ts time.Time) {
	event := models.GroundTruthEvent{Timestamp: ts, ActionType: t, Target: target, PID: pid}
	select {
	case o.events <- event:
	default:
		o.dropped.Add(1)
	}
}

// unixTarget renders the sun_path bytes the probe captured. An empty payload
// means the kernel record had no readable name. A leading NUL marks an
// abstract socket, shown as "@name" with any non-printable byte escaped so the
// target stays one line of valid text. A pathname is reported as the caller
// wrote it: a relative path is not resolved against the caller's cwd.
func unixTarget(payload []byte) string {
	switch {
	case len(payload) == 0:
		return models.UnixTargetPrefix + "<unknown>"
	case payload[0] == 0:
		q := strconv.Quote(string(payload[1:]))
		return models.UnixTargetPrefix + "@" + q[1:len(q)-1]
	default:
		return models.UnixTargetPrefix + string(payload)
	}
}

// emit sends one models.GroundTruthEvent for conn if it hasn't already been
// emitted (a connection whose SNI was parsed emits once, at NET_HELLO time;
// one that never yielded a hostname emits once, at NET_CLOSE, with a
// peer-address fallback target). The event's PID is the process that
// connected, whichever process sent or closed.
func (o *Observer) emit(conn *connection, ts time.Time) {
	if conn.emitted {
		return
	}
	// A hello still being followed when the connection ends (its close, a
	// new connect, the end of the capture) is parsed from what arrived; a
	// name found there stamps the connection at the hello, as a whole one
	// does.
	if conn.helloPending && o.resolveHello(conn) {
		ts = conn.helloAt
	}
	tgid := conn.tgid
	// Port 53 is DNS. The resolver connects to it for every name an agent
	// looks up, so no trajectory records it and it cannot be aligned; but a
	// connection to that port is also a way to move data, and dropping it
	// silently hid that. It is capability evidence, like a listener: in the
	// capture and the report, never a finding (N-20). A query that parsed
	// was emitted with its name when it was sent (dnsQuery); this is the
	// connection that sent something no query could be read from. One that
	// sent nothing falls through to a dial below: Go's address selection
	// connects a datagram socket to port 53 of every candidate address and
	// sends nothing (N-27).
	if conn.port == 53 && conn.wrote {
		conn.emitted = true
		o.coverage.DNS++
		o.emitGroundTruthOnly(models.NetDNS, tgid, peerAddrPort(conn.family, conn.addr, conn.port), ts)
		return
	}
	// Port 0 is not a connection. The resolver connects a datagram socket to
	// each candidate address with port 0 to ask the kernel which source address
	// it would use (RFC 3484 address selection), once per address family, before
	// the real connection. In a paired capture every real connection had such
	// twins (an IPv4 and an IPv6 address with port 0), with nothing ever sent.
	// They name the destination's addresses, which change with DNS, so no
	// trajectory could claim them and no baseline could list them. Counted,
	// not emitted (N-19).
	if conn.port == 0 && !conn.datagram {
		conn.emitted = true
		o.coverage.AddressProbes++
		return
	}
	conn.emitted = true

	target := conn.host
	if target == "" {
		target = peerAddrPort(conn.family, conn.addr, conn.port)
		// No name and not a byte written: the losing half of a dual-stack
		// connect, or a probe. It carried nothing, so it is capability
		// evidence and never something a claim or a baseline rule must name
		// (N-22). A connection that did write and had no name is a real
		// connection by address.
		if !conn.wrote {
			o.coverage.Dials++
			o.emitGroundTruthOnly(models.NetDial, tgid, target, ts)
			return
		}
	}

	isTopLevel := true
	event := models.GroundTruthEvent{
		Timestamp:  ts,
		ActionType: models.NetConnect,
		Target:     target,
		IsTopLevel: &isTopLevel,
		PID:        tgid,
	}

	select {
	case o.events <- event:
	default:
		o.dropped.Add(1)
	}
}

// dnsQuery handles the bytes of one send on a port-53 connection, or one
// datagram to port 53. When they parse as a DNS query, a net_dns event
// carrying the question is emitted, stamped at the send, and the connection
// is marked emitted so its close adds no event without a name. Bytes that
// do not parse are counted, never trusted: the connection then ends as a
// net_dns event with the resolver's address alone (N-27).
func (o *Observer) dnsQuery(conn *connection, payload []byte, ts time.Time) {
	q, err := parseDNSQuery(payload, conn.sotype)
	if err != nil {
		o.coverage.DNSUnparsed++
		return
	}
	conn.emitted = true
	o.coverage.DNS++
	o.coverage.DNSNamed++
	o.emitGroundTruthOnly(models.NetDNS, conn.tgid, dnsTarget(q, peerAddrPort(conn.family, conn.addr, conn.port)), ts)
}

// handleDatagram turns a datagram sent to an explicit address into the
// event a connection to that address that sent the same bytes would give
// (N-28): to port 53, net_dns, one per datagram, with the question when it
// parses (N-27); to any other port, net_connect by address, once per
// socket and destination. The PID is the sender's.
func (o *Observer) handleDatagram(hdr bpfNetEventHdr, payload []byte, ts time.Time) {
	conn := &connection{
		tgid:     hdr.Tgid,
		family:   hdr.Family,
		addr:     hdr.Addr,
		port:     hdr.Port,
		openedAt: ts,
		wrote:    true,
		sotype:   hdr.Sotype,
		datagram: true,
	}
	if conn.port == 53 && conn.sotype == sockDgram {
		o.coverage.Datagrams++
		o.dnsQuery(conn, payload, ts)
		o.emit(conn, ts) // the resolver alone, when no question parsed
		return
	}
	key := dgramKey{sock: hdr.Sock, family: hdr.Family, addr: hdr.Addr, port: hdr.Port}
	if o.dgrams == nil {
		o.dgrams = map[dgramKey]bool{}
	}
	if o.dgrams[key] {
		return
	}
	o.dgrams[key] = true
	o.coverage.Datagrams++
	o.emit(conn, ts)
}

// peerAddrPort formats a fallback target for a connection whose first bytes
// never parsed as a ClientHello with SNI (non-TLS traffic, or a truncated
// hello that lost the extension before it was reached).
func peerAddrPort(family uint8, addr [16]byte, port uint16) string {
	var ip stdnet.IP
	switch family {
	case afInet:
		ip = stdnet.IP(addr[:4])
	case afInet6:
		ip = stdnet.IP(addr[:16])
	default:
		return ""
	}
	return stdnet.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
}
