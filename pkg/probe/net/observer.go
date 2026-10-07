// Package net is the Tier 3 network probe. This first slice (S3, see
// docs/plan/06_tier3_network_design.md section 11) implements only the
// kernel-side identity half: connect/write/sendto/sendmsg/close
// tracepoints, first-write ClientHello capture, and SNI extraction via
// pkg/tlsparse. Content correlation against the SSL_write uprobe (tls.bpf.c,
// the active_write/NET_BIND join, models.ActionNetRequest) is S5 and is not
// implemented here; see STATE.md and design doc section 13 (D1, D3, D5) for
// what blocks it.
//
// Because this slice has no content layer yet, it emits
// models.ActionType(models.NetConnect) events -- "a connection was observed,
// here is its resolved hostname if any" -- rather than NetRequest events.
// This is a deliberate stand-in for S3 only: once S5 lands, connections with
// captured content should produce NetRequest events instead, and
// Observer.readLoop's emission point is where that switch happens.
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
)

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
	// design doc section 4.1), so an Observer with no tracked PID at all
	// sees nothing until TrackPID is called.
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
	// the next candidate, per design doc section 9. Defaults to 5s.
	ValidationTimeout time.Duration
}

// connection is per-connection correlator state, keyed by (tgid, fd).
type connection struct {
	family   uint8
	addr     [16]byte
	port     uint16
	openedAt time.Time
	host     string
	alpn     []string
	emitted  bool
}

// Observer watches network connections via eBPF and emits
// models.GroundTruthEvent values. See the package doc comment for what this
// slice does and does not cover.
type Observer struct {
	objs        bpfObjects
	connectLink link.Link
	writeLink   link.Link
	sendtoLink  link.Link
	sendmsgLink link.Link
	closeLink   link.Link
	forkLink    link.Link
	exitLink    link.Link
	bindLink    link.Link
	listenLink  link.Link
	reader      *ringbuf.Reader
	events      chan models.GroundTruthEvent
	stopped     chan struct{}
	cfg         Config
	dropped     atomic.Uint64
	stopOnce    sync.Once

	// Kernel-side counters snapshotted by Stop, before it closes the maps
	// they live in. kernelCountersFinal is raised after the values are set.
	finalFaulted        atomic.Uint64
	finalRingbufDrops   atomic.Uint64
	finalUntracked      atomic.Uint64
	finalStateFull      atomic.Uint64
	kernelCountersFinal atomic.Bool

	bootOffsetNs int64

	conns map[connKeyGo]*connection

	// Content-capture (S5) state. tlsObjs and sslWriteLink are zero/nil
	// when cfg.ExePath is unset -- Observer then runs identity-only, as it
	// did before this slice existed.
	tlsObjs      tlsbpfObjects
	sslWriteLink link.Link
	tlsForkLink  link.Link
	tlsExitLink  link.Link
	exe          *link.Executable
	sslReader    *ringbuf.Reader

	tlsCandidates   []tlsoffset.Candidate
	tlsBuildID      string
	tlsCache        *tlsoffset.Cache
	tlsAttachErr    error
	validationFrame *sslRecord // the frame that validated the chosen candidate; correlate() must not drop it

	// tlsReady is closed by Start once attachAndValidateTLS has finished (or
	// immediately, when content capture was never configured). It exists to
	// keep exactly one goroutine reading o.sslReader at a time: ringbuf.Reader
	// holds its internal mutex for the whole of a blocking Read, so a feeder
	// goroutine parked in Read starves the validator -- which then reports
	// "no candidate validated" even though the offset was right and the
	// feeder was receiving its frames. The ssl feeder waits here; the
	// validator owns the reader until it closes.
	tlsReady  chan struct{}
	tlsActive bool // content capture validated and attached; read only after <-tlsReady

	pending  map[sslKey]*tlsparse.Stream
	coverage Coverage
}

// connKeyGo mirrors net.bpf.c's conn_key; it is the correlator's own map
// key, decoded from bpfNetEventHdr fields rather than sharing bpfConnKey's
// generated type, since the header carries tgid/fd directly.
type connKeyGo struct {
	tgid uint32
	fd   uint32
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

	connectLink, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.TraceConnect, nil)
	if err != nil {
		_ = objs.Close()
		return nil, fmt.Errorf("attach sys_enter_connect: %w", err)
	}
	writeLink, err := link.Tracepoint("syscalls", "sys_enter_write", objs.TraceWrite, nil)
	if err != nil {
		_ = connectLink.Close()
		_ = objs.Close()
		return nil, fmt.Errorf("attach sys_enter_write: %w", err)
	}
	sendtoLink, err := link.Tracepoint("syscalls", "sys_enter_sendto", objs.TraceSendto, nil)
	if err != nil {
		_ = writeLink.Close()
		_ = connectLink.Close()
		_ = objs.Close()
		return nil, fmt.Errorf("attach sys_enter_sendto: %w", err)
	}
	sendmsgLink, err := link.Tracepoint("syscalls", "sys_enter_sendmsg", objs.TraceSendmsg, nil)
	if err != nil {
		_ = sendtoLink.Close()
		_ = writeLink.Close()
		_ = connectLink.Close()
		_ = objs.Close()
		return nil, fmt.Errorf("attach sys_enter_sendmsg: %w", err)
	}
	closeLink, err := link.Tracepoint("syscalls", "sys_enter_close", objs.TraceClose, nil)
	if err != nil {
		_ = sendmsgLink.Close()
		_ = sendtoLink.Close()
		_ = writeLink.Close()
		_ = connectLink.Close()
		_ = objs.Close()
		return nil, fmt.Errorf("attach sys_enter_close: %w", err)
	}

	forkLink, err := link.Tracepoint("task", "task_newtask", objs.HandleFork, nil)
	if err != nil {
		_ = closeLink.Close()
		_ = sendmsgLink.Close()
		_ = sendtoLink.Close()
		_ = writeLink.Close()
		_ = connectLink.Close()
		_ = objs.Close()
		return nil, fmt.Errorf("attach task_newtask: %w", err)
	}

	exitLink, err := link.Tracepoint("sched", "sched_process_exit", objs.HandleExit, nil)
	if err != nil {
		_ = forkLink.Close()
		_ = closeLink.Close()
		_ = sendmsgLink.Close()
		_ = sendtoLink.Close()
		_ = writeLink.Close()
		_ = connectLink.Close()
		_ = objs.Close()
		return nil, fmt.Errorf("attach sched_process_exit: %w", err)
	}

	bindLink, err := link.Tracepoint("syscalls", "sys_enter_bind", objs.TraceBind, nil)
	if err != nil {
		_ = exitLink.Close()
		_ = forkLink.Close()
		_ = closeLink.Close()
		_ = sendmsgLink.Close()
		_ = sendtoLink.Close()
		_ = writeLink.Close()
		_ = connectLink.Close()
		_ = objs.Close()
		return nil, fmt.Errorf("attach sys_enter_bind: %w", err)
	}
	listenLink, err := link.Tracepoint("syscalls", "sys_enter_listen", objs.TraceListen, nil)
	if err != nil {
		_ = bindLink.Close()
		_ = exitLink.Close()
		_ = forkLink.Close()
		_ = closeLink.Close()
		_ = sendmsgLink.Close()
		_ = sendtoLink.Close()
		_ = writeLink.Close()
		_ = connectLink.Close()
		_ = objs.Close()
		return nil, fmt.Errorf("attach sys_enter_listen: %w", err)
	}

	reader, err := ringbuf.NewReader(objs.NetEvents)
	if err != nil {
		_ = listenLink.Close()
		_ = bindLink.Close()
		_ = exitLink.Close()
		_ = forkLink.Close()
		_ = closeLink.Close()
		_ = sendmsgLink.Close()
		_ = sendtoLink.Close()
		_ = writeLink.Close()
		_ = connectLink.Close()
		_ = objs.Close()
		return nil, fmt.Errorf("open ring buffer: %w", err)
	}

	o := &Observer{
		objs:         objs,
		connectLink:  connectLink,
		writeLink:    writeLink,
		sendtoLink:   sendtoLink,
		sendmsgLink:  sendmsgLink,
		closeLink:    closeLink,
		forkLink:     forkLink,
		exitLink:     exitLink,
		bindLink:     bindLink,
		listenLink:   listenLink,
		reader:       reader,
		events:       make(chan models.GroundTruthEvent, cfg.EventBufSize),
		stopped:      make(chan struct{}),
		tlsReady:     make(chan struct{}),
		cfg:          cfg,
		bootOffsetNs: bootOffsetNs,
		conns:        make(map[connKeyGo]*connection),
		pending:      make(map[sslKey]*tlsparse.Stream),
	}

	if cfg.ExePath != "" {
		if err := o.prepareTLS(cfg); err != nil {
			_ = reader.Close()
			_ = listenLink.Close()
			_ = bindLink.Close()
			_ = closeLink.Close()
			_ = sendmsgLink.Close()
			_ = sendtoLink.Close()
			_ = writeLink.Close()
			_ = connectLink.Close()
			_ = objs.Close()
			return nil, fmt.Errorf("prepare SSL_write content capture: %w", err)
		}
	}

	return o, nil
}

// httpRequestLineRE recognizes an HTTP/1.x request line at the start of a
// captured buffer, for offset validation only (design doc section 9 step
// 2-3): "does this candidate's first captured write look like a real
// SSL_write(request_bytes) call, not some other BoringSSL internal buffer".
// It is deliberately looser than tlsparse.ParseHTTP1, which needs a
// complete header block; validation only needs the request line.
var httpRequestLineRE = regexp.MustCompile(`^[A-Z]{2,10} \S+ HTTP/1\.[01]\r\n`)

// prepareTLS loads tls.bpf.c's objects, seeds its tracked_pids, opens the
// executable and the ssl_events ring buffer, and resolves SSL_write
// candidates in cfg.ExePath -- everything content capture needs except the
// actual uprobe attach, which Start (via attachAndValidateTLS) performs.
// Splitting attach out of New matches design doc section 9: "Validation is
// a separate mandatory step performed by net.Observer.Start", not New --
// because the process(es) whose traffic will validate a candidate may not
// exist yet at New time.
func (o *Observer) prepareTLS(cfg Config) (err error) {
	candidates, buildID, err := tlsoffset.ScanELF(cfg.ExePath)
	if err != nil {
		return fmt.Errorf("scan ELF for SSL_write: %w", err)
	}

	cachePath := cfg.CachePath
	if cachePath == "" {
		cachePath = filepath.Join(os.TempDir(), "agent-trace-tlsoffset-cache.json")
	}
	cache := tlsoffset.NewCache(cachePath)
	if cached := cache.Lookup(buildID); cached != nil {
		candidates = append([]tlsoffset.Candidate{{FileOff: cached.SSLWrite, Score: 1 << 30}}, candidates...)
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
	return nil
}

// attachAndValidateTLS is design doc section 9's validation step: attach
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
	for _, cand := range o.tlsCandidates {
		l, err := o.exe.Uprobe("", o.tlsObjs.ProbeSslWrite, &link.UprobeOptions{Address: cand.FileOff})
		if err != nil {
			continue
		}
		rec, seen, ok := validateSSLWriteCandidate(o.sslReader, timeout)
		framesSeen += seen
		if ok {
			o.sslWriteLink = l
			o.validationFrame = &rec
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
	_ = o.tlsCache.Store(o.tlsBuildID, tlsoffset.Target{Path: cfg.ExePath, BuildID: o.tlsBuildID, SSLWrite: chosen.FileOff})
}

// validateSSLWriteCandidate blocks for up to timeout waiting for one frame
// on reader and, if it looks like an HTTP/1.x request line, decodes and
// returns it (ok=true) so the caller can feed it to the correlator instead
// of discarding it -- a short-lived tracked process may never call
// SSL_write again after the one write that validated the offset, so
// dropping this frame would silently lose its content.
//
// seen reports whether a frame arrived at all (1) or the read timed out /
// the reader was closed (0), which is what lets the caller tell a wrong
// offset apart from non-HTTP/1.x plaintext.
func validateSSLWriteCandidate(reader *ringbuf.Reader, timeout time.Duration) (rec sslRecord, seen int, ok bool) {
	reader.SetDeadline(time.Now().Add(timeout))
	record, err := reader.Read()
	if err != nil {
		return sslRecord{}, 0, false
	}
	var hdr tlsbpfSslFrameHdr
	hdrSize := binary.Size(hdr)
	if len(record.RawSample) < hdrSize {
		return sslRecord{}, 1, false
	}
	payload := record.RawSample[hdrSize:]
	if !httpRequestLineRE.Match(payload) {
		return sslRecord{}, 1, false
	}
	if err := binary.Read(bytes.NewReader(record.RawSample), binary.NativeEndian, &hdr); err != nil {
		return sslRecord{}, 1, false
	}
	return sslRecord{hdr: hdr, payload: append([]byte(nil), payload...)}, 1, true
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
	if o.tlsObjs.TrackedPids != nil {
		if err := o.tlsObjs.TrackedPids.Update(&p, &one, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update tls tracked_pids: %w", err)
		}
	}
	return nil
}

// Coverage reports how much of the observed network activity was
// attributed to content, per design doc section 8. FaultedReads and
// RingbufDrops come from eBPF maps: they are read live while the observer
// runs and from the snapshot Stop took before closing the maps afterwards.
// Both are zero for the TLS side when content capture (cfg.ExePath) was
// never configured.
func (o *Observer) Coverage() Coverage {
	cov := o.coverage
	snapshot := func() kernelCounts {
		return kernelCounts{
			faulted:   o.finalFaulted.Load(),
			drops:     o.finalRingbufDrops.Load(),
			untracked: o.finalUntracked.Load(),
			stateFull: o.finalStateFull.Load(),
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
	return cov
}

// kernelCounts are the percpu counters the eBPF programs maintain, summed.
type kernelCounts struct {
	faulted   uint64 // SSL reads that faulted
	drops     uint64 // records the net and TLS ring buffers discarded because they were full
	untracked uint64 // descendants that could not be added to a tracked_pids map
	stateFull uint64 // connections lost because the conns map was full
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
	add(&k.faulted, o.tlsObjs.FaultedReads)
	add(&k.drops, o.tlsObjs.DropCount)
	add(&k.untracked, o.tlsObjs.UntrackedCount)
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
func (o *Observer) CaptureCoverage() models.ProbeCoverage {
	cov := o.Coverage()
	content := models.ContentActive
	switch {
	case o.cfg.ExePath == "":
		content = models.ContentIdentityOnly
	case o.tlsAttachErr != nil:
		content = models.ContentAttachFailed
	}
	return models.ProbeCoverage{
		Ran:               true,
		RingbufDrops:      cov.RingbufDrops,
		ChannelDrops:      o.Dropped(),
		UntrackedChildren: cov.UntrackedChildren,
		StateMapFull:      cov.StateMapFull,
		FaultedReads:      cov.FaultedReads,
		Content:           content,
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
func (o *Observer) Start() {
	go o.correlate()
	if o.exe != nil {
		o.attachAndValidateTLS(o.cfg)
	}
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
		// Snapshot the kernel counters before the maps are closed below;
		// Coverage reads this snapshot afterwards. Order matters: the
		// values are stored before the final flag is raised.
		k, _ := o.kernelCounters()
		o.finalFaulted.Store(k.faulted)
		o.finalRingbufDrops.Store(k.drops)
		o.finalUntracked.Store(k.untracked)
		o.finalStateFull.Store(k.stateFull)
		o.kernelCountersFinal.Store(true)
		if o.sslWriteLink != nil {
			_ = o.sslWriteLink.Close()
		}
		if o.tlsForkLink != nil {
			_ = o.tlsForkLink.Close()
		}
		if o.tlsExitLink != nil {
			_ = o.tlsExitLink.Close()
		}
		_ = o.tlsObjs.Close()
		_ = o.closeLink.Close()
		_ = o.sendmsgLink.Close()
		_ = o.sendtoLink.Close()
		_ = o.writeLink.Close()
		_ = o.connectLink.Close()
		_ = o.forkLink.Close()
		_ = o.exitLink.Close()
		_ = o.bindLink.Close()
		_ = o.listenLink.Close()
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
// o.pending, o.coverage): it drives both ring buffers via one select loop,
// per design doc section 6. The two feeder goroutines below exist only
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
			o.handleSSLFrame(rec.hdr.Tgid, rec.hdr.Tid, rec.payload, ts)
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
// o.sslReader and o.validationFrame to this goroutine.
func (o *Observer) sslFeed(out chan<- sslRecord) {
	defer close(out)

	<-o.tlsReady
	if !o.tlsActive {
		return // content capture unconfigured, or validation failed
	}

	// The frame that validated the chosen SSL_write candidate was consumed
	// straight off the ring buffer before this goroutine started reading.
	// Replay it so a tracked process that calls SSL_write only once still
	// gets its content correlated.
	if o.validationFrame != nil {
		out <- *o.validationFrame
		o.validationFrame = nil
	}

	var hdr tlsbpfSslFrameHdr
	hdrSize := binary.Size(hdr)

	for {
		record, err := o.sslReader.Read()
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
		payloadEnd := hdrSize + int(hdr.Len)
		if payloadEnd > len(record.RawSample) {
			continue
		}
		payload := append([]byte(nil), record.RawSample[hdrSize:payloadEnd]...)
		out <- sslRecord{hdr: hdr, payload: payload}
	}
}

func (o *Observer) handleNetRecord(rec netRecord) {
	hdr := rec.hdr
	key := connKeyGo{tgid: hdr.Tgid, fd: hdr.Fd}
	ts := time.Unix(0, int64(hdr.TsNs)+o.bootOffsetNs)

	switch hdr.Type {
	case netConnect:
		o.conns[key] = &connection{
			family:   hdr.Family,
			addr:     hdr.Addr,
			port:     hdr.Port,
			openedAt: ts,
		}
		o.coverage.Connections++

	case netHello:
		conn, ok := o.conns[key]
		if !ok {
			return
		}
		hello, err := tlsparse.ParseClientHello(rec.payload)
		if err != nil || hello.ServerName == "" {
			return
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
		o.emit(key, conn, int32(hdr.Tgid), ts)

	case netSockBind:
		o.emitListener(models.NetBind, hdr, rec.payload, ts)

	case netSockListen:
		o.emitListener(models.NetListen, hdr, rec.payload, ts)

	case netUnixConnect:
		o.emitGroundTruthOnly(models.NetUnixConnect, hdr.Tgid, unixTarget(rec.payload), ts)

	case netBind:
		// No-op: the write-bracket join this event existed for is
		// abandoned (D1, design doc section 13); net.bpf.c never emits it.
		return

	case netClose:
		conn, ok := o.conns[key]
		if ok {
			o.emit(key, conn, int32(hdr.Tgid), ts)
		}
		delete(o.conns, key)
	}
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
// peer-address fallback target).
func (o *Observer) emit(key connKeyGo, conn *connection, tgid int32, ts time.Time) {
	if conn.emitted {
		return
	}
	// Port 53 is DNS. DNS lookups are OS-level infrastructure triggered
	// implicitly by any hostname resolution — the agent does not explicitly
	// "connect" to a DNS server. Emitting these events would require every
	// agent trajectory to record DNS connections, which is impractical and
	// outside the scope of Tier 3's detection goals. Skip silently.
	if conn.port == 53 {
		conn.emitted = true // prevent double-emit on close
		return
	}
	// Port 0 is not a connection. The resolver connects a datagram socket to
	// each candidate address with port 0 to ask the kernel which source address
	// it would use (RFC 3484 address selection), once per address family, before
	// the real connection. In a paired capture every real connection had such
	// twins (an IPv4 and an IPv6 address with port 0), with nothing ever sent.
	// They name the destination's addresses, which change with DNS, so no
	// trajectory could claim them and no baseline could list them.
	if conn.port == 0 {
		conn.emitted = true
		return
	}
	conn.emitted = true

	target := conn.host
	if target == "" {
		target = peerAddrPort(conn.family, conn.addr, conn.port)
	}

	isTopLevel := true
	event := models.GroundTruthEvent{
		Timestamp:  ts,
		ActionType: models.NetConnect,
		Target:     target,
		IsTopLevel: &isTopLevel,
		PID:        uint32(tgid),
	}

	select {
	case o.events <- event:
	default:
		o.dropped.Add(1)
	}
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
