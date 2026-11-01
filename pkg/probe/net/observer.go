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
	"maps"
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
	netBind    uint8 = 3 // reserved, never emitted (N-D1)
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
	// for content capture. Without it, Observer runs identity-only:
	// NetConnect events with a resolved hostname, no NetRequest events. Required for TrackedPID's process to yield
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

	// Content lists content methods by name with the executable or library
	// each hooks, as the agent's profile chooses them (N-39): at most one
	// of MethodTLSSymbols and MethodOpenSSLEx (the SSL side, which ExePath
	// also sets as MethodTLSSymbols), MethodRustlsAEAD, and MethodGoCrypto
	// (N-48). Empty with no ExePath: identity-only.
	Content []ContentMethod
}

// Content method names, as config/agents.json names them (N-39).
const (
	MethodTLSSymbols = "tls-symbols"    // SSL_write and SSL_read
	MethodOpenSSLEx  = "tls-openssl-ex" // SSL_write_ex and SSL_read_ex
	MethodRustlsAEAD = "tls-rustls-aead"
	MethodGoCrypto   = "tls-go-crypto" // Go's crypto/tls.(*Conn).Write and Read (N-48)
)

// ContentMethod is one content method and the file it hooks.
type ContentMethod struct {
	Method string
	Path   string
}

// contentPlan is Config's content methods resolved: the SSL side's method
// and file, the rustls file and the Go file; "" for a side not configured.
type contentPlan struct {
	sslMethod, sslPath string
	aeadPath           string
	goPath             string
}

// planContent resolves cfg's content methods, refusing an unknown method,
// a method without a path, or two SSL-side methods.
func planContent(cfg Config) (contentPlan, error) {
	var p contentPlan
	ms := cfg.Content
	if cfg.ExePath != "" {
		ms = append([]ContentMethod{{Method: MethodTLSSymbols, Path: cfg.ExePath}}, ms...)
	}
	for _, m := range ms {
		if m.Path == "" {
			return p, fmt.Errorf("content method %s names no file", m.Method)
		}
		switch m.Method {
		case MethodTLSSymbols, MethodOpenSSLEx:
			if p.sslMethod != "" {
				return p, fmt.Errorf("content methods %s and %s both hook SSL calls; a capture takes one", p.sslMethod, m.Method)
			}
			p.sslMethod, p.sslPath = m.Method, m.Path
		case MethodRustlsAEAD:
			if p.aeadPath != "" {
				return p, fmt.Errorf("content method %s given twice", m.Method)
			}
			p.aeadPath = m.Path
		case MethodGoCrypto:
			if p.goPath != "" {
				return p, fmt.Errorf("content method %s given twice", m.Method)
			}
			p.goPath = m.Path
		default:
			return p, fmt.Errorf("unknown content method %q (%s, %s, %s or %s)", m.Method, MethodTLSSymbols, MethodOpenSSLEx, MethodRustlsAEAD, MethodGoCrypto)
		}
	}
	return p, nil
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
// models.GroundTruthEvent values. See the package doc comment for what it
// does and does not cover.
type Observer struct {
	objs    bpfObjects
	links   []link.Link // net.bpf.c raw tracepoints, in attach order
	reader  *ringbuf.Reader
	events  chan models.GroundTruthEvent
	stopped chan struct{}
	// stopping is closed when Stop begins, so a validation in progress
	// gives up instead of trying further candidates (N-32).
	stopping chan struct{}
	// sslDraining is raised by Stop once the TLS write side is detached:
	// the next flush of the ssl ring then ends sslFeed's reading (N-32).
	sslDraining atomic.Bool
	cfg         Config
	dropped     atomic.Uint64
	stopOnce    sync.Once

	// tracking is raised once a pid is in tracked_pids, by New or TrackPID.
	// Until then the probe watches nothing (N-26).
	tracking atomic.Bool

	// Kernel-side counters snapshotted by Stop, before it closes the maps
	// they live in. kernelCountersFinal is raised after the values are set.
	finalFaulted        atomic.Uint64
	finalNetDrops       atomic.Uint64
	finalTLSDrops       atomic.Uint64
	finalUntracked      atomic.Uint64
	finalStateFull      atomic.Uint64
	finalIOURingNet     atomic.Uint64
	finalIOURingOps     atomic.Uint64
	finalIOURingRings   atomic.Uint64
	finalHelloFaults    atomic.Uint64
	finalReadFaults     atomic.Uint64
	finalReadDrops      atomic.Uint64
	kernelCountersFinal atomic.Bool

	// Occupancy diagnostics (N-33): the high-water mark of each ring, and the
	// entries of each tracked_pids map. tlsTracked is nil without content
	// capture.
	netRing     ringMeter
	sslRing     ringMeter
	netRingSize uint64
	sslRingSize uint64
	netTracked  *trackedCounter
	tlsTracked  *trackedCounter

	// iouringSubmitUnseen is set when the kernel has no io_uring_submit_req
	// tracepoint, so io_uring operations cannot be classified; every ring a
	// tracked process sets up then counts as network activity (N-25).
	iouringSubmitUnseen bool

	bootOffsetNs int64

	conns  map[uint64]*connection // by socket inode number
	dgrams map[dgramKey]bool      // datagram destinations already emitted (N-28)

	// Content-capture state. tlsObjs and sslWriteLinks are zero/nil when
	// cfg.ExePath is unset: Observer then runs identity-only.
	// sslWriteLinks are the entry and return probes at the validated
	// SSL_write offset (N-37), and sslWrites reads the return's per-call
	// counts (N-36); nil until the offset validated.
	tlsObjs       tlsbpfObjects
	sslWriteLinks []link.Link
	sslWrites     *sslWriteMeter
	// firstLinks are the probes New attaches at the first candidate, so a
	// tracked process's SSL_write between New and Start is captured and
	// waits in ssl_events for validation. attachAndValidateTLS takes them
	// over (and clears the field) when it tries that candidate.
	firstLinks  []link.Link
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

	// plan is the content methods New resolved from cfg.
	plan contentPlan
	// writeProgs and readProgs are the entry and return programs of the
	// SSL side's method: SSL_write and SSL_read, or their _ex forms.
	writeProgs, readProgs [2]*ebpf.Program

	// The rustls side (N-39, N-40), set up by prepareAEAD; aeadReader is
	// nil without it. aeadLinks are its uprobes and its sys_enter hook.
	aeadExe      *link.Executable
	aeadLinks    []link.Link
	aeadReader   *ringbuf.Reader
	aeadRing     ringMeter
	aeadRingSize uint64
	aeadDraining atomic.Bool
	aeadScan     tlsoffset.AEADResult
	// Owned by correlate: whether a rustls write frame began with an
	// HTTP/1.x request line and a read frame with a status line, which
	// validate the located methods; and the first socket each encrypter
	// was bound to.
	aeadWriteValid, aeadReadValid bool
	aeadBound                     map[sslKey]uint64
	finalAEADDrops                atomic.Uint64

	// The Go side (N-47, N-48), set up by prepareGo; goReader is nil
	// without it. goLinks are its entry and return probes.
	goLinks    []link.Link
	goReader   *ringbuf.Reader
	goRing     ringMeter
	goRingSize uint64
	goDraining atomic.Bool
	goScan     tlsoffset.GoTLSResult
	goCounts   *goCountsMeter
	// Owned by correlate: whether a Go write frame began with a request
	// line or the HTTP/2 preface and a read frame with a status line or a
	// server SETTINGS frame.
	goWriteValid, goReadValid bool
	finalGoDrops              atomic.Uint64
}

// rawTracepoint is one program and the raw tracepoint it attaches to.
type rawTracepoint struct {
	name string
	prog *ebpf.Program
}

// netRawTracepoints lists the net.bpf.c programs New attaches, in attach
// order. Every hook is a raw tracepoint, whose detach does not wait for an
// RCU grace period the way a perf-event tracepoint's does (N-32): the
// syscall hooks sit behind the one sys_enter dispatcher.
func netRawTracepoints(objs *bpfObjects) []rawTracepoint {
	return []rawTracepoint{
		{"task_newtask", objs.HandleFork},
		{"sched_process_exit", objs.HandleExit},
		{"sys_enter", objs.TraceSysEnter},
	}
}

// sysEnterPrograms lists the programs the sys_enter dispatcher tail-calls,
// indexed by their slot (enum sys_slot in net.bpf.c, same order). The send
// hooks beyond write, sendto and sendmsg, and dup2 and dup3, complete the
// send side of a connection (N-23, N-24).
func sysEnterPrograms(objs *bpfObjects) []*ebpf.Program {
	return []*ebpf.Program{
		objs.TraceConnect,
		objs.TraceBind,
		objs.TraceListen,
		objs.TraceWrite,
		objs.TraceSendto,
		objs.TraceSendmsg,
		objs.TraceSendmmsg,
		objs.TraceWritev,
		objs.TracePwritev2,
		objs.TraceSendfile,
		objs.TraceSplice,
		objs.TraceClose,
		objs.TraceDup2,
		objs.TraceDup3,
	}
}

// iouringSubmitTracepoint is the io_uring operation counter's program
// (N-25). Unlike the programs above, a missing tracepoint is not an error: a
// kernel built without io_uring, or one older than the event's name, lacks
// it, and New handles that.
func iouringSubmitTracepoint(objs *bpfObjects) rawTracepoint {
	return rawTracepoint{"io_uring_submit_req", objs.TraceIouringSubmit}
}

// kernelHasIOURing reports whether the kernel has io_uring, from its trace
// events in tracefs. Without tracefs it cannot tell and says yes, so a ring
// is never taken as harmless for want of a mount.
func kernelHasIOURing() bool {
	for _, root := range []string{"/sys/kernel/tracing", "/sys/kernel/debug/tracing"} {
		if _, err := os.Stat(filepath.Join(root, "events")); err != nil {
			continue
		}
		_, err := os.Stat(filepath.Join(root, "events", "io_uring"))
		return err == nil
	}
	return true
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

	netTracked := &trackedCounter{stat: objs.TrackedStat, seededMap: objs.TrackedSeeded, capacity: objs.TrackedPids.MaxEntries()}
	if cfg.TrackedPID > 0 {
		p := uint32(cfg.TrackedPID)
		one := uint8(1)
		if err := netTracked.seed(objs.TrackedPids, &p, &one); err != nil {
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
	// The dispatcher's slots are filled before it is attached, so no syscall
	// reaches an empty slot.
	for slot, prog := range sysEnterPrograms(&objs) {
		if err := objs.SysEnterProgs.Update(uint32(slot), prog, ebpf.UpdateAny); err != nil {
			closeAll()
			return nil, fmt.Errorf("fill sys_enter slot %d: %w", slot, err)
		}
	}
	for _, tp := range netRawTracepoints(&objs) {
		l, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: tp.name, Program: tp.prog})
		if err != nil {
			closeAll()
			return nil, fmt.Errorf("attach %s: %w", tp.name, err)
		}
		links = append(links, l)
	}
	submitTP := iouringSubmitTracepoint(&objs)
	submitSeen := false
	if l, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: submitTP.name, Program: submitTP.prog}); err == nil {
		links = append(links, l)
		submitSeen = true
	} else if !errors.Is(err, os.ErrNotExist) {
		closeAll()
		return nil, fmt.Errorf("attach %s: %w", submitTP.name, err)
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
		stopping:     make(chan struct{}),
		tlsReady:     make(chan struct{}),
		cfg:          cfg,
		bootOffsetNs: bootOffsetNs,
		conns:        make(map[uint64]*connection),
		dgrams:       make(map[dgramKey]bool),
		tlsConns:     make(map[sslKey]*tlsConn),
		readOK:       make(chan struct{}),
		readStop:     make(chan struct{}),
		readDone:     make(chan struct{}),
		netTracked:   netTracked,
		netRingSize:  uint64(objs.NetEvents.MaxEntries()),

		iouringSubmitUnseen: !submitSeen && kernelHasIOURing(),
	}
	o.tracking.Store(cfg.TrackedPID > 0)

	plan, err := planContent(cfg)
	if err != nil {
		_ = reader.Close()
		closeAll()
		return nil, err
	}
	o.plan = plan
	o.aeadBound = map[sslKey]uint64{}
	if plan.sslPath != "" || plan.aeadPath != "" || plan.goPath != "" {
		if err := o.prepareTLS(cfg); err != nil {
			_ = reader.Close()
			closeAll()
			return nil, fmt.Errorf("prepare content capture: %w", err)
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

// prepareTLS loads the tls.bpf.c programs of the configured content methods
// and the maps they use, and no other (selectTLSPrograms), so a method a
// capture does not use can never stop another from loading. It seeds
// tracked_pids and attaches the fork and exit tracepoints, then prepares
// each configured side: prepareSSL for SSL_write and SSL_read or their _ex
// forms, prepareAEAD for rustls (N-39), prepareGo for Go (N-48). A side
// that cannot be prepared (its file unreadable, its anchors not found) fails
// New: the method is refused, never silently dropped.
func (o *Observer) prepareTLS(cfg Config) (err error) {
	tlsSpec, err := loadTlsbpf()
	if err != nil {
		return fmt.Errorf("load tls bpf spec: %w", err)
	}
	if cfg.TrackedPIDsMax != 0 {
		tlsSpec.Maps["tracked_pids"].MaxEntries = cfg.TrackedPIDsMax
	}
	if err := selectTLSPrograms(tlsSpec, o.plan.methods()); err != nil {
		return err
	}
	coll, err := ebpf.NewCollection(tlsSpec)
	if err != nil {
		return fmt.Errorf("load tls eBPF objects: %w", err)
	}
	assignCollection(&o.tlsObjs, coll)
	defer func() {
		if err != nil {
			closeLinks(o.goLinks)
			o.goLinks = nil
			if o.goReader != nil {
				_ = o.goReader.Close()
				o.goReader = nil
			}
			o.goCounts = nil
			closeLinks(o.aeadLinks)
			o.aeadLinks = nil
			if o.aeadReader != nil {
				_ = o.aeadReader.Close()
				o.aeadReader = nil
			}
			closeLinks(o.firstLinks)
			closeLinks(o.firstReadLinks)
			o.firstLinks, o.firstReadLinks = nil, nil
			if o.sslReader != nil {
				_ = o.sslReader.Close()
				o.sslReader = nil
			}
			if o.tlsForkLink != nil {
				_ = o.tlsForkLink.Close()
				o.tlsForkLink = nil
			}
			if o.tlsExitLink != nil {
				_ = o.tlsExitLink.Close()
				o.tlsExitLink = nil
			}
			o.exe = nil
			_ = o.tlsObjs.Close()
			o.tlsObjs = tlsbpfObjects{}
			o.tlsTracked = nil
		}
	}()

	tlsTracked := &trackedCounter{stat: o.tlsObjs.TrackedStat, seededMap: o.tlsObjs.TrackedSeeded, capacity: o.tlsObjs.TrackedPids.MaxEntries()}
	if cfg.TrackedPID > 0 {
		p := uint32(cfg.TrackedPID)
		one := uint8(1)
		if err := tlsTracked.seed(o.tlsObjs.TrackedPids, &p, &one); err != nil {
			return fmt.Errorf("update tls tracked_pids: %w", err)
		}
	}
	o.tlsTracked = tlsTracked

	if o.tlsForkLink, err = link.AttachRawTracepoint(link.RawTracepointOptions{Name: "task_newtask", Program: o.tlsObjs.HandleFork}); err != nil {
		return fmt.Errorf("attach tls task_newtask: %w", err)
	}
	if o.tlsExitLink, err = link.AttachRawTracepoint(link.RawTracepointOptions{Name: "sched_process_exit", Program: o.tlsObjs.HandleExit}); err != nil {
		return fmt.Errorf("attach tls sched_process_exit: %w", err)
	}

	if o.plan.sslPath != "" {
		if err := o.prepareSSL(cfg); err != nil {
			return err
		}
	}
	if o.plan.aeadPath != "" {
		if err := o.prepareAEAD(); err != nil {
			return fmt.Errorf("prepare %s content capture: %w", MethodRustlsAEAD, err)
		}
	}
	if o.plan.goPath != "" {
		if err := o.prepareGo(); err != nil {
			return fmt.Errorf("prepare %s content capture: %w", MethodGoCrypto, err)
		}
	}
	return nil
}

// prepareSSL resolves the SSL side's write and read candidates in its file,
// by symbol or by the method's locator (tlsoffset.Scan for tls-symbols,
// tlsoffset.ScanOpenSSLEx for tls-openssl-ex), opens the file and the
// ssl_events reader, and attaches the write probes at the first
// (highest-ranked) candidate. Validation is a separate mandatory step
// performed by net.Observer.Start, not New, because the process(es) whose
// traffic will validate a candidate may not exist yet at New time. The first
// candidate is attached here all the same: a process started after New and
// tracked before Start (an agent started by watch) can send its first
// request before Start runs, and a uprobe attached only in Start missed that
// frame, so validation then waited for a second request that may never
// come. The frame waits in ssl_events until validation reads it.
func (o *Observer) prepareSSL(cfg Config) error {
	path := o.plan.sslPath
	scan := tlsoffset.Scan
	cacheKey := func(id string) string { return id }
	o.writeProgs = [2]*ebpf.Program{o.tlsObjs.ProbeSslWrite, o.tlsObjs.ProbeSslWriteReturn}
	o.readProgs = [2]*ebpf.Program{o.tlsObjs.ProbeSslReadEntry, o.tlsObjs.ProbeSslReadReturn}
	if o.plan.sslMethod == MethodOpenSSLEx {
		scan = tlsoffset.ScanOpenSSLEx
		// Kept apart from tls-symbols' offsets for the same build.
		cacheKey = func(id string) string {
			if id == "" {
				return ""
			}
			return id + "/" + MethodOpenSSLEx
		}
		o.writeProgs = [2]*ebpf.Program{o.tlsObjs.ProbeSslWriteEx, o.tlsObjs.ProbeSslWriteExReturn}
		o.readProgs = [2]*ebpf.Program{o.tlsObjs.ProbeSslReadExEntry, o.tlsObjs.ProbeSslReadExReturn}
	}
	res, err := scan(path)
	if err != nil {
		return fmt.Errorf("scan %s for %s: %w", path, o.plan.sslMethod, err)
	}
	candidates, buildID, readCands := res.Write, cacheKey(res.BuildID), res.Read

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
		return fmt.Errorf("no write candidates found in %s", path)
	}

	exe, err := link.OpenExecutable(path)
	if err != nil {
		return fmt.Errorf("open executable %s: %w", path, err)
	}
	o.sslRingSize = uint64(o.tlsObjs.SslEvents.MaxEntries())
	sslReader, err := ringbuf.NewReader(o.tlsObjs.SslEvents)
	if err != nil {
		return fmt.Errorf("open ssl ring buffer: %w", err)
	}
	o.exe = exe
	o.sslReader = sslReader
	o.tlsCache = cache
	o.tlsBuildID = buildID
	o.tlsCandidates = candidates
	o.readCands = dedupCandidates(readCands)
	// A failed attach is not fatal here: attachAndValidateTLS tries the
	// candidate again and reports the outcome.
	if ls, err := o.attachWrite(candidates[0].FileOff); err == nil {
		o.firstLinks = ls
	}
	// The read probes at the first read candidate, for the same reason:
	// the response to a request sent before Start must not be missed.
	if len(o.readCands) > 0 {
		if ls, err := o.attachRead(o.readCands[0].FileOff); err == nil {
			o.firstReadLinks = ls
		}
	}
	return nil
}

// attachAndValidateTLS is the validation step (N-D4): attach the
// SSL_write probes at each candidate in turn and require its first captured
// frame from a tracked process to begin with an HTTP/1.x request line or
// the HTTP/2 client preface (validRequestStart; D4:
// runtime validation is authoritative, the ELF scan's score is only a
// sorting hint). Called from Start, which blocks on it -- see Start's doc
// comment for why that's acceptable despite Start having no error return.
//
// On success the validated offset is cached by build ID, o.sslWriteLinks
// is set and o.tlsActive becomes true. On failure (no candidate validates
// within its timeout) it leaves o.sslWriteLinks nil, closes o.sslReader, and
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
	stopped := false
	for i, cand := range o.tlsCandidates {
		select {
		case <-o.stopping:
			stopped = true
		default:
		}
		if stopped {
			break
		}
		var ls []link.Link
		if i == 0 && o.firstLinks != nil {
			ls, o.firstLinks = o.firstLinks, nil // attached in New (prepareTLS)
		} else {
			var err error
			if ls, err = o.attachWrite(cand.FileOff); err != nil {
				continue
			}
		}
		rec, seen, ok := o.validateSSLWriteCandidate(timeout)
		framesSeen += seen
		if ok {
			o.sslWriteLinks = ls
			o.replay = append(o.replay, rec)
			chosen = cand
			validated = true
			break
		}
		closeLinks(ls)
	}
	if !validated {
		// Distinguish "the offset is wrong / nothing wrote" from "the
		// offset is fine but the plaintext is neither HTTP/1.x nor HTTP/2",
		// so the reader does not hunt for a symbol-resolution bug that
		// isn't there.
		switch {
		case stopped:
			o.tlsAttachErr = fmt.Errorf("no SSL_write candidate validated in %s before the capture stopped", o.plan.sslPath)
		case framesSeen > 0:
			o.tlsAttachErr = fmt.Errorf("no SSL_write candidate validated in %s (%d tried): captured %d frame(s), none began with an HTTP/1.x request line or the HTTP/2 client preface",
				o.plan.sslPath, len(o.tlsCandidates), framesSeen)
		default:
			o.tlsAttachErr = fmt.Errorf("no SSL_write candidate validated in %s (%d tried): no frame was captured from a tracked process within %s",
				o.plan.sslPath, len(o.tlsCandidates), timeout)
		}
		_ = o.sslReader.Close()
		return
	}

	o.sslReader.SetDeadline(time.Time{}) // clear the validation deadline for normal operation
	// The per-call counts of SSL_write (N-36) start here, at the validated
	// offset only: the return probe at a rejected candidate would have
	// counted another function's returns. A failed switch leaves the
	// counts unmeasured.
	var zero, on uint32 = 0, 1
	if m := o.tlsObjs.SslWriteCounting; m != nil && o.tlsObjs.SslWriteStat != nil {
		if err := m.Update(&zero, &on, ebpf.UpdateAny); err == nil {
			o.sslWrites = &sslWriteMeter{stat: o.tlsObjs.SslWriteStat}
		}
	}
	o.tlsActive = true
	o.writeOffset = chosen.FileOff
	target := tlsoffset.Target{Path: o.plan.sslPath, BuildID: o.tlsBuildID, SSLWrite: chosen.FileOff}
	if prev := o.tlsCache.Lookup(o.tlsBuildID); prev != nil && prev.SSLWrite == chosen.FileOff {
		target.SSLRead = prev.SSLRead // kept until a validation replaces it
	}
	_ = o.tlsCache.Store(o.tlsBuildID, target)
}

// validateSSLWriteCandidate blocks for up to timeout waiting for one write
// frame on o.sslReader and, if validRequestStart accepts it (an HTTP/1.x
// request line or the HTTP/2 preface),
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
// wrong offset apart from plaintext that is neither HTTP/1.x nor HTTP/2.
func (o *Observer) validateSSLWriteCandidate(timeout time.Duration) (rec sslRecord, seen int, ok bool) {
	o.sslReader.SetDeadline(time.Now().Add(timeout))
	for {
		record, err := o.sslReader.Read()
		if err != nil {
			return sslRecord{}, 0, false
		}
		o.sslRing.observe(&record)
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
		if !validRequestStart(rec.payload) {
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
	if err := o.netTracked.seed(o.objs.TrackedPids, &p, &one); err != nil {
		return fmt.Errorf("update tracked_pids: %w", err)
	}
	o.tracking.Store(true)
	if o.tlsObjs.TrackedPids != nil {
		if err := o.tlsTracked.seed(o.tlsObjs.TrackedPids, &p, &one); err != nil {
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
	cov.WSRefusedReasons = maps.Clone(cov.WSRefusedReasons)
	snapshot := func() kernelCounts {
		return kernelCounts{
			faulted:    o.finalFaulted.Load(),
			netDrop:    o.finalNetDrops.Load(),
			tlsDrop:    o.finalTLSDrops.Load(),
			untracked:  o.finalUntracked.Load(),
			stateFull:  o.finalStateFull.Load(),
			uringNet:   o.finalIOURingNet.Load(),
			uringOps:   o.finalIOURingOps.Load(),
			uringRing:  o.finalIOURingRings.Load(),
			helloFault: o.finalHelloFaults.Load(),
			readFault:  o.finalReadFaults.Load(),
			readDrop:   o.finalReadDrops.Load(),
			aeadDrop:   o.finalAEADDrops.Load(),
			goDrop:     o.finalGoDrops.Load(),
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
	cov.RingbufDrops += k.netDrop + k.tlsDrop + k.aeadDrop + k.goDrop
	cov.AEADRingDrops += k.aeadDrop
	cov.GoRingDrops += k.goDrop
	cov.NetRingDrops += k.netDrop
	cov.TLSRingDrops += k.tlsDrop
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
	netDrop    uint64 // records the net ring buffer discarded because it was full
	tlsDrop    uint64 // write frames the TLS ring buffer discarded because it was full
	untracked  uint64 // descendants that could not be added to a tracked_pids map
	stateFull  uint64 // connections lost because the conns map was full
	uringNet   uint64 // io_uring operations on sockets by tracked processes (N-25)
	uringOps   uint64 // io_uring operations of any kind by tracked processes
	uringRing  uint64 // io_uring rings set up by tracked processes
	helloFault uint64 // hello reads that faulted on a connection still waiting for its hello
	readFault  uint64 // SSL_read buffers that faulted
	readDrop   uint64 // SSL_read frames the TLS ring buffer discarded
	aeadDrop   uint64 // rustls frames and bind records the aead_events ring discarded
	goDrop     uint64 // Go write frames the go_events ring discarded
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
	add(&k.netDrop, o.objs.DropCount)
	add(&k.untracked, o.objs.UntrackedCount)
	add(&k.stateFull, o.objs.StateLostCount)
	add(&k.uringNet, o.objs.IouringNetCount)
	add(&k.uringOps, o.objs.IouringOpsCount)
	add(&k.uringRing, o.objs.IouringSetupCount)
	add(&k.helloFault, o.objs.HelloFaultCount)
	add(&k.faulted, o.tlsObjs.FaultedReads)
	add(&k.tlsDrop, o.tlsObjs.DropCount)
	add(&k.untracked, o.tlsObjs.UntrackedCount)
	add(&k.readFault, o.tlsObjs.ReadFaultCount)
	add(&k.readDrop, o.tlsObjs.ReadDropCount)
	add(&k.aeadDrop, o.tlsObjs.AeadDropCount)
	add(&k.goDrop, o.tlsObjs.GoDropCount)
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
	methods := o.contentMethods()
	// The probe's state is active when any configured method's is (N-42):
	// one method that saw nothing does not mark the content the others read
	// as not captured. An adapter reads the state of the method its claims
	// depend on (models.ProbeCoverage.MethodContent).
	content, responses := models.ContentIdentityOnly, models.ContentIdentityOnly
	if len(methods) > 0 {
		content, responses = models.ContentAttachFailed, models.ContentAttachFailed
		for _, m := range methods {
			if m.Requests == models.ContentActive {
				content = models.ContentActive
			}
			if m.Responses == models.ContentActive {
				responses = models.ContentActive
			}
		}
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
		RequestsCut:       uint64(cov.RequestsCut),
		Diagnostics:       o.diagnostics(cov, methods),
	}
}

// contentMethods is the state of each configured content method (N-39).
// The SSL side's requests are active once its write offset validated and
// its responses once its read offset did; the rustls side's once a write
// frame began with a request line and a read frame with a status line.
// Read after Stop.
func (o *Observer) contentMethods() map[string]models.ContentMethodState {
	state := func(ok bool) string {
		if ok {
			return models.ContentActive
		}
		return models.ContentAttachFailed
	}
	m := map[string]models.ContentMethodState{}
	if o.plan.sslPath != "" {
		m[o.plan.sslMethod] = models.ContentMethodState{Requests: state(o.tlsAttachErr == nil && o.tlsActive), Responses: state(o.readActive.Load())}
	}
	if o.plan.aeadPath != "" {
		m[MethodRustlsAEAD] = models.ContentMethodState{Requests: state(o.aeadWriteValid), Responses: state(o.aeadReadValid)}
	}
	if o.plan.goPath != "" {
		m[MethodGoCrypto] = models.ContentMethodState{Requests: state(o.goWriteValid), Responses: state(o.goReadValid)}
	}
	return m
}

// diagnostics assembles the occupancy and content counters of the capture
// (N-33). Diagnostics only: Assess reads none of them.
func (o *Observer) diagnostics(cov Coverage, methods map[string]models.ContentMethodState) *models.ProbeDiagnostics {
	d := &models.ProbeDiagnostics{
		Rings: map[string]models.RingStats{"net_events": {
			SizeBytes: o.netRingSize, PeakBytes: o.netRing.peak.Load(), Records: o.netRing.records.Load(), Drops: cov.NetRingDrops,
		}},
		TrackedSets: map[string]models.TrackedSetStats{},
		NetContent:  netContentCounts(cov),
	}
	if o.netTracked != nil {
		d.TrackedSets["net"] = o.netTracked.stats()
	}
	if o.tlsTracked != nil {
		d.TrackedSets["tls"] = o.tlsTracked.stats()
	}
	if o.plan.sslPath != "" {
		readDrops := cov.ReadDrops
		d.Rings["ssl_events"] = models.RingStats{
			SizeBytes: o.sslRingSize, PeakBytes: o.sslRing.peak.Load(), Records: o.sslRing.records.Load(), Drops: cov.TLSRingDrops, ReadDrops: &readDrops,
		}
	}
	if o.sslWrites != nil {
		d.SSLWrites = o.sslWrites.counts()
	}
	if o.aeadReader != nil {
		d.Rings["aead_events"] = models.RingStats{
			SizeBytes: o.aeadRingSize, PeakBytes: o.aeadRing.peak.Load(), Records: o.aeadRing.records.Load(), Drops: cov.AEADRingDrops,
		}
	}
	if o.goReader != nil {
		d.Rings["go_events"] = models.RingStats{
			SizeBytes: o.goRingSize, PeakBytes: o.goRing.peak.Load(), Records: o.goRing.records.Load(), Drops: cov.GoRingDrops,
		}
	}
	if o.goCounts != nil {
		d.GoTLS = o.goCounts.counts()
	}
	if len(methods) > 0 {
		d.ContentMethods = methods
	}
	return d
}

// netContentCounts copies the correlator's counters into the capture's
// record.
func netContentCounts(c Coverage) *models.NetContentCounts {
	return &models.NetContentCounts{
		Connections: c.Connections, WithHostname: c.WithHostname, WithContent: c.WithContent,
		Dials: c.Dials, AddressProbes: c.AddressProbes, OpenAtStop: c.OpenAtStop, Replaced: c.Replaced,
		HellosFollowed: c.HellosFollowed, DNS: c.DNS, DNSNamed: c.DNSNamed, DNSUnparsed: c.DNSUnparsed, Datagrams: c.Datagrams,
		ContentUnsupported: c.ContentUnsupported, H2Preface: c.H2Preface, H2PrefaceUnvalidated: c.H2PrefaceUnvalidated, FramesH2: c.FramesH2,
		H2Requests: c.H2Requests, H2Responses: c.H2Responses, H2Unparsed: c.H2Unparsed, H2Malformed: c.H2Malformed, H2NoPreface: c.H2NoPreface,
		FramesUnattributed: c.FramesUnattributed, FramesTruncated: c.FramesTruncated, RequestsCut: c.RequestsCut,
		Responses: c.Responses, ResponsesUnpaired: c.ResponsesUnpaired, ResponsesUnattributed: c.ResponsesUnattributed,
		ResponsesIncomplete: c.ResponsesIncomplete, ResponsesTruncated: c.ResponsesTruncated, ResponsesUnparsed: c.ResponsesUnparsed,
		SSEEvents: c.SSEEvents, ReadsUnvalidated: c.ReadsUnvalidated, ReadFaults: c.ReadFaults,
		WebSockets: c.WebSockets, WSAccepted: c.WSAccepted, WSRequests: c.WSRequests, WSServerMessages: c.WSServerMessages, WSModelRequests: c.WSModelRequests,
		WSRefused: c.WSRefused, WSRefusedReasons: c.WSRefusedReasons, WSDeflate: c.WSDeflate, WSUnparsed: c.WSUnparsed,
		AEADUnvalidated: c.AEADUnvalidated, AEADUnbound: c.AEADUnbound, AEADRebound: c.AEADRebound, AEADUnpaired: c.AEADUnpaired,
		GoUnvalidated: c.GoUnvalidated, GoUnbound: c.GoUnbound, GoConnReused: c.GoConnReused,
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

// Stop ends the capture without losing what is already in the rings, and
// releases all resources (N-32). It detaches the producers first, then lets
// each feeder read its ring until it is empty and return: a ring flush wakes
// a feeder blocked in Read, which then reads with a deadline of now, so it
// gets every record already committed and stops at the first empty read.
// The net side goes first; the TLS write side is detached once Start has
// finished (a validation in progress gives up when the flush interrupts
// it), and its ring is drained the same way. correlate closes the events
// channel once both feeders have returned, which happens before it signals
// o.stopped, so Stop waits on o.stopped alone and must not close o.events
// again. Every hook is a raw tracepoint or a uprobe, so no step waits for a
// fixed time. Safe to call once, after Start.
func (o *Observer) Stop() error {
	o.stopOnce.Do(func() {
		close(o.stopping)
		closeLinksReverse(o.links)
		o.links = nil
		_ = o.reader.Flush() // netFeed drains the net ring and returns
		if o.sslReader != nil {
			// Interrupts a validation still reading; a failed validation
			// has already closed the reader, and this is then a no-op.
			_ = o.sslReader.Flush()
		}
		<-o.tlsReady
		// Start has returned, so the TLS write side's links are settled.
		closeLinks(o.sslWriteLinks)
		closeLinks(o.firstLinks) // never taken over by a validation
		if o.tlsForkLink != nil {
			_ = o.tlsForkLink.Close()
		}
		if o.tlsExitLink != nil {
			_ = o.tlsExitLink.Close()
		}
		o.sslDraining.Store(true)
		if o.sslReader != nil {
			_ = o.sslReader.Flush() // sslFeed drains the TLS ring and returns
		}
		// The rustls side: its probes and socket hook detached, its ring
		// drained the same way.
		closeLinksReverse(o.aeadLinks)
		o.aeadLinks = nil
		o.aeadDraining.Store(true)
		if o.aeadReader != nil {
			_ = o.aeadReader.Flush()
		}
		// The Go side, the same way.
		closeLinksReverse(o.goLinks)
		o.goLinks = nil
		o.goDraining.Store(true)
		if o.goReader != nil {
			_ = o.goReader.Flush()
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
		o.finalNetDrops.Store(k.netDrop)
		o.finalTLSDrops.Store(k.tlsDrop)
		o.finalUntracked.Store(k.untracked)
		o.finalStateFull.Store(k.stateFull)
		o.finalIOURingNet.Store(k.uringNet)
		o.finalIOURingOps.Store(k.uringOps)
		o.finalIOURingRings.Store(k.uringRing)
		o.finalHelloFaults.Store(k.helloFault)
		o.finalReadFaults.Store(k.readFault)
		o.finalReadDrops.Store(k.readDrop)
		o.finalAEADDrops.Store(k.aeadDrop)
		o.finalGoDrops.Store(k.goDrop)
		o.kernelCountersFinal.Store(true)
		if o.netTracked != nil {
			o.netTracked.snapshot()
		}
		if o.tlsTracked != nil {
			o.tlsTracked.snapshot()
		}
		if o.sslWrites != nil {
			o.sslWrites.snapshot()
		}
		if o.goCounts != nil {
			o.goCounts.snapshot()
		}
		closeLinks(o.readLinks)
		_ = o.reader.Close()
		if o.sslReader != nil {
			_ = o.sslReader.Close() // idempotent
		}
		if o.aeadReader != nil {
			_ = o.aeadReader.Close()
		}
		if o.goReader != nil {
			_ = o.goReader.Close()
		}
		_ = o.tlsObjs.Close()
		_ = o.objs.Close()
	})
	return nil
}

// closeLinksReverse closes links in the reverse of attach order.
func closeLinksReverse(ls []link.Link) {
	for i := len(ls) - 1; i >= 0; i-- {
		_ = ls[i].Close()
	}
}

// drainRead classifies a ring-buffer read error for a feeder that drains at
// Stop (N-32). A flush starts the drain when drain allows it: the reader's
// deadline becomes now, so further reads return what the ring holds and then
// os.ErrDeadlineExceeded, which ends the feeder, as does a closed reader.
func drainRead(r *ringbuf.Reader, err error, drain bool) (stop bool) {
	switch {
	case errors.Is(err, ringbuf.ErrClosed), errors.Is(err, os.ErrDeadlineExceeded):
		return true
	case errors.Is(err, ringbuf.ErrFlushed) && drain:
		r.SetDeadline(time.Now())
	}
	return false
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

	var aeadCh chan sslRecord
	if o.aeadReader != nil {
		aeadCh = make(chan sslRecord, 64)
		go o.aeadFeed(aeadCh)
	}
	var goCh chan sslRecord
	if o.goReader != nil {
		goCh = make(chan sslRecord, 64)
		go o.goFeed(goCh)
	}

	// Each feeder's channel is set to nil once it closes: a closed channel is
	// always ready, so leaving it in the select would spin this goroutine at
	// 100% CPU until the other feeder finished. A nil channel blocks forever
	// and drops out of the select instead.
	defer o.flushOpenConnections()
	defer o.flushResponses()
	for netCh != nil || sslCh != nil || aeadCh != nil || goCh != nil {
		select {
		case rec, ok := <-goCh:
			if !ok {
				goCh = nil
				continue
			}
			o.handleGoRecord(rec, time.Unix(0, int64(rec.hdr.TsNs)+o.bootOffsetNs))

		case rec, ok := <-aeadCh:
			if !ok {
				aeadCh = nil
				continue
			}
			o.handleAEADRecord(rec, time.Unix(0, int64(rec.hdr.TsNs)+o.bootOffsetNs))

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
			if drainRead(o.reader, err, true) {
				return
			}
			continue
		}
		o.netRing.observe(&record)
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
			// A flush before the write side is detached (the one that
			// interrupts a validation, when it arrives after the validation
			// ended) does not start the drain.
			if drainRead(o.sslReader, err, o.sslDraining.Load()) {
				return
			}
			continue
		}
		o.sslRing.observe(&record)
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
	return true
}

// emitListener sends a NetBind or NetListen event. They carry no hostname and
// need no connection state, so they bypass the connection correlator. They
// are ground truth only, never claimable (models.ActionType.IsClaimable); the
// verifier keys on the action type.
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

	event := models.GroundTruthEvent{
		Timestamp:  ts,
		ActionType: models.NetConnect,
		Target:     target,
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
