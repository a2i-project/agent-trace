// Package proc is the Tier 2 process probe. It attaches eBPF tracepoints to
// execve and process exit and emits models.GroundTruthEvent values that an
// independent verifier can compare against an agent's self-reported trajectory.
package proc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// The -I flag points clang at the multiarch UAPI headers (<asm/types.h>);
// x86_64-linux-gnu matches both local dev and the x86_64 CI runner. Add other
// triplets here if the build ever moves to a different architecture.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type event_hdr -type exec_scratch bpf proc.bpf.c -- -I/usr/include/x86_64-linux-gnu

// Kind values mirror the KIND_* constants in proc.bpf.c.
const (
	kindExec uint32 = 0
	kindExit uint32 = 1
	kindFork uint32 = 2
)

// Config controls the observer's behavior.
type Config struct {
	// PIDFilter, if > 0, restricts emitted events to this process tree. The
	// configured PID is the ancestry root; its direct children are top-level
	// events and deeper descendants are forensic-only events.
	PIDFilter int32

	// CommandFilter, if non-empty, restricts emitted events to commands whose
	// reconstructed command line has this prefix (e.g. "/usr/bin/git"). Useful
	// in tests and on shared hosts.
	CommandFilter string

	// DeferRootPID, if true and PIDFilter is 0, puts the probe into
	// ancestry-filtered mode immediately (an empty tracked_pids, so every
	// event is dropped) instead of the zero-value default of global mode
	// (every process on the host treated as top-level). Set this whenever
	// the caller will call SetRootPID once the root PID becomes known --
	// e.g. exec-wrap ("spawn the agent, then learn its PID") -- so there is
	// no window between New and SetRootPID during which unrelated host
	// activity gets recorded as verification-grade ground truth. Leave it
	// false for a genuine "no ancestry scoping, watch the whole host" probe
	// that will never call SetRootPID.
	DeferRootPID bool

	// EventBufSize is the channel buffer size for emitted events.
	// Defaults to 4096 if zero.
	EventBufSize int

	// RingbufBytes overrides the size of the kernel ring buffer that carries
	// events to userspace. Zero keeps the compiled-in 1 MiB. It exists so
	// tests can force a full buffer and exercise RingbufDrops; production
	// callers should leave it zero. Must be a power-of-two multiple of the
	// page size.
	RingbufBytes uint32

	// TrackedPIDsMax overrides the capacity of the kernel tracked_pids map.
	// Zero keeps the compiled-in 16384. It exists so tests can force an
	// overflow and exercise UntrackedChildren; production callers should
	// leave it zero.
	TrackedPIDsMax uint32

	// ExecsMax overrides the capacity of the kernel execs map, which holds
	// one entry per live exec until its exit record is written. Zero keeps
	// the compiled-in 4096. Test only, to force StateMapFull.
	ExecsMax uint32
}

// Observer watches process spawns via eBPF and emits GroundTruthEvents.
type Observer struct {
	objs          bpfObjects
	execLink      link.Link
	forkLink      link.Link
	exitLink      link.Link
	exitGroupLink link.Link
	reader        *ringbuf.Reader
	events        chan models.GroundTruthEvent
	stopped       chan struct{}
	cfg           Config
	dropped       atomic.Uint64
	stopOnce      sync.Once

	// finalRingbufDrops is the kernel drop counter as Stop last read it,
	// before closing the map. ringbufDropsFinal is raised after it is set.
	finalRingbufDrops atomic.Uint64
	ringbufDropsFinal atomic.Bool

	// finalUntracked is the untracked_count snapshot, same protocol.
	finalUntracked   atomic.Uint64
	untrackedIsFinal atomic.Bool

	// finalStateFull is the state_lost_count snapshot, same protocol.
	finalStateFull   atomic.Uint64
	stateFullIsFinal atomic.Bool

	// bootOffsetNs converts a bpf_ktime_get_ns() reading (ns since boot) to a
	// wall-clock UnixNano. Computed once at New() from a matched pair of
	// CLOCK_MONOTONIC and wall-clock reads, so it drifts slowly with NTP
	// adjustments over long uptimes -- acceptable for a probe whose consumer
	// compares timestamps within a configurable delta, not exactly.
	bootOffsetNs int64
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
	if cfg.RingbufBytes != 0 {
		spec.Maps["events"].MaxEntries = cfg.RingbufBytes
	}
	if cfg.TrackedPIDsMax != 0 {
		spec.Maps["tracked_pids"].MaxEntries = cfg.TrackedPIDsMax
	}
	if cfg.ExecsMax != 0 {
		spec.Maps["execs"].MaxEntries = cfg.ExecsMax
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("load eBPF objects: %w", err)
	}

	if cfg.PIDFilter > 0 || cfg.DeferRootPID {
		zero := uint32(0)
		one := uint8(1)
		if err := objs.ConfigMap.Update(&zero, &one, ebpf.UpdateAny); err != nil {
			_ = objs.Close()
			return nil, fmt.Errorf("update config_map: %w", err)
		}
	}

	if cfg.PIDFilter > 0 {
		zero := uint32(0)
		pid := uint32(cfg.PIDFilter)
		if err := objs.RootPidMap.Update(&zero, &pid, ebpf.UpdateAny); err != nil {
			_ = objs.Close()
			return nil, fmt.Errorf("update root_pid_map: %w", err)
		}
		// Seed the root as a top-level shell: is_shell=1 so its direct
		// children are verification-grade, is_toplevel=1 so handle_fork's
		// "parent is on the top-level shell chain" rule propagates from it.
		// The root is exempt from per-execve is_shell re-evaluation (Fix 3b).
		info := bpfProcInfo{IsShell: 1, IsToplevel: 1}
		if err := objs.TrackedPids.Update(&pid, &info, ebpf.UpdateAny); err != nil {
			_ = objs.Close()
			return nil, fmt.Errorf("update tracked_pids: %w", err)
		}
	}

	forkLink, err := link.Tracepoint("task", "task_newtask", objs.HandleFork, nil)
	if err != nil {
		_ = objs.Close()
		return nil, fmt.Errorf("attach task_newtask: %w", err)
	}

	execLink, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.HandleExecve, nil)
	if err != nil {
		_ = objs.Close()
		return nil, fmt.Errorf("attach sys_enter_execve: %w", err)
	}

	exitGroupLink, err := link.Tracepoint("syscalls", "sys_enter_exit_group", objs.HandleExitGroup, nil)
	if err != nil {
		_ = execLink.Close()
		_ = objs.Close()
		return nil, fmt.Errorf("attach sys_enter_exit_group: %w", err)
	}

	exitLink, err := link.Tracepoint("sched", "sched_process_exit", objs.HandleExit, nil)
	if err != nil {
		_ = exitGroupLink.Close()
		_ = execLink.Close()
		_ = objs.Close()
		return nil, fmt.Errorf("attach sched_process_exit: %w", err)
	}

	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		_ = exitLink.Close()
		_ = exitGroupLink.Close()
		_ = execLink.Close()
		_ = objs.Close()
		return nil, fmt.Errorf("open ring buffer: %w", err)
	}

	return &Observer{
		objs:          objs,
		execLink:      execLink,
		forkLink:      forkLink,
		exitLink:      exitLink,
		exitGroupLink: exitGroupLink,
		reader:        reader,
		events:        make(chan models.GroundTruthEvent, cfg.EventBufSize),
		stopped:       make(chan struct{}),
		cfg:           cfg,
		bootOffsetNs:  bootOffsetNs,
	}, nil
}

// computeBootOffsetNs pairs a CLOCK_MONOTONIC read with a wall-clock read
// taken immediately after, and returns the constant such that
// wallNs = monotonicNs + bootOffsetNs for any later bpf_ktime_get_ns()
// reading (which is also CLOCK_MONOTONIC-based).
func computeBootOffsetNs() (int64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, fmt.Errorf("clock_gettime CLOCK_MONOTONIC: %w", err)
	}
	monoNs := ts.Nano()
	wallNs := time.Now().UnixNano()
	return wallNs - monoNs, nil
}

// Events returns the channel on which GroundTruthEvents are delivered.
// The channel is closed when Stop returns.
func (o *Observer) Events() <-chan models.GroundTruthEvent {
	return o.events
}

// RingbufDrops reports how many records the kernel-side ring buffer discarded
// because it was full. Unlike Dropped, which counts the Go channel, these
// events never reached userspace at all, so a non-zero value means the ground
// truth for this run is incomplete and a verdict built on it is unreliable.
// Valid while the observer runs and after Stop returns.
func (o *Observer) RingbufDrops() uint64 {
	if !o.ringbufDropsFinal.Load() {
		if v, err := sumPerCPU(o.objs.DropCount); err == nil {
			return v
		}
	}
	return o.finalRingbufDrops.Load()
}

// UntrackedChildren reports how many descendants of the tracked tree could not
// be added to the kernel tracked_pids map because it was full. Each such
// process, and everything it forks, is invisible to this probe, so a non-zero
// value means the ground truth is incomplete. One increment can stand for a
// whole subtree: treat the value as a lower bound. Valid while the observer
// runs and after Stop returns.
func (o *Observer) UntrackedChildren() uint64 {
	if !o.untrackedIsFinal.Load() {
		if v, err := sumPerCPU(o.objs.UntrackedCount); err == nil {
			return v
		}
	}
	return o.finalUntracked.Load()
}

// StateMapFull reports how many exit records were lost because the kernel
// execs map was full when the process started. Each is an exit and exit code
// missing from the ground truth. A lower bound. Valid while the observer runs
// and after Stop returns.
func (o *Observer) StateMapFull() uint64 {
	if !o.stateFullIsFinal.Load() {
		if v, err := sumPerCPU(o.objs.StateLostCount); err == nil {
			return v
		}
	}
	return o.finalStateFull.Load()
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

// CaptureCoverage reports the loss counters for this capture. Call after Stop.
func (o *Observer) CaptureCoverage() models.ProbeCoverage {
	return models.ProbeCoverage{
		Ran:               true,
		RingbufDrops:      o.RingbufDrops(),
		ChannelDrops:      o.Dropped(),
		UntrackedChildren: o.UntrackedChildren(),
		StateMapFull:      o.StateMapFull(),
	}
}

// Dropped reports how many events were discarded because the events channel was
// full. Check after Stop returns.
func (o *Observer) Dropped() uint64 {
	return o.dropped.Load()
}

// Start begins reading ring-buffer records in a background goroutine.
func (o *Observer) Start() {
	go o.readLoop()
}

// Stop unblocks the read loop, waits for it, and releases all resources.
// The events channel is closed after Stop returns. Safe to call once.
func (o *Observer) Stop() error {
	o.stopOnce.Do(func() {
		_ = o.reader.Close() // unblocks readLoop's Read with ErrClosed
		<-o.stopped
		// Snapshot the counter before objs.Close releases its map.
		if v, err := sumPerCPU(o.objs.DropCount); err == nil {
			o.finalRingbufDrops.Store(v)
		}
		o.ringbufDropsFinal.Store(true)
		if v, err := sumPerCPU(o.objs.UntrackedCount); err == nil {
			o.finalUntracked.Store(v)
		}
		o.untrackedIsFinal.Store(true)
		if v, err := sumPerCPU(o.objs.StateLostCount); err == nil {
			o.finalStateFull.Store(v)
		}
		o.stateFullIsFinal.Store(true)
		_ = o.exitLink.Close()
		_ = o.exitGroupLink.Close()
		_ = o.forkLink.Close()
		_ = o.execLink.Close()
		_ = o.objs.Close()
		close(o.events)
	})
	return nil
}

// emitForkEdge sends a ProcessFork event: PID is the new process, PPID its
// parent. The target is the child's pid, since a fork has no command line.
func (o *Observer) emitForkEdge(hdr *bpfEventHdr) {
	event := models.GroundTruthEvent{
		Timestamp:  time.Unix(0, hdr.TsNs+o.bootOffsetNs),
		ActionType: models.ProcessFork,
		Target:     strconv.FormatUint(uint64(hdr.Pid), 10),
		PID:        hdr.Pid,
		PPID:       hdr.Ppid,
	}
	select {
	case o.events <- event:
	default:
		o.dropped.Add(1)
	}
}

func (o *Observer) readLoop() {
	defer close(o.stopped)

	var hdr bpfEventHdr
	hdrSize := binary.Size(hdr)
	const filenameLen = 256 // Matches FILENAME_LEN in proc.bpf.c

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
		// The root process's initial exec can happen before SetRootPID installs
		// the ancestry filter. The root itself is the controller, not an agent
		// action, so never expose its events as verification-grade events.
		if o.cfg.PIDFilter > 0 && int32(hdr.Pid) == o.cfg.PIDFilter {
			continue
		}

		var actionType models.ActionType
		switch hdr.Kind {
		case kindExec:
			actionType = models.ProcessExec
		case kindExit:
			actionType = models.ProcessExit
		case kindFork:
			// A header-only record: the edge parent -> child, for the
			// process tree. It has no command line, so it skips the payload
			// handling below.
			if o.cfg.CommandFilter != "" {
				continue
			}
			o.emitForkEdge(&hdr)
			continue
		default:
			continue
		}

		// Extract filename and args from the payload
		var fnBytes, argsBytes []byte
		if len(record.RawSample) >= hdrSize+filenameLen {
			fnBytes = record.RawSample[hdrSize : hdrSize+filenameLen]
			
			argsStart := hdrSize + filenameLen
			argsEnd := argsStart + int(hdr.ArgsSize)
			if argsEnd > len(record.RawSample) {
				argsEnd = len(record.RawSample)
			}
			if argsStart < argsEnd {
				argsBytes = record.RawSample[argsStart:argsEnd]
			}
		}

		target := commandLine(cString(fnBytes), argsBytes, hdr.Nargs)
		if target == "" {
			continue
		}
		if o.cfg.CommandFilter != "" && !strings.HasPrefix(target, o.cfg.CommandFilter) {
			continue
		}

		isTopLevel := hdr.IsToplevel == 1
		event := models.GroundTruthEvent{
			Timestamp:  time.Unix(0, hdr.TsNs+o.bootOffsetNs),
			ActionType: actionType,
			Target:     target,
			IsTopLevel: &isTopLevel,
			PID:        hdr.Pid,
			PPID:       hdr.Ppid,
		}
		if hdr.HasExitCode != 0 {
			code := hdr.ExitCode
			event.ExitCode = &code
		}

		select {
		case o.events <- event:
		default:
			o.dropped.Add(1)
		}
	}
}

// commandLine builds the ground-truth command identity for an exec/exit
// event. The leading token is the kernel-resolved execve path (filename),
// never argv[0]: a process can call execve() with any argv[0] it likes,
// unrelated to the binary actually being loaded (process masquerading), so
// argv[0] carries no evidentiary weight about what ran. The remaining
// tokens are argv[1:], rejoined from the fixed-width slots the BPF program
// wrote; argv[0] itself is dropped from the reported target since filename
// already identifies the binary and keeping both would just reintroduce a
// second, spoofable name for the same slot.
//
// If filename wasn't captured (e.g. the in-kernel read failed), this falls
// back to argv[0] so the event isn't silently dropped, but that fallback
// path carries the same caller-controlled-string weakness the filename read
// exists to avoid; it should be rare in practice (filename capture failing
// on a successful execve would itself be unusual).
func commandLine(filename string, args []byte, nargs uint32) string {
	var argv []string
	start := 0
	for i := uint32(0); i < nargs && start < len(args); i++ {
		end := start
		for end < len(args) && args[end] != 0 {
			end++
		}
		argv = append(argv, string(args[start:end]))
		start = end + 1
	}

	cmd := filename
	rest := argv
	if cmd == "" {
		if len(argv) == 0 {
			return ""
		}
		cmd = argv[0]
		rest = argv[1:]
	} else if len(argv) > 0 {
		rest = argv[1:]
	}

	parts := append([]string{cmd}, rest...)
	return strings.Join(parts, " ")
}

// cString converts a NUL-terminated byte slice into a Go string.
func cString(b []byte) string {
	buf := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0 {
			break
		}
		buf = append(buf, c)
	}
	return string(buf)
}

// SetRootPID configures the probe to only track this process and its descendants.
// It also clears the CommandFilter if any, since ancestry tracking replaces it.
func (o *Observer) SetRootPID(pid int32) error {
	zero := uint32(0)
	one := uint8(1)
	if err := o.objs.ConfigMap.Update(&zero, &one, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update config_map: %w", err)
	}
	p := uint32(pid)
	if err := o.objs.RootPidMap.Update(&zero, &p, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update root_pid_map: %w", err)
	}
	// Seed the root as a top-level shell: is_shell=1 so its direct children
	// are verification-grade, is_toplevel=1 so handle_fork's shell-chain
	// rule propagates from it. Exempt from per-execve is_shell re-eval (3b).
	info := bpfProcInfo{IsShell: 1, IsToplevel: 1}
	if err := o.objs.TrackedPids.Update(&p, &info, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update tracked_pids: %w", err)
	}
	o.cfg.PIDFilter = pid
	o.cfg.CommandFilter = ""
	return nil
}
