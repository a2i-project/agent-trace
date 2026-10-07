// Command watch is the ground-truth recorder half of the live verification
// harness (see the three-component architecture in
// docs/plan/01_protocol_architecture.md): it runs whichever probes are
// requested against a workspace, prints each ground-truth event as it is
// captured, and writes the accumulated ground truth to a JSON file that
// `verify` can compare against a trajectory.
//
// Invocation modes:
//
//   - watch --workspace PATH -- <agent command> [args...]
//     watch launches the agent itself, records its PID as the proc probe's
//     ancestry root (so the agent's own exec is suppressed and only its
//     descendants count as agent actions), runs it to completion, then
//     writes the ground truth. This is the mode that makes ancestry
//     tracking actually work.
//
//   - watch --workspace PATH --root-pid N
//     Attach the ancestry root to an already-running PID (e.g. a container
//     entrypoint watch cannot be the parent of). Anything that PID did
//     before this call is invisible to the proc probe; the fs probe is
//     unaffected. Records until Ctrl+C.
//
//   - watch --workspace PATH
//     No ancestry scoping. The proc probe reports every process on the host
//     unless --proc-filter narrows it. Records until Ctrl+C.
//
// Extending this for a new tier's probe is one addition to probeBuilders
// below; nothing else in this file needs to change.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/probe"
	"github.com/agent-trace/agent-trace/pkg/probe/fs"
	probenet "github.com/agent-trace/agent-trace/pkg/probe/net"
	"github.com/agent-trace/agent-trace/pkg/probe/proc"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// watchConfig holds the flags a probe builder may need. Add fields here as
// new probes need new configuration (e.g. a listen address for a Tier 3
// network proxy).
type watchConfig struct {
	Workspace    string
	ProcFilter   string
	EventBufSize int

	// AncestryPending is true whenever runWatch will call the proc probe's
	// SetRootPID once the root PID becomes known (exec-wrap or --root-pid).
	// It tells the proc builder to start in ancestry-filtered mode from the
	// moment its tracepoints attach, instead of the zero-value global mode --
	// otherwise every process on the host would be recorded as top-level
	// ground truth during the window before SetRootPID runs.
	AncestryPending bool

	// NetExePath, when set, enables the SSL_write uprobe on that executable
	// for content capture (Tier 3 S5+). Empty means identity-only (SNI only).
	NetExePath string

	// NetCachePath is the JSON cache file for pre-computed TLS offsets.
	// Defaults to $TMPDIR/agent-trace-tlsoffset-cache.json when empty.
	NetCachePath string

	// ProcRingbufBytes overrides the proc probe's kernel ring buffer size.
	// Zero keeps the default. Set from tests only, to force event loss; there
	// is deliberately no command-line flag for it.
	ProcRingbufBytes uint32
}

type builderFunc func(watchConfig) (probe.Observer, error)

// probeBuilders is the extension point: one entry per probe this harness
// knows how to run. Add a case here when a new tier's probe lands.
var probeBuilders = map[string]builderFunc{
	"fs": func(cfg watchConfig) (probe.Observer, error) {
		return fs.New(fs.Config{
			Path:         cfg.Workspace,
			PathFilter:   cfg.Workspace,
			EventBufSize: cfg.EventBufSize,
		})
	},
	"proc": func(cfg watchConfig) (probe.Observer, error) {
		return proc.New(proc.Config{
			CommandFilter: cfg.ProcFilter,
			EventBufSize:  cfg.EventBufSize,
			DeferRootPID:  cfg.AncestryPending,
			RingbufBytes:  cfg.ProcRingbufBytes,
		})
	},
	// Tier 3 network probe: emits NetConnect events with resolved hostname
	// (SNI) for each outbound TLS connection from the tracked process. When
	// cfg.NetExePath is set, the SSL_write uprobe is also attached for
	// content capture (NetRequest events).
	"net": func(cfg watchConfig) (probe.Observer, error) {
		return probenet.New(probenet.Config{
			EventBufSize: cfg.EventBufSize,
			ExePath:      cfg.NetExePath,
			CachePath:    cfg.NetCachePath,
		})
	},
}

// buildCoverage assembles the per-probe loss record written next to the
// events. Every known probe gets an entry: one that was not selected is
// recorded with Ran=false, so the file shows what was not watched instead of
// leaving the verifier to guess. Call after every probe has stopped.
func buildCoverage(reporters map[string]probe.CoverageReporter) models.Coverage {
	cov := models.Coverage{Schema: models.CoverageSchema, Probes: make(map[string]models.ProbeCoverage, len(probeBuilders))}
	for name := range probeBuilders {
		if r, ok := reporters[name]; ok {
			cov.Probes[name] = r.CaptureCoverage()
		} else {
			cov.Probes[name] = models.ProbeCoverage{Ran: false}
		}
	}
	return cov
}

// sortGround orders events by time. It is stable, because events read in one
// batch share a timestamp and keep the order the probe emitted them in, and the
// verifier aligns by position: an unstable sort could swap such ties.
func sortGround(g models.GroundTruth) {
	sort.SliceStable(g, func(i, j int) bool { return g[i].Timestamp.Before(g[j].Timestamp) })
}

// workspaceAbs is the workspace as an absolute path, which is how the probes
// report paths. The verifier uses it to recognise the workspace inside the
// targets of a harness baseline.
func workspaceAbs(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}

func availableProbes() string {
	names := make([]string, 0, len(probeBuilders))
	for name := range probeBuilders {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// watchOptions is the fully parsed configuration for one runWatch call.
// main() fills it from flags; tests construct it directly.
type watchOptions struct {
	cfg       watchConfig
	probes    string
	out       string
	rootPID   int
	agentArgs []string // command (and args) after "--"; empty means no exec-wrap
}

func main() {
	var workspace, probesFlag, procFilter, out string
	var bufSize, rootPID int
	var netExePath, netCachePath string

	flag.StringVar(&workspace, "workspace", "", "Path to the workspace to watch (fs probe)")
	flag.StringVar(&probesFlag, "probes", "fs,proc", "Comma-separated probes to run (available: "+availableProbes()+")")
	flag.StringVar(&procFilter, "proc-filter", "", "Only report processes whose command line has this prefix (proc probe); ignored when an agent command or --root-pid is given, since ancestry scoping replaces it")
	flag.StringVar(&out, "out", "ground_truth.json", "Path to write the captured ground truth JSON on exit")
	flag.IntVar(&bufSize, "buf", 4096, "Per-probe event channel buffer size")
	flag.IntVar(&rootPID, "root-pid", 0, "Attach the proc probe's ancestry root to this already-running PID instead of launching the agent. RACE: anything that PID did before this call is invisible to the proc probe (the fs probe is unaffected). Mutually exclusive with a trailing -- <command>.")
	flag.StringVar(&netExePath, "net-exe-path", "", "Path to the TLS library (e.g. libssl.so.3) for SSL_write content capture (net probe, Tier 3 S5+). Empty = identity-only (SNI).")
	flag.StringVar(&netCachePath, "net-cache-path", "", "JSON cache file for pre-computed TLS offsets (net probe). Defaults to $TMPDIR/agent-trace-tlsoffset-cache.json.")
	flag.Usage = func() {
		out := flag.CommandLine.Output()
		_, _ = fmt.Fprintln(out, "Usage: watch --workspace PATH [flags] [-- <agent command> [args...]]")
		_, _ = fmt.Fprintln(out)
		_, _ = fmt.Fprintln(out, "With a trailing `-- <command>`, watch launches the command, records its PID as")
		_, _ = fmt.Fprintln(out, "the proc probe's ancestry root, runs it to completion, then writes the ground")
		_, _ = fmt.Fprintln(out, "truth. Without one, watch records until Ctrl+C.")
		_, _ = fmt.Fprintln(out)
		flag.PrintDefaults()
	}
	flag.Parse()

	opts := watchOptions{
		cfg:       watchConfig{Workspace: workspace, ProcFilter: procFilter, EventBufSize: bufSize, NetExePath: netExePath, NetCachePath: netCachePath},
		probes:    probesFlag,
		out:       out,
		rootPID:   rootPID,
		agentArgs: flag.Args(),
	}
	if err := runWatch(opts); err != nil {
		log.Fatal(err)
	}
}

// runWatch builds the requested probes, records ground truth according to the
// invocation mode implied by opts, and writes the result to opts.out. It is
// the whole of watch's behavior, split out from main so it can be tested.
func runWatch(opts watchOptions) error {
	if opts.cfg.Workspace == "" {
		return errors.New("--workspace is required")
	}
	if opts.rootPID != 0 && len(opts.agentArgs) > 0 {
		return errors.New("--root-pid and a trailing `-- <command>` are mutually exclusive")
	}
	if os.Getuid() != 0 {
		return errors.New("watch requires root (fanotify + eBPF); rerun with sudo")
	}

	// Ancestry scoping (exec-wrap or --root-pid) calls SetRootPID once the
	// root PID is known, some time after the proc probe is built. Flag that
	// now so the proc builder starts filtered from the outset instead of in
	// global mode for that window -- see watchConfig.AncestryPending.
	opts.cfg.AncestryPending = len(opts.agentArgs) > 0 || opts.rootPID != 0

	// Build probes. The proc and net observers are held separately from the
	// rest: their Start must be sequenced after the ancestry root PID is
	// known so we can call TrackPID / SetRootPID first.
	var others []probe.Observer
	reporters := make(map[string]probe.CoverageReporter)
	var procObs *proc.Observer
	var netObs *probenet.Observer
	for _, name := range strings.Split(opts.probes, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		build, ok := probeBuilders[name]
		if !ok {
			return fmt.Errorf("unknown probe %q (available: %s)", name, availableProbes())
		}
		obs, err := build(opts.cfg)
		if err != nil {
			return fmt.Errorf("start %s probe: %w", name, err)
		}
		// A probe that cannot report what it lost would be written into the
		// coverage record as clean. Refuse it up front.
		rep, ok := obs.(probe.CoverageReporter)
		if !ok {
			return fmt.Errorf("probe %q does not implement probe.CoverageReporter", name)
		}
		reporters[name] = rep
		if name == "proc" {
			p, ok := obs.(*proc.Observer)
			if !ok {
				return fmt.Errorf("proc builder returned %T, want *proc.Observer", obs)
			}
			procObs = p
			continue
		}
		if name == "net" {
			n, ok := obs.(*probenet.Observer)
			if !ok {
				return fmt.Errorf("net builder returned %T, want *probenet.Observer", obs)
			}
			netObs = n
			continue
		}
		others = append(others, obs)
	}
	if len(others) == 0 && procObs == nil && netObs == nil {
		return errors.New("no probes selected")
	}
	if opts.rootPID != 0 && procObs == nil {
		return errors.New("--root-pid requires the proc probe")
	}

	var (
		mu     sync.Mutex
		ground models.GroundTruth
		wg     sync.WaitGroup
	)
	collect := func(o probe.Observer) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for e := range o.Events() {
				fmt.Printf("%s  %-14s %s", e.Timestamp.Format("15:04:05.000"), e.ActionType, e.Target)
				if e.ExitCode != nil {
					fmt.Printf("  (exit %d)", *e.ExitCode)
				}
				fmt.Println()
				mu.Lock()
				ground = append(ground, e)
				mu.Unlock()
			}
		}()
	}

	// Every non-proc, non-net observer starts now. The proc observer's
	// readLoop starts only once its ancestry root PID is known, so the
	// root's own (already buffered) execve is reliably suppressed by PID --
	// matching the ordering in tests/e2e/tier2_test.go's runTier2Agent.
	// The net observer is also deferred: TrackPID must be called first so
	// its BPF tracked_pids map is populated before the agent starts sending
	// traffic, and Start blocks during TLS validation so it runs in a goroutine.
	for _, o := range others {
		collect(o)
		o.Start()
	}
	if procObs != nil {
		collect(procObs)
	}
	if netObs != nil {
		collect(netObs)
	}

	procStarted := false
	startProc := func() {
		if procObs != nil && !procStarted {
			procObs.Start()
			procStarted = true
		}
	}
	netStarted := false
	startNet := func(pid int32) {
		if netObs != nil && !netStarted {
			if pid > 0 {
				if err := netObs.TrackPID(pid); err != nil {
					log.Printf("net probe TrackPID(%d): %v", pid, err)
				}
			}
			go netObs.Start() // Start blocks during TLS validation; run async.
			netStarted = true
		}
	}
	stopEverything := func() {
		// Ensure the proc readLoop exists before Stop, or Stop blocks
		// forever waiting on a goroutine that was never launched.
		startProc()
		startNet(0) // no-op if already started; ensures goroutine+events exist
		for _, o := range others {
			if err := o.Stop(); err != nil {
				log.Printf("stop probe: %v", err)
			}
		}
		if netObs != nil {
			if err := netObs.Stop(); err != nil {
				log.Printf("stop net probe: %v", err)
			}
		}
		if procObs != nil {
			if err := procObs.Stop(); err != nil {
				log.Printf("stop proc probe: %v", err)
			}
		}
		wg.Wait()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	var agentErr error
	// groundRoot is the pid the verifier roots the process forest at: the
	// launched agent, or --root-pid. Zero when watch records host-wide with no
	// agent, which the verifier reads as "no tree".
	var groundRoot uint32
	switch {
	case len(opts.agentArgs) > 0:
		// Give the fs probe a moment to be fully reading before the agent runs.
		time.Sleep(200 * time.Millisecond)

		cmd := exec.Command(opts.agentArgs[0], opts.agentArgs[1:]...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		if err := cmd.Start(); err != nil {
			stopEverything()
			return fmt.Errorf("start agent %q: %w", opts.agentArgs[0], err)
		}
		groundRoot = uint32(cmd.Process.Pid)
		// SetRootPID after Start (PID must exist) but before the proc readLoop
		// starts, so the root's buffered execve is dropped by PID match.
		if procObs != nil {
			if err := procObs.SetRootPID(int32(cmd.Process.Pid)); err != nil {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				stopEverything()
				return fmt.Errorf("set proc probe root pid: %w", err)
			}
			startProc()
		}
		// Wire the agent's PID into the net probe so its connections are visible.
		startNet(int32(cmd.Process.Pid))
		fmt.Printf("watching %s (probes: %s) -- running %s\n",
			opts.cfg.Workspace, opts.probes, strings.Join(opts.agentArgs, " "))

		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case agentErr = <-done:
		case <-sigCh:
			fmt.Println("\ninterrupted -- stopping the agent early")
			_ = cmd.Process.Kill()
			<-done
		}
		// Let the kernel deliver, and the probes drain, the trailing events.
		time.Sleep(300 * time.Millisecond)

	case opts.rootPID > 0:
		groundRoot = uint32(opts.rootPID)
		if err := procObs.SetRootPID(int32(opts.rootPID)); err != nil {
			stopEverything()
			return fmt.Errorf("set proc probe root pid: %w", err)
		}
		startProc()
		startNet(int32(opts.rootPID))
		fmt.Printf("watching %s (probes: %s), proc ancestry root pid %d -- press Ctrl+C to stop and write %s\n",
			opts.cfg.Workspace, opts.probes, opts.rootPID, opts.out)
		<-sigCh

	default:
		startProc()
		startNet(0)
		fmt.Printf("watching %s (probes: %s) -- press Ctrl+C to stop and write %s\n",
			opts.cfg.Workspace, opts.probes, opts.out)
		<-sigCh
	}

	fmt.Println("\nstopping probes...")
	stopEverything()

	if netObs != nil {
		nc := netObs.Coverage()
		fmt.Printf("net probe coverage: connections=%d withHostname=%d withContent=%d unattributed=%d unsupported=%d\n",
			nc.Connections, nc.WithHostname, nc.WithContent, nc.FramesUnattributed, nc.ContentUnsupported)
		if err := netObs.TLSAttachError(); err != nil {
			log.Printf("net probe TLS attach warning: %v", err)
		}
	}

	cov := buildCoverage(reporters)
	names := make([]string, 0, len(cov.Probes))
	for name := range cov.Probes {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		p := cov.Probes[name]
		if !p.Ran {
			fmt.Printf("%s probe: not run\n", name)
			continue
		}
		fmt.Printf("%s probe loss: ringbufDrops=%d untrackedChildren=%d stateMapFull=%d channelDrops=%d faultedReads=%d queueOverflow=%v\n",
			name, p.RingbufDrops, p.UntrackedChildren, p.StateMapFull, p.ChannelDrops, p.FaultedReads, p.QueueOverflow)
	}
	if c := verification.Assess(&cov); !c.Complete {
		log.Printf("WARNING: %s is incomplete and a verdict built on it is unreliable:", opts.out)
		for _, r := range c.Reasons {
			log.Printf("  %s", r)
		}
	}

	sortGround(ground)

	if ground == nil {
		ground = models.GroundTruth{}
	}
	b, err := json.MarshalIndent(models.GroundTruthFile{Events: ground, Coverage: &cov, RootPID: groundRoot, Workspace: workspaceAbs(opts.cfg.Workspace)}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal ground truth: %w", err)
	}
	if err := os.WriteFile(opts.out, b, 0644); err != nil {
		return fmt.Errorf("write %s: %w", opts.out, err)
	}
	fmt.Printf("wrote %d events to %s\n", len(ground), opts.out)

	if agentErr != nil {
		return fmt.Errorf("agent exited with error: %w", agentErr)
	}
	return nil
}
