// Command watch is the ground-truth recorder half of the live verification
// harness (see the three-component architecture in
// docs/architecture/40_tools.md): it runs whichever probes are
// requested against a workspace, prints each ground-truth event as it is
// captured, and writes the accumulated ground truth to a JSON file that
// `verify` can compare against a trajectory.
//
// Invocation modes:
//
//   - watch --workspace PATH -- <agent command> [args...]
//     watch launches the agent itself, held before its exec until its PID
//     is registered with the probes (P-23), records that PID as the proc
//     probe's ancestry root (so the agent's own exec is suppressed and only
//     its descendants count as agent actions), runs it to completion, then
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
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/agent-trace/agent-trace/pkg/agent"
	_ "github.com/agent-trace/agent-trace/pkg/agent/claudecode"
	_ "github.com/agent-trace/agent-trace/pkg/agent/gemini"
	"github.com/agent-trace/agent-trace/pkg/agent/sensitive"
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
	// The fs probe marks every real filesystem and filters nothing by path:
	// an agent's file claims may name any path, so the agent's tree is
	// observed wherever it goes. What other processes did outside the
	// workspace is dropped by scopeFSEvents once the tree is known.
	"fs": func(cfg watchConfig) (probe.Observer, error) {
		return fs.New(fs.Config{
			Path:           cfg.Workspace,
			AllFilesystems: true,
			EventBufSize:   cfg.EventBufSize,
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

// responseLine is the net probe's response capture diagnostic (N-29): the
// capture's state, one of the models.Content* constants, and the
// correlator's response counters.
func responseLine(state string, nc probenet.Coverage) string {
	return fmt.Sprintf("net probe responses: state=%s responses=%d unpaired=%d unattributed=%d incomplete=%d truncated=%d unparsed=%d sseEvents=%d readsUnvalidated=%d readFaults=%d readDrops=%d",
		state, nc.Responses, nc.ResponsesUnpaired, nc.ResponsesUnattributed, nc.ResponsesIncomplete, nc.ResponsesTruncated, nc.ResponsesUnparsed, nc.SSEEvents, nc.ReadsUnvalidated, nc.ReadFaults, nc.ReadDrops)
}

// diagnosticsLine is a probe's occupancy and content counters on one line
// (P-34, N-33): each ring's size, high-water mark, records read and drops,
// each tracked set's capacity, peak and entries at the stop, and the net
// probe's content counters. Empty when the probe recorded none.
func diagnosticsLine(name string, d *models.ProbeDiagnostics) string {
	if d == nil {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s probe diagnostics:", name)
	for _, ring := range sortedKeys(d.Rings) {
		r := d.Rings[ring]
		fmt.Fprintf(&b, " ring %s size=%d peak=%d records=%d drops=%d", ring, r.SizeBytes, r.PeakBytes, r.Records, r.Drops)
		if r.ReadDrops != nil {
			fmt.Fprintf(&b, " readDrops=%d", *r.ReadDrops)
		}
		b.WriteString(";")
	}
	for _, set := range sortedKeys(d.TrackedSets) {
		t := d.TrackedSets[set]
		fmt.Fprintf(&b, " tracked %s capacity=%d peak=%d atStop=%d;", set, t.Capacity, t.Peak, t.AtStop)
	}
	if c := d.NetContent; c != nil {
		fmt.Fprintf(&b, " content connections=%d withHostname=%d withContent=%d contentUnsupported=%d h2Preface=%d h2PrefaceUnvalidated=%d framesH2=%d framesUnattributed=%d framesTruncated=%d dials=%d responses=%d;",
			c.Connections, c.WithHostname, c.WithContent, c.ContentUnsupported, c.H2Preface, c.H2PrefaceUnvalidated, c.FramesH2, c.FramesUnattributed, c.FramesTruncated, c.Dials, c.Responses)
	}
	return strings.TrimSuffix(b.String(), ";")
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
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

// passthrough hides the *os.File behind an io.Writer, so os/exec gives the
// child a pipe and copies from it, instead of handing the child the file
// descriptor itself.
type passthrough struct{ io.Writer }

// underDir reports whether path is dir or inside it. A plain prefix test
// would let /ws admit /ws2.
func underDir(path, dir string) bool {
	return path == dir || strings.HasPrefix(path, strings.TrimSuffix(dir, "/")+"/")
}

// scopeFSEvents applies the tree-or-workspace rule once the capture is
// complete and every fork record is known: a file event is kept when the
// agent's tree caused it, wherever the path is, or when the path is under
// the workspace, whoever caused it. Every other file event is counted and
// dropped. Non-file events are kept as they are. The rule is applied here
// and not in the probe because the probe reads an event some time after the
// access, when a short-lived child has often already left any live tracked
// set; the forest built from the fork records has no such race.
//
// A file event with no path is dropped too (dropUnresolvedFSEvents), and
// unresolvedInTree counts those the forest places in the agent's tree, one
// per event as FSScope.Unresolved counts them: the agent's own events the
// capture lost (V-39). An event with no pid (caused by the kernel) is not
// the tree's.
func scopeFSEvents(g models.GroundTruth, root uint32, workspace string) (kept models.GroundTruth, dropped, unresolvedInTree int) {
	g = dropSelfFSEvents(g, uint32(os.Getpid()))
	forest := verification.BuildForest(g, root)
	kept = make(models.GroundTruth, 0, len(g))
	for _, e := range g {
		if verification.LaneOf(e.ActionType) != verification.LaneFS {
			kept = append(kept, e)
			continue
		}
		zone := forest.Attribute(e).Zone
		inTree := zone == verification.ZoneAgent || zone == verification.ZoneSubtree
		if e.Target == "" {
			if inTree {
				unresolvedInTree++
			}
			continue
		}
		if inTree || underDir(e.Target, workspace) {
			kept = append(kept, e)
			continue
		}
		dropped++
	}
	return kept, dropped, unresolvedInTree
}

// dropUnresolvedFSEvents removes the file events whose path the probe could
// not resolve (an empty target) and counts them by action type. A delete
// inside a tree being removed is the usual case: the parent directory's
// handle is stale by the time the event is read. The verifier cannot align
// or attribute an event with no path, and the file format rejects one, so
// the count goes into the scope record instead.
func dropUnresolvedFSEvents(g models.GroundTruth) (models.GroundTruth, map[string]int) {
	out := make(models.GroundTruth, 0, len(g))
	var unresolved map[string]int
	for _, e := range g {
		if e.Target == "" && verification.LaneOf(e.ActionType) == verification.LaneFS {
			if unresolved == nil {
				unresolved = map[string]int{}
			}
			unresolved[string(e.ActionType)]++
			continue
		}
		out = append(out, e)
	}
	return out, unresolved
}

// dropSelfFSEvents removes the file events the recorder itself caused: the
// startup hash walk, the hash reads the probe did not already strip, and the
// writes of its own log. They are not counted as dropped, since nothing of
// the agent's is in them.
func dropSelfFSEvents(g models.GroundTruth, self uint32) models.GroundTruth {
	out := make(models.GroundTruth, 0, len(g))
	for _, e := range g {
		if e.PID == self && verification.LaneOf(e.ActionType) == verification.LaneFS {
			continue
		}
		out = append(out, e)
	}
	return out
}

// holdScript runs in the launched process before the agent. It blocks on
// descriptor 3 until watch writes a line, closes the descriptor, and execs
// the agent in place, so the agent keeps the pid watch registered with the
// probes and is tracked from its first instruction (P-23). End of file
// without a line means watch gave up, and the agent never runs.
const holdScript = `read -r _ <&3 || exit 1; exec 3<&-; exec "$@"`

// heldAgent is an agent process started by startHeld and not yet released.
type heldAgent struct {
	cmd  *exec.Cmd
	gate *os.File // write end of the pipe the hold script reads
}

// startHeld starts args under holdScript. The command is resolved here, so a
// missing program is an error from watch, as with exec.Command, and not an
// exit status of the shell. The process exists when startHeld returns, but
// runs nothing of the agent's until release.
func startHeld(args []string, stdin io.Reader, stdout, stderr io.Writer) (*heldAgent, error) {
	path, err := exec.LookPath(args[0])
	if err != nil {
		return nil, err
	}
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command("/bin/sh", append([]string{"-c", holdScript, "agent-trace-hold", path}, args[1:]...)...)
	cmd.ExtraFiles = []*os.File{r}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	err = cmd.Start()
	_ = r.Close()
	if err != nil {
		_ = w.Close()
		return nil, err
	}
	return &heldAgent{cmd: cmd, gate: w}, nil
}

// pid is the pid the agent will run under.
func (h *heldAgent) pid() int { return h.cmd.Process.Pid }

// release lets the held process exec the agent.
func (h *heldAgent) release() error {
	_, err := h.gate.Write([]byte("\n"))
	if cerr := h.gate.Close(); err == nil {
		err = cerr
	}
	return err
}

// abort ends a held process that was never released; the agent never runs.
func (h *heldAgent) abort() {
	_ = h.gate.Close()
	_ = h.cmd.Process.Kill()
	_ = h.cmd.Wait()
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
	// sensitive are the harness's security-sensitive files, as the adapters
	// declare them, snapshotted at start and stop (V-40). Empty takes no
	// snapshot.
	sensitive []string
	// agentHome is the home a declared "~/" resolves against. Empty means
	// the home of the user sudo was run by, else the recorder's own.
	agentHome string
}

func main() {
	var workspace, probesFlag, procFilter, out string
	var bufSize, rootPID int
	var netExePath, netCachePath string
	var agentName, agentHome string

	flag.StringVar(&workspace, "workspace", "", "Path to the workspace to watch (fs probe)")
	flag.StringVar(&probesFlag, "probes", "fs,proc", "Comma-separated probes to run (available: "+availableProbes()+")")
	flag.StringVar(&procFilter, "proc-filter", "", "Only report processes whose command line has this prefix (proc probe); ignored when an agent command or --root-pid is given, since ancestry scoping replaces it")
	flag.StringVar(&out, "out", "ground_truth.json", "Path to write the captured ground truth JSON on exit")
	flag.IntVar(&bufSize, "buf", 4096, "Per-probe event channel buffer size")
	flag.IntVar(&rootPID, "root-pid", 0, "Attach the proc probe's ancestry root to this already-running PID instead of launching the agent. RACE: anything that PID did before this call is invisible to the proc probe (the fs probe is unaffected). Mutually exclusive with a trailing -- <command>.")
	flag.StringVar(&netExePath, "net-exe-path", "", "Path to the TLS library (e.g. libssl.so.3) for SSL_write content capture (net probe, Tier 3 S5+). Empty = identity-only (SNI).")
	flag.StringVar(&netCachePath, "net-cache-path", "", "JSON cache file for pre-computed TLS offsets (net probe). Defaults to $TMPDIR/agent-trace-tlsoffset-cache.json.")
	flag.StringVar(&agentName, "agent", "", "Adapter whose security-sensitive harness files are snapshotted at start and stop ("+strings.Join(agent.Names(), ", ")+"). Default: the files of every adapter")
	flag.StringVar(&agentHome, "agent-home", "", "Home directory of the user the agent runs as, which a declared ~/ file resolves against. Default: the home of the user who ran sudo ($SUDO_UID), else root's")
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

	files, err := declaredSensitive(agentName)
	if err != nil {
		log.Fatal(err)
	}
	opts := watchOptions{
		cfg:       watchConfig{Workspace: workspace, ProcFilter: procFilter, EventBufSize: bufSize, NetExePath: netExePath, NetCachePath: netCachePath},
		probes:    probesFlag,
		out:       out,
		rootPID:   rootPID,
		agentArgs: flag.Args(),
		sensitive: files,
		agentHome: agentHome,
	}
	if err := runWatch(opts); err != nil {
		log.Fatal(err)
	}
}

// declaredSensitive is the security-sensitive files of the named adapter, or
// of every registered adapter when name is empty, so a capture made without
// naming the agent still holds its harness's files (V-40, I-59).
func declaredSensitive(name string) ([]string, error) {
	names := agent.Names()
	if name != "" {
		if _, ok := agent.Lookup(name); !ok {
			return nil, fmt.Errorf("unknown agent %q (registered: %s)", name, strings.Join(names, ", "))
		}
		names = []string{name}
	}
	var files []string
	seen := map[string]bool{}
	for _, n := range names {
		a, _ := agent.Lookup(n)
		for _, f := range agent.SensitiveFiles(a) {
			if !seen[f] {
				seen[f] = true
				files = append(files, f)
			}
		}
	}
	return files, nil
}

// resolveAgentHome is the home a declared "~/" resolves against and the uid
// that owns it, which every snapshotted file must belong to. watch runs as
// root under sudo, so without a flag the home is that of the user sudo was
// run by: the agent is run as that user (scripts/capture-claude-code.sh
// does so with setpriv), not as root.
func resolveAgentHome(flagHome string) (string, int, error) {
	home := flagHome
	if home == "" {
		if uid := os.Getenv("SUDO_UID"); uid != "" {
			u, err := user.LookupId(uid)
			if err != nil {
				return "", 0, fmt.Errorf("look up the home of SUDO_UID %s: %w", uid, err)
			}
			home = u.HomeDir
		} else {
			h, err := os.UserHomeDir()
			if err != nil {
				return "", 0, err
			}
			home = h
		}
	}
	home, err := filepath.Abs(home)
	if err != nil {
		return "", 0, err
	}
	fi, err := os.Stat(home)
	if err != nil {
		return "", 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || !fi.IsDir() {
		return "", 0, fmt.Errorf("%s is not a directory", home)
	}
	return home, int(st.Uid), nil
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
	var fsObs *fs.Observer
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
		if name == "fs" {
			if f, ok := obs.(*fs.Observer); ok {
				fsObs = f
			}
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
	self := uint32(os.Getpid())
	collect := func(o probe.Observer) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for e := range o.Events() {
				// The recorder's own file activity is never the agent's: the
				// startup walk, the hash reads, and this very log line, which
				// on a marked filesystem would otherwise produce the event it
				// prints, without end.
				if e.PID == self && verification.LaneOf(e.ActionType) == verification.LaneFS {
					continue
				}
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

	// The harness's sensitive files are read before the agent runs and again
	// once the probes have stopped (V-40). Reading them is the recorder's own
	// file activity, which the fs scope drops.
	workspace := workspaceAbs(opts.cfg.Workspace)
	var snap *sensitive.Snapshot
	if len(opts.sensitive) > 0 {
		home, owner, err := resolveAgentHome(opts.agentHome)
		if err == nil {
			snap, err = sensitive.Start(opts.sensitive, home, workspace, owner)
		}
		if err != nil {
			log.Printf("sensitive files: no snapshot taken: %v", err)
		}
	}

	var agentErr error
	// groundRoot is the pid the verifier roots the process forest at: the
	// launched agent, or --root-pid. Zero when watch records host-wide with no
	// agent, which the verifier reads as "no tree".
	var groundRoot uint32
	switch {
	case len(opts.agentArgs) > 0:
		// Give the fs probe a moment to be fully reading before the agent runs.
		time.Sleep(200 * time.Millisecond)

		// The agent's output passes through watch on a pipe rather than
		// inheriting the descriptors: when stdout is a file on a marked
		// filesystem, every line the agent prints would otherwise be a file
		// write by the agent, with no claim to explain it.
		held, err := startHeld(opts.agentArgs, os.Stdin, passthrough{os.Stdout}, passthrough{os.Stderr})
		if err != nil {
			stopEverything()
			return fmt.Errorf("start agent %q: %w", opts.agentArgs[0], err)
		}
		pid := held.pid()
		groundRoot = uint32(pid)
		// The process is held before the agent's exec, so registering its pid
		// now covers everything the agent does (P-23). SetRootPID also comes
		// before the proc readLoop starts, so the root's own exec is dropped
		// by pid match.
		if procObs != nil {
			if err := procObs.SetRootPID(int32(pid)); err != nil {
				held.abort()
				stopEverything()
				return fmt.Errorf("set proc probe root pid: %w", err)
			}
			startProc()
		}
		// Wire the agent's PID into the net probe so its connections are visible.
		startNet(int32(pid))
		cmd := held.cmd
		if err := held.release(); err != nil {
			held.abort()
			stopEverything()
			return fmt.Errorf("release agent %q: %w", opts.agentArgs[0], err)
		}
		fmt.Printf("watching %s (probes: %s) -- running %s\n",
			opts.cfg.Workspace, opts.probes, strings.Join(opts.agentArgs, " "))

		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case agentErr = <-done:
		case <-sigCh:
			fmt.Println("\ninterrupted -- stopping the agent early")
			_ = cmd.Process.Kill()
			if err := <-done; err != nil {
				fmt.Printf("agent stopped: %v\n", err)
			}
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

	var sensitiveRec *models.SensitiveSnapshot
	if snap != nil {
		rec := snap.Stop()
		sensitiveRec = &rec
		files, changes := sensitive.Changed(rec)
		fmt.Printf("sensitive files: %d snapshotted under %s at start and stop; %d changed (%d change(s) by key path)\n", len(rec.Files), rec.Home, files, changes)
	}

	if netObs != nil {
		nc := netObs.Coverage()
		fmt.Printf("net probe coverage: connections=%d withHostname=%d withContent=%d unattributed=%d unsupported=%d dns=%d addressProbes=%d openAtStop=%d replaced=%d dials=%d\n",
			nc.Connections, nc.WithHostname, nc.WithContent, nc.FramesUnattributed, nc.ContentUnsupported, nc.DNS, nc.AddressProbes, nc.OpenAtStop, nc.Replaced, nc.Dials)
		if err := netObs.TLSAttachError(); err != nil {
			log.Printf("net probe TLS attach warning: %v", err)
		}
		fmt.Println(responseLine(netObs.CaptureCoverage().Responses, nc))
		if err := netObs.ResponseAttachError(); err != nil {
			log.Printf("net probe response capture warning: %v", err)
		}
	}

	cov := buildCoverage(reporters)

	// The scope rule runs before the coverage is printed and judged, since
	// it is what counts the agent tree's unresolved file events (V-39).
	var scope *models.FSScope
	if fsObs != nil {
		marked, unmarked := fsObs.Scope()
		scope = &models.FSScope{Rule: models.FSScopeUnfiltered, Mounts: marked, Unmarked: unmarked}
		scope.Filesystems, scope.MountTableChanged = fsObs.MountTable()
		ground = dropSelfFSEvents(ground, self)
		var resolved models.GroundTruth
		resolved, scope.Unresolved = dropUnresolvedFSEvents(ground)
		if groundRoot != 0 {
			var dropped, inTree int
			ground, dropped, inTree = scopeFSEvents(ground, groundRoot, workspace)
			scope.Rule, scope.DroppedOutside = models.FSScopeTreeOrWorkspace, dropped
			fsCov := cov.Probes["fs"]
			fsCov.UnresolvedInTree = uint64(inTree)
			cov.Probes["fs"] = fsCov
			fmt.Printf("fs scope: %d filesystem(s) marked, %d unmarked; kept the agent tree's file events anywhere and %s for everyone else; dropped %d event(s) by other processes elsewhere\n",
				len(marked), len(unmarked), workspace, dropped)
			if inTree > 0 {
				log.Printf("fs probe: %d of the unresolved file event(s) were caused by the agent's tree: event loss (V-39)", inTree)
			}
		} else {
			ground = resolved
		}
		for typ, n := range scope.Unresolved {
			log.Printf("fs probe: %d %s event(s) had no resolvable path and are counted, not recorded", n, typ)
		}
		for point, why := range unmarked {
			log.Printf("fs probe could not mark %s: %s", point, why)
		}
	}

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
		fmt.Printf("%s probe loss: ringbufDrops=%d untrackedChildren=%d stateMapFull=%d channelDrops=%d faultedReads=%d queueOverflow=%v hashlessCloses=%d ioUringNetOps=%d undrainedRecords=%d unresolvedPaths=%d unresolvedInTree=%d responseGaps=%d\n",
			name, p.RingbufDrops, p.UntrackedChildren, p.StateMapFull, p.ChannelDrops, p.FaultedReads, p.QueueOverflow, p.HashlessCloses, p.IOURingNetOps, p.UndrainedRecords, p.UnresolvedPaths, p.UnresolvedInTree, p.ResponseGaps)
		if line := diagnosticsLine(name, p.Diagnostics); line != "" {
			fmt.Println(line)
		}
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
	b, err := json.MarshalIndent(models.GroundTruthFile{Events: ground, Coverage: &cov, RootPID: groundRoot, Workspace: workspace, FSScope: scope, Sensitive: sensitiveRec}, "", "  ")
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
