package proc

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func skipUnprivileged(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("requires root or CAP_BPF+CAP_PERFMON")
	}
}

// collect drains the observer's event channel until it is closed.
func collect(obs *Observer) []models.GroundTruthEvent {
	var got []models.GroundTruthEvent
	for e := range obs.Events() {
		got = append(got, e)
	}
	return got
}

func TestObserver_CapturesExecAndExit(t *testing.T) {
	skipUnprivileged(t)

	nonce := fmt.Sprintf("agenttrace-%d", time.Now().UnixNano())

	obs, err := New(Config{
		CommandFilter: "/bin/echo",
		EventBufSize:  256,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	obs.Start()

	// Give the tracepoints a moment to attach before generating events.
	time.Sleep(150 * time.Millisecond)

	if err := exec.Command("/bin/echo", nonce).Run(); err != nil {
		t.Fatalf("spawn echo: %v", err)
	}

	time.Sleep(300 * time.Millisecond)
	if err := obs.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	got := collect(obs)

	var sawExec, sawExit bool
	for _, e := range got {
		if !strings.Contains(e.Target, nonce) {
			continue
		}
		if e.Target != "/bin/echo "+nonce {
			t.Errorf("unexpected target %q, want %q", e.Target, "/bin/echo "+nonce)
		}
		switch e.ActionType {
		case models.ProcessExec:
			sawExec = true
		case models.ProcessExit:
			sawExit = true
		default:
			t.Errorf("unexpected action type %q", e.ActionType)
		}
		if e.Timestamp.IsZero() {
			t.Error("event has zero timestamp")
		}
	}

	if !sawExec {
		t.Errorf("no process_exec event for %q; got %d events: %v", nonce, len(got), got)
	}
	if !sawExit {
		t.Errorf("no process_exit event for %q; got %d events: %v", nonce, len(got), got)
	}
}

func TestObserver_ExitCodeAndTimestamps(t *testing.T) {
	skipUnprivileged(t)

	nonce := fmt.Sprintf("agenttrace-exit-%d", time.Now().UnixNano())

	obs, err := New(Config{
		CommandFilter: "/bin/sh",
		EventBufSize:  256,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	obs.Start()
	time.Sleep(150 * time.Millisecond)

	before := time.Now()
	// Deliberately nonzero, to confirm the probe reports the code the
	// process actually returned rather than defaulting to 0.
	_ = exec.Command("/bin/sh", "-c", fmt.Sprintf("echo %s; exit 7", nonce)).Run()
	after := time.Now()

	time.Sleep(300 * time.Millisecond)
	if err := obs.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	got := collect(obs)

	var execEvent, exitEvent *models.GroundTruthEvent
	for i := range got {
		if !strings.Contains(got[i].Target, nonce) {
			continue
		}
		switch got[i].ActionType {
		case models.ProcessExec:
			execEvent = &got[i]
		case models.ProcessExit:
			exitEvent = &got[i]
		}
	}
	if execEvent == nil || exitEvent == nil {
		t.Fatalf("missing exec (%v) or exit (%v) event for %q; got %d events: %v",
			execEvent != nil, exitEvent != nil, nonce, len(got), got)
	}

	if exitEvent.ExitCode == nil {
		t.Fatal("exit event has nil ExitCode")
	}
	if *exitEvent.ExitCode != 7 {
		t.Errorf("ExitCode = %d, want 7", *exitEvent.ExitCode)
	}
	if execEvent.ExitCode != nil {
		t.Errorf("exec event has non-nil ExitCode %d, want nil", *execEvent.ExitCode)
	}

	// The kernel timestamps (bpf_ktime_get_ns + userspace boot offset)
	// should land inside a generous window around the actual wall-clock
	// window in which the command ran, and exec must not be reported after
	// exit.
	window := 2 * time.Second
	lo, hi := before.Add(-window), after.Add(window)
	if execEvent.Timestamp.Before(lo) || execEvent.Timestamp.After(hi) {
		t.Errorf("exec timestamp %v outside expected window [%v, %v]", execEvent.Timestamp, lo, hi)
	}
	if exitEvent.Timestamp.Before(lo) || exitEvent.Timestamp.After(hi) {
		t.Errorf("exit timestamp %v outside expected window [%v, %v]", exitEvent.Timestamp, lo, hi)
	}
	if exitEvent.Timestamp.Before(execEvent.Timestamp) {
		t.Errorf("exit timestamp %v before exec timestamp %v", exitEvent.Timestamp, execEvent.Timestamp)
	}
}

// TestObserver_ResistsArgv0Spoofing is the live-kernel counterpart to
// TestCommandLine_UsesResolvedFilenameNotArgv0: it doesn't just check the
// parsing helper in isolation, it spawns a real process that performs the
// actual masquerading primitive (execve() with an argv[0] unrelated to the
// binary being loaded) and confirms the probe's reported ground truth is
// built from the kernel-resolved path, not the caller-supplied argv[0]. This
// also confirms CommandFilter itself can't be evaded by argv[0] spoofing,
// since it prefix-matches the same target string.
func TestObserver_ResistsArgv0Spoofing(t *testing.T) {
	skipUnprivileged(t)

	nonce := fmt.Sprintf("agenttrace-spoof-%d", time.Now().UnixNano())

	obs, err := New(Config{
		CommandFilter: "/bin/true",
		EventBufSize:  256,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	obs.Start()
	time.Sleep(150 * time.Millisecond)

	// Bypass exec.Command's LookPath convenience: set Path to the real
	// binary directly but Args[0] to an unrelated, misleading name. This is
	// exactly execve(real_path, {"fake_name", ...}, envp), the process
	// masquerading primitive malware uses to disguise itself in ps/argv-based
	// tooling.
	//
	// Deliberately /bin/true, not /bin/echo: on distros shipping uutils'
	// Rust coreutils (this dev environment included), the coreutils
	// binaries are a multicall dispatcher that itself checks argv[0]
	// against the executable name and refuses to run on a mismatch
	// ("Security violation: Requested utility ... does not match executable
	// name"), which would make this test fail before the kernel probe is
	// even exercised, for a reason unrelated to what's being tested. /bin/true
	// here resolves to GNU coreutils' standalone `gnutrue` binary, which,
	// like a typical statically-single-purpose binary, does not interpret
	// argv[0] at all. Picking a test binary that itself dispatches on
	// argv[0] would silently defeat the point of this test on such systems.
	cmd := &exec.Cmd{
		Path: "/bin/true",
		Args: []string{"totally-not-true", nonce},
	}
	if err := cmd.Run(); err != nil {
		t.Fatalf("spawn spoofed-argv0 true: %v", err)
	}

	time.Sleep(300 * time.Millisecond)
	if err := obs.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	got := collect(obs)

	var found bool
	for _, e := range got {
		if !strings.Contains(e.Target, nonce) {
			continue
		}
		found = true
		if strings.HasPrefix(e.Target, "totally-not-true") {
			t.Errorf("ground truth trusted the spoofed argv[0]: target=%q", e.Target)
		}
		if !strings.HasPrefix(e.Target, "/bin/true") {
			t.Errorf("expected target built from the resolved execve path /bin/true, got %q", e.Target)
		}
	}
	if !found {
		t.Fatalf("no event observed for the spoofed-argv0 process; got %d events: %v", len(got), got)
	}
}

// TestObserver_ShellChainStaysTopLevel is the live-kernel proof for Fix 3b:
// a chain of pure shell re-execs must keep its payload verification-grade,
// not demote it to forensic-only at a depth-1 cutoff. The test process is
// the ancestry root. The outer shell forks (`& wait`) an inner shell, so
// the final `/bin/echo` is a genuine grandchild reached across a fork
// through a shell -- exactly what a depth-1 rule would demote. Under 3b it
// must still be IsTopLevel.
func TestObserver_ShellChainStaysTopLevel(t *testing.T) {
	skipUnprivileged(t)

	nonce := fmt.Sprintf("agenttrace-shellchain-%d", time.Now().UnixNano())

	obs, err := New(Config{EventBufSize: 512, DeferRootPID: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// The test process is the ancestry root: its own exec is suppressed by
	// PID, and the descendants spawned below are what we assert on.
	if err := obs.SetRootPID(int32(os.Getpid())); err != nil {
		t.Fatalf("SetRootPID: %v", err)
	}
	obs.Start()
	time.Sleep(150 * time.Millisecond)

	script := "/bin/sh -c '/bin/echo " + nonce + " chain' & wait"
	if err := exec.Command("/bin/sh", "-c", script).Run(); err != nil {
		t.Fatalf("spawn nested shell chain: %v", err)
	}

	time.Sleep(300 * time.Millisecond)
	if err := obs.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	got := collect(obs)
	var sawEcho bool
	for _, e := range got {
		if e.ActionType != models.ProcessExec || !strings.HasPrefix(e.Target, "/bin/echo ") {
			continue
		}
		if !strings.Contains(e.Target, nonce) {
			continue
		}
		sawEcho = true
		if e.IsTopLevel == nil || !*e.IsTopLevel {
			t.Errorf("nested-shell echo should be top-level, got IsTopLevel=%v (target %q)",
				e.IsTopLevel, e.Target)
		}
	}
	if !sawEcho {
		t.Fatalf("no /bin/echo exec event for the nested-shell chain; got %d events: %v", len(got), got)
	}
}

// TestObserver_NonShellIntermediateDemotesChildren is the contrast to
// TestObserver_ShellChainStaysTopLevel: once the chain hits a real
// (non-shell) binary, that binary is still top-level itself but its own
// children go back to forensic-only. Here `xargs` (spawned by a shell) is
// the non-shell intermediate and the `/bin/echo <nonce>` it forks must be
// IsTopLevel=false. This is the make->cc false-positive fix, preserved.
func TestObserver_NonShellIntermediateDemotesChildren(t *testing.T) {
	skipUnprivileged(t)

	nonce := fmt.Sprintf("agenttrace-nonshell-%d", time.Now().UnixNano())

	obs, err := New(Config{EventBufSize: 512, DeferRootPID: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := obs.SetRootPID(int32(os.Getpid())); err != nil {
		t.Fatalf("SetRootPID: %v", err)
	}
	obs.Start()
	time.Sleep(150 * time.Millisecond)

	// The nonce appears in three argv strings: the root `sh -c <script>`,
	// the `xargs /bin/echo <nonce> leaf` xargs itself execs, and the
	// `/bin/echo <nonce> leaf` that xargs forks. They are told apart by
	// command token: the leaf is the one whose resolved path is /bin/echo.
	script := "echo | /usr/bin/xargs /bin/echo " + nonce + " leaf"
	if err := exec.Command("/bin/sh", "-c", script).Run(); err != nil {
		t.Fatalf("spawn shell -> xargs -> echo: %v", err)
	}

	time.Sleep(300 * time.Millisecond)
	if err := obs.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	got := collect(obs)
	var sawLeaf, sawXargs bool
	for _, e := range got {
		if e.ActionType != models.ProcessExec || !strings.Contains(e.Target, nonce) {
			continue
		}
		switch {
		case strings.HasPrefix(e.Target, "/usr/bin/xargs "):
			sawXargs = true
			if e.IsTopLevel == nil || !*e.IsTopLevel {
				t.Errorf("xargs (direct child of the shell) should be top-level, got %v", e.IsTopLevel)
			}
		case strings.HasPrefix(e.Target, "/bin/echo "):
			sawLeaf = true
			if e.IsTopLevel != nil && *e.IsTopLevel {
				t.Errorf("echo forked by xargs should be forensic-only, got IsTopLevel=true (target %q)", e.Target)
			}
		}
	}
	if !sawXargs {
		t.Fatalf("no exec event for xargs; got %d events: %v", len(got), got)
	}
	if !sawLeaf {
		t.Fatalf("no /bin/echo exec event forked by xargs; got %d events: %v", len(got), got)
	}
}

func TestObserver_CommandFilterExcludesOthers(t *testing.T) {
	skipUnprivileged(t)

	obs, err := New(Config{
		CommandFilter: "/nonexistent/path/prefix",
		EventBufSize:  256,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	obs.Start()
	time.Sleep(150 * time.Millisecond)

	_ = exec.Command("/bin/true").Run()
	_ = exec.Command("/bin/ls", "/").Run()

	time.Sleep(300 * time.Millisecond)
	_ = obs.Stop()

	if got := collect(obs); len(got) != 0 {
		t.Errorf("expected no events past the filter, got %d: %v", len(got), got)
	}
}

func TestObserver_StopIsIdempotent(t *testing.T) {
	skipUnprivileged(t)

	obs, err := New(Config{EventBufSize: 16})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	obs.Start()

	if err := obs.Stop(); err != nil {
		t.Fatalf("first Stop: %v", err)
	}
	if err := obs.Stop(); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
}

// TestObserver_CountsRingbufDrops forces the kernel ring buffer to overflow
// and checks the drop counter sees it. The ring is shrunk to one page and each
// exec carries ~6 KB of argv, so the event record can never fit: every exec
// and its paired exit record is discarded in-kernel, deterministically,
// regardless of how fast userspace drains the buffer.
func TestObserver_CountsRingbufDrops(t *testing.T) {
	skipUnprivileged(t)

	const bigExecs = 3
	nonce := fmt.Sprintf("agenttrace-drop-%d", time.Now().UnixNano())

	obs, err := New(Config{
		CommandFilter: "/bin/true",
		EventBufSize:  256,
		RingbufBytes:  4096,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	obs.Start()
	time.Sleep(150 * time.Millisecond)

	bigArg := nonce + strings.Repeat("x", 6000)
	for i := 0; i < bigExecs; i++ {
		if err := exec.Command("/bin/true", bigArg).Run(); err != nil {
			t.Fatalf("spawn true: %v", err)
		}
	}
	time.Sleep(300 * time.Millisecond)

	live := obs.RingbufDrops()
	if err := obs.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	after := obs.RingbufDrops()

	// Each oversized exec drops its exec record and its exit record.
	if live < bigExecs {
		t.Errorf("RingbufDrops while running = %d, want >= %d", live, bigExecs)
	}
	if after < live {
		t.Errorf("RingbufDrops after Stop = %d, less than the %d read while running: the Stop snapshot was lost", after, live)
	}

	for _, e := range collect(obs) {
		if strings.Contains(e.Target, nonce) {
			t.Errorf("event for an oversized exec reached userspace: %q", e.Target)
		}
	}
}

// trackedKeys lists the keys currently in the kernel tracked_pids map.
func trackedKeys(t *testing.T, obs *Observer) map[uint32]bool {
	t.Helper()
	keys := map[uint32]bool{}
	var k uint32
	var v bpfProcInfo
	it := obs.objs.TrackedPids.Iterate()
	for it.Next(&k, &v) {
		keys[k] = true
	}
	if err := it.Err(); err != nil {
		t.Fatalf("iterate tracked_pids: %v", err)
	}
	return keys
}

// TestObserver_CountsUntrackedChildren overflows a tiny tracked_pids map with
// concurrently live children and checks the kernel counter sees it, both while
// running and after Stop (the snapshot must survive the map closing). A
// descendant that cannot be tracked is invisible, which downstream reads as
// the agent never acting, so the loss has to be countable.
func TestObserver_CountsUntrackedChildren(t *testing.T) {
	skipUnprivileged(t)

	const capacity, children = 4, 24
	obs, err := New(Config{EventBufSize: 512, DeferRootPID: true, TrackedPIDsMax: capacity})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := obs.SetRootPID(int32(os.Getpid())); err != nil {
		t.Fatalf("SetRootPID: %v", err)
	}
	obs.Start()
	time.Sleep(150 * time.Millisecond)

	// All children stay alive together, so their entries cannot be reclaimed
	// by exits and the map must fill.
	var procs []*exec.Cmd
	for i := 0; i < children; i++ {
		c := exec.Command("/bin/sleep", "2")
		if err := c.Start(); err != nil {
			t.Fatalf("spawn sleep: %v", err)
		}
		procs = append(procs, c)
	}
	t.Cleanup(func() {
		for _, c := range procs {
			_ = c.Process.Kill()
			_ = c.Wait()
		}
	})
	time.Sleep(300 * time.Millisecond)

	live := obs.UntrackedChildren()
	if live < children-capacity {
		t.Errorf("UntrackedChildren while running = %d, want >= %d (capacity %d, %d live children)",
			live, children-capacity, capacity, children)
	}
	if n := len(trackedKeys(t, obs)); n > capacity {
		t.Errorf("tracked_pids holds %d entries, capacity %d", n, capacity)
	}
	if err := obs.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if after := obs.UntrackedChildren(); after < live {
		t.Errorf("UntrackedChildren after Stop = %d, less than the %d read while running: the Stop snapshot was lost", after, live)
	}
	cov := obs.CaptureCoverage()
	if cov.UntrackedChildren == 0 {
		t.Error("CaptureCoverage().UntrackedChildren = 0, want the overflow reported")
	}
	// The root and the children that fit fill the map: its peak is its
	// capacity (P-34).
	if got := cov.Diagnostics.TrackedSets["proc"]; got.Peak != capacity || got.Capacity != capacity {
		t.Errorf("tracked set = %+v, want a peak at the capacity %d", got, capacity)
	}
	for range obs.Events() {
	}
}

// TestObserver_NoUntrackedChildrenWhenMapFits is the control: the same shape
// of workload against the default capacity must report zero, so a non-zero
// count means a real overflow and not a counter that always fires.
func TestObserver_NoUntrackedChildrenWhenMapFits(t *testing.T) {
	skipUnprivileged(t)

	obs, err := New(Config{EventBufSize: 512, DeferRootPID: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := obs.SetRootPID(int32(os.Getpid())); err != nil {
		t.Fatalf("SetRootPID: %v", err)
	}
	obs.Start()
	time.Sleep(150 * time.Millisecond)
	for i := 0; i < 24; i++ {
		if err := exec.Command("/bin/true").Run(); err != nil {
			t.Fatalf("spawn true: %v", err)
		}
	}
	time.Sleep(300 * time.Millisecond)
	if err := obs.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if got := obs.UntrackedChildren(); got != 0 {
		t.Errorf("UntrackedChildren = %d, want 0 with the default map capacity", got)
	}
	for range obs.Events() {
	}
}

// TestObserver_ThreadsAreNotTracked pins the CLONE_THREAD fix. A thread shares
// its process's tgid, which is already tracked, and its tid is never removed by
// the exit handler (it only deletes on tid == tgid). Tracking tids would leak
// one entry per thread and, once a tid number is reused as an unrelated
// process's pid, track a stranger. With a map of 8 slots and 64 live threads,
// the unfixed code overflows and reports untracked children.
func TestObserver_ThreadsAreNotTracked(t *testing.T) {
	skipUnprivileged(t)

	obs, err := New(Config{EventBufSize: 512, DeferRootPID: true, TrackedPIDsMax: 8})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := obs.SetRootPID(int32(os.Getpid())); err != nil {
		t.Fatalf("SetRootPID: %v", err)
	}
	obs.Start()
	time.Sleep(150 * time.Millisecond)

	// Each goroutine pins an OS thread and blocks, forcing one clone per
	// goroutine that stays alive until release is closed.
	release := make(chan struct{})
	started := make(chan struct{}, 64)
	for i := 0; i < 64; i++ {
		go func() {
			runtime.LockOSThread()
			started <- struct{}{}
			<-release
		}()
	}
	for i := 0; i < 64; i++ {
		<-started
	}
	time.Sleep(200 * time.Millisecond)

	tasks, err := os.ReadDir("/proc/self/task")
	if err != nil {
		t.Fatalf("read /proc/self/task: %v", err)
	}
	if len(tasks) < 32 {
		t.Fatalf("only %d threads exist, the test did not create the load it needs", len(tasks))
	}
	keys := trackedKeys(t, obs)
	for _, task := range tasks {
		tid, _ := strconv.Atoi(task.Name())
		if tid != os.Getpid() && keys[uint32(tid)] {
			t.Errorf("thread %d is in tracked_pids: threads must not be tracked as processes", tid)
		}
	}
	if got := obs.UntrackedChildren(); got != 0 {
		t.Errorf("UntrackedChildren = %d, want 0: threads must not consume tracked_pids slots", got)
	}
	close(release)
	if err := obs.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	// A thread is not a child process: 64 threads must leave no fork record.
	for e := range obs.Events() {
		if e.ActionType == models.ProcessFork {
			t.Errorf("thread creation produced a fork record: %+v", e)
		}
	}
}

// TestObserver_CountsStateMapFull shrinks the execs map and keeps more
// children alive at once than it can hold. A process whose entry cannot be
// stored never gets an exit record, so its exit and exit code silently vanish
// from the ground truth. The counter must see that, live and after Stop.
func TestObserver_CountsStateMapFull(t *testing.T) {
	skipUnprivileged(t)

	const capacity, children = 2, 10
	obs, err := New(Config{EventBufSize: 512, DeferRootPID: true, ExecsMax: capacity})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := obs.SetRootPID(int32(os.Getpid())); err != nil {
		t.Fatalf("SetRootPID: %v", err)
	}
	obs.Start()
	time.Sleep(150 * time.Millisecond)

	var procs []*exec.Cmd
	for i := 0; i < children; i++ {
		c := exec.Command("/bin/sleep", "2")
		if err := c.Start(); err != nil {
			t.Fatalf("spawn sleep: %v", err)
		}
		procs = append(procs, c)
	}
	t.Cleanup(func() {
		for _, c := range procs {
			_ = c.Process.Kill()
			_ = c.Wait()
		}
	})
	time.Sleep(300 * time.Millisecond)

	live := obs.StateMapFull()
	if live < children-capacity {
		t.Errorf("StateMapFull while running = %d, want >= %d", live, children-capacity)
	}
	if err := obs.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if after := obs.StateMapFull(); after < live {
		t.Errorf("StateMapFull after Stop = %d, less than the %d read while running: the Stop snapshot was lost", after, live)
	}
	if obs.CaptureCoverage().StateMapFull == 0 {
		t.Error("CaptureCoverage().StateMapFull = 0, want the loss reported")
	}
	for range obs.Events() {
	}
}

// TestObserver_NoStateMapFullWhenMapFits is the control.
func TestObserver_NoStateMapFullWhenMapFits(t *testing.T) {
	skipUnprivileged(t)

	obs, err := New(Config{EventBufSize: 512, DeferRootPID: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := obs.SetRootPID(int32(os.Getpid())); err != nil {
		t.Fatalf("SetRootPID: %v", err)
	}
	obs.Start()
	time.Sleep(150 * time.Millisecond)
	var procs []*exec.Cmd
	for i := 0; i < 10; i++ {
		c := exec.Command("/bin/sleep", "1")
		if err := c.Start(); err != nil {
			t.Fatalf("spawn sleep: %v", err)
		}
		procs = append(procs, c)
	}
	for _, c := range procs {
		_ = c.Wait()
	}
	time.Sleep(300 * time.Millisecond)
	if err := obs.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if got := obs.StateMapFull(); got != 0 {
		t.Errorf("StateMapFull = %d, want 0 with the default map capacity", got)
	}
	for range obs.Events() {
	}
}

// TestObserver_EventsCarryProcessIdentity checks that exec and exit events name
// the process that caused them and its parent, which is the tree the verifier
// walks (V1). A shell running two commands gives a chain: test -> sh ->
// two children. The ppid comes from the kernel task struct at exec time, so the
// test checks it against pids the test itself observed, not against anything
// the probe reports.
func TestObserver_EventsCarryProcessIdentity(t *testing.T) {
	skipUnprivileged(t)

	nonce := fmt.Sprintf("agenttrace-ident-%d", time.Now().UnixNano())
	obs, err := New(Config{EventBufSize: 512, DeferRootPID: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := obs.SetRootPID(int32(os.Getpid())); err != nil {
		t.Fatalf("SetRootPID: %v", err)
	}
	obs.Start()
	time.Sleep(150 * time.Millisecond)

	// The trailing builtin keeps the shell from exec'ing its last command
	// (dash and bash both do), which would reuse the shell's pid.
	cmd := exec.Command("/bin/sh", "-c", "/bin/echo "+nonce+" a; /bin/echo "+nonce+" b; :")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	shPID := uint32(cmd.Process.Pid)
	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	if err := obs.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	var shells, echoes int
	childPIDs := map[uint32]bool{}
	for _, e := range collect(obs) {
		switch {
		case e.ActionType == models.ProcessExec && e.PID == shPID:
			shells++
			if e.PPID != uint32(os.Getpid()) {
				t.Errorf("shell exec PPID = %d, want the test process %d", e.PPID, os.Getpid())
			}
		case strings.Contains(e.Target, nonce) && strings.HasPrefix(e.Target, "/bin/echo "):
			echoes++
			childPIDs[e.PID] = true
			if e.PID == 0 || e.PID == shPID {
				t.Errorf("%s of %q has PID %d, want the echo's own pid (shell is %d)", e.ActionType, e.Target, e.PID, shPID)
			}
			if e.PPID != shPID {
				t.Errorf("%s of %q has PPID %d, want the shell %d", e.ActionType, e.Target, e.PPID, shPID)
			}
		}
	}
	if shells == 0 {
		t.Error("no shell exec event carried the shell's pid")
	}
	if echoes < 4 { // two echoes, each with an exec and an exit record
		t.Errorf("saw %d echo events, want exec and exit for both", echoes)
	}
	if len(childPIDs) != 2 {
		t.Errorf("echo events came from %d distinct pids, want 2", len(childPIDs))
	}
}

// TestObserver_ForkRecordsPlaceProcessesThatNeverExec is the reason fork
// records exist. A subshell runs a builtin without exec, so it has no exec
// record, yet it is a child of the shell and may write files. Every process the
// tree contains must be reachable from the root through fork edges, whether or
// not it execs, and each exec'd child must be preceded by its own fork edge.
func TestObserver_ForkRecordsPlaceProcessesThatNeverExec(t *testing.T) {
	skipUnprivileged(t)

	nonce := fmt.Sprintf("agenttrace-fork-%d", time.Now().UnixNano())
	obs, err := New(Config{EventBufSize: 512, DeferRootPID: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := obs.SetRootPID(int32(os.Getpid())); err != nil {
		t.Fatalf("SetRootPID: %v", err)
	}
	obs.Start()
	time.Sleep(150 * time.Millisecond)

	// ( ... ) forks a subshell that never execs. /bin/echo forks and execs.
	// The trailing builtin keeps the shell from exec'ing its last command.
	cmd := exec.Command("/bin/sh", "-c", "( : "+nonce+" ); /bin/echo "+nonce+"; :")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	shPID := uint32(cmd.Process.Pid)
	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	if err := obs.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	events := collect(obs)
	forkedFrom := map[uint32]uint32{} // child -> parent, from fork records
	execd := map[uint32]bool{}
	var echoPID uint32
	for i, e := range events {
		switch e.ActionType {
		case models.ProcessFork:
			if e.PID == 0 || e.PPID == 0 {
				t.Errorf("fork record without pid or ppid: %+v", e)
			}
			if _, dup := forkedFrom[e.PID]; dup {
				t.Errorf("two fork records for pid %d", e.PID)
			}
			forkedFrom[e.PID] = e.PPID
		case models.ProcessExec:
			execd[e.PID] = true
			if strings.HasPrefix(e.Target, "/bin/echo ") && strings.Contains(e.Target, nonce) {
				echoPID = e.PID
				if _, ok := forkedFrom[e.PID]; !ok {
					t.Errorf("event %d: echo %d exec'd with no earlier fork record", i, e.PID)
				}
			}
		}
	}
	if echoPID == 0 {
		t.Fatalf("no exec for echo; events: %v", events)
	}
	if forkedFrom[echoPID] != shPID {
		t.Errorf("echo %d forked from %d, want the shell %d", echoPID, forkedFrom[echoPID], shPID)
	}
	var subshell uint32
	for child, parent := range forkedFrom {
		if parent == shPID && !execd[child] {
			subshell = child
		}
	}
	if subshell == 0 {
		t.Errorf("no fork record for a child of the shell that never exec'd (the subshell); forks: %v", forkedFrom)
	}
	// Every fork edge must lead back to the root.
	for child := range forkedFrom {
		pid := child
		for depth := 0; pid != uint32(os.Getpid()); depth++ {
			parent, ok := forkedFrom[pid]
			if !ok || depth > 16 {
				if pid != shPID { // the shell's own parent is the root, whose fork predates tracking
					t.Errorf("pid %d does not lead back to the root %d through fork records", child, os.Getpid())
				}
				break
			}
			pid = parent
		}
	}
}

// A tracked process that exits without ever exec'ing leaves tracked_pids.
// It has no execs entry, and the exit handler used to return on that before
// deleting it, so the stale entry would track any later process that reused
// the pid although it is not a descendant.
func TestObserver_ProcessThatNeverExecsLeavesTheTrackedSet(t *testing.T) {
	skipUnprivileged(t)

	obs, err := New(Config{EventBufSize: 512, DeferRootPID: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := obs.SetRootPID(int32(os.Getpid())); err != nil {
		t.Fatalf("SetRootPID: %v", err)
	}
	obs.Start()
	time.Sleep(150 * time.Millisecond)

	// The subshell prints its own pid with builtins only (dash has no
	// BASHPID), so it never execs. The shell waits for it, so it has exited
	// when Output returns. The trailing builtin keeps the shell from exec'ing.
	out, err := exec.Command("/bin/sh", "-c", "( read -r pid _ < /proc/self/stat; echo $pid ); :").Output()
	if err != nil {
		t.Fatalf("run shell: %v", err)
	}
	sub, err := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 32)
	if err != nil {
		t.Fatalf("subshell pid %q: %v", out, err)
	}
	var info bpfProcInfo
	lookupErr := obs.objs.TrackedPids.Lookup(uint32(sub), &info)
	if err := obs.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if lookupErr == nil {
		t.Errorf("subshell %d is still in tracked_pids after it exited", sub)
	} else if !errors.Is(lookupErr, ebpf.ErrKeyNotExist) {
		t.Errorf("look up subshell %d in tracked_pids: %v", sub, lookupErr)
	}
	var forked bool
	for _, e := range collect(obs) {
		if e.ActionType == models.ProcessFork && e.PID == uint32(sub) {
			forked = true
		}
	}
	if !forked {
		t.Errorf("no fork record for subshell %d: it was never tracked, so the test proves nothing", sub)
	}
}

// A command line of up to 128 KiB is recorded whole. Linux allows a single
// argument of up to 128 KiB, so one Bash command of a harness always fits;
// before P-19 the cap was 8 KiB and a long heredoc mismatched its claim.
func TestObserver_LongCommandLineIsRecordedWhole(t *testing.T) {
	skipUnprivileged(t)
	nonce := fmt.Sprintf("agenttrace-long-%d", time.Now().UnixNano())
	arg := nonce + strings.Repeat("x", 100<<10)
	obs, err := New(Config{CommandFilter: "/bin/true", EventBufSize: 256})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	obs.Start()
	time.Sleep(150 * time.Millisecond)
	if err := exec.Command("/bin/true", arg).Run(); err != nil {
		t.Fatalf("spawn: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	if err := obs.Stop(); err != nil {
		t.Fatal(err)
	}
	var sawExec, sawExit bool
	for _, e := range collect(obs) {
		if !strings.Contains(e.Target, nonce) {
			continue
		}
		if e.Target != "/bin/true "+arg {
			t.Errorf("%s target has %d bytes, want the whole %d", e.ActionType, len(e.Target), len("/bin/true "+arg))
		}
		if e.TargetTruncated {
			t.Errorf("%s flagged truncated at %d bytes", e.ActionType, len(e.Target))
		}
		switch e.ActionType {
		case models.ProcessExec:
			sawExec = true
		case models.ProcessExit:
			sawExit = true
		}
	}
	if !sawExec || !sawExit {
		t.Errorf("exec=%v exit=%v, want both with the full command line", sawExec, sawExit)
	}
}

// A command line the probe cannot hold whole (here 64 arguments of 4 KiB) is
// recorded as far as it goes and flagged, on the exec and on the exit that
// is joined to it.
func TestObserver_OverlongCommandLineIsFlagged(t *testing.T) {
	skipUnprivileged(t)
	nonce := fmt.Sprintf("agenttrace-over-%d", time.Now().UnixNano())
	args := []string{nonce}
	for i := 0; i < 63; i++ {
		args = append(args, strings.Repeat("y", 4<<10))
	}
	obs, err := New(Config{CommandFilter: "/bin/true", EventBufSize: 256})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	obs.Start()
	time.Sleep(150 * time.Millisecond)
	if err := exec.Command("/bin/true", args...).Run(); err != nil {
		t.Fatalf("spawn: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	if err := obs.Stop(); err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, e := range collect(obs) {
		if !strings.Contains(e.Target, nonce) {
			continue
		}
		seen++
		if !e.TargetTruncated {
			t.Errorf("%s with %d bytes not flagged truncated", e.ActionType, len(e.Target))
		}
		if len(e.Target) > 128<<10+len("/bin/true ")+1 {
			t.Errorf("%s target has %d bytes, over the cap", e.ActionType, len(e.Target))
		}
	}
	if seen != 2 {
		t.Errorf("saw %d events with the nonce, want the exec and the exit", seen)
	}
}

// An exec through a file descriptor (execveat with AT_EMPTY_PATH, glibc's
// fexecve) was invisible: only execve was hooked. Python's os.execve takes a
// descriptor and uses exactly that call. The record names the program as
// "(fexecve)", since there is no path, with the arguments (P-21).
func TestObserver_ExecThroughADescriptorIsRecorded(t *testing.T) {
	skipUnprivileged(t)
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not installed")
	}
	nonce := fmt.Sprintf("agenttrace-fexecve-%d", time.Now().UnixNano())
	obs, err := New(Config{CommandFilter: "(fexecve)", EventBufSize: 256})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	obs.Start()
	time.Sleep(150 * time.Millisecond)
	// Only os.execve accepts a descriptor as the program; it then calls
	// execveat(fd, "", argv, envp, AT_EMPTY_PATH).
	script := fmt.Sprintf("import os; fd = os.open('/bin/true', os.O_RDONLY); os.execve(fd, ['true', %q], os.environ)", nonce)
	if err := exec.Command("python3", "-c", script).Run(); err != nil {
		t.Fatalf("python: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	if err := obs.Stop(); err != nil {
		t.Fatal(err)
	}
	var sawExec, sawExit bool
	for _, e := range collect(obs) {
		if !strings.Contains(e.Target, nonce) {
			continue
		}
		if e.Target != "(fexecve) "+nonce {
			t.Errorf("target %q, want %q", e.Target, "(fexecve) "+nonce)
		}
		switch e.ActionType {
		case models.ProcessExec:
			sawExec = true
		case models.ProcessExit:
			sawExit = true
		}
	}
	if !sawExec || !sawExit {
		t.Errorf("exec=%v exit=%v, want both for the exec through a descriptor", sawExec, sawExit)
	}
}

// The Config comments name the compiled-in capacities that the overrides
// replace. The spec is parsed without loading it into the kernel, so this
// runs unprivileged and keeps the comments and proc.bpf.c in step.
func TestSpec_CompiledInCapacitiesMatchConfigComments(t *testing.T) {
	spec, err := loadBpf()
	if err != nil {
		t.Fatalf("loadBpf: %v", err)
	}
	for name, want := range map[string]uint32{
		"events":       8 << 20, // Config.RingbufBytes: 8 MiB
		"tracked_pids": 16384,   // Config.TrackedPIDsMax
		"execs":        4096,    // Config.ExecsMax
	} {
		if got := spec.Maps[name].MaxEntries; got != want {
			t.Errorf("map %s has %d entries compiled in, the Config comment says %d", name, got, want)
		}
	}
}

// runTracked starts an observer that tracks this test's descendants, runs
// each command to completion, and returns the events by pid.
func runTracked(t *testing.T, cmds []*exec.Cmd) map[uint32][]models.GroundTruthEvent {
	t.Helper()
	obs, err := New(Config{EventBufSize: 1024, DeferRootPID: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := obs.SetRootPID(int32(os.Getpid())); err != nil {
		t.Fatalf("SetRootPID: %v", err)
	}
	obs.Start()
	time.Sleep(150 * time.Millisecond)
	for _, c := range cmds {
		if err := c.Run(); err != nil {
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) {
				_ = obs.Stop()
				t.Fatalf("run %s: %v", c.Path, err)
			}
		}
	}
	// CI sets this bound: the exit records must leave the ring buffer.
	time.Sleep(300 * time.Millisecond)
	if err := obs.Stop(); err != nil {
		t.Fatal(err)
	}
	byPID := map[uint32][]models.GroundTruthEvent{}
	for _, e := range collect(obs) {
		byPID[e.PID] = append(byPID[e.PID], e)
	}
	return byPID
}

// edgeCase is one command run several times at a truncation boundary.
// full is the command line the kernel ran, as the probe would render it whole.
type edgeCase struct {
	name     string
	cmd      func() *exec.Cmd
	full     string
	mustFlag bool // the command line does not fit: every record is flagged
}

// edgeRuns is how often each boundary case runs. A probe read can fail on a
// valid argv (it cannot fault a page in), and the probe then flags the record
// as cut. That is allowed for a command line that fits, so the tests ask for
// one whole record among the runs, never a record that claims to be whole
// and is not.
const edgeRuns = 5

// checkEdgeCases runs every case edgeRuns times under one observer and
// checks, per record: an unflagged record carries the whole command line
// (soundness, every run); a case that cannot fit is always flagged; a case
// that fits is recorded whole and unflagged at least once.
func checkEdgeCases(t *testing.T, cases []edgeCase) {
	t.Helper()
	var cmds []*exec.Cmd
	for _, c := range cases {
		for r := 0; r < edgeRuns; r++ {
			cmds = append(cmds, c.cmd())
		}
	}
	byPID := runTracked(t, cmds)
	for i, c := range cases {
		whole := 0
		for r := 0; r < edgeRuns; r++ {
			cmd := cmds[i*edgeRuns+r]
			var kinds []models.ActionType
			for _, e := range byPID[uint32(cmd.Process.Pid)] {
				if e.ActionType == models.ProcessFork {
					continue
				}
				kinds = append(kinds, e.ActionType)
				switch {
				case !e.TargetTruncated && e.Target != c.full:
					t.Errorf("%s, run %d: %s is unflagged with %d bytes, the command line has %d: a cut record claims to be whole",
						c.name, r, e.ActionType, len(e.Target), len(c.full))
				case c.mustFlag && !e.TargetTruncated:
					t.Errorf("%s, run %d: %s not flagged truncated", c.name, r, e.ActionType)
				case e.TargetTruncated && !c.mustFlag:
					t.Logf("%s, run %d: %s flagged with %d of %d bytes (fail-safe)", c.name, r, e.ActionType, len(e.Target), len(c.full))
				}
				if !c.mustFlag && !e.TargetTruncated && e.ActionType == models.ProcessExec {
					whole++
				}
			}
			if len(kinds) != 2 {
				t.Errorf("%s, run %d: saw %v, want the exec and the exit", c.name, r, kinds)
			}
		}
		if !c.mustFlag && whole == 0 {
			t.Errorf("%s: no run of %d recorded the command line whole", c.name, edgeRuns)
		}
	}
}

// A command line that fills the 128 KiB args area exactly, NULs included,
// is whole: only one that does not fit is cut. The same holds for a single
// string that fills the area by itself (an argv[0] of 131071 bytes, the
// most Linux accepts), whose read returns the buffer size whether it fit or
// was cut (P-19, V-26).
func TestObserver_CommandLineOfExactly128KiBIsWhole(t *testing.T) {
	skipUnprivileged(t)
	const area = 128 << 10
	head := len("/bin/true") + 1 // argv[0] and its NUL share the area
	fill := strings.Repeat("z", area-head-1)
	long0 := strings.Repeat("a", area-1)
	checkEdgeCases(t, []edgeCase{
		{"argv fills the area", func() *exec.Cmd { return exec.Command("/bin/true", fill) }, "/bin/true " + fill, false},
		{"argv is one byte over", func() *exec.Cmd { return exec.Command("/bin/true", fill+"z") }, "/bin/true " + fill + "z", true},
		{"argv[0] alone fills the area", func() *exec.Cmd { return &exec.Cmd{Path: "/bin/true", Args: []string{long0}} }, "/bin/true", false},
	})
}

// A program path of FILENAME_LEN-1 (255) bytes fills the filename buffer
// with its NUL and is whole; one of 256 bytes is cut and flagged.
func TestObserver_ProgramPathOf255BytesIsWhole(t *testing.T) {
	skipUnprivileged(t)
	dir := t.TempDir()
	link := func(n int) string {
		p := dir + "/" + strings.Repeat("p", n-len(dir)-1)
		if err := os.Symlink("/bin/true", p); err != nil {
			t.Fatalf("symlink of %d bytes: %v", n, err)
		}
		return p
	}
	whole, cut := link(255), link(256)
	checkEdgeCases(t, []edgeCase{
		{"a 255-byte path", func() *exec.Cmd { return exec.Command(whole, "whole") }, whole + " whole", false},
		{"a 256-byte path", func() *exec.Cmd { return exec.Command(cut, "cut") }, cut + " cut", true},
	})
}

// The exit code is the status the parent reads from wait, the low 8 bits of
// the exit_group argument, not the argument itself: _exit(263) is status 7
// and _exit(-1) is 255, which is what a shell or a harness reports.
func TestObserver_ExitCodeIsTheWaitStatus(t *testing.T) {
	skipUnprivileged(t)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not installed")
	}
	args := []int{263, -1, 256}
	cmds := make([]*exec.Cmd, len(args))
	for i, a := range args {
		cmds[i] = exec.Command(python, "-c", fmt.Sprintf("import os; os._exit(%d)", a))
	}
	byPID := runTracked(t, cmds)
	for i, c := range cmds {
		want := int32(c.ProcessState.ExitCode())
		var exit *models.GroundTruthEvent
		for j, e := range byPID[uint32(c.Process.Pid)] {
			if e.ActionType == models.ProcessExit {
				exit = &byPID[uint32(c.Process.Pid)][j]
			}
		}
		switch {
		case exit == nil:
			t.Errorf("_exit(%d): no exit event", args[i])
		case exit.ExitCode == nil:
			t.Errorf("_exit(%d): exit event has no exit code", args[i])
		case *exit.ExitCode != want:
			t.Errorf("_exit(%d): ExitCode = %d, want the wait status %d", args[i], *exit.ExitCode, want)
		}
	}
}

// leaderExitsFirst ends its main thread with a raw exit, so the thread-group
// leader is a zombie while a second thread lives on, forks and execs a child,
// and ends the process with exit_group(3).
const leaderExitsFirst = `
import ctypes, os, subprocess, sys, threading, time
sys_exit, nonce = int(sys.argv[1]), sys.argv[2]
tgid = os.getpid()
def worker():
    deadline = time.monotonic() + 5
    while True:
        with open(f"/proc/{tgid}/task/{tgid}/stat") as f:
            state = f.read().rsplit(")", 1)[1].split()[0]
        if state == "Z":
            break
        if time.monotonic() > deadline:
            os._exit(99)
        time.sleep(0.01)
    subprocess.run(["/bin/true", nonce])
    os._exit(3)
threading.Thread(target=worker).start()
ctypes.CDLL(None).syscall(sys_exit, 0)
`

// A process whose thread-group leader exits first is still alive: it stays
// tracked, so a child it forks afterwards is in the tree, and its exit record
// comes when the last thread exits, with that exit's code. The probe used to
// treat the leader's exit as the process's.
func TestObserver_ProcessOutlivesItsLeaderThread(t *testing.T) {
	skipUnprivileged(t)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not installed")
	}
	nonce := fmt.Sprintf("agenttrace-leader-%d", time.Now().UnixNano())
	cmd := exec.Command(python, "-c", leaderExitsFirst, strconv.Itoa(unix.SYS_EXIT), nonce)
	byPID := runTracked(t, []*exec.Cmd{cmd})
	if code := cmd.ProcessState.ExitCode(); code != 3 {
		t.Fatalf("the script exited %d, want 3 (99: the leader never became a zombie)", code)
	}
	pid := uint32(cmd.Process.Pid)

	var child, exit *models.GroundTruthEvent
	for p, evs := range byPID {
		for i, e := range evs {
			switch {
			case e.ActionType == models.ProcessExec && e.Target == "/bin/true "+nonce:
				child = &byPID[p][i]
			case p == pid && e.ActionType == models.ProcessExit:
				if exit != nil {
					t.Errorf("a second exit record for %d: %+v", pid, e)
				}
				exit = &byPID[p][i]
			}
		}
	}
	if child == nil {
		t.Errorf("no exec of the child forked after the leader exited: the process left the tracked set while it lived")
	} else if child.PPID != pid {
		t.Errorf("child's PPID = %d, want %d", child.PPID, pid)
	}
	switch {
	case exit == nil:
		t.Errorf("no exit record for %d", pid)
	case exit.ExitCode == nil || *exit.ExitCode != 3:
		t.Errorf("exit record has ExitCode %v, want 3 from the last thread's exit_group", exit.ExitCode)
	case child != nil && exit.Timestamp.Before(child.Timestamp):
		t.Errorf("exit record at %v precedes the child's exec at %v", exit.Timestamp, child.Timestamp)
	}
}

// execveatScript calls execveat(dirfd, path, ["true", nonce], [], flags),
// with dirfd an opened directory or AT_FDCWD when none is given.
const execveatScript = `
import ctypes, os, sys
nr, dirpath, path, flags, nonce = int(sys.argv[1]), sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5]
dirfd = os.open(dirpath, os.O_RDONLY | os.O_DIRECTORY) if dirpath else -100
argv = (ctypes.c_char_p * 3)(b"true", nonce.encode(), None)
envp = (ctypes.c_char_p * 1)(None)
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall(ctypes.c_long(nr), ctypes.c_long(dirfd), ctypes.c_char_p(path.encode()), argv, envp, ctypes.c_long(flags))
os._exit(100 + ctypes.get_errno())
`

// AT_EMPTY_PATH makes execveat exec the descriptor only when the pathname
// is empty; with a pathname the kernel looks the path up as usual, so the
// record names it (P-21). An exec with AT_EMPTY_PATH and an absolute path
// used to be recorded as "(fexecve)", which hid the program. A pathname
// relative to a directory descriptor is recorded as given.
func TestObserver_ExecveatWithAPathNamesIt(t *testing.T) {
	skipUnprivileged(t)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not installed")
	}
	cases := []struct {
		name, dir, path string
		flags           int
		target          string
	}{
		{"AT_EMPTY_PATH with an absolute path", "", "/bin/true", unix.AT_EMPTY_PATH, "/bin/true"},
		{"a path relative to a directory descriptor", "/bin", "true", 0, "true"},
	}
	nonce := fmt.Sprintf("agenttrace-execveat-%d", time.Now().UnixNano())
	cmds := make([]*exec.Cmd, len(cases))
	for i, c := range cases {
		cmds[i] = exec.Command(python, "-c", execveatScript,
			strconv.Itoa(unix.SYS_EXECVEAT), c.dir, c.path, strconv.Itoa(c.flags), fmt.Sprintf("%s-%d", nonce, i))
	}
	byPID := runTracked(t, cmds)
	for i, c := range cases {
		if code := cmds[i].ProcessState.ExitCode(); code != 0 {
			t.Errorf("%s: exited %d, want 0 from /bin/true (100+errno: execveat failed)", c.name, code)
			continue
		}
		want := fmt.Sprintf("%s %s-%d", c.target, nonce, i)
		var seen bool
		for _, e := range byPID[uint32(cmds[i].Process.Pid)] {
			// The launcher's own exec carries the nonce among its arguments
			// too; the record under test is the one execveat made.
			if e.ActionType == models.ProcessExec && !strings.HasPrefix(e.Target, python) && strings.HasSuffix(e.Target, fmt.Sprintf("%s-%d", nonce, i)) {
				seen = true
				if e.Target != want {
					t.Errorf("%s: target %q, want %q", c.name, e.Target, want)
				}
			}
		}
		if !seen {
			t.Errorf("%s: no exec record with the nonce", c.name)
		}
	}
}

// exitOf returns the one exit record of pid, failing the test on none or two.
func exitOf(t *testing.T, byPID map[uint32][]models.GroundTruthEvent, pid uint32) *models.GroundTruthEvent {
	t.Helper()
	var exit *models.GroundTruthEvent
	for i, e := range byPID[pid] {
		if e.ActionType != models.ProcessExit {
			continue
		}
		if exit != nil {
			t.Errorf("a second exit record for %d: %+v", pid, e)
		}
		exit = &byPID[pid][i]
	}
	if exit == nil {
		t.Errorf("no exit record for %d; its events: %+v", pid, byPID[pid])
	}
	return exit
}

// failThenExec attempts an exec of a program that does not exist, then, when
// argv[2] says so, execs /bin/true; otherwise it exits 5 as python.
const failThenExec = `
import os, sys
nonce, then = sys.argv[1], sys.argv[2]
try:
    os.execv("/nonexistent-" + nonce, ["x", nonce])
except OSError:
    pass
if then == "exec":
    os.execv("/bin/true", ["true", nonce])
os._exit(5)
`

// A failed exec attempt is recorded (P-4) but does not become the process's
// command line: the exit names the image that exited (P-31). The exit used
// to carry the latest attempt, so a process that tried a missing binary
// exited under its name.
func TestObserver_FailedExecDoesNotNameTheExit(t *testing.T) {
	skipUnprivileged(t)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not installed")
	}
	nonce := fmt.Sprintf("agenttrace-failexec-%d", time.Now().UnixNano())
	thenExec := exec.Command(python, "-c", failThenExec, nonce+"-a", "exec")
	thenExit := exec.Command(python, "-c", failThenExec, nonce+"-b", "exit")
	byPID := runTracked(t, []*exec.Cmd{thenExec, thenExit})
	if code := thenExec.ProcessState.ExitCode(); code != 0 {
		t.Fatalf("the exec case exited %d, want 0 from /bin/true", code)
	}
	if code := thenExit.ProcessState.ExitCode(); code != 5 {
		t.Fatalf("the exit case exited %d, want 5", code)
	}

	for _, c := range []struct {
		cmd    *exec.Cmd
		nonce  string
		want   string
		code   int32
		reason string
	}{
		{thenExec, nonce + "-a", "/bin/true " + nonce + "-a", 0, "the exec that took effect after the failed one"},
		{thenExit, nonce + "-b", "", 5, "python, the image that exited"},
	} {
		pid := uint32(c.cmd.Process.Pid)
		var attempt bool
		for _, e := range byPID[pid] {
			if e.ActionType == models.ProcessExec && e.Target == "/nonexistent-"+c.nonce+" "+c.nonce {
				attempt = true
			}
		}
		if !attempt {
			t.Errorf("%s: no exec record of the failed attempt (P-4)", c.nonce)
		}
		exit := exitOf(t, byPID, pid)
		if exit == nil {
			continue
		}
		want := c.want
		if want == "" {
			want = python + " -c " + failThenExec + " " + c.nonce + " exit"
		}
		if exit.Target != want {
			t.Errorf("%s: exit target %q, want %s %q", c.nonce, exit.Target, c.reason, want)
		}
		if exit.ExitCode == nil || *exit.ExitCode != c.code {
			t.Errorf("%s: exit code %v, want %d", c.nonce, exit.ExitCode, c.code)
		}
	}
}

// A process that execs twice exits as its last image: a shell that execs a
// shell that execs /bin/true is /bin/true when it exits (P-31). The first
// exec record still names the first program.
func TestObserver_ProcessThatExecsTwiceExitsAsItsLastImage(t *testing.T) {
	skipUnprivileged(t)
	nonce := fmt.Sprintf("agenttrace-twice-%d", time.Now().UnixNano())
	inner := "exec /bin/true " + nonce
	outer := "exec /bin/sh -c '" + inner + "'"
	cmd := exec.Command("/bin/sh", "-c", outer)
	byPID := runTracked(t, []*exec.Cmd{cmd})
	pid := uint32(cmd.Process.Pid)

	var execs []string
	for _, e := range byPID[pid] {
		if e.ActionType == models.ProcessExec {
			execs = append(execs, e.Target)
		}
	}
	wantExecs := []string{"/bin/sh -c " + inner, "/bin/true " + nonce}
	if len(execs) != 3 || execs[0] != "/bin/sh -c "+outer || execs[1] != wantExecs[0] || execs[2] != wantExecs[1] {
		t.Errorf("exec records %q, want the outer shell, the inner shell and /bin/true", execs)
	}
	if exit := exitOf(t, byPID, pid); exit != nil && exit.Target != "/bin/true "+nonce {
		t.Errorf("exit target %q, want the last image %q", exit.Target, "/bin/true "+nonce)
	}
}

// threadExec execs /bin/true from a thread that is not the leader. The kernel
// gives the exec'ing thread the leader's pid, so the success record names the
// thread's old pid, and the exit must still join that thread's attempt.
const threadExec = `
import os, sys, threading, time
nonce = sys.argv[1]
threading.Thread(target=lambda: os.execv("/bin/true", ["true", nonce])).start()
time.sleep(10)
os._exit(99)
`

func TestObserver_ExecByANonLeaderThreadNamesTheExit(t *testing.T) {
	skipUnprivileged(t)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not installed")
	}
	nonce := fmt.Sprintf("agenttrace-threadexec-%d", time.Now().UnixNano())
	cmd := exec.Command(python, "-c", threadExec, nonce)
	byPID := runTracked(t, []*exec.Cmd{cmd})
	if code := cmd.ProcessState.ExitCode(); code != 0 {
		t.Fatalf("exited %d, want 0 from /bin/true (99: the thread's exec did not happen)", code)
	}
	if exit := exitOf(t, byPID, uint32(cmd.Process.Pid)); exit != nil && exit.Target != "/bin/true "+nonce {
		t.Errorf("exit target %q, want %q", exit.Target, "/bin/true "+nonce)
	}
}

// Every exec attempt of a tracked tree has its record, and every exec that
// took effect its exit, with no loss counted (P-32). On kernel 7.0 the
// perf-event sys_enter_execve tracepoint skipped the program for some execs
// without a count, so a shell's children went missing; the raw tracepoint
// dispatcher must see them all. Stop runs as soon as the shell has exited,
// with no sleep, so the records still in the ring at Stop must be drained.
func TestObserver_EveryExecAttemptIsRecorded(t *testing.T) {
	skipUnprivileged(t)
	const okRuns, failRuns = 200, 50
	nonce := fmt.Sprintf("agenttrace-many-%d", time.Now().UnixNano())

	obs, err := New(Config{EventBufSize: 8192, DeferRootPID: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := obs.SetRootPID(int32(os.Getpid())); err != nil {
		t.Fatalf("SetRootPID: %v", err)
	}
	obs.Start()
	time.Sleep(150 * time.Millisecond)

	script := fmt.Sprintf(`i=0
while [ $i -lt %d ]; do /bin/true %s-ok-$i; i=$((i+1)); done
i=0
while [ $i -lt %d ]; do /nonexistent-%s %s-fail-$i 2>/dev/null; i=$((i+1)); done
exit 0`, okRuns, nonce, failRuns, nonce, nonce)
	if err := exec.Command("/bin/sh", "-c", script).Run(); err != nil {
		_ = obs.Stop()
		t.Fatalf("run shell: %v", err)
	}
	if err := obs.Stop(); err != nil {
		t.Fatal(err)
	}

	execs := map[string]int{}
	exits := map[string]int{}
	for _, e := range collect(obs) {
		// The shell's own exec and exit name the nonce through its script;
		// only its children are counted.
		if !strings.Contains(e.Target, nonce+"-") || strings.HasPrefix(e.Target, "/bin/sh ") {
			continue
		}
		switch e.ActionType {
		case models.ProcessExec:
			execs[e.Target]++
		case models.ProcessExit:
			exits[e.Target]++
			if e.ExitCode == nil || *e.ExitCode != 0 {
				t.Errorf("exit of %q has code %v, want 0", e.Target, e.ExitCode)
			}
		}
	}
	var okExecs, failExecs, okExits int
	for i := 0; i < okRuns; i++ {
		target := fmt.Sprintf("/bin/true %s-ok-%d", nonce, i)
		if execs[target] != 1 {
			t.Errorf("%d exec records of %q, want 1", execs[target], target)
		}
		if exits[target] != 1 {
			t.Errorf("%d exit records of %q, want 1", exits[target], target)
		}
		okExecs += execs[target]
		okExits += exits[target]
	}
	for i := 0; i < failRuns; i++ {
		target := fmt.Sprintf("/nonexistent-%s %s-fail-%d", nonce, nonce, i)
		if execs[target] != 1 {
			t.Errorf("%d exec records of the failed attempt %q, want 1 (P-4)", execs[target], target)
		}
		failExecs += execs[target]
	}
	var total int
	for _, n := range execs {
		total += n
	}
	if total != okRuns+failRuns {
		t.Errorf("%d exec records name the nonce, want %d successful plus %d failed attempts", total, okRuns, failRuns)
	}
	cov := obs.CaptureCoverage()
	if cov.RingbufDrops != 0 || cov.ChannelDrops != 0 || cov.UntrackedChildren != 0 || cov.StateMapFull != 0 {
		t.Errorf("loss counted: %+v", cov)
	}
	t.Logf("exec records: %d of %d successful, %d of %d failed; exits %d of %d", okExecs, okRuns, failExecs, failRuns, okExits, okRuns)
}
