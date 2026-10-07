package proc

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
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
