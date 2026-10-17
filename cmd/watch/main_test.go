package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/probe"
	"github.com/agent-trace/agent-trace/pkg/probe/fs"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

func skipUnprivileged(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("requires root (fanotify + eBPF)")
	}
}

// TestRunWatch_ExecWrapSuppressesRootSeesChild exercises the Fix 3a wiring:
// runWatch launches the "agent" itself and records its PID as the proc
// probe's ancestry root. Two properties must hold:
//
//   - the agent process's own exec must NOT appear as a ground-truth event
//     (it is the controller, not an agent action), matching the suppression
//     tests/e2e/tier2_test.go's runTier2Agent already relies on;
//   - a child the agent spawns MUST appear, tagged top-level.
//
// The fake agent is a shell (the ancestry root) that forks one child,
// `/bin/echo <nonce>`, via `&` so the shell genuinely forks rather than
// exec-ing echo in place.
func TestRunWatch_ExecWrapSuppressesRootSeesChild(t *testing.T) {
	skipUnprivileged(t)

	ws := t.TempDir()
	out := filepath.Join(t.TempDir(), "ground_truth.json")
	nonce := fmt.Sprintf("watch-3a-%d", time.Now().UnixNano())
	// The child forks after a delay; TestRunWatch_ImmediateForkIsTracked
	// covers a fork at the agent's first instruction.
	script := "sleep 2 && /bin/echo " + nonce + " & wait"

	opts := watchOptions{
		cfg:       watchConfig{Workspace: ws, EventBufSize: 256},
		probes:    "proc",
		out:       out,
		agentArgs: []string{"/bin/sh", "-c", script},
	}

	if err := runWatch(opts); err != nil {
		t.Fatalf("runWatch: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read %s: %v", out, err)
	}
	file, err := models.ParseGroundTruthFile(data)
	if err != nil {
		t.Fatalf("parse ground truth: %v", err)
	}
	if file.Coverage == nil {
		t.Fatal("watch wrote no coverage record")
	}
	if file.RootPID == 0 {
		t.Error("watch wrote no root_pid for a launched agent")
	}
	// The root pid must be the launched shell: the exec of the script's own
	// shell names it as the parent of the echo's subshell chain.
	var rootSeen bool
	for _, e := range file.Events {
		if e.PID == file.RootPID || e.PPID == file.RootPID {
			rootSeen = true
		}
	}
	if !rootSeen {
		t.Errorf("no event names root_pid %d as pid or ppid", file.RootPID)
	}
	if !file.Coverage.Probes["proc"].Ran {
		t.Errorf("proc probe not recorded as run: %+v", file.Coverage.Probes)
	}
	ground := file.Events

	var sawRoot, sawChild bool
	for _, e := range ground {
		if e.ActionType != models.ProcessExec {
			continue
		}
		if strings.HasPrefix(e.Target, "/bin/sh") && strings.Contains(e.Target, nonce) {
			// The root shell's own exec line (its argv carries the -c script).
			sawRoot = true
		}
		if strings.HasPrefix(e.Target, "/bin/echo") && strings.Contains(e.Target, nonce) {
			sawChild = true
			if e.IsTopLevel != nil && !*e.IsTopLevel {
				t.Errorf("child exec %q tagged forensic-only, want top-level", e.Target)
			}
		}
	}
	if sawRoot {
		t.Errorf("root agent exec leaked into ground truth; events: %+v", ground)
	}
	if !sawChild {
		t.Errorf("child exec (echo %s) missing from ground truth; events: %+v", nonce, ground)
	}
}

// TestRunWatch_ImmediateForkIsTracked checks that a child the agent forks at
// once is in the tree: the agent is held before its exec until its pid is
// registered with the probes (P-23), so there is no window in which a fork is
// untracked. Before that, watch registered the pid after the agent started and
// such a child could be missed on a slow runner. A single run passes by luck
// as often as not without the hold; run it with -count=50 to judge the fix.
func TestRunWatch_ImmediateForkIsTracked(t *testing.T) {
	skipUnprivileged(t)

	out := filepath.Join(t.TempDir(), "ground_truth.json")
	nonce := fmt.Sprintf("watch-immediate-%d", time.Now().UnixNano())
	opts := watchOptions{
		cfg:       watchConfig{Workspace: t.TempDir(), EventBufSize: 256},
		probes:    "proc",
		out:       out,
		agentArgs: []string{"/bin/sh", "-c", "/bin/echo " + nonce + " & wait"},
	}
	if err := runWatch(opts); err != nil {
		t.Fatalf("runWatch: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read %s: %v", out, err)
	}
	file, err := models.ParseGroundTruthFile(data)
	if err != nil {
		t.Fatalf("parse ground truth: %v", err)
	}
	var forked, execd bool
	for _, e := range file.Events {
		if e.ActionType == models.ProcessFork && e.PPID == file.RootPID {
			forked = true
		}
		if e.ActionType == models.ProcessExec && e.Target == "/bin/echo "+nonce {
			execd = true
		}
	}
	if !forked || !execd {
		t.Errorf("immediate child missing (fork from root %d: %v, exec of echo: %v); events: %+v", file.RootPID, forked, execd, file.Events)
	}
}

// A held agent runs nothing until it is released, and then runs under the pid
// it was held with, which is the pid watch registers with the probes (P-23).
// Needs no privileges.
func TestStartHeld_RunsTheAgentOnlyAfterReleaseUnderTheSamePID(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "pid")
	held, err := startHeld([]string{"sh", "-c", `echo $$ > "$1"`, "agent", marker}, nil, nil, nil)
	if err != nil {
		t.Fatalf("startHeld: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	if _, err := os.Stat(marker); err == nil {
		held.abort()
		t.Fatal("the agent ran before it was released")
	}
	if err := held.release(); err != nil {
		held.abort()
		t.Fatalf("release: %v", err)
	}
	if err := held.cmd.Wait(); err != nil {
		t.Fatalf("agent: %v", err)
	}
	got, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("the agent did not run after release: %v", err)
	}
	if want := fmt.Sprint(held.pid()); strings.TrimSpace(string(got)) != want {
		t.Errorf("agent ran as pid %s, want the held pid %s", strings.TrimSpace(string(got)), want)
	}
}

// An agent that is never released never runs, and a missing program is
// reported by watch before any process is started.
func TestStartHeld_AbortAndMissingProgram(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	held, err := startHeld([]string{"/bin/sh", "-c", `: > "$1"`, "agent", marker}, nil, nil, nil)
	if err != nil {
		t.Fatalf("startHeld: %v", err)
	}
	held.abort()
	if _, err := os.Stat(marker); err == nil {
		t.Error("an aborted agent ran")
	}
	if _, err := startHeld([]string{"agent-trace-no-such-program"}, nil, nil, nil); err == nil {
		t.Error("startHeld accepted a program that does not exist")
	}
}

// TestRunWatch_RejectsRootPIDWithCommand is a pure-logic guard that needs no
// privileges: the two ancestry-root mechanisms are mutually exclusive.
func TestRunWatch_RejectsRootPIDWithCommand(t *testing.T) {
	err := runWatch(watchOptions{
		cfg:       watchConfig{Workspace: t.TempDir()},
		probes:    "proc",
		rootPID:   1234,
		agentArgs: []string{"/bin/true"},
	})
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected mutual-exclusion error, got %v", err)
	}
}

type fakeReporter struct{ cov models.ProbeCoverage }

func (f fakeReporter) CaptureCoverage() models.ProbeCoverage { return f.cov }

func TestBuildCoverage_RecordsEveryKnownProbe(t *testing.T) {
	cov := buildCoverage(map[string]probe.CoverageReporter{
		"proc": fakeReporter{models.ProbeCoverage{Ran: true, RingbufDrops: 5}},
	})
	if cov.Schema != models.CoverageSchema {
		t.Errorf("schema = %d, want %d", cov.Schema, models.CoverageSchema)
	}
	if len(cov.Probes) != len(probeBuilders) {
		t.Fatalf("recorded %d probes, want all %d known", len(cov.Probes), len(probeBuilders))
	}
	if got := cov.Probes["proc"]; !got.Ran || got.RingbufDrops != 5 {
		t.Errorf("proc = %+v, want ran with 5 drops", got)
	}
	for _, name := range []string{"fs", "net"} {
		if cov.Probes[name].Ran {
			t.Errorf("%s was not selected but is recorded as run", name)
		}
	}
}

// TestRunWatch_RecordsLossInCoverage forces the proc probe's kernel ring to
// overflow (one-page ring, an exec whose argv alone exceeds it) and checks the
// loss reaches the written file and makes the capture count as incomplete.
func TestRunWatch_RecordsLossInCoverage(t *testing.T) {
	skipUnprivileged(t)

	out := filepath.Join(t.TempDir(), "ground_truth.json")
	script := "sleep 2 && /bin/true " + strings.Repeat("x", 6000)

	opts := watchOptions{
		cfg:       watchConfig{Workspace: t.TempDir(), EventBufSize: 256, ProcRingbufBytes: 4096},
		probes:    "proc",
		out:       out,
		agentArgs: []string{"/bin/sh", "-c", script},
	}
	if err := runWatch(opts); err != nil {
		t.Fatalf("runWatch: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read %s: %v", out, err)
	}
	file, err := models.ParseGroundTruthFile(data)
	if err != nil {
		t.Fatalf("parse ground truth: %v", err)
	}
	if file.Coverage == nil {
		t.Fatal("no coverage record written")
	}
	if got := file.Coverage.Probes["proc"].RingbufDrops; got == 0 {
		t.Errorf("proc RingbufDrops = 0, want > 0 after forcing the ring to overflow")
	}
	if verification.Assess(file.Coverage).Complete {
		t.Error("Assess reported a capture with ring buffer drops as complete")
	}
}

// Events from one batch share a timestamp, and the verifier aligns by
// position, so ties must keep the order the probe emitted them in.
func TestSortGroundKeepsTiesInArrivalOrder(t *testing.T) {
	ts := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	var g models.GroundTruth
	for i := 0; i < 500; i++ {
		g = append(g, models.GroundTruthEvent{Timestamp: ts, ActionType: models.FileWrite, Target: fmt.Sprintf("/w/%03d", i)})
	}
	g = append(g, models.GroundTruthEvent{Timestamp: ts.Add(-time.Second), ActionType: models.FileOpen, Target: "/w/earlier"})
	sortGround(g)
	if g[0].Target != "/w/earlier" {
		t.Fatalf("first = %s, want the earliest event", g[0].Target)
	}
	for i := 1; i < len(g); i++ {
		if want := fmt.Sprintf("/w/%03d", i-1); g[i].Target != want {
			t.Fatalf("tie %d = %s, want %s: a tie was reordered", i, g[i].Target, want)
		}
	}
}

func TestWorkspaceAbsIsAbsolute(t *testing.T) {
	if got := workspaceAbs("rel/dir"); !filepath.IsAbs(got) || !strings.HasSuffix(got, "rel/dir") {
		t.Errorf("workspaceAbs(rel/dir) = %q", got)
	}
	if got := workspaceAbs("/already/abs"); got != "/already/abs" {
		t.Errorf("workspaceAbs(/already/abs) = %q", got)
	}
}

// The tree-or-workspace rule is pure: it needs the fork records and the
// workspace, nothing from the kernel.
func TestScopeFSEvents_KeepsTheTreeAnywhereAndTheWorkspaceForEveryone(t *testing.T) {
	const root, child, stranger = 100, 200, 900
	ts := time.Now()
	ev := func(typ models.ActionType, target string, pid, ppid uint32) models.GroundTruthEvent {
		return models.GroundTruthEvent{Timestamp: ts, ActionType: typ, Target: target, PID: pid, PPID: ppid}
	}
	g := models.GroundTruth{
		ev(models.ProcessFork, "200", child, root),
		ev(models.ProcessExec, "/bin/sh -c x", child, root),
		ev(models.FileWrite, "/ws/in.txt", root, 0),         // agent, in the workspace
		ev(models.FileWrite, "/home/u/.bashrc", root, 0),    // agent, elsewhere: kept
		ev(models.FileWrite, "/tmp/tool.cfg", child, root),  // a command's child, elsewhere: kept
		ev(models.FileOpen, "/ws/in.txt", stranger, 0),      // another process, in the workspace: kept
		ev(models.FileWrite, "/ws2/other.txt", stranger, 0), // another process, a look-alike prefix: dropped
		ev(models.FileWrite, "/etc/passwd", stranger, 0),    // another process, elsewhere: dropped
		ev(models.FileOpen, "/ws/x", 0, 0),                  // no pid, in the workspace: kept
		ev(models.FileOpen, "/var/x", 0, 0),                 // no pid, elsewhere: dropped
		ev(models.NetConnect, "example.com", stranger, 0),   // not a file event: untouched
	}
	kept, dropped, _ := scopeFSEvents(g, root, "/ws")
	if dropped != 3 {
		t.Errorf("dropped = %d, want 3", dropped)
	}
	var targets []string
	for _, e := range kept {
		targets = append(targets, e.Target)
	}
	want := []string{"200", "/bin/sh -c x", "/ws/in.txt", "/home/u/.bashrc", "/tmp/tool.cfg", "/ws/in.txt", "/ws/x", "example.com"}
	if strings.Join(targets, ",") != strings.Join(want, ",") {
		t.Errorf("kept = %v\nwant %v", targets, want)
	}
}

// The recorder's own file events are never the agent's. Before this, watch
// printing an event to a log on a marked filesystem produced the event it
// printed, without end (2.7 MB of its own log lines in one short capture).
func TestScopeFSEvents_DropsTheRecordersOwnFileEvents(t *testing.T) {
	self := uint32(os.Getpid())
	ts := time.Now()
	g := models.GroundTruth{
		{Timestamp: ts, ActionType: models.FileWrite, Target: "/out/capture.log", PID: self},
		{Timestamp: ts, ActionType: models.FileOpen, Target: "/ws/seed.txt", PID: self}, // the startup walk
		{Timestamp: ts, ActionType: models.FileWrite, Target: "/ws/a.txt", PID: 100},
		{Timestamp: ts, ActionType: models.NetConnect, Target: "example.com", PID: self}, // not a file event
	}
	kept, dropped, _ := scopeFSEvents(g, 100, "/ws")
	if dropped != 0 || len(kept) != 2 || kept[0].Target != "/ws/a.txt" || kept[1].Target != "example.com" {
		t.Errorf("kept=%v dropped=%d", kept, dropped)
	}
}

// An event the probe could not name (a delete whose parent directory was
// already gone) cannot be aligned and would make the file unreadable; it is
// counted by type in the scope record instead.
func TestDropUnresolvedFSEvents_CountsNamelessEvents(t *testing.T) {
	ts := time.Now()
	g := models.GroundTruth{
		{Timestamp: ts, ActionType: models.FileDelete, Target: "", PID: 100, PathIsAmbiguous: true},
		{Timestamp: ts, ActionType: models.FileDelete, Target: "", PID: 100, PathIsAmbiguous: true},
		{Timestamp: ts, ActionType: models.FileWrite, Target: "/ws/a", PID: 100},
	}
	kept, unresolved := dropUnresolvedFSEvents(g)
	if len(kept) != 1 || kept[0].Target != "/ws/a" || unresolved["file_delete"] != 2 || len(unresolved) != 1 {
		t.Errorf("kept=%v unresolved=%v", kept, unresolved)
	}
	if _, u := dropUnresolvedFSEvents(kept); u != nil {
		t.Error("a clean capture must record no unresolved map")
	}
}

// TestRunWatch_SnapshotsSensitiveFiles checks the snapshot of the harness's
// security-sensitive files (V-40): a declared file the agent changes is
// recorded with the key path and kind of the change and nothing of its
// content, and a declared file that is absent at both ends is recorded as
// missing with no change.
func TestRunWatch_SnapshotsSensitiveFiles(t *testing.T) {
	skipUnprivileged(t)

	ws, home := t.TempDir(), t.TempDir()
	cfg := filepath.Join(home, ".tool.json")
	if err := os.WriteFile(cfg, []byte(`{"permissions":{"allow":["Read"]},"n":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "ground_truth.json")
	opts := watchOptions{
		cfg:       watchConfig{Workspace: ws, EventBufSize: 256},
		probes:    "proc",
		out:       out,
		agentArgs: []string{"/bin/sh", "-c", `printf '{"permissions":{"allow":["Read","Bash(curl-secret)"]},"n":1}' > "$0"`, cfg},
		sensitive: []string{"~/.tool.json", "~/.absent.json"},
		agentHome: home,
	}
	if err := runWatch(opts); err != nil {
		t.Fatalf("runWatch: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "curl-secret") {
		t.Error("the capture holds content of a sensitive file")
	}
	file, err := models.ParseGroundTruthFile(data)
	if err != nil {
		t.Fatal(err)
	}
	if file.Sensitive == nil || file.Sensitive.Home != home || len(file.Sensitive.Files) != 2 {
		t.Fatalf("sensitive record = %+v, want both declared files under %s", file.Sensitive, home)
	}
	changed := file.Sensitive.Files[0]
	want := []models.SensitiveChange{{Key: []string{"permissions", "allow"}, Kind: models.SensitiveEntriesAdded, Entries: 1}}
	if changed.Path != cfg || changed.Start.State != models.SensitivePresent || changed.Start.Digest == changed.Stop.Digest ||
		len(changed.Changes) != 1 || changed.Changes[0].Kind != want[0].Kind || strings.Join(changed.Changes[0].Key, ".") != "permissions.allow" || changed.Changes[0].Entries != 1 {
		t.Errorf("changed file = %+v, want %+v", changed, want)
	}
	absent := file.Sensitive.Files[1]
	if absent.Start.State != models.SensitiveMissing || absent.Stop.State != models.SensitiveMissing || len(absent.Changes) != 0 {
		t.Errorf("absent file = %+v, want missing at both ends with no change", absent)
	}
}

func TestDeclaredSensitive(t *testing.T) {
	all, err := declaredSensitive("")
	if err != nil {
		t.Fatal(err)
	}
	has := func(files []string, f string) bool {
		for _, x := range files {
			if x == f {
				return true
			}
		}
		return false
	}
	if !has(all, "~/.claude.json") || !has(all, "~/.gemini/antigravity-cli/settings.json") {
		t.Errorf("every adapter's files = %v, want Claude Code's and agy's", all)
	}
	cc, err := declaredSensitive("claude-code")
	if err != nil || !has(cc, "~/.claude.json") || has(cc, "~/.gemini/antigravity-cli/settings.json") {
		t.Errorf("claude-code's files = %v, %v", cc, err)
	}
	if g, err := declaredSensitive("generic"); err != nil || len(g) != 0 {
		t.Errorf("generic's files = %v, %v, want none", g, err)
	}
	if _, err := declaredSensitive("nope"); err == nil {
		t.Error("an unknown agent is not refused")
	}
}

func TestResolveAgentHome(t *testing.T) {
	home := t.TempDir()
	got, owner, err := resolveAgentHome(home)
	if err != nil || got != home || owner != os.Getuid() {
		t.Errorf("resolveAgentHome(%s) = %s, %d, %v, want the directory and its owner %d", home, got, owner, err, os.Getuid())
	}
	f := filepath.Join(home, "file")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := resolveAgentHome(f); err == nil {
		t.Error("a file is accepted as a home")
	}
	t.Setenv("SUDO_UID", fmt.Sprint(os.Getuid()))
	if got, _, err := resolveAgentHome(""); err != nil || got == "" {
		t.Errorf("home of SUDO_UID = %q, %v", got, err)
	}
}

// The unresolved events the forest places in the agent's tree are counted
// apart, as event loss (V-39); every unresolved event, the tree's or not, is
// still left out of the capture.
func TestScopeFSEvents_CountsTheTreesUnresolvedEvents(t *testing.T) {
	const root, child, grandchild, stranger = 100, 200, 300, 900
	ts := time.Now()
	ev := func(typ models.ActionType, target string, pid, ppid uint32) models.GroundTruthEvent {
		return models.GroundTruthEvent{Timestamp: ts, ActionType: typ, Target: target, PID: pid, PPID: ppid}
	}
	g := models.GroundTruth{
		ev(models.ProcessFork, "200", child, root),
		ev(models.ProcessFork, "300", grandchild, child),
		ev(models.FileDelete, "", root, 0),           // the agent itself: counted
		ev(models.FileDelete, "", child, root),       // a command: counted
		ev(models.FileWrite, "", grandchild, 200),    // beneath a command: counted
		ev(models.FileDelete, "", stranger, 0),       // another process: not counted
		ev(models.FileDelete, "", 0, 0),              // no pid (the kernel): not counted
		ev(models.FileWrite, "/ws/a", root, 0),       // resolved: kept
		ev(models.FileDelete, "/etc/x", stranger, 0), // resolved, outside: dropped
	}
	kept, dropped, inTree := scopeFSEvents(g, root, "/ws")
	if inTree != 3 {
		t.Errorf("unresolvedInTree = %d, want 3", inTree)
	}
	if dropped != 1 {
		t.Errorf("dropped = %d, want 1: an unresolved event is not counted as outside the scope", dropped)
	}
	for _, e := range kept {
		if e.Target == "" {
			t.Errorf("an unresolved event was kept: %+v", e)
		}
	}
	if len(kept) != 3 {
		t.Errorf("kept = %v, want the two forks and /ws/a", kept)
	}
	if _, _, n := scopeFSEvents(g[len(g)-2:], root, "/ws"); n != 0 {
		t.Errorf("a capture with no unresolved event counted %d", n)
	}
}

// A real unresolved event, made by the kernel: a child deletes a file in a
// directory it removes before the probe reads the queue. The tree is outside
// the workspace, so the start walk never resolves it and the directory cache
// cannot name the delete (P-28). Placed in the tree by its pid, watch counts
// it, and the count makes the capture incomplete; rooted elsewhere, it stays
// a note.
func TestScopeFSEvents_CountsARealUnresolvedEventOfTheTree(t *testing.T) {
	skipUnprivileged(t)
	ws := t.TempDir()
	sub := filepath.Join(t.TempDir(), "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "leaf"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	o, err := probeBuilders["fs"](watchConfig{Workspace: ws, EventBufSize: 4096})
	if err != nil {
		t.Fatalf("fs builder: %v", err)
	}
	obs := o.(*fs.Observer)
	// The marks exist from New, so the kernel queues the child's records now
	// and the probe reads them only after Start, when sub is gone.
	rm := exec.Command("rm", "-rf", sub)
	if out, err := rm.CombinedOutput(); err != nil {
		t.Fatalf("rm: %v\n%s", err, out)
	}
	agent := uint32(rm.Process.Pid)

	var g models.GroundTruth
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for e := range o.Events() {
			if e.PID == agent {
				g = append(g, e)
			}
		}
	}()
	o.Start()
	// CI sets the bound, not the dev box: a contended runner reads the queue late.
	time.Sleep(500 * time.Millisecond)
	if err := o.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	<-drained

	_, _, inTree := scopeFSEvents(g, agent, ws)
	if inTree == 0 {
		t.Fatalf("no unresolved event of the tree counted; the child's events: %+v", g)
	}
	cov := obs.CaptureCoverage()
	if cov.UnresolvedPaths < uint64(inTree) {
		t.Errorf("UnresolvedPaths = %d < unresolvedInTree = %d: the tree's count must be a subset", cov.UnresolvedPaths, inTree)
	}
	cov.UnresolvedInTree = uint64(inTree)
	if c := verification.Assess(&models.Coverage{Schema: models.CoverageSchema, Probes: map[string]models.ProbeCoverage{"fs": cov}}); c.Complete {
		t.Errorf("Assess judged complete a capture that lost %d event(s) of the tree", inTree)
	}
	if _, _, n := scopeFSEvents(g, agent+1_000_000, ws); n != 0 {
		t.Errorf("rooted at another process, %d event(s) were counted as the tree's", n)
	}
}
