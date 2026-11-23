package e2e

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/probe/fs"
	probenet "github.com/agent-trace/agent-trace/pkg/probe/net"
	"github.com/agent-trace/agent-trace/pkg/probe/proc"
)

// Environment of TestHelperWriteThenAct.
const (
	writeThenActFile = "AGENT_TRACE_WRITE_THEN_ACT_FILE"
	writeThenActDial = "AGENT_TRACE_WRITE_THEN_ACT_DIAL"
)

// TestHelperWriteThenAct is the child of TestKernelClock_FileEventsOrderBeforeTheExecOrConnectThatFollows:
// it writes a file, then execs /bin/true or connects to an address and
// sends a byte. It does nothing unless run as that child.
func TestHelperWriteThenAct(t *testing.T) {
	target := os.Getenv(writeThenActFile)
	if target == "" {
		return
	}
	if err := os.WriteFile(target, []byte("written before the next action\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if addr := os.Getenv(writeThenActDial); addr != "" {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = c.Write([]byte{1})
		_ = c.Close()
		return
	}
	if err := syscall.Exec("/bin/true", []string{"true"}, os.Environ()); err != nil {
		t.Fatal(err)
	}
}

// P-55 with P-54 and N-56, as root on a kernel that can attach the kernel
// clock: a process that writes a file and then execs, or writes a file and
// then connects, has its file events ordered before the exec or the connect
// on the shared clock, every time, and every file event is a point
// (NotBefore equals Timestamp). The read-time clock could not promise this:
// it stamps a record when the probe reads it, which can be after the exec's
// kernel stamp. Twenty children of each kind run under one root, each
// writing its own file.
func TestKernelClock_FileEventsOrderBeforeTheExecOrConnectThatFollows(t *testing.T) {
	skipUnprivileged(t)
	const runs = 20
	workspace := t.TempDir()

	fsObs, err := fs.New(fs.Config{Path: workspace, PathFilter: workspace, EventBufSize: 4096, KernelClock: true})
	if err != nil {
		t.Fatalf("fs.New: %v", err)
	}
	if running, why := fsObs.KernelClockState(); !running {
		fsObs.Start()
		_ = fsObs.Stop()
		t.Skipf("the kernel clock cannot run here: %s", why)
	}
	procObs, err := proc.New(proc.Config{EventBufSize: 1024, DeferRootPID: true})
	if err != nil {
		t.Fatalf("proc.New: %v", err)
	}
	netObs, err := probenet.New(probenet.Config{EventBufSize: 1024})
	if err != nil {
		t.Fatalf("probenet.New: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(io.Discard, c); _ = c.Close() }()
		}
	}()
	fsObs.Start()
	time.Sleep(200 * time.Millisecond)

	// The root waits on its stdin until both probes track it.
	var script strings.Builder
	script.WriteString("read go\n")
	for i := 0; i < runs; i++ {
		fmt.Fprintf(&script, "%s=%s %q -test.run='^TestHelperWriteThenAct$'\n", writeThenActFile, filepath.Join(workspace, fmt.Sprintf("exec-%02d", i)), os.Args[0])
		fmt.Fprintf(&script, "%s=%s %s=%s %q -test.run='^TestHelperWriteThenAct$'\n", writeThenActFile, filepath.Join(workspace, fmt.Sprintf("dial-%02d", i)), writeThenActDial, ln.Addr().String(), os.Args[0])
	}
	cmd := exec.Command("sh", "-c", script.String())
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	root := int32(cmd.Process.Pid)
	if err := procObs.SetRootPID(root); err != nil {
		t.Fatalf("SetRootPID: %v", err)
	}
	procObs.Start()
	if err := netObs.TrackPID(root); err != nil {
		t.Fatalf("TrackPID: %v", err)
	}
	go netObs.Start()
	_, _ = stdin.Write([]byte("go\n"))
	_ = stdin.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("children: %v", err)
	}
	// CI sets this bound: the trailing records must drain on a loaded runner.
	time.Sleep(time.Second)
	for _, s := range []interface{ Stop() error }{fsObs, procObs, netObs} {
		if err := s.Stop(); err != nil {
			t.Fatalf("Stop: %v", err)
		}
	}

	files := map[string][]models.GroundTruthEvent{} // by path
	after := map[uint32]time.Time{}                 // the exec of /bin/true or the connect, by pid
	for e := range fsObs.Events() {
		files[e.Target] = append(files[e.Target], e)
	}
	for e := range procObs.Events() {
		if e.ActionType == models.ProcessExec && strings.Contains(e.Target, "true") {
			after[e.PID] = e.Timestamp
		}
	}
	for e := range netObs.Events() {
		if e.ActionType == models.NetConnect || e.ActionType == models.NetDial {
			after[e.PID] = e.Timestamp
		}
	}
	if cov := fsObs.CaptureCoverage(); cov.Diagnostics == nil || cov.Diagnostics.Rings["fs_clock"].Records == 0 {
		t.Errorf("the coverage record does not show the kernel clock's ring: %+v", cov.Diagnostics)
	}

	checked := 0
	for i := 0; i < runs; i++ {
		for _, kind := range []string{"exec", "dial"} {
			path := filepath.Join(workspace, fmt.Sprintf("%s-%02d", kind, i))
			evs := files[path]
			if len(evs) == 0 {
				t.Errorf("%s: no file event", path)
				continue
			}
			pid := evs[0].PID
			next, ok := after[pid]
			if !ok {
				t.Errorf("%s: no %s of pid %d", path, kind, pid)
				continue
			}
			for _, e := range evs {
				if e.NotBefore == nil || !e.NotBefore.Equal(e.Timestamp) {
					t.Errorf("%s %s: bounds [%v, %v], want a point", e.ActionType, path, e.NotBefore, e.Timestamp)
				}
				if !e.Timestamp.Before(next) {
					t.Errorf("%s %s at %v is not before the %s at %v", e.ActionType, path, e.Timestamp, kind, next)
				}
			}
			checked++
		}
	}
	t.Logf("%d of %d children had their file events before their exec or connect", checked, 2*runs)
}
