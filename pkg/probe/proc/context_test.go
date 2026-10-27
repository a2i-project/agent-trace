package proc

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// execsWithNonce runs cmds under a tracked observer and returns the exec
// events whose target contains nonce.
func execsWithNonce(t *testing.T, nonce string, cmds ...*exec.Cmd) []models.GroundTruthEvent {
	t.Helper()
	var out []models.GroundTruthEvent
	for _, es := range runTracked(t, cmds) {
		for _, e := range es {
			if e.ActionType == models.ProcessExec && strings.Contains(e.Target, nonce) {
				out = append(out, e)
			}
		}
	}
	return out
}

// realPath resolves p's symbolic links, as the kernel's walk does.
func realPath(t *testing.T, p string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatalf("EvalSymlinks(%s): %v", p, err)
	}
	return r
}

// A relative program path is relative to the working directory, which the
// exec record now carries (P-36); the success record names the file the new
// image runs, with its links resolved, and the kernel's filename, which is
// the one the probe read.
func TestObserver_RelativeExecReportsItsCwd(t *testing.T) {
	skipUnprivileged(t)
	dir := t.TempDir()
	if err := os.Symlink("/bin/true", filepath.Join(dir, "x")); err != nil {
		t.Fatal(err)
	}
	nonce := fmt.Sprintf("agenttrace-cwd-%d", time.Now().UnixNano())
	got := execsWithNonce(t, nonce, exec.Command("/bin/sh", "-c", fmt.Sprintf("cd '%s' && ./x %s", dir, nonce)))
	var e *models.GroundTruthEvent
	for i := range got {
		if got[i].Target == "./x "+nonce {
			e = &got[i]
		}
	}
	if e == nil {
		t.Fatalf("no exec of ./x %s among %+v", nonce, got)
	}
	if want := realPath(t, dir); e.Cwd != want || e.CwdTruncated {
		t.Errorf("cwd %q (truncated %v), want %q", e.Cwd, e.CwdTruncated, want)
	}
	if e.Image == nil {
		t.Fatalf("the exec took effect but carries no image")
	}
	if want := realPath(t, "/bin/true"); e.Image.Program != want || e.Image.Filename != "./x" || e.Image.FilenameChanged || e.Image.Truncated {
		t.Errorf("image %+v, want program %q and filename ./x, unchanged and whole", *e.Image, want)
	}
}

// The walk crosses mounts: a directory on a filesystem mounted below the
// root is named through its mount point (P-36).
func TestObserver_CwdAcrossMounts(t *testing.T) {
	skipUnprivileged(t)
	nonce := fmt.Sprintf("agenttrace-mnt-%d", time.Now().UnixNano())
	var dirs []string
	var cmds []*exec.Cmd
	for _, d := range []string{"/proc/sys", "/sys/kernel", "/dev/shm"} {
		if st, err := os.Stat(d); err != nil || !st.IsDir() {
			continue
		}
		d = realPath(t, d)
		dirs = append(dirs, d)
		cmds = append(cmds, exec.Command("/bin/sh", "-c", fmt.Sprintf("cd '%s' && /bin/true %s-%d", d, nonce, len(dirs)-1)))
	}
	if len(dirs) == 0 {
		t.Skip("none of /proc/sys, /sys/kernel, /dev/shm exists")
	}
	got := execsWithNonce(t, nonce, cmds...)
	for i, d := range dirs {
		target := fmt.Sprintf("/bin/true %s-%d", nonce, i)
		seen := false
		for _, e := range got {
			if e.Target != target {
				continue
			}
			seen = true
			if e.Cwd != d || e.CwdTruncated {
				t.Errorf("%s: cwd %q (truncated %v), want %q", target, e.Cwd, e.CwdTruncated, d)
			}
		}
		if !seen {
			t.Errorf("no exec of %s", target)
		}
	}
}

// A working directory deeper than the walk's 32 steps is flagged, and the
// probe keeps its deepest names (P-36): 40 names below the temporary
// directory, itself at least two below the root.
func TestObserver_DeepCwdIsFlagged(t *testing.T) {
	skipUnprivileged(t)
	deep := realPath(t, t.TempDir())
	for i := 0; i < 40; i++ {
		deep = filepath.Join(deep, fmt.Sprintf("d%d", i))
	}
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	nonce := fmt.Sprintf("agenttrace-deep-%d", time.Now().UnixNano())
	got := execsWithNonce(t, nonce, exec.Command("/bin/sh", "-c", fmt.Sprintf("cd '%s' && /bin/true %s", deep, nonce)))
	seen := false
	for _, e := range got {
		// The shell's own exec names the nonce too, in its command
		// string, and runs in the test's directory.
		if e.Target != "/bin/true "+nonce {
			continue
		}
		seen = true
		if !e.CwdTruncated {
			t.Errorf("cwd %q of a %d-byte path not flagged", e.Cwd, len(deep))
			continue
		}
		if e.Cwd == "" || strings.HasPrefix(e.Cwd, "/") || !strings.HasSuffix(deep, "/"+e.Cwd) {
			t.Errorf("cut cwd %q is not the end of %q without a leading slash", e.Cwd, deep)
		}
	}
	if !seen {
		t.Errorf("no exec of /bin/true %s among %+v", nonce, got)
	}
}

// An exec through a descriptor names no path at entry, and the kernel names
// it /dev/fd/N; the success record names the program the descriptor opened
// (P-36, the limit P-21 recorded).
func TestObserver_FexecveNamesItsProgram(t *testing.T) {
	skipUnprivileged(t)
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not installed")
	}
	nonce := fmt.Sprintf("agenttrace-fexecve-image-%d", time.Now().UnixNano())
	script := fmt.Sprintf("import os; fd = os.open('/bin/true', os.O_RDONLY); os.execve(fd, ['true', %q], os.environ)", nonce)
	got := execsWithNonce(t, nonce, exec.Command("python3", "-c", script))
	var e *models.GroundTruthEvent
	for i := range got {
		if got[i].Target == "(fexecve) "+nonce {
			e = &got[i]
		}
	}
	if e == nil {
		t.Fatalf("no exec of (fexecve) %s among %+v", nonce, got)
	}
	if e.Image == nil {
		t.Fatalf("the exec took effect but carries no image")
	}
	if want := realPath(t, "/bin/true"); e.Image.Program != want {
		t.Errorf("program %q, want %q", e.Image.Program, want)
	}
	if !strings.HasPrefix(e.Image.Filename, "/dev/fd/") || e.Image.FilenameChanged {
		t.Errorf("image %+v, want a /dev/fd/N filename that is not a change", *e.Image)
	}
}

// A script runs its interpreter: the success record names the interpreter
// as the script's first line wrote it, and the program is the interpreter's
// file (P-36).
func TestObserver_ScriptNamesItsInterpreter(t *testing.T) {
	skipUnprivileged(t)
	script := filepath.Join(t.TempDir(), "run.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	nonce := fmt.Sprintf("agenttrace-script-%d", time.Now().UnixNano())
	got := execsWithNonce(t, nonce, exec.Command(script, nonce))
	var e *models.GroundTruthEvent
	for i := range got {
		if got[i].Target == script+" "+nonce {
			e = &got[i]
		}
	}
	if e == nil {
		t.Fatalf("no exec of %s %s among %+v", script, nonce, got)
	}
	if e.Image == nil {
		t.Fatalf("the exec took effect but carries no image")
	}
	want := models.ExecImage{Filename: script, Interpreter: "/bin/sh", Program: realPath(t, "/bin/sh")}
	if *e.Image != want {
		t.Errorf("image %+v, want %+v", *e.Image, want)
	}
}

// A failed attempt carries no image and is still recorded (P-4), released
// when its process's records end or at Stop (P-36).
func TestObserver_FailedExecHasNoImage(t *testing.T) {
	skipUnprivileged(t)
	nonce := fmt.Sprintf("agenttrace-noimage-%d", time.Now().UnixNano())
	got := execsWithNonce(t, nonce, exec.Command("/bin/sh", "-c", fmt.Sprintf("/nonexistent-%s a 2>/dev/null; /bin/true %s", nonce, nonce)))
	var failed, ok bool
	for _, e := range got {
		switch e.Target {
		case "/nonexistent-" + nonce + " a":
			failed = true
			if e.Image != nil {
				t.Errorf("the failed attempt carries an image: %+v", *e.Image)
			}
			if e.Cwd == "" {
				t.Errorf("the failed attempt carries no cwd")
			}
		case "/bin/true " + nonce:
			ok = true
			if e.Image == nil {
				t.Errorf("the exec of /bin/true carries no image")
			}
		}
	}
	if !failed || !ok {
		t.Errorf("failed attempt seen %v, successful exec seen %v, want both", failed, ok)
	}
}
