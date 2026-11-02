package proc

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestObserver_RecordsTheRootsLastImage holds a shell as the root, as watch
// holds the agent before its exec, then lets it exec sleep and exit. The
// root's exec is never an event, and RootImage names the program it ran,
// its path resolved (P-46).
func TestObserver_RecordsTheRootsLastImage(t *testing.T) {
	skipUnprivileged(t)
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep on PATH")
	}
	want, err := filepath.EvalSymlinks(sleep)
	if err != nil {
		t.Fatal(err)
	}
	obs, err := New(Config{EventBufSize: 512, DeferRootPID: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cmd := exec.Command("/bin/sh", "-c", "read x; exec "+sleep+" 0.2")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if err := obs.SetRootPID(int32(cmd.Process.Pid)); err != nil {
		t.Fatalf("SetRootPID: %v", err)
	}
	obs.Start()
	if obs.RootImage() != nil {
		t.Error("an image before the root exec'd")
	}
	_, _ = stdin.Write([]byte("go\n"))
	_ = stdin.Close()
	_ = cmd.Wait()
	time.Sleep(300 * time.Millisecond)
	if err := obs.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	for _, e := range collect(obs) {
		if e.PID == uint32(cmd.Process.Pid) {
			t.Errorf("an event of the root: %+v", e)
		}
	}
	img := obs.RootImage()
	if img == nil || img.Program != want || !strings.HasSuffix(img.Filename, "sleep") || img.Truncated {
		t.Fatalf("root image %+v, want program %s", img, want)
	}
}
