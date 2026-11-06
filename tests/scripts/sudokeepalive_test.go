package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// refreshingSudo is the sudo shim that also records every credential
// refresh, sudo -n -v.
const refreshingSudo = `#!/usr/bin/env bash
[ "$*" != "-n -v" ] || echo refresh >>"$FAKE_DIR/sudo.refresh"
while [ $# -gt 0 ]; do case $1 in -*) shift ;; *) break ;; esac; done
[ $# -eq 0 ] || exec "$@"
`

// The capture refreshes the sudo credential while it runs, so the sudo -n
// steps after a run longer than sudo's timeout still have one, and stops
// refreshing when it exits (I-161).
func TestTheCaptureKeepsTheSudoCredentialWhileItRuns(t *testing.T) {
	root, tmp, env := layout(t, "slow")
	write(t, filepath.Join(tmp, "bin", "sudo"), refreshingSudo, 0o755)
	cmd := exec.Command("bash", filepath.Join(root, "scripts", "capture-agent.sh"), "--no-build", "--task", "basic", filepath.Join(tmp, "out"))
	cmd.Env = append(env, "SUDO_REFRESH_S=1")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("capture: %v\n%s", err, b)
	}
	refreshes := func() int {
		b, _ := os.ReadFile(filepath.Join(tmp, "fake", "sudo.refresh"))
		return strings.Count(string(b), "refresh")
	}
	n := refreshes()
	if n == 0 {
		t.Fatalf("no credential refresh during a capture whose task run lasted 3 s")
	}
	time.Sleep(2500 * time.Millisecond)
	if m := refreshes(); m != n {
		t.Errorf("%d refreshes after the capture exited, want none", m-n)
	}
}
