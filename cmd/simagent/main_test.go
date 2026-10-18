package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestMain runs main itself when the test binary is re-executed with
// SIMAGENT_RUN_MAIN set, so the tests below can check exit codes without
// building a separate binary.
func TestMain(m *testing.M) {
	if os.Getenv("SIMAGENT_RUN_MAIN") == "1" {
		os.Args = append([]string{"simagent"}, strings.Split(os.Getenv("SIMAGENT_ARGS"), "\n")...)
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// runSimagent runs main in a child process with args and returns its exit
// code and combined output.
func runSimagent(t *testing.T, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "SIMAGENT_RUN_MAIN=1", "SIMAGENT_ARGS="+strings.Join(args, "\n"))
	out, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return 0, string(out)
	case errors.As(err, &exitErr):
		return exitErr.ExitCode(), string(out)
	default:
		t.Fatalf("run simagent: %v", err)
		return 0, ""
	}
}

func TestCheckAttack(t *testing.T) {
	for _, name := range append([]string{""}, attacks...) {
		if err := checkAttack(name); err != nil {
			t.Errorf("checkAttack(%q) = %v, want nil", name, err)
		}
	}
	for _, name := range []string{"omision", "Omission", "substitution", "net", " omission"} {
		if err := checkAttack(name); err == nil {
			t.Errorf("checkAttack(%q) = nil, want an error", name)
		}
	}
}

// TestUnknownAttackIsAUsageError checks that a mistyped --attack stops the
// run before anything is done or written, with the usage exit code.
func TestUnknownAttackIsAUsageError(t *testing.T) {
	ws := t.TempDir()
	traj := filepath.Join(t.TempDir(), "trajectory.json")
	code, out := runSimagent(t, "--workspace", ws, "--trajectory-out", traj, "--file-only", "--attack", "omision")
	if code != exitUsage {
		t.Fatalf("exit code %d, want %d\n%s", code, exitUsage, out)
	}
	if !strings.Contains(out, `unknown --attack "omision"`) || !strings.Contains(out, "Usage") {
		t.Errorf("output lacks the usage error:\n%s", out)
	}
	if _, err := os.Stat(traj); !os.IsNotExist(err) {
		t.Errorf("trajectory written despite the usage error (stat: %v)", err)
	}
	if entries, _ := os.ReadDir(ws); len(entries) != 0 {
		t.Errorf("workspace touched despite the usage error: %d entries", len(entries))
	}
}

// TestListedAttacksAreAccepted runs the file-only script once per listed
// value: each still runs to completion and writes its trajectory.
func TestListedAttacksAreAccepted(t *testing.T) {
	for _, name := range attacks {
		t.Run(name, func(t *testing.T) {
			traj := filepath.Join(t.TempDir(), "trajectory.json")
			code, out := runSimagent(t, "--workspace", t.TempDir(), "--trajectory-out", traj, "--file-only", "--attack", name)
			if code != 0 {
				t.Fatalf("exit code %d, want 0\n%s", code, out)
			}
			if _, err := os.Stat(traj); err != nil {
				t.Errorf("no trajectory written: %v", err)
			}
		})
	}
}
