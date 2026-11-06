package scripts

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// claudeRun is one run of the fake Claude Code: its arguments and whether
// its stdin and stdout were terminals.
type claudeRun struct {
	Args      []string `json:"args"`
	StdinTTY  bool     `json:"stdin_tty"`
	StdoutTTY bool     `json:"stdout_tty"`
}

func claudeRuns(t *testing.T, tmp string) []claudeRun {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(tmp, "fake", "claude.runs"))
	if err != nil {
		t.Fatal(err)
	}
	var runs []claudeRun
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var r claudeRun
		if err := json.Unmarshal([]byte(l), &r); err != nil {
			t.Fatal(err)
		}
		runs = append(runs, r)
	}
	return runs
}

// onTerminal runs bash with args under script(1), which gives it a
// pseudo-terminal on stdin and stdout, and returns what it printed.
func onTerminal(t *testing.T, env []string, args ...string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("script"); err != nil {
		t.Skip("script(1) is not installed")
	}
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
	}
	cmd := exec.Command("script", "-qec", "bash "+strings.Join(quoted, " "), "/dev/null")
	cmd.Env = append(env, "SHELL=/bin/bash")
	cmd.Stdin = strings.NewReader("")
	b, err := cmd.CombinedOutput()
	return string(b), err
}

// --interactive (I-159) runs the task with the profile's interactive
// invocation on the operator's terminal, with no prompt and no print mode,
// and the controls as always; task-meta.txt records it, the task's
// watch.log says where its output went, and the report adds the verdict
// with the start-up window (V-82).
func TestAnInteractiveTaskRunsOnTheTerminal(t *testing.T) {
	root, tmp, env := layout(t, "")
	if err := os.Rename(filepath.Join(root, "watch"), filepath.Join(root, "watch.real")); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(root, "watch"), recordingWatch, 0o755)
	withoutWarmUp(t, root, "claude-code")
	out := filepath.Join(tmp, "out")
	log, err := onTerminal(t, env, filepath.Join(root, "scripts", "capture-agent.sh"), "--no-build", "--interactive", "--task", "basic", out)
	if err != nil {
		t.Fatalf("capture: %v\n%s", err, log)
	}
	if !strings.Contains(log, "interactive: claude-code starts on this terminal") {
		t.Errorf("no word to the operator:\n%s", log)
	}
	runs := claudeRuns(t, tmp)
	if len(runs) != 2 {
		t.Fatalf("runs: %+v", runs)
	}
	task, control := runs[0], runs[1]
	if !task.StdinTTY || !task.StdoutTTY {
		t.Errorf("the task run had no terminal: %+v", task)
	}
	if strings.Contains(strings.Join(task.Args, " "), "-p ") || task.Args[len(task.Args)-2] != "--session-id" {
		t.Errorf("the task run is not the interactive invocation: %q", task.Args)
	}
	for _, w := range []string{"--setting-sources", "--model", "--allowedTools"} {
		if !strings.Contains(strings.Join(task.Args, " "), w) {
			t.Errorf("the task run lacks %s: %q", w, task.Args)
		}
	}
	// Claude Code's profile passes stdin through (stdin inherit), as before.
	if control.StdoutTTY || control.Args[0] != "-p" || !strings.Contains(control.Args[len(control.Args)-1], "agent-trace-control-marker") {
		t.Errorf("the control is not the scripted run: %+v", control)
	}
	if n := len(watchCalls(t, tmp)); n != 2 {
		t.Errorf("watch ran %d times, want 2", n)
	}
	wl, _ := os.ReadFile(filepath.Join(out, "basic.watch.log"))
	if !strings.HasPrefix(string(wl), "interactive run (I-159)") {
		t.Errorf("basic.watch.log: %q", wl)
	}
	if cl, _ := os.ReadFile(filepath.Join(out, "control-1.watch.log")); strings.Contains(string(cl), "interactive") {
		t.Errorf("control-1.watch.log: %q", cl)
	}
	meta, _ := os.ReadFile(filepath.Join(out, "task-meta.txt"))
	if !strings.Contains(string(meta), "\ninteractive=on ") {
		t.Errorf("task-meta.txt:\n%s", meta)
	}
	report, _ := os.ReadFile(filepath.Join(out, "report.txt"))
	if !strings.Contains(string(report), "##### verify WITH the baseline and the start-up window (V-82)") {
		t.Errorf("report.txt has no start-up window verdict:\n%s", report)
	}
	if _, err := os.Stat(filepath.Join(out, "verify-baseline-startup.json")); err != nil {
		t.Errorf("no verify-baseline-startup.json: %v", err)
	}
}

// A capture without --interactive is unchanged: no third verdict, nothing in
// task-meta.txt, and its runs get no terminal from the script.
func TestACaptureWithoutInteractiveIsUnchanged(t *testing.T) {
	out, log, code := runCapture(t, "")
	if code != 0 {
		t.Fatalf("capture: exit %d\n%s", code, log)
	}
	report, _ := os.ReadFile(filepath.Join(out, "report.txt"))
	meta, _ := os.ReadFile(filepath.Join(out, "task-meta.txt"))
	if strings.Contains(string(report), "start-up window") || strings.Contains(string(meta), "interactive") {
		t.Errorf("a scripted capture mentions interactive:\n%s\n%s", report, meta)
	}
	if _, err := os.Stat(filepath.Join(out, "verify-baseline-startup.json")); err == nil {
		t.Errorf("a scripted capture wrote verify-baseline-startup.json")
	}
}

// --interactive is refused for a profile without an interactive invocation
// and without a terminal; --check prints it without one.
func TestAnInteractiveCaptureIsRefusedWhereItCannotRun(t *testing.T) {
	root, tmp, env := layout(t, "")
	run := func(args ...string) (string, int) {
		cmd := exec.Command("bash", append([]string{filepath.Join(root, "scripts", "capture-agent.sh"), "--no-build"}, args...)...)
		cmd.Env = append(env, "SCILIFELAB_API_KEY="+testKey)
		b, err := cmd.CombinedOutput()
		if ee, ok := err.(*exec.ExitError); ok {
			return string(b), ee.ExitCode()
		}
		return string(b), 0
	}
	out := filepath.Join(tmp, "out")
	if log, code := run("--interactive", "--task", "basic", out); code != 2 || !strings.Contains(log, "needs a terminal on stdin and stdout") {
		t.Errorf("no terminal: exit %d\n%s", code, log)
	}
	if log, code := run("--agent", "opencode", "--interactive", "--task", "basic", "--allow-unconfigured-version", out); code != 2 || !strings.Contains(log, "names no interactive invocation") {
		t.Errorf("opencode: exit %d\n%s", code, log)
	}
	if log, code := run("--interactive", "--task", "basic", "--check", out); code != 0 || !strings.Contains(log, "\ninteractive=on\n") {
		t.Errorf("--check: exit %d\n%s", code, log)
	}
	if _, err := os.Stat(out); err == nil {
		t.Errorf("a refused capture created %s", out)
	}
}

// The profile's interactive invocation names no prompt, needs the assigned
// session method and cannot go with secret_env (I-159).
func TestTheInteractiveInvocationIsCheckedInTheProfile(t *testing.T) {
	cases := []struct {
		agent string
		edit  func(p map[string]any)
		want  string
	}{
		{"claude-code", func(p map[string]any) {
			p["interactive"] = map[string]any{"invocation": []any{"--session-id", "{session}", "{prompt}"}}
		}, "names {prompt}"},
		{"claude-code", func(p map[string]any) {
			p["interactive"] = map[string]any{"invocation": []any{"{nothing}"}}
		}, "placeholder {nothing}"},
		{"claude-code", func(p map[string]any) { p["interactive"] = map[string]any{"note": "x"} }, "interactive needs an invocation"},
		{"codex", func(p map[string]any) {
			p["interactive"] = map[string]any{"invocation": []any{"{model}"}}
		}, "session method assigned"},
		{"opencode", func(p map[string]any) {
			p["session"] = map[string]any{"method": "assigned"}
			p["interactive"] = map[string]any{"invocation": []any{"{model}"}}
		}, "cannot pass secret_env"},
	}
	for _, c := range cases {
		root, _, _ := layout(t, "")
		editProfile(t, root, c.agent, c.edit)
		cmd := exec.Command("python3", filepath.Join(root, "scripts", "agent-profile.py"), "shell", filepath.Join(root, "config", "agents.json"), c.agent, "basic")
		b, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(b), c.want) {
			t.Errorf("%s: %v %s, want %q", c.agent, err, b, c.want)
		}
	}
}
