package scripts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	// The control is an interactive session too, typed by the driver on a
	// terminal of its own (I-163).
	if !control.StdinTTY || !control.StdoutTTY || strings.Contains(strings.Join(control.Args, " "), "-p ") || control.Args[len(control.Args)-2] != "--session-id" {
		t.Errorf("the control is not a driven interactive run: %+v", control)
	}
	if n := len(watchCalls(t, tmp)); n != 2 {
		t.Errorf("watch ran %d times, want 2", n)
	}
	wl, _ := os.ReadFile(filepath.Join(out, "basic.watch.log"))
	if !strings.HasPrefix(string(wl), "interactive run (I-159)") {
		t.Errorf("basic.watch.log: %q", wl)
	}
	if cl, _ := os.ReadFile(filepath.Join(out, "control-1.watch.log")); !strings.Contains(string(cl), "pty-drive: turn 2 ended") {
		t.Errorf("control-1.watch.log: %q", cl)
	}
	if sl, _ := os.ReadFile(filepath.Join(out, "control-1.pty.log")); !strings.Contains(string(sl), "Claude Code v2.1.306") {
		t.Errorf("control-1.pty.log: %q", sl)
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
	checkDrivenControls(t, tmp, out, 1)
	// The baseline and the session are both interactive: no mode warning;
	// the review closes the report.
	if strings.Contains(string(report), "V-103") || !strings.Contains(string(report), "##### review of the baseline's rules (report only, I-164)") {
		t.Errorf("report.txt:\n%s", report)
	}
	if !strings.Contains(string(meta), "\ncontrols=interactive driven prompts_sha256=") {
		t.Errorf("task-meta.txt:\n%s", meta)
	}
}

// checkDrivenControls checks what n driven controls leave (I-163): the
// driver's prompts typed in order after the trust dialog's keys, the
// control mode recorded with the prompts' hash, an interactive baseline,
// and a cost measurement that found watch, not the driver.
func checkDrivenControls(t *testing.T, tmp, out string, n int) {
	t.Helper()
	var prompts []string
	for _, r := range readTUILog(t, filepath.Join(tmp, "fake")) {
		if r.DialogKeys != "" && r.DialogKeys != "\x1b[B\r" {
			t.Errorf("dialog keys %q", r.DialogKeys)
		}
		if r.Prompt != "" {
			prompts = append(prompts, r.Prompt)
		}
	}
	cp, _ := os.ReadFile(filepath.Join(out, "control-prompt.txt"))
	want := strings.Repeat(string(cp)+"|Reply with the single word ok. Do not use any tool.|", n)
	if strings.Join(prompts, "|")+"|" != want || !strings.Contains(string(cp), "agent-trace-control-marker") {
		t.Errorf("prompts %q, want %d times the control prompt and the reply", prompts, n)
	}
	sum := sha256.Sum256([]byte(string(cp) + "\nReply with the single word ok. Do not use any tool.\n"))
	if m, _ := os.ReadFile(filepath.Join(out, "control-mode.txt")); string(m) != "interactive driven prompts_sha256="+hex.EncodeToString(sum[:]) {
		t.Errorf("control-mode.txt %q", m)
	}
	var b struct {
		Mode string `json:"mode"`
	}
	raw, _ := os.ReadFile(filepath.Join(out, "baseline.json"))
	if err := json.Unmarshal(raw, &b); err != nil || b.Mode != "interactive" {
		t.Errorf("baseline mode %q (%v)", b.Mode, err)
	}
	for i := 1; i <= n; i++ {
		c, _ := os.ReadFile(filepath.Join(out, fmt.Sprintf("control-%d.cost.json", i)))
		if strings.Contains(string(c), "not found") || !strings.Contains(string(c), `"watch_cpu_s"`) {
			t.Errorf("control-%d.cost.json: %s", i, c)
		}
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

// --controls-only (I-164) records the driven controls alone, with no task
// run and no terminal of the operator's, keeps the sudo credential for the
// whole loop (I-161), builds an interactive baseline and writes the verify
// command and the review; --review-against lists only what a print-mode
// baseline lacks.
func TestControlsOnlyRecordsTheInteractiveControls(t *testing.T) {
	root, tmp, env := layout(t, "")
	withoutWarmUp(t, root, "claude-code")
	write(t, filepath.Join(tmp, "bin", "sudo"), refreshingSudo, 0o755)
	printBase := filepath.Join(tmp, "print-baseline.json")
	write(t, printBase, `{"schema":1,"agent":"claude-code","agent_version":"2.1.306","runs":5,"min_agreement":0.2,"rules":[]}`, 0o644)
	out := filepath.Join(tmp, "out")
	cmd := exec.Command("bash", filepath.Join(root, "scripts", "capture-agent.sh"), "--no-build", "--interactive", "--controls-only", "--review-against", printBase, "--task", "basic", out)
	cmd.Env = append(env, "CONTROLS=2", "SUDO_REFRESH_S=1")
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("capture: %v\n%s", err, b)
	}
	runs := claudeRuns(t, tmp)
	if len(runs) != 2 {
		t.Fatalf("runs: %+v", runs)
	}
	if _, err := os.Stat(filepath.Join(out, "basic.ground_truth.json")); err == nil {
		t.Errorf("a controls-only capture recorded the task")
	}
	checkDrivenControls(t, tmp, out, 2)
	meta, _ := os.ReadFile(filepath.Join(out, "task-meta.txt"))
	if !strings.Contains(string(meta), "\ncontrols_only=on no task run\n") || strings.Contains(string(meta), "interactive=on") {
		t.Errorf("task-meta.txt:\n%s", meta)
	}
	report, _ := os.ReadFile(filepath.Join(out, "report.txt"))
	for _, w := range []string{"##### controls only (I-164)", "--baseline " + filepath.Join(out, "baseline.json") + " --interactive", "against:", "only what it lacks", "/home/shim/.claude/projects/"} {
		if !strings.Contains(string(report), w) {
			t.Errorf("report.txt lacks %q:\n%s", w, report)
		}
	}
	if r, _ := os.ReadFile(filepath.Join(tmp, "fake", "sudo.refresh")); !strings.Contains(string(r), "refresh") {
		t.Errorf("no credential refresh during the controls")
	}
}

// Driven controls and controls-only are refused where they cannot work:
// --controls-only with a task run's options, --review-against without
// driven controls, --controls-only --interactive on a profile without a
// driver, and controls of another mode from --baseline-from.
func TestDrivenControlsAreRefusedWhereTheyCannotWork(t *testing.T) {
	root, tmp, env := layout(t, "")
	run := func(args ...string) (string, int) {
		cmd := exec.Command("bash", append([]string{filepath.Join(root, "scripts", "capture-agent.sh"), "--no-build", "--task", "basic"}, args...)...)
		cmd.Env = env
		b, err := cmd.CombinedOutput()
		if ee, ok := err.(*exec.ExitError); ok {
			return string(b), ee.ExitCode()
		}
		return string(b), 0
	}
	out := filepath.Join(tmp, "out")
	if log, code := run("--controls-only", "--controls-before", "1", out); code != 2 || !strings.Contains(log, "records the control runs alone") {
		t.Errorf("--controls-before: exit %d\n%s", code, log)
	}
	if log, code := run("--review-against", "/nonexistent", out); code != 2 || !strings.Contains(log, "this capture records none") {
		t.Errorf("--review-against: exit %d\n%s", code, log)
	}
	if log, code := run("--interactive", "--check", out); code != 0 || !strings.Contains(log, "\ncontrols=interactive driven prompts_sha256=") {
		t.Errorf("--check: exit %d\n%s", code, log)
	}
	// Print-mode controls on disk, offered to an interactive capture.
	prev := filepath.Join(tmp, "prev")
	for f, c := range map[string]string{"control-1.ground_truth.json": "{}", "control-agent.txt": "claude-code", "control-tools.txt": "Read Write Edit Bash", "control-version.txt": "2.1.306", "control-model.txt": "claude-sonnet-5-5"} {
		write(t, filepath.Join(prev, f), c, 0o644)
	}
	b, _ := exec.Command("python3", "-c", "import json,sys;print(json.load(open(sys.argv[1]))['adapters']['claude-code']['controls']['prompt'].replace('{command}', ': agent-trace-control-marker'), end='')", filepath.Join(root, "config", "agents.json")).Output()
	write(t, filepath.Join(prev, "control-prompt.txt"), string(b), 0o644)
	if log, code := run("--check", "--baseline-from", prev, out); code != 0 {
		t.Fatalf("print controls for a print capture: exit %d\n%s", code, log)
	}
	if log, code := run("--interactive", "--check", "--baseline-from", prev, out); code != 1 || !strings.Contains(log, "a baseline holds for one control mode") {
		t.Errorf("print controls for an interactive capture: exit %d\n%s", code, log)
	}
	editProfile(t, root, "claude-code", func(p map[string]any) { delete(p["interactive"].(map[string]any), "driver") })
	if log, code := run("--interactive", "--controls-only", out); code != 2 || !strings.Contains(log, "names no interactive.driver") {
		t.Errorf("no driver: exit %d\n%s", code, log)
	}
	if log, code := run("--interactive", "--check", out); code != 0 || !strings.Contains(log, "\ncontrols=print\n") {
		t.Errorf("no driver --check: exit %d\n%s", code, log)
	}
	if _, err := os.Stat(out); err == nil {
		t.Errorf("a refused capture created %s", out)
	}
}
