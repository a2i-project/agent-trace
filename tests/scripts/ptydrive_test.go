package scripts

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// fakeTUI stands in for an interactive agent on a terminal: it records its
// window size, shows a trust dialog drawn with cursor moves and escape
// sequences and options unnumbered as 2.1.306 draws them, draws it again with the cursor on the second option at Down,
// exits on Enter with the cursor on the first (as Claude Code 2.1.306 does)
// and goes on with it on the second; it then shows a banner with an input glyph and
// echoes what is typed. Each line typed is a prompt: after a second it
// appends to --file a user record, a sidechain end_turn and one assistant
// message written as two end_turn records with one id, and records whether
// input arrived while the turn ran. As Claude Code 2.1.306 under
// --disable-slash-commands, /exit is an unknown command, and only two
// Ctrl-D on an empty input within half a second exit (with $FAKE_TUI_EXIT);
// one alone prints "Press Ctrl-D again to exit".
// FAKE_TUI_MODE: reset draws the dialog once more with the cursor back on
// the first option 0.2 s after the first Down (as 2.1.306 did on
// 2026-11-11), resetalways after every Down, noselect never draws it
// again; noready shows no banner, noturn writes no end_turn, stuck
// never exits. Everything it sees goes to $FAKE_DIR/tui.log.
const fakeTUI = `#!/usr/bin/env python3
import json, os, select, sys, time, tty
args = sys.argv[1:]
path = args[args.index("--file") + 1]
model = args[args.index("--model") + 1] if "--model" in args else "m"
sid = os.path.basename(path)[:-len(".jsonl")]
mode = os.environ.get("FAKE_TUI_MODE", "")
rec = open(os.path.join(os.environ["FAKE_DIR"], "tui.log"), "a")
def log(**k):
    rec.write(json.dumps(k) + "\n"); rec.flush()
def out(s):
    os.write(1, s.encode())
size = os.get_terminal_size(1)
log(columns=size.columns, lines=size.lines, term=os.environ.get("TERM", ""))
tty.setraw(0)
def dialog(cursor):
    mark = ["\x1b[32m\u276f\x1b[0m" if cursor == i else " " for i in (0, 1)]
    out("\x1b[2;1H%s No, exit\x1b[K\r\n%s Yes,\x1b[1CI\x1b[1Ctrust\x1b[1Cthis\x1b[1Cfolder\x1b[K\r\n" % tuple(mark))
out("\x1b[2J\x1b[H\x1b]0;fake\x07Do\x1b[1Cyou\x1b[1Ctrust\x1b[1Cthe\x1b[1Cfiles?\r\n")
dialog(0)
keys, cursor, resets = b"", 0, {"reset": 1, "resetalways": 99}.get(mode, 0)
while not keys.endswith(b"\r"):
    data = os.read(0, 64)
    keys += data
    for _ in range(data.count(b"\x1b[B")):
        cursor = 1
        if mode != "noselect":
            dialog(1)
        if resets:
            resets -= 1
            time.sleep(0.2)
            cursor = 0
            dialog(0)
log(dialog_keys=keys.decode())
if cursor != 1 or keys.replace(b"\x1b[B", b"") != b"\r":
    out("bye\r\n"); sys.exit(1)
if mode == "noready":
    time.sleep(30); sys.exit(0)
out("\x1b[2J\x1b[H\x1b[1mClaude Code\x1b[0m v2.1.306\r\n\x1b[2C\u276f ")
n, buf, ctrl_d = 0, b"", None
def append(*recs):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a") as f:
        for r in recs:
            f.write(json.dumps(r) + "\n")
while True:
    data = os.read(0, 1024)
    if not data:
        sys.exit(3)
    now = time.monotonic()
    for ch in data:
        if ch == 4 and not buf:
            if ctrl_d is not None and now - ctrl_d <= 0.5:
                log(exit=True)
                if mode == "stuck":
                    ctrl_d = None
                    continue
                out("\r\nbye\r\n"); sys.exit(int(os.environ.get("FAKE_TUI_EXIT", "0")))
            ctrl_d = now
            out("\r\nPress Ctrl-D again to exit\r\n")
            continue
        if ch != 13:
            buf += bytes([ch]); out(bytes([ch]).decode(errors="replace")); continue
        text, buf = buf.decode(), b""
        if text.startswith("/"):
            log(unknown_command=text)
            out("\r\nUnknown command: %s\r\n\x1b[2C\u276f " % text)
            continue
        n += 1
        log(prompt=text)
        base = {"sessionId": sid, "version": "2.1.306", "timestamp": "2026-11-07T10:00:00Z", "cwd": os.getcwd()}
        append(dict(base, type="user", isSidechain=False, message={"role": "user", "content": text}))
        out("\r\n\u2733 Working\u2026")
        time.sleep(1)
        if mode != "noturn":
            mid = "msg_%d" % n
            append(dict(base, type="assistant", isSidechain=True, message={"id": "side_%d" % n, "model": model, "stop_reason": "end_turn", "content": []}),
                   dict(base, type="assistant", isSidechain=False, message={"id": mid, "model": model, "stop_reason": "end_turn", "content": [{"type": "thinking"}]}),
                   dict(base, type="assistant", isSidechain=False, message={"id": mid, "model": model, "stop_reason": "end_turn", "content": [{"type": "text", "text": "ok"}]}))
        busy = bool(select.select([0], [], [], 0)[0])
        log(turn=n, typed_during_turn=busy)
        out("\r\nok\r\n\x1b[2C\u276f ")
`

type tuiLog struct {
	Columns    int    `json:"columns"`
	Lines      int    `json:"lines"`
	Term       string `json:"term"`
	DialogKeys string `json:"dialog_keys"`
	Prompt     string `json:"prompt"`
	Exit       bool   `json:"exit"`
	Unknown    string `json:"unknown_command"`
	Turn       int    `json:"turn"`
	TypedEarly bool   `json:"typed_during_turn"`
}

func readTUILog(t *testing.T, fake string) []tuiLog {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fake, "tui.log"))
	if err != nil {
		t.Fatal(err)
	}
	var out []tuiLog
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var r tuiLog
		if err := json.Unmarshal([]byte(l), &r); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

// driverArgs are the flags of Claude Code's driver in the profile, with the
// fake's transcript under dir.
func driverArgs(log, dir, session string, prompts ...string) []string {
	args := []string{"--log", log, "--dialog", "Yes, I trust this folder", "down enter", "--ready", "Claude Code v", "--ready", "\u276f",
		"--exit-keys", "ctrl-d ctrl-d", "--trace-method", "jsonl-session", "--trace-dir", dir, "--session", session, "--settle", "0.3", "--key-delay", "0.1",
		"--dialog-selected", "Yes, I trust this folder", "\u276f Yes, I trust this folder"}
	for _, p := range prompts {
		args = append(args, "--prompt", p)
	}
	return args
}

// drive runs scripts/pty-drive.py with args and the fake agent after --,
// and returns its exit status, its stderr and the fake's directory.
func drive(t *testing.T, env []string, args ...string) (int, string, string) {
	t.Helper()
	for _, tool := range []string{"python3"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
	_, here, _, _ := runtime.Caller(0)
	repo := filepath.Join(filepath.Dir(here), "..", "..")
	tmp := t.TempDir()
	fake := filepath.Join(tmp, "fake")
	write(t, filepath.Join(tmp, "fake-tui"), fakeTUI, 0o755)
	if err := os.MkdirAll(fake, 0o755); err != nil {
		t.Fatal(err)
	}
	full := append([]string{filepath.Join(repo, "scripts", "pty-drive.py")}, args...)
	full = append(full, "--", "python3", filepath.Join(tmp, "fake-tui"), "--file", filepath.Join(tmp, "projects", "-ws", "s1.jsonl"))
	for i, a := range full {
		full[i] = strings.ReplaceAll(a, "{tmp}", tmp)
	}
	// A bound for a driver that hangs, so the test fails instead of the
	// package timing out; every drive here ends within 40 s.
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "python3", full...)
	cmd.WaitDelay = 5 * time.Second
	cmd.Env = append(append(os.Environ(), "FAKE_DIR="+fake, "TERM="), env...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return code, stderr.String(), fake
}

// The driver answers the dialog with the profile's keys, waits for the
// ready screen, types the prompts in order, each only after the previous
// turn ended by the transcript (one message in two records, a sidechain
// end_turn not counted), exits with the exit command and passes the child's
// status through; the screen log holds the cleaned text (I-162).
func TestTheDriverRunsAScriptedSession(t *testing.T) {
	code, stderr, fake := drive(t, []string{"FAKE_TUI_EXIT=7"}, driverArgs("{tmp}/screen.log", "{tmp}/projects", "s1", "first prompt", "Reply with ok.")...)
	if code != 7 {
		t.Fatalf("exit %d, want the child's 7\n%s", code, stderr)
	}
	log := readTUILog(t, fake)
	if log[0].Columns != 120 || log[0].Lines != 40 || log[0].Term != "xterm-256color" {
		t.Errorf("window or TERM: %+v", log[0])
	}
	var prompts []string
	exited := false
	for _, r := range log {
		if r.DialogKeys != "" && r.DialogKeys != "\x1b[B\r" {
			t.Errorf("dialog keys %q", r.DialogKeys)
		}
		if r.Prompt != "" {
			prompts = append(prompts, r.Prompt)
		}
		if r.TypedEarly {
			t.Errorf("input arrived during turn %d", r.Turn)
		}
		exited = exited || r.Exit
	}
	if strings.Join(prompts, "|") != "first prompt|Reply with ok." || !exited {
		t.Errorf("prompts %q, exit %v", prompts, exited)
	}
	for _, w := range []string{"pty-drive: ready", "pty-drive: turn 2 ended", "status 7"} {
		if !strings.Contains(stderr, w) {
			t.Errorf("stderr lacks %q:\n%s", w, stderr)
		}
	}
	screen, _ := os.ReadFile(filepath.Join(filepath.Dir(fake), "screen.log"))
	if !strings.Contains(string(screen), "Claude Code v2.1.306") || strings.Contains(string(screen), "\x1b") || strings.Contains(string(screen), "\r") {
		t.Errorf("screen log not cleaned:\n%q", screen)
	}
}

// Every wait is bounded: no ready screen, or a turn that never ends, is a
// timeout (exit 124) after which the driver types the exit command; a child
// that ignores it is stopped by a signal after the grace period. A child
// that exits before the script is done fails the drive, and an unknown key
// name is a usage error before anything runs.
func TestTheDriverTimesOutAndStopsTheSession(t *testing.T) {
	quick := []string{"--ready-timeout", "3", "--turn-timeout", "3", "--exit-timeout", "5", "--kill-grace", "2"}
	cases := []struct {
		name, mode string
		code       int
		says       string
		exited     bool
	}{
		{"no ready screen", "noready", 124, "timeout: no ready screen", false},
		{"no end of turn", "noturn", 124, "timeout: no end of turn 1", true},
		{"exit ignored", "stuck", 124, "sending SIGTERM", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			args := driverArgs("{tmp}/screen.log", "{tmp}/projects", "s1", "a prompt")
			if c.mode == "stuck" {
				// The turn ends; the exit command at the end is ignored.
				args = append(args, "--exit-timeout", "2", "--kill-grace", "1")
			} else {
				args = append(args, quick...)
			}
			start := time.Now()
			code, stderr, fake := drive(t, []string{"FAKE_TUI_MODE=" + c.mode}, args...)
			if code != c.code || !strings.Contains(stderr, c.says) {
				t.Errorf("exit %d, want %d with %q:\n%s", code, c.code, c.says, stderr)
			}
			if time.Since(start) > 40*time.Second {
				t.Errorf("took %v", time.Since(start))
			}
			exited := false
			for _, r := range readTUILog(t, fake) {
				exited = exited || r.Exit
			}
			if exited != c.exited {
				t.Errorf("exit command seen %v, want %v", exited, c.exited)
			}
		})
	}
	t.Run("session ends early", func(t *testing.T) {
		args := driverArgs("{tmp}/screen.log", "{tmp}/projects", "s1", "a prompt")
		args[4] = "enter" // the dialog's Enter alone makes the fake exit 1
		args = withoutSelected(args)
		code, stderr, _ := drive(t, nil, append(args, quick...)...)
		if code != 1 || !strings.Contains(stderr, "the session ended while waiting for ready screen") {
			t.Errorf("exit %d:\n%s", code, stderr)
		}
	})
	t.Run("typed /exit is an unknown command", func(t *testing.T) {
		args := driverArgs("{tmp}/screen.log", "{tmp}/projects", "s1", "a prompt")
		for i, a := range args {
			if a == "--exit-keys" {
				args[i], args[i+1] = "--exit-command", "/exit"
			}
		}
		code, stderr, fake := drive(t, nil, append(args, "--exit-timeout", "2", "--kill-grace", "1")...)
		if code != 124 || !strings.Contains(stderr, "timeout: no exit of the session") {
			t.Errorf("exit %d:\n%s", code, stderr)
		}
		unknown := false
		for _, r := range readTUILog(t, fake) {
			unknown = unknown || r.Unknown == "/exit"
		}
		if !unknown {
			t.Errorf("the fake never saw /exit")
		}
	})
	t.Run("exit keys too far apart", func(t *testing.T) {
		args := append(driverArgs("{tmp}/screen.log", "{tmp}/projects", "s1", "a prompt"), "--exit-key-delay", "1", "--exit-timeout", "2", "--kill-grace", "1")
		code, stderr, _ := drive(t, nil, args...)
		if code != 124 || !strings.Contains(stderr, "timeout: no exit of the session") {
			t.Errorf("exit %d:\n%s", code, stderr)
		}
	})
	t.Run("exit keys and command", func(t *testing.T) {
		args := append(driverArgs("{tmp}/screen.log", "{tmp}/projects", "s1", "a prompt"), "--exit-command", "/exit")
		code, stderr, _ := drive(t, nil, args...)
		if code != 2 || !strings.Contains(stderr, "exactly one of --exit-keys and --exit-command") {
			t.Errorf("exit %d:\n%s", code, stderr)
		}
	})
	t.Run("unknown exit key", func(t *testing.T) {
		args := driverArgs("{tmp}/screen.log", "{tmp}/projects", "s1", "a prompt")
		for i, a := range args {
			if a == "--exit-keys" {
				args[i+1] = "ctrl-d eof"
			}
		}
		code, stderr, _ := drive(t, nil, args...)
		if code != 2 || !strings.Contains(stderr, "--exit-keys: unknown key name(s) eof") {
			t.Errorf("exit %d:\n%s", code, stderr)
		}
	})
	t.Run("unknown key", func(t *testing.T) {
		args := driverArgs("{tmp}/screen.log", "{tmp}/projects", "s1", "a prompt")
		args[4] = "down return"
		code, stderr, _ := drive(t, nil, append(args, quick...)...)
		if code != 2 || !strings.Contains(stderr, "unknown key name(s) return") {
			t.Errorf("exit %d:\n%s", code, stderr)
		}
	})
}

// withoutSelected drops --dialog-selected and its two values from args.
func withoutSelected(args []string) []string {
	for i, a := range args {
		if a == "--dialog-selected" {
			return append(append([]string{}, args[:i]...), args[i+3:]...)
		}
	}
	return args
}

// A dialog's last key goes only once the screen shows the option it
// confirms selected: a dialog drawn again with the cursor back on another
// option gets the keys before the last again, and one that never shows the
// option selected ends the drive as a timeout without the last key. Without
// --dialog-selected, the redrawn dialog of 2026-11-11 makes the Enter exit.
func TestTheDriverConfirmsOnlyASelectedOption(t *testing.T) {
	quick := []string{"--ready-timeout", "10", "--exit-timeout", "5", "--kill-grace", "1"}
	cases := []struct {
		name, mode string
		selected   bool
		code       int
		says, keys string
	}{
		{"drawn again", "reset", true, 0, "drawn again without", "\x1b[B\x1b[B\r"},
		{"drawn again, unchecked", "reset", false, 1, "the session ended while waiting for ready screen", "\x1b[B\r"},
		{"never drawn selected", "noselect", true, 124, "does not show '\u276f Yes, I trust this folder' selected; not sending enter", ""},
		{"always drawn back", "resetalways", true, 124, "still not selected after sending down 3 times; not sending enter", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			args := append(driverArgs("{tmp}/screen.log", "{tmp}/projects", "s1", "a prompt"), quick...)
			if !c.selected {
				args = withoutSelected(args)
			}
			code, stderr, fake := drive(t, []string{"FAKE_TUI_MODE=" + c.mode}, args...)
			if code != c.code || !strings.Contains(stderr, c.says) {
				t.Errorf("exit %d, want %d with %q:\n%s", code, c.code, c.says, stderr)
			}
			keys := ""
			for _, r := range readTUILog(t, fake) {
				keys += r.DialogKeys
			}
			if keys != c.keys {
				t.Errorf("dialog keys %q, want %q", keys, c.keys)
			}
		})
	}
	for _, c := range []struct{ marker, text, says string }{
		{"Trust?", "\u276f Trust?", "names no --dialog marker"},
		{"Yes, I trust this folder", "\u276f Yes", "must hold the marker"},
	} {
		args := driverArgs("{tmp}/screen.log", "{tmp}/projects", "s1", "a prompt")
		for i, a := range args {
			if a == "--dialog-selected" {
				args[i+1], args[i+2] = c.marker, c.text
			}
		}
		code, stderr, _ := drive(t, nil, args...)
		if code != 2 || !strings.Contains(stderr, c.says) {
			t.Errorf("%q %q: exit %d:\n%s", c.marker, c.text, code, stderr)
		}
	}
}

// The profile's driver (I-162) is checked where the profile is read: its
// dialogs, key names, ready markers, exit command and prompts, the first of
// which must be the capture's control prompt, and a trace whose turns the
// driver can count.
func TestTheDriverIsCheckedInTheProfile(t *testing.T) {
	driver := func(p map[string]any) map[string]any {
		return p["interactive"].(map[string]any)["driver"].(map[string]any)
	}
	cases := []struct {
		edit func(p map[string]any)
		want string
	}{
		{func(p map[string]any) { driver(p)["prompts"] = []any{"Reply ok."} }, "must start with {control_prompt}"},
		{func(p map[string]any) { driver(p)["prompts"] = []any{"{control_prompt}", "{control_prompt}"} }, "name it once"},
		{func(p map[string]any) { driver(p)["ready"] = []any{} }, "driver.ready must list"},
		{func(p map[string]any) { delete(driver(p), "exit_keys") }, "needs exactly one of exit"},
		{func(p map[string]any) { driver(p)["exit"] = "/exit" }, "needs exactly one of exit"},
		{func(p map[string]any) { driver(p)["exit_keys"] = []any{"ctrl-d", "eof"} }, "exit_keys names unknown key(s) eof"},
		{func(p map[string]any) { delete(driver(p), "exit_keys"); driver(p)["exit"] = "" }, "driver.exit must be a command"},
		{func(p map[string]any) {
			driver(p)["dialogs"] = []any{map[string]any{"marker": "Trust?", "keys": []any{"down", "return"}}}
		}, "unknown key(s) return"},
		{func(p map[string]any) { driver(p)["dialogs"] = []any{map[string]any{"marker": "Trust?"}} }, "needs a marker and a list of keys"},
		{func(p map[string]any) {
			driver(p)["dialogs"] = []any{map[string]any{"marker": "Trust?", "keys": []any{"down", "enter"}, "selected": "\u276f Yes"}}
		}, "selected must be the selected option's screen text, holding the marker"},
		{func(p map[string]any) { p["trace"].(map[string]any)["method"] = "jsonl-rollout" }, "whose turns the driver counts"},
	}
	for _, c := range cases {
		root, _, _ := layout(t, "")
		editProfile(t, root, "claude-code", c.edit)
		cmd := exec.Command("python3", filepath.Join(root, "scripts", "agent-profile.py"), "shell", filepath.Join(root, "config", "agents.json"), "claude-code", "basic")
		b, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(b), c.want) {
			t.Errorf("%v %s, want %q", err, b, c.want)
		}
	}
	// The key names the profile reader accepts are those the driver maps.
	_, here, _, _ := runtime.Caller(0)
	scripts := filepath.Join(filepath.Dir(here), "..", "..", "scripts")
	keys := func(file, expr string) string {
		code := "import importlib.util, sys\ns = importlib.util.spec_from_file_location('m', sys.argv[1])\nm = importlib.util.module_from_spec(s)\ns.loader.exec_module(m)\nprint(' '.join(sorted(" + expr + ")))"
		b, err := exec.Command("python3", "-c", code, filepath.Join(scripts, file)).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v %s", file, err, b)
		}
		return string(b)
	}
	if a, b := keys("pty-drive.py", "m.KEYS"), keys("agent-profile.py", "m.DRIVER_KEYS"); a != b {
		t.Errorf("pty-drive.py maps %s, agent-profile.py accepts %s", a, b)
	}
}
