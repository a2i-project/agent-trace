package scripts

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The run-as shims (I-137, I-138). getent knows one user besides root,
// agenttrace, with a uid and gid that are not the test's and the home the
// test gives it; chown records its arguments and changes nothing, since the
// test cannot give a file to another uid. The other shims (sudo, setpriv)
// run what follows their options as the test's user, so "another user's"
// files are the test's own, which is what lets the script's paths be
// checked without root.
const fakeGetent = `#!/usr/bin/env bash
[ "$1" = passwd ] || exit 2
case $2 in
  agenttrace) echo "agenttrace:x:4242:4243:agent-trace capture user:$FAKE_RUN_HOME:/bin/sh" ;;
  root) echo "root:x:0:0:root:/root:/bin/bash" ;;
  *) exit 2 ;;
esac
`

const fakeChown = `#!/usr/bin/env bash
printf '%s\n' "$*" >>"$FAKE_DIR/chown.calls"
`

// watchArgs records each watch command line, which the fake watch writes
// to $FAKE_DIR/watch.argv one JSON array per run.
const recordingWatch = `#!/usr/bin/env bash
python3 -c 'import json, os, sys; open(os.path.join(os.environ["FAKE_DIR"], "watch.argv"), "a").write(json.dumps(sys.argv[1:]) + "\n")' "$@"
` + "exec \"$(dirname \"$0\")/watch.real\" \"$@\"\n"

// runAsLayout adds the run-as shims to a layout, gives agenttrace a home
// under tmp holding the agent's binaries (on that user's PATH,
// ~/.local/bin) and Claude Code's settings and personal instructions, and
// removes the settings from the operator's home, so a capture that read the
// operator's home would refuse. It returns the agent's home and the
// workspace root.
func runAsLayout(t *testing.T, root, tmp string, env []string) (home, wsRoot string, newEnv []string) {
	t.Helper()
	home = filepath.Join(tmp, "agenthome")
	wsRoot = filepath.Join(tmp, "wsroot")
	bin := filepath.Join(tmp, "bin")
	write(t, filepath.Join(bin, "getent"), fakeGetent, 0o755)
	write(t, filepath.Join(bin, "chown"), fakeChown, 0o755)
	for _, a := range []string{"claude", "codex", "agy", "opencode"} {
		copyFile(t, filepath.Join(bin, a), filepath.Join(home, ".local", "bin", a), 0o755)
		if err := os.Remove(filepath.Join(bin, a)); err != nil {
			t.Fatal(err)
		}
	}
	write(t, filepath.Join(home, ".claude", "settings.json"), `{"env": {"DISABLE_UPDATES": "1"}}`, 0o644)
	write(t, filepath.Join(home, ".claude", "CLAUDE.md"), "the agent user's instructions\n", 0o644)
	if err := os.Remove(filepath.Join(tmp, "home", ".claude", "settings.json")); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(tmp, "home", ".claude", "CLAUDE.md"), "the operator's instructions\n", 0o644)
	if err := os.Rename(filepath.Join(root, "watch"), filepath.Join(root, "watch.real")); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(root, "watch"), recordingWatch, 0o755)
	return home, wsRoot, append(env, "FAKE_RUN_HOME="+home)
}

func watchCalls(t *testing.T, tmp string) [][]string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(tmp, "fake", "watch.argv"))
	if err != nil {
		t.Fatal(err)
	}
	var calls [][]string
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var a []string
		if err := json.Unmarshal([]byte(l), &a); err != nil {
			t.Fatal(err)
		}
		calls = append(calls, a)
	}
	return calls
}

// after returns the words that follow word in args, up to n of them.
func after(args []string, word string, n int) []string {
	for i, a := range args {
		if a == word && i+n < len(args) {
			return args[i+1 : i+1+n]
		}
	}
	return nil
}

// A capture run as another user (I-137, I-138) finds the agent on that
// user's PATH, queries its version as that user, checks the version lock
// in that user's settings, moves that user's instruction file aside and
// leaves yours alone, passes that home to watch, runs the agent with that
// uid in a workspace under the workspace root, copies the workspace back
// and removes it from the root, copies the transcript from that home, and
// records the user in task-meta.txt and the check.
func TestARunAsAnotherUserUsesItsHomeAndTheWorkspaceRoot(t *testing.T) {
	root, tmp, env := layout(t, "")
	home, wsRoot, env := runAsLayout(t, root, tmp, env)
	out := filepath.Join(tmp, "out")
	run := func(extra ...string) (string, error) {
		args := append([]string{filepath.Join(root, "scripts", "capture-agent.sh"), "--no-build", "--task", "basic",
			"--run-as", "agenttrace", "--workspace-root", wsRoot}, extra...)
		cmd := exec.Command("bash", append(args, out)...)
		cmd.Env = env
		b, err := cmd.CombinedOutput()
		return string(b), err
	}
	check, err := run("--check")
	if err != nil || !strings.Contains(check, "run_as=agenttrace uid=4242\n") {
		t.Fatalf("--check: %v\n%s", err, check)
	}
	log, err := run()
	if err != nil {
		t.Fatalf("capture: %v\n%s", err, log)
	}
	calls := watchCalls(t, tmp)
	if len(calls) != 2 {
		t.Fatalf("watch ran %d times", len(calls))
	}
	for i, c := range calls {
		label := []string{"basic", "control-1"}[i]
		ws := after(c, "--workspace", 1)
		if len(ws) != 1 || !strings.HasPrefix(ws[0], wsRoot+"/capture-") || filepath.Base(ws[0]) != "ws-"+label {
			t.Errorf("%s: watch --workspace %v, want under %s", label, ws, wsRoot)
		}
		if h := after(c, "--agent-home", 1); len(h) != 1 || h[0] != home {
			t.Errorf("%s: watch --agent-home %v, want %s", label, h, home)
		}
		if id := after(c, "--reuid", 3); strings.Join(id, " ") != "4242 --regid 4243" {
			t.Errorf("%s: setpriv %v", label, id)
		}
		if d := after(c, "env", 2); len(ws) == 1 && strings.Join(d, " ") != "-C "+ws[0] {
			t.Errorf("%s: env %v, want -C %s", label, d, ws[0])
		}
		joined := strings.Join(c, " ")
		if !strings.Contains(joined, " HOME="+home+" ") || !strings.Contains(joined, " PATH="+home+"/.local/bin:/usr/local/bin:/usr/bin:/bin ") ||
			!strings.Contains(joined, " "+filepath.Join(home, ".local", "bin", "claude")+" ") {
			t.Errorf("%s: watch command %s", label, joined)
		}
		if b, err := os.ReadFile(filepath.Join(out, "ws-"+label, "b.txt")); err != nil || string(b) != "seed\n" {
			t.Errorf("%s: workspace not copied back: %v", label, err)
		}
	}
	if left, _ := filepath.Glob(filepath.Join(wsRoot, "*")); len(left) != 0 {
		t.Errorf("the workspace root still holds %v", left)
	}
	if b, _ := os.ReadFile(filepath.Join(tmp, "fake", "version.home")); !strings.HasPrefix(string(b), "/tmp/agent-trace-version.") {
		t.Errorf("version queried with HOME %q, want a throwaway home in /tmp", b)
	}
	if b, _ := os.ReadFile(filepath.Join(tmp, "fake", "claude-md.seen")); string(b) != "absent\nabsent\n" {
		t.Errorf("the agent user's CLAUDE.md during the runs: %q", b)
	}
	for _, p := range []string{filepath.Join(home, ".claude", "CLAUDE.md"), filepath.Join(tmp, "home", ".claude", "CLAUDE.md")} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s: %v", p, err)
		}
		if _, err := os.Lstat(p + ".agent-trace-aside"); err == nil {
			t.Errorf("%s is left aside", p)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(out, "basic.trace.txt")); strings.TrimSpace(string(b)) != "read" {
		t.Errorf("basic.trace.txt = %q", b)
	}
	meta, _ := os.ReadFile(filepath.Join(out, "task-meta.txt"))
	for _, want := range []string{"run_as=agenttrace uid=4242\n", fmt.Sprintf("operator_uid=%d\n", os.Getuid()), "workspace_root=" + wsRoot + "/capture-",
		"instruction_file=~/.claude/CLAUDE.md sha256="} {
		if !strings.Contains(string(meta), want) {
			t.Errorf("task-meta.txt lacks %q:\n%s", want, meta)
		}
	}
	var gt struct {
		Workspace string `json:"workspace"`
	}
	if b, err := os.ReadFile(filepath.Join(out, "basic.ground_truth.json")); err != nil || json.Unmarshal(b, &gt) != nil || !strings.HasPrefix(gt.Workspace, wsRoot+"/capture-") {
		t.Errorf("ground truth workspace %q (%v)", gt.Workspace, err)
	}
	chowns, _ := os.ReadFile(filepath.Join(tmp, "fake", "chown.calls"))
	if !strings.Contains(string(chowns), "-R 4242:4243 -- "+wsRoot+"/capture-") ||
		!strings.Contains(string(chowns), fmt.Sprintf("-R %d:%d -- %s/ws-basic", os.Getuid(), os.Getgid(), out)) {
		t.Errorf("chown calls:\n%s", chowns)
	}
	if _, err := os.Stat(filepath.Join(out, "verify-baseline.json")); err != nil {
		t.Errorf("no verdict: %v\n%s", err, log)
	}

	// The fixture script takes the workspace root's directory as the one
	// the capture was recorded in, and rewrites the agent user's home, which
	// a real watch records as the snapshot's home, and its name.
	for _, label := range []string{"basic", "control-1"} {
		p := filepath.Join(out, label+".ground_truth.json")
		var g map[string]any
		if b, err := os.ReadFile(p); err != nil || json.Unmarshal(b, &g) != nil {
			t.Fatalf("%s: %v", p, err)
		}
		g["coverage"].(map[string]any)["sensitive"] = map[string]any{"home": home, "files": []any{}}
		g["events"] = append(g["events"].([]any), map[string]any{"timestamp": "2026-10-31T10:00:00.050Z", "action_type": "file_open",
			"target": home + "/.claude/settings.json", "pid": 1000, "comm": "agenttrace"})
		nb, _ := json.Marshal(g)
		write(t, p, string(nb), 0o644)
	}
	fixture := filepath.Join(tmp, "fixture")
	fx := exec.Command("python3", filepath.Join(filepath.Dir(here()), "..", "..", "scripts", "make-capture-fixture.py"), out, fixture, "basic")
	fx.Env = append(env, "USER=operator-name")
	if b, err := fx.CombinedOutput(); err != nil {
		t.Fatalf("make-capture-fixture: %v\n%s", err, b)
	}
	b, err := os.ReadFile(filepath.Join(fixture, "basic.ground_truth.json"))
	if err != nil {
		t.Fatal(err)
	}
	if s := string(b); !strings.Contains(s, `"workspace": "/ws/basic"`) || !strings.Contains(s, "/home/user/.claude/settings.json") ||
		strings.Contains(s, home) || strings.Contains(s, wsRoot) || strings.Contains(s, "agenttrace") {
		t.Errorf("fixture ground truth:\n%s", s)
	}
}

func here() string {
	_, f, _, _ := runtime.Caller(0)
	return f
}

// Without --run-as the command lines are today's: the agent runs with your
// uid and gid, in its workspace in the output, and watch gets neither a
// home nor env -C.
func TestTheDefaultRunIsUnchanged(t *testing.T) {
	root, tmp, env := layout(t, "")
	if err := os.Rename(filepath.Join(root, "watch"), filepath.Join(root, "watch.real")); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(root, "watch"), recordingWatch, 0o755)
	out := filepath.Join(tmp, "out")
	cmd := exec.Command("bash", filepath.Join(root, "scripts", "capture-agent.sh"), "--no-build", "--task", "basic", out)
	cmd.Env = env
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("capture: %v\n%s", err, b)
	}
	for _, c := range watchCalls(t, tmp) {
		joined := strings.Join(c, " ")
		ws := after(c, "--workspace", 1)
		if len(ws) != 1 || filepath.Dir(ws[0]) != out || strings.Contains(joined, "--agent-home") || strings.Contains(joined, " -C ") ||
			strings.Join(after(c, "--reuid", 3), " ") != fmt.Sprintf("%d --regid %d", os.Getuid(), os.Getgid()) ||
			strings.Join(after(c, "--reset-env", 2), " ") != "env DISABLE_UPDATES=1" {
			t.Errorf("watch command %s", joined)
		}
	}
	if meta, _ := os.ReadFile(filepath.Join(out, "task-meta.txt")); strings.Contains(string(meta), "run_as=") {
		t.Errorf("task-meta.txt records a run-as user:\n%s", meta)
	}
}

// editProfile applies edit to the profile of agent in the layout's config.
func editProfile(t *testing.T, root, agent string, edit func(p map[string]any)) {
	t.Helper()
	path := filepath.Join(root, "config", "agents.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	edit(c["adapters"].(map[string]any)[agent].(map[string]any))
	nb, _ := json.Marshal(c)
	write(t, path, string(nb), 0o644)
}

// The environment a profile passes from your session cannot reach another
// user's agent: the capture refuses, naming the agent and the variables
// (I-137), except those the profile marks operator only (I-150). Root and
// an unknown user are refused too.
func TestARunAsAnotherUserIsRefusedWhereItCannotWork(t *testing.T) {
	root, tmp, env := layout(t, "")
	_, wsRoot, env := runAsLayout(t, root, tmp, env)
	env = append(env, "DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent", "XDG_RUNTIME_DIR=/nonexistent")
	copyProfile(t, root, "gemini", "busagent")
	editProfile(t, root, "busagent", func(p map[string]any) {
		p["versions"] = []any{map[string]any{"version": "1.3.4"}}
		p["pass_env"].(map[string]any)["operator_only"] = []any{"XDG_RUNTIME_DIR"}
	})
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"--agent", "busagent", "--run-as", "agenttrace"}, "busagent's profile passes DBUS_SESSION_BUS_ADDRESS from your session"},
		{[]string{"--run-as", "root"}, "is root"},
		{[]string{"--run-as", "nobody-here"}, "no user nobody-here"},
		{[]string{"--run-as", "agenttrace", "--workspace-root", filepath.Join(tmp, "home", "ws")}, "is inside your home"},
	} {
		args := append([]string{filepath.Join(root, "scripts", "capture-agent.sh"), "--check", "--workspace-root", wsRoot}, c.args...)
		cmd := exec.Command("bash", append(args, filepath.Join(tmp, "out"))...)
		cmd.Env = env
		b, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(b), c.want) {
			t.Errorf("%v: %v\n%s", c.args, err, b)
		}
	}
}

// agy's session bus is operator only (I-150): a run as another user gets
// neither DBUS_SESSION_BUS_ADDRESS nor XDG_RUNTIME_DIR although your
// session has them, its conversation database is copied from that user's
// home, and task-meta.txt and the check name what was not passed. As the
// operator the run still gets both.
func TestAgyRunsAsAnotherUserWithoutTheSessionBus(t *testing.T) {
	root, tmp, env := layout(t, "")
	home, wsRoot, env := runAsLayout(t, root, tmp, env)
	env = append(env, "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus", "XDG_RUNTIME_DIR=/run/user/1000")
	out := filepath.Join(tmp, "out")
	run := func(extra ...string) (string, error) {
		args := append([]string{filepath.Join(root, "scripts", "capture-agent.sh"), "--no-build", "--agent", "gemini", "--task", "basic",
			"--run-as", "agenttrace", "--workspace-root", wsRoot}, extra...)
		cmd := exec.Command("bash", append(args, out)...)
		cmd.Env = env
		b, err := cmd.CombinedOutput()
		return string(b), err
	}
	check, err := run("--check")
	if err != nil || !strings.Contains(check, "pass_env_not_passed=DBUS_SESSION_BUS_ADDRESS XDG_RUNTIME_DIR\n") {
		t.Fatalf("--check: %v\n%s", err, check)
	}
	log, err := run()
	if err != nil {
		t.Fatalf("capture: %v\n%s", err, log)
	}
	calls := watchCalls(t, tmp)
	if len(calls) != 2 {
		t.Fatalf("watch ran %d times", len(calls))
	}
	for _, c := range calls {
		joined := strings.Join(c, " ")
		if strings.Contains(joined, "DBUS_SESSION_BUS_ADDRESS") || strings.Contains(joined, "XDG_RUNTIME_DIR") ||
			!strings.Contains(joined, " "+filepath.Join(home, ".local", "bin", "agy")+" ") {
			t.Errorf("watch command %s", joined)
		}
	}
	if _, err := os.Stat(filepath.Join(out, "basic.conversation.db")); err != nil {
		t.Errorf("conversation database: %v", err)
	}
	meta, _ := os.ReadFile(filepath.Join(out, "task-meta.txt"))
	if !strings.Contains(string(meta), "pass_env_not_passed=DBUS_SESSION_BUS_ADDRESS XDG_RUNTIME_DIR (operator only: ") {
		t.Errorf("task-meta.txt:\n%s", meta)
	}

	// As the operator, the session's variables are passed as before.
	root, tmp, env = layout(t, "")
	if err := os.Rename(filepath.Join(root, "watch"), filepath.Join(root, "watch.real")); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(root, "watch"), recordingWatch, 0o755)
	env = append(env, "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus", "XDG_RUNTIME_DIR=/run/user/1000")
	out = filepath.Join(tmp, "out")
	cmd := exec.Command("bash", filepath.Join(root, "scripts", "capture-agent.sh"), "--no-build", "--agent", "gemini", "--task", "basic", out)
	cmd.Env = env
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("capture as the operator: %v\n%s", err, b)
	}
	for _, c := range watchCalls(t, tmp) {
		if got := strings.Join(after(c, "--reset-env", 3), " "); got != "env DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus XDG_RUNTIME_DIR=/run/user/1000" {
			t.Errorf("as the operator: %s", got)
		}
	}
	if meta, _ := os.ReadFile(filepath.Join(out, "task-meta.txt")); strings.Contains(string(meta), "pass_env_not_passed") {
		t.Errorf("as the operator, task-meta.txt:\n%s", meta)
	}
}

// The SQLite traces of another user's agent are read as that user, into a
// directory of that user's, and fetched (I-137): OpenCode's session
// database and its backup, and Codex's rollouts and database snapshots.
func TestARunAsAnotherUserCopiesSQLiteTraces(t *testing.T) {
	root, tmp, env := layout(t, "")
	home, wsRoot, env := runAsLayout(t, root, tmp, env)
	out := filepath.Join(tmp, "out")
	cmd := exec.Command("bash", filepath.Join(root, "scripts", "capture-agent.sh"), "--no-build", "--agent", "opencode", "--task", "parallel",
		"--allow-unconfigured-version", "--run-as", "agenttrace", "--workspace-root", wsRoot, out)
	cmd.Env = append(env, "SCILIFELAB_API_KEY="+testKey)
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("opencode capture: %v\n%s", err, b)
	}
	for _, f := range []string{"parallel.opencode.db", "parallel.opencode.db.backup", "control-1.opencode.db.backup"} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
	if _, err := os.Stat(filepath.Join(home, ".config", "agent-trace", "opencode-1.19.5.json")); err != nil {
		t.Errorf("the configuration file is not in the agent user's home: %v", err)
	}
	if st, _ := os.ReadFile(filepath.Join(out, "parallel.trace.txt")); strings.TrimSpace(string(st)) != "read" {
		t.Errorf("parallel.trace.txt = %q", st)
	}

	// The profile's catalog path is under ~/, the agent user's home.
	catalog := privateCatalog(t, root, tmp)
	copyFile(t, catalog, filepath.Join(home, ".config", "agent-trace", filepath.Base(catalog)), 0o600)
	if err := os.Remove(catalog); err != nil {
		t.Fatal(err)
	}
	out = filepath.Join(tmp, "out-codex")
	copyProfile(t, root, "codex", "noadapter")
	cmd = exec.Command("bash", filepath.Join(root, "scripts", "capture-agent.sh"), "--no-build", "--agent", "noadapter", "--task", "parallel",
		"--allow-unconfigured-version", "--run-as", "agenttrace", "--workspace-root", wsRoot, out)
	cmd.Env = env
	b, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("codex capture: %v\n%s", err, b)
	}
	for _, want := range []string{"1 subagent rollout(s) copied", "2 database snapshot(s) taken"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("log lacks %q:\n%s", want, b)
		}
	}
	for _, f := range []string{"parallel.rollout.jsonl", "parallel.rollout/databases/state_5.sqlite", "parallel.rollout/subagents"} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}

// The setup script (I-140) prints, without root, each profiled agent's
// last listed version with its version lock and changes nothing; without
// root it refuses to set anything up.
func TestTheSetupScriptPrintsThePinnedVersionsAndNeedsRoot(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("runs as root: the refusal without root cannot be checked")
	}
	script := filepath.Join(filepath.Dir(here()), "..", "..", "scripts", "setup-capture-user.sh")
	b, err := exec.Command("bash", script, "--steps-only").CombinedOutput()
	if err != nil {
		t.Fatalf("--steps-only: %v\n%s", err, b)
	}
	var cfg struct {
		Adapters map[string]struct {
			Binary   string `json:"binary"`
			Versions []struct {
				Version string `json:"version"`
			} `json:"versions"`
		} `json:"adapters"`
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(here()), "..", "..", "config", "agents.json"))
	if err != nil || json.Unmarshal(raw, &cfg) != nil {
		t.Fatal(err)
	}
	for name, p := range cfg.Adapters {
		if len(p.Versions) == 0 {
			continue
		}
		v := p.Versions[len(p.Versions)-1].Version
		if want := fmt.Sprintf("  %s: %s %s ", name, p.Binary, v); !strings.Contains(string(b), want) || !strings.Contains(string(b), "--version   # must print "+v) {
			t.Errorf("steps lack %q:\n%s", want, b)
		}
	}
	if !strings.Contains(string(b), `DISABLE_UPDATES=1 claude auth login`) {
		t.Errorf("steps lack the version lock on the login:\n%s", b)
	}
	// agy (I-150): the copy is yours to make, and the sign-in leaves out
	// the operator-only session bus, as the capture runs it.
	for _, want := range []string{
		`as you: cat "$(readlink -f "$(command -v agy)")" | sudo -u agenttrace sh -c 'mkdir -p /home/agenttrace/.local/bin && cat >/home/agenttrace/.local/bin/agy`,
		"    env -u DBUS_SESSION_BUS_ADDRESS -u XDG_RUNTIME_DIR AGY_CLI_DISABLE_AUTO_UPDATE=true agy   # sign in once",
	} {
		if !strings.Contains(string(b), want) {
			t.Errorf("steps lack %q:\n%s", want, b)
		}
	}
	if strings.Contains(string(b), "refuses it") {
		t.Errorf("steps still say a profile is refused:\n%s", b)
	}
	b, err = exec.Command("bash", script).CombinedOutput()
	if err == nil || !strings.Contains(string(b), "run it with sudo") {
		t.Errorf("without root: %v\n%s", err, b)
	}
}
