// Package scripts tests the capture scripts with shims in place of the
// agent, sudo, setpriv and watch, so no agent runs, no probe loads and
// nothing needs root.
package scripts

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The shims. claude prints a configured version, writes a transcript whose
// assistant record names the pinned model, and, for the task run with
// FAKE_TASK=delete, deletes it again as an agent's command would; it leaves
// the events a capture would hold in $FAKE_DIR/events.json, with the
// transcript under /home/shim, a home the adapter declares (I-30, I-74).
// watch runs the command after -- and writes a loss-free ground truth of
// those events. sudo and setpriv run what follows their options.
const fakeClaude = `#!/usr/bin/env python3
import json, os, re, sys
args = sys.argv[1:]
if args[:1] == ["--version"]:
    with open(os.path.join(os.environ["FAKE_DIR"], "version.home"), "a") as f:
        f.write(os.environ["HOME"] + "\n")
    print("2.1.306 (Claude Code)"); sys.exit()
sid = args[args.index("--session-id") + 1]
model = args[args.index("--model") + 1]
prompt = args[-1]
ws = os.getcwd()
proj = re.sub("[^a-zA-Z0-9]", "-", ws)
real = os.path.join(os.environ["HOME"], ".claude", "projects", proj)
os.makedirs(real, exist_ok=True)
path = os.path.join(real, sid + ".jsonl")
rec = {"type": "assistant", "sessionId": sid, "version": "2.1.306", "timestamp": "2026-10-31T10:00:00Z", "cwd": ws,
       "message": {"id": "m1", "model": model, "content": [{"type": "text", "text": "done"}]}}
with open(path, "w") as f:
    f.write(json.dumps(rec) + "\n")
obs = "/home/shim/.claude/projects/%s/%s.jsonl" % (proj, sid)
root = 1000
def ev(ms, typ, target, pid=root, **kw):
    e = {"timestamp": "2026-10-31T10:00:00.%03dZ" % ms, "action_type": typ, "target": target, "pid": pid}
    e.update(kw)
    return e
events = [ev(1, "file_open", obs), ev(2, "file_write", obs), ev(3, "file_close", obs)]
with open(os.path.join(os.environ["FAKE_DIR"], "claude-md.seen"), "a") as f:
    f.write("present\n" if os.path.lexists(os.path.join(os.environ["HOME"], ".claude", "CLAUDE.md")) else "absent\n")
if "agent-trace-control-marker" not in prompt and os.environ.get("FAKE_TASK") == "term":
    # Stop the capture script as a user's kill would, while this run lasts:
    # the outermost ancestor running it, not the subshell around the run.
    pid, script = os.getppid(), 0
    while pid > 1:
        argv = open("/proc/%d/cmdline" % pid, "rb").read().split(b"\0")
        if len(argv) > 1 and argv[1].endswith(b"/capture-agent.sh"):
            script = pid
        pid = int(open("/proc/%d/stat" % pid).read().rsplit(")", 1)[1].split()[1])
    os.kill(script, 15)
if "agent-trace-control-marker" not in prompt and os.environ.get("FAKE_TASK") == "delete":
    os.remove(path)
    cmd = "/bin/bash -c rm " + obs
    events += [ev(10, "process_fork", "x", 2001, ppid=root), ev(11, "process_exec", cmd, 2001, ppid=root),
               ev(12, "file_delete", obs, 2001), ev(13, "process_exit", cmd, 2001, ppid=root, exit_code=0)]
with open(os.path.join(os.environ["FAKE_DIR"], "events.json"), "w") as f:
    json.dump(events, f)
`

// fakeCodex stands in for Codex, and for an agent with a profile and no
// adapter (I-79) under a copy of its profile: it
// prints its thread id as codex exec --json does, writes a rollout under
// ~/.codex/sessions whose turn context names the model and effort it was
// given and, when the prompt names spawn_agent, a subagent rollout that
// starts with its parent's history (a turn context of another model and a
// call, before the ordinal its metadata names), and two databases. It
// records its arguments and whether its stdin is /dev/null.
const fakeCodex = `#!/usr/bin/env python3
import json, os, sqlite3, stat, sys, uuid
args = sys.argv[1:]
if args[:1] == ["--version"]:
    print("codex-cli 0.166.0"); sys.exit()
fake = os.environ["FAKE_DIR"]
st = os.fstat(0)
null = stat.S_ISCHR(st.st_mode) and os.path.samestat(st, os.stat("/dev/null"))
with open(os.path.join(fake, "codex.calls"), "a") as f:
    f.write(json.dumps({"args": args, "stdin_null": null}) + "\n")
model = args[args.index("-m") + 1]
effort = [a.split("=", 1)[1] for a in args if a.startswith("model_reasoning_effort=")][0]
prompt = args[-1]
home = os.path.join(os.environ["HOME"], ".codex")
d = os.path.join(home, "sessions", "2026", "10", "31")
os.makedirs(d, exist_ok=True)
tid = str(uuid.uuid4())
def rec(o, typ, payload):
    return json.dumps({"timestamp": "2026-10-31T10:00:00.000Z", "ordinal": o, "type": typ, "payload": payload}) + "\n"
with open(os.path.join(d, "rollout-2026-10-31T10-00-00-%s.jsonl" % tid), "w") as f:
    f.write(rec(0, "session_meta", {"id": tid, "session_id": tid, "cli_version": "0.166.0"}))
    f.write(rec(1, "turn_context", {"model": model, "effort": effort}))
if "spawn_agent" in prompt:
    sid = str(uuid.uuid4())
    with open(os.path.join(d, "rollout-2026-10-31T10-00-01-%s.jsonl" % sid), "w") as f:
        f.write(rec(0, "session_meta", {"id": sid, "session_id": tid, "cli_version": "0.166.0", "subagent_history_start_ordinal": 3}))
        f.write(rec(1, "turn_context", {"model": "parent-history", "effort": effort}))
        f.write(rec(2, "response_item", {"type": "function_call", "name": "spawn_agent"}))
        f.write(rec(3, "turn_context", {"model": model, "effort": effort}))
for db in ("thread_history_1.sqlite", "state_5.sqlite"):
    c = sqlite3.connect(os.path.join(home, db))
    c.execute("create table if not exists t(x)"); c.execute("insert into t values (?)", (tid,)); c.commit(); c.close()
print(json.dumps({"type": "thread.started", "thread_id": tid}, separators=(",", ":")))
json.dump([], open(os.path.join(fake, "events.json"), "w"))
`

// fakeAgy stands in for agy: it prints its version, writes a conversation
// database under ~/.gemini/antigravity-cli/conversations with one step and
// the model in its executor metadata, and prints the conversation id as agy
// -p --output-format json does. For the task run with FAKE_TASK=delete it
// deletes the database again as an agent's command would, with the events a
// capture would hold under /home/shim; with FAKE_TASK=garble it overwrites
// the database with bytes that are not one.
const fakeAgy = `#!/usr/bin/env python3
import json, os, sqlite3, sys, uuid
args = sys.argv[1:]
if args[:1] == ["--version"]:
    print("1.3.4"); sys.exit()
model = args[args.index("--model") + 1]
prompt = args[-1]
cid = str(uuid.uuid4())
d = os.path.join(os.environ["HOME"], ".gemini", "antigravity-cli", "conversations")
os.makedirs(d, exist_ok=True)
path = os.path.join(d, cid + ".db")
c = sqlite3.connect(path)
c.execute("create table steps (idx integer, step_type integer, status integer, has_subtrajectory boolean, step_payload blob)")
c.execute("insert into steps values (0, 1, 3, 0, x'')")
c.execute("create table executor_metadata (data blob)")
c.execute("insert into executor_metadata values (?)", (b"\x0a" + model.encode(),))
c.commit(); c.close()
obs = "/home/shim/.gemini/antigravity-cli/conversations/%s.db" % cid
root = 1000
def ev(ms, typ, target, pid=root, **kw):
    e = {"timestamp": "2026-10-31T10:00:00.%03dZ" % ms, "action_type": typ, "target": target, "pid": pid}
    e.update(kw)
    return e
events = [ev(1, "file_open", obs), ev(2, "file_write", obs), ev(3, "file_close", obs)]
task = "agent-trace-control-marker" not in prompt and os.environ.get("FAKE_TASK")
if task == "delete":
    os.remove(path)
    cmd = "/bin/bash -c rm " + obs
    events += [ev(10, "process_fork", "x", 2001, ppid=root), ev(11, "process_exec", cmd, 2001, ppid=root),
               ev(12, "file_delete", obs, 2001), ev(13, "process_exit", cmd, 2001, ppid=root, exit_code=0)]
if task == "garble":
    open(path, "wb").write(b"not a database\n" * 64)
with open(os.path.join(os.environ["FAKE_DIR"], "events.json"), "w") as f:
    json.dump(events, f)
print(json.dumps({"conversation_id": cid, "response": "ok"}, separators=(",", ":")))
`

const fakeWatch = `#!/usr/bin/env bash
set -e
out= ws=
while [ $# -gt 0 ] && [ "$1" != -- ]; do
  case $1 in --out) out=$2; shift 2 ;; --workspace) ws=$2; shift 2 ;; *) shift ;; esac
done
shift
"$@"
python3 - "$out" "$ws" "$FAKE_DIR/events.json" <<'PY'
import json, sys
out, ws, events = sys.argv[1:]
cov = {"schema": 2, "probes": {p: {"ran": True} for p in ("fs", "proc", "net")}}
json.dump({"events": json.load(open(events)), "coverage": cov, "root_pid": 1000, "workspace": ws}, open(out, "w"))
PY
`

const fakeSudo = `#!/usr/bin/env bash
while [ $# -gt 0 ]; do case $1 in -*) shift ;; *) break ;; esac; done
[ $# -eq 0 ] || exec "$@"
`

const fakeSetpriv = `#!/usr/bin/env bash
while [ $# -gt 0 ]; do case $1 in --reuid|--regid) shift 2 ;; -*) shift ;; *) break ;; esac; done
exec "$@"
`

func write(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

func copyFile(t *testing.T, from, to string, mode os.FileMode) {
	t.Helper()
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	write(t, to, string(b), mode)
}

// layout lays out a repository root with the capture script, its wrapper,
// its helpers, the agent config, the built verify and baseline and the fake
// watch, and the shims; it returns the root and the environment of a run.
func layout(t *testing.T, mode string) (root, tmp string, env []string) {
	t.Helper()
	for _, tool := range []string{"bash", "python3", "realpath", "sha256sum"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
	_, here, _, _ := runtime.Caller(0)
	repo := filepath.Join(filepath.Dir(here), "..", "..")
	tmp = t.TempDir()
	root = filepath.Join(tmp, "root")
	for _, f := range []string{"capture-agent.sh", "capture-claude-code.sh", "agent-profile.py", "measure-watch.py", "extract-model-catalog.py"} {
		copyFile(t, filepath.Join(repo, "scripts", f), filepath.Join(root, "scripts", f), 0o755)
	}
	copyFile(t, filepath.Join(repo, "config", "agents.json"), filepath.Join(root, "config", "agents.json"), 0o644)
	write(t, filepath.Join(root, "watch"), fakeWatch, 0o755)
	build := exec.Command("go", "build", "-o", root+string(os.PathSeparator), "./cmd/verify", "./cmd/baseline")
	build.Dir = repo
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, b)
	}
	bin := filepath.Join(tmp, "bin")
	write(t, filepath.Join(bin, "claude"), fakeClaude, 0o755)
	write(t, filepath.Join(bin, "codex"), fakeCodex, 0o755)
	write(t, filepath.Join(bin, "agy"), fakeAgy, 0o755)
	write(t, filepath.Join(bin, "sudo"), fakeSudo, 0o755)
	write(t, filepath.Join(bin, "setpriv"), fakeSetpriv, 0o755)
	home := filepath.Join(tmp, "home")
	write(t, filepath.Join(home, ".claude", "settings.json"), `{"env": {"DISABLE_UPDATES": "1"}}`, 0o644)
	fake := filepath.Join(tmp, "fake")
	if err := os.MkdirAll(fake, 0o755); err != nil {
		t.Fatal(err)
	}
	env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "HOME="+home, "CONTROLS=1",
		"FAKE_DIR="+fake, "FAKE_TASK="+mode, "AGENT_TRACE_CONFIG="+filepath.Join(root, "config", "agents.json"))
	return root, tmp, env
}

// runCapture runs one capture of the basic task with one control.
func runCapture(t *testing.T, mode string) (out, log string, code int) {
	t.Helper()
	root, tmp, env := layout(t, mode)
	out = filepath.Join(tmp, "out")
	cmd := exec.Command("bash", filepath.Join(root, "scripts", "capture-agent.sh"), "--no-build", "--task", "basic", out)
	cmd.Env = env
	b, err := cmd.CombinedOutput()
	code = 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("capture: %v\n%s", err, b)
		}
		code = ee.ExitCode()
	}
	return out, string(b), code
}

type verifyJSON struct {
	Outcome string `json:"outcome"`
	Trace   *struct {
		State    string `json:"state"`
		Compared bool   `json:"compared"`
	} `json:"trace"`
	TraceTampering []json.RawMessage `json:"trace_tampering"`
}

func readVerify(t *testing.T, path string) verifyJSON {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v verifyJSON
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// A task run whose agent deleted its transcript is a result (I-75): the
// capture exits 0 with the ground truth and the report, the model check is
// not run and not failed, nothing reads "no transcript found" (which the
// campaign classifies as X4), and verify reports the trace deleted, NOT
// FAITHFUL with the delete the probes saw (V-59).
func TestCaptureKeepsARunWhoseTranscriptWasDeleted(t *testing.T) {
	out, log, code := runCapture(t, "delete")
	if code != 0 {
		t.Fatalf("exit %d, want 0:\n%s", code, log)
	}
	if strings.Contains(log, "no transcript found") || strings.Contains(log, "MODEL MISMATCH") {
		t.Errorf("the log reads like a harness error:\n%s", log)
	}
	for _, want := range []string{"TRACE DELETED OR DAMAGED: no transcript for session", "TRACE DELETED OR DAMAGED: missing, 1 piece(s) of tampering evidence; the run is NOT FAITHFUL"} {
		if !strings.Contains(log, want) {
			t.Errorf("log lacks %q:\n%s", want, log)
		}
	}
	for _, f := range []string{"basic.ground_truth.json", "report.txt", "verify.json", "verify-baseline.json", "baseline.json"} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
	if _, err := os.Stat(filepath.Join(out, "basic.session.jsonl")); err == nil {
		t.Error("a transcript was copied although it was deleted")
	}
	if b, _ := os.ReadFile(filepath.Join(out, "basic.trace.txt")); strings.TrimSpace(string(b)) != "missing" {
		t.Errorf("basic.trace.txt = %q, want missing", b)
	}
	order, _ := os.ReadFile(filepath.Join(out, "order.tsv"))
	if !strings.Contains(string(order), "\tbasic\ttask\t") || !strings.Contains(string(order), "model_check=trace-missing;") {
		t.Errorf("order.tsv:\n%s", order)
	}
	report, _ := os.ReadFile(filepath.Join(out, "report.txt"))
	if !strings.Contains(string(report), "CANNOT VERIFY: the trace was deleted or damaged (missing)") || strings.Contains(string(report), "I-57") {
		t.Errorf("report:\n%s", report)
	}
	v := readVerify(t, filepath.Join(out, "verify-baseline.json"))
	if v.Outcome != "NOT FAITHFUL" || v.Trace == nil || v.Trace.State != "missing" || len(v.TraceTampering) != 1 {
		t.Errorf("verify-baseline.json: %+v", v)
	}
}

// An honest run reads as before, and its transcript, copied as the run left
// it, is compared with the probe's last hash only when the capture holds a
// hash; the shim's holds none, so nothing is compared and the run is not
// changed by the comparison.
func TestCaptureOfAnIntactTranscriptIsUnchanged(t *testing.T) {
	out, log, code := runCapture(t, "")
	if code != 0 {
		t.Fatalf("exit %d, want 0:\n%s", code, log)
	}
	if strings.Contains(log, "TRACE") {
		t.Errorf("an intact transcript was reported:\n%s", log)
	}
	if b, _ := os.ReadFile(filepath.Join(out, "basic.trace.txt")); strings.TrimSpace(string(b)) != "read" {
		t.Errorf("basic.trace.txt = %q, want read", b)
	}
	order, _ := os.ReadFile(filepath.Join(out, "order.tsv"))
	if !strings.Contains(string(order), "model_check=0;observed=claude-sonnet-5-5;") {
		t.Errorf("order.tsv:\n%s", order)
	}
	if v := readVerify(t, filepath.Join(out, "verify-baseline.json")); v.TraceTampering != nil || (v.Trace != nil && v.Trace.State != "") {
		t.Errorf("verify-baseline.json: %+v", v)
	}
	// Claude Code's profile names no edit tool (I-88): its controls edit
	// nothing and its baseline excludes the command alone.
	var bl struct {
		Excluded []string `json:"excluded"`
	}
	if b, err := os.ReadFile(filepath.Join(out, "baseline.json")); err != nil || json.Unmarshal(b, &bl) != nil ||
		strings.Join(bl.Excluded, "|") != ": agent-trace-control-marker" {
		t.Errorf("baseline.json excluded %v (%v)", bl.Excluded, err)
	}
	if p, _ := os.ReadFile(filepath.Join(out, "control-prompt.txt")); strings.Contains(string(p), "agent-trace-control.txt") {
		t.Errorf("control-prompt.txt names the edit file: %s", p)
	}
}

// The version query runs once, in a throwaway home the script removes, so
// it cannot leave state in the agent's home that the first run then
// changes (Codex 0.166.0 leaves its arg0 staging directory, I-90).
func TestTheVersionQueryRunsInAThrowawayHome(t *testing.T) {
	root, tmp, env := layout(t, "")
	cmd := exec.Command("bash", filepath.Join(root, "scripts", "capture-agent.sh"), "--no-build", "--task", "basic", filepath.Join(tmp, "out"))
	cmd.Env = env
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("capture: %v\n%s", err, b)
	}
	b, err := os.ReadFile(filepath.Join(tmp, "fake", "version.home"))
	homes := strings.Fields(string(b))
	if err != nil || len(homes) != 1 || homes[0] == filepath.Join(tmp, "home") {
		t.Fatalf("version queried with HOME %v (%v), want once in a throwaway home", homes, err)
	}
	if _, err := os.Stat(homes[0]); !os.IsNotExist(err) {
		t.Errorf("the throwaway home %s is left: %v", homes[0], err)
	}
}

// A profile that names an edit tool must name the edited file in every
// control prompt, and one that names none may not (I-88).
func TestTheControlEditIsCheckedInTheProfile(t *testing.T) {
	root, tmp, env := layout(t, "")
	path := filepath.Join(root, "config", "agents.json")
	orig, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct{ agent, key, value, want string }{
		"edit tool without the file":    {"codex", "prompt", "Use exec_command to run exactly this no-op command: {command} .", "does not name the file the controls edit"},
		"the file without an edit tool": {"claude-code", "prompt", "Run {command} and create {file}.", "names {file}, and the profile has no controls.edit_tool"},
	} {
		var cfg map[string]any
		if err := json.Unmarshal(orig, &cfg); err != nil {
			t.Fatal(err)
		}
		cfg["adapters"].(map[string]any)[c.agent].(map[string]any)["controls"].(map[string]any)[c.key] = c.value
		nb, _ := json.Marshal(cfg)
		write(t, path, string(nb), 0o644)
		cmd := exec.Command("bash", filepath.Join(root, "scripts", "capture-agent.sh"), "--check", "--agent", c.agent, filepath.Join(tmp, "out"))
		cmd.Env = env
		b, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(b), c.want) {
			t.Errorf("%s: %v\n%s", name, err, b)
		}
	}
}

// The old name runs the agent-neutral script: --check through either prints
// the same controls, of the profile's default agent.
func TestCaptureClaudeCodeIsAWrapper(t *testing.T) {
	root, tmp, env := layout(t, "")
	var outs []string
	for _, script := range []string{"capture-agent.sh", "capture-claude-code.sh"} {
		cmd := exec.Command("bash", filepath.Join(root, "scripts", script), "--check", "--task", "parallel", filepath.Join(tmp, "out"))
		cmd.Env = env
		b, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s --check: %v\n%s", script, err, b)
		}
		outs = append(outs, string(b))
	}
	if outs[0] != outs[1] || !strings.Contains(outs[0], "agent=claude-code\n") {
		t.Errorf("capture-agent.sh:\n%s\ncapture-claude-code.sh:\n%s", outs[0], outs[1])
	}
}

// --content is refused by the profile, never by the agent's name: a content
// method none refuses with the profile's reason, and a method this build
// does not implement (proxy, say) refuses as such.
func TestContentRefusalComesFromTheProfile(t *testing.T) {
	root, tmp, env := layout(t, "")
	path := filepath.Join(root, "config", "agents.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ content, want string }{
		{`[{"method": "none", "reason": "a reason from the profile"}]`, "a reason from the profile"},
		{`[{"method": "proxy", "listen": "127.0.0.1:0"}]`, "the content method proxy (parser '') of claude-code's profile is not implemented in this build"},
	} {
		var c map[string]any
		if err := json.Unmarshal(b, &c); err != nil {
			t.Fatal(err)
		}
		var content any
		if err := json.Unmarshal([]byte(tc.content), &content); err != nil {
			t.Fatal(err)
		}
		c["adapters"].(map[string]any)["claude-code"].(map[string]any)["content"] = content
		nb, _ := json.Marshal(c)
		write(t, path, string(nb), 0o644)
		cmd := exec.Command("bash", filepath.Join(root, "scripts", "capture-agent.sh"), "--check", "--content", "--task", "basic", filepath.Join(tmp, "out"))
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(out), tc.want) {
			t.Errorf("content %s: err %v, output:\n%s", tc.content, err, out)
		}
	}
}

// An agent with a profile and no adapter in the build (Codex, I-79) is
// captured with the profile's methods and no baseline or verdict: the
// session id from the agent's output, the rollout and the subagent rollout
// the run created (without its parent's history), the databases'
// snapshots, the model and effort checked from the rollout, the model
// catalog's absolute path and the effort inside the invocation's words, and
// stdin from /dev/null.
func TestCaptureOfAnAgentWithoutAnAdapter(t *testing.T) {
	root, tmp, env := layout(t, "")
	out := filepath.Join(tmp, "out")
	catalog := privateCatalog(t, root, tmp)
	// Codex has an adapter (I-82); a copy of its profile under a name no
	// adapter has, with no version, is an agent captured before its adapter.
	copyProfile(t, root, "codex", "noadapter")
	cmd := exec.Command("bash", filepath.Join(root, "scripts", "capture-agent.sh"), "--no-build", "--agent", "noadapter",
		"--task", "parallel", "--allow-unconfigured-version", out)
	cmd.Env = env
	b, err := cmd.CombinedOutput()
	log := string(b)
	if err != nil {
		t.Fatalf("capture: %v\n%s", err, log)
	}
	for _, want := range []string{"NOTE: this build has no noadapter adapter", "1 subagent rollout(s) copied", "2 database snapshot(s) taken", "done (no adapter, no verdict)"} {
		if !strings.Contains(log, want) {
			t.Errorf("log lacks %q:\n%s", want, log)
		}
	}
	for _, f := range []string{"parallel.rollout.jsonl", "parallel.trace.txt", "parallel.ground_truth.json", "control-1.rollout.jsonl",
		"parallel.rollout/databases/state_5.sqlite", "parallel.rollout/databases/thread_history_1.sqlite", "report.txt"} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
	for _, f := range []string{"baseline.json", "verify.json"} {
		if _, err := os.Stat(filepath.Join(out, f)); err == nil {
			t.Errorf("%s exists without an adapter", f)
		}
	}
	// The profile's edit tool (I-88): the controls add the edit file, and
	// the baseline to build excludes it beside the command.
	if p, _ := os.ReadFile(filepath.Join(out, "control-prompt.txt")); !strings.Contains(string(p), "2) Use apply_patch to add the file agent-trace-control.txt containing the single word ok.") || strings.Contains(string(p), "{") {
		t.Errorf("control-prompt.txt: %s", p)
	}
	if r, _ := os.ReadFile(filepath.Join(out, "report.txt")); !strings.Contains(string(r), "--exclude ': agent-trace-control-marker' --exclude '{workspace}/agent-trace-control.txt' --out baseline.json") {
		t.Errorf("report.txt: %s", r)
	}
	if subs, _ := filepath.Glob(filepath.Join(out, "parallel.rollout", "subagents", "rollout-*.jsonl")); len(subs) != 1 {
		t.Errorf("subagent rollouts copied: %v", subs)
	}
	order, _ := os.ReadFile(filepath.Join(out, "order.tsv"))
	for _, want := range []string{"\tparallel\ttask\t", "model_check=0;observed=gpt-6.1-terra;effort=medium;subagents=gpt-6.1-terra\t", "subagents=1;subagent_tool_calls=0"} {
		if !strings.Contains(string(order), want) {
			t.Errorf("order.tsv lacks %q:\n%s", want, order)
		}
	}
	meta, _ := os.ReadFile(filepath.Join(out, "task-meta.txt"))
	for _, want := range []string{"effort=medium\n", "model_catalog=~/.config/agent-trace/codex-catalog-0.166.0.json sha256=", "instruction_file=~/.codex/AGENTS.md absent\n"} {
		if !strings.Contains(string(meta), want) {
			t.Errorf("task-meta.txt lacks %q:\n%s", want, meta)
		}
	}
	calls, err := os.ReadFile(filepath.Join(tmp, "fake", "codex.calls"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(calls)), "\n")
	if len(lines) != 2 { // the task and CONTROLS=1
		t.Fatalf("codex ran %d times:\n%s", len(lines), calls)
	}
	for _, l := range lines {
		var c struct {
			Args      []string `json:"args"`
			StdinNull bool     `json:"stdin_null"`
		}
		if err := json.Unmarshal([]byte(l), &c); err != nil {
			t.Fatal(err)
		}
		joined := strings.Join(c.Args, " ")
		if !c.StdinNull || !strings.Contains(joined, "model_catalog_json="+catalog+" ") ||
			!strings.Contains(joined, " -c model_reasoning_effort=medium --json ") || !strings.HasPrefix(joined, "exec --skip-git-repo-check -s danger-full-access --ignore-user-config ") {
			t.Errorf("codex call: %s", l)
		}
	}
}

// privateCatalog writes a model cache with one fake gpt-6.1-terra entry into
// the shim home, extracts the profile's catalog from it with the
// repository's script, and pins the extracted file's hash in the test's
// profile, as the real profile pins the private catalog's (I-80). It
// returns the catalog's path.
func privateCatalog(t *testing.T, root, tmp string) string {
	t.Helper()
	home := filepath.Join(tmp, "home")
	write(t, filepath.Join(home, ".codex", "models_cache.json"),
		`{"client_version": "0.166.0", "models": [{"slug": "other"}, {"slug": "gpt-6.1-terra", "shell_type": "unified_exec"}]}`, 0o644)
	catalog := filepath.Join(home, ".config", "agent-trace", "codex-catalog-0.166.0.json")
	b, err := exec.Command("python3", filepath.Join(root, "scripts", "extract-model-catalog.py"),
		filepath.Join(home, ".codex", "models_cache.json"), "gpt-6.1-terra", catalog).CombinedOutput()
	if err != nil {
		t.Fatalf("extract: %v\n%s", err, b)
	}
	sum := strings.Fields(string(b))[0]
	setCatalogHash(t, root, sum)
	return catalog
}

// copyProfile adds a copy of the test config's profile from under the name
// to, with no version listed.
func copyProfile(t *testing.T, root, from, to string) {
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
	adapters := c["adapters"].(map[string]any)
	var p map[string]any
	pb, _ := json.Marshal(adapters[from])
	if err := json.Unmarshal(pb, &p); err != nil {
		t.Fatal(err)
	}
	p["versions"] = []any{}
	adapters[to] = p
	nb, _ := json.Marshal(c)
	write(t, path, string(nb), 0o644)
}

func setCatalogHash(t *testing.T, root, sum string) {
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
	c["adapters"].(map[string]any)["codex"].(map[string]any)["model"].(map[string]any)["catalog"].(map[string]any)["sha256"] = sum
	nb, _ := json.Marshal(c)
	write(t, path, string(nb), 0o644)
}

// The private catalog is refused when it is missing or its hash is not the
// profile's, and the refusal gives the extraction command.
func TestCaptureRefusesAMissingOrChangedCatalog(t *testing.T) {
	root, tmp, env := layout(t, "")
	check := func() string {
		cmd := exec.Command("bash", filepath.Join(root, "scripts", "capture-agent.sh"), "--check", "--agent", "codex",
			"--task", "basic", "--allow-unconfigured-version", filepath.Join(tmp, "out"))
		cmd.Env = env
		b, err := cmd.CombinedOutput()
		if err == nil {
			t.Errorf("--check passed:\n%s", b)
		}
		return string(b)
	}
	if out := check(); !strings.Contains(out, "is missing; write it from the agent's cache with:") || !strings.Contains(out, "extract-model-catalog.py") {
		t.Errorf("missing catalog:\n%s", out)
	}
	privateCatalog(t, root, tmp)
	setCatalogHash(t, root, strings.Repeat("0", 64))
	if out := check(); !strings.Contains(out, "profile pins "+strings.Repeat("0", 64)) || !strings.Contains(out, "extract-model-catalog.py") {
		t.Errorf("changed catalog:\n%s", out)
	}
}

// The profile's instruction files are absent while each run lasts and back,
// unchanged, after it (I-79): after a whole capture, and after a capture
// stopped by SIGTERM during its task run.
func TestInstructionFilesAreAsideOnlyDuringRuns(t *testing.T) {
	for _, mode := range []string{"", "term"} {
		root, tmp, env := layout(t, mode)
		md := filepath.Join(tmp, "home", ".claude", "CLAUDE.md")
		write(t, md, "my instructions\n", 0o600)
		cmd := exec.Command("bash", filepath.Join(root, "scripts", "capture-agent.sh"), "--no-build", "--task", "basic", filepath.Join(tmp, "out"))
		cmd.Env = env
		b, err := cmd.CombinedOutput()
		if (err != nil) != (mode == "term") {
			t.Errorf("mode %q: %v\n%s", mode, err, b)
		}
		if got, err := os.ReadFile(md); err != nil || string(got) != "my instructions\n" {
			t.Errorf("mode %q: CLAUDE.md after the capture: %q, %v", mode, got, err)
		}
		if st, err := os.Stat(md); err == nil && st.Mode().Perm() != 0o600 {
			t.Errorf("mode %q: CLAUDE.md mode %v", mode, st.Mode())
		}
		if _, err := os.Lstat(md + ".agent-trace-aside"); err == nil {
			t.Errorf("mode %q: the aside file is left", mode)
		}
		seen, _ := os.ReadFile(filepath.Join(tmp, "fake", "claude-md.seen"))
		if strings.Contains(string(seen), "present") || !strings.Contains(string(seen), "absent") {
			t.Errorf("mode %q: the runs saw CLAUDE.md: %q", mode, seen)
		}
		if mode == "" {
			meta, _ := os.ReadFile(filepath.Join(tmp, "out", "task-meta.txt"))
			if !strings.Contains(string(meta), "instruction_file=~/.claude/CLAUDE.md sha256=") {
				t.Errorf("task-meta.txt:\n%s", meta)
			}
		}
	}
}

// A file an interrupted capture left aside is never overwritten: the next
// capture refuses before anything else and says how to put it back.
func TestAnAsideFileFromAnInterruptedCaptureIsRefused(t *testing.T) {
	root, tmp, env := layout(t, "")
	aside := filepath.Join(tmp, "home", ".claude", "CLAUDE.md.agent-trace-aside")
	write(t, aside, "kept\n", 0o644)
	cmd := exec.Command("bash", filepath.Join(root, "scripts", "capture-agent.sh"), "--check", "--task", "basic", filepath.Join(tmp, "out"))
	cmd.Env = env
	b, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(b), "mv -n '"+aside+"'") {
		t.Errorf("err %v:\n%s", err, b)
	}
	if got, _ := os.ReadFile(aside); string(got) != "kept\n" {
		t.Errorf("the aside file changed: %q", got)
	}
}

// agy's conversation database is a declared trace (I-102): a task run whose
// database is gone or is not a database is kept as a result, its model is
// not checked, and verify reports a trace it cannot verify; an intact one
// reads, passes the model check and is compared with nothing the shim's
// capture hashed. The database is covered (V-75), so the command that
// deleted it is tampering and that run is NOT FAITHFUL; the shim garbles
// the database without an event, so that run is INCONCLUSIVE.
func TestCaptureOfAgyKeepsARunWhoseDatabaseIsGoneOrDamaged(t *testing.T) {
	for mode, want := range map[string]struct {
		state, outcome, log string
		tampering           bool
	}{
		"delete": {"missing", "NOT FAITHFUL", "TRACE DELETED OR DAMAGED: missing, 1 piece(s) of tampering evidence; the run is NOT FAITHFUL", true},
		"garble": {"damaged", "INCONCLUSIVE", "TRACE DELETED OR DAMAGED: the transcript of basic is damaged", false},
		"":       {"read", "", "", false},
	} {
		root, tmp, env := layout(t, mode)
		out := filepath.Join(tmp, "out")
		cmd := exec.Command("bash", filepath.Join(root, "scripts", "capture-agent.sh"), "--no-build", "--agent", "gemini", "--task", "basic", out)
		// The agy profile requires a session bus; CI runners have none, and the
		// shim never uses it.
		cmd.Env = append(env, "DBUS_SESSION_BUS_ADDRESS=unix:path="+filepath.Join(tmp, "bus"), "XDG_RUNTIME_DIR="+tmp)
		b, err := cmd.CombinedOutput()
		log := string(b)
		if err != nil {
			t.Errorf("%q: capture: %v\n%s", mode, err, log)
			continue
		}
		if strings.Contains(log, "MODEL MISMATCH") || strings.Contains(log, "no conversation database found") {
			t.Errorf("%q: the log reads like a harness error:\n%s", mode, log)
		}
		if want.log != "" && !strings.Contains(log, want.log) {
			t.Errorf("%q: log lacks %q:\n%s", mode, want.log, log)
		}
		if want.log == "" && strings.Contains(log, "TRACE") {
			t.Errorf("an intact database was reported:\n%s", log)
		}
		if b, _ := os.ReadFile(filepath.Join(out, "basic.trace.txt")); strings.TrimSpace(string(b)) != want.state {
			t.Errorf("%q: basic.trace.txt = %q, want %s", mode, b, want.state)
		}
		order, _ := os.ReadFile(filepath.Join(out, "order.tsv"))
		check := "model_check=trace-" + want.state + ";"
		if want.state == "read" {
			check = "model_check=0;observed=gemini-3.8-flash-high;"
		}
		if !strings.Contains(string(order), check) {
			t.Errorf("%q: order.tsv lacks %q:\n%s", mode, check, order)
		}
		v := readVerify(t, filepath.Join(out, "verify-baseline.json"))
		if want.outcome != "" && (v.Outcome != want.outcome || v.Trace == nil || (v.TraceTampering != nil) != want.tampering) {
			t.Errorf("%q: verify-baseline.json: %+v", mode, v)
		}
		if want.outcome == "" && (v.TraceTampering != nil || (v.Trace != nil && v.Trace.State != "")) {
			t.Errorf("intact: verify-baseline.json: %+v", v)
		}
	}
}
