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
if "agent-trace-control-marker" not in prompt and os.environ.get("FAKE_TASK") == "delete":
    os.remove(path)
    cmd = "/bin/bash -c rm " + obs
    events += [ev(10, "process_fork", "x", 2001, ppid=root), ev(11, "process_exec", cmd, 2001, ppid=root),
               ev(12, "file_delete", obs, 2001), ev(13, "process_exit", cmd, 2001, ppid=root, exit_code=0)]
with open(os.path.join(os.environ["FAKE_DIR"], "events.json"), "w") as f:
    json.dump(events, f)
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
	for _, f := range []string{"capture-agent.sh", "capture-claude-code.sh", "agent-profile.py", "measure-watch.py"} {
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
