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

// opencodeCalls returns the prompts of the fake OpenCode's runs, in order.
func opencodeCalls(t *testing.T, tmp string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(tmp, "fake", "opencode.calls"))
	if err != nil {
		t.Fatal(err)
	}
	var prompts []string
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var c struct {
			Args []string `json:"args"`
		}
		if err := json.Unmarshal([]byte(l), &c); err != nil {
			t.Fatal(err)
		}
		prompts = append(prompts, c.Args[len(c.Args)-1])
	}
	return prompts
}

const warmUpPrompt = "Use the grep tool to search the files in this directory"

// The profile's warm-up (I-151) runs once, first, outside watch, in a
// throwaway workspace that is removed, and is recorded in warm-up.txt and
// task-meta.txt; an agent whose profile names none gets none.
func TestTheWarmUpRunsOnceBeforeTheFirstRecordedRun(t *testing.T) {
	root, tmp, env := layout(t, "")
	if err := os.Rename(filepath.Join(root, "watch"), filepath.Join(root, "watch.real")); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(root, "watch"), recordingWatch, 0o755)
	out := filepath.Join(tmp, "out")
	cmd := exec.Command("bash", filepath.Join(root, "scripts", "capture-agent.sh"), "--no-build", "--agent", "opencode",
		"--task", "basic", "--allow-unconfigured-version", out)
	cmd.Env = append(env, "SCILIFELAB_API_KEY="+testKey)
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("capture: %v\n%s", err, b)
	}
	prompts := opencodeCalls(t, tmp)
	if len(prompts) != 3 || !strings.HasPrefix(prompts[0], warmUpPrompt) || strings.HasPrefix(prompts[1], warmUpPrompt) {
		t.Fatalf("runs: %q", prompts)
	}
	calls := watchCalls(t, tmp)
	if len(calls) != 2 {
		t.Errorf("watch ran %d times, want the task and one control", len(calls))
	}
	for _, c := range calls {
		if strings.Contains(strings.Join(c, " "), warmUpPrompt) {
			t.Errorf("the warm-up ran under watch: %v", c)
		}
	}
	if _, err := os.Stat(filepath.Join(out, "ws-warm-up")); err == nil {
		t.Errorf("the warm-up's workspace is left")
	}
	rec, _ := os.ReadFile(filepath.Join(out, "warm-up.txt"))
	for _, want := range []string{"agent=opencode\n", "version=1.19.5\n", "exit=0\n", "model=scilifelab/Qwen3-235B-A22B\n", "prompt_sha256="} {
		if !strings.Contains(string(rec), want) {
			t.Errorf("warm-up.txt lacks %q:\n%s", want, rec)
		}
	}
	meta, _ := os.ReadFile(filepath.Join(out, "task-meta.txt"))
	if !strings.Contains(string(meta), "warm_up=ran exit=0 prompt_sha256=") {
		t.Errorf("task-meta.txt:\n%s", meta)
	}

	// A profile that names no warm-up makes none (every repository profile
	// names one since I-155, so the test removes Claude Code's).
	croot, ctmp, cenv := layout(t, "")
	withoutWarmUp(t, croot, "claude-code")
	cout := filepath.Join(ctmp, "out")
	ccmd := exec.Command("bash", filepath.Join(croot, "scripts", "capture-agent.sh"), "--no-build", "--task", "basic", cout)
	ccmd.Env = cenv
	if b, err := ccmd.CombinedOutput(); err != nil {
		t.Fatalf("claude capture: %v\n%s", err, b)
	}
	if _, err := os.Stat(filepath.Join(cout, "warm-up.txt")); err == nil {
		t.Errorf("a warm-up ran for a profile without one")
	}
	if meta, _ := os.ReadFile(filepath.Join(cout, "task-meta.txt")); strings.Contains(string(meta), "warm_up") {
		t.Errorf("task-meta.txt:\n%s", meta)
	}
}

// A failed warm-up stops the capture before any recorded run.
func TestAFailedWarmUpStopsTheCapture(t *testing.T) {
	_, tmp, out, log, err := runOpencode(t, "warmfail", "basic", testKey)
	if err == nil || !strings.Contains(log, "WARM-UP FAILED (exit 3)") {
		t.Fatalf("capture: %v\n%s", err, log)
	}
	if len(opencodeCalls(t, tmp)) != 1 {
		t.Errorf("runs after the failed warm-up")
	}
	if m, _ := filepath.Glob(filepath.Join(out, "*.ground_truth.json")); len(m) != 0 {
		t.Errorf("recorded runs: %v", m)
	}
	if rec, _ := os.ReadFile(filepath.Join(out, "warm-up.txt")); !strings.Contains(string(rec), "exit=3\n") {
		t.Errorf("warm-up.txt:\n%s", rec)
	}
}

// --warm-up-only makes the warm-up alone; --warm-up-from records a passed
// one of the same agent, version, user and prompt instead of making one,
// and refuses another.
func TestAWarmUpRecordReplacesTheCapturesOwn(t *testing.T) {
	root, tmp, env := layout(t, "")
	env = append(env, "SCILIFELAB_API_KEY="+testKey)
	capture := func(out string, extra ...string) (string, error) {
		args := append([]string{filepath.Join(root, "scripts", "capture-agent.sh"), "--no-build", "--agent", "opencode",
			"--task", "basic", "--allow-unconfigured-version"}, extra...)
		cmd := exec.Command("bash", append(args, out)...)
		cmd.Env = env
		b, err := cmd.CombinedOutput()
		return string(b), err
	}
	wdir := filepath.Join(tmp, "warm")
	if log, err := capture(wdir, "--warm-up-only"); err != nil {
		t.Fatalf("--warm-up-only: %v\n%s", err, log)
	}
	if m, _ := filepath.Glob(filepath.Join(wdir, "*.ground_truth.json")); len(m) != 0 || len(opencodeCalls(t, tmp)) != 1 {
		t.Errorf("--warm-up-only recorded %v", m)
	}
	rec := filepath.Join(wdir, "warm-up.txt")
	out := filepath.Join(tmp, "out")
	if log, err := capture(out, "--warm-up-from", rec); err != nil {
		t.Fatalf("--warm-up-from: %v\n%s", err, log)
	}
	if p := opencodeCalls(t, tmp); len(p) != 3 || strings.HasPrefix(p[1], warmUpPrompt) || strings.HasPrefix(p[2], warmUpPrompt) {
		t.Errorf("runs: %q", p)
	}
	meta, _ := os.ReadFile(filepath.Join(out, "task-meta.txt"))
	if !strings.Contains(string(meta), "warm_up=before this capture exit=0 prompt_sha256=") || !strings.Contains(string(meta), "record="+rec+"\n") {
		t.Errorf("task-meta.txt:\n%s", meta)
	}
	b, _ := os.ReadFile(rec)
	write(t, rec, strings.Replace(string(b), "exit=0", "exit=3", 1), 0o644)
	if log, err := capture(filepath.Join(tmp, "out2"), "--warm-up-from", rec); err == nil || !strings.Contains(log, "does not record exit=0") {
		t.Errorf("a failed record: %v\n%s", err, log)
	}
	withoutWarmUp(t, root, "claude-code")
	if log, err := capture(filepath.Join(tmp, "out3"), "--agent", "claude-code", "--warm-up-only"); err == nil || !strings.Contains(log, "names no warm_up") {
		t.Errorf("--warm-up-only without a warm_up: %v\n%s", err, log)
	}
}

// For another user the warm-up runs as that user, in a workspace under the
// workspace root that is removed, and its record names that uid.
func TestTheWarmUpRunsAsTheRunAsUser(t *testing.T) {
	root, tmp, env := layout(t, "")
	home, wsRoot, env := runAsLayout(t, root, tmp, env)
	out := filepath.Join(tmp, "out")
	cmd := exec.Command("bash", filepath.Join(root, "scripts", "capture-agent.sh"), "--no-build", "--agent", "opencode", "--task", "basic",
		"--allow-unconfigured-version", "--run-as", "agenttrace", "--workspace-root", wsRoot, "--warm-up-only", out)
	cmd.Env = append(env, "SCILIFELAB_API_KEY="+testKey)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("warm-up: %v\n%s", err, b)
	}
	rec, _ := os.ReadFile(filepath.Join(out, "warm-up.txt"))
	if !strings.Contains(string(rec), "run_uid=4242\n") || !strings.Contains(string(rec), "run_as=agenttrace\n") {
		t.Errorf("warm-up.txt:\n%s", rec)
	}
	if left, _ := filepath.Glob(filepath.Join(wsRoot, "*", "*")); len(left) != 0 {
		t.Errorf("the workspace root holds %v", left)
	}
	if _, err := os.Stat(filepath.Join(home, ".local", "share", "opencode", "opencode.db")); err != nil {
		t.Errorf("the warm-up did not run in the agent user's home: %v", err)
	}
	chowns, _ := os.ReadFile(filepath.Join(tmp, "fake", "chown.calls"))
	if !strings.Contains(string(chowns), "-R 4242:4243 -- "+wsRoot+"/capture-") {
		t.Errorf("chown calls:\n%s", chowns)
	}
}

// A campaign makes one warm-up per agent that names one, before its first
// slot, passes its record to every capture of that agent, and lists it in
// the manifest and each run.json. It also passes --fs-kernel-hash.
func TestACampaignWarmsUpOnceBeforeItsFirstSlot(t *testing.T) {
	root, tmp, env := layout(t, "")
	_, here, _, _ := runtime.Caller(0)
	copyFile(t, filepath.Join(filepath.Dir(here), "..", "..", "scripts", "capture-campaign.sh"), filepath.Join(root, "scripts", "capture-campaign.sh"), 0o755)
	write(t, filepath.Join(tmp, "bin", "make"), "#!/bin/sh\nexit 0\n", 0o755)
	write(t, filepath.Join(tmp, "plan.txt"), "opencode basic 2\n", 0o644)
	run := func(extra ...string) (string, error) {
		args := append([]string{filepath.Join(root, "scripts", "capture-campaign.sh"), "--controls", "1", "--seed", "1",
			"--allow-unconfigured-version"}, extra...)
		cmd := exec.Command("bash", append(args, filepath.Join(tmp, "plan.txt"), filepath.Join(tmp, "campaign"))...)
		cmd.Env = append(env, "SCILIFELAB_API_KEY="+testKey)
		b, err := cmd.CombinedOutput()
		return string(b), err
	}
	if log, err := run("--dry-run"); err != nil || !strings.Contains(log, "warm-up: opencode once before the first slot") {
		t.Fatalf("dry run: %v\n%s", err, log)
	}
	log, err := run("--fs-kernel-hash")
	if err != nil {
		t.Fatalf("campaign: %v\n%s", err, log)
	}
	n := 0
	for _, p := range opencodeCalls(t, tmp) {
		if strings.HasPrefix(p, warmUpPrompt) {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d warm-up runs, want 1\n%s", n, log)
	}
	var m struct {
		WarmUps []map[string]any `json:"warm_ups"`
		Runs    []map[string]any `json:"runs"`
	}
	b, err := os.ReadFile(filepath.Join(tmp, "campaign", "manifest.json"))
	if err != nil || json.Unmarshal(b, &m) != nil {
		t.Fatalf("manifest: %v", err)
	}
	if len(m.WarmUps) != 1 || m.WarmUps[0]["exit"] != float64(0) || m.WarmUps[0]["agent"] != "opencode" {
		t.Errorf("warm_ups: %v", m.WarmUps)
	}
	if len(m.Runs) != 2 {
		t.Fatalf("%d runs", len(m.Runs))
	}
	for _, r := range m.Runs {
		if w, _ := r["warm_up"].(string); !strings.HasPrefix(w, "before this capture exit=0") {
			t.Errorf("run %v: warm_up %q", r["dir"], w)
		}
		// --fs-kernel-hash reaches every capture (I-154).
		if r["fs_kernel_hash"] != "on" || r["scale"].(map[string]any)["file_hashes"] == nil {
			t.Errorf("run %v: fs_kernel_hash %v, scale %v", r["dir"], r["fs_kernel_hash"], r["scale"])
		}
	}
}

// withoutWarmUp removes agent's warm_up from the test's copy of the agent
// configuration, for the checks of a profile that names none.
func withoutWarmUp(t *testing.T, root, agent string) {
	t.Helper()
	path := filepath.Join(root, "config", "agents.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	delete(cfg["adapters"].(map[string]any)[agent].(map[string]any), "warm_up")
	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	write(t, path, string(out)+"\n", 0o644)
}
