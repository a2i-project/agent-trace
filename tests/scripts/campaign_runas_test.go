package scripts

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// The campaign passes --run-as to every check (I-137): a dry run as
// another user asks for sudo before its checks and schedules the run.
func TestACampaignDryRunPassesTheRunAsUser(t *testing.T) {
	root, tmp, env := layout(t, "")
	_, wsRoot, env := runAsLayout(t, root, tmp, env)
	_, here, _, _ := runtime.Caller(0)
	copyFile(t, filepath.Join(filepath.Dir(here), "..", "..", "scripts", "capture-campaign.sh"), filepath.Join(root, "scripts", "capture-campaign.sh"), 0o755)
	write(t, filepath.Join(tmp, "plan.txt"), "claude-code basic 1\n", 0o644)
	cmd := exec.Command("bash", filepath.Join(root, "scripts", "capture-campaign.sh"), "--dry-run", "--run-as", "agenttrace",
		"--workspace-root", wsRoot, filepath.Join(tmp, "plan.txt"), filepath.Join(tmp, "campaign"))
	cmd.Env = env
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("dry run: %v\n%s", err, b)
	}
	for _, want := range []string{"run as: agenttrace (uid 4242)", "claude-code  basic", "dry run: everything checked"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("dry run lacks %q:\n%s", want, b)
		}
	}
}

// summarize writes the run-as user a run's task-meta.txt records into its
// run.json (I-137), the form cmd/analyze reads (I-139), and nothing for a
// run recorded without one.
func TestRunJSONRecordsTheRunAsUser(t *testing.T) {
	_, here, _, _ := runtime.Caller(0)
	src, err := os.ReadFile(filepath.Join(filepath.Dir(here), "..", "..", "scripts", "capture-campaign.sh"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?s)cat >"\$helper" <<'PY'\n(.*?)\nPY\n`).FindSubmatch(src)
	if m == nil {
		t.Fatal("no helper in capture-campaign.sh")
	}
	tmp := t.TempDir()
	helper := filepath.Join(tmp, "helper.py")
	write(t, helper, string(m[1]), 0o644)
	repo := filepath.Join(filepath.Dir(here), "..", "..")
	for _, c := range []struct {
		meta string
		want string
	}{
		{"task=basic\nrun_as=agenttrace uid=4242\noperator_uid=1000\n", `{"user":"agenttrace","uid":4242,"operator_uid":1000}`},
		{"task=basic\n", ""},
	} {
		run := filepath.Join(tmp, fmt.Sprintf("c%d", len(c.want)), "claude-code-2.1.306", "basic", "run-01")
		write(t, filepath.Join(run, "task-meta.txt"), c.meta, 0o644)
		cmd := exec.Command("python3", helper, "summarize", run, "claude-code", "2.1.306", "basic", "1", "identity",
			"2026-11-05T10:00:00+00:00", "2026-11-05T10:01:00+00:00", "0", "1", "1", "1", "1", "claude-sonnet-5-5", "2.1.306")
		cmd.Env = append(os.Environ(), "CAMPAIGN_AGENT_CONFIG="+filepath.Join(repo, "config", "agents.json"))
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("summarize: %v\n%s", err, b)
		}
		b, err := os.ReadFile(filepath.Join(run, "run.json"))
		if err != nil {
			t.Fatal(err)
		}
		var r map[string]json.RawMessage
		if err := json.Unmarshal(b, &r); err != nil {
			t.Fatal(err)
		}
		got := ""
		if raw, ok := r["run_as"]; ok {
			var v any
			_ = json.Unmarshal(raw, &v)
			nb, _ := json.Marshal(v)
			got = string(nb)
			// json.Marshal sorts keys; compare as values.
			var w any
			_ = json.Unmarshal([]byte(c.want), &w)
			wb, _ := json.Marshal(w)
			c.want = string(wb)
		}
		if got != c.want {
			t.Errorf("task-meta %q: run_as %s, want %s", c.meta, got, c.want)
		}
	}
}
