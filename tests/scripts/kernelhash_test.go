package scripts

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// --fs-kernel-hash (I-154) reaches watch for the task and every control,
// and task-meta.txt records it; where the kernel copy did not run, the
// capture says so and goes on. Without it watch gets no flag and
// task-meta.txt records off; AGENT_TRACE_FS_KERNEL_HASH=1 turns it on.
func TestTheFsKernelHashSettingReachesWatch(t *testing.T) {
	for _, c := range []struct {
		name string
		flag []string
		env  []string
		on   bool
		note bool
	}{
		{"off", nil, nil, false, false},
		{"flag", []string{"--fs-kernel-hash"}, nil, true, false},
		{"env, unavailable", nil, []string{"AGENT_TRACE_FS_KERNEL_HASH=1", "FAKE_KHASH=unavailable: no BPF LSM"}, true, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			root, tmp, env := layout(t, "")
			if err := os.Rename(filepath.Join(root, "watch"), filepath.Join(root, "watch.real")); err != nil {
				t.Fatal(err)
			}
			write(t, filepath.Join(root, "watch"), recordingWatch, 0o755)
			out := filepath.Join(tmp, "out")
			args := append([]string{filepath.Join(root, "scripts", "capture-agent.sh"), "--no-build", "--task", "basic"}, c.flag...)
			cmd := exec.Command("bash", append(args, out)...)
			cmd.Env = append(env, c.env...)
			b, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("capture: %v\n%s", err, b)
			}
			calls := watchCalls(t, tmp)
			if len(calls) != 2 {
				t.Fatalf("watch ran %d times", len(calls))
			}
			for _, w := range calls {
				if got := strings.Contains(strings.Join(w, " "), " --fs-kernel-hash "); got != c.on {
					t.Errorf("watch %v: --fs-kernel-hash %v, want %v", w, got, c.on)
				}
			}
			want := "fs_kernel_hash=off\n"
			if c.on {
				want = "fs_kernel_hash=on\n"
			}
			if meta, _ := os.ReadFile(filepath.Join(out, "task-meta.txt")); !strings.Contains(string(meta), want) {
				t.Errorf("task-meta.txt lacks %q:\n%s", want, meta)
			}
			if got := strings.Count(string(b), "NOTE: --fs-kernel-hash: the kernel copy is unavailable: no BPF LSM; the fs probe hashed in userspace (2 closes)"); (got == 2) != c.note {
				t.Errorf("%d notes:\n%s", got, b)
			}
		})
	}
}

// summarize writes fs_kernel_hash from task-meta.txt and the hashed closes
// by source from each ground truth's coverage into run.json (I-154), and
// neither for a run whose records hold none.
func TestRunJSONRecordsTheHashSources(t *testing.T) {
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
	gt := `{"events": [], "root_pid": 1, "coverage": {"schema": 2, "probes": {"fs": {"ran": true, "diagnostics": {"file_hashes": {"mode": "kernel", "kernel": 7, "userspace": 1, "fallbacks": {"raced": 1}, "lost": 0, "sync_timeouts": 0}}}}}}`
	for i, c := range []struct {
		meta, gt string
		on       string
		kernel   float64
	}{
		{"task=basic\nfs_kernel_hash=on\n", gt, "on", 7},
		{"task=basic\n", `{"events": [], "coverage": {"schema": 2, "probes": {"fs": {"ran": true}}}}`, "", -1},
	} {
		run := filepath.Join(tmp, "c"+string(rune('0'+i)), "claude-code-2.1.306", "basic", "run-01")
		write(t, filepath.Join(run, "task-meta.txt"), c.meta, 0o644)
		write(t, filepath.Join(run, "basic.ground_truth.json"), c.gt, 0o644)
		write(t, filepath.Join(run, "control-1.ground_truth.json"), c.gt, 0o644)
		cmd := exec.Command("python3", helper, "summarize", run, "claude-code", "2.1.306", "basic", "1", "identity",
			"2026-11-06T10:00:00+00:00", "2026-11-06T10:01:00+00:00", "0", "1", "1", "1", "1", "claude-sonnet-5-5", "2.1.306")
		cmd.Env = append(os.Environ(), "CAMPAIGN_AGENT_CONFIG="+filepath.Join(repo, "config", "agents.json"))
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("summarize: %v\n%s", err, b)
		}
		var r struct {
			FsKernelHash string `json:"fs_kernel_hash"`
			Scale        struct {
				FileHashes *struct {
					Kernel float64 `json:"kernel"`
				} `json:"file_hashes"`
			} `json:"scale"`
			ControlScale []struct {
				FileHashes *struct {
					Kernel float64 `json:"kernel"`
				} `json:"file_hashes"`
			} `json:"control_scale"`
		}
		b, _ := os.ReadFile(filepath.Join(run, "run.json"))
		if err := json.Unmarshal(b, &r); err != nil {
			t.Fatal(err)
		}
		if r.FsKernelHash != c.on {
			t.Errorf("%d: fs_kernel_hash %q", i, r.FsKernelHash)
		}
		got := -1.0
		if r.Scale.FileHashes != nil {
			got = r.Scale.FileHashes.Kernel
		}
		if got != c.kernel || len(r.ControlScale) != 1 || (r.ControlScale[0].FileHashes != nil) != (c.kernel >= 0) {
			t.Errorf("%d: run.json\n%s", i, b)
		}
	}
}
