package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A capture records the kernel, the active LSMs and, inside a VM of
// vm/run.sh, the image and recipe the runner wrote at boot (I-166); outside
// one it says vm=none.
func TestTaskMetaRecordsTheEnvironment(t *testing.T) {
	for _, c := range []struct {
		name, info, want string
	}{
		{"vm", `{"image": "agent-trace-abc.qcow2", "image_sha256": "ad10", "recipe_commit": "1455ad0", "recipe_dirty": true, "run": "run-1-s1"}`,
			"vm=agent-trace-abc.qcow2 image_sha256=ad10 recipe_commit=1455ad0 (dirty) run=run-1-s1"},
		{"none", "", "vm=none"},
	} {
		t.Run(c.name, func(t *testing.T) {
			root, tmp, env := layout(t, "")
			info := filepath.Join(tmp, "vm.json")
			if c.info != "" {
				write(t, info, c.info, 0o644)
			}
			out := filepath.Join(tmp, "out")
			cmd := exec.Command("bash", filepath.Join(root, "scripts", "capture-agent.sh"), "--no-build", "--task", "basic", out)
			cmd.Env = append(env, "AGENT_TRACE_VM_INFO="+info)
			if b, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("capture: %v\n%s", err, b)
			}
			b, err := os.ReadFile(filepath.Join(out, "task-meta.txt"))
			if err != nil {
				t.Fatal(err)
			}
			meta := string(b)
			for _, want := range []string{"\n" + c.want + "\n", "\nkernel=", "\nlsm="} {
				if !strings.Contains(meta, want) {
					t.Errorf("task-meta.txt lacks %q:\n%s", want, meta)
				}
			}
		})
	}
}
