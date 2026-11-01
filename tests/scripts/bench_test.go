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

func repoRoot() string {
	_, here, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(here), "..", "..")
}

// profiledFixtures returns, per listed fixture directory with control
// captures, the agent and version its profile gives it.
func profiledFixtures(t *testing.T, repo string) map[string][2]string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repo, "config", "agents.json"))
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Adapters map[string]struct {
			Versions []struct {
				Version  string   `json:"version"`
				Fixtures []string `json:"fixtures"`
			} `json:"versions"`
		} `json:"adapters"`
	}
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	out := map[string][2]string{}
	for agent, a := range c.Adapters {
		for _, v := range a.Versions {
			for _, f := range v.Fixtures {
				if m, _ := filepath.Glob(filepath.Join(repo, f, "control-*.ground_truth.json")); len(m) > 0 {
					out[filepath.Base(f)] = [2]string{agent, v.Version}
				}
			}
		}
	}
	return out
}

// The benchmark's dry run lists every paired fixture the profiles list, each
// agent alike, and writes nothing to its output directory (I-98).
func TestBenchmarkDryRunListsEveryProfiledFixture(t *testing.T) {
	if b, err := exec.Command("/usr/bin/time", "--version").CombinedOutput(); err != nil || !strings.Contains(string(b), "GNU") {
		t.Skip("the benchmark needs GNU time at /usr/bin/time")
	}
	repo := repoRoot()
	out := filepath.Join(t.TempDir(), "out")
	cmd := exec.Command("bash", filepath.Join(repo, "scripts", "bench-overhead.sh"), "--dry-run", "--reps", "2", out)
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("dry run: %v\n%s", err, b)
	}
	text := string(b)
	fx := profiledFixtures(t, repo)
	if len(fx) == 0 {
		t.Fatal("no profiled fixture with controls")
	}
	for name, av := range fx {
		if !strings.Contains(text, "\n  "+name+" ("+av[0]+" "+av[1]+", ") {
			t.Errorf("dry run does not list %s as %s %s:\n%s", name, av[0], av[1], text)
		}
	}
	if !strings.Contains(text, "--agent codex") {
		t.Errorf("dry run runs no Codex command:\n%s", text)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Errorf("dry run created %s", out)
	}
}

// The comparison's gated captures are found through the profiles, with the
// agent and session file the profile gives (I-98).
func TestComparisonFixturesComeFromTheProfiles(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 is not on PATH")
	}
	repo := repoRoot()
	const prog = `import os, sys
sys.dont_write_bytecode = True
sys.path.insert(0, sys.argv[1])
import common
for n in common.FIXTURES:
    s = common.fixture_subject(n)
    print(n, s.agent, os.path.exists(s.session), os.path.exists(s.ground_truth))
`
	b, err := exec.Command("python3", "-c", prog, filepath.Join(repo, "scripts", "compare")).CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 4 {
		t.Fatalf("want the four gated captures, got:\n%s", b)
	}
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) != 4 || f[1] != "claude-code" || f[2] != "True" || f[3] != "True" {
			t.Errorf("subject %q: want claude-code with its session and ground truth present", l)
		}
	}
}
