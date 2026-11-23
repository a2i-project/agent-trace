package verification_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/agent"
	_ "github.com/agent-trace/agent-trace/pkg/agent/claudecode"
	_ "github.com/agent-trace/agent-trace/pkg/agent/codex"
	_ "github.com/agent-trace/agent-trace/pkg/agent/gemini"
	_ "github.com/agent-trace/agent-trace/pkg/agent/opencode"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// pairedFixture is one checked-in task run with the adapter and session
// that read it.
type pairedFixture struct {
	name, ground, session string
	adapter               agent.Adapter
}

func pairedFixtures(t *testing.T) []pairedFixture {
	t.Helper()
	adapters := map[string]string{"claudecode": "claude-code", "codex": "codex", "gemini": "gemini", "opencode": "opencode"}
	var out []pairedFixture
	dirs, _ := filepath.Glob("../agent/*/testdata/paired-*")
	for _, dir := range dirs {
		a, ok := agent.Lookup(adapters[filepath.Base(filepath.Dir(filepath.Dir(dir)))])
		if !ok {
			t.Fatalf("%s: no adapter", dir)
		}
		gts, _ := filepath.Glob(filepath.Join(dir, "*.ground_truth.json"))
		for _, gt := range gts {
			label := strings.TrimSuffix(filepath.Base(gt), ".ground_truth.json")
			if strings.HasPrefix(label, "control-") {
				continue
			}
			for _, ext := range []string{".session.jsonl", ".rollout.jsonl", ".conversation.db", ".opencode.db"} {
				if s := filepath.Join(dir, label+ext); fileExists(s) {
					out = append(out, pairedFixture{name: filepath.Base(dir), ground: gt, session: s, adapter: a})
				}
			}
		}
	}
	if len(out) < 20 {
		t.Fatalf("found %d paired fixtures, want every checked-in one", len(out))
	}
	return out
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func (f pairedFixture) verify(t *testing.T, claims models.Trajectory) verification.Verdict {
	t.Helper()
	data, err := os.ReadFile(f.ground)
	if err != nil {
		t.Fatal(err)
	}
	g, err := models.ParseGroundTruthFile(data)
	if err != nil {
		t.Fatal(err)
	}
	return verification.Verify(agent.Prepare(f.adapter, claims, g, nil, verification.Options{IntervalSlack: 500 * time.Millisecond}))
}

// No honest run of the checked-in fixtures, of four harnesses, has an order
// finding or a lifetime finding (V-105, V-106). Exchanging two consecutive
// claims of different lanes is an order finding when the probes' bounds
// make the exchange certain; the rate is logged.
func TestHonestFixturesHaveNoOrderOrLifetimeFinding(t *testing.T) {
	compared, swaps, caught := 0, 0, 0
	for _, f := range pairedFixtures(t) {
		claims, _, _, err := agent.ReadTrace(f.adapter, f.session, false)
		if err != nil {
			t.Fatalf("%s: %v", f.name, err)
		}
		v := f.verify(t, claims)
		if len(v.OrderViolations) != 0 || len(v.Lifetimes.Findings) != 0 {
			t.Errorf("%s: order %+v, lifetime %+v", f.name, v.OrderViolations, v.Lifetimes.Findings)
		}
		compared += v.Lifetimes.Compared + v.Lifetimes.StartOnly
		for i := 0; i+1 < len(claims); i++ {
			a, b := claims[i], claims[i+1]
			if verification.LaneOf(a.ActionType) == verification.LaneOf(b.ActionType) || a.ThreadID != b.ThreadID || (a.BlockID != "" && a.BlockID == b.BlockID) || a.ImpliedBy != "" || b.ImpliedBy != "" {
				continue
			}
			swapped := append(models.Trajectory{}, claims...)
			swapped[i], swapped[i+1] = b, a
			swaps++
			if len(f.verify(t, swapped).OrderViolations) > 0 {
				caught++
			}
		}
	}
	if compared == 0 || caught == 0 {
		t.Errorf("compared %d command claims, caught %d exchanges: the checks ran on nothing", compared, caught)
	}
	t.Logf("%d command claims compared with their lifetime; %d of %d exchanges of consecutive claims of two lanes are order findings", compared, caught, swaps)
}
