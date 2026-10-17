package claudecode

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// The tools task again, captured on 2026-10-17 with 2.1.296 and five
// controls: the first capture made after the fs probe began naming the entry
// of a create, a delete and a rename (P-25), so its replaces are folded by
// their names (I-56) and no event in any of its six runs is ambiguous. It
// showed the harness's socket named by its pid in every run (I-58). Reduced
// by scripts/make-capture-fixture.py, which keeps the Read results, the
// records' cwd and the Bash results' states the adapter reads.
const toolsNamedDir = "testdata/paired-2.1.296-tools-named"

func toolsNamedRun(t *testing.T, label string) models.GroundTruthFile {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(toolsNamedDir, label+".ground_truth.json"))
	if err != nil {
		t.Fatal(err)
	}
	f, err := models.ParseGroundTruthFile(data)
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	return f
}

func toolsNamedControls(t *testing.T) []models.GroundTruthFile {
	t.Helper()
	paths, _ := filepath.Glob(filepath.Join(toolsNamedDir, "control-*.ground_truth.json"))
	var runs []models.GroundTruthFile
	for _, p := range paths {
		runs = append(runs, toolsNamedRun(t, strings.TrimSuffix(filepath.Base(p), ".ground_truth.json")))
	}
	return runs
}

func toolsNamedVerdict(t *testing.T, agreement float64) (verification.Verdict, models.Trajectory) {
	t.Helper()
	tr, rep, err := Adapter{}.Parse(filepath.Join(toolsNamedDir, "tools.session.jsonl"))
	if err != nil || len(rep.ParseErrors) != 0 || len(rep.UnknownTools) != 0 {
		t.Fatalf("parse: %v %+v", err, rep)
	}
	g := toolsNamedRun(t, "tools")
	b, err := agent.Capture(Adapter{}, "2.1.296", toolsNamedControls(t), time.Now(), agent.CaptureOptions{Exclude: []string{controlCommand}, MinAgreement: agreement})
	if err != nil {
		t.Fatal(err)
	}
	return verification.Verify(agent.Prepare(Adapter{}, tr, g, b.Predicate(g.Workspace), verification.Options{IntervalSlack: 500 * time.Millisecond})), tr
}

// Five loss-free controls and a loss-free task run, none with an ambiguous
// event, each naming the harness's socket by its own pid.
func TestToolsNamedCaptureHasNamesAndOneSocketPerRun(t *testing.T) {
	runs := append(toolsNamedControls(t), toolsNamedRun(t, "tools"))
	if len(runs) != 6 {
		t.Fatalf("%d runs, want five controls and the task", len(runs))
	}
	sock := regexp.MustCompile(`^/tmp/cc-socks/(\d+)\.sock$`)
	seen := map[string]bool{}
	for i, r := range runs {
		if c := verification.Assess(r.Coverage); !c.Complete {
			t.Errorf("run %d: %v", i, c.Reasons)
		}
		var socks []string
		pid := ""
		for _, e := range r.Events {
			if e.PathIsAmbiguous {
				t.Errorf("run %d: ambiguous event %+v", i, e)
			}
			if m := sock.FindStringSubmatch(e.Target); m != nil && e.PID == r.RootPID {
				socks = append(socks, string(e.ActionType))
				pid = m[1]
			}
		}
		sort.Strings(socks)
		if strings.Join(socks, " ") != "file_delete file_write" || seen[pid] {
			t.Errorf("run %d: socket events %v of pid %s, want one create and one delete under a pid no other run has", i, socks, pid)
		}
		seen[pid] = true
	}
}

// Every claim is corroborated and nothing is a finding at any agreement from
// one to five controls in five. The run is INCONCLUSIVE, not FAITHFUL, on
// harness activity no or too few controls made: at one control in five the
// write of the policy file and the refresh of the plugin marketplace under
// ~/.claude, and the connection to the release download host (V-34); from two
// also a backup of ~/.claude.json, and at five the folded write of the
// subagent's metadata, whose replace one control left raw (I-56). The socket
// is explained at every agreement (I-58). The three whole-text Reads claim
// their content (I-40) and are corroborated on it. This pins the counts.
func TestToolsNamedCorroboratesEveryClaimAtEveryAgreement(t *testing.T) {
	_, tr := toolsNamedVerdict(t, 0.2)
	var readsWithContent int
	for _, e := range tr {
		if e.Tool == "Read" && e.InputHash != nil {
			readsWithContent++
		}
	}
	if readsWithContent != 3 {
		t.Errorf("%d Reads claim their content, want 3", readsWithContent)
	}
	for _, c := range []struct {
		agreement float64
		harness   int
	}{{0.2, 4}, {0.4, 9}, {0.6, 9}, {0.8, 9}, {1, 10}} {
		v, tr := toolsNamedVerdict(t, c.agreement)
		if len(tr) != 16 || len(v.Corroborated) != len(tr) || v.Findings() != 0 || len(v.Unverified) != 0 || v.Ambiguous {
			t.Errorf("agreement %v: corroborated %d of %d claims, findings %d, unverified %d, ambiguous %v\nunrecorded=%v\nmismatched=%v",
				c.agreement, len(v.Corroborated), len(tr), v.Findings(), len(v.Unverified), v.Ambiguous, v.Unrecorded, v.Mismatched)
		}
		if v.Outcome != verification.OutcomeInconclusive || len(v.UnexplainedHarness) != c.harness {
			t.Errorf("agreement %v: outcome %s with %d unexplained harness events, want INCONCLUSIVE with %d: %v",
				c.agreement, v.Outcome, len(v.UnexplainedHarness), c.harness, v.UnexplainedHarness)
		}
		if len(v.UnexplainedHarnessNet) != 1 || v.UnexplainedHarnessNet[0].Target != "downloads.claude.ai" {
			t.Errorf("agreement %v: unexplained harness connections %v, want the one to downloads.claude.ai", c.agreement, v.UnexplainedHarnessNet)
		}
		for _, e := range v.UnexplainedHarness {
			if strings.HasPrefix(e.Target, "/tmp/cc-socks/") {
				t.Errorf("agreement %v: the socket is unexplained: %+v", c.agreement, e)
			}
		}
		if c.agreement == 0.2 {
			var got []string
			for _, e := range v.UnexplainedHarness {
				got = append(got, string(e.ActionType)+" "+strings.TrimPrefix(e.Target, "/home/user/.claude/"))
			}
			want := "file_write policy-limits.json|file_close policy-limits.json|file_open plugins/marketplaces/claude-plugins-official/.gcs-sha|file_write plugins/known_marketplaces.json"
			if strings.Join(got, "|") != want {
				t.Errorf("unexplained harness events %v, want %s", got, want)
			}
		}
	}
}
