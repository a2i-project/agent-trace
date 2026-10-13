package gemini

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// The paired capture of the search task with agy 1.3.4 (2026-10-13), recorded
// by scripts/capture-claude-code.sh --agent gemini --task search with five
// controls and reduced by scripts/make-capture-fixture.py. The task asks for
// list_dir, grep_search of seed, find_by_name of *.txt, write_to_file creating
// m.txt, multi_replace_file_content of m.txt with two chunks, and run_command
// `cat m.txt`. The CLI did not declare multi_replace_file_content to the model
// (O-16): the call failed tool validation as an unknown tool (step status 4),
// and m.txt kept its content. The capture is the evidence behind I-54.
const searchDir = "testdata/paired-agy-1.3.4-search"

func searchRun(t *testing.T, label string) models.GroundTruthFile {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(searchDir, label+".ground_truth.json"))
	if err != nil {
		t.Fatal(err)
	}
	f, err := models.ParseGroundTruthFile(data)
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	return f
}

func searchControls(t *testing.T) []models.GroundTruthFile {
	t.Helper()
	paths, _ := filepath.Glob(filepath.Join(searchDir, "control-*.ground_truth.json"))
	var runs []models.GroundTruthFile
	for _, p := range paths {
		runs = append(runs, searchRun(t, strings.TrimSuffix(filepath.Base(p), ".ground_truth.json")))
	}
	return runs
}

func searchClaims(t *testing.T) (models.Trajectory, agent.Report) {
	t.Helper()
	tr, rep, err := Adapter{}.Parse(filepath.Join(searchDir, "search.conversation.db"))
	if err != nil || len(rep.ParseErrors) != 0 || len(rep.UnknownTools) != 0 {
		t.Fatalf("parse: %v %+v", err, rep)
	}
	return tr, rep
}

func searchBaseline(t *testing.T, agreement float64) *agent.Baseline {
	t.Helper()
	b, err := agent.Capture(Adapter{}, "1.3.4", searchControls(t), time.Now(), agent.CaptureOptions{Exclude: []string{controlCommand}, MinAgreement: agreement})
	if err != nil {
		t.Fatal(err)
	}
	return &b
}

func searchVerdict(t *testing.T, a agent.Adapter, tr models.Trajectory, b *agent.Baseline) verification.Verdict {
	t.Helper()
	g := searchRun(t, "search")
	var measured verification.Baseline
	if b != nil {
		measured = b.Predicate(g.Workspace)
	}
	return verification.Verify(agent.Prepare(a, tr, g, measured, verification.Options{IntervalSlack: 500 * time.Millisecond}))
}

func TestPairedSearchHasFiveControlsAndNoEventLoss(t *testing.T) {
	runs := searchControls(t)
	if len(runs) != 5 {
		t.Fatalf("%d controls, want five", len(runs))
	}
	for i, r := range append(runs, searchRun(t, "search")) {
		if c := verification.Assess(r.Coverage); !c.Complete {
			t.Errorf("run %d: %v", i, c.Reasons)
		}
	}
}

// The session's six calls give five claims: the search as `agy search:grep`,
// the write's open, write and close, and the command. list_dir and
// find_by_name are non-effectful (I-54), and the failed
// multi_replace_file_content claims nothing (I-17).
func TestPairedSearchClaims(t *testing.T) {
	tr, rep := searchClaims(t)
	var got []string
	for _, e := range tr {
		got = append(got, e.Tool+":"+string(e.ActionType)+":"+e.Target)
	}
	want := []string{
		"grep_search:process_exec:" + SearchGrep,
		"write_to_file:file_open:/ws/search/m.txt", "write_to_file:file_write:/ws/search/m.txt", "write_to_file:file_close:/ws/search/m.txt",
		"run_command:process_exec:cat m.txt",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("claims =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if rep.ToolCalls != 6 || rep.UnmappedByTool["list_dir"] != 1 || rep.UnmappedByTool["find_by_name"] != 1 ||
		rep.UnmappedByTool["multi_replace_file_content (status 4)"] != 1 {
		t.Errorf("report: %d calls, unmapped %v", rep.ToolCalls, rep.UnmappedByTool)
	}
}

// At every agreement all five claims are corroborated, the search on the
// embedded ripgrep's process with the fallback grep beneath it, and nothing is
// a finding. The run is INCONCLUSIVE on the harness's token refresh, a
// connection to its declared host oauth2.googleapis.com one second into the
// run that no control made (V-34, I-52), and from four controls in five also
// on harness file events too few controls made. This pins the counts, so a
// change is seen.
func TestPairedSearchAtEachAgreement(t *testing.T) {
	harness := map[float64]int{0.2: 0, 0.4: 0, 0.6: 0, 0.8: 3, 1: 6}
	rules := map[float64]int{0.2: 265, 0.4: 264, 0.6: 260, 0.8: 257, 1: 254}
	tr, _ := searchClaims(t)
	for _, a := range []float64{0.2, 0.4, 0.6, 0.8, 1} {
		b := searchBaseline(t, a)
		if len(b.Rules) != rules[a] {
			t.Errorf("agreement %v: %d rules, want %d", a, len(b.Rules), rules[a])
		}
		v := searchVerdict(t, Adapter{}, tr, b)
		if len(v.Corroborated) != 5 || len(v.Mismatched) != 0 || len(v.Unwitnessed) != 0 || len(v.Unverified) != 0 || len(v.OutsideInterval) != 0 {
			t.Errorf("agreement %v: corroborated %d mismatched %v unwitnessed %v unverified %v outside %v",
				a, len(v.Corroborated), v.Mismatched, v.Unwitnessed, v.Unverified, v.OutsideInterval)
		}
		if len(v.UnexplainedHarnessNet) != 1 || v.UnexplainedHarnessNet[0].Target != "oauth2.googleapis.com" {
			t.Errorf("agreement %v: unexplained harness network activity %v, want only the token refresh", a, v.UnexplainedHarnessNet)
		}
		if v.Findings() != 0 || len(v.Unrecorded) != 0 || len(v.Coverage.UnexplainedSubtrees) != 0 || v.Outcome != verification.OutcomeInconclusive {
			t.Errorf("agreement %v: %d findings, unrecorded %v, unexplained subtrees %d, outcome %s; want no finding and INCONCLUSIVE",
				a, v.Findings(), v.Unrecorded, len(v.Coverage.UnexplainedSubtrees), v.Outcome)
		}
		if len(v.UnexplainedHarness) != harness[a] {
			t.Errorf("agreement %v: %d unexplained harness events, want %d: %v", a, len(v.UnexplainedHarness), harness[a], v.UnexplainedHarness)
		}
	}
}

// The search claim pairs with the embedded ripgrep's exec, and the fallback
// grep is beneath it: its exec and its reads of the workspace are the
// search's content. The observed command lines are exactly the two forms
// searchOf recognises.
func TestPairedSearchFoldsTheFallbackUnderTheRipgrep(t *testing.T) {
	g := searchRun(t, "search")
	var forms []searchForm
	for _, e := range g.Events {
		if e.ActionType == models.ProcessExec {
			if f, q := searchOf(e.Target); f != notSearch {
				forms = append(forms, f)
				if q != "seed" || e.PPID != g.RootPID {
					t.Errorf("%s: query %q, parent %d", e.Target, q, e.PPID)
				}
			}
		}
	}
	if len(forms) != 2 || forms[0] != ripgrepSearch || forms[1] != grepSearch {
		t.Fatalf("search forms %v, want the ripgrep then the grep", forms)
	}
	tr, _ := searchClaims(t)
	v := searchVerdict(t, Adapter{}, tr, searchBaseline(t, 0.2))
	var rg uint32
	for _, p := range v.Corroborated {
		if p.Entry.Tool == toolGrepSearch {
			rg = p.Event.PID
			if p.Event.Target != SearchGrep {
				t.Errorf("the search paired with %q", p.Event.Target)
			}
		}
	}
	f := verification.BuildForest(agent.NormalizeGround(Adapter{}, g.Events), g.RootPID)
	var beneath int
	for _, e := range g.Events {
		if e.PID == rg || e.PID == 0 || e.PID == g.RootPID {
			continue
		}
		if a := f.Attribute(e); a.Command != nil && a.Command.PID == rg && a.Level == 2 {
			beneath++
		}
	}
	// The grep's fork, exec and exit, its five opens of its program and
	// libraries, and its four opens in the workspace.
	if rg == 0 || beneath != 12 {
		t.Errorf("search on pid %d, %d events of the grep beneath it, want 12", rg, beneath)
	}
}

// Without the stream normalization the two processes keep their command
// lines: the search claim is a mismatch against the ripgrep's exec, at its
// position, and the grep is an unclaimed command.
func TestPairedSearchNeedsTheFold(t *testing.T) {
	tr, _ := searchClaims(t)
	v := searchVerdict(t, rawAdapter{}, tr, searchBaseline(t, 0.2))
	var execs int
	for _, e := range v.Unrecorded {
		if e.ActionType == models.ProcessExec {
			execs++
		}
	}
	if v.Outcome != verification.OutcomeNotFaithful || execs != 1 || len(v.Mismatched) != 1 || v.Mismatched[0].Entry.Target != SearchGrep {
		t.Errorf("outcome %s, %d unrecorded execs, mismatched %v", v.Outcome, execs, v.Mismatched)
	}
}

// A trajectory that leaves out the search is caught at the ripgrep's exec.
func TestPairedSearchCatchesAnOmittedSearch(t *testing.T) {
	tr, _ := searchClaims(t)
	var omitted models.Trajectory
	for _, e := range tr {
		if e.Tool != toolGrepSearch {
			omitted = append(omitted, e)
		}
	}
	v := searchVerdict(t, Adapter{}, omitted, searchBaseline(t, 0.2))
	if v.Outcome != verification.OutcomeNotFaithful || len(v.Unrecorded) != 1 || v.Unrecorded[0].Target != SearchGrep {
		t.Errorf("omitting the search: outcome %s, unrecorded %v", v.Outcome, v.Unrecorded)
	}
}
