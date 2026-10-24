package claudecode

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// The tools task on Claude Code 2.1.306 (2026-10-24), with five controls and
// directory-entry names, as the named capture of 2.1.296. The probe saw the
// same shapes for Read, Edit, Write and NotebookEdit as on 2.1.296; what
// changed is the transcript, which now also holds api-request,
// api-request-shape and api-request-blob records. An api-request-blob copies
// an API request, whose content repeats earlier tool_use and tool_result
// blocks under the same ids, with no timestamp and no structured result: here
// the three Reads of one message and the two Edits with the ToolSearch of
// another. Read from such records, those six calls were claimed twice
// (I-62). Reduced by scripts/make-capture-fixture.py, which keeps the copies'
// tool blocks so the fixture shows the adapter the repeats.
const tools306Dir = "testdata/paired-2.1.306-tools"

func tools306Run(t *testing.T, label string) models.GroundTruthFile {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(tools306Dir, label+".ground_truth.json"))
	if err != nil {
		t.Fatal(err)
	}
	f, err := models.ParseGroundTruthFile(data)
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	return f
}

func tools306Controls(t *testing.T) []models.GroundTruthFile {
	t.Helper()
	paths, _ := filepath.Glob(filepath.Join(tools306Dir, "control-*.ground_truth.json"))
	var runs []models.GroundTruthFile
	for _, p := range paths {
		runs = append(runs, tools306Run(t, strings.TrimSuffix(filepath.Base(p), ".ground_truth.json")))
	}
	return runs
}

func tools306Verdict(t *testing.T, agreement float64) (verification.Verdict, models.Trajectory) {
	t.Helper()
	tr, rep, err := Adapter{}.Parse(filepath.Join(tools306Dir, "tools.session.jsonl"))
	if err != nil || len(rep.ParseErrors) != 0 || len(rep.UnknownTools) != 0 {
		t.Fatalf("parse: %v %+v", err, rep)
	}
	g := tools306Run(t, "tools")
	b, err := agent.Capture(Adapter{}, "2.1.306", tools306Controls(t), time.Now(), agent.CaptureOptions{Exclude: []string{controlCommand}, MinAgreement: agreement})
	if err != nil {
		t.Fatal(err)
	}
	return verification.Verify(agent.Prepare(Adapter{}, tr, g, b.Predicate(g.Workspace), verification.Options{IntervalSlack: 500 * time.Millisecond})), tr
}

// Five loss-free controls and a loss-free task run, none with an ambiguous
// event.
func TestTools306CaptureHasFiveControlsNamesAndNoEventLoss(t *testing.T) {
	runs := append(tools306Controls(t), tools306Run(t, "tools"))
	if len(runs) != 6 {
		t.Fatalf("%d runs, want five controls and the task", len(runs))
	}
	for i, r := range runs {
		if c := verification.Assess(r.Coverage); !c.Complete {
			t.Errorf("run %d: %v", i, c.Reasons)
		}
		for _, e := range r.Events {
			if e.PathIsAmbiguous {
				t.Errorf("run %d: ambiguous event %+v", i, e)
			}
		}
	}
}

// Every tool the task used is claimed once: 14 calls, 16 claims, the
// subagent's Write from its own transcript, the three whole-text Reads with
// their content (I-40) and the two Edits with theirs (I-31).
func TestTools306TaskClaimsEveryToolItUsedOnce(t *testing.T) {
	tr, rep, err := Adapter{}.Parse(filepath.Join(tools306Dir, "tools.session.jsonl"))
	if err != nil || len(rep.UnknownTools) != 0 || len(rep.ParseErrors) != 0 {
		t.Fatalf("parse: %v %+v", err, rep)
	}
	if rep.AgentVersion != "2.1.306" || rep.ToolCalls != 14 || rep.Entries != 16 || len(tr) != 16 ||
		rep.UnmappedByTool["Agent"] != 1 || rep.UnmappedByTool["ToolSearch"] != 1 {
		t.Errorf("version %s, %d calls, %d entries, unmapped %v; want 2.1.306, 14, 16, Agent 1 and ToolSearch 1",
			rep.AgentVersion, rep.ToolCalls, rep.Entries, rep.UnmappedByTool)
	}
	var notebook, subagentWrite, readsWithContent, editWrites int
	for _, e := range tr {
		if e.Timestamp.IsZero() {
			t.Errorf("a claim with no timestamp: %+v", e)
		}
		switch {
		case e.Tool == "NotebookEdit" && e.ActionType == models.FileWrite:
			notebook++
		case e.Tool == "Write" && e.ThreadID != "" && strings.HasSuffix(e.Target, "/subagent.txt"):
			subagentWrite++
		case e.Tool == "Read" && e.InputHash != nil:
			readsWithContent++
		case e.Tool == "Edit" && e.ActionType == models.FileWrite && e.OutputHash != nil:
			editWrites++
		}
	}
	if notebook != 1 || subagentWrite != 1 || readsWithContent != 3 || editWrites != 2 {
		t.Errorf("NotebookEdit writes %d, subagent Writes %d, Reads with content %d, hashed Edit writes %d; want 1, 1, 3, 2",
			notebook, subagentWrite, readsWithContent, editWrites)
	}
}

// Every claim is corroborated and nothing is a finding at every agreement
// below all five controls. The run is INCONCLUSIVE on harness activity in the
// harness's own directories that too few controls made: at one control in
// five the task run's refresh of the model catalog cache, which no control
// made, and from two also the write of the policy file. At five in five the
// harness's package-manager probe (sh -c uname -s ...), which the task run
// and four controls ran and control-2 did not, is an Unrecorded command and
// an unexplained subtree: two findings, the occasional harness command of
// O-30, not an adapter misfit. This pins the counts.
func TestTools306CorroboratesEveryClaimAndPinsTheAgreements(t *testing.T) {
	for _, c := range []struct {
		agreement float64
		findings  int
		harness   int
	}{{0.2, 0, 1}, {0.4, 0, 3}, {0.6, 0, 3}, {0.8, 0, 3}, {1, 2, 8}} {
		v, tr := tools306Verdict(t, c.agreement)
		if len(tr) != 16 || len(v.Corroborated) != len(tr) || v.Findings() != c.findings || len(v.Unverified) != 0 || v.Ambiguous {
			t.Errorf("agreement %v: corroborated %d of %d claims, findings %d (want %d), unverified %d, ambiguous %v\nunrecorded=%v\nmismatched=%v\nunwitnessed=%v\noutside=%v",
				c.agreement, len(v.Corroborated), len(tr), v.Findings(), c.findings, len(v.Unverified), v.Ambiguous, v.Unrecorded, v.Mismatched, v.Unwitnessed, v.OutsideInterval)
		}
		want := verification.OutcomeInconclusive
		if c.findings > 0 {
			want = verification.OutcomeNotFaithful
		}
		if v.Outcome != want || len(v.UnexplainedHarness) != c.harness || len(v.UnexplainedHarnessNet) != 0 {
			t.Errorf("agreement %v: outcome %s with %d unexplained harness events and %d connections, want %s with %d and none: %v",
				c.agreement, v.Outcome, len(v.UnexplainedHarness), len(v.UnexplainedHarnessNet), want, c.harness, v.UnexplainedHarness)
		}
		if c.findings > 0 && (len(v.Unrecorded) != 1 || v.Unrecorded[0].ActionType != models.ProcessExec ||
			!strings.HasPrefix(v.Unrecorded[0].Target, "/usr/bin/sh -c uname -s\n") || len(v.Coverage.UnexplainedSubtrees) != 1) {
			t.Errorf("agreement %v: unrecorded %v, unexplained subtrees %d; want the package-manager probe and its subtree",
				c.agreement, v.Unrecorded, len(v.Coverage.UnexplainedSubtrees))
		}
		if c.agreement == 0.2 && (len(v.UnexplainedHarness) != 1 || v.UnexplainedHarness[0].ActionType != models.FileWrite ||
			!strings.HasPrefix(v.UnexplainedHarness[0].Target, "/home/user/.claude/cache/model-catalog/")) {
			t.Errorf("unexplained harness events %v, want the model catalog's write", v.UnexplainedHarness)
		}
	}
}

// tools306Records reads the fixture's transcript as raw records.
func tools306Records(t *testing.T) []map[string]any {
	t.Helper()
	f, err := os.Open(filepath.Join(tools306Dir, "tools.session.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		var r map[string]any
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

// tools306Session writes records as a session transcript in a new directory,
// with the fixture's subagent transcript beside it, and returns its path.
func tools306Session(t *testing.T, records []map[string]any) string {
	t.Helper()
	dir := t.TempDir()
	var b strings.Builder
	for _, r := range records {
		line, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	p := filepath.Join(dir, "tools.session.jsonl")
	if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	subs, _ := filepath.Glob(filepath.Join(tools306Dir, "tools.session", "subagents", "agent-*.jsonl"))
	if err := os.MkdirAll(filepath.Join(dir, "tools.session", "subagents"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, s := range subs {
		data, err := os.ReadFile(s)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "tools.session", "subagents", filepath.Base(s)), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

// The api-request-blob copies in the fixture repeat six calls and their
// results, and claim nothing: the transcript with them parses to exactly the
// claims and report of the transcript without them (I-62).
func TestTools306APIRequestCopiesClaimNothing(t *testing.T) {
	records := tools306Records(t)
	var without []map[string]any
	repeated := map[string]bool{}
	for _, r := range records {
		if r["type"] != "api-request-blob" {
			without = append(without, r)
			continue
		}
		for _, b := range r["message"].(map[string]any)["content"].([]any) {
			if blk := b.(map[string]any); blk["type"] == "tool_use" {
				repeated[blk["id"].(string)] = true
			}
		}
	}
	if len(records)-len(without) != 4 || len(repeated) != 6 {
		t.Fatalf("%d api-request-blob records repeating %d calls, want 4 repeating 6", len(records)-len(without), len(repeated))
	}
	got, gotRep, err := Adapter{}.Parse(filepath.Join(tools306Dir, "tools.session.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	want, wantRep, err := Adapter{}.Parse(tools306Session(t, without))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(gotRep, wantRep) {
		t.Errorf("the copies changed the parse:\nwith    %+v\n%v\nwithout %+v\n%v", gotRep, got, wantRep, want)
	}
}

// A call or a result stated twice by records that do state calls is claimed
// once, and each repeat is a parse error (I-62). The copies are relabelled as
// the assistant's and the user's records, by the role their message carries.
func TestTools306RepeatedCallsAreParseErrorsNotSecondClaims(t *testing.T) {
	records := tools306Records(t)
	for _, r := range records {
		if r["type"] == "api-request-blob" {
			r["type"] = r["message"].(map[string]any)["role"]
		}
	}
	tr, rep, err := Adapter{}.Parse(tools306Session(t, records))
	if err != nil {
		t.Fatal(err)
	}
	want, _, err := Adapter{}.Parse(filepath.Join(tools306Dir, "tools.session.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(tr, want) || rep.ToolCalls != 14 {
		t.Errorf("relabelled copies gave %d calls and %d claims, want 14 calls and the fixture's %d claims", rep.ToolCalls, len(tr), len(want))
	}
	var uses, results int
	for _, e := range rep.ParseErrors {
		switch {
		case strings.Contains(e, ": tool_use ") && strings.HasSuffix(e, " repeated; the first is kept"):
			uses++
		case strings.Contains(e, ": tool_result ") && strings.HasSuffix(e, " repeated; the first is kept"):
			results++
		default:
			t.Errorf("unexpected parse error %q", e)
		}
	}
	if uses != 6 || results != 6 {
		t.Errorf("%d repeated calls and %d repeated results reported, want 6 and 6: %v", uses, results, rep.ParseErrors)
	}
}
