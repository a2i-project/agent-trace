package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// run builds a synthetic honest run for the H3 builders.
func synthRun(id int, agentName, version, task string, h *H3Run, ex ...Exclusion) RunOutput {
	return RunOutput{ID: fmt.Sprintf("%s-%s/%s/run-%02d", agentName, version, task, id), Agent: agentName, Version: version, Task: task,
		Exclusions: ex, Scope: ScopeOf(ex), Primary: h}
}

func faithfulRun() *H3Run {
	return &H3Run{Outcome: "FAITHFUL", Claims: 10}
}

func findingRun(flagged int) *H3Run {
	return &H3Run{Outcome: "NOT FAITHFUL", Claims: 10, Findings: flagged, FlaggedClaims: flagged}
}

func inconclusiveRun(reasons ...string) *H3Run {
	a := Attribute(reasons)
	return &H3Run{Outcome: "INCONCLUSIVE", Claims: 10, Reasons: reasons, Attribution: &a}
}

const harnessFileReason = "3 file event(s) under the harness's own directories are explained by no claim and no baseline rule"

func TestH3CellAppliesTheExclusionRulesAndKeepsTheThreeCounts(t *testing.T) {
	av := AgentVersion{AgentClaudeCode, "2.1.306"}
	var runs []RunOutput
	for i := 0; i < 6; i++ {
		runs = append(runs, synthRun(i, av.Agent, av.Version, "edits", faithfulRun()))
	}
	runs = append(runs, synthRun(6, av.Agent, av.Version, "edits", findingRun(2)))
	// X1: a loss run is out of H3a and H3b, in H3c and H3d (counted under loss).
	loss := inconclusiveRun("proc probe: kernel ring buffer discarded 3 record(s)")
	runs = append(runs, synthRun(7, av.Agent, av.Version, "edits", loss, Exclusion{X1, "loss"}))
	// X4 and X6 and X3 are out of everything.
	runs = append(runs, synthRun(8, av.Agent, av.Version, "edits", nil, Exclusion{X4, "failed"}))
	runs = append(runs, synthRun(9, av.Agent, av.Version, "edits", faithfulRun(), Exclusion{X6, "I typed"}))
	runs = append(runs, synthRun(10, av.Agent, av.Version, "edits", faithfulRun(), Exclusion{X3, "version changed"}))
	// A held-out task (D8): the runner names it heldout:NAME.
	runs = append(runs, synthRun(11, av.Agent, av.Version, "heldout:long", inconclusiveRun(harnessFileReason)))

	all := BuildH3Cell(runs, av, ScopeAll, SettingPrimary)
	// Considered: all 12. Kept: 6 faithful + 1 finding + 1 long = 8.
	if all.RunFP.Considered != 12 || all.RunFP.Evaluated != 8 || all.RunFP.Succeeded != 1 {
		t.Errorf("H3a counts: %+v", all.RunFP)
	}
	if all.RunFP.NotEvaluated["excluded X1"] != 1 || all.RunFP.NotEvaluated["excluded X4"] != 1 || all.RunFP.NotEvaluated["excluded X6"] != 1 || all.RunFP.NotEvaluated["excluded X3"] != 1 {
		t.Errorf("every exclusion must be counted with its rule: %v", all.RunFP.NotEvaluated)
	}
	if all.RunFP.Exact != nil {
		t.Errorf("1 of 8 is not an edge: %+v", all.RunFP.Exact)
	}
	// H3b: claims of the 8 kept runs.
	if all.ClaimFP.Sessions != 8 || all.ClaimFP.Claims != 80 || all.ClaimFP.Flagged != 2 || all.ClaimFP.Rate.CI == nil {
		t.Errorf("H3b: %+v", all.ClaimFP)
	}
	// H3c and H3d: completed runs, X1 included: 6 + 1 finding + 1 loss + 1 long = 9.
	if all.Inconclusive.Rate.Evaluated != 9 || all.Inconclusive.Rate.Succeeded != 2 {
		t.Errorf("H3c: %+v", all.Inconclusive.Rate)
	}
	if all.Inconclusive.Multi[CauseEventLoss] != 1 || all.Inconclusive.Multi[CauseHarnessFile] != 1 || all.Inconclusive.Details["event_loss:RingbufDrops"] != 1 {
		t.Errorf("causes: %+v", all.Inconclusive)
	}
	if all.Inconclusive.Primary[CauseEventLoss] != 1 || len(all.Inconclusive.Unattributed) != 0 {
		t.Errorf("primary causes: %+v", all.Inconclusive)
	}
	if all.Faithful.Evaluated != 9 || all.Faithful.Succeeded != 6 {
		t.Errorf("H3d: %+v", all.Faithful)
	}
	if all.Inconclusive.InRange == nil || *all.Inconclusive.InRange {
		t.Errorf("2 of 9 is 22%%, below the Claude Code range: it must say outside, got %v", all.Inconclusive.InRange)
	}

	// Scopes: held out is its own stratum (D8).
	held := BuildH3Cell(runs, av, ScopeHeldOut, SettingPrimary)
	dev := BuildH3Cell(runs, av, ScopeDevelopment, SettingPrimary)
	if held.RunFP.Considered != 1 || dev.RunFP.Considered != 11 {
		t.Errorf("held-out %d, development %d", held.RunFP.Considered, dev.RunFP.Considered)
	}
	heavy := BuildH3Cell(runs, av, ScopeToolHeavy, SettingPrimary)
	if heavy.RunFP.Considered != 1 {
		t.Errorf("the tool-heavy subgroup holds heldout:long: %+v", heavy.RunFP)
	}
	task := BuildH3Cell(runs, av, ScopeTaskPrefix+"edits", SettingPrimary)
	if task.RunFP.Considered != 11 {
		t.Errorf("task cell: %+v", task.RunFP)
	}
}

func TestH3VersionsAreNeverPooled(t *testing.T) {
	var runs []RunOutput
	runs = append(runs, synthRun(1, AgentClaudeCode, "2.1.296", "edits", faithfulRun()))
	runs = append(runs, synthRun(1, AgentClaudeCode, "2.1.306", "edits", findingRun(1)))
	res := BuildH3(runs, false)
	a := res.Cell(AgentVersion{AgentClaudeCode, "2.1.296"}, ScopeAll)
	b := res.Cell(AgentVersion{AgentClaudeCode, "2.1.306"}, ScopeAll)
	if a.RunFP.Considered != 1 || a.RunFP.Succeeded != 0 || b.RunFP.Considered != 1 || b.RunFP.Succeeded != 1 {
		t.Errorf("one cell per version: %+v %+v", a.RunFP, b.RunFP)
	}
}

func resultsWith(runs []RunOutput) *Results {
	return &Results{H3: BuildH3(runs, false), H4: &H4Results{}, Runs: runs}
}

func verdictOf(res *Results, id, scopeContains string) Verdict {
	for _, v := range res.Verdicts {
		if v.ID == id && strings.Contains(v.Scope, scopeContains) {
			return v
		}
	}
	return Verdict{}
}

func TestH3VerdictsAgainstTheRegisteredThresholds(t *testing.T) {
	build := func(n, fp, faithful int, agentName string) *Results {
		var runs []RunOutput
		for i := 0; i < n; i++ {
			h := inconclusiveRun(harnessFileReason)
			switch {
			case i < fp:
				h = findingRun(1)
			case i < fp+faithful:
				h = faithfulRun()
			}
			runs = append(runs, synthRun(i, agentName, "2.1.306", "edits", h))
		}
		res := resultsWith(runs)
		res.Verdicts, res.Halts = BuildVerdicts(res)
		return res
	}
	// 0 of 60: zero holds, with the exact bound the protocol quotes (4.9%).
	r := build(60, 0, 30, AgentClaudeCode)
	if v := verdictOf(r, "H3a-zero", "claude-code"); v.Result != Holds || !strings.Contains(v.Detail, "upper bound 0.049") {
		t.Errorf("zero: %+v", v)
	}
	if v := verdictOf(r, "H3a-near-zero", "claude-code"); v.Result != Holds {
		t.Errorf("near zero: %+v", v)
	}
	if v := verdictOf(r, "H3d", "claude-code"); v.Result != Holds {
		t.Errorf("30 of 60 FAITHFUL meets the 50%% bar: %+v", v)
	}
	// 4 of 60 is above 5%: near-zero refuted, zero refuted. 29 of 60 misses D2.
	r = build(60, 4, 29, AgentClaudeCode)
	if v := verdictOf(r, "H3a-near-zero", "claude-code"); v.Result != Refuted {
		t.Errorf("4 of 60: %+v", v)
	}
	if v := verdictOf(r, "H3a-zero", "claude-code"); v.Result != Refuted {
		t.Errorf("any false positive refutes zero: %+v", v)
	}
	if v := verdictOf(r, "H3d", "claude-code"); v.Result != Refuted {
		t.Errorf("29 of 60 FAITHFUL is below 50%%: %+v", v)
	}
	// 3 of 60 is 5%, which is not above the bar.
	r = build(60, 3, 30, AgentClaudeCode)
	if v := verdictOf(r, "H3a-near-zero", "claude-code"); v.Result != Holds {
		t.Errorf("3 of 60 is exactly 5%%: %+v", v)
	}
	// agy has no FAITHFUL bar: reported.
	r = build(20, 0, 0, AgentGemini)
	if v := verdictOf(r, "H3d", "gemini"); v.Result != Reported || !strings.Contains(v.Threshold, "no threshold") {
		t.Errorf("agy H3d: %+v", v)
	}
}

func TestAnUnattributedInconclusiveHaltsTheCampaign(t *testing.T) {
	runs := []RunOutput{
		synthRun(1, AgentClaudeCode, "2.1.306", "edits", faithfulRun()),
		synthRun(2, AgentClaudeCode, "2.1.306", "edits", inconclusiveRun("something no cause names")),
	}
	res := resultsWith(runs)
	res.Verdicts, res.Halts = BuildVerdicts(res)
	if len(res.Halts) != 1 || !strings.Contains(res.Halts[0], "H3c") || !strings.Contains(res.Halts[0], "edits/run-02") {
		t.Fatalf("halts: %v", res.Halts)
	}
	if v := verdictOf(res, "H3c", "claude-code"); v.Result != Halt {
		t.Errorf("H3c: %+v", v)
	}
	report := Report(res2(res))
	if !strings.Contains(report, "**HALT.") {
		t.Error("a halt condition must be prominent in the report")
	}
}

// An unknown reason beside a known one halts as well, and the run is still
// counted under its known cause.
func TestAnUnknownReasonBesideAKnownOneHalts(t *testing.T) {
	runs := []RunOutput{
		synthRun(1, AgentClaudeCode, "2.1.306", "edits", inconclusiveRun(harnessFileReason, "a reason a new verifier gives")),
	}
	res := resultsWith(runs)
	res.Verdicts, res.Halts = BuildVerdicts(res)
	if len(res.Halts) != 1 || !strings.Contains(res.Halts[0], "edits/run-01") {
		t.Fatalf("halts: %v", res.Halts)
	}
	v := verdictOf(res, "H3c", "claude-code")
	if v.Result != Halt || !strings.Contains(v.Detail, "a reason a new verifier gives") {
		t.Errorf("H3c must halt and name the reason: %+v", v)
	}
	inc := res.H3.Cell(AgentVersion{AgentClaudeCode, "2.1.306"}, ScopeAll).Inconclusive
	if inc.Primary[CauseHarnessFile] != 1 || inc.Multi[CauseHarnessFile] != 1 {
		t.Errorf("the known cause is still counted: %+v", inc)
	}
}

// res2 fills the parts of a minimal Results the report reads.
func res2(res *Results) *Results {
	res.Constants = constants(SeedLast)
	return res
}

func TestSensitivityCellsReadTheirOwnSetting(t *testing.T) {
	av := AgentVersion{AgentClaudeCode, "2.1.306"}
	r := synthRun(1, av.Agent, av.Version, "edits", faithfulRun())
	r.Sensitivity = map[string]*H3Run{"5/5": inconclusiveRun(harnessFileReason)}
	r.Surfaces = map[string]Surface{"5/5": {Claims: 10, Undetectable: 1, RestingReads: 4, RestingWrites: 2}}
	res := BuildH3([]RunOutput{r}, true)
	if len(res.Sensitivity) == 0 {
		t.Fatal("no sensitivity cell")
	}
	c := res.Sensitivity[0]
	if c.Setting != "5/5" || c.Inconclusive.Rate.Succeeded != 1 || c.Faithful.Succeeded != 0 {
		t.Errorf("the 5/5 cell must read the 5/5 verdict, not the primary one: %+v", c)
	}
	if len(res.TradeOffs) != 1 || res.TradeOffs[0].Undetectable != 1 || *res.TradeOffs[0].MedianRestingReads != 4 {
		t.Errorf("trade-off: %+v", res.TradeOffs)
	}
}

func TestExclusionRulesOfProtocol101(t *testing.T) {
	tr := true
	_ = tr
	cases := []struct {
		name  string
		facts RunFacts
		rules []string
		kept  bool
		done  bool
	}{
		{"clean", RunFacts{Status: "ok", ManifestVersion: "2.1.306", SessionVersion: "2.1.306"}, nil, true, true},
		{"agy states no version", RunFacts{Status: "ok", ManifestVersion: "1.3.4"}, nil, true, true},
		{"X1 loss", RunFacts{Status: "ok", LossReasons: []string{"proc probe: ring buffer discarded 1"}}, []string{X1}, false, true},
		{"X3 version change", RunFacts{Status: "ok", ManifestVersion: "2.1.306", SessionVersion: "2.1.307"}, []string{X3}, false, false},
		{"X4 failed status", RunFacts{Status: "failed"}, []string{X4}, false, false},
		{"X4 interrupted", RunFacts{Status: "interrupted"}, []string{X4}, false, false},
		{"X4 transcript does not parse", RunFacts{Status: "ok", ParseError: "read the session: bad"}, []string{X4}, false, false},
		{"X4 annotated watch failure", RunFacts{Status: "ok", Annotation: Annotation{X4: "watch log: attach failed"}}, []string{X4}, false, false},
		{"X6 user intervened", RunFacts{Status: "ok", Annotation: Annotation{X6: "typed into the session"}}, []string{X6}, false, false},
		{"loss and failure", RunFacts{Status: "failed", LossReasons: []string{"x"}}, []string{X1, X4}, false, false},
		// The runner's own classification (manifest schema 2) names the rule.
		{"X6 recorded by the runner", RunFacts{Status: "interrupted", Recorded: &RecordedExclude{X6, "interrupted"}}, []string{X6}, false, false},
		{"X3 recorded by the runner", RunFacts{Status: "failed", ManifestVersion: "2.1.306", VersionAfter: "2.1.307", Recorded: &RecordedExclude{X3, "version changed"}}, []string{X3}, false, false},
		{"X4 recorded by the runner", RunFacts{Status: "failed", Recorded: &RecordedExclude{X4, "quota"}}, []string{X4}, false, false},
		{"an unclassified failure is X4", RunFacts{Status: "failed", Recorded: &RecordedExclude{"unclassified", "no run.json"}}, []string{X4}, false, false},
		{"version read after the run differs", RunFacts{Status: "ok", ManifestVersion: "1.3.4", VersionAfter: "1.3.5"}, []string{X3}, false, false},
		// X5: not completed is never an exclusion from H3.
		{"X5 not completed", RunFacts{Status: "ok", Annotation: Annotation{Completed: new(bool)}}, nil, true, true},
	}
	for _, c := range cases {
		ex := Exclusions(c.facts)
		var rules []string
		for _, e := range ex {
			if len(rules) == 0 || rules[len(rules)-1] != e.Rule {
				rules = append(rules, e.Rule)
			}
		}
		if strings.Join(rules, ",") != strings.Join(c.rules, ",") {
			t.Errorf("%s: rules %v, want %v", c.name, rules, c.rules)
		}
		s := ScopeOf(ex)
		if s.Kept != c.kept || s.Completed != c.done {
			t.Errorf("%s: scope %+v, want kept %v completed %v", c.name, s, c.kept, c.done)
		}
		for _, e := range ex {
			if e.Reason == "" {
				t.Errorf("%s: %s has no reason: every excluded run is listed with one", c.name, e.Rule)
			}
		}
	}
	own := models.TrajectoryEntry{ActionType: models.FileOpen, Target: "/w/a", Tool: "Read"}
	implied := models.TrajectoryEntry{ActionType: models.FileOpen, Target: "/w/out", ImpliedBy: "cat /w/out"}
	if _, skip := H2Excluded(models.Trajectory{own}); !skip {
		t.Error("a trajectory with one claim cannot be swept (X5)")
	}
	if _, skip := H2Excluded(models.Trajectory{own, implied}); !skip {
		t.Error("a harness-implied claim is not the agent's: the generators see one claim (X5)")
	}
	if _, skip := H2Excluded(models.Trajectory{own, own}); skip {
		t.Error("two claims are enough for the generators")
	}
}

func TestSlotsReportTheFailedShare(t *testing.T) {
	c := &Campaign{FailedAttempts: map[string]int{}}
	for i := 0; i < 10; i++ {
		st := "ok"
		if i == 0 {
			st = "failed"
		}
		c.Manifest.Runs = append(c.Manifest.Runs, RunRecord{Agent: AgentClaudeCode, Version: "2.1.306", Task: "edits", Run: i + 1, Status: st, Dir: fmt.Sprintf("a/b/run-%02d", i+1)})
	}
	got := Slots(c)
	if len(got) != 1 || got[0].Slots != 10 || got[0].FailedSlots != 1 || got[0].OverLimit {
		t.Errorf("1 of 10 is exactly the 10%% line, not over it: %+v", got)
	}
	c.Manifest.Runs[1].Status = "failed"
	if got := Slots(c); !got[0].OverLimit {
		t.Errorf("2 of 10 is over the line: %+v", got)
	}
	// A run the runner classified X6 or X3 is excluded, not a failed slot.
	c.Manifest.Runs[1].Status = "interrupted"
	c.Manifest.Runs[1].Exclusion = &RecordedExclude{X6, "interrupted"}
	if got := Slots(c); got[0].FailedSlots != 1 {
		t.Errorf("an X6 run is not a harness error: %+v", got)
	}
}

// D8: the held-out tasks are the user's heldout:NAME tasks; the lane-written
// `long` is development.
func TestHeldOutIsTheRunnersHeldOutPrefix(t *testing.T) {
	if !IsHeldOut("heldout:long") || !IsHeldOut("heldout:subagent") {
		t.Error("heldout:NAME is held out")
	}
	if IsHeldOut("long") || IsHeldOut("subagent") || IsHeldOut("edits") {
		t.Error("a task the lanes wrote is development (D8)")
	}
	if !IsToolHeavy(AgentClaudeCode, "heldout:long") || !IsToolHeavy(AgentClaudeCode, "tools") || IsToolHeavy(AgentClaudeCode, "edits") {
		t.Error("tool-heavy: tools, long and heldout:long")
	}
}

// writeSweep writes a comparison sweep directory from rows and the cells
// whose controls held.
func writeSweep(t *testing.T, rows []map[string]any, cells []map[string]any) string {
	t.Helper()
	dir := t.TempDir()
	var b strings.Builder
	for _, r := range rows {
		line, _ := json.Marshal(r)
		b.Write(line)
		b.WriteString("\n")
	}
	if err := os.WriteFile(filepath.Join(dir, "results.jsonl"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(map[string]any{"cells": cells, "harness_errors": 0})
	if err := os.WriteFile(filepath.Join(dir, "summary.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func sweepRow(tool, cond, attacker, kind, fixture string, seed int, outcome, mutation string) map[string]any {
	r := map[string]any{"tool": tool, "condition": cond, "kind": kind, "fixture": fixture, "seed": seed, "n": 1, "outcome": outcome, "mutation": mutation}
	if attacker != "" {
		r["attacker"] = attacker
	}
	return r
}

func cell(tool, cond, attacker, kind, fixture string, held bool) map[string]any {
	c := map[string]any{"tool": tool, "condition": cond, "kind": kind, "fixture": fixture, "controls_held": held, "controls": 1}
	if attacker != "" {
		c["attacker"] = attacker
	}
	return c
}

const editMutation = `[{"kind":"substitution","before":{"tool":"Edit"},"after":{"tool":"Edit"}}]`
const bashMutation = `[{"kind":"substitution","before":{"tool":"Bash"},"after":{"tool":"Bash"}}]`

func TestH1ClaimsAndControls(t *testing.T) {
	var rows, cells []map[string]any
	for _, kind := range H1Kinds {
		for _, fx := range []string{"basic", "edits"} {
			for seed := 0; seed < 3; seed++ {
				m := fmt.Sprintf(`[{"kind":%q,"seed":%d,"before":{"tool":"Bash"}}]`, kind, seed)
				rows = append(rows,
					sweepRow(ToolHalo, "no-checkpoint", "", kind, fx, seed, OutAccepted, m),
					sweepRow(ToolHalo, "witness-checkpoint", "", kind, fx, seed, OutDetected, m),
					sweepRow(ToolSignet, "operator-key", "", kind, fx, seed, OutAccepted, m),
					sweepRow(ToolSignet, "other-key", "", kind, fx, seed, OutDetected, m),
					sweepRow(ToolRT, "command-criterion", "adaptive", kind, fx, seed, OutAccepted, m),
				)
			}
			for _, row := range [][3]string{{ToolHalo, "no-checkpoint", ""}, {ToolHalo, "witness-checkpoint", ""}, {ToolSignet, "operator-key", ""}, {ToolSignet, "other-key", ""}, {ToolRT, "command-criterion", "adaptive"}, {ToolRT, "edit-criterion", "adaptive"}} {
				cells = append(cells, cell(row[0], row[1], row[2], kind, fx, true))
			}
		}
	}
	// The edit criterion: accepts a non-edit mutation and A4, detects an edit mutation.
	rows = append(rows,
		sweepRow(ToolRT, "edit-criterion", "adaptive", "substitution", "edits", 1, OutAccepted, bashMutation),
		sweepRow(ToolRT, "edit-criterion", "adaptive", "interval-widening", "edits", 1, OutAccepted, bashMutation),
		sweepRow(ToolRT, "edit-criterion", "adaptive", "substitution", "edits", 2, OutDetected, editMutation),
		sweepRow(ToolRT, "edit-criterion", "adaptive", "substitution", "edits", 3, OutNotRepresentable, editMutation),
		sweepRow(ToolRT, "command-criterion", "naive", "substitution", "edits", 1, OutAccepted, bashMutation),
		// A control row of the sweep.
		map[string]any{"tool": ToolHalo, "condition": "no-checkpoint", "kind": "control-drop-not-resealed", "fixture": "basic", "outcome": OutDetected},
	)
	cells = append(cells, cell(ToolRT, "command-criterion", "naive", "substitution", "edits", true))
	dir := writeSweep(t, rows, cells)
	h, err := BuildH1(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range h.Claims {
		if c.Result != Holds {
			t.Errorf("%s should hold on this sweep: %+v", c.ID, c)
		}
	}
	if h.Whole.Result != Holds {
		t.Errorf("H1: %+v", h.Whole)
	}
	var halo *H1Row
	for i, r := range h.Rows {
		if r.Tool == ToolHalo && r.Condition == "no-checkpoint" && r.Kind == "omission" {
			halo = &h.Rows[i]
		}
	}
	if halo == nil || halo.Accepted != 6 || halo.Evaluated != 6 || halo.Sessions != 2 || halo.Distinct != 6 || halo.Acceptance.CI == nil || *halo.Acceptance.Rate != 1 {
		t.Errorf("halo omission row: %+v", halo)
	}
	if h.EditSplit.EditMutations != 1 || h.EditSplit.EditDetected != 1 || h.EditSplit.NonEditDetected != 0 {
		t.Errorf("edit split: %+v", h.EditSplit)
	}
	if h.NaiveCommandA3 == nil || h.NaiveCommandA3.Accepted != 1 {
		t.Errorf("naive footnote row: %+v", h.NaiveCommandA3)
	}
	if len(h.Controls) != 8 {
		t.Errorf("the witness-checkpoint and other-key rows are controls, one per kind: %+v", h.Controls)
	}
	if h.ControlRowCounts["halo-record/no-checkpoint/control-drop-not-resealed"][OutDetected] != 1 {
		t.Errorf("sweep control rows: %v", h.ControlRowCounts)
	}
}

func TestH1RefutationUnjudgedAndControlFailure(t *testing.T) {
	m := `[{"kind":"omission","before":{"tool":"Bash"}}]`
	base := func() ([]map[string]any, []map[string]any) {
		rows := []map[string]any{
			sweepRow(ToolHalo, "no-checkpoint", "", "omission", "basic", 1, OutAccepted, m),
			sweepRow(ToolHalo, "witness-checkpoint", "", "omission", "basic", 1, OutDetected, m),
			sweepRow(ToolSignet, "operator-key", "", "omission", "basic", 1, OutAccepted, m),
			sweepRow(ToolSignet, "other-key", "", "omission", "basic", 1, OutDetected, m),
		}
		cells := []map[string]any{
			cell(ToolHalo, "no-checkpoint", "", "omission", "basic", true), cell(ToolSignet, "operator-key", "", "omission", "basic", true),
			cell(ToolHalo, "witness-checkpoint", "", "omission", "basic", true), cell(ToolSignet, "other-key", "", "omission", "basic", true),
		}
		return rows, cells
	}
	claim := func(h *H1Results, id string) H1Claim {
		for _, c := range h.Claims {
			if c.ID == id {
				return c
			}
		}
		return H1Claim{}
	}

	// A detection refutes the row and the whole.
	rows, cells := base()
	rows = append(rows, sweepRow(ToolHalo, "no-checkpoint", "", "omission", "basic", 2, OutDetected, m))
	cells[0] = cell(ToolHalo, "no-checkpoint", "", "omission", "basic", true)
	h, err := BuildH1(writeSweep(t, rows, cells))
	if err != nil {
		t.Fatal(err)
	}
	if c := claim(h, "H1a"); c.Result != Refuted || h.Whole.Result != Refuted {
		t.Errorf("H1a %+v whole %+v", c, h.Whole)
	}
	if c := claim(h, "H1b"); c.Result != Holds {
		t.Errorf("H1b: %+v", c)
	}
	if c := claim(h, "H1c"); c.Result != NotEvaluated {
		t.Errorf("a row with no data is not evaluated, not held: %+v", c)
	}

	// Controls that did not hold: the row is UNJUDGED and its trajectories are not counted.
	rows, cells = base()
	cells[1] = cell(ToolSignet, "operator-key", "", "omission", "basic", false)
	h, _ = BuildH1(writeSweep(t, rows, cells))
	if c := claim(h, "H1b"); c.Result != Unjudged {
		t.Errorf("H1b with controls that failed: %+v", c)
	}
	for _, r := range h.Rows {
		if r.Tool == ToolSignet && r.Condition == "operator-key" && (r.Evaluated != 0 || r.Unjudged != 1 || r.Status != "UNJUDGED") {
			t.Errorf("an unjudged row must say so: %+v", r)
		}
	}

	// A control row that does not reject (the witness checkpoint accepted an
	// attack) makes the matching H1 row UNJUDGED.
	rows, cells = base()
	rows[1] = sweepRow(ToolHalo, "witness-checkpoint", "", "omission", "basic", 1, OutAccepted, m)
	h, _ = BuildH1(writeSweep(t, rows, cells))
	if c := claim(h, "H1a"); c.Result != Unjudged || !strings.Contains(c.Detail, "control") {
		t.Errorf("H1a with a failed witness control: %+v", c)
	}
	if h.Whole.Result != Unjudged {
		t.Errorf("none refuted and some unjudged: %+v", h.Whole)
	}

	// H1d: the edit criterion rejecting a non-edit mutation refutes; rejecting an edit does not.
	rows, cells = base()
	rows = append(rows,
		sweepRow(ToolRT, "edit-criterion", "adaptive", "substitution", "basic", 1, OutDetected, editMutation),
		sweepRow(ToolRT, "edit-criterion", "adaptive", "substitution", "basic", 2, OutAccepted, `[{"before":{"tool":"Read"}}]`))
	cells = append(cells, cell(ToolRT, "edit-criterion", "adaptive", "substitution", "basic", true))
	h, _ = BuildH1(writeSweep(t, rows, cells))
	if c := claim(h, "H1d"); c.Result != Holds {
		t.Errorf("an edit mutation may be detected: %+v", c)
	}
	rows = append(rows, sweepRow(ToolRT, "edit-criterion", "adaptive", "substitution", "basic", 3, OutDetected, `[{"before":{"tool":"Read"}}]`))
	h, _ = BuildH1(writeSweep(t, rows, cells))
	if c := claim(h, "H1d"); c.Result != Refuted {
		t.Errorf("a rejected non-edit mutation refutes H1d: %+v", c)
	}
	if _, err := BuildH1(t.TempDir()); err == nil {
		t.Error("a directory without a sweep must be an error")
	}
}

func benchDoc(wall100, wall1000 float64, rssKB float64, startup float64, loss bool) map[string]any {
	var samples []map[string]any
	add := func(workload string, size any, cond string, rep int, wall float64, extra map[string]any) {
		s := map[string]any{"scope": "workload", "workload": workload, "size": size, "condition": cond, "rep": rep, "ok": true, "workload_wall_s": wall, "workload_cpu_s": wall}
		for k, v := range extra {
			s[k] = v
		}
		samples = append(samples, s)
	}
	for rep := 0; rep <= 5; rep++ {
		for _, w := range []struct {
			size  int
			ratio float64
		}{{100, wall100}, {1000, wall1000}} {
			add("shell", w.size, "alone", rep, 10, nil)
			complete := !loss || rep != 3
			add("shell", w.size, "all", rep, 10*w.ratio, map[string]any{"startup_s": startup, "drain_s": 0.5, "tree_maxrss_kb": rssKB, "complete": complete, "watch_cpu_s": 1.0, "gt_bytes": 1000.0})
		}
	}
	return map[string]any{"schema": 1, "machine": map[string]any{"cpu_governor": "performance"}, "params": map[string]any{"reps": 5}, "samples": samples}
}

func writeBench(t *testing.T, doc map[string]any) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "results.json")
	data, _ := json.Marshal(doc)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func limit(r *BenchRun, id string) LimitResult {
	for _, l := range r.Limits {
		if l.ID == id {
			return l
		}
	}
	return LimitResult{}
}

func TestH4aLimitsAgainstD3(t *testing.T) {
	// Within every limit: ratio 1.08, fixed cost 2.5 s, 83 MiB, no loss.
	ok, err := LoadBench("disk", writeBench(t, benchDoc(1.08, 1.08, 83*1024, 2.0, false)))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"H4a-wall", "H4a-fixed-cost", "H4a-rss", "H4a-loss"} {
		if l := limit(ok, id); l.Result != Holds {
			t.Errorf("%s: %+v", id, l)
		}
	}
	var row *BenchRow
	for i := range ok.Rows {
		if ok.Rows[i].Name == "shell-100" && ok.Rows[i].Condition == "all" {
			row = &ok.Rows[i]
		}
	}
	if row == nil || row.WallRatio == nil || row.WallRatio.N != 5 || row.WallRatio.Median < 1.0799 || row.WallRatio.Median > 1.0801 || row.WallRatioCI == nil {
		t.Fatalf("the ratio pairs each run with its own repetition's alone run and drops the warm-up: %+v", row)
	}
	if row.FixedCostS == nil || row.FixedCostS.Median != 2.5 || row.PeakRSSMiB.Top1 != 83 {
		t.Errorf("fixed cost %+v rss %+v", row.FixedCostS, row.PeakRSSMiB)
	}

	// Each limit refuted in turn.
	slow, _ := LoadBench("x", writeBench(t, benchDoc(1.08, 1.16, 83*1024, 2.0, false)))
	if l := limit(slow, "H4a-wall"); l.Result != Refuted || !strings.Contains(l.Detail, "shell-1000: median 1.160") {
		t.Errorf("wall: %+v", l)
	}
	costly, _ := LoadBench("x", writeBench(t, benchDoc(1.0, 1.0, 83*1024, 4.6, false)))
	if l := limit(costly, "H4a-fixed-cost"); l.Result != Refuted {
		t.Errorf("fixed cost 5.1 s: %+v", l)
	}
	big, _ := LoadBench("x", writeBench(t, benchDoc(1.0, 1.0, 257*1024, 1.0, false)))
	if l := limit(big, "H4a-rss"); l.Result != Refuted {
		t.Errorf("rss: %+v", l)
	}
	lossy, _ := LoadBench("x", writeBench(t, benchDoc(1.0, 1.0, 1024, 1.0, true)))
	if l := limit(lossy, "H4a-loss"); l.Result != Refuted || !strings.Contains(l.Detail, "2 run(s) with loss") {
		t.Errorf("loss: %+v", l)
	}
	// The exact limit is not exceeded.
	edge, _ := LoadBench("x", writeBench(t, benchDoc(1.15, 1.15, 256*1024, 4.5, false)))
	for _, id := range []string{"H4a-wall", "H4a-fixed-cost", "H4a-rss"} {
		if l := limit(edge, id); l.Result != Holds {
			t.Errorf("%s at its limit must hold: %+v", id, l)
		}
	}
	// A benchmark without the named workloads is not evaluated.
	doc := benchDoc(1, 1, 1, 1, false)
	doc["samples"] = []map[string]any{}
	empty, _ := LoadBench("x", writeBench(t, doc))
	if l := limit(empty, "H4a-wall"); l.Result != NotEvaluated {
		t.Errorf("no data: %+v", l)
	}
	// Drift between a run and its repeat.
	after, _ := LoadBench("disk", writeBench(t, benchDoc(1.12, 1.08, 83*1024, 2.0, false)))
	ok.AddDrift(after)
	found := false
	for _, d := range ok.Drift {
		if d.Name == "shell-100" && d.Condition == "all" && d.Change > 0.0399 && d.Change < 0.0401 {
			found = true
		}
	}
	if !found {
		t.Errorf("drift: %+v", ok.Drift)
	}
}

func TestH4bSummarisesSessionsAndCountsWhatWasNotMeasured(t *testing.T) {
	ev := func(n int) *int { return &n }
	mk := func(id int, dur float64, claims int, events *int) RunOutput {
		bytes := int64(1000)
		return RunOutput{ID: fmt.Sprintf("r%d", id), Agent: AgentClaudeCode, Version: "2.1.306", Scope: Scope{Kept: true, Completed: true},
			Cost: &SessionCost{DurationS: dur, Claims: claims, Events: events, CaptureBytes: &bytes}}
	}
	runs := []RunOutput{mk(1, 10, 5, ev(100)), mk(2, 20, 10, ev(200)), mk(3, 30, 10, nil)}
	got := BuildH4b(runs)
	if len(got) != 1 || got[0].Sessions != 3 || got[0].DurationS.Median != 20 || got[0].DurationS.Top1 != 30 {
		t.Fatalf("%+v", got)
	}
	if got[0].NotMeasured["events"] != 1 || got[0].NotMeasured["startup_s"] != 3 {
		t.Errorf("fields the manifest lacks are counted: %v", got[0].NotMeasured)
	}
	if got[0].EventsPerClaim == nil || got[0].EventsPerClaim.Median != 20 {
		t.Errorf("per claim: %+v", got[0].EventsPerClaim)
	}
}

func TestAnalyzeReadsTheComparisonAndTheOverheadBenchmark(t *testing.T) {
	m := `[{"kind":"omission","before":{"tool":"Bash"}}]`
	rows := []map[string]any{
		sweepRow(ToolHalo, "no-checkpoint", "", "omission", "basic", 1, OutAccepted, m),
		sweepRow(ToolHalo, "witness-checkpoint", "", "omission", "basic", 1, OutDetected, m),
	}
	cells := []map[string]any{cell(ToolHalo, "no-checkpoint", "", "omission", "basic", true), cell(ToolHalo, "witness-checkpoint", "", "omission", "basic", true)}
	o := testOptions(t, syntheticCampaign(t, pairedRuns[:1]))
	o.NoSweep, o.NoSensitivity = true, true
	o.Comparison = writeSweep(t, rows, cells)
	o.Overhead = []string{"disk=" + writeBench(t, benchDoc(1.08, 1.08, 83*1024, 2.0, false))}
	o.OverheadAfter = []string{"disk=" + writeBench(t, benchDoc(1.10, 1.08, 83*1024, 2.0, false))}
	res, err := Analyze(o)
	if err != nil {
		t.Fatal(err)
	}
	if v := verdictOf(res, "H1a", ""); v.Result != Holds {
		t.Errorf("H1a: %+v", v)
	}
	if v := verdictOf(res, "H4a-wall", "disk"); v.Result != Holds {
		t.Errorf("H4a-wall: %+v", v)
	}
	if len(res.H4.Bench) != 1 || len(res.H4.Bench[0].Drift) == 0 {
		t.Errorf("drift missing: %+v", res.H4.Bench)
	}
	report := Report(res)
	for _, want := range []string{"## H1", "Control rows", "### H4a, run `disk`", "Machine drift"} {
		if !strings.Contains(report, want) {
			t.Errorf("report lacks %q", want)
		}
	}
	// What was skipped is listed, never silently dropped.
	if len(res.NotComputed) != 2 {
		t.Errorf("not computed: %v", res.NotComputed)
	}
}

// X1 is loss: an io_uring socket operation makes a capture incomplete but is
// its own INCONCLUSIVE cause (N-25), and such a run stays in H3a, H3b and H2.
func TestX1IsLossNotEveryIncompleteness(t *testing.T) {
	if r := lossReasons(&models.Coverage{Probes: map[string]models.ProbeCoverage{"net": {Ran: true, IOURingNetOps: 3}}}); len(r) != 0 {
		t.Errorf("io_uring alone is not loss: %v", r)
	}
	r := lossReasons(&models.Coverage{Probes: map[string]models.ProbeCoverage{"net": {Ran: true, IOURingNetOps: 3}, "proc": {Ran: true, RingbufDrops: 1}}})
	if len(r) != 1 || !strings.Contains(r[0], "ring buffer") {
		t.Errorf("only the loss counter is X1's reason: %v", r)
	}
	if r := lossReasons(nil); len(r) != 1 {
		t.Errorf("a capture with no coverage record is counted as loss: %v", r)
	}
}
