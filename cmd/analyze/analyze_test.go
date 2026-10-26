package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/attack"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// fixtureRun describes one run of a synthetic campaign built from the
// checked-in paired captures.
type fixtureRun struct {
	agent, version, task string
	run                  int
	fixture              string // directory under pkg/agent, "" for a run with no files
	status               string
}

func fixtureDir(t *testing.T, rel string) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", "pkg", "agent", rel))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Skipf("fixture %s is absent: %v", rel, err)
	}
	return p
}

// syntheticCampaign lays out a campaign directory in the runner's layout: a
// manifest.json and, per run, <agent>-<version>/<task>/run-NN, here a symlink
// to a checked-in paired capture (read only), so no capture is copied.
func syntheticCampaign(t *testing.T, runs []fixtureRun) string {
	t.Helper()
	dir := t.TempDir()
	m := Manifest{Schema: 1, Generated: "2026-10-26T00:00:00+00:00", Commit: "deadbee"}
	for _, r := range runs {
		rel := filepath.Join(r.agent+"-"+r.version, r.task, "run-"+twoDigits(r.run))
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if r.fixture != "" {
			if err := os.Symlink(fixtureDir(t, r.fixture), full); err != nil {
				t.Fatal(err)
			}
		}
		rec := RunRecord{Agent: r.agent, Version: r.version, Task: r.task, Run: r.run, Mode: "identity", Dir: rel, Status: r.status, DurationS: 60}
		rec.Controls.Taken, rec.Controls.From = true, rel
		m.Runs = append(m.Runs, rec)
	}
	if err := writeJSON(filepath.Join(dir, "manifest.json"), m); err != nil {
		t.Fatal(err)
	}
	return dir
}

func twoDigits(n int) string { return fmt.Sprintf("%02d", n) }

var pairedRuns = []fixtureRun{
	{"claude-code", "2.1.296", "edits", 1, "claudecode/testdata/paired-2.1.296-edits", "ok"},
	{"claude-code", "2.1.296", "tools", 1, "claudecode/testdata/paired-2.1.296-tools", "ok"},
	{"gemini", "1.3.4", "basic", 1, "gemini/testdata/paired-agy-1.3.4-basic", "ok"},
	{"gemini", "1.3.4", "search", 1, "gemini/testdata/paired-agy-1.3.4-search", "ok"},
	{"claude-code", "2.1.296", "edits", 2, "", "failed"},
}

func testOptions(t *testing.T, dir string) Options {
	t.Helper()
	cfg, err := filepath.Abs(filepath.Join("..", "..", "config", "agents.json"))
	if err != nil {
		t.Fatal(err)
	}
	return Options{Campaign: dir, Out: dir, Config: cfg, LastSeed: 3, Jobs: 2}
}

// The end-to-end test: a campaign built from the paired fixtures, analysed in
// full, checked against what the fixtures are known to show (docs/architecture
// 50_attack_generators.md): the honest controls have no finding, every
// mutation of the gated captures is detected, classified and located, and the
// agy captures are INCONCLUSIVE for harness activity the baseline lacks.
func TestEndToEndOnPairedFixtures(t *testing.T) {
	dir := syntheticCampaign(t, pairedRuns)
	res, err := Analyze(testOptions(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Halts) != 0 {
		t.Fatalf("halt conditions on honest fixtures: %v", res.Halts)
	}
	byAgent := map[string]Counts{}
	for _, c := range res.Counts {
		byAgent[c.Agent] = c
	}
	cc, ag := byAgent[AgentClaudeCode], byAgent[AgentGemini]
	if cc.Considered != 3 || cc.Kept != 2 || cc.ByRule[X4] != 1 || ag.Considered != 2 || ag.Kept != 2 {
		t.Errorf("counts: claude-code %+v, gemini %+v", cc, ag)
	}
	if len(res.Excluded) != 1 || !strings.Contains(res.Excluded[0].ID, "edits/run-02") || res.Excluded[0].Exclusions[0].Rule != X4 {
		t.Fatalf("the failed slot must be listed as X4: %+v", res.Excluded)
	}
	for _, e := range res.Excluded[0].Exclusions {
		if strings.Contains(e.Reason, dir) {
			t.Errorf("a reason names the campaign's absolute path: %s", e.Reason)
		}
	}
	if len(res.Slots) != 2 || !res.Slots[0].OverLimit {
		t.Errorf("one failed slot of three is over the 10%% line: %+v", res.Slots)
	}

	// H3: no finding on an honest capture; every INCONCLUSIVE is attributed.
	for _, av := range []AgentVersion{{AgentClaudeCode, "2.1.296"}, {AgentGemini, "1.3.4"}} {
		cell := res.H3.Cell(av, ScopeAll)
		if cell == nil {
			t.Fatalf("no H3 cell for %v", av)
		}
		if cell.RunFP.Evaluated != 2 || cell.RunFP.Succeeded != 0 || cell.RunFP.Exact == nil || cell.RunFP.Exact.Kind != "upper" {
			t.Errorf("%v H3a: %+v", av, cell.RunFP)
		}
		if len(cell.Inconclusive.Unattributed) != 0 {
			t.Errorf("%v: unattributed INCONCLUSIVE runs %v", av, cell.Inconclusive.Unattributed)
		}
		if cell.ClaimFP.Claims == 0 || cell.ClaimFP.Flagged != 0 || cell.ClaimFP.Rate.CI == nil {
			t.Errorf("%v H3b: %+v", av, cell.ClaimFP)
		}
	}
	agy := res.H3.Cell(AgentVersion{AgentGemini, "1.3.4"}, ScopeAll)
	if agy.Inconclusive.Rate.Succeeded != 2 || agy.Inconclusive.Multi[CauseHarnessNet] != 2 {
		t.Errorf("both agy captures are INCONCLUSIVE on the token refresh (V-34): %+v", agy.Inconclusive)
	}
	if res.H3.Cell(AgentVersion{AgentClaudeCode, "2.1.296"}, ScopeToolHeavy) == nil {
		t.Error("the tools task belongs to the tool-heavy subgroup (D5)")
	}
	if len(res.H3.Sensitivity) == 0 || len(res.H3.TradeOffs) == 0 {
		t.Error("the sensitivity grid and its trade-off are missing")
	}
	loo := false
	for _, c := range res.H3.Sensitivity {
		loo = loo || c.Setting == SettingLOO
	}
	if !loo {
		t.Error("no leave-one-out cell: two claude-code captures share a pool")
	}

	// H2.
	if res.H2 == nil || res.H2.Sessions != 4 || !res.H2.Reduced {
		t.Fatalf("H2: %+v", res.H2)
	}
	if len(res.H2.Contradictions) != 0 {
		t.Errorf("an omission marked undetectable by design was detected: %+v", res.H2.Contradictions)
	}
	for _, m := range res.H2.Misses {
		t.Errorf("a detectable mutation was missed: %+v", m.Entry)
	}
	for _, a := range res.H2.A4 {
		if len(a.Violations) != 0 || len(a.ComposedMisses) != 0 || a.Positions == 0 || a.ComposedPositions == 0 {
			t.Errorf("A4 on %s: %+v", a.Agent, a)
		}
	}
	// The gated gemini captures: every detectable mutation detected, classified, located.
	t3 := PrimaryPooled(res.Runs, AgentGemini, false)
	if t3.Detectable == 0 || t3.Detected != t3.Detectable || t3.Classified != t3.Detectable || t3.Located != t3.Detectable {
		t.Errorf("gemini primary tally: %+v", t3)
	}
	// The tools capture shows mislocation cases, none of them a path artefact.
	rm := 0
	for _, c := range res.H2.MislocationCases {
		rm++
		if c.Category < Mis1 || c.Category > Mis6 {
			t.Errorf("category %d", c.Category)
		}
	}
	if rm == 0 {
		t.Error("the tools capture has fabrications paired as mismatches (protocol 5.7), none was assigned")
	}
	if len(res.H2.Surface) != 2 || res.H2.Surface[0].Claims == 0 {
		t.Errorf("the attack surface: %+v", res.H2.Surface)
	}
	wantIDs := map[string]bool{"H2a": true, "H2b": true, "H2c": true, "H2d": true, "H2e": true, "H3a-zero": true, "H3a-near-zero": true, "H3b": true, "H3c": true, "H3d": true, "H1": true, "H4a": true, "H4b": true}
	for _, v := range res.Verdicts {
		delete(wantIDs, v.ID)
	}
	if len(wantIDs) != 0 {
		t.Errorf("verdict lines missing for %v", wantIDs)
	}
	for _, v := range res.Verdicts {
		if v.ID == "H1" && v.Result != NotEvaluated {
			t.Errorf("H1 without a comparison directory: %+v", v)
		}
	}
	report := Report(res)
	for _, want := range []string{"## Halt conditions", "## Verdicts", "REDUCED SWEEP", "### Attack surface per session", "### Premise check", "H3c", "Every excluded run"} {
		if !strings.Contains(report, want) {
			t.Errorf("report lacks %q", want)
		}
	}
	// The JSON must be valid and carry the registration.
	data, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if back["constants"].(map[string]any)["bootstrap_seed"].(float64) != 20261018 {
		t.Error("the bootstrap seed is not in the results")
	}
}

// Same inputs, byte-identical outputs, whatever the scheduling.
func TestOutputsAreByteIdentical(t *testing.T) {
	dir := syntheticCampaign(t, pairedRuns[:3])
	var outs [2]string
	for i, jobs := range []int{1, 4} {
		o := testOptions(t, dir)
		o.Jobs = jobs
		o.LastSeed = 2
		o.Out = filepath.Join(t.TempDir(), "out")
		if code := run(runArgs(o), &bytes.Buffer{}, &bytes.Buffer{}); code != 0 && code != exitHalt {
			t.Fatalf("run exited %d", code)
		}
		outs[i] = o.Out
	}
	for _, name := range []string{"results.json", "report.md"} {
		a, err := os.ReadFile(filepath.Join(outs[0], name))
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join(outs[1], name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(a, b) {
			t.Errorf("%s differs between a run with one worker and one with four", name)
		}
	}
}

func runArgs(o Options) []string {
	return []string{"--campaign", o.Campaign, "--out", o.Out, "--config", o.Config, "--seeds", strconv.FormatUint(o.LastSeed, 10), "--jobs", strconv.Itoa(o.Jobs)}
}

// The sweep must agree with pkg/attack's own Tally on the same inputs: the
// cross-check that the attack evaluation is unchanged by running it here.
func TestSweepAgreesWithTheAttackPackageTally(t *testing.T) {
	dir := syntheticCampaign(t, pairedRuns[:1])
	c, err := LoadCampaign(dir)
	if err != nil {
		t.Fatal(err)
	}
	s, err := LoadSession(c, c.Manifest.Runs[0])
	if err != nil {
		t.Fatal(err)
	}
	b, err := BuildBaseline(s.Adapter, s.Version, s.Controls, 1.0)
	if err != nil {
		t.Fatal(err)
	}
	const last = 12
	run := s.Sweep(b, SweepOptions{LastSeed: last})

	claims, _ := attack.WithoutImplied(s.Claims)
	in := s.input(claims, b)
	honest := verification.Verify(in)
	avoid := s.observed()
	for _, spec := range GenSpecs() {
		if spec.Variant != "omit" && spec.Variant != "fabricate" && spec.Variant != "substitute" || spec.Exhaustive {
			continue
		}
		var want attack.Tally
		for seed := SeedFirst; seed <= last; seed++ {
			mut, rec, err := generate(spec, claims, seed, 0, avoid)
			if err != nil {
				t.Fatal(err)
			}
			want.Add(attack.MarkUndetectableByDesign(attack.Score(rec, verification.Verify(s.input(mut, b))), honest, in.Baseline))
		}
		var got *Tally
		for _, tl := range run.Tallies {
			if tl.Variant == spec.Variant && tl.N == spec.N {
				got = tl
			}
		}
		if got == nil {
			t.Fatalf("no tally for %s n=%d", spec.Variant, spec.N)
		}
		if got.Mutations != want.Mutations || got.Distinct != want.Distinct || got.Undetectable != want.Undetectable ||
			got.OutOfCapture+got.Unverifiable != want.Detectable()-got.Detectable ||
			got.Detected != want.Detected || got.Classified != want.Classified || got.Located != want.Located ||
			got.AmbiguousRuns != want.Ambiguous || got.Unaccounted != want.Unaccounted {
			t.Errorf("%s n=%d: sweep %+v, attack.Tally %+v", spec.Variant, spec.N, *got, want)
		}
	}
}

func TestCampaignResolvesPathsOfAnotherMachine(t *testing.T) {
	dir := t.TempDir()
	run := filepath.Join(dir, "claude-code-2.1.306", "long", "run-01")
	if err := os.MkdirAll(run, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "claude-code-2.1.306", "long", "run-01.failed-20261026-101010"), 0o755); err != nil {
		t.Fatal(err)
	}
	m := `{"schema":1,"commit":"abc","runs":[{"agent":"claude-code","version":"2.1.306","task":"long","run":1,"dir":"/elsewhere/out/claude-code-2.1.306/long/run-01","status":"ok","controls":{"taken":false,"from":"/elsewhere/out/claude-code-2.1.306/long/run-01"}}]}`
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(m), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "annotations.json"), []byte(`{"runs":{"claude-code-2.1.306/long/run-01":{"x6":"I typed a key","completed":false}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := LoadCampaign(dir)
	if err != nil {
		t.Fatal(err)
	}
	r := c.Manifest.Runs[0]
	if c.RunDir(r) != run || c.ID(r) != "claude-code-2.1.306/long/run-01" || c.ControlsDir(r) != run {
		t.Errorf("dir %s id %s controls %s", c.RunDir(r), c.ID(r), c.ControlsDir(r))
	}
	if c.FailedAttempts[c.ID(r)] != 1 {
		t.Errorf("the moved-aside attempt must count: %v", c.FailedAttempts)
	}
	ann := c.Annotations.Runs[c.ID(r)]
	ex := Exclusions(RunFacts{Status: r.Status, Annotation: ann})
	if len(ex) != 1 || ex[0].Rule != X6 || ann.Completed == nil || *ann.Completed {
		t.Errorf("annotation: %+v %+v", ann, ex)
	}
	if got := Slots(c); got[0].MovedAside != 1 || got[0].Slots != 1 {
		t.Errorf("slots %+v", got)
	}
}

func TestClassifyPutsAMutationInOneClass(t *testing.T) {
	claim := models.TrajectoryEntry{ActionType: models.FileClose, Target: "/w/a", Tool: "Write", Timestamp: time.Unix(1, 0)}
	mk := func(kind attack.Kind, ubd, det bool) attack.MutationResult {
		after := claim
		return attack.MutationResult{Mutation: attack.Mutation{Kind: kind, After: &after}, Detected: det, UndetectableByDesign: ubd}
	}
	var v verification.Verdict
	if got := classify(mk(attack.Fabrication, false, true), v); got != ClassDetectable {
		t.Errorf("a detected mutation is detectable: %s", got)
	}
	if got := classify(mk(attack.Omission, true, false), v); got != ClassUndetectable {
		t.Errorf("flagged by design: %s", got)
	}
	v.OutOfScope = []models.TrajectoryEntry{claim}
	if got := classify(mk(attack.Fabrication, false, false), v); got != ClassOutOfCapture {
		t.Errorf("a fabrication set aside as out of scope: %s", got)
	}
	if got := classify(mk(attack.Fabrication, false, true), v); got != ClassDetectable {
		t.Errorf("a detected mutation is never set aside: %s", got)
	}
	v = verification.Verdict{Unverified: []verification.MatchedPair{{Entry: claim, Diffs: []string{"output_hash"}}}}
	if got := classify(mk(attack.Substitution, false, false), v); got != ClassUnverifiable {
		t.Errorf("a substituted value the probe did not capture: %s", got)
	}
}

func TestMislocationCategories(t *testing.T) {
	at := time.Unix(10, 0)
	mkClaim := func(typ models.ActionType, target string) models.TrajectoryEntry {
		return models.TrajectoryEntry{ActionType: typ, Target: target, Tool: "Read", Timestamp: at}
	}
	fab := mkClaim(models.FileOpen, "/w/fake")
	truth := mkClaim(models.FileOpen, "/w/truth")
	ev := models.GroundTruthEvent{ActionType: models.FileOpen, Target: "/w/other"}
	mutFab := attack.MutationResult{Mutation: attack.Mutation{Kind: attack.Fabrication, After: &fab}, Detected: true}
	pairFinding := func(kind string, c models.TrajectoryEntry) attack.Finding {
		c2 := c
		e2 := ev
		return attack.Finding{Kind: kind, Claim: &c2, Event: &e2}
	}

	// 1 and 2: a fabrication paired as a mismatch, inside or outside its interval.
	d := attack.Diagnosis{Findings: []attack.Finding{pairFinding("mismatched", fab)}}
	if got := categoryOfMutation(mutFab, d, verification.Verdict{}); got != Mis1 {
		t.Errorf("inside the interval: %d", got)
	}
	d.Findings = append(d.Findings, pairFinding("outside_interval", fab))
	if got := categoryOfMutation(mutFab, d, verification.Verdict{}); got != Mis2 {
		t.Errorf("outside the interval: %d", got)
	}
	// An undetected fabrication is not decided: category 6.
	if got := categoryOfMutation(attack.MutationResult{Mutation: attack.Mutation{Kind: attack.Fabrication, After: &fab}}, attack.Diagnosis{}, verification.Verdict{}); got != Mis6 {
		t.Errorf("no finding at all: %d", got)
	}
	// 4: the substituted claim was a harness-shared read.
	before := mkClaim(models.FileOpen, "/w/shared")
	after := before
	after.Target = "/w/sibling"
	sub := attack.MutationResult{Mutation: attack.Mutation{Kind: attack.Substitution, Field: attack.FieldTarget, Before: &before, After: &after}, Detected: true}
	honest := verification.Verdict{CorroboratedHarnessShared: []verification.MatchedPair{{Entry: before}}}
	if got := categoryOfMutation(sub, attack.Diagnosis{}, honest); got != Mis4 {
		t.Errorf("harness-shared read: %d", got)
	}
	// 5: paired with another observed event of the same type.
	ds := attack.Diagnosis{Findings: []attack.Finding{pairFinding("mismatched", after)}}
	if got := categoryOfMutation(sub, ds, verification.Verdict{}); got != Mis5 {
		t.Errorf("another event of the same type: %d", got)
	}
	// 3: an omission whose event a truthful claim took.
	omitted := mkClaim(models.FileOpen, "/w/other")
	om := attack.MutationResult{Mutation: attack.Mutation{Kind: attack.Omission, Before: &omitted}, Detected: true}
	do := attack.Diagnosis{Findings: []attack.Finding{pairFinding("mismatched", truth)}}
	if got := categoryOfMutation(om, do, verification.Verdict{}); got != Mis3 {
		t.Errorf("event lost to a neighbour: %d", got)
	}

	// Findings.
	rec := attack.Record{Mutations: []attack.Mutation{mutFab.Mutation}}
	spec := GenSpec{Variant: "fabricate"}
	if c, _ := categoryOfFinding(pairFinding("outside_interval", fab), rec, spec); c != Mis2 {
		t.Errorf("interval finding on a fabricated claim: %d", c)
	}
	if c, _ := categoryOfFinding(pairFinding("mismatched", truth), rec, spec); c != Mis3 {
		t.Errorf("a truthful claim flagged: %d", c)
	}
	if c, what := categoryOfFinding(pairFinding("outside_interval", truth), rec, GenSpec{Variant: "omit-retime", Retime: true}); c != Mis6 || !strings.Contains(what, "retime") {
		t.Errorf("the retime side effect is category 6 with its reason: %d %s", c, what)
	}
	if c, _ := categoryOfFinding(attack.Finding{Kind: "unrecorded", Event: &ev}, rec, spec); c != Mis6 {
		t.Errorf("an unrecorded event with no mutation behind it: %d", c)
	}
}

func TestCompareHonestListsEveryDifference(t *testing.T) {
	claim := models.TrajectoryEntry{ActionType: models.FileOpen, Target: "/w/a", Timestamp: time.Unix(1, 0)}
	implied := claim
	implied.ImpliedBy = "cat /w/a"
	a := verification.Verdict{Outcome: verification.OutcomeFaithful}
	b := verification.Verdict{Outcome: verification.OutcomeInconclusive, Unwitnessed: []models.TrajectoryEntry{claim}}
	diffs := CompareHonest(models.Trajectory{claim}, a, models.Trajectory{claim, implied}, b)
	have := map[string]bool{}
	for _, d := range diffs {
		have[d.What] = true
	}
	for _, w := range []string{"outcome", "claims", "unwitnessed", "finding"} {
		if !have[w] {
			t.Errorf("difference %q not listed: %+v", w, diffs)
		}
	}
	if same := CompareHonest(models.Trajectory{claim}, a, models.Trajectory{claim}, a); len(same) != 0 {
		t.Errorf("identical paths differ: %+v", same)
	}
}

func TestCostFromTheCapabilityRecord(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "verify-baseline.json")
	doc := `{"commands":[{"events":[{"a": 1},{"b":2}]},{"events":[]},{"events":[{"c":3}]}]}`
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	ev, by, ok := capabilityRecord(path)
	// [{"a":1},{"b":2},{"c":3}] is 25 bytes.
	if !ok || ev != 3 || by != 25 {
		t.Errorf("events %d bytes %d ok %v", ev, by, ok)
	}
	if _, _, ok := capabilityRecord(filepath.Join(dir, "missing.json")); ok {
		t.Error("a missing report is not measured")
	}
}

// H2d's composed check runs at every position with a neighbour on each side,
// also where one neighbour's interval cannot widen (claims of one parallel
// block share a timestamp), and only an omission no longer found refutes it.
func TestComposedA4CoversEveryInnerPosition(t *testing.T) {
	at := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	var claims models.Trajectory
	for i := range 4 {
		claims = append(claims, models.TrajectoryEntry{ActionType: models.FileOpen, Target: fmt.Sprintf("/w/f%d", i), Tool: "Read", Timestamp: at})
	}
	run := &AttackRun{}
	honest := verification.Verdict{}
	run.a4(claims, honest, func(models.Trajectory) verification.Verdict { return honest }, nil)
	if run.A4.ComposedPositions != 2 {
		t.Errorf("both inner positions must be checked, got %d", run.A4.ComposedPositions)
	}
	if len(run.A4.ComposedNotFound) != 2 || len(run.A4.ComposedMisses) != 2 {
		t.Errorf("a verifier that finds nothing misses both: %+v", run.A4)
	}

	// Found but neither classified nor located: H2d holds, H2b and H2c judge it.
	res := &Results{H2: &H2Results{Sessions: 1, A4: []A4Summary{{Agent: AgentClaudeCode, Sessions: 1, Positions: 3, ComposedPositions: 2, ComposedMisses: []string{"x: detected=true classified=false located=false"}}}}, H3: &H3Results{}, H4: &H4Results{}}
	res.Verdicts, res.Halts = BuildVerdicts(res)
	if v := verdictOf(res, "H2d", "every capture"); v.Result != Holds || !strings.Contains(v.Detail, "not classified or not located") {
		t.Errorf("H2d: %+v", v)
	}
	res.H2.A4[0].ComposedNotFound = []string{"y: detected=false"}
	res.H2.A4[0].ComposedMisses = append(res.H2.A4[0].ComposedMisses, "y: detected=false")
	res.Verdicts, res.Halts = BuildVerdicts(res)
	if v := verdictOf(res, "H2d", "every capture"); v.Result != Refuted {
		t.Errorf("an omission not found refutes H2d: %+v", v)
	}
}

// results.json and report.md are published (D14): they name the campaign,
// the config and the other inputs by their last path element, and the
// config by its hash, never by a path of the analysing machine.
func TestOutputsNameNoPathOfTheAnalysingMachine(t *testing.T) {
	dir := syntheticCampaign(t, pairedRuns[:1])
	o := testOptions(t, dir)
	o.LastSeed = 1
	o.Out = filepath.Join(t.TempDir(), "out")
	if code := run(append(runArgs(o), "--no-sweep", "--no-sensitivity"), &bytes.Buffer{}, &bytes.Buffer{}); code != 0 && code != exitHalt {
		t.Fatalf("run exited %d", code)
	}
	for _, name := range []string{"results.json", "report.md"} {
		data, err := os.ReadFile(filepath.Join(o.Out, name))
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range []string{dir, filepath.Dir(o.Config)} {
			if bytes.Contains(data, []byte(p)) {
				t.Errorf("%s names %s", name, p)
			}
		}
	}
	data, _ := os.ReadFile(filepath.Join(o.Out, "results.json"))
	if !bytes.Contains(data, []byte(`"agent_config_sha256": "`)) {
		t.Error("the config's hash is not recorded")
	}
}

// h2Run is a swept run whose one primary tally has the given counts.
func h2Run(id, variant string, detectable, detected, classified, located int) RunOutput {
	return RunOutput{ID: id, Agent: AgentClaudeCode, Version: "2.1.306", Task: "edits", Attack: &AttackRun{Tallies: []*Tally{{Variant: variant, N: 1, AttackedRuns: detectable, Mutations: detectable, Detectable: detectable, Detected: detected, Classified: classified, Located: located}}}}
}

func h2Verdict(t *testing.T, runs []RunOutput, misses []Miss, id string) Verdict {
	t.Helper()
	res := &Results{Runs: runs, H2: BuildH2(runs, SeedLast), H3: &H3Results{}, H4: &H4Results{}}
	res.H2.Misses = misses
	res.Verdicts, res.Halts = BuildVerdicts(res)
	return verdictOf(res, id, "every capture")
}

// H2b and H2c divide by the detected mutations: a miss refutes H2a only.
func TestH2bAndH2cAreOverDetectedMutations(t *testing.T) {
	runs := []RunOutput{h2Run("r1", "fabricate", 10, 9, 9, 9)}
	misses := []Miss{{Run: "r1", Variant: "fabricate", N: 1}}
	if v := h2Verdict(t, runs, misses, "H2a"); v.Result != Refuted {
		t.Errorf("H2a: %+v", v)
	}
	for _, id := range []string{"H2b", "H2c"} {
		v := h2Verdict(t, runs, misses, id)
		if v.Result != Holds || !strings.Contains(v.Detail, "9 of 9 detected") || !strings.Contains(v.Detail, "over the detectable mutations 9 of 10") {
			t.Errorf("%s: %+v", id, v)
		}
	}
	runs = []RunOutput{h2Run("r1", "fabricate", 10, 10, 9, 10)}
	if v := h2Verdict(t, runs, nil, "H2b"); v.Result != Refuted {
		t.Errorf("one detected mutation not classified refutes H2b: %+v", v)
	}
}
