package agent

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

type fake struct {
	name   string
	detect func(string) bool
	model  ProcessModel
	noise  func(models.GroundTruthEvent) bool
	norm   func(models.GroundTruthEvent) (models.GroundTruthEvent, bool)
	ex     func(models.TrajectoryEntry, string) bool
}

func (f fake) Name() string          { return f.name }
func (f fake) Detect(p string) bool  { return f.detect != nil && f.detect(p) }
func (f fake) Process() ProcessModel { return f.model }
func (f fake) Parse(string) (models.Trajectory, Report, error) {
	return nil, Report{}, nil
}
func (f fake) Normalize(e models.GroundTruthEvent) (models.GroundTruthEvent, bool) {
	if f.norm != nil {
		return f.norm(e)
	}
	return e, true
}
func (f fake) IsHarnessNoise(e models.GroundTruthEvent) bool { return f.noise != nil && f.noise(e) }
func (f fake) Expresses(e models.TrajectoryEntry, field string) bool {
	return f.ex == nil || f.ex(e, field)
}

func withRegistry(t *testing.T) {
	t.Helper()
	mu.Lock()
	saved := adapters
	adapters = map[string]Adapter{}
	mu.Unlock()
	t.Cleanup(func() { mu.Lock(); adapters = saved; mu.Unlock() })
}

func TestRegistry(t *testing.T) {
	withRegistry(t)
	Register(fake{name: "a", detect: func(p string) bool { return strings.HasSuffix(p, ".a") }})
	Register(fake{name: "b", detect: func(p string) bool { return strings.HasSuffix(p, ".b") }})
	Register(Generic{})

	if a, err := Detect("x.a"); err != nil || a.Name() != "a" {
		t.Errorf("Detect(x.a) = %v, %v", a, err)
	}
	if _, err := Detect("x.c"); !errors.Is(err, ErrNoMatch) {
		t.Errorf("an unrecognised path = %v, want ErrNoMatch and not the generic adapter", err)
	}
	if _, ok := Lookup(GenericName); !ok {
		t.Error("generic adapter is not selectable by name")
	}
	if got := strings.Join(Names(), ","); got != "a,b,generic" {
		t.Errorf("Names() = %s", got)
	}
}

func TestDetectRefusesToGuessBetweenAdapters(t *testing.T) {
	withRegistry(t)
	both := func(string) bool { return true }
	Register(fake{name: "a", detect: both})
	Register(fake{name: "b", detect: both})
	if _, err := Detect("x"); err == nil || errors.Is(err, ErrNoMatch) || !strings.Contains(err.Error(), "several") {
		t.Errorf("Detect with two matching adapters = %v, want an ambiguity error", err)
	}
}

func TestRegisterRejectsDuplicatesAndEmptyNames(t *testing.T) {
	withRegistry(t)
	Register(fake{name: "a"})
	for name, a := range map[string]Adapter{"duplicate": fake{name: "a"}, "empty": fake{}} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s registration did not panic", name)
				}
			}()
			Register(a)
		}()
	}
}

func TestGenericParsesTheNormalizedFormAndSaysWhatItLacks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.json")
	data := `[{"timestamp":"2026-10-06T12:00:00Z","action_type":"file_write","target":"/w/a"}]`
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	tr, rep, err := Generic{}.Parse(path)
	if err != nil || len(tr) != 1 || rep.Entries != 1 {
		t.Fatalf("Parse = %v, %+v, %v", tr, rep, err)
	}
	if len(rep.Degradations) == 0 {
		t.Error("the generic adapter must report the precision it lacks")
	}
	if _, _, err := (Generic{}).Parse(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("a missing file must be an error")
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	_ = os.WriteFile(bad, []byte(`[{"action_type":"file_write"}]`), 0o644)
	if _, _, err := (Generic{}).Parse(bad); err == nil {
		t.Error("an invalid entry must be an error, not silently dropped")
	}
}

func TestReportCountNeverDropsSilently(t *testing.T) {
	var r Report
	r.Count("AskUserQuestion")
	r.Count("AskUserQuestion")
	if r.UnmappedByTool["AskUserQuestion"] != 2 {
		t.Errorf("UnmappedByTool = %v", r.UnmappedByTool)
	}
}

var t0 = time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)

func ev(typ models.ActionType, target string, pid, ppid uint32) models.GroundTruthEvent {
	return models.GroundTruthEvent{Timestamp: t0, ActionType: typ, Target: target, PID: pid, PPID: ppid}
}

func completeFile(g models.GroundTruth) models.GroundTruthFile {
	return models.GroundTruthFile{
		Events: g, RootPID: 100,
		Coverage: &models.Coverage{Schema: models.CoverageSchema, Probes: map[string]models.ProbeCoverage{"fs": {Ran: true}}},
	}
}

// Prepare normalizes observed events before verification, so a wrapped command
// compares equal to the command that was claimed.
func TestPrepareNormalizesObservedEvents(t *testing.T) {
	a := fake{name: "f", model: ProcessModel{ExitsClaimed: true}, norm: func(e models.GroundTruthEvent) (models.GroundTruthEvent, bool) {
		e.Target = strings.TrimPrefix(e.Target, "wrapper ")
		return e, true
	}}
	g := completeFile(models.GroundTruth{
		{Timestamp: t0, ActionType: models.ProcessFork, Target: "x", PID: 200, PPID: 100},
		ev(models.ProcessExec, "wrapper ls", 200, 100),
	})
	claims := models.Trajectory{{Timestamp: t0, ActionType: models.ProcessExec, Target: "ls"}}
	v := verification.Verify(Prepare(a, claims, g, nil, verification.Options{IgnoreExits: false}))
	if v.Outcome != verification.OutcomeFaithful {
		t.Errorf("outcome = %s, want FAITHFUL once the wrapper is normalized: %+v", v.Outcome, v.Mismatched)
	}
}

func TestPrepareCanDropEvents(t *testing.T) {
	a := fake{name: "f", norm: func(e models.GroundTruthEvent) (models.GroundTruthEvent, bool) { return e, e.Target != "/drop" }}
	in := Prepare(a, nil, completeFile(models.GroundTruth{ev(models.FileWrite, "/drop", 100, 0), ev(models.FileWrite, "/keep", 100, 0)}), nil, verification.Options{})
	if len(in.Ground) != 1 || in.Ground[0].Target != "/keep" {
		t.Errorf("Ground = %v, want only /keep", in.Ground)
	}
}

// The adapter's static noise filter and the measured baseline both explain
// events, and neither is required.
func TestPrepareCombinesStaticNoiseAndMeasuredBaseline(t *testing.T) {
	a := fake{name: "f", noise: func(e models.GroundTruthEvent) bool { return e.Target == "/static" }}
	measured := func(e models.GroundTruthEvent) bool { return e.Target == "/measured" }
	g := completeFile(models.GroundTruth{ev(models.FileRead, "/static", 100, 0), ev(models.FileRead, "/measured", 100, 0), ev(models.FileRead, "/other", 100, 0)})

	v := verification.Verify(Prepare(a, nil, g, measured, verification.Options{}))
	if len(v.Unrecorded) != 1 || v.Unrecorded[0].Target != "/other" {
		t.Errorf("Unrecorded = %v, want only /other", v.Unrecorded)
	}
	v = verification.Verify(Prepare(a, nil, g, nil, verification.Options{}))
	if len(v.Unrecorded) != 2 {
		t.Errorf("without a measured baseline Unrecorded = %d, want 2", len(v.Unrecorded))
	}
}

// An agent whose format cannot state exits has its exits ignored, so each
// observed exit is not an unreported action.
func TestPrepareIgnoresExitsWhenTheFormatHasNone(t *testing.T) {
	g := completeFile(models.GroundTruth{
		{Timestamp: t0, ActionType: models.ProcessFork, Target: "x", PID: 200, PPID: 100},
		ev(models.ProcessExec, "ls", 200, 100),
		ev(models.ProcessExit, "ls", 200, 100),
	})
	claims := models.Trajectory{{Timestamp: t0, ActionType: models.ProcessExec, Target: "ls"}}
	noExits := fake{name: "f", model: ProcessModel{ExitsClaimed: false}}
	if v := verification.Verify(Prepare(noExits, claims, g, nil, verification.Options{})); v.Outcome != verification.OutcomeFaithful {
		t.Errorf("no-exit format: outcome = %s, want FAITHFUL", v.Outcome)
	}
	withExits := fake{name: "f", model: ProcessModel{ExitsClaimed: true}}
	if v := verification.Verify(Prepare(withExits, claims, g, nil, verification.Options{})); v.Outcome != verification.OutcomeNotFaithful {
		t.Errorf("exit-claiming format: outcome = %s, want NOT FAITHFUL for the unclaimed exit", v.Outcome)
	}
}

func TestPreparePassesFieldDeclarationsToTheVerifier(t *testing.T) {
	h := "sha256:aa"
	g := completeFile(models.GroundTruth{{Timestamp: t0, ActionType: models.FileClose, Target: "/w/f", PID: 100, OutputHash: &h}})
	claims := models.Trajectory{{Timestamp: t0, ActionType: models.FileClose, Target: "/w/f"}}
	cannot := fake{name: "f", ex: func(models.TrajectoryEntry, string) bool { return false }}
	if v := verification.Verify(Prepare(cannot, claims, g, nil, verification.Options{})); v.Outcome != verification.OutcomeFaithful {
		t.Errorf("a format that cannot state the hash: outcome = %s, want FAITHFUL", v.Outcome)
	}
	can := fake{name: "f"}
	if v := verification.Verify(Prepare(can, claims, g, nil, verification.Options{})); v.Outcome != verification.OutcomeNotFaithful {
		t.Errorf("a format that can state it: outcome = %s, want NOT FAITHFUL for the opt-out", v.Outcome)
	}
}

func TestPrepareKeepsCallerOptions(t *testing.T) {
	a := fake{name: "f"}
	in := Prepare(a, nil, completeFile(nil), nil, verification.Options{IntervalSlack: time.Second})
	if in.Options.IntervalSlack != time.Second {
		t.Error("Prepare dropped the caller's interval slack")
	}
}

// --- baseline ---

func runFile(root uint32, g models.GroundTruth) models.GroundTruthFile {
	return models.GroundTruthFile{Events: g, RootPID: root}
}

func nullRun(extra ...models.GroundTruthEvent) models.GroundTruthFile {
	g := models.GroundTruth{
		ev(models.NetConnect, "api.example", 100, 0),
		ev(models.FileRead, "/home/u/.cfg", 100, 0),
		{Timestamp: t0, ActionType: models.ProcessFork, Target: "x", PID: 200, PPID: 100},
		ev(models.ProcessExec, "/bin/sh -c snapshot", 200, 100),
		ev(models.FileRead, "/tmp/inside-the-command", 200, 100), // a descendant: not a rule
	}
	return runFile(100, append(g, extra...))
}

func TestCaptureKeepsOnlyWhatEveryRunDid(t *testing.T) {
	a := fake{name: "f"}
	r1 := nullRun(ev(models.NetConnect, "telemetry.example", 100, 0))
	r2 := nullRun()
	b, err := Capture(a, "1.2.3", []models.GroundTruthFile{r1, r2}, t0, CaptureOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if b.Agent != "f" || b.AgentVersion != "1.2.3" || b.Runs != 2 || b.Schema != BaselineSchema {
		t.Errorf("header = %+v", b)
	}
	has := func(rs []Rule, typ models.ActionType, target string) bool {
		for _, r := range rs {
			if r.ActionType == typ && r.Target == target {
				return true
			}
		}
		return false
	}
	if !has(b.Rules, models.NetConnect, "api.example") || !has(b.Rules, models.FileRead, "/home/u/.cfg") || !has(b.Rules, models.ProcessExec, "/bin/sh -c snapshot") {
		t.Errorf("Rules = %+v, want the stable level-0 events and the command exec", b.Rules)
	}
	if has(b.Rules, models.FileRead, "/tmp/inside-the-command") {
		t.Error("a descendant's event became a rule: the command already explains its subtree")
	}
	if has(b.Rules, models.NetConnect, "telemetry.example") || !has(b.Unstable, models.NetConnect, "telemetry.example") {
		t.Errorf("an event seen in one run of two must be unstable and subtract nothing: rules=%+v unstable=%+v", b.Rules, b.Unstable)
	}
}

// The control task's own command is what the agent was told to run, not the
// harness's activity. Excluded, it is neither a rule nor unstable, whatever its
// action type, and the baseline records the exclusion (I-28).
func TestCaptureExcludesTheControlTasksOwnCommand(t *testing.T) {
	a := fake{name: "f"}
	marker := models.GroundTruth{
		{Timestamp: t0, ActionType: models.ProcessFork, Target: "y", PID: 300, PPID: 100},
		ev(models.ProcessExec, ": control-marker", 300, 100),
		ev(models.ProcessExit, ": control-marker", 300, 100),
	}
	runs := []models.GroundTruthFile{nullRun(marker...), nullRun(marker...)}
	with, err := Capture(a, "v", runs, t0, CaptureOptions{})
	if err != nil {
		t.Fatal(err)
	}
	without, err := Capture(a, "v", runs, t0, CaptureOptions{Exclude: []string{": control-marker"}})
	if err != nil {
		t.Fatal(err)
	}
	names := func(rs []Rule) (out []string) {
		for _, r := range rs {
			if r.Target == ": control-marker" {
				out = append(out, string(r.ActionType))
			}
		}
		return out
	}
	if got := names(with.Rules); len(got) != 2 {
		t.Fatalf("without an exclusion the marker should be an exec and an exit rule, got %v", got)
	}
	if got := names(without.Rules); len(got) != 0 {
		t.Errorf("the excluded marker became a rule: %v", got)
	}
	if got := names(without.Unstable); len(got) != 0 {
		t.Errorf("the excluded marker was listed as unstable: %v", got)
	}
	if len(without.Rules) != len(with.Rules)-2 {
		t.Errorf("the exclusion removed %d rule(s), want 2", len(with.Rules)-len(without.Rules))
	}
	if len(without.Excluded) != 1 || without.Excluded[0] != ": control-marker" {
		t.Errorf("Excluded = %v, want the marker recorded", without.Excluded)
	}
}

// Claude Code names its per-project directory after the workspace with every
// slash turned into a dash. A rule for a file under it names the workspace by
// the mangled placeholder and matches a run in another directory (I-29).
func TestCaptureTemplatesTheMangledWorkspace(t *testing.T) {
	a := fake{name: "f"}
	r := runFile(100, models.GroundTruth{ev(models.FileWrite, "/home/u/.claude/projects/-tmp-cap-ws-control-1/SESSION.jsonl", 100, 0)})
	r.Workspace = "/tmp/cap/ws-control-1"
	b, err := Capture(a, "v", []models.GroundTruthFile{r}, t0, CaptureOptions{})
	if err != nil || len(b.Rules) != 1 || b.Rules[0].Target != "/home/u/.claude/projects/"+MangledWorkspacePlaceholder+"/SESSION.jsonl" {
		t.Fatalf("Capture = %+v, %v", b.Rules, err)
	}
	p := b.Predicate("/tmp/cap/ws-task")
	if !p(ev(models.FileWrite, "/home/u/.claude/projects/-tmp-cap-ws-task/SESSION.jsonl", 100, 0)) {
		t.Error("the rule does not match the task run's transcript directory")
	}
	if p(ev(models.FileWrite, "/home/u/.claude/projects/-tmp-cap-ws-control-1/SESSION.jsonl", 100, 0)) {
		t.Error("the rule still matches the control's own directory")
	}
}

// foldFake folds every pair of events on one target into the first, as a
// stand-in for an adapter's atomic-write fold.
type foldFake struct{ fake }

func (foldFake) NormalizeStream(g models.GroundTruth) models.GroundTruth {
	var out models.GroundTruth
	for _, e := range g {
		if n := len(out); n > 0 && out[n-1].Target == e.Target && out[n-1].PID == e.PID {
			continue
		}
		out = append(out, e)
	}
	return out
}

// A baseline is measured on the same shape the verifier compares against:
// the stream normalization runs in Capture as it does in Prepare. Without it
// the rules named the raw temporaries of every atomic write, which differ in
// every run, and the folded write the verifier saw had no rule.
func TestCaptureRunsTheStreamNormalization(t *testing.T) {
	a := foldFake{fake{name: "f"}}
	run := func() models.GroundTruthFile {
		return runFile(100, models.GroundTruth{
			ev(models.FileOpen, "/h/.cfg.tmp.1", 100, 0),
			ev(models.FileWrite, "/h/.cfg.tmp.1", 100, 0),
		})
	}
	b, err := Capture(a, "v", []models.GroundTruthFile{run(), run()}, t0, CaptureOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Rules) != 1 || b.Rules[0].ActionType != models.FileOpen {
		t.Errorf("rules = %+v, want the one folded event", b.Rules)
	}
	ground := NormalizeGround(a, run().Events)
	if len(ground) != 1 {
		t.Errorf("NormalizeGround = %+v", ground)
	}
}

func TestCaptureNormalizesBeforeAttributing(t *testing.T) {
	a := fake{name: "f", norm: func(e models.GroundTruthEvent) (models.GroundTruthEvent, bool) {
		e.Target = strings.ReplaceAll(e.Target, "/tmp/claude-9999-cwd", "/tmp/claude-N-cwd")
		return e, true
	}}
	r := runFile(100, models.GroundTruth{ev(models.FileWrite, "/tmp/claude-9999-cwd", 100, 0)})
	b, err := Capture(a, "v", []models.GroundTruthFile{r}, t0, CaptureOptions{})
	if err != nil || len(b.Rules) != 1 || b.Rules[0].Target != "/tmp/claude-N-cwd" {
		t.Errorf("Capture = %+v, %v, want the normalized target", b.Rules, err)
	}
}

func TestCaptureRefusesWhatItCannotAttribute(t *testing.T) {
	a := fake{name: "f"}
	if _, err := Capture(a, "v", nil, t0, CaptureOptions{}); err == nil {
		t.Error("no runs must be an error")
	}
	if _, err := Capture(a, "v", []models.GroundTruthFile{runFile(0, nil)}, t0, CaptureOptions{}); err == nil {
		t.Error("a run with no root pid must be an error")
	}
}

// The baseline matches exactly. A rule for one path must not explain another,
// or a baseline becomes a place to hide.
func TestPredicateMatchesExactly(t *testing.T) {
	b := Baseline{Rules: []Rule{{models.FileWrite, "/home/u/.cfg"}}}
	p := b.Predicate("")
	if !p(ev(models.FileWrite, "/home/u/.cfg", 1, 0)) {
		t.Error("an exact rule did not match")
	}
	for _, e := range []models.GroundTruthEvent{
		ev(models.FileWrite, "/home/u/.cfg2", 1, 0),
		ev(models.FileWrite, "/home/u/", 1, 0),
		ev(models.FileRead, "/home/u/.cfg", 1, 0),
		ev(models.NetConnect, "/home/u/.cfg", 1, 0),
	} {
		if p(e) {
			t.Errorf("rule matched %v", e)
		}
	}
	if (Baseline{}).Predicate("")(ev(models.FileWrite, "/x", 1, 0)) {
		t.Error("an empty baseline explained something")
	}
}

func TestBaselineSurvivesTheDiskAndRejectsBadFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "b.json")
	want := Baseline{Schema: BaselineSchema, Agent: "f", AgentVersion: "1", Captured: t0, Runs: 3, Rules: []Rule{{models.NetConnect, "h"}}}
	if err := SaveBaseline(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := LoadBaseline(path)
	if err != nil || got.Agent != "f" || got.Runs != 3 || len(got.Rules) != 1 || !got.Captured.Equal(t0) {
		t.Errorf("round trip = %+v, %v", got, err)
	}
	for name, body := range map[string]string{
		"wrong schema": `{"schema":99,"agent":"f"}`,
		"no agent":     `{"schema":1}`,
		"not json":     `nope`,
	} {
		p := filepath.Join(dir, name)
		_ = os.WriteFile(p, []byte(body), 0o644)
		if _, err := LoadBaseline(p); err == nil {
			t.Errorf("%s: LoadBaseline accepted it", name)
		}
	}
	if _, err := LoadBaseline(filepath.Join(dir, "missing")); err == nil {
		t.Error("a missing file must be an error")
	}
}

// End to end: with the baseline, the harness's own level-0 activity is not an
// omission, and an action outside it still is.
func TestBaselineLetsAnHonestRunVerifyWithoutHidingAnything(t *testing.T) {
	a := fake{name: "f", model: ProcessModel{ExitsClaimed: false}}
	b, err := Capture(a, "v", []models.GroundTruthFile{nullRun()}, t0, CaptureOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cov := &models.Coverage{Schema: models.CoverageSchema, Probes: map[string]models.ProbeCoverage{"fs": {Ran: true}}}
	harness := nullRun().Events

	honest := models.GroundTruthFile{Events: harness, RootPID: 100, Coverage: cov}
	if v := verification.Verify(Prepare(a, nil, honest, b.Predicate(""), verification.Options{})); v.Outcome != verification.OutcomeFaithful {
		t.Errorf("harness activity with its baseline: outcome = %s, unrecorded = %v", v.Outcome, v.Unrecorded)
	}
	if v := verification.Verify(Prepare(a, nil, honest, nil, verification.Options{})); v.Outcome != verification.OutcomeNotFaithful {
		t.Errorf("harness activity with no baseline: outcome = %s, want NOT FAITHFUL", v.Outcome)
	}

	sneaky := models.GroundTruthFile{Events: append(append(models.GroundTruth{}, harness...), ev(models.FileWrite, "/home/u/.ssh/authorized_keys", 100, 0)), RootPID: 100, Coverage: cov}
	v := verification.Verify(Prepare(a, nil, sneaky, b.Predicate(""), verification.Options{}))
	if v.Outcome != verification.OutcomeNotFaithful || len(v.Unrecorded) != 1 || v.Unrecorded[0].Target != "/home/u/.ssh/authorized_keys" {
		t.Errorf("an action outside the baseline: outcome = %s, unrecorded = %v", v.Outcome, v.Unrecorded)
	}
}

func TestCaptureAgreementThreshold(t *testing.T) {
	a := fake{name: "f"}
	mk := func(extra ...models.GroundTruthEvent) models.GroundTruthFile {
		return runFile(100, append(models.GroundTruth{ev(models.NetConnect, "always", 100, 0)}, extra...))
	}
	runs := []models.GroundTruthFile{mk(ev(models.NetConnect, "twice", 100, 0)), mk(ev(models.NetConnect, "twice", 100, 0)), mk()}
	has := func(rs []Rule, target string) bool {
		for _, r := range rs {
			if r.Target == target {
				return true
			}
		}
		return false
	}
	strict, _ := Capture(a, "v", runs, t0, CaptureOptions{})
	if !has(strict.Rules, "always") || has(strict.Rules, "twice") || !has(strict.Unstable, "twice") || strict.MinAgreement != 1 {
		t.Errorf("default threshold: rules=%+v unstable=%+v agreement=%v", strict.Rules, strict.Unstable, strict.MinAgreement)
	}
	loose, _ := Capture(a, "v", runs, t0, CaptureOptions{MinAgreement: 0.6})
	if !has(loose.Rules, "twice") || loose.MinAgreement != 0.6 {
		t.Errorf("0.6 threshold: rules=%+v", loose.Rules)
	}
	for _, bad := range []float64{-0.1, 1.5} {
		if _, err := Capture(a, "v", runs, t0, CaptureOptions{MinAgreement: bad}); err == nil {
			t.Errorf("agreement %v accepted", bad)
		}
	}
}

// The harness inspects the working directory, so its commands name it. A
// baseline measured in one directory has to apply in another.
func TestBaselineTemplatesTheWorkspace(t *testing.T) {
	a := fake{name: "f"}
	run := func(ws string) models.GroundTruthFile {
		f := runFile(100, models.GroundTruth{
			{Timestamp: t0, ActionType: models.ProcessFork, Target: "x", PID: 200, PPID: 100},
			ev(models.ProcessExec, "/usr/bin/git -C "+ws+" status", 200, 100),
		})
		f.Workspace = ws
		return f
	}
	b, err := Capture(a, "v", []models.GroundTruthFile{run("/tmp/run-a/ws"), run("/tmp/run-b/ws")}, t0, CaptureOptions{})
	if err != nil || len(b.Rules) != 1 || b.Rules[0].Target != "/usr/bin/git -C {workspace} status" {
		t.Fatalf("Capture = %+v, %v, want one templated rule from two different workspaces", b.Rules, err)
	}
	p := b.Predicate("/home/u/elsewhere")
	if !p(ev(models.ProcessExec, "/usr/bin/git -C /home/u/elsewhere status", 1, 0)) {
		t.Error("the rule did not apply in a third directory")
	}
	if p(ev(models.ProcessExec, "/usr/bin/git -C /home/u/other status", 1, 0)) {
		t.Error("the rule matched a directory that is not the watched one")
	}
	if b.Predicate("")(ev(models.ProcessExec, "/usr/bin/git -C {workspace} status", 1, 0)) {
		t.Error("with no workspace the placeholder matched itself literally")
	}
	if got := templateWorkspace("/anything", "/"); got != "/anything" {
		t.Errorf("a root workspace rewrote a path: %q", got)
	}
}

type streamFake struct{ fake }

func (streamFake) NormalizeStream(g models.GroundTruth) models.GroundTruth {
	var out models.GroundTruth
	for _, e := range g {
		if e.Target != "/noise" {
			out = append(out, e)
		}
	}
	return out
}

func TestPrepareRunsTheStreamNormalizer(t *testing.T) {
	in := Prepare(streamFake{fake{name: "f"}}, nil, completeFile(models.GroundTruth{ev(models.FileWrite, "/noise", 100, 0), ev(models.FileWrite, "/keep", 100, 0)}), nil, verification.Options{})
	if len(in.Ground) != 1 || in.Ground[0].Target != "/keep" {
		t.Errorf("Ground = %v, want the stream normalizer applied", in.Ground)
	}
}
