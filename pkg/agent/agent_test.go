package agent

import (
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
	if _, err := Detect("x.c"); err == nil {
		t.Error("an unrecognised path must be an error, not the generic adapter")
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
	if _, err := Detect("x"); err == nil || !strings.Contains(err.Error(), "several") {
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
