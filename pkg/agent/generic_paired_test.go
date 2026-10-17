package agent_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/agent/claudecode"
	"github.com/agent-trace/agent-trace/pkg/agent/gemini"
	"github.com/agent-trace/agent-trace/pkg/attack"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// The real paired fixtures of both native adapters, each read by its own
// adapter, converted to the generic trajectory format and verified with
// Generic against the same capture. The table pins what Generic concludes and
// what the native adapter does that Generic cannot, so a change to either is
// seen. The rows are the lost-precision table of the Generic section of
// docs/architecture/30_agent_adapters.md.
type genericRow struct {
	dir, session, task string
	native             agent.Adapter

	// What the native adapter does that Generic cannot, counted on the task
	// run: claims it derived as harness-implied (dropped by the converter),
	// observed events its Normalize rewrites (a wrapper's argv to the claimed
	// command), events its NormalizeStream folds away, events whose
	// Canonical form differs, and, with the baseline, the unexplained harness
	// file events and harness-host connections it reports apart.
	implied, rewritten, folded, canonical, harnessFiles, harnessNet int

	nativeOutcome verification.Outcome
	// Generic with its own baseline from the same controls, then without one.
	withBaseline, without genericCounts
}

type genericCounts struct {
	outcome                                                                        verification.Outcome
	corroborated, mismatched, unwitnessed, unrecorded, exits, subtrees, unverified int
}

func (c genericCounts) String() string {
	return fmt.Sprintf("%s corroborated=%d mismatched=%d unwitnessed=%d unrecorded=%d (exits %d) subtrees=%d unverified=%d",
		c.outcome, c.corroborated, c.mismatched, c.unwitnessed, c.unrecorded, c.exits, c.subtrees, c.unverified)
}

func countsOf(v verification.Verdict) genericCounts {
	c := genericCounts{
		outcome: v.Outcome, corroborated: len(v.Corroborated), mismatched: len(v.Mismatched), unwitnessed: len(v.Unwitnessed),
		unrecorded: len(v.Unrecorded), subtrees: len(v.Coverage.UnexplainedSubtrees), unverified: len(v.Unverified),
	}
	for _, e := range v.Unrecorded {
		if e.ActionType == models.ProcessExit {
			c.exits++
		}
	}
	return c
}

const (
	faithful     = verification.OutcomeFaithful
	inconclusive = verification.OutcomeInconclusive
	notFaithful  = verification.OutcomeNotFaithful
)

var genericRows = []genericRow{
	{"claudecode/testdata/paired-2.1.286", "task.session.jsonl", "task", claudecode.Adapter{}, 0, 4, 15, 0, 0, 0, faithful,
		genericCounts{notFaithful, 6, 1, 0, 18, 2, 1, 2}, genericCounts{notFaithful, 6, 1, 0, 64, 10, 9, 2}},
	{"claudecode/testdata/paired-2.1.286-parallel", "parallel.session.jsonl", "parallel", claudecode.Adapter{}, 0, 10, 0, 0, 0, 0, faithful,
		genericCounts{notFaithful, 4, 4, 0, 6, 5, 1, 0}, genericCounts{notFaithful, 4, 4, 0, 43, 13, 9, 0}},
	{"claudecode/testdata/paired-2.1.286-project", "project.session.jsonl", "project", claudecode.Adapter{}, 0, 8, 70, 0, 0, 0, faithful,
		genericCounts{notFaithful, 16, 3, 0, 51, 4, 1, 3}, genericCounts{notFaithful, 16, 3, 0, 91, 12, 9, 3}},
	{"claudecode/testdata/paired-2.1.286-project-heredoc", "project.session.jsonl", "project", claudecode.Adapter{}, 0, 8, 43, 184, 8, 0, inconclusive,
		genericCounts{notFaithful, 0, 3, 0, 113, 4, 1, 0}, genericCounts{notFaithful, 0, 3, 0, 410, 12, 9, 0}},
	{"claudecode/testdata/paired-2.1.286-p17", "basic.session.jsonl", "basic", claudecode.Adapter{}, 0, 4, 54, 152, 0, 0, faithful,
		genericCounts{notFaithful, 6, 1, 0, 113, 2, 1, 3}, genericCounts{notFaithful, 6, 1, 0, 419, 10, 9, 3}},
	{"claudecode/testdata/paired-2.1.296-edits", "edits.session.jsonl", "edits", claudecode.Adapter{}, 0, 4, 65, 150, 2, 0, inconclusive,
		genericCounts{notFaithful, 11, 1, 0, 123, 2, 1, 6}, genericCounts{notFaithful, 11, 1, 0, 405, 10, 9, 6}},
	{"claudecode/testdata/paired-2.1.296-tools", "tools.session.jsonl", "tools", claudecode.Adapter{}, 0, 7, 67, 190, 1, 0, inconclusive,
		genericCounts{notFaithful, 14, 2, 0, 163, 3, 1, 6}, genericCounts{notFaithful, 14, 2, 0, 462, 11, 9, 6}},
	{"claudecode/testdata/paired-2.1.296-shapes", "shapes.session.jsonl", "shapes", claudecode.Adapter{}, 1, 13, 34, 191, 5, 0, inconclusive,
		genericCounts{notFaithful, 5, 5, 0, 137, 6, 1, 2}, genericCounts{notFaithful, 5, 5, 0, 437, 14, 9, 2}},
	{"claudecode/testdata/paired-2.1.296-tools-named", "tools.session.jsonl", "tools", claudecode.Adapter{}, 0, 6, 83, 216, 4, 1, inconclusive,
		genericCounts{notFaithful, 8, 8, 0, 221, 3, 1, 6}, genericCounts{notFaithful, 8, 8, 0, 497, 11, 9, 6}},
	{"gemini/testdata/paired-agy-1.3.4-basic", "basic.conversation.db", "basic", gemini.Adapter{}, 0, 3, 16, 229, 0, 1, inconclusive,
		genericCounts{notFaithful, 9, 2, 0, 221, 1, 0, 0}, genericCounts{notFaithful, 9, 2, 0, 599, 1, 0, 0}},
	{"gemini/testdata/paired-agy-1.3.4-search", "search.conversation.db", "search", gemini.Adapter{}, 0, 1, 10, 283, 0, 1, inconclusive,
		genericCounts{notFaithful, 3, 2, 0, 269, 3, 1, 0}, genericCounts{notFaithful, 3, 2, 0, 669, 3, 1, 0}},
}

// convertToGeneric writes what the native adapter read as the generic
// format and reads it back with Generic. The converter applies only what the
// format can state: the entries as they are, without the harness-implied
// claims, which only an adapter derives and which the format cannot carry
// (V-33). Nothing on the observed side is converted: Generic normalizes
// nothing.
func convertToGeneric(t *testing.T, tr models.Trajectory) models.Trajectory {
	t.Helper()
	own, _ := attack.WithoutImplied(tr)
	data, err := json.Marshal(own)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "trajectory.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	g, _ := agent.Lookup(agent.GenericName)
	out, rep, err := g.Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	if rep.AgentVersion != "" {
		t.Errorf("Generic stated a harness version %q: the format has none", rep.AgentVersion)
	}
	return out
}

func loadGround(t *testing.T, path string) models.GroundTruthFile {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := models.ParseGroundTruthFile(data)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return f
}

// lostCounts measures, on the task run, what the native adapter's
// normalization and declarations do that Generic's do not.
func lostCounts(a agent.Adapter, tr models.Trajectory, g models.GroundTruthFile) (implied, rewritten, folded, canonical int) {
	for _, e := range tr {
		if e.ImpliedBy != "" {
			implied++
		}
	}
	var normalized models.GroundTruth
	for _, e := range g.Events {
		n, keep := a.Normalize(e)
		if !keep {
			continue
		}
		if n.Target != e.Target {
			rewritten++
		}
		normalized = append(normalized, n)
	}
	ground := agent.NormalizeGround(a, g.Events)
	folded = len(normalized) - len(ground)
	if c, ok := a.(agent.Canonicalizer); ok {
		for _, e := range ground {
			if c.Canonical(e).Target != e.Target {
				canonical++
			}
		}
	}
	return
}

func TestGenericOnRealPairedFixtures(t *testing.T) {
	g, _ := agent.Lookup(agent.GenericName)
	opts := verification.Options{IntervalSlack: 500 * time.Millisecond}
	for _, r := range genericRows {
		t.Run(filepath.Base(r.dir), func(t *testing.T) {
			tr, rep, err := r.native.Parse(filepath.Join(r.dir, r.session))
			if err != nil || len(rep.ParseErrors) != 0 || len(rep.UnknownTools) != 0 {
				t.Fatalf("native parse: %v %+v", err, rep)
			}
			gtr := convertToGeneric(t, tr)
			task := loadGround(t, filepath.Join(r.dir, r.task+".ground_truth.json"))
			paths, _ := filepath.Glob(filepath.Join(r.dir, "control-*.ground_truth.json"))
			var runs []models.GroundTruthFile
			for _, p := range paths {
				runs = append(runs, loadGround(t, p))
			}
			// The capture script's default agreement: one control in N.
			copts := agent.CaptureOptions{Exclude: []string{claudecode.ControlCommand}, MinAgreement: 1 / float64(len(runs))}
			nb, err := agent.Capture(r.native, rep.AgentVersion, runs, time.Now(), copts)
			if err != nil {
				t.Fatal(err)
			}
			gb, err := agent.Capture(g, "", runs, time.Now(), copts)
			if err != nil {
				t.Fatal(err)
			}

			nv := verification.Verify(agent.PrepareWithBaseline(r.native, tr, task, &nb, opts))
			implied, rewritten, folded, canonical := lostCounts(r.native, tr, task)
			gv := verification.Verify(agent.PrepareWithBaseline(g, gtr, task, &gb, opts))
			with := countsOf(gv)
			// Every claim finds an event and every disagreement is on the
			// target: a command against its wrapper's argv, a write against a
			// temporary or the harness's own file. None is a content
			// disagreement on the claimed target, which would be a finding
			// the native adapter missed rather than precision Generic lost.
			for _, m := range gv.Mismatched {
				if !slices.Contains(m.Diffs, verification.DiffTarget) {
					t.Errorf("a mismatch on the claimed target: %s %s against %s, %v", m.Entry.ActionType, m.Entry.Target, m.Event.Target, m.Diffs)
				}
			}
			without := countsOf(verification.Verify(agent.PrepareWithBaseline(g, gtr, task, nil, opts)))
			got := genericRow{r.dir, r.session, r.task, r.native, implied, rewritten, folded, canonical,
				len(nv.UnexplainedHarness), len(nv.UnexplainedHarnessNet), nv.Outcome, with, without}
			if got.implied != r.implied || got.rewritten != r.rewritten || got.folded != r.folded ||
				got.canonical != r.canonical || got.harnessFiles != r.harnessFiles || got.harnessNet != r.harnessNet || got.nativeOutcome != r.nativeOutcome {
				t.Errorf("native: implied=%d rewritten=%d folded=%d canonical=%d harness files=%d harness net=%d outcome=%s, want %d %d %d %d %d %d %s",
					got.implied, got.rewritten, got.folded, got.canonical, got.harnessFiles, got.harnessNet, got.nativeOutcome,
					r.implied, r.rewritten, r.folded, r.canonical, r.harnessFiles, r.harnessNet, r.nativeOutcome)
			}
			if with != r.withBaseline {
				t.Errorf("generic with a baseline: %v\nwant %v", with, r.withBaseline)
			}
			if without != r.without {
				t.Errorf("generic without a baseline: %v\nwant %v", without, r.without)
			}
		})
	}
}

// Capture leaves the control task's own command out of the rules by its
// normalized target (I-28). Generic normalizes nothing, so the exclusion,
// which names the claimed command, matches no event: agy runs the marker
// through the same argv in every control, which becomes a rule that would
// explain an unclaimed run of it.
func TestGenericBaselineKeepsTheControlCommand(t *testing.T) {
	const dir = "gemini/testdata/paired-agy-1.3.4-basic"
	paths, _ := filepath.Glob(filepath.Join(dir, "control-*.ground_truth.json"))
	var runs []models.GroundTruthFile
	for _, p := range paths {
		runs = append(runs, loadGround(t, p))
	}
	wrapped := models.GroundTruthEvent{ActionType: models.ProcessExec, Target: "/usr/bin/bash -c " + claudecode.ControlCommand}
	for _, a := range []agent.Adapter{gemini.Adapter{}, agent.Generic{}} {
		b, err := agent.Capture(a, "", runs, time.Now(), agent.CaptureOptions{Exclude: []string{claudecode.ControlCommand}})
		if err != nil {
			t.Fatal(err)
		}
		_, native := a.(gemini.Adapter)
		n, keep := a.Normalize(wrapped)
		if !keep || (native && n.Target != claudecode.ControlCommand) {
			t.Fatalf("%s normalized the marker's argv to %q", a.Name(), n.Target)
		}
		if got := b.Predicate(runs[0].Workspace)(n); got == native {
			t.Errorf("%s: the marker command baselined = %v, want %v", a.Name(), got, !native)
		}
	}
}

// The generic format cannot carry a harness-implied claim (V-33): the marker
// has no JSON form, so a converted trajectory never names it, and Generic
// refuses a trajectory that does. A converter that kept the entry would turn
// the harness's read into a claim of the agent's, so it drops it.
func TestGenericFormatCannotCarryImpliedBy(t *testing.T) {
	tr, _, err := claudecode.Adapter{}.Parse("claudecode/testdata/paired-2.1.296-shapes/shapes.session.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	implied := 0
	for _, e := range tr {
		if e.ImpliedBy != "" {
			implied++
		}
	}
	if implied != 1 {
		t.Fatalf("%d harness-implied claims in the shapes fixture, want 1", implied)
	}
	data, err := json.Marshal(tr)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("implied_by")) {
		t.Error("the marshalled trajectory names implied_by")
	}
	if got := convertToGeneric(t, tr); len(got) != len(tr)-implied {
		t.Errorf("converted %d claims, want %d without the harness-implied one", len(got), len(tr)-implied)
	}
	var raw []map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	raw[0]["implied_by"] = "cat x"
	forged, _ := json.Marshal(raw)
	path := filepath.Join(t.TempDir(), "forged.json")
	if err := os.WriteFile(path, forged, 0o600); err != nil {
		t.Fatal(err)
	}
	g, _ := agent.Lookup(agent.GenericName)
	if _, _, err := g.Parse(path); err == nil {
		t.Error("Generic read a trajectory that names implied_by")
	}
}

// What Generic declares, against what each native adapter declares: no
// harness directories, hosts, sensitive files or canonical form, and exits
// claimed.
func TestGenericDeclaresNoneOfTheNativeDeclarations(t *testing.T) {
	g, _ := agent.Lookup(agent.GenericName)
	if _, ok := g.(agent.HarnessOwner); ok {
		t.Error("Generic declares harness directories")
	}
	if _, ok := g.(agent.HarnessHoster); ok {
		t.Error("Generic declares harness hosts")
	}
	if _, ok := g.(agent.Canonicalizer); ok {
		t.Error("Generic has a canonical form")
	}
	if _, ok := g.(agent.StreamNormalizer); ok {
		t.Error("Generic folds the event stream")
	}
	if agent.SensitiveFiles(g) != nil {
		t.Error("Generic declares sensitive files")
	}
	if !g.Process().ExitsClaimed {
		t.Error("Generic does not claim exits")
	}
	for _, n := range []agent.Adapter{claudecode.Adapter{}, gemini.Adapter{}} {
		if _, ok := n.(agent.HarnessOwner); !ok {
			t.Errorf("%s declares no harness directories", n.Name())
		}
		if _, ok := n.(agent.HarnessHoster); !ok {
			t.Errorf("%s declares no harness hosts", n.Name())
		}
		if _, ok := n.(agent.Canonicalizer); !ok {
			t.Errorf("%s has no canonical form", n.Name())
		}
		if _, ok := n.(agent.StreamNormalizer); !ok {
			t.Errorf("%s folds nothing", n.Name())
		}
		if len(agent.SensitiveFiles(n)) == 0 {
			t.Errorf("%s declares no sensitive files", n.Name())
		}
		if n.Process().ExitsClaimed {
			t.Errorf("%s claims exits", n.Name())
		}
	}
}
