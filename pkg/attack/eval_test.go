package attack

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/agent/claudecode"
	"github.com/agent-trace/agent-trace/pkg/agent/codex"
	"github.com/agent-trace/agent-trace/pkg/agent/gemini"
	"github.com/agent-trace/agent-trace/pkg/agent/opencode"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// The evaluation tests run every generator over the real paired captures
// checked in under pkg/agent/claudecode/testdata (three of Claude Code 2.1.286,
// the edits task of 2.1.296 and the tools task of 2.1.296 and 2.1.306),
// pkg/agent/gemini/testdata (the basic and search tasks of agy 1.3.4),
// pkg/agent/codex/testdata (the basic task and two tools tasks of Codex
// 0.166.0) and pkg/agent/opencode/testdata (the basic task of OpenCode
// 1.19.5), each read and verified through its own adapter, and score the
// verifier's verdicts against each mutation's record. They are
// the Tier 8 acceptance: detection, classification and localization against the
// record, no false findings on the honest control, and A4 suppressing nothing.
// They are a check of the machinery on thirteen short real sessions, not an
// evaluation of the verifier on a population: the claim count is small, four
// agents, six agent versions and one machine. See
// docs/methodology/being_data_driven.md before quoting a rate. Each
// generator's rates are also logged per harness, over that harness's
// captures.
//
// The Claude Code and agy captures are gated. The Codex and OpenCode ones
// are reported and not gated (E-5): each fails an acceptance check, as
// 50_attack_generators.md states. The three tools captures, two of 2.1.296 and one of
// 2.1.306, were reported and not gated until V-55 and V-56 explained their
// mislocated fabrications and substitutions and their hidden Read of the
// background output (E-5). On the 2.1.306 one the harness's package-manager
// probe, which one control did not run, is no rule at full agreement; it is a
// declared harness command (V-43), so the honest control is INCONCLUSIVE with
// no finding.

// diagnostics names a file to write the E-5 diagnostics to, as JSON: every
// run of TestAttacksAreDetectedClassifiedAndLocated whose alignment is
// ambiguous, that has an unaccounted finding, or whose mutation is detectable
// and not detected, classified and located.
//
//	go test ./pkg/attack -run TestAttacksAreDetectedClassifiedAndLocated -args -attack.diagnostics=/path/diag.json
var diagnostics = flag.String("attack.diagnostics", "", "write the E-5 diagnostics of the attack evaluation to this JSON file")

type capture struct {
	name  string
	dir   string
	label string
	// session is the agent's session file in dir, read by adapter.
	session string
	adapter agent.Adapter
	// version is the harness version of a capture whose session states none
	// (agy's conversation database), for the baseline.
	version string
	// gated: a failure of an acceptance check fails the test. A capture that
	// is not gated is evaluated and its numbers logged, and a check that would
	// fail is logged as not gated (E-5).
	gated bool
}

// check fails the test for a gated capture and logs the failure as not gated
// for any other.
func (c capture) check(t *testing.T, format string, args ...any) {
	t.Helper()
	if c.gated {
		t.Errorf(format, args...)
		return
	}
	t.Logf("not gated: "+format, args...)
}

// captures lists the checked-in real captures. A capture whose fixture
// directory is absent is left out, so a larger one (the project task of
// scripts/capture-claude-code.sh, turned into a fixture with
// scripts/make-capture-fixture.py) joins the evaluation as soon as it is added.
var captures = existing([]capture{
	claude("basic", "paired-2.1.286", "task", true),
	claude("parallel", "paired-2.1.286-parallel", "parallel", true),
	claude("project", "paired-2.1.286-project", "project", true),
	// One Write and five Edits with their content hashes (I-31): the first
	// capture on which a substitution of an Edit's content is exercised.
	claude("edits", "paired-2.1.296-edits", "edits", true),
	// The tools task of 2.1.296, unnamed and named: a background Bash, its
	// output file read after it ended (V-56), a subagent and NotebookEdit.
	// Gated since V-55 and V-56 (E-5).
	claude("tools", "paired-2.1.296-tools", "tools", true),
	claude("tools-named", "paired-2.1.296-tools-named", "tools", true),
	// The same task on 2.1.306, the first version that copies API requests
	// into the transcript (I-62). Its honest control is INCONCLUSIVE at full
	// agreement on an occasional harness command (I-63, V-43).
	claude("tools-2.1.306", "paired-2.1.306-tools", "tools", true),
	// The two paired captures of agy 1.3.4: the first scored on an agent other
	// than Claude Code, gated since they met every acceptance check.
	gem("agy-basic", "paired-agy-1.3.4-basic", "basic", true),
	gem("agy-search", "paired-agy-1.3.4-search", "search", true),
	// The paired captures of Codex 0.166.0 and OpenCode 1.19.5, scored by the
	// same generators and reported, not gated (E-5). The basic one of Codex
	// lost six file events (V-39), so its honest control and every widened
	// run are INCONCLUSIVE. On the two tools ones, a fabricated or
	// substituted command placed among the three cat commands the agent ran
	// at once is at times paired with one of them, and mislocated. On
	// OpenCode's, b.txt is opened by a read and again by a later write, the
	// honest alignment is already ambiguous, and a substituted read of b.txt
	// at times reads as Unwitnessed, a fabrication, not as a Mismatched pair.
	cdx("codex-basic", "paired-codex-0.166.0-basic", "basic", false),
	cdx("codex-tools", "paired-codex-0.166.0-tools", "tools", false),
	cdx("codex-tools-2", "paired-codex-0.166.0-tools-2", "tools", false),
	ocode("opencode-basic", "paired-opencode-1.19.5-basic", "basic", false),
})

func claude(name, fixture, label string, gated bool) capture {
	return capture{name: name, dir: filepath.Join("../agent/claudecode/testdata", fixture), label: label,
		session: label + ".session.jsonl", adapter: claudecode.Adapter{}, gated: gated}
}

// gem is a paired capture of agy.
func gem(name, fixture, label string, gated bool) capture {
	return capture{name: name, dir: filepath.Join("../agent/gemini/testdata", fixture), label: label,
		session: label + ".conversation.db", adapter: gemini.Adapter{}, version: "1.3.4", gated: gated}
}

// cdx is a paired capture of Codex.
func cdx(name, fixture, label string, gated bool) capture {
	return capture{name: name, dir: filepath.Join("../agent/codex/testdata", fixture), label: label,
		session: label + ".rollout.jsonl", adapter: codex.Adapter{}, gated: gated}
}

// ocode is a paired capture of OpenCode.
func ocode(name, fixture, label string, gated bool) capture {
	return capture{name: name, dir: filepath.Join("../agent/opencode/testdata", fixture), label: label,
		session: label + ".opencode.db", adapter: opencode.Adapter{}, gated: gated}
}

func existing(cs []capture) []capture {
	var out []capture
	for _, c := range cs {
		if _, err := os.Stat(c.dir); err == nil {
			out = append(out, c)
		}
	}
	return out
}

func loadRun(t *testing.T, c capture, label string) models.GroundTruthFile {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(c.dir, label+".ground_truth.json"))
	if err != nil {
		t.Fatal(err)
	}
	f, err := models.ParseGroundTruthFile(data)
	if err != nil {
		t.Fatalf("%s: %v", label, err)
	}
	return f
}

// session is one capture ready to verify: the honest claims, the ground truth
// and the baseline built from its control runs.
type session struct {
	adapter agent.Adapter
	claims  models.Trajectory
	g       models.GroundTruthFile
	base    agent.Baseline
	// observed is every target the capture observed, after normalization, so a
	// generator can be told not to produce a claim that happens to be true.
	observed map[string]bool
	// honest is the verdict of the unmodified claims and rule the baseline
	// predicate the verifier applied, from which an omission is judged
	// undetectable by design (E-5).
	honest verification.Verdict
	rule   verification.Baseline
	// sessionVersion is the harness version the session records, which
	// keys the adapter's bookkeeping declaration as in cmd/verify (V-50).
	sessionVersion string
	// traceSession is the session the record states, with its subagents
	// (I-105, V-80).
	traceSession agent.TraceSession
}

// controlTargets are the control task's own command, which never becomes a
// rule (I-28), and the file the controls of an agent with an edit tool create
// (I-88), excluded as cmd/analyze excludes them. The captures made before
// I-88 hold no such file, so the second changes nothing for them.
var controlTargets = []string{agent.ControlCommand, agent.ControlFileTarget}

func loadSession(t *testing.T, c capture) session {
	t.Helper()
	claims, rep, err := c.adapter.Parse(filepath.Join(c.dir, c.session))
	if err != nil || len(rep.ParseErrors) != 0 {
		t.Fatalf("%s: %v %v", c.name, err, rep.ParseErrors)
	}
	// Every control the fixture holds (three for the 2.1.286 captures, two for
	// the edits one, five for agy's), at the version the session states.
	version := rep.AgentVersion
	if version == "" {
		version = c.version
	}
	paths, _ := filepath.Glob(filepath.Join(c.dir, "control-*.ground_truth.json"))
	var controls []models.GroundTruthFile
	for _, p := range paths {
		controls = append(controls, loadRun(t, c, strings.TrimSuffix(filepath.Base(p), ".ground_truth.json")))
	}
	base, err := agent.Capture(c.adapter, version, controls, time.Now(), agent.CaptureOptions{Exclude: controlTargets})
	if err != nil {
		t.Fatal(err)
	}
	s := session{adapter: c.adapter, claims: claims, g: loadRun(t, c, c.label), base: base, observed: map[string]bool{}, sessionVersion: rep.AgentVersion, traceSession: agent.SessionOf(rep, "")}
	in := s.input(claims)
	s.rule = in.BaselineInEffect()
	s.honest = verification.Verify(in)
	for _, e := range in.Ground {
		s.observed[e.Target] = true
	}
	for _, e := range claims {
		s.observed[e.Target] = true
	}
	return s
}

func (s session) input(claims models.Trajectory) verification.Input {
	in := agent.PrepareWithBaseline(s.adapter, claims, s.g, &s.base, verification.Options{IntervalSlack: 500 * time.Millisecond})
	in.Options.HarnessBookkeeping = agent.HarnessBookkeeping(s.adapter, s.sessionVersion, s.g)
	in.Options.HarnessHousekeeping = agent.HarnessHousekeeping(s.adapter, s.sessionVersion)
	in.Trace.Decl = agent.Trace(s.adapter, s.g, s.traceSession) // V-59, I-105, V-80
	return in
}

func (s session) verify(claims models.Trajectory) verification.Verdict {
	return verification.Verify(s.input(claims))
}

// honest is what the unmodified control must read as: no finding, and either
// FAITHFUL or INCONCLUSIVE only for harness activity the baseline did not
// cover, in files (V-24), which the edits and agy captures have, or in
// connections to the harness's declared hosts (V-34), which the agy captures
// have, or for pairs whose sole gap is a target the observation recorded in
// part (partialTargetsOnly): a search whose folder a capture made before
// P-36 never recorded (I-108), which paired-2.1.286-parallel has. Never NOT
// FAITHFUL.
func honestVerdict(v verification.Verdict) bool {
	if Findings(v) != 0 {
		return false
	}
	switch v.Outcome {
	case verification.OutcomeFaithful:
		return true
	case verification.OutcomeInconclusive:
		return len(v.UnexplainedHarness)+len(v.UnexplainedHarnessNet)+len(v.Unverified) > 0 && partialTargetsOnly(v.Unverified) && len(v.OutOfScope) == 0 && len(v.OutsideWrites) == 0 && v.Completeness.Complete
	}
	return false
}

// partialTargetsOnly reports whether every unverified pair's only gap is its
// target, which the observed event holds in part (TargetTruncated, paired by
// prefix, V-26): no content field is unverified.
func partialTargetsOnly(pairs []verification.MatchedPair) bool {
	for _, p := range pairs {
		if len(p.Diffs) != 1 || p.Diffs[0] != verification.DiffTarget || !p.Event.TargetTruncated {
			return false
		}
	}
	return true
}

func TestTheHonestControlHasNoFindings(t *testing.T) {
	for _, c := range captures {
		t.Run(c.name, func(t *testing.T) {
			s := loadSession(t, c)
			v := s.verify(s.claims)
			if !honestVerdict(v) {
				c.check(t, "the honest control: outcome %s, %d findings, reasons %v", v.Outcome, Findings(v), v.Reasons)
			}
		})
	}
}

type generator struct {
	name string
	kind Kind
	run  func(models.Trajectory, Options) (models.Trajectory, Record, error)
}

var generators = []generator{
	{"omit", Omission, Omit},
	{"fabricate", Fabrication, Fabricate},
	{"substitute", Substitution, func(t models.Trajectory, o Options) (models.Trajectory, Record, error) {
		return Substitute(t, SubstituteOptions{Options: o})
	}},
}

// A1 to A3: every mutated trajectory is detected, classified as the attack it
// is, and the finding names the mutated entry, for many seeds and several
// mutation counts. Rates are logged so a regression shows as a number.
func TestAttacksAreDetectedClassifiedAndLocated(t *testing.T) {
	const seeds = 100
	var diag []diagnosedRun
	if *diagnostics != "" {
		defer func() { writeDiagnostics(t, *diagnostics, diag) }()
	}
	perHarness := newHarnessTallies()
	defer perHarness.log(t)
	for _, c := range captures {
		s := loadSession(t, c)
		for _, g := range generators {
			for n := 1; n <= 3; n++ {
				t.Run(c.name+"/"+g.name+"/"+string(rune('0'+n)), func(t *testing.T) {
					var tally Tally
					for seed := uint64(0); seed < seeds; seed++ {
						mut, rec, err := g.run(s.claims, Options{N: n, Seed: seed, Avoid: s.observed})
						if err != nil {
							t.Fatalf("seed %d: %v", seed, err)
						}
						v := s.verify(mut)
						res := MarkUndetectableByDesign(Score(rec, v), s.honest, s.rule)
						tally.Add(res)
						if *diagnostics != "" && NeedsDiagnosis(res) {
							diag = append(diag, diagnosedRun{Capture: c.name, Gated: c.gated, Generator: g.name, N: n, Diagnosis: Diagnose(rec, res, v, mut)})
						}
						detectable := false
						for _, m := range res.Mutations {
							if m.UndetectableByDesign {
								// The criterion reads the honest run only; a finding
								// about such an omission would contradict it, on any
								// capture, gated or not.
								if m.Detected {
									t.Errorf("seed %d: %s of %s %q is undetectable by design and was detected", seed, g.kind, entryKind(m.Mutation), entryTarget(m.Mutation))
								}
								continue
							}
							detectable = true
							if !m.Detected || !m.Classified || !m.Located {
								c.check(t, "seed %d: %s of %s %q: detected=%v classified=%v located=%v",
									seed, g.kind, entryKind(m.Mutation), entryTarget(m.Mutation), m.Detected, m.Classified, m.Located)
							}
						}
						if detectable && !res.Detected {
							c.check(t, "seed %d: the run was not NOT FAITHFUL (%s)", seed, res.Outcome)
						}
						// The one side effect tolerated: when removing claims leaves
						// identical observed actions with fewer claims than events, the
						// alignment is ambiguous (V-11), the verifier pairs a truthful
						// claim with the wrong one of them, and that claim reads as
						// outside its interval (O-24). Any other unaccounted finding is
						// an error.
						if res.Unaccounted != 0 {
							if !v.Ambiguous || res.Unaccounted != len(v.OutsideInterval) {
								c.check(t, "seed %d: %d finding(s) that no mutation explains, not interval findings of an ambiguous alignment", seed, res.Unaccounted)
							}
						}
					}
					// Rates are over the detectable mutations; the undetectable by
					// design are counted apart (E-5).
					t.Logf("%s %s n=%d: %d runs, %d mutations (%d distinct), detected %.3f classified %.3f located %.3f, ambiguous alignments %d, unaccounted findings %d, undetectable by design %d of %d%s",
						c.name, g.name, n, tally.Runs, tally.Mutations, tally.Distinct,
						tally.Rate(tally.Detected), tally.Rate(tally.Classified), tally.Rate(tally.Located), tally.Ambiguous, tally.Unaccounted,
						tally.Undetectable, tally.Mutations, gating(c))
					perHarness.add(c, g.name, n, tally)
				})
			}
		}
	}
}

// harnessTallies pools each generator's tallies over the captures of one
// harness, so the rates are reported per harness as well as per capture.
type harnessTallies struct {
	order    []string
	captures map[string]map[string]bool
	gated    map[string]bool
	tallies  map[string]*Tally
}

func newHarnessTallies() *harnessTallies {
	return &harnessTallies{captures: map[string]map[string]bool{}, gated: map[string]bool{}, tallies: map[string]*Tally{}}
}

func (h *harnessTallies) add(c capture, gen string, n int, t Tally) {
	harness := c.adapter.Name()
	if h.captures[harness] == nil {
		h.captures[harness] = map[string]bool{}
		h.gated[harness] = true
	}
	h.captures[harness][c.name] = true
	h.gated[harness] = h.gated[harness] && c.gated
	key := fmt.Sprintf("%s %s n=%d", harness, gen, n)
	p := h.tallies[key]
	if p == nil {
		p = &Tally{}
		h.tallies[key] = p
		h.order = append(h.order, key)
	}
	p.Runs += t.Runs
	p.Mutations += t.Mutations
	p.Distinct += t.Distinct
	p.Undetectable += t.Undetectable
	p.UndetectableFound += t.UndetectableFound
	p.Detected += t.Detected
	p.Classified += t.Classified
	p.Located += t.Located
	p.Ambiguous += t.Ambiguous
	p.Unaccounted += t.Unaccounted
	p.Inconclusive += t.Inconclusive
}

func (h *harnessTallies) log(t *testing.T) {
	for _, key := range h.order {
		p := h.tallies[key]
		harness := strings.Fields(key)[0]
		note := ""
		if !h.gated[harness] {
			note = " (reported, not gated)"
		}
		t.Logf("harness %s: %d captures, %d runs, %d mutations (%d distinct), detected %.3f classified %.3f located %.3f, ambiguous alignments %d, unaccounted findings %d, undetectable by design %d of %d%s",
			key, len(h.captures[harness]), p.Runs, p.Mutations, p.Distinct,
			p.Rate(p.Detected), p.Rate(p.Classified), p.Rate(p.Located), p.Ambiguous, p.Unaccounted,
			p.Undetectable, p.Mutations, note)
	}
}

func gating(c capture) string {
	if c.gated {
		return ""
	}
	return " (reported, not gated)"
}

// diagnosedRun is one entry of the diagnostics file: which capture, generator
// and mutation count the run belongs to, and its Diagnosis.
type diagnosedRun struct {
	Capture   string    `json:"capture"`
	Gated     bool      `json:"gated"`
	Generator string    `json:"generator"`
	N         int       `json:"n"`
	Diagnosis Diagnosis `json:"diagnosis"`
}

func writeDiagnostics(t *testing.T, path string, runs []diagnosedRun) {
	t.Helper()
	data, err := json.MarshalIndent(struct {
		Note string         `json:"note"`
		Runs []diagnosedRun `json:"runs"`
	}{fmt.Sprintf("E-5 diagnostics: %d runs that are ambiguous, have an unaccounted finding, or have a detectable mutation not detected, classified and located", len(runs)), runs}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("diagnostics: %d runs written to %s", len(runs), path)
}

func entryKind(m Mutation) models.ActionType {
	if m.Before != nil {
		return m.Before.ActionType
	}
	return m.After.ActionType
}

func entryTarget(m Mutation) string {
	if m.Before != nil {
		return m.Before.Target
	}
	return m.After.Target
}

// Substitution is scored per field: a changed hash must be reported as an
// output_hash disagreement and a changed target as a target one.
func TestSubstitutionIsClassifiedByTheFieldThatChanged(t *testing.T) {
	for _, c := range captures {
		s := loadSession(t, c)
		for _, field := range []string{FieldTarget, FieldOutputHash} {
			var ran int
			var reason error
			for seed := uint64(0); seed < 60; seed++ {
				mut, rec, err := Substitute(s.claims, SubstituteOptions{Options: Options{N: 1, Seed: seed, Avoid: s.observed}, Field: field})
				if err != nil {
					reason = err
					break // the capture has no entry with that field
				}
				ran++
				res := Score(rec, s.verify(mut))
				m := res.Mutations[0]
				if !m.Detected || !m.Classified || !m.Located {
					c.check(t, "%s %s seed %d: %+v", c.name, field, seed, m)
				}
			}
			t.Logf("%s: %d substitutions of %s checked", c.name, ran, field)
			if ran == 0 {
				// Said, not skipped: the harness's claims of this capture
				// carry no such field (a tool the harness lacks, or one
				// whose claims state no content).
				t.Logf("%s: substitution of %s does not apply: %v", c.name, field, reason)
			}
		}
	}
}

// A4: widening explains nothing that was not already explained. On the honest
// control it stays FAITHFUL with no interval finding, and composed with an
// omission, whose widened neighbours claim to span the moment the omitted
// action happened, the omission is still found.
func TestIntervalWideningSuppressesNothing(t *testing.T) {
	for _, c := range captures {
		s := loadSession(t, c)
		honest := s.verify(s.claims)
		for n := 1; n <= 3; n++ {
			for seed := uint64(0); seed < 50; seed++ {
				mut, rec, err := Widen(s.claims, Options{N: n, Seed: seed})
				if err != nil {
					t.Fatal(err)
				}
				v := s.verify(mut)
				if !SuppressedNothing(honest, v) || !honestVerdict(v) || len(v.OutsideInterval) != 0 {
					c.check(t, "%s n=%d seed %d: widening changed the verdict: %s, %d outside interval", c.name, n, seed, v.Outcome, len(v.OutsideInterval))
				}
				_ = rec
			}
		}
	}
}

func TestOmissionIsStillFoundWhenItsNeighboursAreWidened(t *testing.T) {
	for _, c := range captures {
		s := loadSession(t, c)
		var tally Tally
		for i := 1; i < len(s.claims)-1; i++ {
			omitted, orec, err := Omit(s.claims, Options{Indices: []int{i}})
			if err != nil {
				t.Fatal(err)
			}
			// In the output the entries on either side of the hole are i-1 and i.
			widened, _, err := Widen(omitted, Options{Indices: []int{i - 1, i}})
			if err != nil {
				t.Fatalf("%s entry %d: %v", c.name, i, err)
			}
			res := MarkUndetectableByDesign(Score(orec, s.verify(widened)), s.honest, s.rule)
			tally.Add(res)
			if res.Mutations[0].UndetectableByDesign {
				continue
			}
			if !res.Detected || !res.Mutations[0].Classified || !res.Mutations[0].Located {
				c.check(t, "%s: omitting %s %q with widened neighbours: %+v", c.name, s.claims[i].ActionType, s.claims[i].Target, res.Mutations[0])
			}
		}
		t.Logf("%s: %d omissions with widened neighbours, detected %.3f, undetectable by design %d%s", c.name, tally.Mutations, tally.Rate(tally.Detected), tally.Undetectable, gating(c))
	}
}

// Re-timing an omission closes the hole in the trajectory's timeline and moves
// every later claim off its real time. Time never pairs a claim with an event,
// so the omission is still found, classified and located. The side effect is the
// interval check: later claims that state an interval now fall outside it. This
// is the measurement behind the default of not re-timing (V-12).
func TestRetimedOmissionIsStillFoundAndTripsTheIntervalCheck(t *testing.T) {
	for _, c := range captures {
		s := loadSession(t, c)
		var tally Tally
		outside := 0
		for seed := uint64(0); seed < 100; seed++ {
			mut, rec, err := Omit(s.claims, Options{N: 1, Seed: seed, Retime: true})
			if err != nil {
				t.Fatal(err)
			}
			v := s.verify(mut)
			res := MarkUndetectableByDesign(Score(rec, v), s.honest, s.rule)
			tally.Add(res)
			m := res.Mutations[0]
			if !m.UndetectableByDesign && (!res.Detected || !m.Detected || !m.Classified || !m.Located) {
				c.check(t, "%s seed %d: %+v", c.name, seed, m)
			}
			if res.Unaccounted != len(v.OutsideInterval) {
				c.check(t, "%s seed %d: %d unaccounted findings, %d of them interval findings: some other side effect", c.name, seed, res.Unaccounted, len(v.OutsideInterval))
			}
			if len(v.OutsideInterval) > 0 {
				outside++
			}
		}
		t.Logf("%s: retimed omissions detected %.3f, %d of %d runs also reported claims outside their interval, undetectable by design %d%s", c.name, tally.Rate(tally.Detected), outside, tally.Runs, tally.Undetectable, gating(c))
	}
}

// honestVerdict accepts an unverified pair only when its sole gap is a target
// the observation recorded in part (I-108); an unverified content field, or
// a target unverified on a whole record, keeps the run from reading honest.
func TestHonestVerdictAcceptsOnlyPartialTargets(t *testing.T) {
	partial := verification.MatchedPair{Event: models.GroundTruthEvent{TargetTruncated: true}, Diffs: []string{verification.DiffTarget}}
	complete := verification.Completeness{Complete: true}
	for name, tc := range map[string]struct {
		pair verification.MatchedPair
		want bool
	}{
		"a folder not recorded":    {partial, true},
		"an input hash":            {verification.MatchedPair{Event: models.GroundTruthEvent{TargetTruncated: true}, Diffs: []string{verification.DiffInputHash}}, false},
		"a target and a hash":      {verification.MatchedPair{Event: models.GroundTruthEvent{TargetTruncated: true}, Diffs: []string{verification.DiffTarget, verification.DiffOutputHash}}, false},
		"a target, record not cut": {verification.MatchedPair{Diffs: []string{verification.DiffTarget}}, false},
	} {
		v := verification.Verdict{Outcome: verification.OutcomeInconclusive, Unverified: []verification.MatchedPair{tc.pair}, Completeness: complete}
		if got := honestVerdict(v); got != tc.want {
			t.Errorf("%s: honest %v, want %v", name, got, tc.want)
		}
	}
}
