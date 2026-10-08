package attack

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/agent/claudecode"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// The evaluation tests run every generator over the two real paired captures of
// Claude Code 2.1.286 checked in under pkg/agent/claudecode/testdata, and score
// the verifier's verdicts against each mutation's record. They are the Tier 8
// acceptance: detection, classification and localization against the record, no
// false findings on the honest control, and A4 suppressing nothing. They are a
// check of the machinery on two short real sessions, not an evaluation of the
// verifier on a population: the claim count is small, one agent version and one
// machine. See docs/methodology/being_data_driven.md before quoting a rate.

type capture struct {
	name  string
	dir   string
	label string
}

// captures lists the checked-in real captures. A capture whose fixture
// directory is absent is left out, so a larger one (the project task of
// scripts/capture-claude-code.sh, turned into a fixture with
// scripts/make-capture-fixture.py) joins the evaluation as soon as it is added.
var captures = existing([]capture{
	{"basic", "../agent/claudecode/testdata/paired-2.1.286", "task"},
	{"parallel", "../agent/claudecode/testdata/paired-2.1.286-parallel", "parallel"},
	{"project", "../agent/claudecode/testdata/paired-2.1.286-project", "project"},
})

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
	claims models.Trajectory
	g      models.GroundTruthFile
	base   agent.Baseline
	// observed is every target the capture observed, after normalization, so a
	// generator can be told not to produce a claim that happens to be true.
	observed map[string]bool
}

func loadSession(t *testing.T, c capture) session {
	t.Helper()
	claims, rep, err := claudecode.Adapter{}.Parse(filepath.Join(c.dir, c.label+".session.jsonl"))
	if err != nil || len(rep.ParseErrors) != 0 {
		t.Fatalf("%s: %v %v", c.name, err, rep.ParseErrors)
	}
	var controls []models.GroundTruthFile
	for _, l := range []string{"control-1", "control-2", "control-3"} {
		controls = append(controls, loadRun(t, c, l))
	}
	base, err := agent.Capture(claudecode.Adapter{}, "2.1.286", controls, time.Now(), agent.CaptureOptions{Exclude: []string{claudecode.ControlCommand}})
	if err != nil {
		t.Fatal(err)
	}
	s := session{claims: claims, g: loadRun(t, c, c.label), base: base, observed: map[string]bool{}}
	in := s.input(claims)
	for _, e := range in.Ground {
		s.observed[e.Target] = true
	}
	for _, e := range claims {
		s.observed[e.Target] = true
	}
	return s
}

func (s session) input(claims models.Trajectory) verification.Input {
	in := agent.Prepare(claudecode.Adapter{}, claims, s.g, s.base.Predicate(s.g.Workspace), verification.Options{IntervalSlack: 500 * time.Millisecond})
	return in
}

func (s session) verify(claims models.Trajectory) verification.Verdict {
	return verification.Verify(s.input(claims))
}

func TestTheHonestControlHasNoFindings(t *testing.T) {
	for _, c := range captures {
		t.Run(c.name, func(t *testing.T) {
			s := loadSession(t, c)
			v := s.verify(s.claims)
			if v.Outcome != verification.OutcomeFaithful || Findings(v) != 0 {
				t.Fatalf("the honest control: outcome %s, %d findings", v.Outcome, Findings(v))
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
						res := Score(rec, v)
						tally.Add(res)
						if !res.Detected {
							t.Errorf("seed %d: the run was not NOT FAITHFUL (%s)", seed, res.Outcome)
						}
						for _, m := range res.Mutations {
							if !m.Detected || !m.Classified || !m.Located {
								t.Errorf("seed %d: %s of %s %q: detected=%v classified=%v located=%v",
									seed, g.kind, entryKind(m.Mutation), entryTarget(m.Mutation), m.Detected, m.Classified, m.Located)
							}
						}
						// The one side effect tolerated: when removing claims leaves
						// identical observed actions with fewer claims than events, the
						// alignment is ambiguous (V-11), the verifier pairs a truthful
						// claim with the wrong one of them, and that claim reads as
						// outside its interval (O-24). Any other unaccounted finding is
						// an error.
						if res.Unaccounted != 0 {
							if !v.Ambiguous || res.Unaccounted != len(v.OutsideInterval) {
								t.Errorf("seed %d: %d finding(s) that no mutation explains, not interval findings of an ambiguous alignment", seed, res.Unaccounted)
							}
						}
					}
					t.Logf("%s %s n=%d: %d runs, %d mutations (%d distinct), detected %.3f classified %.3f located %.3f, ambiguous alignments %d, unaccounted findings %d",
						c.name, g.name, n, tally.Runs, tally.Mutations, tally.Distinct,
						tally.Rate(tally.Detected), tally.Rate(tally.Classified), tally.Rate(tally.Located), tally.Ambiguous, tally.Unaccounted)
				})
			}
		}
	}
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
			for seed := uint64(0); seed < 60; seed++ {
				mut, rec, err := Substitute(s.claims, SubstituteOptions{Options: Options{N: 1, Seed: seed, Avoid: s.observed}, Field: field})
				if err != nil {
					break // the capture has no entry with that field
				}
				ran++
				res := Score(rec, s.verify(mut))
				m := res.Mutations[0]
				if !m.Detected || !m.Classified || !m.Located {
					t.Errorf("%s %s seed %d: %+v", c.name, field, seed, m)
				}
			}
			t.Logf("%s: %d substitutions of %s checked", c.name, ran, field)
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
				if !SuppressedNothing(honest, v) || v.Outcome != verification.OutcomeFaithful || len(v.OutsideInterval) != 0 {
					t.Fatalf("%s n=%d seed %d: widening changed the verdict: %s, %d outside interval", c.name, n, seed, v.Outcome, len(v.OutsideInterval))
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
			res := Score(orec, s.verify(widened))
			tally.Add(res)
			if !res.Detected || !res.Mutations[0].Classified || !res.Mutations[0].Located {
				t.Errorf("%s: omitting %s %q with widened neighbours: %+v", c.name, s.claims[i].ActionType, s.claims[i].Target, res.Mutations[0])
			}
		}
		t.Logf("%s: %d omissions with widened neighbours, detected %.3f", c.name, tally.Mutations, tally.Rate(tally.Detected))
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
			res := Score(rec, v)
			tally.Add(res)
			m := res.Mutations[0]
			if !res.Detected || !m.Detected || !m.Classified || !m.Located {
				t.Errorf("%s seed %d: %+v", c.name, seed, m)
			}
			if res.Unaccounted != len(v.OutsideInterval) {
				t.Errorf("%s seed %d: %d unaccounted findings, %d of them interval findings: some other side effect", c.name, seed, res.Unaccounted, len(v.OutsideInterval))
			}
			if len(v.OutsideInterval) > 0 {
				outside++
			}
		}
		t.Logf("%s: retimed omissions detected %.3f, %d of %d runs also reported claims outside their interval", c.name, tally.Rate(tally.Detected), outside, tally.Runs)
	}
}
