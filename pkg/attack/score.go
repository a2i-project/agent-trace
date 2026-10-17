package attack

import (
	"fmt"

	"github.com/agent-trace/agent-trace/pkg/matching"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// MutationResult is how a verdict treated one mutation.
type MutationResult struct {
	Mutation Mutation `json:"mutation"`
	// Detected: some finding of any kind refers to the mutated entry or to the
	// observed event that corresponds to it.
	Detected bool `json:"detected"`
	// Classified: the finding is of the kind the attack is. An omission is an
	// unrecorded action (or an unexplained command), a fabrication an
	// unwitnessed claim, a substitution a mismatched pair that names the field.
	// Detected and not Classified is the pre-Tier 6 failure: the right alarm
	// under the wrong name, such as a substitution read as a fabrication plus an
	// omission.
	Classified bool `json:"classified"`
	// Located: the finding names exactly the mutated entry, and not a neighbour.
	Located bool `json:"located"`
	// UndetectableByDesign: an omission whose observed action the verifier's
	// documented design explains, so no finding can arise (E-5). It is set by
	// MarkUndetectableByDesign from the honest run, never from whether this
	// verdict found it. Tally counts it apart: neither a miss nor detected.
	UndetectableByDesign bool `json:"undetectable_by_design"`
}

// Result is how a verdict treated a whole attack.
type Result struct {
	Kind Kind
	// Outcome is the verdict's outcome.
	Outcome verification.Outcome
	// Detected is the run-level result: the outcome is NOT FAITHFUL.
	Detected bool
	// Mutations holds one result per recorded mutation.
	Mutations []MutationResult
	// Unaccounted counts findings in the verdict that no mutation of the record
	// explains: a side effect of the attack, or, on an honest run, a false
	// positive.
	Unaccounted int
	// Ambiguous is true when an alignment has more than one minimum-cost reading,
	// so a finding that points at one position does not exclude the others. It
	// is reported, never resolved (V-11).
	Ambiguous bool
}

// Findings counts a verdict's findings: every claim or event the verdict flags.
func Findings(v verification.Verdict) int { return v.Findings() }

// Score checks a verdict against the record of the mutation that produced the
// trajectory it was computed for. Interval widening has no finding of its own
// (it is an attack on the interval check, and attribution does not use
// intervals), so its mutations are scored Detected, Classified and Located only
// when the verdict names the widened entry in OutsideInterval, which an honest
// widening does not trigger. Use SuppressedNothing to judge what A4 is meant to
// show.
func Score(rec Record, v verification.Verdict) Result {
	res := Result{Kind: rec.Kind, Outcome: v.Outcome, Detected: v.Outcome == verification.OutcomeNotFaithful, Ambiguous: v.Ambiguous}
	for _, m := range rec.Mutations {
		var mr MutationResult
		switch rec.Kind {
		case Omission:
			mr = scoreOmission(m, v)
		case Fabrication:
			mr = scoreFabrication(m, v)
		case Substitution:
			mr = scoreSubstitution(m, v)
		case IntervalWidening:
			mr = scoreWidening(m, v)
		default:
			mr = MutationResult{Mutation: m}
		}
		res.Mutations = append(res.Mutations, mr)
	}
	res.Unaccounted = unaccounted(rec, v)
	return res
}

// unaccounted counts the findings no mutation of the record explains. A single
// omission can be reported twice, as an unrecorded command and as the command's
// unexplained subtree (V3), and both belong to it.
func unaccounted(rec Record, v verification.Verdict) int {
	n := 0
	for _, f := range findingsOf(rec, v, nil) {
		if !f.Accounted {
			n++
		}
	}
	return n
}

// Finding is one finding of a verdict as the diagnostics report it (E-5):
// what kind it is, what it names, and whether a mutation of the record
// explains it.
type Finding struct {
	// Kind is unrecorded, unexplained_subtree, unwitnessed, mismatched or
	// outside_interval.
	Kind string `json:"kind"`
	// ClaimIndex is the position, in the mutated trajectory, of the claim the
	// finding names (unwitnessed, mismatched, outside_interval), or -1 when it
	// names an observed event only or the claim is not found there.
	ClaimIndex int                     `json:"claim_index"`
	Claim      *models.TrajectoryEntry `json:"claim,omitempty"`
	// Event is the observed side: the unrecorded event, the paired event of a
	// mismatched or outside-interval pair, or the exec of an unexplained
	// subtree.
	Event *models.GroundTruthEvent `json:"event,omitempty"`
	Diffs []string                 `json:"diffs,omitempty"`
	// Accounted: a mutation of the record explains the finding, by the same
	// rules as Result.Unaccounted.
	Accounted bool `json:"accounted"`
}

// findingsOf lists the verdict's findings in a fixed order (unrecorded,
// unexplained subtrees, unwitnessed, mismatched, outside interval), each
// marked accounted when a mutation of the record explains it. mutated, when
// given, locates each named claim by position.
func findingsOf(rec Record, v verification.Verdict, mutated models.Trajectory) []Finding {
	var out []Finding
	claimAt := func(e models.TrajectoryEntry) int {
		for i := range mutated {
			if sameClaim(e, &mutated[i]) {
				return i
			}
		}
		return -1
	}
	for _, ev := range v.Unrecorded {
		ok := false
		for _, m := range rec.Mutations {
			switch m.Kind {
			case Omission, Substitution:
				ok = ok || (m.Before.ActionType == ev.ActionType && matching.TargetsMatch(*m.Before, ev))
			}
		}
		ev := ev
		out = append(out, Finding{Kind: "unrecorded", ClaimIndex: -1, Event: &ev, Accounted: ok})
	}
	for _, c := range v.Coverage.UnexplainedSubtrees {
		ok := false
		for _, m := range rec.Mutations {
			if (m.Kind == Omission || m.Kind == Substitution) && m.Before.ActionType == models.ProcessExec && c.Exec != nil && c.Exec.Target == m.Before.Target {
				ok = true
			}
		}
		f := Finding{Kind: "unexplained_subtree", ClaimIndex: -1, Accounted: ok}
		if c.Exec != nil {
			ev := *c.Exec
			f.Event = &ev
		}
		out = append(out, f)
	}
	for _, u := range v.Unwitnessed {
		ok := false
		for _, m := range rec.Mutations {
			if (m.Kind == Fabrication || m.Kind == Substitution) && sameClaim(u, m.After) {
				ok = true
			}
		}
		u := u
		out = append(out, Finding{Kind: "unwitnessed", ClaimIndex: claimAt(u), Claim: &u, Accounted: ok})
	}
	for _, p := range v.Mismatched {
		ok := false
		for _, m := range rec.Mutations {
			if (m.Kind == Substitution || m.Kind == Fabrication) && sameClaim(p.Entry, m.After) {
				ok = true
			}
		}
		out = append(out, pairFinding("mismatched", p, claimAt(p.Entry), ok))
	}
	for _, p := range v.OutsideInterval {
		ok := false
		for _, m := range rec.Mutations {
			if m.Kind == IntervalWidening && p.Entry.ActionType == m.After.ActionType && p.Entry.Target == m.After.Target {
				ok = true
			}
		}
		out = append(out, pairFinding("outside_interval", p, claimAt(p.Entry), ok))
	}
	return out
}

func pairFinding(kind string, p verification.MatchedPair, at int, ok bool) Finding {
	c, ev := p.Entry, p.Event
	return Finding{Kind: kind, ClaimIndex: at, Claim: &c, Event: &ev, Diffs: p.Diffs, Accounted: ok}
}

func sameClaim(a models.TrajectoryEntry, b *models.TrajectoryEntry) bool {
	return b != nil && a.ActionType == b.ActionType && a.Target == b.Target && a.Tool == b.Tool && a.Timestamp.Equal(b.Timestamp)
}

func scoreOmission(m Mutation, v verification.Verdict) MutationResult {
	e := *m.Before
	mr := MutationResult{Mutation: m}
	for _, ev := range v.Unrecorded {
		if ev.ActionType == e.ActionType && matching.TargetsMatch(e, ev) {
			mr.Detected, mr.Classified, mr.Located = true, true, true
		}
	}
	if e.ActionType == models.ProcessExec {
		for _, c := range v.Coverage.UnexplainedSubtrees {
			if c.Exec != nil && c.Exec.Target == e.Target {
				mr.Detected, mr.Classified, mr.Located = true, true, true
			}
		}
	}
	if !mr.Detected {
		// The omitted action's event may have been consumed by another claim
		// and reported as a disagreement: detected, misclassified.
		for _, p := range v.Mismatched {
			if p.Event.ActionType == e.ActionType && matching.TargetsMatch(e, p.Event) {
				mr.Detected = true
			}
		}
	}
	return mr
}

func scoreFabrication(m Mutation, v verification.Verdict) MutationResult {
	mr := MutationResult{Mutation: m}
	for _, u := range v.Unwitnessed {
		if sameClaim(u, m.After) {
			mr.Detected, mr.Classified, mr.Located = true, true, true
		}
	}
	if !mr.Detected {
		for _, p := range v.Mismatched {
			if sameClaim(p.Entry, m.After) {
				mr.Detected = true // consumed an event and read as a disagreement
			}
		}
	}
	return mr
}

func scoreSubstitution(m Mutation, v verification.Verdict) MutationResult {
	mr := MutationResult{Mutation: m}
	for _, p := range v.Mismatched {
		if !sameClaim(p.Entry, m.After) {
			continue
		}
		mr.Detected = true
		for _, d := range p.Diffs {
			if d == m.Field {
				mr.Classified = true
			}
		}
		// Located: the observed side of the pair is what the claim was before the
		// substitution, so the finding names this entry and not a neighbour.
		mr.Located = mr.Classified && matching.TargetsMatch(*m.Before, p.Event) && p.Event.ActionType == m.Before.ActionType
	}
	if !mr.Detected {
		// The split reading: the new claim unwitnessed, the real event unrecorded.
		for _, u := range v.Unwitnessed {
			if sameClaim(u, m.After) {
				mr.Detected = true
			}
		}
	}
	return mr
}

func scoreWidening(m Mutation, v verification.Verdict) MutationResult {
	mr := MutationResult{Mutation: m}
	for _, p := range v.OutsideInterval {
		if p.Entry.ActionType == m.After.ActionType && p.Entry.Target == m.After.Target {
			mr.Detected, mr.Classified, mr.Located = true, true, true
		}
	}
	return mr
}

// SuppressedNothing is the claim A4 exists to test: widening intervals explains
// no event that was not already explained, so the verdict of an attacked run
// has every finding the same run would have had without the widening. It
// compares the finding counts and the outcome of the two verdicts.
func SuppressedNothing(without, with verification.Verdict) bool {
	return with.Outcome == without.Outcome &&
		len(with.Unrecorded) >= len(without.Unrecorded) &&
		len(with.Unwitnessed) >= len(without.Unwitnessed) &&
		len(with.Mismatched) >= len(without.Mismatched) &&
		len(with.Coverage.UnexplainedSubtrees) >= len(without.Coverage.UnexplainedSubtrees)
}

// MarkUndetectableByDesign sets UndetectableByDesign on each omission of the
// result whose observed action the verifier explains by its documented design
// (E-5). The criterion reads only the honest run, verified with the same
// baseline: the omitted claim (the record's Before, found among the honest
// verdict's corroborated pairs by action type, target, tool and timestamp)
// paired with an event that is
//
//   - listed in the honest verdict's CorroboratedHarnessShared (V-36: a read
//     of a file the harness itself opens at rest), or
//   - a level-0 event, that is not a command's exec or exit, that a rule of
//     baseline matches (V7, V-30, V-37).
//
// Without the claim such an event is subtracted with the harness's own
// activity, or kept for another claim on its path and then explained (V-30),
// so it is never Unrecorded. Whether this verdict happened to report the
// omission is not consulted. A nil baseline marks only the V-36 pairs.
func MarkUndetectableByDesign(r Result, honest verification.Verdict, baseline verification.Baseline) Result {
	out := r
	out.Mutations = append([]MutationResult(nil), r.Mutations...)
	for i, mr := range out.Mutations {
		m := mr.Mutation
		if m.Kind != Omission || m.Before == nil {
			continue
		}
		out.Mutations[i].UndetectableByDesign = explainedByDesign(*m.Before, honest, baseline)
	}
	return out
}

func explainedByDesign(e models.TrajectoryEntry, honest verification.Verdict, baseline verification.Baseline) bool {
	for _, p := range honest.CorroboratedHarnessShared {
		if sameClaim(p.Entry, &e) {
			return true
		}
	}
	if baseline == nil {
		return false
	}
	for _, p := range honest.Corroborated {
		if sameClaim(p.Entry, &e) && verification.LaneOf(p.Event.ActionType) != verification.LaneProc && baseline(p.Event) {
			return true
		}
	}
	return false
}

// Diagnosis is the record of one scored run for a later investigation of
// where the verifier put its findings (E-5): every mutation with its scores,
// every finding with what it names and whether a mutation explains it, and
// each lane's count of minimum-cost alignments.
type Diagnosis struct {
	Kind      Kind                 `json:"kind"`
	Seed      uint64               `json:"seed"`
	Outcome   verification.Outcome `json:"outcome"`
	Mutations []MutationResult     `json:"mutations"`
	Findings  []Finding            `json:"findings"`
	// Unaccounted is the number of findings with Accounted false.
	Unaccounted int             `json:"unaccounted"`
	Ambiguous   bool            `json:"ambiguous"`
	Lanes       []LaneDiagnosis `json:"lanes"`
}

// LaneDiagnosis is one lane's alignment summary: Optimal is the number of
// minimum-cost alignments, saturating (V-11).
type LaneDiagnosis struct {
	Lane      verification.Lane `json:"lane"`
	Optimal   uint32            `json:"optimal"`
	Ambiguous bool              `json:"ambiguous"`
}

// Diagnose builds the Diagnosis of a scored result. mutated is the trajectory
// the verdict was computed for, used to give each finding's claim its
// position.
func Diagnose(rec Record, r Result, v verification.Verdict, mutated models.Trajectory) Diagnosis {
	d := Diagnosis{Kind: rec.Kind, Seed: rec.Seed, Outcome: v.Outcome, Ambiguous: v.Ambiguous, Findings: findingsOf(rec, v, mutated)}
	d.Mutations = append(d.Mutations, r.Mutations...)
	for _, f := range d.Findings {
		if !f.Accounted {
			d.Unaccounted++
		}
	}
	for _, la := range v.Alignments {
		d.Lanes = append(d.Lanes, LaneDiagnosis{Lane: la.Lane, Optimal: la.Optimal, Ambiguous: la.Ambiguous})
	}
	return d
}

// NeedsDiagnosis says whether a result is one the diagnostics record: its
// alignment is ambiguous, a finding is unaccounted, or a mutation not
// undetectable by design is not detected, classified and located.
func NeedsDiagnosis(r Result) bool {
	if r.Ambiguous || r.Unaccounted != 0 {
		return true
	}
	for _, m := range r.Mutations {
		if !m.UndetectableByDesign && (!m.Detected || !m.Classified || !m.Located) {
			return true
		}
	}
	return false
}

// Tally accumulates results into the rates an evaluation reports.
type Tally struct {
	Runs      int
	Mutations int
	// Undetectable counts mutations scored UndetectableByDesign (E-5). They
	// are left out of Detected, Classified and Located, and the rates are over
	// the remaining, detectable, mutations.
	Undetectable int
	// UndetectableFound counts those among them a finding was about anyway;
	// the criterion says none should be, so a non-zero count questions it.
	UndetectableFound int
	Detected          int
	Classified        int
	Located           int
	Ambiguous         int // runs whose alignment was ambiguous
	Unaccounted       int // findings no mutation explains, summed over runs
	Inconclusive      int
	// Distinct counts different mutations among those added. Seeds repeat
	// mutations when a trajectory admits few of them (seven single omissions
	// of a seven-claim trajectory), so a rate over a hundred seeds is a rate
	// over this many cases, and has to be reported with it.
	Distinct int

	seen map[string]bool
}

// Add folds one result in.
func (t *Tally) Add(r Result) {
	t.Runs++
	if r.Ambiguous {
		t.Ambiguous++
	}
	if r.Outcome == verification.OutcomeInconclusive {
		t.Inconclusive++
	}
	t.Unaccounted += r.Unaccounted
	if t.seen == nil {
		t.seen = map[string]bool{}
	}
	for _, m := range r.Mutations {
		key := fmt.Sprintf("%s|%d|%s|%s", m.Mutation.Kind, m.Mutation.OriginalIndex, m.Mutation.Field, m.Mutation.New)
		if m.Mutation.After != nil {
			key += "|" + m.Mutation.After.Target
		}
		if !t.seen[key] {
			t.seen[key] = true
			t.Distinct++
		}
		t.Mutations++
		if m.UndetectableByDesign {
			t.Undetectable++
			if m.Detected {
				t.UndetectableFound++
			}
			continue
		}
		if m.Detected {
			t.Detected++
		}
		if m.Classified {
			t.Classified++
		}
		if m.Located {
			t.Located++
		}
	}
}

// Detectable is the number of mutations not undetectable by design.
func (t Tally) Detectable() int { return t.Mutations - t.Undetectable }

// Rate returns n over the number of detectable mutations (E-5), or zero when
// there are none.
func (t Tally) Rate(n int) float64 {
	if t.Detectable() == 0 {
		return 0
	}
	return float64(n) / float64(t.Detectable())
}
