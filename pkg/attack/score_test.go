package attack

import (
	"testing"

	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// E-5: an omission is undetectable by design when, in the honest run, its
// claim paired with an event the design explains: a V-36 shared read, or a
// level-0 event a baseline rule matches. A command's exec never qualifies, and
// a pair whose event no rule matches does not either.
func TestOmissionsUndetectableByDesignAreJudgedOnTheHonestRun(t *testing.T) {
	read := models.TrajectoryEntry{Timestamp: at(1), ActionType: models.FileOpen, Target: "/tmp/task.output", Tool: "Read"}
	write := models.TrajectoryEntry{Timestamp: at(2), ActionType: models.FileWrite, Target: "/home/u/.claude.json", Tool: "Write"}
	cmd := models.TrajectoryEntry{Timestamp: at(3), ActionType: models.ProcessExec, Target: "ls", Tool: "Bash"}
	plain := models.TrajectoryEntry{Timestamp: at(4), ActionType: models.FileOpen, Target: "/w/a.txt", Tool: "Read"}
	ev := func(e models.TrajectoryEntry) models.GroundTruthEvent {
		return models.GroundTruthEvent{Timestamp: e.Timestamp, ActionType: e.ActionType, Target: e.Target}
	}
	pair := func(e models.TrajectoryEntry) verification.MatchedPair {
		return verification.MatchedPair{Entry: e, Event: ev(e)}
	}
	honest := verification.Verdict{
		Corroborated:              []verification.MatchedPair{pair(read), pair(write), pair(cmd), pair(plain)},
		CorroboratedHarnessShared: []verification.MatchedPair{pair(read)},
	}
	rule := func(e models.GroundTruthEvent) bool { return e.Target != plain.Target }
	omit := func(e models.TrajectoryEntry) Result {
		e2 := e
		return Result{Kind: Omission, Mutations: []MutationResult{{Mutation: Mutation{Kind: Omission, Before: &e2}}}}
	}
	for _, tc := range []struct {
		name string
		e    models.TrajectoryEntry
		rule verification.Baseline
		want bool
	}{
		{"a V-36 shared read", read, rule, true},
		{"a V-36 shared read, no baseline given", read, nil, true},
		{"a level-0 write a rule matches", write, rule, true},
		{"a level-0 write, no baseline given", write, nil, false},
		{"a command a rule matches", cmd, rule, false},
		{"a read no rule matches", plain, rule, false},
		{"a claim the honest run did not corroborate", models.TrajectoryEntry{Timestamp: at(9), ActionType: models.FileOpen, Target: "/x"}, rule, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := MarkUndetectableByDesign(omit(tc.e), honest, tc.rule)
			if got := r.Mutations[0].UndetectableByDesign; got != tc.want {
				t.Errorf("undetectable by design = %v, want %v", got, tc.want)
			}
		})
	}
	// Only omissions are judged.
	f := read
	r := MarkUndetectableByDesign(Result{Kind: Fabrication, Mutations: []MutationResult{{Mutation: Mutation{Kind: Fabrication, After: &f}}}}, honest, rule)
	if r.Mutations[0].UndetectableByDesign {
		t.Error("a fabrication was marked undetectable by design")
	}
	// The input result is not modified.
	in := omit(read)
	_ = MarkUndetectableByDesign(in, honest, rule)
	if in.Mutations[0].UndetectableByDesign {
		t.Error("the input result was modified")
	}
}

// E-5: rates are over the detectable mutations, and the undetectable by
// design are counted apart, with those a finding was about anyway.
func TestTallyRatesAreOverDetectableMutations(t *testing.T) {
	var tl Tally
	tl.Add(Result{Mutations: []MutationResult{
		{Mutation: Mutation{Kind: Omission, OriginalIndex: 0}, Detected: true, Classified: true, Located: true},
		{Mutation: Mutation{Kind: Omission, OriginalIndex: 1}, Detected: true, Classified: true},
		{Mutation: Mutation{Kind: Omission, OriginalIndex: 2}, UndetectableByDesign: true},
		{Mutation: Mutation{Kind: Omission, OriginalIndex: 3}, UndetectableByDesign: true, Detected: true},
	}})
	if tl.Mutations != 4 || tl.Undetectable != 2 || tl.UndetectableFound != 1 || tl.Detectable() != 2 || tl.Distinct != 4 {
		t.Fatalf("tally %+v", tl)
	}
	if tl.Rate(tl.Detected) != 1 || tl.Rate(tl.Located) != 0.5 {
		t.Errorf("detected %.3f located %.3f, want 1 and 0.5", tl.Rate(tl.Detected), tl.Rate(tl.Located))
	}
	var none Tally
	none.Add(Result{Mutations: []MutationResult{{Mutation: Mutation{Kind: Omission}, UndetectableByDesign: true}}})
	if none.Rate(none.Detected) != 0 {
		t.Error("a tally with no detectable mutation has a non-zero rate")
	}
}

// The diagnostics name each finding with its claim's position in the mutated
// trajectory, mark which a mutation explains, and carry each lane's Optimal.
func TestDiagnoseNamesFindingsAndLanes(t *testing.T) {
	mutated := models.Trajectory{
		{Timestamp: at(0), ActionType: models.FileOpen, Target: "/w/a", Tool: "Read"},
		{Timestamp: at(5), ActionType: models.FileOpen, Target: "/w/fake", Tool: "Read"},
		{Timestamp: at(9), ActionType: models.FileOpen, Target: "/w/b", Tool: "Read"},
	}
	fab := mutated[1]
	rec := Record{Kind: Fabrication, Seed: 4, Mutations: []Mutation{{Kind: Fabrication, OriginalIndex: -1, Index: 1, After: &fab}}}
	// The fabricated claim took the event of /w/b, which is then read as a
	// mismatch, and /w/b's own claim is unwitnessed: detected, not located.
	v := verification.Verdict{
		Outcome:     verification.OutcomeNotFaithful,
		Ambiguous:   true,
		Mismatched:  []verification.MatchedPair{{Entry: fab, Event: models.GroundTruthEvent{ActionType: models.FileOpen, Target: "/w/b"}, Diffs: []string{"target"}}},
		Unwitnessed: []models.TrajectoryEntry{mutated[2]},
		Alignments:  []verification.LaneAlignment{{Lane: verification.LaneFS, Optimal: 2, Ambiguous: true}},
	}
	res := Score(rec, v)
	if !NeedsDiagnosis(res) {
		t.Fatal("an ambiguous, mislocated result needs no diagnosis")
	}
	d := Diagnose(rec, res, v, mutated)
	if d.Seed != 4 || d.Unaccounted != 1 || len(d.Findings) != 2 || len(d.Lanes) != 1 || d.Lanes[0].Optimal != 2 {
		t.Fatalf("diagnosis %+v", d)
	}
	if f := d.Findings[0]; f.Kind != "unwitnessed" || f.ClaimIndex != 2 || f.Accounted {
		t.Errorf("first finding %+v", f)
	}
	if f := d.Findings[1]; f.Kind != "mismatched" || f.ClaimIndex != 1 || !f.Accounted || f.Event.Target != "/w/b" {
		t.Errorf("second finding %+v", f)
	}
	if m := d.Mutations[0]; !m.Detected || m.Located {
		t.Errorf("mutation %+v", m)
	}
	if res.Unaccounted != d.Unaccounted {
		t.Errorf("Score counts %d unaccounted, the diagnosis %d", res.Unaccounted, d.Unaccounted)
	}
	clean := Result{Mutations: []MutationResult{{Detected: true, Classified: true, Located: true}, {UndetectableByDesign: true}}}
	if NeedsDiagnosis(clean) {
		t.Error("a clean result needs a diagnosis")
	}
}

// V-109: a fabrication or a substitution whose finding the verdict shows on
// an interchangeable claim is located when the finding's set holds the
// mutated claim, and the set's size is recorded and tallied.
func TestLocatedAgainstTheCandidateSet(t *testing.T) {
	ls := func(sec int, block string) models.TrajectoryEntry {
		return models.TrajectoryEntry{Timestamp: at(sec), ActionType: models.ProcessExec, Target: "ls", Tool: "Bash", BlockID: block}
	}
	event := func(sec int, target string) models.GroundTruthEvent {
		return models.GroundTruthEvent{Timestamp: at(sec), ActionType: models.ProcessExec, Target: target}
	}
	verdictOf := func(c models.Trajectory, o models.GroundTruth) verification.Verdict {
		as, err := verification.Align(c, o, verification.Options{})
		if err != nil {
			t.Fatal(err)
		}
		v := verification.Verdict{Alignments: as}
		for _, la := range as {
			for _, e := range la.Edits {
				switch e.Kind {
				case verification.EditInsertion:
					v.Unwitnessed = append(v.Unwitnessed, *e.Claim)
				case verification.EditSubstitution:
					v.Mismatched = append(v.Mismatched, verification.MatchedPair{Entry: *e.Claim, Event: *e.Event, Diffs: e.Diffs})
				}
			}
		}
		return v
	}

	// Two equal claims, one observed: whichever was fabricated, the
	// unwitnessed finding names both.
	c := models.Trajectory{ls(1, ""), ls(2, "")}
	v := verdictOf(c, models.GroundTruth{event(1, "ls")})
	var tally Tally
	for k := range c {
		f := c[k]
		rec := Record{Kind: Fabrication, Mutations: []Mutation{{Kind: Fabrication, OriginalIndex: -1, Index: k, After: &f}}}
		r := Score(rec, v)
		m := r.Mutations[0]
		if !m.Detected || !m.Classified || !m.Located || m.LocatedInSet != 2 || r.Unaccounted != 0 {
			t.Errorf("fabricated claim %d: %+v, unaccounted %d", k, m, r.Unaccounted)
		}
		if d := Diagnose(rec, r, v, c); len(d.Findings) != 1 || len(d.Findings[0].Candidates) != 2 {
			t.Errorf("fabricated claim %d: diagnosis findings %+v", k, d.Findings)
		}
		tally.Add(r)
	}
	if tally.SetSizesString() != "2:2" {
		t.Errorf("set sizes %s, want 2:2", tally.SetSizesString())
	}

	// A block of two equal claims, one of them substituted from "date": the
	// mismatched pair names both members.
	c = models.Trajectory{ls(1, "m"), ls(2, "m")}
	v = verdictOf(c, models.GroundTruth{event(1, "date"), event(2, "ls")})
	for k := range c {
		before := c[k]
		before.Target = "date"
		after := c[k]
		rec := Record{Kind: Substitution, Mutations: []Mutation{{Kind: Substitution, OriginalIndex: k, Index: k, Field: FieldTarget, Old: "date", New: "ls", Before: &before, After: &after}}}
		m := Score(rec, v).Mutations[0]
		if !m.Detected || !m.Classified || !m.Located || m.LocatedInSet != 2 {
			t.Errorf("substituted claim %d: %+v", k, m)
		}
	}

	// The order decides: "ls", "pwd", "ls" against "ls", "pwd". Only the last
	// claim can be unwitnessed, so a fabricated first claim is not located
	// there.
	c = models.Trajectory{ls(1, ""), {Timestamp: at(2), ActionType: models.ProcessExec, Target: "pwd", Tool: "Bash"}, ls(3, "")}
	v = verdictOf(c, models.GroundTruth{event(1, "ls"), event(2, "pwd")})
	first := c[0]
	m := Score(Record{Kind: Fabrication, Mutations: []Mutation{{Kind: Fabrication, OriginalIndex: -1, Index: 0, After: &first}}}, v).Mutations[0]
	if m.Located || m.LocatedInSet != 0 {
		t.Errorf("a fabrication the order excludes was located: %+v", m)
	}
	last := c[2]
	m = Score(Record{Kind: Fabrication, Mutations: []Mutation{{Kind: Fabrication, OriginalIndex: -1, Index: 2, After: &last}}}, v).Mutations[0]
	if !m.Located || m.LocatedInSet != 0 {
		t.Errorf("the fabrication the finding names alone: %+v", m)
	}
}

// E-12: a widened command claim is detected, classified and located by a
// lifetime finding on it that widening can cause (V-110), detected only by
// one it cannot; a lifetime finding on another claim is unaccounted. What A4
// must not do is still checked: the outcome may turn NOT FAITHFUL only
// through more lifetime findings, and no other finding may disappear.
func TestWideningIsScoredThroughLifetimeFindings(t *testing.T) {
	end := at(9)
	widened := models.TrajectoryEntry{Timestamp: at(0), End: &end, ActionType: models.ProcessExec, Target: "make", Tool: "Bash"}
	other := models.TrajectoryEntry{Timestamp: at(10), ActionType: models.ProcessExec, Target: "ls", Tool: "Bash"}
	rec := Record{Kind: IntervalWidening, Mutations: []Mutation{{Kind: IntervalWidening, Index: 0, After: &widened}}}
	verdict := func(fs ...verification.LifetimeFinding) verification.Verdict {
		return verification.Verdict{Outcome: verification.OutcomeNotFaithful, Lifetimes: verification.LifetimeCheck{Findings: fs}}
	}
	for _, c := range []struct {
		name                         string
		finding                      verification.LifetimeFinding
		detected, located, accounted bool
	}{
		{"starts early", verification.LifetimeFinding{Entry: widened, Kind: verification.LifetimeStartsEarly}, true, true, true},
		{"ends late", verification.LifetimeFinding{Entry: widened, Kind: verification.LifetimeEndsLate}, true, true, true},
		{"ran longer", verification.LifetimeFinding{Entry: widened, Kind: verification.LifetimeRanLonger}, true, false, true},
		{"another claim", verification.LifetimeFinding{Entry: other, Kind: verification.LifetimeStartsEarly}, false, false, false},
	} {
		res := Score(rec, verdict(c.finding))
		m := res.Mutations[0]
		if m.Detected != c.detected || m.Classified != c.located || m.Located != c.located || (res.Unaccounted == 0) != c.accounted {
			t.Errorf("%s: %+v, %d unaccounted", c.name, m, res.Unaccounted)
		}
		if d := Diagnose(rec, res, verdict(c.finding), models.Trajectory{widened, other}); len(d.Findings) != 1 || d.Findings[0].Kind != "lifetime" || d.Findings[0].Diffs[0] != c.finding.Kind {
			t.Errorf("%s: diagnosis %+v", c.name, d.Findings)
		}
	}

	honest := verification.Verdict{Outcome: verification.OutcomeFaithful}
	if !SuppressedNothing(honest, verdict(verification.LifetimeFinding{Entry: widened, Kind: verification.LifetimeStartsEarly})) {
		t.Error("a lifetime finding on the widened claim read as a suppression")
	}
	if SuppressedNothing(honest, verification.Verdict{Outcome: verification.OutcomeNotFaithful, Unrecorded: []models.GroundTruthEvent{{}}}) {
		t.Error("an outcome changed by another finding read as nothing suppressed")
	}
	omitted := verification.Verdict{Outcome: verification.OutcomeNotFaithful, Unrecorded: []models.GroundTruthEvent{{}}}
	if SuppressedNothing(omitted, verdict(verification.LifetimeFinding{Entry: widened, Kind: verification.LifetimeStartsEarly})) {
		t.Error("an unrecorded event hidden behind a lifetime finding read as nothing suppressed")
	}
}
