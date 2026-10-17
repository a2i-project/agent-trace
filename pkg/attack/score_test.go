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
