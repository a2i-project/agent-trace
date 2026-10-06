package verification

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
)

func claim(typ models.ActionType, target string) models.TrajectoryEntry {
	return models.TrajectoryEntry{Timestamp: t0, ActionType: typ, Target: target}
}

func obs(typ models.ActionType, target string) models.GroundTruthEvent {
	return models.GroundTruthEvent{Timestamp: t0, ActionType: typ, Target: target}
}

func laneOf(t *testing.T, as []LaneAlignment, l Lane) LaneAlignment {
	t.Helper()
	for _, a := range as {
		if a.Lane == l {
			return a
		}
	}
	t.Fatalf("no alignment for lane %s in %v", l, as)
	return LaneAlignment{}
}

func kinds(a LaneAlignment) []EditKind {
	var out []EditKind
	for _, e := range a.Edits {
		out = append(out, e.Kind)
	}
	return out
}

func mustAlign(t *testing.T, c models.Trajectory, o models.GroundTruth) []LaneAlignment {
	t.Helper()
	as, err := Align(c, o, Options{})
	if err != nil {
		t.Fatalf("Align: %v", err)
	}
	return as
}

func TestAlign_IdenticalSequencesMatchEverywhere(t *testing.T) {
	c := models.Trajectory{claim(models.ProcessExec, "/bin/a"), claim(models.ProcessExec, "/bin/b")}
	o := models.GroundTruth{obs(models.ProcessExec, "/bin/a"), obs(models.ProcessExec, "/bin/b")}
	a := laneOf(t, mustAlign(t, c, o), LaneProc)
	if a.Ambiguous || len(a.Edits) != 2 || a.Edits[0].Kind != EditMatch || a.Edits[1].Kind != EditMatch {
		t.Errorf("alignment = %+v", a)
	}
}

// The three edit operations are the three attacks (08 V5). Each is recovered
// from a deliberately mutated sequence at a known position.
func TestAlign_ThreeEditOperations(t *testing.T) {
	base := []string{"/bin/a", "/bin/b", "/bin/c"}
	events := func(targets ...string) models.GroundTruth {
		var g models.GroundTruth
		for _, x := range targets {
			g = append(g, obs(models.ProcessExec, x))
		}
		return g
	}
	claims := func(targets ...string) models.Trajectory {
		var tr models.Trajectory
		for _, x := range targets {
			tr = append(tr, claim(models.ProcessExec, x))
		}
		return tr
	}
	tests := []struct {
		name     string
		claims   models.Trajectory
		observed models.GroundTruth
		want     []EditKind
		pos      int // index in Edits of the finding
	}{
		{"fabrication: a claim with no action (A2)", claims("/bin/a", "/bin/FAKE", "/bin/b", "/bin/c"), events(base...),
			[]EditKind{EditMatch, EditInsertion, EditMatch, EditMatch}, 1},
		{"omission: an action with no claim (A1)", claims("/bin/a", "/bin/c"), events(base...),
			[]EditKind{EditMatch, EditDeletion, EditMatch}, 1},
		{"substitution: a different action at the position (A3)", claims("/bin/a", "/bin/EVIL", "/bin/c"), events(base...),
			[]EditKind{EditMatch, EditSubstitution, EditMatch}, 1},
	}
	for _, tc := range tests {
		a := laneOf(t, mustAlign(t, tc.claims, tc.observed), LaneProc)
		got := kinds(a)
		if fmt.Sprint(got) != fmt.Sprint(tc.want) {
			t.Errorf("%s: edits = %v, want %v", tc.name, got, tc.want)
			continue
		}
		if a.Ambiguous {
			t.Errorf("%s: unexpectedly ambiguous", tc.name)
		}
		if tc.want[tc.pos] == EditSubstitution {
			e := a.Edits[tc.pos]
			if e.Claim.Target != "/bin/EVIL" || e.Event.Target != "/bin/b" {
				t.Errorf("%s: substitution carries claim %q and event %q, want both sides attached", tc.name, e.Claim.Target, e.Event.Target)
			}
		}
	}
}

// The case the old engine cannot report (08 section 1.1): the agent claims
// cat README and the ground truth shows cat /etc/passwd. One substitution at a
// known position, not one fabrication plus one omission.
func TestAlign_TargetSubstitutionIsOneEdit(t *testing.T) {
	for _, typ := range []models.ActionType{models.ProcessExec, models.FileOpen, models.NetConnect} {
		c := models.Trajectory{claim(typ, "README")}
		o := models.GroundTruth{obs(typ, "/etc/passwd")}
		as := mustAlign(t, c, o)
		a := laneOf(t, as, LaneOf(typ))
		if len(a.Edits) != 1 || a.Edits[0].Kind != EditSubstitution {
			t.Errorf("%s: edits = %v, want a single substitution", typ, kinds(a))
			continue
		}
		if d := a.Edits[0].Diffs; len(d) != 1 || d[0] != DiffTarget {
			t.Errorf("%s: diffs = %v, want [target]", typ, d)
		}
	}
}

func TestAlign_ContentSubstitution(t *testing.T) {
	zero, one := int32(0), int32(1)
	c := models.Trajectory{{Timestamp: t0, ActionType: models.ProcessExit, Target: "/bin/a", ExitCode: &zero}}
	o := models.GroundTruth{{Timestamp: t0, ActionType: models.ProcessExit, Target: "/bin/a", ExitCode: &one}}
	a := laneOf(t, mustAlign(t, c, o), LaneProc)
	if len(a.Edits) != 1 || a.Edits[0].Kind != EditSubstitution || a.Edits[0].Diffs[0] != DiffExitCode {
		t.Errorf("edits = %+v, want one substitution on exit_code", a.Edits)
	}
}

// A claimed read against an observed write at the same position is a
// substitution that crosses action types: cheaper than a fabrication plus an
// omission, dearer than a same-type one, and labelled as a type difference.
func TestAlign_CrossTypeSubstitutionWithinALane(t *testing.T) {
	c := models.Trajectory{claim(models.FileRead, "/w/a")}
	o := models.GroundTruth{obs(models.FileWrite, "/w/a")}
	a := laneOf(t, mustAlign(t, c, o), LaneFS)
	if len(a.Edits) != 1 || a.Edits[0].Kind != EditSubstitution || a.Edits[0].Diffs[0] != DiffType {
		t.Errorf("edits = %+v, want one substitution labelled action_type", a.Edits)
	}
}

// Pairing never crosses lanes: a process claim cannot be substituted by a file
// event. That is a fabrication and an omission.
func TestAlign_LanesNeverPairAcrossProbes(t *testing.T) {
	c := models.Trajectory{claim(models.ProcessExec, "/bin/a")}
	o := models.GroundTruth{obs(models.FileOpen, "/bin/a")}
	as := mustAlign(t, c, o)
	if k := kinds(laneOf(t, as, LaneProc)); fmt.Sprint(k) != fmt.Sprint([]EditKind{EditInsertion}) {
		t.Errorf("proc lane = %v, want one insertion", k)
	}
	if k := kinds(laneOf(t, as, LaneFS)); fmt.Sprint(k) != fmt.Sprint([]EditKind{EditDeletion}) {
		t.Errorf("fs lane = %v, want one deletion", k)
	}
}

// Probe clocks disagree, so the order of a file event against a process event
// is not trusted: the same pair in opposite orders must align identically.
func TestAlign_CrossLaneOrderIsNotChecked(t *testing.T) {
	c := models.Trajectory{claim(models.FileOpen, "/w/a"), claim(models.ProcessExec, "/bin/x")}
	o := models.GroundTruth{obs(models.ProcessExec, "/bin/x"), obs(models.FileOpen, "/w/a")}
	for _, a := range mustAlign(t, c, o) {
		if len(a.Edits) != 1 || a.Edits[0].Kind != EditMatch {
			t.Errorf("lane %s = %v, want a clean match", a.Lane, kinds(a))
		}
	}
}

// Two equally good alignments must be reported as ambiguous, not resolved
// silently by iteration order (08 V5).
func TestAlign_NonUniqueMinimumIsAmbiguous(t *testing.T) {
	c := models.Trajectory{claim(models.ProcessExec, "/bin/cat x"), claim(models.ProcessExec, "/bin/cat x")}
	o := models.GroundTruth{obs(models.ProcessExec, "/bin/cat x")}
	a := laneOf(t, mustAlign(t, c, o), LaneProc)
	if !a.Ambiguous || a.Optimal != 2 {
		t.Errorf("Ambiguous = %v, Optimal = %d, want true and 2", a.Ambiguous, a.Optimal)
	}
	var ins int
	for _, e := range a.Edits {
		if e.Kind == EditInsertion {
			ins++
		}
	}
	if ins != 1 {
		t.Errorf("insertions = %d, want exactly one (which of the two is fabricated is the ambiguity)", ins)
	}

	// With distinct commands the same shape is unambiguous.
	c[1].Target = "/bin/cat y"
	if a := laneOf(t, mustAlign(t, c, o), LaneProc); a.Ambiguous {
		t.Errorf("distinct claims reported ambiguous: %+v", a)
	}
}

// Time orders and never pairs: a constant offset, or any latency, between the
// trajectory's clock and the kernel's changes nothing (08 V6).
func TestAlign_ClockOffsetDoesNotChangeThePairing(t *testing.T) {
	var c models.Trajectory
	var o models.GroundTruth
	for i := 0; i < 3; i++ {
		c = append(c, models.TrajectoryEntry{Timestamp: t0.Add(time.Duration(i) * time.Second), ActionType: models.ProcessExec, Target: "/bin/ls"})
		o = append(o, models.GroundTruthEvent{Timestamp: t0.Add(time.Hour + time.Duration(i)*time.Minute), ActionType: models.ProcessExec, Target: "/bin/ls"})
	}
	a := laneOf(t, mustAlign(t, c, o), LaneProc)
	for i, e := range a.Edits {
		if e.Kind != EditMatch || e.ClaimIndex != i || e.EventIndex != i {
			t.Errorf("edit %d = %+v, want claim %d paired with event %d", i, e, i, i)
		}
	}
}

func TestAlign_IntervalIsAFindingNotAPairingCondition(t *testing.T) {
	end := t0.Add(10 * time.Second)
	c := models.Trajectory{{Timestamp: t0, End: &end, ActionType: models.ProcessExec, Target: "/bin/a"}}
	inside := models.GroundTruth{{Timestamp: t0.Add(5 * time.Second), ActionType: models.ProcessExec, Target: "/bin/a"}}
	late := models.GroundTruth{{Timestamp: t0.Add(11 * time.Second), ActionType: models.ProcessExec, Target: "/bin/a"}}
	early := models.GroundTruth{{Timestamp: t0.Add(-time.Second), ActionType: models.ProcessExec, Target: "/bin/a"}}

	if e := laneOf(t, mustAlign(t, c, inside), LaneProc).Edits[0]; e.OutsideInterval {
		t.Error("an event inside the interval was flagged")
	}
	for name, g := range map[string]models.GroundTruth{"late": late, "early": early} {
		e := laneOf(t, mustAlign(t, c, g), LaneProc).Edits[0]
		if e.Kind != EditMatch || !e.OutsideInterval {
			t.Errorf("%s: edit = %+v, want a match flagged as outside the interval", name, e)
		}
	}
	as, _ := Align(c, late, Options{IntervalSlack: 2 * time.Second})
	if laneOf(t, as, LaneProc).Edits[0].OutsideInterval {
		t.Error("slack did not widen the interval")
	}
	// A point claim has no interval to violate.
	point := models.Trajectory{claim(models.ProcessExec, "/bin/a")}
	if laneOf(t, mustAlign(t, point, late), LaneProc).Edits[0].OutsideInterval {
		t.Error("a claim without an end was flagged")
	}
}

func TestAlign_OneSidedLanes(t *testing.T) {
	c := models.Trajectory{claim(models.ProcessExec, "/bin/a"), claim(models.ProcessExec, "/bin/b")}
	a := laneOf(t, mustAlign(t, c, nil), LaneProc)
	if fmt.Sprint(kinds(a)) != fmt.Sprint([]EditKind{EditInsertion, EditInsertion}) {
		t.Errorf("claims only: %v", kinds(a))
	}
	o := models.GroundTruth{obs(models.FileOpen, "/w/a")}
	if k := kinds(laneOf(t, mustAlign(t, nil, o), LaneFS)); fmt.Sprint(k) != fmt.Sprint([]EditKind{EditDeletion}) {
		t.Errorf("events only: %v", k)
	}
	if as := mustAlign(t, nil, nil); len(as) != 0 {
		t.Errorf("empty input produced %v", as)
	}
}

func TestAlign_RefusesALaneTooLargeToAlign(t *testing.T) {
	var c models.Trajectory
	var o models.GroundTruth
	for i := 0; i < 5000; i++ {
		c = append(c, claim(models.FileOpen, "/w/a"))
		o = append(o, obs(models.FileOpen, "/w/a"))
	}
	if _, err := Align(c, o, Options{}); err != ErrTooLarge {
		t.Errorf("err = %v, want ErrTooLarge", err)
	}
}

// bruteForce returns the minimum cost and the number of alignments that reach
// it, by exhaustive recursion. It shares no code with alignLane's DP, so it
// checks the cost model, the minimum and the ambiguity count independently.
func bruteForce(c models.Trajectory, o models.GroundTruth) (best int, count int) {
	var rec func(i, j, cost int)
	best = 1 << 30
	rec = func(i, j, cost int) {
		if cost > best {
			return
		}
		if i == len(c) && j == len(o) {
			switch {
			case cost < best:
				best, count = cost, 1
			case cost == best:
				count++
			}
			return
		}
		if i < len(c) && j < len(o) {
			pc, _ := pairCost(c[i], o[j])
			rec(i+1, j+1, cost+pc)
		}
		if i < len(c) {
			rec(i+1, j, cost+costIndel)
		}
		if j < len(o) {
			rec(i, j+1, cost+costIndel)
		}
	}
	rec(0, 0, 0)
	return best, count
}

func TestAlign_AgreesWithBruteForceOnRandomSequences(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	targets := []string{"a", "b", "c"}
	types := []models.ActionType{models.FileOpen, models.FileWrite}
	pick := func() (models.ActionType, string) {
		return types[rng.Intn(len(types))], targets[rng.Intn(len(targets))]
	}
	for trial := 0; trial < 400; trial++ {
		var c models.Trajectory
		var o models.GroundTruth
		for i, n := 0, rng.Intn(6); i < n; i++ {
			ty, tg := pick()
			c = append(c, claim(ty, tg))
		}
		for i, n := 0, rng.Intn(6); i < n; i++ {
			ty, tg := pick()
			o = append(o, obs(ty, tg))
		}
		wantCost, wantCount := bruteForce(c, o)
		as := mustAlign(t, c, o)
		if len(c) == 0 && len(o) == 0 {
			continue
		}
		a := laneOf(t, as, LaneFS)

		// Every claim and every event appears exactly once, in order.
		ci, ei := 0, 0
		cost := 0
		for _, e := range a.Edits {
			if e.ClaimIndex >= 0 {
				if e.ClaimIndex != ci {
					t.Fatalf("trial %d: claims out of order or skipped: %+v", trial, a.Edits)
				}
				ci++
			}
			if e.EventIndex >= 0 {
				if e.EventIndex != ei {
					t.Fatalf("trial %d: events out of order or skipped: %+v", trial, a.Edits)
				}
				ei++
			}
			switch e.Kind {
			case EditInsertion, EditDeletion:
				cost += costIndel
			default:
				pc, _ := pairCost(*e.Claim, *e.Event)
				cost += pc
			}
		}
		if ci != len(c) || ei != len(o) {
			t.Fatalf("trial %d: consumed %d/%d claims and %d/%d events", trial, ci, len(c), ei, len(o))
		}
		if cost != wantCost {
			t.Fatalf("trial %d: alignment costs %d, brute force minimum is %d\nclaims %v\nevents %v", trial, cost, wantCost, c, o)
		}
		if int(a.Optimal) != wantCount {
			t.Fatalf("trial %d: %d optimal alignments, brute force finds %d\nclaims %v\nevents %v", trial, a.Optimal, wantCount, c, o)
		}
	}
}
