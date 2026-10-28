package verification

import (
	"math/rand"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// V-55: a baseline event kept for a claim on its path (V-30) pairs only with
// a claim on its own target. A fabricated claim beside it is Unwitnessed and
// the event is explained by the baseline; a substituted claim pairs with the
// event it replaced; a claim on the event's path still pairs, and still
// disagrees on content.
func TestVerify_AKeptBaselineEventPairsOnlyWithAClaimOnItsTarget(t *testing.T) {
	const (
		out  = "/tmp/h/tasks/b1.output"
		a    = "/w/a"
		fake = "/w/fake"
	)
	base := func(e models.GroundTruthEvent) bool { return e.Target == out }
	verify := func(claims models.Trajectory, g ...models.GroundTruthEvent) Verdict {
		return Verify(Input{Claims: claims, Ground: g, RootPID: agentPID, Coverage: completeCov(), Baseline: base})
	}
	// The harness opens out at 1 and 2; the agent reads a at 3 and out at 5.
	ground := []models.GroundTruthEvent{agentEv(1, models.FileOpen, out), agentEv(2, models.FileOpen, out), agentEv(3, models.FileOpen, a), agentEv(5, models.FileOpen, out)}

	honest := verify(models.Trajectory{claimAt(3, models.FileOpen, a), claimAt(5, models.FileOpen, out)}, ground...)
	if honest.Findings() != 0 || honest.Ambiguous || len(honest.Corroborated) != 2 {
		t.Fatalf("honest: %d findings, ambiguous %v, %d corroborated", honest.Findings(), honest.Ambiguous, len(honest.Corroborated))
	}

	fab := verify(models.Trajectory{claimAt(2, models.FileOpen, fake), claimAt(3, models.FileOpen, a), claimAt(5, models.FileOpen, out)}, ground...)
	if len(fab.Unwitnessed) != 1 || fab.Unwitnessed[0].Target != fake || len(fab.Mismatched) != 0 || len(fab.Unrecorded) != 0 {
		t.Fatalf("fabrication: unwitnessed %v, mismatched %v, unrecorded %v", fab.Unwitnessed, fab.Mismatched, fab.Unrecorded)
	}
	if fab.Ambiguous {
		t.Fatalf("fabrication: an unpaired claim beside unpaired events is one pairing, got %+v", fab.Alignments)
	}

	sub := verify(models.Trajectory{claimAt(3, models.FileOpen, fake), claimAt(5, models.FileOpen, out)}, ground...)
	if len(sub.Mismatched) != 1 || sub.Mismatched[0].Event.Target != a || len(sub.Unwitnessed) != 0 || len(sub.Unrecorded) != 0 || sub.Ambiguous {
		t.Fatalf("substitution: mismatched %v, unwitnessed %v, unrecorded %v, ambiguous %v", sub.Mismatched, sub.Unwitnessed, sub.Unrecorded, sub.Ambiguous)
	}

	content := verify(models.Trajectory{claimAt(3, models.FileOpen, a), withClaimHash(claimAt(5, models.FileWrite, out), nil, sp("sha256:aa"))},
		agentEv(1, models.FileOpen, out), agentEv(3, models.FileOpen, a), withHash(agentEv(5, models.FileWrite, out), nil, sp("sha256:bb")))
	if len(content.Mismatched) != 1 || content.Mismatched[0].Event.Target != out {
		t.Fatalf("a claim on the kept event's path: mismatched %v", content.Mismatched)
	}
}

// V-55 against the brute force of V-32: with random kept events, the reading
// shown takes no refused pair, has the minimum cost and the fewest interval
// violations, and Optimal counts pairings, so an unpaired claim beside an
// unpaired kept event is one reading.
func TestAlign_KeptEventsAgreeWithBruteForce(t *testing.T) {
	rng := rand.New(rand.NewSource(55))
	targets := []string{"a", "b", "c"}
	types := []models.ActionType{models.FileOpen, models.FileWrite}
	blocks := []string{"", "m1", "m1", "m2"}
	sawRefused, sawUnpairedBesideKept := 0, 0
	for trial := 0; trial < 1500; trial++ {
		var c models.Trajectory
		for i, n := 0, 1+rng.Intn(5); i < n; i++ {
			e := models.TrajectoryEntry{Timestamp: t0.Add(time.Duration(rng.Intn(10)) * time.Second), ActionType: types[rng.Intn(2)], Target: targets[rng.Intn(3)], BlockID: blocks[rng.Intn(len(blocks))]}
			if rng.Intn(3) > 0 {
				end := e.Timestamp.Add(time.Duration(rng.Intn(4)) * time.Second)
				e.End = &end
			}
			c = append(c, e)
		}
		var o models.GroundTruth
		var kept []bool
		for i, n := 0, rng.Intn(6); i < n; i++ {
			o = append(o, models.GroundTruthEvent{Timestamp: t0.Add(time.Duration(rng.Intn(12)) * time.Second), ActionType: types[rng.Intn(2)], Target: targets[rng.Intn(3)]})
			kept = append(kept, rng.Intn(2) == 0)
		}
		opts := Options{kept: kept}
		wantCost, wantPairings, wantViol := bruteForceBlocksWith(c, o, opts)
		as, err := Align(c, o, opts)
		if err != nil {
			t.Fatal(err)
		}
		a := laneOf(t, as, LaneFS)
		cost, viol, deletionsOfKept, insertions := 0, 0, 0, 0
		var pairs [][2]int
		for _, e := range a.Edits {
			switch e.Kind {
			case EditInsertion:
				cost += insertCost(*e.Claim)
				insertions++
			case EditDeletion:
				cost += costIndel
				if kept[e.EventIndex] {
					deletionsOfKept++
				}
			default:
				pc, ok := pairCostOf(*e.Claim, *e.Event, kept[e.EventIndex], opts)
				if !ok {
					t.Fatalf("trial %d: a refused pair was taken: %+v", trial, e)
				}
				cost += pc
				if e.OutsideInterval {
					viol++
				}
				pairs = append(pairs, [2]int{e.ClaimIndex, e.EventIndex})
			}
		}
		for j := range o {
			for i := range c {
				if _, ok := pairCostOf(c[i], o[j], kept[j], opts); !ok {
					sawRefused++
				}
			}
		}
		if insertions > 0 && deletionsOfKept > 0 {
			sawUnpairedBesideKept++
		}
		if cost != wantCost || viol != wantViol {
			t.Fatalf("trial %d: reading costs (%d, %d), brute force (%d, %d)\nclaims %+v\nevents %+v kept %v", trial, cost, viol, wantCost, wantViol, c, o, kept)
		}
		if !wantPairings[pairingKey(classes(c, runsOf(c)), pairs)] {
			t.Fatalf("trial %d: the reading shown is not a minimum-cost pairing", trial)
		}
		if int(a.Optimal) != len(wantPairings) || a.Ambiguous != (len(wantPairings) > 1) {
			t.Fatalf("trial %d: Optimal = %d, brute force finds %d pairings\nclaims %+v\nevents %+v kept %v\nedits %+v", trial, a.Optimal, len(wantPairings), c, o, kept, a.Edits)
		}
	}
	if sawRefused == 0 || sawUnpairedBesideKept < 50 {
		t.Fatalf("the trials exercised too little: %d refused pairs, %d readings with an unpaired claim beside an unpaired kept event", sawRefused, sawUnpairedBesideKept)
	}
	t.Logf("%d readings with an unpaired claim beside an unpaired kept event", sawUnpairedBesideKept)
}
