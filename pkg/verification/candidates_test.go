package verification

import (
	"math/rand"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// bruteForceFindings enumerates every alignment the fences allow, as
// bruteForceBlocksWith does, and returns, over the minimum-cost ones, which
// claims some alignment leaves unpaired and which events some alignment
// pairs each claim with.
func bruteForceFindings(c models.Trajectory, o models.GroundTruth, opts Options) (unpaired map[int]bool, pairedWith map[[2]int]bool) {
	var runs [][]int
	for i := 0; i < len(c); {
		j := i + 1
		for c[i].BlockID != "" && j < len(c) && c[j].BlockID == c[i].BlockID {
			j++
		}
		var r []int
		for k := i; k < j; k++ {
			r = append(r, k)
		}
		runs = append(runs, r)
		i = j
	}
	var perms func(xs []int) [][]int
	perms = func(xs []int) [][]int {
		if len(xs) <= 1 {
			return [][]int{append([]int(nil), xs...)}
		}
		var out [][]int
		for i := range xs {
			rest := append(append([]int(nil), xs[:i]...), xs[i+1:]...)
			for _, p := range perms(rest) {
				out = append(out, append([]int{xs[i]}, p...))
			}
		}
		return out
	}
	orders := [][]int{nil}
	for _, r := range runs {
		var next [][]int
		for _, prefix := range orders {
			for _, p := range perms(r) {
				next = append(next, append(append([]int(nil), prefix...), p...))
			}
		}
		orders = next
	}
	best := 1 << 30
	unpaired, pairedWith = map[int]bool{}, map[[2]int]bool{}
	for _, order := range orders {
		var ins []int
		var pairs [][2]int
		var rec func(i, j, cost int)
		rec = func(i, j, cost int) {
			if cost > best {
				return
			}
			if i == len(order) && j == len(o) {
				if cost < best {
					best = cost
					unpaired, pairedWith = map[int]bool{}, map[[2]int]bool{}
				}
				for _, q := range ins {
					unpaired[q] = true
				}
				for _, p := range pairs {
					pairedWith[p] = true
				}
				return
			}
			if i < len(order) && j < len(o) {
				if pc, ok := pairCostOf(c[order[i]], o[j], opts.keptAt(j), opts); ok {
					pairs = append(pairs, [2]int{order[i], j})
					rec(i+1, j+1, cost+pc)
					pairs = pairs[:len(pairs)-1]
				}
			}
			if i < len(order) {
				ins = append(ins, order[i])
				rec(i+1, j, cost+insertCost(c[order[i]]))
				ins = ins[:len(ins)-1]
			}
			if j < len(o) {
				rec(i, j+1, cost+costIndel)
			}
		}
		rec(0, 0, 0)
	}
	return unpaired, pairedWith
}

// V-109 against an independent brute force: on random lanes with blocks,
// repeated claims and kept baseline events, each insertion and substitution
// names exactly the claims interchangeable with its own that some
// minimum-cost alignment leaves unpaired, or pairs with its event, and names
// nothing more when that is its own claim alone.
func TestAlign_CandidatesAgreeWithBruteForce(t *testing.T) {
	rng := rand.New(rand.NewSource(109))
	targets := []string{"a", "a", "b", "c"}
	types := []models.ActionType{models.FileOpen, models.FileWrite}
	blocks := []string{"", "", "m1", "m1", "m2", "m2"}
	sets, crossSegment := 0, 0
	for trial := 0; trial < 3000; trial++ {
		var c models.Trajectory
		for i, n := 0, 1+rng.Intn(6); i < n; i++ {
			c = append(c, models.TrajectoryEntry{Timestamp: t0.Add(time.Duration(i) * time.Second), ActionType: types[rng.Intn(2)], Target: targets[rng.Intn(len(targets))], BlockID: blocks[rng.Intn(len(blocks))]})
		}
		var o models.GroundTruth
		for i, n := 0, rng.Intn(6); i < n; i++ {
			o = append(o, models.GroundTruthEvent{Timestamp: t0.Add(time.Duration(i) * time.Second), ActionType: types[rng.Intn(2)], Target: targets[rng.Intn(len(targets))]})
		}
		opts := Options{}
		if rng.Intn(3) == 0 {
			opts.kept = make([]bool, len(o))
			for j := range o {
				opts.kept[j] = rng.Intn(3) == 0
			}
		}
		unpaired, pairedWith := bruteForceFindings(c, o, opts)
		as, err := Align(c, o, opts)
		if err != nil {
			t.Fatal(err)
		}
		a := laneOf(t, as, LaneFS)
		runOf := runsOf(c)
		for _, e := range a.Edits {
			if e.Kind != EditInsertion && e.Kind != EditSubstitution {
				if e.Candidates != nil {
					t.Fatalf("trial %d: a %s names candidates", trial, e.Kind)
				}
				continue
			}
			var want []int
			for q := range c {
				if q != e.ClaimIndex && !interchangeable(*e.Claim, c[q]) {
					continue
				}
				if q == e.ClaimIndex || e.Kind == EditInsertion && unpaired[q] || e.Kind == EditSubstitution && pairedWith[[2]int{q, e.EventIndex}] {
					want = append(want, q)
				}
			}
			var got []int
			for _, p := range e.Candidates {
				for q := range c {
					if p == &c[q] {
						got = append(got, q)
					}
				}
			}
			if len(want) == 1 {
				want = nil
			}
			if len(got) != len(want) {
				t.Fatalf("trial %d: %s of claim %d names %v, brute force %v\nclaims %+v\nevents %+v\nkept %v", trial, e.Kind, e.ClaimIndex, got, want, c, o, opts.kept)
			}
			for i := range got {
				if got[i] != want[i] {
					t.Fatalf("trial %d: %s of claim %d names %v, brute force %v", trial, e.Kind, e.ClaimIndex, got, want)
				}
			}
			if len(want) > 1 {
				sets++
				for _, q := range want {
					if runOf[q] != runOf[e.ClaimIndex] {
						crossSegment++
						break
					}
				}
			}
		}
	}
	t.Logf("%d findings name a set, %d of them across segments", sets, crossSegment)
	if sets < 100 || crossSegment < 50 {
		t.Errorf("the random cases gave %d sets, %d across segments, too few to mean anything", sets, crossSegment)
	}
}

// The case behind V-109: two equal claims, one observed. Each minimum-cost
// alignment leaves a different one unwitnessed, so the finding names both.
// Where the order decides which one is unpaired, the finding names it alone.
func TestAlign_AFindingOnOneOfEqualClaimsNamesThemAll(t *testing.T) {
	c := concat(execs("ls", "ls"))
	a := laneOf(t, mustAlign(t, c, execEvents("ls")), LaneProc)
	if !a.Ambiguous || countKinds(a)[EditInsertion] != 1 {
		t.Fatalf("edits %v, Optimal %d", kinds(a), a.Optimal)
	}
	for _, e := range a.Edits {
		if e.Kind == EditInsertion && (len(e.Candidates) != 2 || e.Candidates[0] != &c[0] || e.Candidates[1] != &c[1]) {
			t.Errorf("the unwitnessed claim names %v, want both claims", e.Candidates)
		}
	}
	// "ls", "pwd", "ls" against "ls", "pwd": the second "ls" is the only
	// reading at minimum cost, so the finding names it alone.
	c = concat(execs("ls", "pwd", "ls"))
	a = laneOf(t, mustAlign(t, c, execEvents("ls", "pwd")), LaneProc)
	for _, e := range a.Edits {
		if e.Kind == EditInsertion && (e.ClaimIndex != 2 || e.Candidates != nil) {
			t.Errorf("insertion of claim %d names %v, want claim 2 alone", e.ClaimIndex, e.Candidates)
		}
	}
	// A substitution: two equal claims in sequence, two events, the second a
	// different command. Only the second claim can pair with it in order.
	c = concat(execs("ls", "ls"))
	a = laneOf(t, mustAlign(t, c, execEvents("ls", "date")), LaneProc)
	for _, e := range a.Edits {
		if e.Candidates != nil {
			t.Errorf("%s of claim %d names %v, want none", e.Kind, e.ClaimIndex, e.Candidates)
		}
	}
	// In one block the two may pair either way: the substitution names both,
	// though the count treats the exchange as one reading (V-32).
	c = inBlock("m", execs("ls", "ls")...)
	a = laneOf(t, mustAlign(t, c, execEvents("date", "ls")), LaneProc)
	if a.Ambiguous {
		t.Errorf("Optimal %d, want one reading", a.Optimal)
	}
	for _, e := range a.Edits {
		if e.Kind == EditSubstitution && len(e.Candidates) != 2 {
			t.Errorf("the substitution names %v, want both members", e.Candidates)
		}
	}
}

// A run without findings computes no candidates and runs the program no
// more than before: every edit is a match or a deletion.
func TestAlign_NoFindingNoCandidates(t *testing.T) {
	c := concat(execs("ls", "ls", "ls"))
	a := laneOf(t, mustAlign(t, c, execEvents("ls", "ls", "ls", "ls")), LaneProc)
	for _, e := range a.Edits {
		if e.Candidates != nil {
			t.Errorf("%s names %v", e.Kind, e.Candidates)
		}
	}
}

// Verify reports the sets: an unwitnessed claim among equal ones names them
// all, through Verdict.CandidateSets.
func TestVerify_AnUnwitnessedClaimAmongEqualOnesNamesThemAll(t *testing.T) {
	c := concat(execs("ls", "ls"))
	as := mustAlign(t, c, execEvents("ls"))
	v := Verdict{Alignments: as}
	sets := v.CandidateSets()
	if len(sets) != 1 || sets[0].Finding != "unwitnessed" || len(sets[0].Claims) != 2 || sets[0].Event != nil {
		t.Fatalf("sets %+v", sets)
	}
}
