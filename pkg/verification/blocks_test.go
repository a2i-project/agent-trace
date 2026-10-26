package verification

import (
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// inBlock gives each claim the block id.
func inBlock(id string, cs ...models.TrajectoryEntry) []models.TrajectoryEntry {
	for i := range cs {
		cs[i].BlockID = id
	}
	return cs
}

func execs(targets ...string) []models.TrajectoryEntry {
	var out []models.TrajectoryEntry
	for _, x := range targets {
		out = append(out, claim(models.ProcessExec, x))
	}
	return out
}

func execEvents(targets ...string) models.GroundTruth {
	var out models.GroundTruth
	for _, x := range targets {
		out = append(out, obs(models.ProcessExec, x))
	}
	return out
}

func concat(parts ...[]models.TrajectoryEntry) models.Trajectory {
	var out models.Trajectory
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// countKinds counts the edits of each kind.
func countKinds(a LaneAlignment) map[EditKind]int {
	out := map[EditKind]int{}
	for _, e := range a.Edits {
		out[e.Kind]++
	}
	return out
}

// V-32: the claims of one block match in any order. The shapes capture's case
// is the two-member block observed reversed; a three-member block is checked
// in every order its events can arrive.
func TestAlign_ABlockMatchesInAnyOrder(t *testing.T) {
	two := concat(execs("/bin/before"), inBlock("m1", execs("sleep 2; cat slow.txt", "cat fast.txt")...), execs("/bin/after"))
	a := laneOf(t, mustAlign(t, two, execEvents("/bin/before", "cat fast.txt", "sleep 2; cat slow.txt", "/bin/after")), LaneProc)
	if k := countKinds(a); k[EditMatch] != 4 || len(a.Edits) != 4 || a.Ambiguous || a.Optimal != 1 || len(a.Degradations) != 0 {
		t.Errorf("reversed pair: edits = %v, Optimal = %d, degradations = %v, want four matches and a unique reading", kinds(a), a.Optimal, a.Degradations)
	}

	three := inBlock("m2", execs("a", "b", "c")...)
	for _, order := range [][]string{{"a", "b", "c"}, {"b", "c", "a"}, {"c", "a", "b"}, {"c", "b", "a"}, {"a", "c", "b"}, {"b", "a", "c"}} {
		a := laneOf(t, mustAlign(t, three, execEvents(order...)), LaneProc)
		if k := countKinds(a); k[EditMatch] != 3 || len(a.Edits) != 3 || a.Ambiguous {
			t.Errorf("observed %v: edits = %v, ambiguous = %v, want three matches", order, kinds(a), a.Ambiguous)
			continue
		}
		// The edits follow the observed order, each claim with its own event.
		for i, e := range a.Edits {
			if e.Event.Target != order[i] || e.Claim.Target != order[i] {
				t.Errorf("observed %v: edit %d pairs %q with %q", order, i, e.Claim.Target, e.Event.Target)
			}
		}
	}
}

// Without a block id, or with each call in its own block, the order is still
// checked: the strict reading of the same events has findings.
func TestAlign_WithoutABlockTheOrderIsChecked(t *testing.T) {
	ev := execEvents("cat fast.txt", "sleep 2; cat slow.txt")
	for name, c := range map[string]models.Trajectory{
		"no block":       concat(execs("sleep 2; cat slow.txt", "cat fast.txt")),
		"two blocks":     concat(inBlock("m1", execs("sleep 2; cat slow.txt")...), inBlock("m2", execs("cat fast.txt")...)),
		"block and none": concat(inBlock("m1", execs("sleep 2; cat slow.txt")...), execs("cat fast.txt")),
	} {
		a := laneOf(t, mustAlign(t, c, ev), LaneProc)
		if countKinds(a)[EditMatch] == 2 {
			t.Errorf("%s: edits = %v, want the crossed order to be a finding", name, kinds(a))
		}
	}
}

// The fence: every claim of an earlier block precedes every claim of a later
// one. Members of two blocks observed swapped across the boundary are still
// findings, while each block alone may be reversed.
func TestAlign_TheFenceBetweenBlocksHolds(t *testing.T) {
	c := concat(inBlock("m1", execs("a", "b")...), inBlock("m2", execs("c", "d")...))
	ok := laneOf(t, mustAlign(t, c, execEvents("b", "a", "d", "c")), LaneProc)
	if countKinds(ok)[EditMatch] != 4 || ok.Ambiguous {
		t.Errorf("each block reversed: edits = %v, want four matches", kinds(ok))
	}
	for _, order := range [][]string{{"a", "c", "b", "d"}, {"c", "a", "b", "d"}, {"d", "c", "b", "a"}} {
		a := laneOf(t, mustAlign(t, c, execEvents(order...)), LaneProc)
		if countKinds(a)[EditMatch] == 4 {
			t.Errorf("observed %v across the fence: edits = %v, want a finding", order, kinds(a))
		}
	}
}

// Grouping buys the freedom to reorder and nothing else: a fabricated, an
// omitted and a substituted member are found as before.
func TestAlign_ABlockStillFindsFabricationOmissionAndSubstitution(t *testing.T) {
	// Fabrication: the block claims three calls, two happened, in reverse.
	fab := laneOf(t, mustAlign(t, inBlock("m", execs("a", "FAKE", "b")...), execEvents("b", "a")), LaneProc)
	if k := countKinds(fab); k[EditMatch] != 2 || k[EditInsertion] != 1 {
		t.Errorf("fabrication: edits = %v, want two matches and one insertion", kinds(fab))
	}
	for _, e := range fab.Edits {
		if e.Kind == EditInsertion && e.Claim.Target != "FAKE" {
			t.Errorf("fabrication: insertion is %q, want FAKE", e.Claim.Target)
		}
	}
	// Omission: an unclaimed command runs between the block's members.
	om := laneOf(t, mustAlign(t, inBlock("m", execs("a", "b")...), execEvents("b", "/bin/secret", "a")), LaneProc)
	if k := countKinds(om); k[EditMatch] != 2 || k[EditDeletion] != 1 {
		t.Errorf("omission: edits = %v, want two matches and one deletion", kinds(om))
	}
	for _, e := range om.Edits {
		if e.Kind == EditDeletion && e.Event.Target != "/bin/secret" {
			t.Errorf("omission: deletion is %q, want /bin/secret", e.Event.Target)
		}
	}
	// Substitution: one member claims a different target than ran.
	sub := laneOf(t, mustAlign(t, inBlock("m", execs("a", "EVIL")...), execEvents("b", "a")), LaneProc)
	if k := countKinds(sub); k[EditMatch] != 1 || k[EditSubstitution] != 1 {
		t.Errorf("substitution: edits = %v, want one match and one substitution", kinds(sub))
	}
}

// A block over the cap falls back to the trajectory's order and says so.
func TestAlign_ABlockOverTheCapFallsBackWithADegradation(t *testing.T) {
	var targets []string
	for i := 0; i < maxBlock+1; i++ {
		targets = append(targets, fmt.Sprintf("cmd-%02d", i))
	}
	reversed := make([]string, len(targets))
	for i, x := range targets {
		reversed[len(targets)-1-i] = x
	}
	over := laneOf(t, mustAlign(t, inBlock("big", execs(targets...)...), execEvents(reversed...)), LaneProc)
	if countKinds(over)[EditMatch] == len(targets) {
		t.Errorf("over the cap: edits = %v, want the strict reading's findings", kinds(over))
	}
	if len(over.Degradations) != 1 || !strings.Contains(over.Degradations[0], "exceeds") {
		t.Errorf("over the cap: degradations = %v, want one naming the cap", over.Degradations)
	}

	// At the cap the block is reordered exactly.
	at := laneOf(t, mustAlign(t, inBlock("big", execs(targets[:maxBlock]...)...), execEvents(reversed[1:]...)), LaneProc)
	if countKinds(at)[EditMatch] != maxBlock || at.Ambiguous || len(at.Degradations) != 0 {
		t.Errorf("at the cap: edits = %v, degradations = %v, want %d matches", kinds(at), at.Degradations, maxBlock)
	}

	// Verify carries the degradation into the verdict.
	var g models.GroundTruth
	for i, x := range reversed {
		pid := uint32(500 + i)
		g = append(g, fork(i*10, pid, agentPID), execEv(i*10+1, pid, agentPID, x))
	}
	var tr models.Trajectory
	for _, c := range inBlock("big", execs(targets...)...) {
		c.Timestamp = at0()
		tr = append(tr, c)
	}
	if v := run(tr, g); len(v.Degradations) != 1 {
		t.Errorf("Verify degradations = %v, want the lane's one", v.Degradations)
	}
}

func at0() time.Time { return at(0) }

// A block whose claims are not contiguous in the lane is free only within each
// run, and the report says so.
func TestAlign_ANonContiguousBlockIsFreeOnlyWithinEachRun(t *testing.T) {
	c := concat(inBlock("m", execs("a", "b")...), execs("x"), inBlock("m", execs("c")...))
	a := laneOf(t, mustAlign(t, c, execEvents("b", "a", "x", "c")), LaneProc)
	if countKinds(a)[EditMatch] != 4 {
		t.Errorf("edits = %v, want four matches", kinds(a))
	}
	if len(a.Degradations) != 1 || !strings.Contains(a.Degradations[0], "not contiguous") {
		t.Errorf("degradations = %v, want one", a.Degradations)
	}
	crossed := laneOf(t, mustAlign(t, c, execEvents("c", "x", "a", "b")), LaneProc)
	if countKinds(crossed)[EditMatch] == 4 {
		t.Errorf("crossed runs: edits = %v, want a finding", kinds(crossed))
	}
}

// The fence orders the start of a call. An exit never joins a block: it is
// aligned in the trajectory's order, as before, with a degradation, so a
// format that claims exits keeps today's reading of them.
func TestAlign_ExitClaimsAreNotBlockMembers(t *testing.T) {
	exit := func(x string) models.TrajectoryEntry { return claim(models.ProcessExit, x) }
	c := concat(inBlock("m", execs("a", "b")...), inBlock("m", exit("a"), exit("b")))
	g := models.GroundTruth{obs(models.ProcessExec, "b"), obs(models.ProcessExec, "a"), obs(models.ProcessExit, "a"), obs(models.ProcessExit, "b")}
	a := laneOf(t, mustAlign(t, c, g), LaneProc)
	if countKinds(a)[EditMatch] != 4 {
		t.Errorf("edits = %v, want four matches", kinds(a))
	}
	if len(a.Degradations) != 1 || !strings.Contains(a.Degradations[0], "exit") {
		t.Errorf("degradations = %v, want the exit one", a.Degradations)
	}
	// The exits observed in the other order are a finding, as without blocks.
	g[2], g[3] = g[3], g[2]
	if countKinds(laneOf(t, mustAlign(t, c, g), LaneProc))[EditMatch] == 4 {
		t.Error("exits observed out of order: want a finding")
	}
}

// Ambiguity counts pairings. Orderings of a block that give one pairing are
// one reading, and so are pairings that differ only by exchanging members
// equal in every compared field: two identical calls in one message, each
// observed once, are not an ambiguity. Members that differ are.
func TestAlign_BlockAmbiguityCountsPairings(t *testing.T) {
	same := inBlock("m", execs("cat x", "cat x")...)
	a := laneOf(t, mustAlign(t, same, execEvents("cat x", "cat x")), LaneProc)
	if a.Ambiguous || a.Optimal != 1 || countKinds(a)[EditMatch] != 2 {
		t.Errorf("identical members: Optimal = %d, edits = %v, want 1 and two matches", a.Optimal, kinds(a))
	}
	// One of two identical members fabricated: which one is not a question.
	one := laneOf(t, mustAlign(t, same, execEvents("cat x")), LaneProc)
	if one.Ambiguous || countKinds(one)[EditInsertion] != 1 {
		t.Errorf("identical members, one observed: Optimal = %d, edits = %v, want a unique insertion", one.Optimal, kinds(one))
	}
	// Outside a block the old count stands: the same two claims in order,
	// one observed, are two readings (TestAlign_NonUniqueMinimumIsAmbiguous).
	if seq := laneOf(t, mustAlign(t, concat(execs("cat x", "cat x")), execEvents("cat x")), LaneProc); seq.Optimal != 2 {
		t.Errorf("identical claims without a block: Optimal = %d, want 2", seq.Optimal)
	}
	// Two members that differ, both substituted: which event each one ran
	// as is unknown, and that is reported.
	swapped := laneOf(t, mustAlign(t, inBlock("m", execs("p", "q")...), execEvents("r", "s")), LaneProc)
	if !swapped.Ambiguous || swapped.Optimal != 2 || countKinds(swapped)[EditSubstitution] != 2 {
		t.Errorf("two substitutions: Optimal = %d, edits = %v, want 2 and two substitutions", swapped.Optimal, kinds(swapped))
	}
	// Two members unpaired: inserting them in either order is one reading.
	none := laneOf(t, mustAlign(t, inBlock("m", execs("p", "q")...), nil), LaneProc)
	if none.Ambiguous || none.Optimal != 1 {
		t.Errorf("two insertions: Optimal = %d, want 1", none.Optimal)
	}
	// One member with no event is one reading: which member is missing is
	// fixed by the targets, not by the order.
	sub := laneOf(t, mustAlign(t, inBlock("m", execs("a", "b")...), execEvents("a")), LaneProc)
	if sub.Ambiguous || countKinds(sub)[EditInsertion] != 1 {
		t.Errorf("one missing member: Optimal = %d, edits = %v, want a unique insertion", sub.Optimal, kinds(sub))
	}
}

// Members of a block in different lanes are reordered in each lane alone.
func TestAlign_ABlockSpanningLanesIsFreeInEachLane(t *testing.T) {
	c := inBlock("m", claim(models.ProcessExec, "a"), claim(models.FileOpen, "/w/x"), claim(models.ProcessExec, "b"), claim(models.FileOpen, "/w/y"))
	g := models.GroundTruth{obs(models.FileOpen, "/w/y"), obs(models.ProcessExec, "b"), obs(models.FileOpen, "/w/x"), obs(models.ProcessExec, "a")}
	for _, a := range mustAlign(t, c, g) {
		if countKinds(a)[EditMatch] != 2 || len(a.Edits) != 2 {
			t.Errorf("lane %s: edits = %v, want two matches", a.Lane, kinds(a))
		}
	}
}

// V-31 inside a block: among equal-cost pairings, the one with the fewest
// pairs outside their interval is shown, even when the two pairings are one
// reading for the count because the members are interchangeable.
func TestAlign_BlockTiesPreferThePairingInsideTheInterval(t *testing.T) {
	mk := func(start, end int) models.TrajectoryEntry {
		e := at(end)
		return models.TrajectoryEntry{Timestamp: at(start), End: &e, ActionType: models.ProcessExec, Target: "cat x", BlockID: "m"}
	}
	c := models.Trajectory{mk(0, 100), mk(500, 600)}
	g := models.GroundTruth{
		{Timestamp: at(550), ActionType: models.ProcessExec, Target: "cat x"},
		{Timestamp: at(50), ActionType: models.ProcessExec, Target: "cat x"},
	}
	a := laneOf(t, mustAlign(t, c, g), LaneProc)
	for _, e := range a.Edits {
		if e.OutsideInterval {
			t.Errorf("edit %+v is outside its interval, want the pairing inside both", e)
		}
	}
	if a.Ambiguous || a.Optimal != 1 {
		t.Errorf("Optimal = %d, want 1", a.Optimal)
	}
}

// pairingKey names a reading by its pairs, which is what Optimal counts: each
// claim is replaced by its class, the first claim of its run equal to it in
// every compared field, so exchanging equal members of one block is one
// reading.
func pairingKey(class []int, pairs [][2]int) string {
	s := make([]string, len(pairs))
	for i, p := range pairs {
		s[i] = fmt.Sprintf("%d-%d", class[p[0]], p[1])
	}
	sort.Strings(s)
	return strings.Join(s, ",")
}

// classes gives each claim the index of the first claim of its run with the
// same type, target, tool and content fields.
func classes(c models.Trajectory, runOf []int) []int {
	str := func(p *string) string {
		if p == nil {
			return "<nil>"
		}
		return *p
	}
	code := func(p *int32) string {
		if p == nil {
			return "<nil>"
		}
		return fmt.Sprint(*p)
	}
	same := func(a, b models.TrajectoryEntry) bool {
		return a.ActionType == b.ActionType && a.Target == b.Target && a.Tool == b.Tool && a.ImpliedBy == b.ImpliedBy &&
			str(a.InputHash) == str(b.InputHash) && str(a.OutputHash) == str(b.OutputHash) &&
			code(a.ExitCode) == code(b.ExitCode) && str(a.RequestHash) == str(b.RequestHash)
	}
	// A harness-implied claim's interval decides whether it may pair (V-33),
	// so for it time is compared too.
	sameTime := func(a, b models.TrajectoryEntry) bool {
		if a.ImpliedBy == "" {
			return true
		}
		if !a.Timestamp.Equal(b.Timestamp) || (a.End == nil) != (b.End == nil) {
			return false
		}
		return a.End == nil || a.End.Equal(*b.End)
	}
	out := make([]int, len(c))
	for i := range c {
		out[i] = i
		for k := 0; k < i; k++ {
			if runOf[k] == runOf[i] && same(c[k], c[i]) && sameTime(c[k], c[i]) {
				out[i] = k
				break
			}
		}
	}
	return out
}

// runsOf numbers the runs: consecutive claims sharing a non-empty block id.
func runsOf(c models.Trajectory) []int {
	runOf := make([]int, len(c))
	for i := 1; i < len(c); i++ {
		runOf[i] = runOf[i-1]
		if c[i].BlockID == "" || c[i].BlockID != c[i-1].BlockID {
			runOf[i]++
		}
	}
	return runOf
}

// bruteForceBlocks enumerates every order of the claims the fences allow (each
// run of claims sharing a block id permuted, runs in order) and every
// alignment of each order, and returns the minimum cost, the distinct pairings
// that reach it, and the fewest interval violations among them. It shares no
// code with alignBlocks but the cost of one pair and of one unpaired claim
// (pairCostOf, insertCost: a harness-implied claim costs nothing unpaired and
// is refused most pairs, V-33).
func bruteForceBlocks(c models.Trajectory, o models.GroundTruth) (best int, pairings map[string]bool, bestViol int) {
	class := classes(c, runsOf(c))
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
	best, bestViol = 1<<30, 1<<30
	pairings = map[string]bool{}
	for _, order := range orders {
		var pairs [][2]int
		var rec func(i, j, cost, viol int)
		rec = func(i, j, cost, viol int) {
			if cost > best {
				return
			}
			if i == len(order) && j == len(o) {
				if cost < best {
					best, bestViol = cost, viol
					pairings = map[string]bool{}
				}
				bestViol = min(bestViol, viol)
				pairings[pairingKey(class, pairs)] = true
				return
			}
			if i < len(order) && j < len(o) {
				if pc, ok := pairCostOf(c[order[i]], o[j], Options{}); ok {
					v := 0
					if outsideInterval(c[order[i]], o[j], 0) {
						v = 1
					}
					pairs = append(pairs, [2]int{order[i], j})
					rec(i+1, j+1, cost+pc, viol+v)
					pairs = pairs[:len(pairs)-1]
				}
			}
			if i < len(order) {
				rec(i+1, j, cost+insertCost(c[order[i]]), viol)
			}
			if j < len(o) {
				rec(i, j+1, cost+costIndel, viol)
			}
		}
		rec(0, 0, 0, 0)
	}
	return best, pairings, bestViol
}

// V-32 against an independent brute force: on random lanes with blocks, the
// reading shown is a valid one (every claim and event once, events in order,
// blocks in order), it has the minimum cost and, among those, the fewest
// interval violations, and Optimal is the number of distinct minimum-cost
// pairings, with exchanges of interchangeable members of one block counted
// once.
func TestAlign_BlocksAgreeWithBruteForce(t *testing.T) {
	rng := rand.New(rand.NewSource(32))
	targets := []string{"a", "b", "c"}
	types := []models.ActionType{models.FileOpen, models.FileWrite}
	blocks := []string{"", "m1", "m1", "m2", "m2"}
	hashes := []*string{nil, nil, sp("h1"), sp("h2")}
	sawBlock, sawAmbiguous := 0, 0
	for trial := 0; trial < 1000; trial++ {
		var c models.Trajectory
		for i, n := 0, 1+rng.Intn(5); i < n; i++ {
			e := models.TrajectoryEntry{Timestamp: t0.Add(time.Duration(rng.Intn(10)) * time.Second), ActionType: types[rng.Intn(2)], Target: targets[rng.Intn(3)], BlockID: blocks[rng.Intn(len(blocks))], OutputHash: hashes[rng.Intn(len(hashes))]}
			if rng.Intn(3) > 0 {
				end := e.Timestamp.Add(time.Duration(rng.Intn(4)) * time.Second)
				e.End = &end
			}
			c = append(c, e)
		}
		var o models.GroundTruth
		for i, n := 0, rng.Intn(6); i < n; i++ {
			o = append(o, models.GroundTruthEvent{Timestamp: t0.Add(time.Duration(rng.Intn(12)) * time.Second), ActionType: types[rng.Intn(2)], Target: targets[rng.Intn(3)], OutputHash: hashes[rng.Intn(len(hashes))]})
		}
		wantCost, wantPairings, wantViol := bruteForceBlocks(c, o)
		a := laneOf(t, mustAlign(t, c, o), LaneFS)

		runOf := runsOf(c)
		for i := 1; i < len(c); i++ {
			if runOf[i] == runOf[i-1] {
				sawBlock++
				break
			}
		}
		seenClaim := map[int]bool{}
		nextEvent, lastRun := 0, 0
		cost, viol := 0, 0
		var pairs [][2]int
		for _, e := range a.Edits {
			if e.ClaimIndex >= 0 {
				if seenClaim[e.ClaimIndex] || runOf[e.ClaimIndex] < lastRun {
					t.Fatalf("trial %d: claim %d repeated or before an earlier block: %+v", trial, e.ClaimIndex, a.Edits)
				}
				seenClaim[e.ClaimIndex] = true
				lastRun = runOf[e.ClaimIndex]
			}
			if e.EventIndex >= 0 {
				if e.EventIndex != nextEvent {
					t.Fatalf("trial %d: events out of order: %+v", trial, a.Edits)
				}
				nextEvent++
			}
			switch e.Kind {
			case EditInsertion, EditDeletion:
				cost += costIndel
			default:
				pc, _ := pairCost(*e.Claim, *e.Event, nil, nil)
				cost += pc
				if e.OutsideInterval {
					viol++
				}
				pairs = append(pairs, [2]int{e.ClaimIndex, e.EventIndex})
			}
		}
		if len(seenClaim) != len(c) || nextEvent != len(o) {
			t.Fatalf("trial %d: consumed %d/%d claims and %d/%d events", trial, len(seenClaim), len(c), nextEvent, len(o))
		}
		if cost != wantCost || viol != wantViol {
			t.Fatalf("trial %d: reading costs (%d, %d violations), brute force minimum is (%d, %d)\nclaims %+v\nevents %+v", trial, cost, viol, wantCost, wantViol, c, o)
		}
		if !wantPairings[pairingKey(classes(c, runOf), pairs)] {
			t.Fatalf("trial %d: the reading shown is not a minimum-cost pairing", trial)
		}
		if int(a.Optimal) != len(wantPairings) || a.Ambiguous != (len(wantPairings) > 1) {
			t.Fatalf("trial %d: Optimal = %d, brute force finds %d pairings\nclaims %+v\nevents %+v", trial, a.Optimal, len(wantPairings), c, o)
		}
		if a.Ambiguous {
			sawAmbiguous++
		}
	}
	t.Logf("%d lanes with a block, %d ambiguous", sawBlock, sawAmbiguous)
	if sawBlock < 300 || sawAmbiguous < 50 {
		t.Errorf("the random cases exercised %d lanes with a block and %d ambiguous ones, too few to mean anything", sawBlock, sawAmbiguous)
	}
}

// With single-claim segments the block program is alignLane's: the same
// reading, edit for edit, and the same count, so a lane without a block reads
// as it did before V-32 whichever program aligns it.
func TestAlign_SingleClaimSegmentsReadAsTheOrderedAlignment(t *testing.T) {
	rng := rand.New(rand.NewSource(320))
	targets := []string{"a", "b"}
	types := []models.ActionType{models.FileOpen, models.FileWrite}
	for trial := 0; trial < 500; trial++ {
		var c models.Trajectory
		var o models.GroundTruth
		for i, n := 0, rng.Intn(7); i < n; i++ {
			e := models.TrajectoryEntry{Timestamp: t0.Add(time.Duration(rng.Intn(10)) * time.Second), ActionType: types[rng.Intn(2)], Target: targets[rng.Intn(2)]}
			if rng.Intn(2) > 0 {
				end := e.Timestamp.Add(time.Duration(rng.Intn(4)) * time.Second)
				e.End = &end
			}
			c = append(c, e)
		}
		for i, n := 0, rng.Intn(7); i < n; i++ {
			o = append(o, models.GroundTruthEvent{Timestamp: t0.Add(time.Duration(rng.Intn(12)) * time.Second), ActionType: types[rng.Intn(2)], Target: targets[rng.Intn(2)]})
		}
		ci, ei := make([]int, len(c)), make([]int, len(o))
		segs := make([][]int, len(c))
		for i := range ci {
			ci[i], segs[i] = i, []int{i}
		}
		for j := range ei {
			ei[j] = j
		}
		want, err := alignLane(LaneFS, c, o, ci, ei, Options{})
		if err != nil {
			t.Fatal(err)
		}
		got, err := alignBlocks(LaneAlignment{Lane: LaneFS}, c, o, ci, ei, segs, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if got.Optimal != want.Optimal || len(got.Edits) != len(want.Edits) {
			t.Fatalf("trial %d: Optimal %d/%d, %d/%d edits", trial, got.Optimal, want.Optimal, len(got.Edits), len(want.Edits))
		}
		for k := range got.Edits {
			g, w := got.Edits[k], want.Edits[k]
			if g.Kind != w.Kind || g.ClaimIndex != w.ClaimIndex || g.EventIndex != w.EventIndex || g.OutsideInterval != w.OutsideInterval {
				t.Fatalf("trial %d: edit %d is %+v, alignLane gives %+v", trial, k, g, w)
			}
		}
	}
}

// The shapes capture's case end to end: two Bash calls of one message, the
// second one's command started first. Before V-32 both were Mismatched.
func TestVerify_AParallelBlockStartedOutOfOrderIsFaithful(t *testing.T) {
	g := models.GroundTruth{
		fork(10, 701, agentPID), execEv(11, 701, agentPID, "cat fast.txt"),
		fork(12, 702, agentPID), execEv(13, 702, agentPID, "sleep 2; cat slow.txt"),
	}
	tr := models.Trajectory{claimAt(0, models.ProcessExec, "sleep 2; cat slow.txt"), claimAt(1, models.ProcessExec, "cat fast.txt")}
	if v := run(tr, g); v.Outcome != OutcomeNotFaithful || len(v.Mismatched) != 2 {
		t.Fatalf("without a block: outcome %v, mismatched %d, want the crossed pair", v.Outcome, len(v.Mismatched))
	}
	tr[0].BlockID, tr[1].BlockID = "msg", "msg"
	v := run(tr, g)
	wantOutcome(t, v, OutcomeFaithful)
	if len(v.Corroborated) != 2 || v.Ambiguous || len(v.Degradations) != 0 {
		t.Errorf("corroborated = %d, ambiguous = %v, degradations = %v", len(v.Corroborated), v.Ambiguous, v.Degradations)
	}
}

// The fence orders the start of a call, not its end. A background command of
// one block outlives the next block: its descendants and its file events come
// after the next block's command started, and its exit later still. They are
// the command's content and, for a format without exits, not aligned, so
// nothing reads as out of order.
func TestVerify_ABackgroundCallMayOutliveItsBlock(t *testing.T) {
	g := models.GroundTruth{
		fork(10, 801, agentPID), execEv(11, 801, agentPID, "sleep 3; echo done > bg.txt"),
		fork(20, 802, agentPID), execEv(21, 802, agentPID, "cat notes.txt"),
		exitEv(30, 802, agentPID, "cat notes.txt"),
		fork(3000, 803, 801), execEv(3001, 803, 801, "/bin/echo done"),
		fsEv(3002, 801, "/w/bg.txt"),
		exitEv(3010, 801, agentPID, "sleep 3; echo done > bg.txt"),
	}
	tr := models.Trajectory{claimAt(0, models.ProcessExec, "sleep 3; echo done > bg.txt"), claimAt(5, models.ProcessExec, "cat notes.txt")}
	tr[0].BlockID, tr[1].BlockID = "m1", "m2"
	v := Verify(Input{Claims: tr, Ground: g, RootPID: agentPID, Coverage: completeCov(), Options: Options{IgnoreExits: true}})
	wantOutcome(t, v, OutcomeFaithful)
	if len(v.Corroborated) != 2 || v.Coverage.Explained == 0 {
		t.Errorf("corroborated = %d, explained = %d, want 2 and the background subtree", len(v.Corroborated), v.Coverage.Explained)
	}
}
