package verification

import (
	"errors"
	"fmt"
	"math"
	"math/bits"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// blockSegments cuts a lane's claims into segments: a segment is either one
// claim or a run of consecutive claims of the lane that share a non-empty
// BlockID, whose members may match in any order (V-32). Segments keep the
// trajectory's order. The returned slices hold positions in ci.
//
// Three cases are aligned more strictly than the rule allows, each with a
// degradation: a run over maxBlock is split into single claims; a block whose
// claims are not contiguous in the lane is free only within each run; and a
// process exit never joins a block, since the fence orders the start of a
// call and a call may end after a later block has started.
func blockSegments(lane Lane, claims models.Trajectory, ci []int) ([][]int, []string) {
	var segs [][]int
	var degr []string
	seen := map[string]bool{}
	split := map[string]bool{}
	exits := 0
	for p := 0; p < len(ci); {
		c := claims[ci[p]]
		if c.BlockID == "" || c.ActionType == models.ProcessExit {
			if c.BlockID != "" {
				exits++
			}
			segs = append(segs, []int{p})
			p++
			continue
		}
		q := p + 1
		for q < len(ci) && claims[ci[q]].BlockID == c.BlockID && claims[ci[q]].ActionType != models.ProcessExit {
			q++
		}
		if seen[c.BlockID] && !split[c.BlockID] {
			split[c.BlockID] = true
			degr = append(degr, fmt.Sprintf("%s lane: the claims of one parallel block are not contiguous in the trajectory, so each run of them is reordered only within itself (V-32)", lane))
		}
		seen[c.BlockID] = true
		if q-p > maxBlock {
			degr = append(degr, fmt.Sprintf("%s lane: a parallel block of %d claims exceeds the %d the alignment reorders, so its claims are aligned in the order the trajectory gives them and an out-of-order completion reads as a finding (V-32)", lane, q-p, maxBlock))
			for ; p < q; p++ {
				segs = append(segs, []int{p})
			}
			continue
		}
		run := make([]int, 0, q-p)
		for ; p < q; p++ {
			run = append(run, p)
		}
		segs = append(segs, run)
	}
	if exits > 0 {
		degr = append(degr, fmt.Sprintf("%s lane: %d process exit claim(s) carry a parallel block id; exits are aligned in the order the trajectory gives them, outside their block, so a call that ends after a later block starts reads as an order finding (V-32)", lane, exits))
	}
	return segs, degr
}

// errTraceback reports a dynamic program whose traceback found no step that
// keeps it on the optimum, which is a bug.
var errTraceback = errors.New("alignment traceback lost the optimum")

// alignBlocks is the alignment of a lane whose claims hold at least one
// parallel block (V-32). It is the program of alignLane over states instead of
// claim prefixes: a state is a segment s and the set (a bitmask) of the
// members of s already consumed, with "every member of s consumed" written as
// the next segment with none. Members are consumed by pairing them, in the
// order of the events they pair with; the members of a segment left unpaired
// are inserted together, once the segment's pairs are done (a flush). Every
// pairing has exactly one such path among the minimum-cost alignments: an
// unpaired member and an unpaired event inside the same segment's span would
// pair more cheaply (V-10), so a minimum-cost alignment has no choice of where
// to put either. So the count is of pairings, and a lane of single-claim
// segments is exactly alignLane's program.
//
// Bounds: a segment of k claims has 2^k - 1 states, k <= maxBlock, and the
// table holds (states + 1) * (m + 1) cells of 12 bytes, refused above
// maxCells. A cell looks at most k pair predecessors and one deletion, and the
// first state of a segment also at most 2^k - 1 flush predecessors, so the
// work is O(cells * maxBlock).
func alignBlocks(la LaneAlignment, claims models.Trajectory, observed models.GroundTruth, ci, ei []int, segs [][]int, opts Options) (LaneAlignment, error) {
	n, m := len(ci), len(ei)
	K := len(segs)
	off := make([]int, K+1)
	for s, seg := range segs {
		off[s+1] = off[s] + (1 << len(seg)) - 1
	}
	states := off[K] + 1 // the last is the final state, segment K with mask 0
	w := m + 1
	if states > maxCells/w {
		return la, ErrTooLarge
	}

	const inf = math.MaxInt32 / 4
	const satur = 1 << 30
	add := func(a, b uint32) uint32 {
		if a+b > satur || a+b < a {
			return satur
		}
		return a + b
	}
	pair := make([]int8, n*m)
	for p := 0; p < n; p++ {
		for j := 0; j < m; j++ {
			pc, _ := pairCost(claims[ci[p]], observed[ei[j]], opts.Expresses)
			pair[p*m+j] = int8(pc)
		}
	}
	// outside reports whether pairing claim position p with event j (1-based)
	// puts the event outside the claim's interval.
	outside := func(p, j int) int32 {
		if outsideInterval(claims[ci[p]], observed[ei[j-1]], opts.IntervalSlack) {
			return 1
		}
		return 0
	}
	size := func(s int) int { return len(segs[s]) }
	full := func(s int) int { return 1<<size(s) - 1 }

	// twins[s][t] is the set of members of segment s before t that are
	// interchangeable with t: equal in every field the comparison reads.
	// Exchanging them changes no cost, so a pairing and its exchange are
	// one reading; the count runs over pairings where interchangeable
	// members pair in their trajectory order, one per class. Time is not
	// among those fields: like V-31's, this choice concerns the count only.
	twins := make([][]int, K)
	hasTwins := false
	for s, seg := range segs {
		twins[s] = make([]int, len(seg))
		for t := range seg {
			for u := 0; u < t; u++ {
				if interchangeable(claims[ci[seg[u]]], claims[ci[seg[t]]]) {
					twins[s][t] |= 1 << u
					hasTwins = true
				}
			}
		}
	}

	// fill runs the program. With canonical set, a member pairs only after
	// its interchangeable predecessors, so ways counts readings up to
	// exchange; viol is then meaningless.
	fill := func(canonical bool) ([]int32, []int32, []uint32) {
		cost := make([]int32, states*w)
		viol := make([]int32, states*w)
		ways := make([]uint32, states*w)
		for x := range cost {
			cost[x] = inf
		}
		cost[0], ways[0] = 0, 1
		allowed := func(s, t, before int) bool {
			return !canonical || before&twins[s][t] == twins[s][t]
		}
		for s := 0; s <= K; s++ {
			masks := 1
			if s < K {
				masks = full(s)
			}
			for mask := 0; mask < masks; mask++ {
				x := off[s] + mask
				for j := 0; j <= m; j++ {
					if x == 0 && j == 0 {
						continue
					}
					best, bv, count := int32(inf), int32(math.MaxInt32), uint32(0)
					consider := func(c, v int32, wy uint32) {
						switch {
						case c >= inf:
						case c < best:
							best, bv, count = c, v, wy
						case c == best:
							bv = min(bv, v)
							count = add(count, wy)
						}
					}
					if j > 0 {
						// Pair a member with event j.
						if mask != 0 {
							for t := 0; t < size(s); t++ {
								if before := mask &^ (1 << t); mask&(1<<t) != 0 && allowed(s, t, before) {
									y := (off[s]+before)*w + j - 1
									p := segs[s][t]
									consider(cost[y]+int32(pair[p*m+j-1]), viol[y]+outside(p, j), ways[y])
								}
							}
						} else if s > 0 {
							for t := 0; t < size(s-1); t++ {
								if before := full(s-1) &^ (1 << t); allowed(s-1, t, before) {
									y := (off[s-1]+before)*w + j - 1
									p := segs[s-1][t]
									consider(cost[y]+int32(pair[p*m+j-1]), viol[y]+outside(p, j), ways[y])
								}
							}
						}
					}
					if mask == 0 && s > 0 {
						// Flush: the members of the previous segment left
						// unconsumed are inserted.
						for pm := 0; pm < full(s-1); pm++ {
							y := (off[s-1]+pm)*w + j
							left := size(s-1) - bits.OnesCount(uint(pm))
							consider(cost[y]+int32(left*costIndel), viol[y], ways[y])
						}
					}
					if j > 0 {
						// Event j unpaired: a deletion.
						y := x*w + j - 1
						consider(cost[y]+costIndel, viol[y], ways[y])
					}
					cost[x*w+j], viol[x*w+j], ways[x*w+j] = best, bv, count
				}
			}
		}
		return cost, viol, ways
	}

	final := off[K]
	if hasTwins {
		_, _, ways := fill(true)
		la.Optimal = ways[final*w+m]
	}
	cost, viol, ways := fill(false)
	if !hasTwins {
		la.Optimal = ways[final*w+m]
	}
	la.Ambiguous = la.Optimal > 1

	// Trace back, keeping both costs on their optimum: pair, then insertion,
	// then deletion, and among pairs the member latest in the trajectory, so
	// a block observed in its own order reads as alignLane would read it.
	var rev []Edit
	emitPair := func(p, j int) {
		c, e := claims[ci[p]], observed[ei[j-1]]
		_, diffs := pairCost(c, e, opts.Expresses)
		ed := Edit{Kind: EditMatch, ClaimIndex: ci[p], EventIndex: ei[j-1], Claim: &claims[ci[p]], Event: &observed[ei[j-1]]}
		if len(diffs) > 0 {
			ed.Kind, ed.Diffs = EditSubstitution, diffs
		}
		ed.OutsideInterval = outsideInterval(c, e, opts.IntervalSlack)
		ed.Unverified = unverifiedFields(c, e)
		rev = append(rev, ed)
	}
	s, mask, j := K, 0, m
	for s > 0 || mask != 0 || j > 0 {
		x := off[s] + mask
		here, hv := cost[x*w+j], viol[x*w+j]
		moved := false
		if j > 0 {
			ps, base := s, mask
			if mask == 0 {
				ps, base = s-1, -1
			}
			if ps >= 0 {
				if base < 0 {
					base = full(ps)
				}
				for t := size(ps) - 1; t >= 0 && !moved; t-- {
					if base&(1<<t) == 0 {
						continue
					}
					pm := base &^ (1 << t)
					y := (off[ps]+pm)*w + j - 1
					p := segs[ps][t]
					if here == cost[y]+int32(pair[p*m+j-1]) && hv == viol[y]+outside(p, j) {
						emitPair(p, j)
						s, mask, j = ps, pm, j-1
						moved = true
					}
				}
			}
		}
		if !moved && mask == 0 && s > 0 {
			for pm := full(s-1) - 1; pm >= 0 && !moved; pm-- {
				y := (off[s-1]+pm)*w + j
				left := size(s-1) - bits.OnesCount(uint(pm))
				if here == cost[y]+int32(left*costIndel) && hv == viol[y] {
					for t := size(s-1) - 1; t >= 0; t-- {
						if pm&(1<<t) == 0 {
							p := segs[s-1][t]
							rev = append(rev, Edit{Kind: EditInsertion, ClaimIndex: ci[p], EventIndex: -1, Claim: &claims[ci[p]]})
						}
					}
					s, mask = s-1, pm
					moved = true
				}
			}
		}
		if !moved && j > 0 {
			y := x*w + j - 1
			if here == cost[y]+costIndel && hv == viol[y] {
				rev = append(rev, Edit{Kind: EditDeletion, ClaimIndex: -1, EventIndex: ei[j-1], Event: &observed[ei[j-1]]})
				j--
				moved = true
			}
		}
		if !moved {
			return la, errTraceback
		}
	}
	for k := len(rev) - 1; k >= 0; k-- {
		la.Edits = append(la.Edits, rev[k])
	}
	return la, nil
}

// interchangeable reports whether two claims are equal in every field the
// pair comparison reads (pairCost, contentDiffs, unverifiedFields and the
// adapter's Expresses, which may read the tool), so that exchanging them
// changes no cost and no finding. Time is left out.
func interchangeable(a, b models.TrajectoryEntry) bool {
	return a.ActionType == b.ActionType && a.Target == b.Target && a.Tool == b.Tool &&
		eqPtr(a.InputHash, b.InputHash) && eqPtr(a.OutputHash, b.OutputHash) &&
		eqPtr(a.ExitCode, b.ExitCode) && eqPtr(a.RequestHash, b.RequestHash)
}

func eqPtr[T comparable](a, b *T) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}
