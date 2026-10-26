package verification

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"time"

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

// bandSlack is how far above the lane's lower bound the first band reaches
// (V-42): four unpaired entries, two columns either side of the narrowest
// band. A lane whose minimum is dearer widens it.
const bandSlack = 4 * costIndel

// alignBlocks aligns one lane (alignLane calls it for every lane). It is a
// dynamic program over states instead of claim prefixes: a state is a segment
// s and the set (a bitmask) of the members of s already consumed, with "every
// member of s consumed" written as the next segment with none. A segment is a
// parallel block (V-32) or one claim. Members are consumed by pairing them, in
// the order of the events they pair with; the members of a segment left
// unpaired are inserted together, once the segment's pairs are done (a
// flush). Every pairing has exactly one such path among the minimum-cost
// alignments: an unpaired ordinary member and an unpaired event inside the
// same segment's span would pair more cheaply (V-10), so a minimum-cost
// alignment has no choice of where to put either. So the count is of
// pairings, and with one-claim segments the program is the ordered alignment
// of V4 and V-31: a pair is the diagonal step, a flush the insertion.
//
// A harness-implied member costs nothing unpaired and may be refused a pair
// (V-33), so an unpaired one and an unpaired event can share a span, and a
// deletion could then come before or after the flush that inserts it. With
// such a member in the lane, each cell has a second layer holding the paths
// whose last move is a flush, and a deletion may not follow one: the deletions
// of a span come before its flushes, which again gives one path per pairing.
// A lane without one has a single layer and is the program above, step for
// step.
//
// Bounds: a segment of k claims has 2^k - 1 states, k <= maxBlock. The program
// runs only over a band of cells (V-42). A cell whose state has decided c
// claims, co of them ordinary, after j events lies on no path cheaper than
// lowerBound(c, co, j): pairs cost at least nothing, and at least the surplus
// of events over claims on either side of the cell, and of ordinary claims
// over events, is left unpaired. Given an upper bound U on the minimum cost,
// a cell whose bound exceeds U lies on no minimum-cost path. Every cell of
// every minimum-cost path, and every path a minimum-cost path's prefix could
// take instead, is kept, so the minimum, the fewest interval violations, the
// count and every traceback step are those of the whole table; a cell left
// out reads as unreachable and only ever raises a value off the optimum. The
// first band takes U as the lane's own bound plus bandSlack; while the
// minimum found exceeds U, U grows to that minimum or to twice its slack,
// whichever is smaller, and the program runs again, so the band that ends it
// holds every minimum-cost path. The bound is convex in j, so each state's
// cells are one interval of columns. A band of more than maxCells cells per
// layer is refused with ErrTooLarge. An honest lane's band is a few columns
// wider than the surplus of events over claims, so the cells grow with the
// states times that surplus and the findings, not with states times events.
// A cell looks at most k pair predecessors and one deletion, and the first
// state of a segment also at most 2^k - 1 flush predecessors, so the work is
// O(cells * maxBlock) per run of the program.
func alignBlocks(la LaneAlignment, claims models.Trajectory, observed models.GroundTruth, ci, ei []int, segs [][]int, opts Options) (LaneAlignment, error) {
	n, m := len(ci), len(ei)
	K := len(segs)
	off := make([]int, K+1)
	for s, seg := range segs {
		off[s+1] = off[s] + (1 << len(seg)) - 1
	}
	states := off[K] + 1 // the last is the final state, segment K with mask 0
	if states > maxCells {
		return la, ErrTooLarge
	}
	// fl is the layer a flush writes: 0 when no member is harness-implied, so
	// the program has one layer and reads as before V-33.
	fl, layers := 0, 1
	ins := make([]int32, n)
	ordinaryClaims := 0
	for p := range ci {
		ins[p] = int32(insertCost(claims[ci[p]]))
		if implied(claims[ci[p]]) {
			fl, layers = 1, 2
		} else {
			ordinaryClaims++
		}
	}

	const inf = math.MaxInt32 / 4
	const satur = 1 << 30
	add := func(a, b uint32) uint32 {
		if a+b > satur || a+b < a {
			return satur
		}
		return a + b
	}
	size := func(s int) int { return len(segs[s]) }
	full := func(s int) int { return 1<<size(s) - 1 }
	// flushCost is the cost of inserting the members of segment s outside pm.
	flushCost := func(s, pm int) int32 {
		var c int32
		for t, p := range segs[s] {
			if pm&(1<<t) == 0 {
				c += ins[p]
			}
		}
		return c
	}

	// decided[x] is the number of claims state x has decided (paired or
	// inserted), ordinary[x] how many of them are not harness-implied.
	decided := make([]int32, states)
	ordinary := make([]int32, states)
	before, beforeOrdinary := 0, 0
	for s, seg := range segs {
		for mask := 0; mask < full(s); mask++ {
			c, co := before, beforeOrdinary
			for t, p := range seg {
				if mask&(1<<t) != 0 {
					c++
					if !implied(claims[ci[p]]) {
						co++
					}
				}
			}
			decided[off[s]+mask], ordinary[off[s]+mask] = int32(c), int32(co)
		}
		before += len(seg)
		for _, p := range seg {
			if !implied(claims[ci[p]]) {
				beforeOrdinary++
			}
		}
	}
	decided[off[K]], ordinary[off[K]] = int32(n), int32(ordinaryClaims)
	// lowerBound is the least cost of any path through state x after j
	// events: of the j events at most min(j, c) are paired, and of the m - j
	// after it at most min(m - j, n - c), and every other event, and every
	// ordinary claim beyond the pairs on its side, costs costIndel.
	lowerBound := func(x, j int) int {
		c, co := int(decided[x]), int(ordinary[x])
		p := min(j, c)
		q := min(m-j, n-c)
		return costIndel * ((j - p) + max(0, co-p) + (m - j - q) + max(0, ordinaryClaims-co-q))
	}

	// band is the set of cells one run of the program fills: for each state
	// the columns lo..hi (none when hi < lo), stored from base.
	type band struct {
		lo, hi []int32
		base   []int
		cells  int
		full   bool
	}
	at := func(bd *band, x, j int) int {
		if j < int(bd.lo[x]) || j > int(bd.hi[x]) {
			return -1
		}
		return bd.base[x] + j - int(bd.lo[x])
	}
	// makeBand keeps the cells whose bound is at most u. The bound is convex
	// in j, so they are an interval around its minimum.
	makeBand := func(u int) (*band, bool) {
		bd := &band{lo: make([]int32, states), hi: make([]int32, states), base: make([]int, states), full: true}
		for x := 0; x < states; x++ {
			jm := sort.Search(m, func(j int) bool { return lowerBound(x, j+1) >= lowerBound(x, j) })
			lo, hi := 1, 0
			if lowerBound(x, jm) <= u {
				lo = sort.Search(jm, func(j int) bool { return lowerBound(x, j) <= u })
				hi = jm + sort.Search(m-jm, func(k int) bool { return lowerBound(x, jm+k+1) > u })
			}
			bd.lo[x], bd.hi[x], bd.base[x] = int32(lo), int32(hi), bd.cells
			if hi >= lo {
				bd.cells += hi - lo + 1
			}
			if lo != 0 || hi != m {
				bd.full = false
			}
			if bd.cells > maxCells/layers {
				return nil, false
			}
		}
		return bd, true
	}

	// pair holds, for the events e the band can pair claim position p with
	// (those of the columns of its segment's states and of the state after
	// them), the pair's code: -1 when the pair is refused (a harness-implied
	// claim, V-33), else its cost plus pairOutside when the event falls
	// outside the claim's interval.
	const pairOutside = 4
	var pair []int8
	var pairLo, pairHi, pairBase []int
	pairCode := func(p, e int) int8 {
		pc, ok := pairCostOf(claims[ci[p]], observed[ei[e]], opts)
		if !ok {
			return -1
		}
		if outsideInterval(claims[ci[p]], observed[ei[e]], opts.IntervalSlack) {
			pc += pairOutside
		}
		return int8(pc)
	}
	pairsFor := func(bd *band) bool {
		total := 0
		lo, hi, base := make([]int, n), make([]int, n), make([]int, n)
		for s, seg := range segs {
			first, last := m, -1
			for x := off[s]; x <= off[s+1]; x++ {
				if bd.hi[x] >= bd.lo[x] {
					first, last = min(first, max(0, int(bd.lo[x])-1)), max(last, int(bd.hi[x])-1)
				}
			}
			for _, p := range seg {
				lo[p], hi[p], base[p] = first, last, total
				if last >= first {
					total += last - first + 1
				}
			}
		}
		if total > maxCells {
			return false
		}
		// A wider band keeps the codes the previous one computed.
		next := make([]int8, total)
		for p := 0; p < n; p++ {
			for e := lo[p]; e <= hi[p]; e++ {
				if pair != nil && e >= pairLo[p] && e <= pairHi[p] {
					next[base[p]+e-lo[p]] = pair[pairBase[p]+e-pairLo[p]]
				} else {
					next[base[p]+e-lo[p]] = pairCode(p, e)
				}
			}
		}
		pair, pairLo, pairHi, pairBase = next, lo, hi, base
		return true
	}
	// pairAt is the code of pairing p with event e. The band never asks
	// outside the range pairsFor filled; the fallback keeps it exact if it
	// did.
	pairAt := func(p, e int) int8 {
		if e < pairLo[p] || e > pairHi[p] {
			return pairCode(p, e)
		}
		return pair[pairBase[p]+e-pairLo[p]]
	}

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

	// table holds one layer of the program per cell of the band.
	type table struct {
		cost, viol []int32
		ways       []uint32
	}
	// best reads a cell over every layer: the minimum cost, the fewest
	// violations among the paths of that cost, and their count. Layers hold
	// disjoint paths (by their last move), so the counts add. A cell outside
	// the band (y < 0) is unreachable.
	best := func(tb []table, y int) (int32, int32, uint32) {
		if y < 0 {
			return inf, math.MaxInt32, 0
		}
		c, v, wy := tb[0].cost[y], tb[0].viol[y], tb[0].ways[y]
		for l := 1; l < len(tb); l++ {
			switch lc := tb[l].cost[y]; {
			case lc >= inf:
			case lc < c:
				c, v, wy = lc, tb[l].viol[y], tb[l].ways[y]
			case lc == c:
				v = min(v, tb[l].viol[y])
				wy = add(wy, tb[l].ways[y])
			}
		}
		return c, v, wy
	}

	// fill runs the program over the band. With canonical set, a member
	// pairs only after its interchangeable predecessors, so ways counts
	// readings up to exchange; viol is then meaningless.
	// A move into a state: a pair of claim position p, a member of the
	// segment of state from, with the next event, or a flush from state from
	// that inserts the members it left at cost flush.
	type move struct {
		from, p int
		flush   int32
	}
	// movesInto lists the moves into state x (segment s, mask): the pairs
	// that consume one member of the mask, or, for a segment's first state,
	// that consume the previous segment's last member, and that segment's
	// flushes. With canonical set, a member pairs only after its
	// interchangeable predecessors.
	movesInto := func(s, mask int, canonical bool, pairs, flushes []move) ([]move, []move) {
		pairs, flushes = pairs[:0], flushes[:0]
		allowed := func(s, t, before int) bool {
			return !canonical || before&twins[s][t] == twins[s][t]
		}
		if mask != 0 {
			for t := 0; t < size(s); t++ {
				if before := mask &^ (1 << t); mask&(1<<t) != 0 && allowed(s, t, before) {
					pairs = append(pairs, move{from: off[s] + before, p: segs[s][t]})
				}
			}
		} else if s > 0 {
			for t := 0; t < size(s-1); t++ {
				if before := full(s-1) &^ (1 << t); allowed(s-1, t, before) {
					pairs = append(pairs, move{from: off[s-1] + before, p: segs[s-1][t]})
				}
			}
			for pm := 0; pm < full(s-1); pm++ {
				flushes = append(flushes, move{from: off[s-1] + pm, flush: flushCost(s-1, pm)})
			}
		}
		return pairs, flushes
	}

	// fill runs the program over the band. With canonical set, a member
	// pairs only after its interchangeable predecessors, so ways counts
	// readings up to exchange; viol is then meaningless.
	fill := func(bd *band, canonical bool) []table {
		tb := make([]table, layers)
		for l := range tb {
			tb[l] = table{make([]int32, bd.cells), make([]int32, bd.cells), make([]uint32, bd.cells)}
			for y := range tb[l].cost {
				tb[l].cost[y] = inf
			}
		}
		origin := at(bd, 0, 0)
		tb[0].cost[origin], tb[0].ways[origin] = 0, 1
		type acc struct {
			c, v int32
			wy   uint32
		}
		consider := func(a *acc, c, v int32, wy uint32) {
			switch {
			case c >= inf:
			case c < a.c:
				a.c, a.v, a.wy = c, v, wy
			case c == a.c:
				a.v = min(a.v, v)
				a.wy = add(a.wy, wy)
			}
		}
		var pairs, flushes []move
		for s := 0; s <= K; s++ {
			masks := 1
			if s < K {
				masks = full(s)
			}
			for mask := 0; mask < masks; mask++ {
				x := off[s] + mask
				pairs, flushes = movesInto(s, mask, canonical, pairs, flushes)
				for j := int(bd.lo[x]); j <= int(bd.hi[x]); j++ {
					if x == 0 && j == 0 {
						continue
					}
					a := [2]acc{{c: inf, v: math.MaxInt32}, {c: inf, v: math.MaxInt32}}
					if j > 0 {
						// Pair a member with event j.
						for _, mv := range pairs {
							code := pairAt(mv.p, j-1)
							if code < 0 {
								continue
							}
							c, v, wy := best(tb, at(bd, mv.from, j-1))
							if c >= inf {
								continue
							}
							consider(&a[0], c+int32(code%pairOutside), v+int32(code/pairOutside), wy)
						}
					}
					// Flush: the members of the previous segment left
					// unconsumed are inserted.
					for _, mv := range flushes {
						c, v, wy := best(tb, at(bd, mv.from, j))
						if c >= inf {
							continue
						}
						consider(&a[fl], c+mv.flush, v, wy)
					}
					if j > 0 {
						// Event j unpaired: a deletion, never straight after a
						// flush (layer 0 only).
						if y := at(bd, x, j-1); y >= 0 {
							consider(&a[0], tb[0].cost[y]+costIndel, tb[0].viol[y], tb[0].ways[y])
						}
					}
					y := at(bd, x, j)
					for l := 0; l < layers; l++ {
						tb[l].cost[y], tb[l].viol[y], tb[l].ways[y] = a[l].c, a[l].v, a[l].wy
					}
				}
			}
		}
		return tb
	}

	final := off[K]
	floor := lowerBound(0, 0)
	u := floor + bandSlack
	var bd *band
	var tb []table
	for {
		var ok bool
		if bd, ok = makeBand(u); !ok || !pairsFor(bd) {
			return la, ErrTooLarge
		}
		tb = fill(bd, false)
		c, _, _ := best(tb, at(bd, final, m))
		if int(c) <= u || bd.full {
			break
		}
		next := floor + 2*(u-floor)
		if c < inf {
			next = min(next, int(c))
		}
		u = next
	}
	_, _, la.Optimal = best(tb, at(bd, final, m))
	if hasTwins {
		_, _, la.Optimal = best(fill(bd, true), at(bd, final, m))
	}
	la.Ambiguous = la.Optimal > 1

	// Trace back, keeping both costs on their optimum: pair, then insertion,
	// then deletion, and among pairs the member latest in the trajectory, so
	// a block observed in its own order reads as alignLane would read it.
	// afterDeletion is set when the step taken forward from the current cell
	// was a deletion, which may not follow a flush (layer 0 only).
	var rev []Edit
	emitPair := func(p, j int) {
		c, e := claims[ci[p]], observed[ei[j-1]]
		_, diffs := pairCost(c, e, opts.Expresses, opts.mounts)
		ed := Edit{Kind: EditMatch, ClaimIndex: ci[p], EventIndex: ei[j-1], Claim: &claims[ci[p]], Event: &observed[ei[j-1]]}
		if len(diffs) > 0 {
			ed.Kind, ed.Diffs = EditSubstitution, diffs
		}
		ed.OutsideInterval = outsideInterval(c, e, opts.IntervalSlack)
		ed.Unverified = unverifiedFields(c, e)
		rev = append(rev, ed)
	}
	s, mask, j := K, 0, m
	afterDeletion := false
	for s > 0 || mask != 0 || j > 0 {
		x := off[s] + mask
		cell := at(bd, x, j)
		if cell < 0 {
			return la, errTraceback
		}
		here, hv, _ := best(tb, cell)
		if afterDeletion {
			here, hv = tb[0].cost[cell], tb[0].viol[cell]
		}
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
					p := segs[ps][t]
					code := pairAt(p, j-1)
					if code < 0 {
						continue
					}
					if c, v, _ := best(tb, at(bd, off[ps]+pm, j-1)); c < inf && here == c+int32(code%pairOutside) && hv == v+int32(code/pairOutside) {
						emitPair(p, j)
						s, mask, j = ps, pm, j-1
						moved, afterDeletion = true, false
					}
				}
			}
		}
		if !moved && mask == 0 && s > 0 && (!afterDeletion || fl == 0) {
			for pm := full(s-1) - 1; pm >= 0 && !moved; pm-- {
				if c, v, _ := best(tb, at(bd, off[s-1]+pm, j)); c < inf && here == c+flushCost(s-1, pm) && hv == v {
					for t := size(s-1) - 1; t >= 0; t-- {
						if pm&(1<<t) == 0 {
							p := segs[s-1][t]
							rev = append(rev, Edit{Kind: EditInsertion, ClaimIndex: ci[p], EventIndex: -1, Claim: &claims[ci[p]]})
						}
					}
					s, mask = s-1, pm
					moved, afterDeletion = true, false
				}
			}
		}
		if !moved && j > 0 {
			if y := at(bd, x, j-1); y >= 0 && here == tb[0].cost[y]+costIndel && hv == tb[0].viol[y] {
				rev = append(rev, Edit{Kind: EditDeletion, ClaimIndex: -1, EventIndex: ei[j-1], Event: &observed[ei[j-1]]})
				j--
				moved, afterDeletion = true, true
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
// pair comparison reads (pairCost, contentDiffs, unverifiedFields, the
// adapter's Expresses, which may read the tool, and the harness-implied
// marker with the command it names, V-33), so that exchanging them
// changes no cost and no finding. Time is left out, except for a
// harness-implied claim, whose interval decides whether it may pair at all.
func interchangeable(a, b models.TrajectoryEntry) bool {
	same := a.ActionType == b.ActionType && a.Target == b.Target && a.Tool == b.Tool && a.ImpliedBy == b.ImpliedBy &&
		eqPtr(a.InputHash, b.InputHash) && eqPtr(a.OutputHash, b.OutputHash) &&
		eqPtr(a.ExitCode, b.ExitCode) && eqPtr(a.RequestHash, b.RequestHash)
	if same && implied(a) {
		return a.Timestamp.Equal(b.Timestamp) && eqTime(a.End, b.End)
	}
	return same
}

func eqTime(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equal(*b)
}

func eqPtr[T comparable](a, b *T) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}
