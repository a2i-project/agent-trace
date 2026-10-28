package verification

// The alignment as it was before V-42 banded it, kept as the reference the
// banded program must reproduce edit for edit, count for count. Only tests
// use it.

import (
	"math"
	"sort"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// refAlign is Align before V-42.
func refAlign(claims models.Trajectory, observed models.GroundTruth, opts Options) ([]LaneAlignment, error) {
	type slot struct {
		claimIdx []int
		eventIdx []int
	}
	lanes := map[Lane]*slot{}
	get := func(l Lane) *slot {
		if lanes[l] == nil {
			lanes[l] = &slot{}
		}
		return lanes[l]
	}
	for i, c := range claims {
		s := get(LaneOf(c.ActionType))
		s.claimIdx = append(s.claimIdx, i)
	}
	for j, e := range observed {
		s := get(LaneOf(e.ActionType))
		s.eventIdx = append(s.eventIdx, j)
	}

	names := make([]string, 0, len(lanes))
	for l := range lanes {
		names = append(names, string(l))
	}
	sort.Strings(names)

	var out []LaneAlignment
	for _, name := range names {
		l := Lane(name)
		s := lanes[l]
		la, err := refAlignLane(l, claims, observed, s.claimIdx, s.eventIdx, opts)
		if err != nil {
			return nil, err
		}
		out = append(out, la)
	}
	return out, nil
}

// refAlignLane is alignLane before V-42.
func refAlignLane(lane Lane, claims models.Trajectory, observed models.GroundTruth, ci, ei []int, opts Options) (LaneAlignment, error) {
	n, m := len(ci), len(ei)
	la := LaneAlignment{Lane: lane}
	if n*m > maxCells || n+1 > maxCells || m+1 > maxCells {
		return la, ErrTooLarge
	}
	segs, degr := blockSegments(lane, claims, ci)
	la.Degradations = degr
	for _, s := range segs {
		if len(s) > 1 {
			return refAlignBlocks(la, claims, observed, ci, ei, segs, opts)
		}
	}
	// A harness-implied claim (V-33) needs the block program's handling of an
	// unpaired claim that costs nothing; a lane without one keeps this program.
	for _, i := range ci {
		if implied(claims[i]) {
			return refAlignBlocks(la, claims, observed, ci, ei, segs, opts)
		}
	}

	w := m + 1
	cost := make([]int32, (n+1)*w)
	// viol is the secondary cost: the fewest pairs outside their claim's
	// interval among the minimum-cost alignments of the prefix (V-31). It
	// only chooses between readings that cost the same, so time never makes
	// a reading with a worse content cost win.
	viol := make([]int32, (n+1)*w)
	ways := make([]uint32, (n+1)*w)
	const satur = 1 << 30
	add := func(a, b uint32) uint32 {
		if a+b > satur || a+b < a {
			return satur
		}
		return a + b
	}
	ways[0] = 1
	for i := 1; i <= n; i++ {
		cost[i*w] = int32(i * costIndel)
		ways[i*w] = 1
	}
	for j := 1; j <= m; j++ {
		cost[j] = int32(j * costIndel)
		ways[j] = 1
	}
	pair := make([]int, n*m) // cost of pairing claim i with event j
	outside := func(i, j int) int32 {
		if outsideInterval(claims[ci[i-1]], observed[ei[j-1]], opts.IntervalSlack) {
			return 1
		}
		return 0
	}
	for i := 1; i <= n; i++ {
		for j := 1; j <= m; j++ {
			pc, _ := pairCost(claims[ci[i-1]], observed[ei[j-1]], opts.Expresses, nil)
			pair[(i-1)*m+(j-1)] = pc
			diag := cost[(i-1)*w+(j-1)] + int32(pc)
			up := cost[(i-1)*w+j] + costIndel   // claim i unpaired: insertion
			left := cost[i*w+(j-1)] + costIndel // event j unpaired: deletion
			best := diag
			if up < best {
				best = up
			}
			if left < best {
				best = left
			}
			// The count and the secondary cost run over the predecessors
			// that reach the minimum primary cost only.
			var count uint32
			bestViol := int32(math.MaxInt32)
			if diag == best {
				count = add(count, ways[(i-1)*w+(j-1)])
				bestViol = min(bestViol, viol[(i-1)*w+(j-1)]+outside(i, j))
			}
			if up == best {
				count = add(count, ways[(i-1)*w+j])
				bestViol = min(bestViol, viol[(i-1)*w+j])
			}
			if left == best {
				count = add(count, ways[i*w+(j-1)])
				bestViol = min(bestViol, viol[i*w+(j-1)])
			}
			cost[i*w+j] = best
			viol[i*w+j] = bestViol
			ways[i*w+j] = count
		}
	}
	la.Optimal = ways[n*w+m]
	la.Ambiguous = la.Optimal > 1

	// Trace back through a minimum-cost alignment with the fewest interval
	// violations; among those, a fixed preference: pair, then insertion,
	// then deletion. A step is taken only when it keeps both costs on the
	// optimum, so the reading shown is minimal in both, primary first.
	var rev []Edit
	i, j := n, m
	for i > 0 || j > 0 {
		here, hv := cost[i*w+j], viol[i*w+j]
		switch {
		case i > 0 && j > 0 && here == cost[(i-1)*w+(j-1)]+int32(pair[(i-1)*m+(j-1)]) && hv == viol[(i-1)*w+(j-1)]+outside(i, j):
			c, e := claims[ci[i-1]], observed[ei[j-1]]
			_, diffs := pairCost(c, e, opts.Expresses, nil)
			ed := Edit{Kind: EditMatch, ClaimIndex: ci[i-1], EventIndex: ei[j-1], Claim: &claims[ci[i-1]], Event: &observed[ei[j-1]]}
			if len(diffs) > 0 {
				ed.Kind, ed.Diffs = EditSubstitution, diffs
			}
			ed.OutsideInterval = outsideInterval(c, e, opts.IntervalSlack)
			ed.Unverified = unverifiedFields(c, e)
			rev = append(rev, ed)
			i--
			j--
		case i > 0 && here == cost[(i-1)*w+j]+costIndel && hv == viol[(i-1)*w+j]:
			rev = append(rev, Edit{Kind: EditInsertion, ClaimIndex: ci[i-1], EventIndex: -1, Claim: &claims[ci[i-1]]})
			i--
		default:
			rev = append(rev, Edit{Kind: EditDeletion, ClaimIndex: -1, EventIndex: ei[j-1], Event: &observed[ei[j-1]]})
			j--
		}
	}
	for k := len(rev) - 1; k >= 0; k-- {
		la.Edits = append(la.Edits, rev[k])
	}
	return la, nil
}

// refAlignBlocks is alignBlocks before V-42.
func refAlignBlocks(la LaneAlignment, claims models.Trajectory, observed models.GroundTruth, ci, ei []int, segs [][]int, opts Options) (LaneAlignment, error) {
	n, m := len(ci), len(ei)
	K := len(segs)
	off := make([]int, K+1)
	for s, seg := range segs {
		off[s+1] = off[s] + (1 << len(seg)) - 1
	}
	states := off[K] + 1 // the last is the final state, segment K with mask 0
	w := m + 1
	// fl is the layer a flush writes: 0 when no member is harness-implied, so
	// the program has one layer and reads as before V-33.
	fl, layers := 0, 1
	ins := make([]int32, n)
	for p := range ci {
		ins[p] = int32(insertCost(claims[ci[p]]))
		if implied(claims[ci[p]]) {
			fl, layers = 1, 2
		}
	}
	for _, j := range ei {
		if opts.keptAt(j) {
			fl, layers = 1, 2
		}
	}
	if states > maxCells/w/layers {
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
	// pair holds the cost of pairing claim position p with event j, or -1
	// when the pair is refused (a harness-implied claim, V-33).
	pair := make([]int8, n*m)
	for p := 0; p < n; p++ {
		for j := 0; j < m; j++ {
			pc, ok := pairCostOf(claims[ci[p]], observed[ei[j]], opts.keptAt(ei[j]), opts)
			if !ok {
				pc = -1
			}
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

	// table holds one layer of the program per cell.
	type table struct {
		cost, viol []int32
		ways       []uint32
	}
	// best reads a cell over every layer: the minimum cost, the fewest
	// violations among the paths of that cost, and their count. Layers hold
	// disjoint paths (by their last move), so the counts add.
	best := func(tb []table, y int) (int32, int32, uint32) {
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

	// fill runs the program. With canonical set, a member pairs only after
	// its interchangeable predecessors, so ways counts readings up to
	// exchange; viol is then meaningless.
	fill := func(canonical bool) []table {
		tb := make([]table, layers)
		for l := range tb {
			tb[l] = table{make([]int32, states*w), make([]int32, states*w), make([]uint32, states*w)}
			for x := range tb[l].cost {
				tb[l].cost[x] = inf
			}
		}
		tb[0].cost[0], tb[0].ways[0] = 0, 1
		allowed := func(s, t, before int) bool {
			return !canonical || before&twins[s][t] == twins[s][t]
		}
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
					var a [2]acc
					for l := range a {
						a[l] = acc{c: inf, v: math.MaxInt32}
					}
					pairFrom := func(ps, t, base int) {
						p := segs[ps][t]
						pc := pair[p*m+j-1]
						if pc < 0 {
							return
						}
						y := (off[ps]+base)*w + j - 1
						c, v, wy := best(tb, y)
						if c >= inf {
							return
						}
						consider(&a[0], c+int32(pc), v+outside(p, j), wy)
					}
					if j > 0 {
						// Pair a member with event j.
						if mask != 0 {
							for t := 0; t < size(s); t++ {
								if before := mask &^ (1 << t); mask&(1<<t) != 0 && allowed(s, t, before) {
									pairFrom(s, t, before)
								}
							}
						} else if s > 0 {
							for t := 0; t < size(s-1); t++ {
								if before := full(s-1) &^ (1 << t); allowed(s-1, t, before) {
									pairFrom(s-1, t, before)
								}
							}
						}
					}
					if mask == 0 && s > 0 {
						// Flush: the members of the previous segment left
						// unconsumed are inserted.
						for pm := 0; pm < full(s-1); pm++ {
							y := (off[s-1]+pm)*w + j
							c, v, wy := best(tb, y)
							if c >= inf {
								continue
							}
							consider(&a[fl], c+flushCost(s-1, pm), v, wy)
						}
					}
					if j > 0 {
						// Event j unpaired: a deletion, never straight after a
						// flush (layer 0 only).
						y := x*w + j - 1
						consider(&a[0], tb[0].cost[y]+costIndel, tb[0].viol[y], tb[0].ways[y])
					}
					for l := 0; l < layers; l++ {
						tb[l].cost[x*w+j], tb[l].viol[x*w+j], tb[l].ways[x*w+j] = a[l].c, a[l].v, a[l].wy
					}
				}
			}
		}
		return tb
	}

	final := off[K]
	if hasTwins {
		_, _, ways := best(fill(true), final*w+m)
		la.Optimal = ways
	}
	tb := fill(false)
	if !hasTwins {
		_, _, ways := best(tb, final*w+m)
		la.Optimal = ways
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
		_, diffs := pairCost(c, e, opts.Expresses, nil)
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
		here, hv, _ := best(tb, x*w+j)
		if afterDeletion {
			here, hv = tb[0].cost[x*w+j], tb[0].viol[x*w+j]
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
					y := (off[ps]+pm)*w + j - 1
					p := segs[ps][t]
					pc := pair[p*m+j-1]
					if pc < 0 {
						continue
					}
					if c, v, _ := best(tb, y); c < inf && here == c+int32(pc) && hv == v+outside(p, j) {
						emitPair(p, j)
						s, mask, j = ps, pm, j-1
						moved, afterDeletion = true, false
					}
				}
			}
		}
		if !moved && mask == 0 && s > 0 && (!afterDeletion || fl == 0) {
			for pm := full(s-1) - 1; pm >= 0 && !moved; pm-- {
				y := (off[s-1]+pm)*w + j
				if c, v, _ := best(tb, y); c < inf && here == c+flushCost(s-1, pm) && hv == v {
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
			y := x*w + j - 1
			if here == tb[0].cost[y]+costIndel && hv == tb[0].viol[y] {
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
