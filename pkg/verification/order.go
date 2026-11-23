package verification

import (
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// OrderViolation is a claim whose observed events all happened, certainly,
// before an observed event of the claim it says came before it (V-106): an
// order finding about the later claim.
type OrderViolation struct {
	// Earlier and Later are the two claims, in claim order.
	Earlier models.TrajectoryEntry
	Later   models.TrajectoryEntry
	// EarlierEvent is the earlier claim's event that certainly began after
	// every event of the later claim ended, and LaterEvent the later claim's
	// event that ended last.
	EarlierEvent models.GroundTruthEvent
	LaterEvent   models.GroundTruthEvent
}

// bounds are the earliest and the latest moment an observed event can have
// happened. A file event happened between its NotBefore and its Timestamp
// (P-52); one without a NotBefore has no known earliest moment (bounded
// false). Process and network events are points.
type bounds struct {
	lo, hi  time.Time
	bounded bool
}

func boundsOf(e models.GroundTruthEvent) bounds {
	if LaneOf(e.ActionType) != LaneFS {
		return bounds{lo: e.Timestamp, hi: e.Timestamp, bounded: true}
	}
	if e.NotBefore == nil {
		return bounds{hi: e.Timestamp}
	}
	lo := *e.NotBefore
	if lo.After(e.Timestamp) {
		lo = e.Timestamp
	}
	return bounds{lo: lo, hi: e.Timestamp, bounded: true}
}

// orderClaim is one claim as the order check reads it: its thread, its
// parallel block, and the events attributed to it with their bounds.
type orderClaim struct {
	thread, block string
	events        []bounds
}

// orderPair is a violation found by orderViolations: the index of the
// earlier and the later claim, and of the event of each that shows it.
type orderPair struct {
	earlier, later           int
	earlierEvent, laterEvent int
}

// orderViolations checks each thread's claims in claim order (V-106, V-107).
// Consecutive claims sharing a non-empty block form one segment, whose
// members have no order among themselves (V-32); every other claim is a
// segment alone. Segments with no event are passed over. For two
// consecutive segments, each member of the later is checked against each
// member of the earlier: it is a violation when some event of the earlier
// claim began, at its earliest moment, after every event of the later claim
// had ended, at its latest. Each later claim is reported once, against the
// earlier claim whose event began last. Claims of different threads are not
// ordered.
func orderViolations(claims []orderClaim) []orderPair {
	// latest returns the claim's event with the latest upper bound and the
	// one with the latest known lower bound, -1 for none.
	latest := func(c orderClaim) (hi, lo int) {
		hi, lo = -1, -1
		for k, b := range c.events {
			if hi < 0 || b.hi.After(c.events[hi].hi) {
				hi = k
			}
			if b.bounded && (lo < 0 || b.lo.After(c.events[lo].lo)) {
				lo = k
			}
		}
		return hi, lo
	}
	type segment []int
	threads := map[string][]segment{}
	var order []string
	for i, c := range claims {
		if len(c.events) == 0 {
			continue
		}
		segs, seen := threads[c.thread]
		if !seen {
			order = append(order, c.thread)
		}
		// A member of a block joins the segment before it only when that
		// segment is the same block and no claim of the thread came
		// between, which the passed-over claims without events do not
		// break when they belong to the block too.
		if n := len(segs); n > 0 && c.block != "" && claims[segs[n-1][0]].block == c.block && contiguous(claims, segs[n-1][len(segs[n-1])-1], i) {
			segs[n-1] = append(segs[n-1], i)
		} else {
			segs = append(segs, segment{i})
		}
		threads[c.thread] = segs
	}
	var out []orderPair
	for _, t := range order {
		segs := threads[t]
		for s := 1; s < len(segs); s++ {
			for _, y := range segs[s] {
				yHi, _ := latest(claims[y])
				best, bestEv := -1, -1
				for _, x := range segs[s-1] {
					_, xLo := latest(claims[x])
					if xLo < 0 || !claims[x].events[xLo].lo.After(claims[y].events[yHi].hi) {
						continue
					}
					if best < 0 || claims[x].events[xLo].lo.After(claims[best].events[bestEv].lo) {
						best, bestEv = x, xLo
					}
				}
				if best >= 0 {
					out = append(out, orderPair{earlier: best, later: y, earlierEvent: bestEv, laterEvent: yHi})
				}
			}
		}
	}
	return out
}

// contiguous reports whether every claim strictly between i and j in claim
// order that belongs to the same thread as j also belongs to j's block.
func contiguous(claims []orderClaim, i, j int) bool {
	for k := i + 1; k < j; k++ {
		if claims[k].thread == claims[j].thread && claims[k].block != claims[j].block {
			return false
		}
	}
	return true
}

// checkOrder builds what the order check reads from the alignment and the
// partition, and returns its violations (V-106). A claim's events are the
// event it paired with, matched or substituted, and, when that event is a
// command's own exec, the command's exit and every event beneath it that
// can have happened by that exit. A background call (V-108) and a command
// whose exit the capture does not hold contribute their exec only: their
// later events may run beside the claims after them. Harness-implied
// claims are not the agent's and are left out.
func checkOrder(claims models.Trajectory, alignments []LaneAlignment, part Partition) []OrderViolation {
	oc := make([]orderClaim, len(claims))
	evs := make([][]models.GroundTruthEvent, len(claims))
	for i, c := range claims {
		oc[i] = orderClaim{thread: c.ThreadID, block: c.BlockID}
	}
	add := func(i int, e models.GroundTruthEvent) {
		oc[i].events = append(oc[i].events, boundsOf(e))
		evs[i] = append(evs[i], e)
	}
	for _, la := range alignments {
		for _, e := range la.Edits {
			if e.Kind != EditMatch && e.Kind != EditSubstitution {
				continue
			}
			claim := claims[e.ClaimIndex]
			if implied(claim) {
				continue
			}
			add(e.ClaimIndex, *e.Event)
			c := part.Owner[e.EventIndex]
			if c == nil || c.Exec == nil || claim.Background || e.Event.ActionType != models.ProcessExec || !sameEvent(*c.Exec, *e.Event) || c.Exit == nil {
				continue
			}
			add(e.ClaimIndex, *c.Exit)
			for _, ev := range c.Content {
				if b := boundsOf(ev); !b.bounded || !b.lo.After(c.Exit.Timestamp) {
					add(e.ClaimIndex, ev)
				}
			}
		}
	}
	var out []OrderViolation
	for _, p := range orderViolations(oc) {
		out = append(out, OrderViolation{
			Earlier: claims[p.earlier], Later: claims[p.later],
			EarlierEvent: evs[p.earlier][p.earlierEvent], LaterEvent: evs[p.later][p.laterEvent],
		})
	}
	return out
}
