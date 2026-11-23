package attack

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// Reordering is attack A5: the agent reports what it did in another order
// than it did it.
const Reordering Kind = "reorder"

// FieldOrder is the Field of a reordering's mutation: Old and New are the
// positions the moved claim left and took.
const FieldOrder = "order"

// The variants of A5.
const (
	// ReorderLane swaps two sequential claims of one lane, each taking the
	// other's start time with its own duration, so the trajectory reads in
	// the new order.
	ReorderLane = "lane"
	// ReorderCrossLane swaps two sequential claims of different lanes, each
	// keeping its own times, so the trajectory's order and its times
	// disagree.
	ReorderCrossLane = "cross_lane"
	// ReorderCrossLaneRetimed swaps two sequential claims of different lanes
	// and rewrites their times as ReorderLane does.
	ReorderCrossLaneRetimed = "cross_lane_retimed"
	// ReorderRegroup swaps two sequential claims adjacent in one lane and
	// gives both a new shared block id, claiming them as one parallel block,
	// whose members may match in any order (V-32); times are rewritten as
	// ReorderLane does.
	ReorderRegroup = "regroup"
)

// ReorderVariants lists the variants in the order the evaluation reports
// them.
var ReorderVariants = []string{ReorderLane, ReorderCrossLane, ReorderCrossLaneRetimed, ReorderRegroup}

// ReorderOptions extends Options with the variant.
type ReorderOptions struct {
	Options
	Variant string
}

// Reorder is attack A5. It makes N swaps of two claims, the variant saying
// which two and what happens to their times and block ids, and records one
// Mutation per swap: OriginalIndex is the earlier position i, Index the later
// position j, Before the claim that stood at i, After that claim as it now
// reads at j, and With the claim that moved from j to i, as it now reads.
//
// Two claims qualify when both are of a lane the probes observe (file,
// process or network), they are sequential (not members of one parallel
// block, whose order is free by design, V-32) and, for a swap within a lane,
// they differ in type, target or content, so the swap changes the claimed
// sequence. A swap across lanes takes two claims with no claim of either
// lane between them, so each lane's own sequence is unchanged and only the
// order across lanes is a lie. Regroup also needs them adjacent in their lane, neither a process
// exit (exits never join a block) and neither sharing its block id with
// another claim, so the new block is exactly the two. opt.Select, when set,
// must admit both. The swaps are disjoint: candidate pairs are shuffled by
// the seed and taken while they share no claim with a pair already taken,
// and fewer than N is ErrTooMany. opt.Indices is not supported.
func Reorder(t models.Trajectory, opt ReorderOptions) (models.Trajectory, Record, error) {
	if err := refuseImplied(t); err != nil {
		return nil, Record{}, err
	}
	switch opt.Variant {
	case ReorderLane, ReorderCrossLane, ReorderCrossLaneRetimed, ReorderRegroup:
	default:
		return nil, Record{}, fmt.Errorf("attack: %q is not a reorder variant (%v)", opt.Variant, ReorderVariants)
	}
	if len(opt.Indices) > 0 {
		return nil, Record{}, errors.New("attack: reorder chooses its pairs; Indices is not supported")
	}
	if opt.N <= 0 {
		return nil, Record{}, fmt.Errorf("attack: N must be positive, got %d", opt.N)
	}
	pairs := reorderPairs(t, opt)
	r := newRand(opt.Seed ^ 0x2545f491)
	r.Shuffle(len(pairs), func(a, b int) { pairs[a], pairs[b] = pairs[b], pairs[a] })
	used := map[int]bool{}
	var chosen [][2]int
	for _, p := range pairs {
		if len(chosen) == opt.N {
			break
		}
		if used[p[0]] || used[p[1]] {
			continue
		}
		used[p[0]], used[p[1]] = true, true
		chosen = append(chosen, p)
	}
	if len(chosen) < opt.N {
		return nil, Record{}, fmt.Errorf("%w: asked for %d disjoint %s swaps, found %d among %d candidate pairs of %d claims", ErrTooMany, opt.N, opt.Variant, len(chosen), len(pairs), len(t))
	}
	// Apply in position order, so the record does not depend on the shuffle
	// beyond which pairs it chose.
	for a := 1; a < len(chosen); a++ {
		for b := a; b > 0 && chosen[b][0] < chosen[b-1][0]; b-- {
			chosen[b], chosen[b-1] = chosen[b-1], chosen[b]
		}
	}
	ids := map[string]bool{}
	for _, e := range t {
		ids[e.BlockID] = true
	}
	out := clone(t)
	rec := Record{Kind: Reordering, Seed: opt.Seed, Variant: opt.Variant}
	for k, p := range chosen {
		i, j := p[0], p[1]
		a, b := cloneEntry(t[i]), cloneEntry(t[j]) // a moves to j, b to i
		if opt.Variant != ReorderCrossLane {
			a, b = retimed(a, t[j]), retimed(b, t[i])
		}
		if opt.Variant == ReorderRegroup {
			id := fmt.Sprintf("reorder-%d-%d", opt.Seed, k)
			for n := 1; ids[id]; n++ {
				id = fmt.Sprintf("reorder-%d-%d-%d", opt.Seed, k, n)
			}
			ids[id] = true
			a.BlockID, b.BlockID = id, id
		}
		out[i], out[j] = b, a
		rec.Mutations = append(rec.Mutations, Mutation{
			Kind: Reordering, OriginalIndex: i, Index: j, Field: FieldOrder, Old: strconv.Itoa(i), New: strconv.Itoa(j),
			Before: entryPtr(t[i]), After: entryPtr(a), With: entryPtr(b),
		})
	}
	return out, rec, nil
}

// retimed returns e moved to the start of the slot it takes, keeping its own
// duration.
func retimed(e models.TrajectoryEntry, slot models.TrajectoryEntry) models.TrajectoryEntry {
	if e.End != nil {
		end := slot.Timestamp.Add(e.End.Sub(e.Timestamp))
		e.End = &end
	}
	e.Timestamp = slot.Timestamp
	return e
}

// reorderPairs lists, in position order, every pair i < j the variant may
// swap.
func reorderPairs(t models.Trajectory, opt ReorderOptions) [][2]int {
	lane := make([]verification.Lane, len(t))
	shared := map[string]int{}
	for i, e := range t {
		lane[i] = verification.LaneOf(e.ActionType)
		if e.BlockID != "" {
			shared[e.BlockID]++
		}
	}
	ok := func(i int) bool {
		return lane[i] != verification.LaneOther && (opt.Select == nil || opt.Select(t[i]))
	}
	var out [][2]int
	for i := range t {
		if !ok(i) {
			continue
		}
		for j := i + 1; j < len(t); j++ {
			if !ok(j) || t[i].BlockID != "" && t[i].BlockID == t[j].BlockID {
				continue
			}
			sameLane := lane[i] == lane[j]
			switch opt.Variant {
			case ReorderLane:
				if !sameLane || !distinguishable(t[i], t[j]) {
					continue
				}
			case ReorderCrossLane, ReorderCrossLaneRetimed:
				// With a claim of either lane between them, the swap would
				// also reorder that lane: a lane swap in disguise.
				if sameLane || !adjacentInLane(lane, i, j) || !adjacentInLane(lane, j, i) {
					continue
				}
			case ReorderRegroup:
				if !sameLane || !distinguishable(t[i], t[j]) || !adjacentInLane(lane, i, j) ||
					t[i].ActionType == models.ProcessExit || t[j].ActionType == models.ProcessExit ||
					t[i].BlockID != "" && shared[t[i].BlockID] > 1 || t[j].BlockID != "" && shared[t[j].BlockID] > 1 {
					continue
				}
			}
			out = append(out, [2]int{i, j})
		}
	}
	return out
}

// adjacentInLane reports whether no claim of the lane of i lies strictly
// between positions i and j, in either order.
func adjacentInLane(lane []verification.Lane, i, j int) bool {
	for k := min(i, j) + 1; k < max(i, j); k++ {
		if lane[k] == lane[i] {
			return false
		}
	}
	return true
}

// distinguishable reports whether two claims differ in type, target or a
// content field, so exchanging them changes the claimed sequence.
func distinguishable(a, b models.TrajectoryEntry) bool {
	return a.ActionType != b.ActionType || a.Target != b.Target || !eqStr(a.InputHash, b.InputHash) ||
		!eqStr(a.OutputHash, b.OutputHash) || !eqStr(a.RequestHash, b.RequestHash) || !eqCode(a.ExitCode, b.ExitCode)
}

func eqStr(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func eqCode(a, b *int32) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}
