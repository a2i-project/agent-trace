package verification

import (
	"errors"
	"sort"
	"time"

	"github.com/agent-trace/agent-trace/pkg/matching"
	"github.com/agent-trace/agent-trace/pkg/models"
)

// Lane groups the action types that one probe produces. Probes stamp events
// with different clocks and read them at different latencies, so the order of
// a file event against a process event is not reliable. Order within a lane is,
// so claims are aligned lane by lane (V4, with V6's caveat).
type Lane string

const (
	LaneFS    Lane = "fs"
	LaneProc  Lane = "proc"
	LaneNet   Lane = "net"
	LaneOther Lane = "other"
)

// LaneOf returns the lane an action type belongs to.
func LaneOf(a models.ActionType) Lane {
	switch a {
	case models.FileOpen, models.FileRead, models.FileWrite, models.FileClose, models.FileRename, models.FileDelete:
		return LaneFS
	case models.ProcessExec, models.ProcessExit:
		return LaneProc
	case models.NetRequest, models.NetDNS, models.NetConnect:
		return LaneNet
	default:
		return LaneOther
	}
}

// EditKind is one operation of the edit script. The script is the finding
// report (V5).
type EditKind int

const (
	// EditMatch: a claim and an observed action at the same position agree.
	EditMatch EditKind = iota
	// EditSubstitution: they sit at the same position and disagree. The agent
	// described action A where it performed B (attack A3, property P3).
	EditSubstitution
	// EditInsertion: a claim with no observed action. The agent reported
	// something that did not happen (A2, P2).
	EditInsertion
	// EditDeletion: an observed top-level action no claim explains. The agent
	// did something it did not report (A1, P1).
	EditDeletion
)

func (k EditKind) String() string {
	switch k {
	case EditMatch:
		return "match"
	case EditSubstitution:
		return "substitution"
	case EditInsertion:
		return "insertion"
	default:
		return "deletion"
	}
}

// Edit is one step of an alignment.
type Edit struct {
	Kind EditKind
	// ClaimIndex and EventIndex index the slices given to Align. -1 when the
	// side is absent (an insertion has no event, a deletion has no claim).
	ClaimIndex int
	EventIndex int
	Claim      *models.TrajectoryEntry
	Event      *models.GroundTruthEvent
	// Diffs names the fields that disagree in a substitution: DiffTarget,
	// the hash and exit code names, and DiffType when the action types differ.
	Diffs []string
	// OutsideInterval is set when the claim carries an interval and the
	// observed action falls outside it. A finding about the claim, not a
	// reason to refuse the pair (V6).
	OutsideInterval bool
}

// DiffType is reported when a substitution crosses action types within a lane,
// such as a claimed file_read against an observed file_write.
const DiffType = "action_type"

// LaneAlignment is the alignment of one lane.
type LaneAlignment struct {
	Lane  Lane
	Edits []Edit
	// Ambiguous is true when more than one alignment has the minimum cost. The
	// edits shown are one of them, chosen by a fixed rule, and a report that
	// points at one position must not claim the others are excluded.
	Ambiguous bool
	// Optimal is how many minimum-cost alignments exist, saturating.
	Optimal uint32
}

// Options tunes an alignment. The zero value is the strict reading.
type Options struct {
	// IntervalSlack widens a claim's interval on both sides before the
	// containment check. Zero means exact. It exists for a trajectory whose
	// clock is not the kernel's.
	IntervalSlack time.Duration
	// Expresses says whether the trajectory format can state a content field
	// (a Diff* name) for a claim. Nil means everything is expressible, the
	// strict reading. See Expresses and contentDiffs.
	Expresses Expresses
	// IgnoreExits removes process exits from both sides before alignment. It
	// is for a format that cannot state an exit (I-15), where every
	// observed exit would otherwise read as an unreported action.
	IgnoreExits bool
}

// ErrTooLarge is returned when a lane is too large to align in bounded memory.
var ErrTooLarge = errors.New("lane too large to align")

const maxCells = 16 << 20

// Edit costs, doubled so no tie exists between a substitution and an adjacent
// insertion plus deletion. A same-type substitution is cheaper than the pair,
// and a cross-type one is cheaper still than the pair but dearer than a
// same-type one, so the cost model separates a content disagreement from a
// structural one (V5).
const (
	costIndel   = 2
	costSubSame = 2
	costSubType = 3
)

// Align aligns the claim sequence against the observed top-level sequence,
// one lane at a time. Claims keep their order. Observed events are taken in
// the order given, so the caller supplies them in time order (Partition does).
// Pairing is by position: two entries are paired because they sit at
// corresponding places in two causally ordered sequences, and only then is
// their content compared, so a substitution of target is reportable instead of
// reading as a fabrication plus an omission.
func Align(claims models.Trajectory, observed models.GroundTruth, opts Options) ([]LaneAlignment, error) {
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
		la, err := alignLane(l, claims, observed, s.claimIdx, s.eventIdx, opts)
		if err != nil {
			return nil, err
		}
		out = append(out, la)
	}
	return out, nil
}

// pairCost returns the cost of aligning claim c with event e, and the fields
// that differ. Any two entries of one lane can be paired: a different action
// type costs more but is still a substitution.
func pairCost(c models.TrajectoryEntry, e models.GroundTruthEvent, ex Expresses) (cost int, diffs []string) {
	if c.ActionType != e.ActionType {
		return costSubType, append([]string{DiffType}, targetAndContentDiffs(c, e, ex)...)
	}
	diffs = targetAndContentDiffs(c, e, ex)
	if len(diffs) == 0 {
		return 0, nil
	}
	return costSubSame, diffs
}

func targetAndContentDiffs(c models.TrajectoryEntry, e models.GroundTruthEvent, ex Expresses) []string {
	var diffs []string
	if !matching.TargetsMatch(c, e) {
		diffs = append(diffs, DiffTarget)
	}
	if c.ActionType == e.ActionType {
		diffs = append(diffs, contentDiffs(c, e, ex)...)
	}
	return diffs
}

func alignLane(lane Lane, claims models.Trajectory, observed models.GroundTruth, ci, ei []int, opts Options) (LaneAlignment, error) {
	n, m := len(ci), len(ei)
	la := LaneAlignment{Lane: lane}
	if n*m > maxCells || n+1 > maxCells || m+1 > maxCells {
		return la, ErrTooLarge
	}

	w := m + 1
	cost := make([]int32, (n+1)*w)
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
	for i := 1; i <= n; i++ {
		for j := 1; j <= m; j++ {
			pc, _ := pairCost(claims[ci[i-1]], observed[ei[j-1]], opts.Expresses)
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
			var count uint32
			if diag == best {
				count = add(count, ways[(i-1)*w+(j-1)])
			}
			if up == best {
				count = add(count, ways[(i-1)*w+j])
			}
			if left == best {
				count = add(count, ways[i*w+(j-1)])
			}
			cost[i*w+j] = best
			ways[i*w+j] = count
		}
	}
	la.Optimal = ways[n*w+m]
	la.Ambiguous = la.Optimal > 1

	// Trace back with a fixed preference: pair, then insertion, then deletion.
	var rev []Edit
	i, j := n, m
	for i > 0 || j > 0 {
		switch {
		case i > 0 && j > 0 && cost[i*w+j] == cost[(i-1)*w+(j-1)]+int32(pair[(i-1)*m+(j-1)]):
			c, e := claims[ci[i-1]], observed[ei[j-1]]
			_, diffs := pairCost(c, e, opts.Expresses)
			ed := Edit{Kind: EditMatch, ClaimIndex: ci[i-1], EventIndex: ei[j-1], Claim: &claims[ci[i-1]], Event: &observed[ei[j-1]]}
			if len(diffs) > 0 {
				ed.Kind, ed.Diffs = EditSubstitution, diffs
			}
			ed.OutsideInterval = outsideInterval(c, e, opts.IntervalSlack)
			rev = append(rev, ed)
			i--
			j--
		case i > 0 && cost[i*w+j] == cost[(i-1)*w+j]+costIndel:
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

// outsideInterval reports whether an observed action falls outside the claim's
// interval. Only a claim that carries an end has one.
func outsideInterval(c models.TrajectoryEntry, e models.GroundTruthEvent, slack time.Duration) bool {
	if c.End == nil {
		return false
	}
	return e.Timestamp.Before(c.Timestamp.Add(-slack)) || e.Timestamp.After(c.End.Add(slack))
}
