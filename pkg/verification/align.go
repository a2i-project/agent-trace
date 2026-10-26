package verification

import (
	"errors"
	"sort"
	"strings"
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
	// reason to refuse the pair (V6). It chooses only between alignments of
	// equal cost (V-31).
	OutsideInterval bool
	// Unverified names the content fields the claim states and the observed
	// event does not carry, so the pair could be neither confirmed nor
	// refuted on them. Not a finding; it keeps FAITHFUL from being asserted
	// (V-22).
	Unverified []string
}

// DiffType is reported when a substitution crosses action types within a lane,
// such as a claimed file_read against an observed file_write.
const DiffType = "action_type"

// LaneAlignment is the alignment of one lane.
type LaneAlignment struct {
	Lane  Lane
	Edits []Edit
	// Ambiguous is true when more than one alignment has the minimum cost. The
	// edits shown are one of them: the one with the fewest pairs outside their
	// claim's interval, then a fixed rule (V-31). A report that points at one
	// position must not claim the others are excluded.
	Ambiguous bool
	// Optimal is how many minimum-cost alignments exist, saturating. With
	// parallel blocks (V-32) an alignment is a pairing: which claim pairs
	// with which event. Orderings of a block that give the same pairing count
	// once; two pairings that differ count twice, even when the claims they
	// exchange are identical, since the report names entries.
	Optimal uint32
	// Degradations names each place where the lane was aligned more strictly
	// than V-32 allows: a block over the cap, a block whose claims are not
	// contiguous, exit claims that carry a block id. The strict reading can
	// add an order finding, never remove one.
	Degradations []string
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
	// HarnessOwned says whether a path belongs to the harness's own
	// directories (its configuration, state and cache), as declared by the
	// adapter. An unexplained level-0 file event there is reported as
	// unexplained harness activity and makes the run INCONCLUSIVE rather
	// than NOT FAITHFUL: the harness does some things only sometimes, and a
	// baseline measured on a few control runs misses them (V-24). Nil
	// declares nothing.
	HarnessOwned func(path string) bool
	// HarnessHosts are the harness's own service hosts, as declared by the
	// adapter: exact host names, compared with the target the net probe
	// gives a connection that sent its name (the TLS SNI). An unexplained
	// level-0 net_connect to exactly one of them is reported as unexplained
	// harness network activity and makes the run INCONCLUSIVE rather than NOT
	// FAITHFUL (V-34). An entry that is not a host name (empty, an IP
	// address, or holding a colon, a slash, a bracket or a space) is ignored,
	// so a declaration never covers a connection known only by its address.
	// Nil declares nothing.
	HarnessHosts []string
	// HarnessCommand recognises the exec of a command the adapter declares
	// as the harness's own and which the harness starts only sometimes, such
	// as a probe for a package manager: true when the exec event is exactly
	// one of the declared command lines as the harness itself started it.
	// A level-1 command whose own exec it recognises, that no baseline rule
	// explains and whose command line no process_exec claim names, is
	// reported as an unexplained harness command and makes the run
	// INCONCLUSIVE rather than NOT FAITHFUL; the events beneath it must be
	// what the controls' same command did, as for a baselined command, or it
	// is an unexplained subtree (V-43). Nil declares nothing.
	HarnessCommand func(models.GroundTruthEvent) bool

	// impliedWitness says whether the command a harness-implied claim names
	// opened the claim's file no later than the event (V-33). Verify sets it
	// from the process tree. Nil, as when Align is called on its own, leaves
	// only the other conditions of impliedPairs.
	impliedWitness func(c models.TrajectoryEntry, e models.GroundTruthEvent) bool
}

// implied reports whether a claim is harness-implied (V-33): marked by an
// adapter and a file open. A marker on any other type is ignored, so the
// claim is aligned as an ordinary one.
func implied(c models.TrajectoryEntry) bool {
	return c.ImpliedBy != "" && c.ActionType == models.FileOpen
}

// insertCost is the cost of leaving a claim unpaired: an ordinary claim is a
// fabrication (V-10), a harness-implied one costs nothing, since the harness
// may not have acted (V-33).
func insertCost(c models.TrajectoryEntry) int {
	if implied(c) {
		return 0
	}
	return costIndel
}

// impliedPairs reports whether a harness-implied claim may pair with an
// event (V-33): only an open of exactly the path it names, not a directory
// record or a truncated one, that agrees on content and states nothing the
// claim cannot check, inside the claim's interval, and, under Verify, opened
// first by the command the claim names. Any other pairing is refused, so a
// harness-implied claim is never Mismatched, never outside its interval and
// never unverified.
func impliedPairs(c models.TrajectoryEntry, e models.GroundTruthEvent, opts Options) bool {
	if e.ActionType != models.FileOpen || e.Target != c.Target || e.PathIsAmbiguous || e.TargetTruncated {
		return false
	}
	if len(contentDiffs(c, e, opts.Expresses)) > 0 || len(unverifiedFields(c, e)) > 0 {
		return false
	}
	if outsideInterval(c, e, opts.IntervalSlack) {
		return false
	}
	return opts.impliedWitness == nil || opts.impliedWitness(c, e)
}

// pairCostOf is pairCost with V-33's refusal: ok is false when the claim is
// harness-implied and may not pair with the event. An ordinary claim pairs
// with any event of its lane.
func pairCostOf(c models.TrajectoryEntry, e models.GroundTruthEvent, opts Options) (cost int, ok bool) {
	if implied(c) {
		return 0, impliedPairs(c, e, opts)
	}
	return pairCostOnly(c, e, opts.Expresses), true
}

// pairCostOnly is pairCost's cost without its list of diffs, which the
// program does not need for a cell and would allocate for every pair that
// differs.
func pairCostOnly(c models.TrajectoryEntry, e models.GroundTruthEvent, ex Expresses) int {
	if c.ActionType != e.ActionType {
		return costSubType
	}
	// Equal targets match whatever the normalization; the test spares the
	// path cleaning for the common pair.
	if c.Target != e.Target && !matching.TargetsMatch(c, e) && !truncatedPrefix(c, e) || len(contentDiffs(c, e, ex)) > 0 {
		return costSubSame
	}
	return 0
}

// ErrTooLarge is returned when a lane is too large to align in bounded memory.
var ErrTooLarge = errors.New("lane too large to align")

// maxCells bounds the cells of one lane's program per layer (V-42): about
// 192 MiB of tables per layer at the limit. A variable only so that tests can
// reach the limit with a small lane.
var maxCells = 16 << 20

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

// maxBlock is the largest parallel block, counted in claims of one lane, whose
// claims the alignment lets match in any order (V-32). It is the harness's
// concurrency limit of 10 calls per message. A larger block is aligned in the
// order the trajectory gives it, with a degradation.
const maxBlock = 10

// Align aligns the claim sequence against the observed top-level sequence,
// one lane at a time. Claims keep their order, except that the claims of one
// parallel block (a run of claims sharing a BlockID) may match in any order
// among themselves; every claim of an earlier block still precedes every
// claim of a later one (V-32). Observed events are taken in the order given,
// so the caller supplies them in time order (Partition does). Pairing is by
// position: two entries are paired because they sit at corresponding places
// in two causally ordered sequences, and only then is their content
// compared, so a substitution of target is reportable instead of reading as a
// fabrication plus an omission.
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
	if !matching.TargetsMatch(c, e) && !truncatedPrefix(c, e) {
		diffs = append(diffs, DiffTarget)
	}
	if c.ActionType == e.ActionType {
		diffs = append(diffs, contentDiffs(c, e, ex)...)
	}
	return diffs
}

// alignLane aligns one lane: its claims are cut into segments (a parallel
// block or one claim) and aligned by alignBlocks, which with one-claim
// segments is the ordered alignment.
func alignLane(lane Lane, claims models.Trajectory, observed models.GroundTruth, ci, ei []int, opts Options) (LaneAlignment, error) {
	la := LaneAlignment{Lane: lane}
	segs, degr := blockSegments(lane, claims, ci)
	la.Degradations = degr
	return alignBlocks(la, claims, observed, ci, ei, segs, opts)
}

// truncatedPrefix reports whether the observed target is a truncated record
// whose text is a prefix of the claim's target. The probe could not record
// the rest, so the pair is not a mismatch; it is unverified beyond the cap
// (unverifiedFields, V-26).
func truncatedPrefix(c models.TrajectoryEntry, e models.GroundTruthEvent) bool {
	return e.TargetTruncated && c.ActionType == e.ActionType && e.Target != "" && strings.HasPrefix(c.Target, e.Target)
}

// outsideInterval reports whether an observed action falls outside the claim's
// interval. Only a claim that carries an end has one.
func outsideInterval(c models.TrajectoryEntry, e models.GroundTruthEvent, slack time.Duration) bool {
	if c.End == nil {
		return false
	}
	return e.Timestamp.Before(c.Timestamp.Add(-slack)) || e.Timestamp.After(c.End.Add(slack))
}
