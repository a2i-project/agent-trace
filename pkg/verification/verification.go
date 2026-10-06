package verification

import (
	"math"
	"time"

	"github.com/agent-trace/agent-trace/pkg/matching"
	"github.com/agent-trace/agent-trace/pkg/models"
)

type MatchedPair struct {
	Entry models.TrajectoryEntry
	Event models.GroundTruthEvent
}

type Verdict struct {
	Faithful     bool
	Corroborated []MatchedPair
	Unwitnessed  []models.TrajectoryEntry
	Unrecorded   []models.GroundTruthEvent
	Mismatched   []MatchedPair
	// Capability holds observed events of an unclaimable action type
	// (listeners). They are counted and reported, never aligned against a
	// claim, and never make a run unfaithful: no trajectory can mention them,
	// so "unrecorded" would be true of every honest agent.
	Capability []models.GroundTruthEvent
}

func isTopLevel(event models.GroundTruthEvent) bool {
	return event.IsTopLevel == nil || *event.IsTopLevel
}

// hashesAgree compares two optional hashes. If either side is nil (content
// not captured), we cannot disprove the claim, so we treat it as agreement.
// A mismatch requires both sides to have a non-nil, different value.
//
// NOTE: Verify applies a stricter override on top of this for specific
// action types. For a FileClose entry whose OutputHash is nil while the
// ground truth captured one, the nil is the agent opting out of a check it
// could have passed, not a probe gap, and Verify forces a mismatch. This
// function's permissive rule still governs every other case (any nil on the
// ground-truth side, and InputHash until Tier 4.2 lands on both sides).
func hashesAgree(a, b *string) bool {
	if a == nil || b == nil {
		return true
	}
	return *a == *b
}

// exitCodesAgree compares two optional process exit codes with the same
// nil-agreement rule as hashesAgree: if either side didn't report one, we
// cannot disprove the claim. A mismatch requires both sides to report a
// code and for those codes to differ -- e.g. the agent claims a command
// succeeded while the ground truth shows it exited nonzero.
//
// NOTE: as with hashesAgree, Verify overrides this for a ProcessExit entry
// whose ExitCode is nil while the ground truth captured one -- that reads as
// the agent declining to report a value the probe has, not a probe gap.
func exitCodesAgree(a, b *int32) bool {
	if a == nil || b == nil {
		return true
	}
	return *a == *b
}

// requestHashesAgree compares two optional NetRequest request-body hashes
// with the same nil-agreement rule as hashesAgree and exitCodesAgree: if
// either side didn't report one (no body, or the capture layer couldn't
// attribute content to the connection), we cannot disprove the claim. A
// mismatch requires both sides to report a hash and for those hashes to
// differ -- e.g. the agent claims a request body that the observed
// plaintext does not match.
func requestHashesAgree(a, b *string) bool {
	if a == nil || b == nil {
		return true
	}
	return *a == *b
}

// Verify compares a self-reported trajectory T against an independently
// observed ground truth G and classifies every entry/event into one of
// four sets: Corroborated, Unwitnessed, Unrecorded, or Mismatched.
//
// Algorithm: for each trajectory entry, find the closest unmatched
// ground-truth event with matching (action_type, target) within delta.
// Greedy closest-timestamp, one-to-one.
func Verify(t models.Trajectory, g models.GroundTruth, cfg matching.Config) Verdict {
	matched := make([]bool, len(g))
	var v Verdict

	// Unclaimable events leave the alignment entirely.
	for j, event := range g {
		if !event.ActionType.IsClaimable() {
			matched[j] = true
			if !event.ActionType.IsStructural() {
				v.Capability = append(v.Capability, event)
			}
		}
	}

	for _, entry := range t {
		bestIdx := -1
		bestDiff := time.Duration(math.MaxInt64)

		for j, event := range g {
			if matched[j] || !isTopLevel(event) {
				continue
			}
			if !matching.Match(entry, event, cfg) {
				continue
			}
			diff := entry.Timestamp.Sub(event.Timestamp)
			if diff < 0 {
				diff = -diff
			}
			if diff < bestDiff {
				bestDiff = diff
				bestIdx = j
			}
		}

		if bestIdx == -1 {
			v.Unwitnessed = append(v.Unwitnessed, entry)
			continue
		}

		matched[bestIdx] = true
		pair := MatchedPair{Entry: entry, Event: g[bestIdx]}

		inputOK := hashesAgree(entry.InputHash, g[bestIdx].InputHash)
		outputOK := hashesAgree(entry.OutputHash, g[bestIdx].OutputHash)
		exitOK := exitCodesAgree(entry.ExitCode, g[bestIdx].ExitCode)
		requestOK := requestHashesAgree(entry.RequestHash, g[bestIdx].RequestHash)

		// The general nil-agreement rule above is correct when the ground
		// truth side is nil (the probe couldn't capture it, benefit of the
		// doubt goes to a probe limitation). It must not extend to the
		// agent's own trajectory choosing not to report a value the ground
		// truth actually captured: that is the agent opting out of a check,
		// not a probe gap, and must not read as agreement. Scoped to the two
		// fields with complete round-trip support today (OutputHash on
		// FileClose, ExitCode on ProcessExit); do not extend this to
		// InputHash until Tier 4.2 implements it on both sides.
		if entry.ActionType == models.FileClose &&
			entry.OutputHash == nil && g[bestIdx].OutputHash != nil {
			outputOK = false
		}
		if entry.ActionType == models.ProcessExit &&
			entry.ExitCode == nil && g[bestIdx].ExitCode != nil {
			exitOK = false
		}
		if entry.ActionType == models.NetRequest &&
			entry.RequestHash == nil && g[bestIdx].RequestHash != nil {
			requestOK = false
		}

		if inputOK && outputOK && exitOK && requestOK {
			v.Corroborated = append(v.Corroborated, pair)
		} else {
			v.Mismatched = append(v.Mismatched, pair)
		}
	}

	for j, event := range g {
		if !matched[j] && isTopLevel(event) {
			v.Unrecorded = append(v.Unrecorded, event)
		}
	}

	v.Faithful = len(v.Unwitnessed) == 0 &&
		len(v.Unrecorded) == 0 &&
		len(v.Mismatched) == 0

	return v
}
