package verification

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/agent-trace/agent-trace/pkg/matching"
	"github.com/agent-trace/agent-trace/pkg/models"
)

// checkpointOpens finds the opens with which the harness copies a file the
// session edited into its checkpoint (TraceDecl.Checkpoint, V-104) and
// returns them as events of ground. An open of a file F qualifies when:
//
//   - it is a file_open of the agent's own process (root), with an exact,
//     untruncated name and an input hash;
//   - some in-scope file claim, not harness-implied, wrote F (a file_write,
//     file_close or file_rename claim naming it, or its alias under the
//     capture's mount table) and reported an end before the open's earliest
//     moment (its NotBefore, else its timestamp);
//   - the same process later writes a file W that checkpoint declares a
//     checkpoint version of F, W has an exact, untruncated name no file
//     claim names, and its file_close carries an output hash equal to the
//     open's input hash;
//   - it is the last open of F by that process before W's first event in
//     stream order, so each version explains one open, the one nearest it.
//
// A capture without a root, a version closed without a hash, and an open
// without one take nothing.
func checkpointOpens(checkpoint func(file, written string) bool, ground models.GroundTruth, claims models.Trajectory, claimed map[string]bool, mounts *matching.Mounts, root uint32) models.GroundTruth {
	if checkpoint == nil || root == 0 {
		return nil
	}
	edited := map[string][]time.Time{}
	for _, c := range claims {
		if implied(c) || c.End == nil {
			continue
		}
		switch c.ActionType {
		case models.FileWrite, models.FileClose, models.FileRename:
		default:
			continue
		}
		edited[c.Target] = append(edited[c.Target], *c.End)
		if n, ok := mounts.Canonical(c.Target); ok && n != c.Target {
			edited[n] = append(edited[n], *c.End)
		}
	}
	if len(edited) == 0 {
		return nil
	}
	exact := func(e models.GroundTruthEvent) bool {
		return e.PID == root && !e.PathIsAmbiguous && !e.TargetTruncated
	}
	opens := map[string][]int{}            // path -> indices of its opens
	byHash := map[string]map[string]bool{} // input hash -> paths opened with it
	first := map[string]int{}              // path -> index of its first event
	var closes []int
	for i, e := range ground {
		if !exact(e) || LaneOf(e.ActionType) != LaneFS {
			continue
		}
		if _, ok := first[e.Target]; !ok {
			first[e.Target] = i
		}
		switch e.ActionType {
		case models.FileOpen:
			opens[e.Target] = append(opens[e.Target], i)
			if e.InputHash != nil && len(edited[e.Target]) > 0 {
				if byHash[*e.InputHash] == nil {
					byHash[*e.InputHash] = map[string]bool{}
				}
				byHash[*e.InputHash][e.Target] = true
			}
		case models.FileClose:
			if e.OutputHash != nil && !claimed[e.Target] {
				closes = append(closes, i)
			}
		}
	}
	editedBefore := func(e models.GroundTruthEvent) bool {
		at := e.Timestamp
		if e.NotBefore != nil {
			at = *e.NotBefore
		}
		for _, end := range edited[e.Target] {
			if end.Before(at) {
				return true
			}
		}
		return false
	}
	taken := map[int]bool{}
	for _, ci := range closes {
		w := ground[ci]
		paths := byHash[*w.OutputHash]
		if len(paths) == 0 {
			continue
		}
		names := make([]string, 0, len(paths))
		for f := range paths {
			names = append(names, f)
		}
		sort.Strings(names)
		for _, f := range names {
			if f == w.Target || !checkpoint(f, w.Target) {
				continue
			}
			idx := opens[f]
			k := sort.SearchInts(idx, first[w.Target]) - 1
			if k < 0 {
				continue
			}
			o := ground[idx[k]]
			if o.InputHash != nil && *o.InputHash == *w.OutputHash && editedBefore(o) {
				taken[idx[k]] = true
			}
		}
	}
	if len(taken) == 0 {
		return nil
	}
	out := make(models.GroundTruth, 0, len(taken))
	for i := range ground {
		if taken[i] {
			out = append(out, ground[i])
		}
	}
	return out
}

// setAsideCheckpoints removes from the aligned sequence each level-0 event
// equal to one of the checkpoint opens (checkpointOpens) that no baseline
// rule recognises, one per open, and returns them (V-104). A command's open
// is never level 0 and is not of the root process, so it is never taken.
func (p Partition) setAsideCheckpoints(opens models.GroundTruth, baseline Baseline) (Partition, []models.GroundTruthEvent) {
	if len(opens) == 0 {
		return p, nil
	}
	left := map[string]int{}
	for _, e := range opens {
		left[checkpointKey(e)]++
	}
	out := p
	out.Observed, out.Owner = nil, nil
	var aside []models.GroundTruthEvent
	for i, e := range p.Observed {
		if k := checkpointKey(e); p.Owner[i] == nil && e.ActionType == models.FileOpen && left[k] > 0 && (baseline == nil || !baseline(e)) {
			left[k]--
			aside = append(aside, e)
			continue
		}
		out.Observed = append(out.Observed, e)
		out.Owner = append(out.Owner, p.Owner[i])
	}
	if aside == nil {
		return p, nil
	}
	return out, aside
}

// checkpointKey identifies an open by the fields the probe recorded for it.
func checkpointKey(e models.GroundTruthEvent) string {
	h, nb := "", ""
	if e.InputHash != nil {
		h = *e.InputHash
	}
	if e.NotBefore != nil {
		nb = e.NotBefore.UTC().Format(time.RFC3339Nano)
	}
	return strings.Join([]string{e.Timestamp.UTC().Format(time.RFC3339Nano), string(e.ActionType), e.Target, h, nb, strconv.FormatUint(uint64(e.PID), 10)}, "\x00")
}
