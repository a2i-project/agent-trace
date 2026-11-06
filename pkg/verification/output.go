package verification

import (
	"path/filepath"
	"sort"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// outputKey identifies an observed event for the output rule.
type outputKey struct {
	ts   time.Time
	typ  models.ActionType
	path string
	pid  uint32
}

func keyOf(e models.GroundTruthEvent) outputKey {
	return outputKey{e.Timestamp, e.ActionType, e.Target, e.PID}
}

// outputRule is what V-101 decides for the harness's own events on the
// output files of claimed calls: the events it explains as the harness's
// (harness), and the opens it gives the agent (agents). An event in neither
// is left to the rules that applied before V-101 (V-56 for a late open).
type outputRule struct {
	harness map[outputKey]bool
	agents  map[outputKey]bool
}

// decided reports whether the rule decided e, and whether it gave it to the
// agent.
func (r outputRule) decided(e models.GroundTruthEvent) (decided, agents bool) {
	k := keyOf(e)
	if r.agents[k] {
		return true, true
	}
	return r.harness[k], false
}

// harnessOutputs applies V-101. Each file of the declared output family
// (Options.BackgroundOutput) is linked to the claims that own it: the claims
// that name its base name (OutputName), or, for a file no claim names, the
// claims with a reported end and no name whose interval holds the earliest
// moment of the file's first event. On a linked file, the events of the
// agent's own process (RootPID) are:
//   - every write-class event, and every open that began a write (the last
//     open before a write since the previous close): the harness's;
//   - another open whose NotBefore the capture records, when the wall clock
//     did not step and the linked claims report their end: the harness's
//     when NotBefore is no later than the last end, the agent's otherwise;
//   - any other open: undecided.
//
// Events of other processes, ambiguous or truncated events and files no
// claim links are undecided.
func harnessOutputs(in Input) outputRule {
	var r outputRule
	family := in.Options.BackgroundOutput
	if family == nil || in.RootPID == 0 {
		return r
	}
	files := map[string][]models.GroundTruthEvent{}
	for _, e := range in.Ground {
		if LaneOf(e.ActionType) != LaneFS || e.PathIsAmbiguous || e.TargetTruncated || !family(e.Target) {
			continue
		}
		files[e.Target] = append(files[e.Target], e)
	}
	if len(files) == 0 {
		return r
	}
	bounded := !clockStepped(in.Coverage)
	r.harness, r.agents = map[outputKey]bool{}, map[outputKey]bool{}
	for path, events := range files {
		sort.SliceStable(events, func(i, j int) bool { return events[i].Timestamp.Before(events[j].Timestamp) })
		done, linked, known := outputEnd(in.Claims, path, events[0])
		if !linked {
			continue
		}
		var opens []models.GroundTruthEvent
		flush := func(began bool) {
			if began && len(opens) > 0 {
				r.harness[keyOf(opens[len(opens)-1])] = true
				opens = opens[:len(opens)-1]
			}
			for _, o := range opens {
				if !bounded || !known || o.NotBefore == nil {
					continue
				}
				if o.NotBefore.After(done) {
					r.agents[keyOf(o)] = true
				} else {
					r.harness[keyOf(o)] = true
				}
			}
			opens = nil
		}
		for _, e := range events {
			if e.PID != in.RootPID {
				continue
			}
			switch {
			case e.ActionType == models.FileOpen:
				opens = append(opens, e)
			case e.ActionType == models.FileWrite:
				flush(true)
				r.harness[keyOf(e)] = true
			case writeClass(e.ActionType):
				flush(false)
				r.harness[keyOf(e)] = true
			}
		}
		flush(false)
	}
	return r
}

// outputEnd links the output file at path, whose first observed event is
// first, to its claims, and returns the latest end they report. known is
// false when a linked claim reports no end.
func outputEnd(claims models.Trajectory, path string, first models.GroundTruthEvent) (done time.Time, linked, known bool) {
	name := filepath.Base(path)
	known = true
	for _, c := range claims {
		if c.OutputName == "" || c.OutputName != name {
			continue
		}
		linked = true
		if c.OutputDone == nil {
			known = false
		} else if c.OutputDone.After(done) {
			done = *c.OutputDone
		}
	}
	if linked {
		return done, true, known
	}
	earliest := first.Timestamp
	if first.NotBefore != nil && first.NotBefore.Before(earliest) {
		earliest = *first.NotBefore
	}
	for _, c := range claims {
		if c.OutputName != "" || c.OutputDone == nil {
			continue
		}
		if earliest.Before(c.Timestamp) || earliest.After(*c.OutputDone) {
			continue
		}
		linked = true
		if c.OutputDone.After(done) {
			done = *c.OutputDone
		}
	}
	return done, linked, true
}

// clockStepped reports whether the capture's fs probe saw the wall clock
// step (P-52), which makes its NotBefore bounds no bounds.
func clockStepped(cov *models.Coverage) bool {
	if cov == nil {
		return false
	}
	return cov.Probes["fs"].ClockStepped
}
