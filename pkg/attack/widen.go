package attack

import (
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// Widen is attack A4: a claim's interval is stretched so it spans time it did
// not cover, to make an observed action fall inside it. For each of N entries
// the interval is widened to take in its neighbours: from the previous claim's
// start to the next claim's end (or a second beyond the entry itself at either
// end of the trajectory), so a point claim becomes an interval. Only entries the
// widening changes can be chosen.
//
// It is a mutation of claims, not of what happened, and attribution is by
// ancestry (V1), so a widened interval explains no event that was not already
// explained: its relevance is to the interval check (V-12), and, composed with
// an omission, to whether widening can hide one.
func Widen(t models.Trajectory, opt Options) (models.Trajectory, Record, error) {
	idx, err := choose(t, opt, func(i int, e models.TrajectoryEntry) bool {
		s, en := widened(t, i)
		return !s.Equal(e.Timestamp) || !en.Equal(endOf(e))
	})
	if err != nil {
		return nil, Record{}, err
	}
	out := clone(t)
	rec := Record{Kind: IntervalWidening, Seed: opt.Seed}
	for _, i := range idx {
		before := entryPtr(out[i])
		oldRange := fmtRange(out[i].Timestamp, endOf(out[i]))
		s, en := widened(t, i)
		out[i].Timestamp = s
		end := en
		out[i].End = &end
		rec.Mutations = append(rec.Mutations, Mutation{
			Kind: IntervalWidening, OriginalIndex: i, Index: i, Field: FieldInterval,
			Old: oldRange, New: fmtRange(s, en), Before: before, After: entryPtr(out[i]),
		})
	}
	return out, rec, nil
}

func endOf(e models.TrajectoryEntry) time.Time {
	if e.End != nil {
		return *e.End
	}
	return e.Timestamp
}

// widened returns the interval entry i would have once widened over its
// neighbours.
func widened(t models.Trajectory, i int) (start, end time.Time) {
	e := t[i]
	start, end = e.Timestamp, endOf(e)
	if i > 0 {
		if p := t[i-1].Timestamp; p.Before(start) {
			start = p
		}
	} else {
		start = start.Add(-time.Second)
	}
	if i+1 < len(t) {
		if n := endOf(t[i+1]); n.After(end) {
			end = n
		}
	} else {
		end = end.Add(time.Second)
	}
	return start, end
}

func fmtRange(s, e time.Time) string {
	return s.UTC().Format(time.RFC3339Nano) + ".." + e.UTC().Format(time.RFC3339Nano)
}
