package attack

import (
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// Omit is attack A1: the agent did something and does not say so. It removes N
// entries and returns the trajectory without them. A careful attacker would not
// leave a hole in the timeline, so every later entry is moved earlier by the
// time the removed entry occupied: its own duration if it has an interval,
// otherwise the gap to the next entry. Entry durations are preserved. Time does
// not pair claims with events (V6), so this changes no verdict, and it keeps the
// mutated trajectory realistic for any check that does look at gaps.
func Omit(t models.Trajectory, opt Options) (models.Trajectory, Record, error) {
	idx, err := choose(t, opt, nil)
	if err != nil {
		return nil, Record{}, err
	}
	removed := map[int]bool{}
	for _, i := range idx {
		removed[i] = true
	}

	rec := Record{Kind: Omission, Seed: opt.Seed}
	out := make(models.Trajectory, 0, len(t)-len(idx))
	var shift time.Duration // how far to move the entries that remain, cumulatively
	for i, e := range t {
		if removed[i] {
			rec.Mutations = append(rec.Mutations, Mutation{
				Kind: Omission, OriginalIndex: i, Index: -1, Before: entryPtr(e),
			})
			shift += occupied(t, i)
			continue
		}
		c := cloneEntry(e)
		c.Timestamp = c.Timestamp.Add(-shift)
		if c.End != nil {
			end := c.End.Add(-shift)
			c.End = &end
		}
		out = append(out, c)
	}
	return out, rec, nil
}

// occupied is the time entry i takes up in the timeline: its own interval when
// it has one, else the gap to the next entry, else zero for the last.
func occupied(t models.Trajectory, i int) time.Duration {
	e := t[i]
	if e.End != nil && e.End.After(e.Timestamp) {
		return e.End.Sub(e.Timestamp)
	}
	if i+1 < len(t) && t[i+1].Timestamp.After(e.Timestamp) {
		return t[i+1].Timestamp.Sub(e.Timestamp)
	}
	return 0
}
