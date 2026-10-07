package attack

import (
	"fmt"
	"sort"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// Fabricate is attack A2: the agent reports something that did not happen. It
// inserts N claims, each modelled on a claim already in the trajectory (the same
// action type, tool and interval width, with a plausible target of the same
// kind) and each placed between two existing claims, inside the trajectory's own
// span and not appended, so the timeline has no tell. A claim that carries a
// content hash in the donor carries a well-formed hash of nothing real. A
// fabricated target never equals one already claimed of the same type, nor one
// in opt.Avoid, so it cannot be true by accident.
//
// It needs at least two claims to insert between. opt.Select and opt.Indices
// are ignored.
func Fabricate(t models.Trajectory, opt Options) (models.Trajectory, Record, error) {
	if opt.N <= 0 {
		return nil, Record{}, fmt.Errorf("attack: N must be positive, got %d", opt.N)
	}
	if len(t) < 2 {
		return nil, Record{}, fmt.Errorf("%w: a fabricated claim needs two claims to sit between, the trajectory has %d", ErrTooMany, len(t))
	}
	r := newRand(opt.Seed)

	claimed := map[string]bool{}
	for _, e := range t {
		claimed[string(e.ActionType)+"|"+e.Target] = true
	}
	used := map[string]bool{}

	type insertion struct {
		before int // inserted ahead of t[before]
		entry  models.TrajectoryEntry
		donor  int
	}
	var ins []insertion
	for i := 0; i < opt.N; i++ {
		d := r.IntN(len(t))
		donor := t[d]
		target := fakeTarget(r, donor, func(s string) bool {
			return opt.Avoid[s] || claimed[string(donor.ActionType)+"|"+s] || used[string(donor.ActionType)+"|"+s]
		})
		used[string(donor.ActionType)+"|"+target] = true
		e := models.TrajectoryEntry{ActionType: donor.ActionType, Target: target, Tool: donor.Tool}
		if donor.OutputHash != nil {
			h := randomHash(r, "")
			e.OutputHash = &h
		}
		if donor.RequestHash != nil {
			h := randomHash(r, "")
			e.RequestHash = &h
		}
		ins = append(ins, insertion{before: 1 + r.IntN(len(t)-1), entry: e, donor: d})
	}
	sort.SliceStable(ins, func(i, j int) bool { return ins[i].before < ins[j].before })

	rec := Record{Kind: Fabrication, Seed: opt.Seed}
	out := make(models.Trajectory, 0, len(t)+len(ins))
	next := 0
	for i, e := range t {
		// Everything inserted ahead of t[i], spread evenly across the gap.
		var group []insertion
		for next < len(ins) && ins[next].before == i {
			group = append(group, ins[next])
			next++
		}
		for k, g := range group {
			prev, nxt := t[i-1].Timestamp, e.Timestamp
			frac := float64(k+1) / float64(len(group)+1)
			at := prev.Add(time.Duration(float64(nxt.Sub(prev)) * frac))
			fe := g.entry
			fe.Timestamp = at
			if don := t[g.donor]; don.End != nil {
				end := at.Add(don.End.Sub(don.Timestamp))
				fe.End = &end
			}
			rec.Mutations = append(rec.Mutations, Mutation{
				Kind: Fabrication, OriginalIndex: -1, Index: len(out), After: entryPtr(fe),
			})
			out = append(out, fe)
		}
		out = append(out, cloneEntry(e))
	}
	return out, rec, nil
}
