package attack

import (
	"errors"
	"testing"

	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// A5: every reorder variant over every checked-in capture, 100 seeds of one
// swap each, scored against its record (E-10). The numbers are logged, not
// gated. Beside the rates, each line says which check names a swapped claim:
// the order check (V-106, the swaps classified and located), the interval
// check (V-12), the lifetime comparison (V-105, V-110) and the alignment
// (unwitnessed, mismatched or unrecorded). A cross-lane swap that moves a
// file claim earlier is ordered only by the file event's earliest moment
// (P-52), which a capture made before the fs probe stamped it lacks: those
// swaps are counted apart. A variant a capture does not admit is said, not
// skipped.
func TestReorderBaselinePerVariant(t *testing.T) {
	const seeds = 100
	for _, c := range captures {
		s := loadSession(t, c)
		bounded := fsBounded(s.g.Events)
		for _, variant := range ReorderVariants {
			var tally, unbounded Tally
			notFaithful, outside := 0, 0
			var by struct{ order, interval, lifetime, alignment int }
			for seed := uint64(0); seed < seeds; seed++ {
				mut, rec, err := Reorder(s.claims, ReorderOptions{Options: Options{N: 1, Seed: seed}, Variant: variant})
				if errors.Is(err, ErrTooMany) {
					t.Logf("%s %s: does not apply: %v", c.name, variant, err)
					break
				}
				if err != nil {
					t.Fatalf("%s %s seed %d: %v", c.name, variant, seed, err)
				}
				v := s.verify(mut)
				res := Score(rec, v)
				tally.Add(res)
				for _, mr := range res.Mutations {
					m := mr.Mutation
					if (variant == ReorderCrossLane || variant == ReorderCrossLaneRetimed) && !bounded && verification.LaneOf(m.With.ActionType) == verification.LaneFS {
						unbounded.Add(Result{Mutations: []MutationResult{mr}})
					}
					if mr.Classified {
						by.order++
					}
					if anyClaim(v.OutsideInterval, m) {
						by.interval++
					}
					if anyLifetime(v.Lifetimes.Findings, m) {
						by.lifetime++
					}
					if alignmentNames(v, m) {
						by.alignment++
					}
				}
				if v.Outcome == verification.OutcomeNotFaithful {
					notFaithful++
				}
				if len(v.OutsideInterval) > 0 {
					outside++
				}
			}
			if tally.Runs == 0 {
				continue
			}
			t.Logf("%s %s: %d runs, %d swaps (%d distinct), detected %.3f classified %.3f located %.3f; swaps named by the order check %d, the interval check %d, the lifetime comparison %d, the alignment %d; %d swaps move a file claim earlier on a capture without its earliest moment, classified %d; runs NOT FAITHFUL %d, runs with a claim outside its interval %d, ambiguous alignments %d, unaccounted findings %d%s",
				c.name, variant, tally.Runs, tally.Mutations, tally.Distinct,
				tally.Rate(tally.Detected), tally.Rate(tally.Classified), tally.Rate(tally.Located),
				by.order, by.interval, by.lifetime, by.alignment, unbounded.Mutations, unbounded.Classified,
				notFaithful, outside, tally.Ambiguous, tally.Unaccounted, gating(c))
		}
	}
}

// fsBounded reports whether the capture's fs probe stamped an earliest
// moment (NotBefore) on any file event.
func fsBounded(g models.GroundTruth) bool {
	for _, e := range g {
		if e.NotBefore != nil && verification.LaneOf(e.ActionType) == verification.LaneFS {
			return true
		}
	}
	return false
}

func anyClaim(pairs []verification.MatchedPair, m Mutation) bool {
	for _, p := range pairs {
		if swappedClaim(m, p.Entry) {
			return true
		}
	}
	return false
}

func anyLifetime(fs []verification.LifetimeFinding, m Mutation) bool {
	for _, f := range fs {
		if swappedClaim(m, f.Entry) {
			return true
		}
	}
	return false
}

// alignmentNames reports whether an alignment finding (unwitnessed,
// mismatched, through its candidate set, or unrecorded) is about the swap.
func alignmentNames(v verification.Verdict, m Mutation) bool {
	sets := v.CandidateSets()
	for _, u := range v.Unwitnessed {
		if members := membersOf(sets, "unwitnessed", u, nil); names(members, m.After) || names(members, m.With) {
			return true
		}
	}
	for _, p := range v.Mismatched {
		if members := membersOf(sets, "mismatched", p.Entry, &p.Event); names(members, m.After) || names(members, m.With) {
			return true
		}
	}
	for _, ev := range v.Unrecorded {
		if reorderEvent(m, ev) {
			return true
		}
	}
	return false
}
