package attack

import (
	"errors"
	"testing"

	"github.com/agent-trace/agent-trace/pkg/verification"
)

// A5, the baseline before the order layers: every reorder variant over every
// checked-in capture, 100 seeds of one swap each, scored against its record.
// The numbers are logged, not gated: they are what the verifier detects
// without an order check, and the order layers change them by design. A
// variant a capture does not admit is said, not skipped.
func TestReorderBaselinePerVariant(t *testing.T) {
	const seeds = 100
	for _, c := range captures {
		s := loadSession(t, c)
		for _, variant := range ReorderVariants {
			var tally Tally
			notFaithful, outside := 0, 0
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
			t.Logf("%s %s: %d runs, %d swaps (%d distinct), detected %.3f classified %.3f located %.3f, runs NOT FAITHFUL %d, runs with a claim outside its interval %d, ambiguous alignments %d, unaccounted findings %d%s",
				c.name, variant, tally.Runs, tally.Mutations, tally.Distinct,
				tally.Rate(tally.Detected), tally.Rate(tally.Classified), tally.Rate(tally.Located),
				notFaithful, outside, tally.Ambiguous, tally.Unaccounted, gating(c))
		}
	}
}
