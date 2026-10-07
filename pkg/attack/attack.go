// Package attack generates the manipulations an evaluation needs: reusable,
// recorded mutations of a trajectory, one generator per attack of the threat
// model. A1 omission drops claims, A2 fabrication inserts claims that did not
// happen, A3 substitution replaces a claim's target or content with a benign
// variant, and A4 interval widening stretches a claim's interval over time it
// did not cover. Each generator returns the mutated trajectory and a Record of
// what it changed, so an evaluation can check that a finding lands on the entry
// that was mutated and is classified as the attack it was.
//
// Generators work on the normalized models.Trajectory, so they apply to any
// agent whose adapter produces claims. Randomness is a seed given by the caller,
// so a mutation is reproducible from its record. The input trajectory is never
// modified. Asking for more mutations than the trajectory admits is an error,
// not a silent partial result.
package attack

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"sort"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// Kind names an attack.
type Kind string

const (
	Omission         Kind = "omission"
	Fabrication      Kind = "fabrication"
	Substitution     Kind = "substitution"
	IntervalWidening Kind = "interval_widening"
)

// ErrTooMany is returned when more mutations are requested than the trajectory
// admits. The error wraps the counts.
var ErrTooMany = errors.New("attack: more mutations requested than the trajectory admits")

// Options selects what a generator mutates.
type Options struct {
	// N is how many entries to mutate (or, for fabrication, to insert).
	N int
	// Seed makes the choice reproducible. The same trajectory, options and seed
	// give the same mutation.
	Seed uint64
	// Select restricts which entries may be chosen. Nil means every entry.
	// Fabrication ignores it: it chooses where to insert, not what to mutate.
	Select func(models.TrajectoryEntry) bool
	// Indices names the entries to mutate explicitly, by position in the input.
	// It overrides N and Select, so an evaluation can compose attacks on known
	// entries. Out-of-range or repeated indices are an error.
	Indices []int
	// Retime makes Omit close the hole an omission leaves in the timeline by
	// moving later claims earlier. It is off by default: the verifier's clock is
	// real, so a claim moved off its real time falls outside the interval it
	// states and is reported (V-12), which makes the attack easier to catch. It
	// exists to measure exactly that. Only Omit reads it.
	Retime bool
	// Avoid lists targets a generator must not produce (fabrication and
	// substitution), for example every target observed in the capture, so a
	// fabricated claim cannot happen to be true.
	Avoid map[string]bool
}

// Mutation is one change, with enough to check a verdict against it.
type Mutation struct {
	Kind Kind
	// OriginalIndex is the entry's position in the input, or -1 for an inserted
	// entry. Index is its position in the output, or -1 for a removed entry.
	OriginalIndex int
	Index         int
	// Field names what changed in a substitution or a widening (target,
	// output_hash, exit_code, request_hash, interval). Empty for an omission or
	// a fabrication.
	Field string
	// Old and New are the field's value before and after, as text.
	Old, New string
	// Before is the original entry (nil for a fabrication) and After the
	// mutated or inserted one (nil for an omission).
	Before *models.TrajectoryEntry
	After  *models.TrajectoryEntry
}

// Record is what a generator did.
type Record struct {
	Kind      Kind
	Seed      uint64
	Mutations []Mutation
}

func newRand(seed uint64) *rand.Rand {
	return rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
}

// clone deep-copies a trajectory, so a generator never aliases its input.
func clone(t models.Trajectory) models.Trajectory {
	out := make(models.Trajectory, len(t))
	for i, e := range t {
		out[i] = cloneEntry(e)
	}
	return out
}

func cloneEntry(e models.TrajectoryEntry) models.TrajectoryEntry {
	if e.End != nil {
		end := *e.End
		e.End = &end
	}
	if e.InputHash != nil {
		h := *e.InputHash
		e.InputHash = &h
	}
	if e.OutputHash != nil {
		h := *e.OutputHash
		e.OutputHash = &h
	}
	if e.ExitCode != nil {
		c := *e.ExitCode
		e.ExitCode = &c
	}
	if e.RequestHash != nil {
		h := *e.RequestHash
		e.RequestHash = &h
	}
	return e
}

func entryPtr(e models.TrajectoryEntry) *models.TrajectoryEntry {
	c := cloneEntry(e)
	return &c
}

// choose returns the positions to mutate, in ascending order. Explicit indices
// win. Otherwise it draws N distinct positions from the entries Select admits,
// restricted further by ok, and fails if there are fewer than N.
func choose(t models.Trajectory, opt Options, ok func(int, models.TrajectoryEntry) bool) ([]int, error) {
	if len(opt.Indices) > 0 {
		seen := map[int]bool{}
		for _, i := range opt.Indices {
			if i < 0 || i >= len(t) {
				return nil, fmt.Errorf("attack: index %d is outside the trajectory of %d entries", i, len(t))
			}
			if seen[i] {
				return nil, fmt.Errorf("attack: index %d given twice", i)
			}
			seen[i] = true
			if ok != nil && !ok(i, t[i]) {
				return nil, fmt.Errorf("attack: entry %d (%s %s) cannot be mutated this way", i, t[i].ActionType, t[i].Target)
			}
		}
		out := append([]int(nil), opt.Indices...)
		sort.Ints(out)
		return out, nil
	}
	if opt.N <= 0 {
		return nil, fmt.Errorf("attack: N must be positive, got %d", opt.N)
	}
	var candidates []int
	for i, e := range t {
		if opt.Select != nil && !opt.Select(e) {
			continue
		}
		if ok != nil && !ok(i, e) {
			continue
		}
		candidates = append(candidates, i)
	}
	if opt.N > len(candidates) {
		return nil, fmt.Errorf("%w: asked for %d, %d candidate entries of %d", ErrTooMany, opt.N, len(candidates), len(t))
	}
	r := newRand(opt.Seed)
	r.Shuffle(len(candidates), func(i, j int) { candidates[i], candidates[j] = candidates[j], candidates[i] })
	out := candidates[:opt.N]
	sort.Ints(out)
	return out, nil
}
