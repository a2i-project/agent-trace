package attack

import (
	"fmt"
	"strconv"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// Field names a substitution can change.
const (
	FieldTarget      = "target"
	FieldOutputHash  = "output_hash"
	FieldExitCode    = "exit_code"
	FieldRequestHash = "request_hash"
	FieldInterval    = "interval"
)

// SubstituteOptions extends Options with the field to change.
type SubstituteOptions struct {
	Options
	// Field restricts the change to one field. Empty means each chosen entry
	// takes a random field it has. An entry without the requested field cannot
	// be chosen.
	Field string
}

// Substitute is attack A3: the agent describes one action where it performed
// another. For each of N entries it replaces one field with a benign variant: a
// sibling file or a no-op command or an ordinary host for the target, a
// different value for a content hash or a request hash, a different exit code.
// The entry keeps its place, type and interval, so only its content is wrong,
// which is exactly the case where pairing by position finds the entry and the
// comparison reports the disagreement. A replacement never equals the original
// or a target in opt.Avoid.
func Substitute(t models.Trajectory, opt SubstituteOptions) (models.Trajectory, Record, error) {
	switch opt.Field {
	case "", FieldTarget, FieldOutputHash, FieldExitCode, FieldRequestHash:
	default:
		return nil, Record{}, fmt.Errorf("attack: %q is not a substitutable field", opt.Field)
	}
	has := func(e models.TrajectoryEntry, f string) bool {
		switch f {
		case FieldTarget:
			return true
		case FieldOutputHash:
			return e.OutputHash != nil
		case FieldExitCode:
			return e.ExitCode != nil
		case FieldRequestHash:
			return e.RequestHash != nil
		}
		return false
	}
	idx, err := choose(t, opt.Options, func(_ int, e models.TrajectoryEntry) bool {
		return opt.Field == "" || has(e, opt.Field)
	})
	if err != nil {
		return nil, Record{}, err
	}
	r := newRand(opt.Seed ^ 0x5bd1e995)
	forbidden := func(s string) bool { return opt.Avoid[s] }

	out := clone(t)
	rec := Record{Kind: Substitution, Seed: opt.Seed}
	for _, i := range idx {
		e := &out[i]
		field := opt.Field
		if field == "" {
			var fields []string
			for _, f := range []string{FieldTarget, FieldOutputHash, FieldExitCode, FieldRequestHash} {
				if has(*e, f) {
					fields = append(fields, f)
				}
			}
			field = fields[r.IntN(len(fields))]
		}
		before := entryPtr(*e)
		var oldV, newV string
		switch field {
		case FieldTarget:
			oldV, newV = e.Target, benignTarget(r, *e, forbidden)
			e.Target = newV
		case FieldOutputHash:
			oldV = *e.OutputHash
			newV = randomHash(r, oldV)
			e.OutputHash = &newV
		case FieldRequestHash:
			oldV = *e.RequestHash
			newV = randomHash(r, oldV)
			e.RequestHash = &newV
		case FieldExitCode:
			oldV = strconv.Itoa(int(*e.ExitCode))
			c := *e.ExitCode + 1
			e.ExitCode = &c
			newV = strconv.Itoa(int(c))
		}
		rec.Mutations = append(rec.Mutations, Mutation{
			Kind: Substitution, OriginalIndex: i, Index: i, Field: field, Old: oldV, New: newV,
			Before: before, After: entryPtr(*e),
		})
	}
	return out, rec, nil
}
