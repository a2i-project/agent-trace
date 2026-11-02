package verification

import (
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// startupSettle is how long after the harness's first write of the session's
// transcript its start-up may still read its start-up-only files (V-82).
// Measured on the Claude Code captures of 2.1.296 and 2.1.306 at hand: no
// open of a declared start-up file by the harness came later than this, or
// later than the first claimed call, except one within startupRewrite of its
// own write of that file.
const startupSettle = time.Second

// startupRewrite is how close to a write of a start-up file by the harness's
// own process an open of it stays the harness's after the start-up (V-82):
// the harness reads back a file it just rewrote, such as its stored
// credentials at a token renewal.
const startupRewrite = 2 * time.Second

// StartupBoundary is the end of the harness's start-up as V-82 reads it:
// whichever comes first of startupSettle after the first file_write by the
// agent's own process (level 0) of the session's main trace file
// (TraceDecl.Main) and the start of the first claim. ok is false when the
// rule is off (Options.StartupOnly nil) or neither anchor exists, and
// nothing is then taken from the harness.
func (in Input) StartupBoundary() (time.Time, bool) {
	if in.Options.StartupOnly == nil || in.RootPID == 0 {
		return time.Time{}, false
	}
	var b time.Time
	found := false
	earlier := func(t time.Time) {
		if !found || t.Before(b) {
			b, found = t, true
		}
	}
	if d := in.Trace.Decl; d != nil && d.Main != nil {
		var first time.Time
		seen := false
		for _, e := range in.Ground {
			if e.ActionType != models.FileWrite || e.PID != in.RootPID || e.PathIsAmbiguous || e.TargetTruncated || !d.Main(e.Target) {
				continue
			}
			if !seen || e.Timestamp.Before(first) {
				first, seen = e.Timestamp, true
			}
		}
		if seen {
			earlier(first.Add(startupSettle))
		}
	}
	for _, c := range in.Claims {
		if !c.Timestamp.IsZero() {
			earlier(c.Timestamp)
		}
	}
	return b, found
}

// startupOpens recognises the opens V-82 takes from the harness: a file_open
// by the agent's own process (level 0), with an exact, untruncated name, of a
// file Options.StartupOnly declares, later than StartupBoundary and more
// than startupRewrite away from every write-class event by that process on
// the same target. Nil when the rule is off or no boundary exists.
func startupOpens(in Input) func(models.GroundTruthEvent) bool {
	boundary, ok := in.StartupBoundary()
	if !ok {
		return nil
	}
	declared := in.Options.StartupOnly
	writes := map[string][]time.Time{}
	for _, e := range in.Ground {
		if writeClass(e.ActionType) && e.PID == in.RootPID && !e.PathIsAmbiguous && !e.TargetTruncated && declared(e.Target) {
			writes[e.Target] = append(writes[e.Target], e.Timestamp)
		}
	}
	root := in.RootPID
	return func(e models.GroundTruthEvent) bool {
		if e.ActionType != models.FileOpen || e.PID != root || e.PathIsAmbiguous || e.TargetTruncated || !e.Timestamp.After(boundary) || !declared(e.Target) {
			return false
		}
		for _, w := range writes[e.Target] {
			if d := e.Timestamp.Sub(w); d >= -startupRewrite && d <= startupRewrite {
				return false
			}
		}
		return true
	}
}

// agentsOpens recognises every open the verifier takes from the harness and
// gives to the agent: a late open of a background output file (V-56) and,
// with the rule on, a start-up file's open after the start-up (V-82).
func agentsOpens(in Input) func(models.GroundTruthEvent) bool {
	late := lateOpens(in.Ground, in.Options.BackgroundOutput)
	startup := startupOpens(in)
	switch {
	case startup == nil:
		return late
	case late == nil:
		return startup
	}
	return func(e models.GroundTruthEvent) bool { return late(e) || startup(e) }
}
