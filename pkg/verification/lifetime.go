package verification

import (
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// Lifetime is the observed interval of one command (V-105): from its own
// first exec to its own exit, both stamped by the proc probe. A descendant
// that outlives the command, such as a server it started with `&`, does not
// extend it: the call the agent reports is the command, and its harness
// returns when the command's own process ends.
type Lifetime struct {
	// Start is the timestamp of the command's own exec.
	Start time.Time
	// End is the timestamp of the command's own exit. Zero when Ended is
	// false: the capture holds no exit, because the command was still
	// running when the capture stopped or the record was lost.
	End   time.Time
	Ended bool
}

// Lifetime returns the command's observed interval, and false when the
// command never exec'd, which leaves it no start to measure from.
func (c *Command) Lifetime() (Lifetime, bool) {
	if c == nil || c.Exec == nil {
		return Lifetime{}, false
	}
	l := Lifetime{Start: c.Exec.Timestamp}
	if c.Exit != nil {
		l.End, l.Ended = c.Exit.Timestamp, true
	}
	return l, true
}

// LifetimeTolerance is how far a claimed interval may extend beyond its
// command's lifetime, on either side, before the extension is reported
// (V-105). On 912 command claims of the checked-in fixtures and the private
// captures of four harnesses, the exec followed the claimed start by at most
// 1.7 s (harness start-up after the model's decision) and the claimed end
// followed the exit by at most 1.1 s (reporting delay, and a Codex cell's
// interval shared by its commands); the tolerance is about three times the
// larger. The clock slack (Options.IntervalSlack) is added to it.
const LifetimeTolerance = 5 * time.Second

// Lifetime discrepancy kinds (LifetimeFinding.Kind).
const (
	// LifetimeRanLonger: the command exited after the claimed end, so the
	// claim reports a shorter command than ran.
	LifetimeRanLonger = "ran_longer"
	// LifetimeStartsEarly: the claimed start precedes the command's exec by
	// more than the tolerance.
	LifetimeStartsEarly = "starts_early"
	// LifetimeEndsLate: the claimed end follows the command's exit by more
	// than the tolerance.
	LifetimeEndsLate = "ends_late"
)

// LifetimeFinding is one claim whose interval disagrees with its command's
// observed lifetime (V-105).
type LifetimeFinding struct {
	Entry    models.TrajectoryEntry
	Lifetime Lifetime
	Kind     string
	// By is how far the claimed interval passes the bound the kind names:
	// for LifetimeRanLonger, how long the command ran past the claimed end
	// plus the slack; for the others, how far the interval extends beyond
	// the lifetime plus the tolerance and the slack.
	By time.Duration
}

// LifetimeCheck is what the comparison of claimed intervals with observed
// lifetimes did (V-105).
type LifetimeCheck struct {
	// SharedShell is set when the adapter declares that its commands share
	// a persistent shell (Options.SharedShell): no claim has a lifetime of
	// its own, and nothing is compared.
	SharedShell bool
	// Compared counts the command claims compared on both sides, and
	// StartOnly those compared on their start only: a background call,
	// whose interval says nothing about its end (V-108), or a command whose
	// exit the capture does not hold.
	Compared, StartOnly int
	// NoEnd counts the command claims paired with a command whose claim
	// states no end: a point says nothing about a duration.
	NoEnd int
	// NoSubtree counts the claims with no command to measure: every claim
	// not paired with a command's own exec (an in-process action, an
	// unwitnessed command, a harness-implied claim).
	NoSubtree int
	// Slack is the clock slack the comparison added to the tolerance
	// (Options.IntervalSlack).
	Slack    time.Duration
	Findings []LifetimeFinding
}

// checkLifetimes compares each claim paired with a command's own exec with
// that command's lifetime (V-105). A claim whose exec lies before its start
// is already outside its interval (V6); this adds the end and the widening.
func checkLifetimes(claims models.Trajectory, alignments []LaneAlignment, part Partition, sharedShell bool, slack time.Duration) LifetimeCheck {
	out := LifetimeCheck{Slack: slack}
	if sharedShell {
		out.SharedShell = true
		out.NoSubtree = len(claims)
		return out
	}
	paired := map[int]*Command{}
	for _, la := range alignments {
		for _, e := range la.Edits {
			if (e.Kind != EditMatch && e.Kind != EditSubstitution) || e.Event.ActionType != models.ProcessExec || implied(*e.Claim) {
				continue
			}
			if c := part.Owner[e.EventIndex]; c != nil && c.Exec != nil && sameEvent(*c.Exec, *e.Event) {
				paired[e.ClaimIndex] = c
			}
		}
	}
	for i, claim := range claims {
		c := paired[i]
		if c == nil {
			out.NoSubtree++
			continue
		}
		l, _ := c.Lifetime()
		if claim.End == nil {
			out.NoEnd++
			continue
		}
		if f, bad := startsEarly(claim, l, slack); bad {
			out.Findings = append(out.Findings, f)
		}
		if claim.Background || !l.Ended {
			out.StartOnly++
			continue
		}
		out.Compared++
		end := *claim.End
		switch {
		case l.End.After(end.Add(slack)):
			out.Findings = append(out.Findings, LifetimeFinding{Entry: claim, Lifetime: l, Kind: LifetimeRanLonger, By: l.End.Sub(end.Add(slack))})
		case end.After(l.End.Add(LifetimeTolerance + slack)):
			out.Findings = append(out.Findings, LifetimeFinding{Entry: claim, Lifetime: l, Kind: LifetimeEndsLate, By: end.Sub(l.End.Add(LifetimeTolerance + slack))})
		}
	}
	return out
}

// startsEarly reports a claimed start that precedes the command's exec by
// more than the tolerance and the slack.
func startsEarly(claim models.TrajectoryEntry, l Lifetime, slack time.Duration) (LifetimeFinding, bool) {
	bound := claim.Timestamp.Add(LifetimeTolerance + slack)
	if !l.Start.After(bound) {
		return LifetimeFinding{}, false
	}
	return LifetimeFinding{Entry: claim, Lifetime: l, Kind: LifetimeStartsEarly, By: l.Start.Sub(bound)}, true
}

// sameEvent reports whether two records are the same observed event: the
// same process, type, time and target.
func sameEvent(a, b models.GroundTruthEvent) bool {
	return a.PID == b.PID && a.ActionType == b.ActionType && a.Timestamp.Equal(b.Timestamp) && a.Target == b.Target
}
