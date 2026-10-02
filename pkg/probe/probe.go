// Package probe defines the contract every ground-truth probe implements:
// Tier 1's filesystem observer (pkg/probe/fs), Tier 2's process observer
// (pkg/probe/proc), and any probe a later tier adds (e.g. a Tier 3 network
// observer). Tooling that runs probes generically, such as cmd/watch, depends
// on this interface instead of any single tier's package.
package probe

import "github.com/agent-trace/agent-trace/pkg/models"

// Observer is a running ground-truth probe. Start begins emitting events in
// the background; Stop releases the probe's resources and closes the channel
// returned by Events. fs.Observer and proc.Observer already satisfy this
// interface structurally, with no changes needed on their side.
type Observer interface {
	Start()
	Stop() error
	Events() <-chan models.GroundTruthEvent
}

// CoverageReporter is implemented by observers that can say what a capture may
// have lost. CaptureCoverage is valid after Stop returns. It is a separate
// interface so Observer stays the minimal contract a probe must meet.
type CoverageReporter interface {
	CaptureCoverage() models.ProbeCoverage
}
