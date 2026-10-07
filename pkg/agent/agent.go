// Package agent isolates everything a harness does differently from the core
// verifier: how its session is read into a trajectory, how observed events are
// rewritten into comparable form, what the harness does on its own, and which
// content fields its format can state. Adding an agent means adding a package
// that implements Adapter and registers itself. pkg/matching and
// pkg/verification contain no agent knowledge.
package agent

import (
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// Adapter is the integration point for one agent harness.
type Adapter interface {
	// Name identifies the agent. A baseline capture is keyed on it.
	Name() string

	// Detect reports whether path is a session artifact this adapter reads, so
	// cmd/verify can choose an adapter without being told.
	Detect(path string) bool

	// Parse reads a session into trajectory entries in claim order. Order is
	// part of the output: the alignment depends on it. Each entry carries its
	// interval, its thread id where subagents were flattened, and its block id
	// where the format issued several calls at once. Report counts what was
	// skipped and why, and never drops silently.
	Parse(path string) (models.Trajectory, Report, error)

	// Normalize rewrites an observed event into the form claims use, for
	// example recovering the claimed command from the harness's wrapper argv.
	// It returns false to drop the event.
	Normalize(models.GroundTruthEvent) (models.GroundTruthEvent, bool)

	// IsHarnessNoise reports events the harness generates on the agent's
	// behalf that belong to neither the trajectory nor the agent's intent.
	// It is what the adapter knows statically. The measured baseline is
	// supplied separately.
	IsHarnessNoise(models.GroundTruthEvent) bool

	// Expresses reports whether the format can state a content field (one of
	// verification.Diff*) for this entry. A nil field is a finding only where
	// it can.
	Expresses(entry models.TrajectoryEntry, field string) bool

	// Process describes how claims map onto the process tree.
	Process() ProcessModel
}

// StreamNormalizer is implemented by an adapter whose observed events can only
// be put into comparable form by looking at several together: a harness that
// writes a file by creating a temporary, writing it and renaming it over the
// target produces five events for what the trajectory calls one write. It runs
// after Normalize, on events in time order with ties in arrival order.
type StreamNormalizer interface {
	NormalizeStream(models.GroundTruth) models.GroundTruth
}

// IntervalKind says what an entry's start timestamp means.
type IntervalKind int

const (
	// IntervalNone: the format reports a point, not an interval.
	IntervalNone IntervalKind = iota
	// IntervalDecision: the start is when the agent decided, and may include
	// approval or queueing latency (Claude Code's tool_use).
	IntervalDecision
	// IntervalExecution: the start is when execution began (Gemini's started).
	IntervalExecution
)

func (k IntervalKind) String() string {
	switch k {
	case IntervalDecision:
		return "decision"
	case IntervalExecution:
		return "execution"
	default:
		return "none"
	}
}

// Concurrency says whether the claim sequence is totally ordered.
type Concurrency int

const (
	// Sequential: one call at a time, so claim order is total.
	Sequential Concurrency = iota
	// Parallel: the harness can issue several calls at once, so entries that
	// share a BlockID have no order among themselves.
	Parallel
	// ConcurrencyUnmeasured: not yet measured for this agent.
	ConcurrencyUnmeasured
)

// ProcessModel describes how an agent's claims map onto the process tree.
type ProcessModel struct {
	// ShellPerCommand: each shell claim execs its own process, so claims align
	// at level 1. False means a persistent shell: no level-1 subtree, and both
	// checks lose their subject.
	ShellPerCommand bool
	// SubagentsInProcess: subagent actions are indistinguishable from
	// main-thread ones in the ground truth, which forces flattening.
	SubagentsInProcess bool
	// Containerized: observed paths and pids live in another namespace from the
	// trajectory's. Not handled by any adapter yet.
	Containerized bool
	// IntervalKind says what the start timestamp means.
	IntervalKind IntervalKind
	// Concurrency says whether the claim sequence is totally ordered.
	Concurrency Concurrency
	// ExitsClaimed is true when the format records process exits, so exits are
	// aligned. False makes the verifier ignore exits on both sides.
	ExitsClaimed bool
}

// Report makes what was not measured visible.
type Report struct {
	// ToolCalls is how many tool invocations the session held.
	ToolCalls int
	// Entries is how many trajectory entries they produced.
	Entries int
	// UnmappedByTool counts tool calls that produced no entry, by tool name.
	// Non-effectful tools are expected here. A tool that is neither mapped nor
	// known to be non-effectful is listed in UnknownTools as well.
	UnmappedByTool map[string]int
	// UnknownTools are tools the adapter has no mapping for and has not
	// declared non-effectful. They may be actions the verifier cannot see.
	UnknownTools []string
	// ParseErrors lists records that could not be read.
	ParseErrors []string
	// Degradations names every precision loss the core must report: a
	// decision-time start, no exit codes, a persistent shell, no baseline.
	Degradations []string
}

// Count records a tool call that produced no entry.
func (r *Report) Count(tool string) {
	if r.UnmappedByTool == nil {
		r.UnmappedByTool = map[string]int{}
	}
	r.UnmappedByTool[tool]++
}

// Prepare turns a capture and an adapter into verification input: observed
// events are normalized, the adapter's noise filter and the measured baseline
// are combined into one baseline, and the adapter's field declarations and
// exit handling become options. measured may be nil.
func Prepare(a Adapter, claims models.Trajectory, g models.GroundTruthFile, measured verification.Baseline, opts verification.Options) verification.Input {
	ground := make(models.GroundTruth, 0, len(g.Events))
	for _, e := range g.Events {
		if n, keep := a.Normalize(e); keep {
			ground = append(ground, n)
		}
	}
	if sn, ok := a.(StreamNormalizer); ok {
		ground = sn.NormalizeStream(ground)
	}
	baseline := func(e models.GroundTruthEvent) bool {
		return a.IsHarnessNoise(e) || (measured != nil && measured(e))
	}
	opts.Expresses = a.Expresses
	opts.IgnoreExits = !a.Process().ExitsClaimed
	return verification.Input{
		Claims:   claims,
		Ground:   ground,
		RootPID:  g.RootPID,
		Coverage: g.Coverage,
		Baseline: baseline,
		Options:  opts,
	}
}
