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

// HarnessOwner is implemented by an adapter that can say which paths belong
// to the harness itself: its configuration, state and cache directories. The
// verifier reports an unexplained level-0 file event there as unexplained
// harness activity, which makes the run INCONCLUSIVE rather than NOT
// FAITHFUL (V-24). It is a declaration of where the harness keeps its own
// files, not of what it does there: nothing is explained by it, so a write
// there by the agent is still reported and still blocks FAITHFUL.
type HarnessOwner interface {
	IsHarnessOwned(path string) bool
}

// HarnessHoster is implemented by an adapter that can name the harness's own
// service hosts: exact host names, as the net probe reports a connection's
// target (its TLS SNI), that the harness itself connects to only sometimes,
// such as an access-token refresh. The verifier reports an unexplained
// level-0 net_connect to exactly one of them as unexplained harness network
// activity, which makes the run INCONCLUSIVE rather than NOT FAITHFUL (V-34).
// Like HarnessOwner it explains nothing: a connection there by a command the
// agent ran stays a finding, and no declared host is a baseline rule. Each
// host is declared from a measured capture (I-52, I-53).
type HarnessHoster interface {
	HarnessHosts() []string
}

// SensitiveDeclarer is implemented by an adapter that can name the harness's
// security-sensitive files: the short list of its settings, permission and
// configuration files whose change by the agent would change what the
// harness lets the agent do. cmd/watch snapshots them at the start and the
// stop of a capture, and the verifier checks what changed against what the
// control runs changed (V-40). Each entry starts with "~/" (the home of the
// user the agent runs as) or "{workspace}/" (the watched directory). Each
// is declared from a measured capture or the harness's own documentation
// (I-59).
type SensitiveDeclarer interface {
	SensitiveFiles() []string
}

// SensitiveFiles is the adapter's declared sensitive files, or nil.
func SensitiveFiles(a Adapter) []string {
	if d, ok := a.(SensitiveDeclarer); ok {
		return d.SensitiveFiles()
	}
	return nil
}

// SensitiveKeyDeclarer is implemented by an adapter one of whose declared
// sensitive files mixes the harness's state (caches, counters, timestamps)
// with its settings. SensitiveKeys returns, for such a file as it is
// declared, the key paths that decide what the harness lets the agent do:
// patterns of dot-separated elements, "*" matching any one element (a
// per-project entry keyed by its directory, say). An unexplained change
// under one of them is a finding; any other unexplained change of the file
// is listed report-only (V-41). Nil for a file that is settings only, whose
// every key path is checked. Each pattern is declared from the harness's
// binary and documentation (I-60).
type SensitiveKeyDeclarer interface {
	SensitiveKeys(file string) []string
}

// SensitiveKeys is the adapter's security-relevant key paths of a declared
// sensitive file, or nil when every key path of it is checked.
func SensitiveKeys(a Adapter, file string) []string {
	if d, ok := a.(SensitiveKeyDeclarer); ok {
		return d.SensitiveKeys(file)
	}
	return nil
}

// Canonicalizer is implemented by an adapter whose observed targets carry ids
// that differ every run: a session id, a pid, a task id in the harness's own
// file paths. Canonical returns the event with those ids replaced by fixed
// tokens. It is applied only where events of different runs are compared:
// when Capture builds rules from control runs and when Prepare matches a
// run's events against them. Pairing a claim with an event, and every other
// comparison within one run, uses the exact target, so a claim names one
// file, not a family of them (I-41).
type Canonicalizer interface {
	Canonical(models.GroundTruthEvent) models.GroundTruthEvent
}

// canonical is the event as it is compared with other runs.
func canonical(a Adapter, e models.GroundTruthEvent) models.GroundTruthEvent {
	if c, ok := a.(Canonicalizer); ok {
		return c.Canonical(e)
	}
	return e
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
	// AgentVersion is the harness version the session records, when the
	// format states one. A baseline holds for one version, so cmd/verify
	// refuses a baseline captured for another.
	AgentVersion string
}

// Count records a tool call that produced no entry.
func (r *Report) Count(tool string) {
	if r.UnmappedByTool == nil {
		r.UnmappedByTool = map[string]int{}
	}
	r.UnmappedByTool[tool]++
}

// NormalizeGround puts observed events into the form claims use: every event
// through the adapter's Normalize, dropping those it rejects, then the whole
// stream through NormalizeStream when the adapter has one. Prepare and the
// baseline's Capture both use it, so a rule is measured on the same shape the
// verifier compares against; a baseline normalized by only one of the two
// steps named the raw temporaries of every atomic write and explained none of
// them.
func NormalizeGround(a Adapter, events models.GroundTruth) models.GroundTruth {
	ground := make(models.GroundTruth, 0, len(events))
	for _, e := range events {
		if n, keep := a.Normalize(e); keep {
			ground = append(ground, n)
		}
	}
	if sn, ok := a.(StreamNormalizer); ok {
		ground = sn.NormalizeStream(ground)
	}
	return ground
}

// Prepare turns a capture and an adapter into verification input: observed
// events are normalized, the adapter's noise filter and the measured baseline
// are combined into one baseline, and the adapter's field declarations and
// exit handling become options. measured may be nil. The measured baseline
// was built from other runs, so it sees each event in its canonical form; the
// events the verifier pairs keep their exact targets (I-41).
func Prepare(a Adapter, claims models.Trajectory, g models.GroundTruthFile, measured verification.Baseline, opts verification.Options) verification.Input {
	ground := NormalizeGround(a, g.Events)
	baseline := func(e models.GroundTruthEvent) bool {
		return a.IsHarnessNoise(e) || (measured != nil && measured(canonical(a, e)))
	}
	opts.Expresses = a.Expresses
	opts.IgnoreExits = !a.Process().ExitsClaimed
	if ho, ok := a.(HarnessOwner); ok {
		opts.HarnessOwned = ho.IsHarnessOwned
	}
	if hh, ok := a.(HarnessHoster); ok {
		opts.HarnessHosts = hh.HarnessHosts()
	}
	return verification.Input{
		Claims:    claims,
		Ground:    ground,
		RootPID:   g.RootPID,
		Coverage:  g.Coverage,
		Baseline:  baseline,
		FSScope:   g.FSScope,
		Workspace: g.Workspace,
		Sensitive: SensitiveInput(a, g, nil),
		Options:   opts,
	}
}

// BaselineSubtree is the baseline's subtree records for a run, in the form
// the verifier asks about them (verification.Input.BaselineSubtree, V-38):
// the command and the event beneath it are compared in their canonical form,
// as rules are. A command the adapter declares harness noise explains its
// whole subtree, as before. Nil when there is no baseline or it records no
// subtrees, which keeps the V7 reading.
func BaselineSubtree(a Adapter, b *Baseline, workspace string) verification.SubtreeBaseline {
	if b == nil {
		return nil
	}
	sub := b.Subtree(workspace)
	if sub == nil {
		return nil
	}
	return func(command, e models.GroundTruthEvent) bool {
		return a.IsHarnessNoise(command) || sub(canonical(a, command), canonical(a, e))
	}
}

// PrepareWithBaseline is Prepare with a measured baseline: its rules as the
// predicate and its subtree records as Input.BaselineSubtree (V-38). b may be
// nil. Prepare given only b.Predicate leaves every baselined command
// explaining its whole subtree, so a caller that holds a Baseline uses this.
func PrepareWithBaseline(a Adapter, claims models.Trajectory, g models.GroundTruthFile, b *Baseline, opts verification.Options) verification.Input {
	var measured verification.Baseline
	if b != nil {
		measured = b.Predicate(g.Workspace)
	}
	in := Prepare(a, claims, g, measured, opts)
	in.BaselineSubtree = BaselineSubtree(a, b, g.Workspace)
	in.Sensitive = SensitiveInput(a, g, b)
	return in
}

// SensitiveInput is the capture's snapshot of the adapter's declared
// sensitive files with the baseline's record of them and the adapter's
// security-relevant key paths of each, as the verifier checks it (V-40,
// V-41). Nil when the capture holds no snapshot or the adapter
// declares no file, which checks and reports nothing. b may be nil, or hold
// no record: the changes are then reported as not checked.
func SensitiveInput(a Adapter, g models.GroundTruthFile, b *Baseline) *verification.SensitiveInput {
	declared := SensitiveFiles(a)
	if g.Sensitive == nil || len(declared) == 0 {
		return nil
	}
	in := &verification.SensitiveInput{}
	var baselined map[string]bool
	if b != nil && b.Sensitive != nil {
		in.Explained = b.SensitiveExplained(g.Workspace)
		baselined = map[string]bool{}
		for _, f := range b.Sensitive.Files {
			baselined[f] = true
		}
	}
	for _, d := range declared {
		sf := verification.SensitiveFile{File: d, Baselined: baselined[d], Keys: SensitiveKeys(a, d)}
		if f := snapshotFile(g.Sensitive, d); f != nil {
			sf.Path, sf.Recorded, sf.Start, sf.Stop = f.Path, true, f.Start.State, f.Stop.State
			for _, c := range f.Changes {
				sf.Changes = append(sf.Changes, verification.SensitiveChange{File: d, Path: f.Path, SensitiveChange: c})
			}
		}
		in.Files = append(in.Files, sf)
	}
	return in
}
