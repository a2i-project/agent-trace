// Package codex adapts Codex CLI sessions (JSONL rollouts) to the verifier.
// See docs/architecture/30_agent_adapters.md for the design and the
// measurements behind it.
package codex

import (
	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// Name is the adapter's registered name.
const Name = "codex"

func init() { agent.Register(Adapter{}) }

// Adapter implements agent.Adapter for Codex.
type Adapter struct{}

func (Adapter) Name() string { return Name }

// The tool names a claim carries (models.TrajectoryEntry.Tool): an
// exec_command's command, and apply_patch's change of one file by its kind.
const (
	toolCommand = "exec_command"
	toolAdd     = "apply_patch:add"
	toolUpdate  = "apply_patch:update"
	toolDelete  = "apply_patch:delete"
)

// Process: every exec_command call is a new child of the harness process
// that execs its own shell (level 1), subagents run as threads of the same
// process (D9), and a claim's start is the moment the model's code-mode cell
// that made the call was recorded, before it ran (D13). The rollout records
// each command's exit code, but the exits are not claimed (I-82).
func (Adapter) Process() agent.ProcessModel {
	return agent.ProcessModel{
		ShellPerCommand:    true,
		SubagentsInProcess: true,
		IntervalKind:       agent.IntervalDecision,
		Concurrency:        agent.Parallel,
		ExitsClaimed:       false,
	}
}

// Expresses declares what the format can state. An added file's record
// holds its whole content, so its write states an output hash; an update's
// record holds only a unified diff, so its write states one only when the
// session recorded the file's whole content before it (I-87), and its nil
// is otherwise the format's (I-82). No exit code (not claimed), no request
// body, no input hash.
func (Adapter) Expresses(e models.TrajectoryEntry, field string) bool {
	switch field {
	case verification.DiffOutputHash:
		return e.Tool == toolAdd || (e.Tool == toolUpdate && e.OutputHash != nil)
	case verification.DiffExitCode, verification.DiffRequestHash, verification.DiffInputHash:
		return false
	}
	return true
}

// IsHarnessNoise declares nothing: the harness's own activity is measured by
// the control runs (D11).
func (Adapter) IsHarnessNoise(models.GroundTruthEvent) bool { return false }

// Normalize recovers the command an exec_command call ran from the
// wrapper's command line (recoverCommand, D6) and drops the kernel's
// " (deleted)" suffix from a file path. Every other event passes through;
// per-run ids are replaced only where runs are compared (Canonical, I-41).
func (Adapter) Normalize(e models.GroundTruthEvent) (models.GroundTruthEvent, bool) {
	switch {
	case e.ActionType == models.ProcessExec || e.ActionType == models.ProcessExit:
		if cmd, ok := recoverCommand(e.Target, e.TargetTruncated); ok {
			e.Target = cmd
		}
	case isFile(e.ActionType):
		e.Target = withoutDeleted(e.Target)
	}
	return e, true
}

// Canonical replaces the per-run ids in the harness's own paths and
// commands with fixed tokens (I-83), where runs are compared
// (agent.Canonicalizer, I-41).
func (Adapter) Canonical(e models.GroundTruthEvent) models.GroundTruthEvent {
	e.Target = canonicalTarget(e.Target)
	return e
}

func withoutDeleted(p string) string {
	const suffix = " (deleted)"
	if len(p) > len(suffix) && p[len(p)-len(suffix):] == suffix {
		return p[:len(p)-len(suffix)]
	}
	return p
}
