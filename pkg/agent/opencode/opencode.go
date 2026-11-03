// Package opencode adapts OpenCode sessions (its SQLite database of every
// session of the account) to the verifier. See
// docs/architecture/30_agent_adapters.md for the design and the
// measurements behind it.
package opencode

import (
	"strings"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// Name is the adapter's registered name.
const Name = "opencode"

func init() { agent.Register(Adapter{}) }

// Adapter implements agent.Adapter for OpenCode.
type Adapter struct{}

func (Adapter) Name() string { return Name }

// Process, measured on the first capture of 1.19.5 (I-120): every bash
// call execs its own `bash -c <command>` as a child of the harness
// process, subagents run as sessions in the same process (D9), and a
// tool part's start and end bracket the call's execution (the exec, the
// opens and the writes fell inside them on every call). The calls of one
// message run concurrently (I-115). The record states exit codes; they
// are not claimed, as for the other adapters.
func (Adapter) Process() agent.ProcessModel {
	return agent.ProcessModel{
		ShellPerCommand:    true,
		SubagentsInProcess: true,
		IntervalKind:       agent.IntervalExecution,
		Concurrency:        agent.Parallel,
		ExitsClaimed:       false,
	}
}

// Expresses declares what the format can state: a write's or an edit's
// output hash exactly when the adapter claims one (I-121), and no exit
// code, request body or input hash.
func (Adapter) Expresses(e models.TrajectoryEntry, field string) bool {
	switch field {
	case verification.DiffOutputHash:
		return (e.Tool == toolWrite || e.Tool == toolEdit) && e.OutputHash != nil
	case verification.DiffExitCode, verification.DiffRequestHash, verification.DiffInputHash:
		return false
	}
	return true
}

// IsHarnessNoise declares nothing: the controls measure the harness (D11).
func (Adapter) IsHarnessNoise(models.GroundTruthEvent) bool { return false }

// shellPrefixes are the bash call's wrapper as the process probe records
// it: the harness runs `<shell> -c <command>` with the shell of $SHELL,
// /bin/bash in the capture; /usr/bin/bash is the same file on a merged-/usr
// system.
var shellPrefixes = []string{"/bin/bash -c ", "/usr/bin/bash -c "}

// Normalize recovers a bash call's command from its wrapper's command line
// (D6) and drops the kernel's " (deleted)" suffix from a file path. The
// probe joins argv with spaces, so `bash -c 'echo' 'hi'` and
// `bash -c 'echo hi'` recover the same command, as for agy (I-47); what
// the shell ran is its subtree either way. A truncated wrapper gives a
// prefix of the command (V-26).
func (Adapter) Normalize(e models.GroundTruthEvent) (models.GroundTruthEvent, bool) {
	switch {
	case e.ActionType == models.ProcessExec || e.ActionType == models.ProcessExit:
		for _, p := range shellPrefixes {
			if strings.HasPrefix(e.Target, p) && len(e.Target) > len(p) {
				e.Target = e.Target[len(p):]
				break
			}
		}
	case isFile(e.ActionType):
		e.Target = strings.TrimSuffix(e.Target, " (deleted)")
	}
	return e, true
}

func isFile(t models.ActionType) bool {
	switch t {
	case models.FileOpen, models.FileRead, models.FileWrite, models.FileClose, models.FileRename, models.FileDelete:
		return true
	}
	return false
}
