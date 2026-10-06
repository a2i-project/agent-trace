package verification

import "github.com/agent-trace/agent-trace/pkg/models"

// Baseline reports whether an observed event is the harness's own activity: the
// model API connection, telemetry, config reads. It is measured by a null-task
// control run, not declared (08 V7). A nil Baseline explains nothing.
type Baseline func(models.GroundTruthEvent) bool

// SubtractBaseline removes the harness's own activity from the aligned
// sequence. A level-0 event the baseline recognises is dropped. A command
// whose exec the baseline recognises is marked, and its exec and exit leave the
// sequence, so no claim is needed for it and it cannot show up as an omission.
// It must run before Align: a baseline event left in the sequence would read as
// something the agent did and did not report.
func (p Partition) SubtractBaseline(b Baseline) (out Partition, subtracted int) {
	out = p
	out.Observed, out.Owner = nil, nil
	if b == nil {
		out.Observed, out.Owner = p.Observed, p.Owner
		return out, 0
	}
	commands := make([]*Command, len(p.Commands))
	copy(commands, p.Commands)
	// Copy-on-write the commands we mark, so p is not mutated.
	replaced := map[*Command]*Command{}
	for i, c := range commands {
		if c.Exec != nil && b(*c.Exec) {
			cc := *c
			cc.Baseline = true
			replaced[c] = &cc
			commands[i] = &cc
		}
	}
	out.Commands = commands
	for i, e := range p.Observed {
		owner := p.Owner[i]
		if owner != nil {
			if replaced[owner] != nil {
				subtracted++ // the baseline command's own exec or exit
				continue
			}
		} else if b(e) {
			subtracted++ // a level-0 baseline event
			continue
		}
		out.Observed = append(out.Observed, e)
		out.Owner = append(out.Owner, owner)
	}
	return out, subtracted
}

// UnexplainedAction is an observed top-level action that no claim explains: a
// deletion in the alignment, which is what an omission looks like (property P1).
type UnexplainedAction struct {
	Event models.GroundTruthEvent
	// Command is set when the action is a command's own exec or exit.
	Command *Command
}

// Coverage is the result of checking that every observed event is explained
// by a claim or by the baseline (08 V3). It is reported apart from the
// alignment, because the two fail for different reasons (V8).
type Coverage struct {
	// UnexplainedActions are the top-level actions no claim aligned to.
	UnexplainedActions []UnexplainedAction
	// UnexplainedSubtrees are the commands whose own exec no claim aligned to,
	// or that never exec'd and did something observable: whole subtrees nothing
	// the agent said accounts for.
	UnexplainedSubtrees []*Command
	// Quiet holds the level-1 processes that never exec'd and caused no
	// observed event. There is nothing in them to explain. Go's os/exec
	// forks one throwaway child per process to probe for pidfd support, and a
	// shell forks subshells that run builtins. Reported, not a finding: the
	// requirement is that every observed event is explained, and none is
	// left unexplained by a process that did nothing.
	Quiet []*Command
	// Explained counts the events inside subtrees of commands a claim explains.
	Explained int
	// Baselined counts the events inside subtrees the baseline explains.
	Baselined int
	// Unknown holds events with no pid, which cannot be placed and so cannot be
	// shown to be explained.
	Unknown models.GroundTruth
	// Outside holds events whose process is not in the agent's tree. They are
	// reported and do not make coverage incomplete: they are not the agent's, as
	// far as the tree can tell.
	Outside models.GroundTruth
	// Complete is true when nothing is unexplained and nothing is unplaced.
	Complete bool
}

// CheckCoverage evaluates coverage from the partition and its alignments. The
// alignments must come from Align over p.Observed, with the baseline already
// subtracted.
func CheckCoverage(p Partition, alignments []LaneAlignment) Coverage {
	cov := Coverage{Unknown: p.Unknown, Outside: p.Outside}

	paired := make([]bool, len(p.Observed))
	for _, la := range alignments {
		for _, e := range la.Edits {
			if e.EventIndex >= 0 && e.Kind != EditDeletion {
				paired[e.EventIndex] = true
			}
		}
	}

	execPaired := map[*Command]bool{}
	for i, ok := range paired {
		if !ok {
			cov.UnexplainedActions = append(cov.UnexplainedActions, UnexplainedAction{Event: p.Observed[i], Command: p.Owner[i]})
			continue
		}
		if c := p.Owner[i]; c != nil && c.Exec != nil && p.Observed[i].ActionType == models.ProcessExec {
			execPaired[c] = true
		}
	}

	for _, c := range p.Commands {
		switch {
		case c.Baseline:
			cov.Baselined += len(c.Content)
		case execPaired[c]:
			cov.Explained += len(c.Content)
		case c.Exec == nil && c.Exit == nil && len(c.Content) == 0:
			cov.Quiet = append(cov.Quiet, c)
		default:
			cov.UnexplainedSubtrees = append(cov.UnexplainedSubtrees, c)
		}
	}
	cov.Complete = len(cov.UnexplainedActions) == 0 && len(cov.UnexplainedSubtrees) == 0 && len(cov.Unknown) == 0
	return cov
}
