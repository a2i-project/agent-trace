package verification

import "github.com/agent-trace/agent-trace/pkg/models"

// Baseline reports whether an observed event is the harness's own activity: the
// model API connection, telemetry, config reads. It is measured by a null-task
// control run, not declared (V7). A nil Baseline explains nothing.
type Baseline func(models.GroundTruthEvent) bool

// SubtreeBaseline reports whether event, beneath a command whose exec the
// Baseline recognised, is something the same command also did beneath it in
// the control runs (V-38). It is asked only about the action types
// SubtreeChecked names. A nil SubtreeBaseline is a baseline that recorded no
// subtrees: a baselined command then explains its whole subtree, as V7 had it.
type SubtreeBaseline func(command, event models.GroundTruthEvent) bool

// SubtreeChecked reports whether an event of this type beneath a baselined
// command must be one the controls' same command also produced (V-38): a
// program run, a file written, closed after writing, renamed or deleted, a
// connection or a request. Reads, exits and capability evidence beneath a
// baselined command stay explained by the command, as before.
func SubtreeChecked(t models.ActionType) bool {
	switch t {
	case models.ProcessExec, models.NetConnect, models.NetRequest:
		return true
	}
	return writeClass(t)
}

// checkBaselinedSubtrees sets, on every baselined command with an exec, the
// events beneath it of a checked type that sub does not recognise
// (Command.Unbaselined, V-38). It copies the commands it changes. A nil sub
// leaves every subtree explained.
func (p Partition) checkBaselinedSubtrees(sub SubtreeBaseline) Partition {
	if sub == nil {
		return p
	}
	out := p
	out.Commands = make([]*Command, len(p.Commands))
	copy(out.Commands, p.Commands)
	for i, c := range out.Commands {
		if !c.Baseline || c.Exec == nil {
			continue
		}
		var unbaselined models.GroundTruth
		for _, e := range c.Content {
			if SubtreeChecked(e.ActionType) && !sub(*c.Exec, e) {
				unbaselined = append(unbaselined, e)
			}
		}
		if len(unbaselined) > 0 {
			cc := *c
			cc.Unbaselined = unbaselined
			out.Commands[i] = &cc
		}
	}
	// Owner points at the commands of the aligned sequence; a baselined
	// command's exec and exit have left it, so no owner needs remapping.
	return out
}

// SubtractBaseline removes the harness's own activity from the aligned
// sequence. A level-0 event the baseline recognises is dropped, unless it is a
// file event on a path in claimed: that one stays, so a claim on a path the
// harness also touches, such as a Read of a background command's output file,
// can pair with it, and Verify counts it as baselined if it stays unpaired
// (V-30). A command whose exec the baseline recognises is marked, and its exec
// and exit leave the sequence, so no claim is needed for it and it cannot show
// up as an omission. It must run before Align: a baseline event left in the
// sequence would read as something the agent did and did not report.
func (p Partition) SubtractBaseline(b Baseline, claimed map[string]bool) (out Partition, subtracted int) {
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
		} else if b(e) && !onClaimedPath(e, claimed) {
			subtracted++ // a level-0 baseline event no claim names
			continue
		}
		out.Observed = append(out.Observed, e)
		out.Owner = append(out.Owner, owner)
	}
	return out, subtracted
}

// onClaimedPath reports whether e is a file event on a path some claim names.
func onClaimedPath(e models.GroundTruthEvent, claimed map[string]bool) bool {
	return LaneOf(e.ActionType) == LaneFS && claimed[e.Target]
}

// UnexplainedAction is an observed top-level action that no claim explains: a
// deletion in the alignment, which is what an omission looks like (property P1).
type UnexplainedAction struct {
	Event models.GroundTruthEvent
	// Command is set when the action is a command's own exec or exit.
	Command *Command
}

// Coverage is the result of checking that every observed event is explained
// by a claim or by the baseline (V3). It is reported apart from the
// alignment, because the two fail for different reasons (V8).
type Coverage struct {
	// UnexplainedActions are the top-level actions no claim aligned to.
	UnexplainedActions []UnexplainedAction
	// UnexplainedSubtrees are the commands whose own exec no claim aligned to,
	// or that never exec'd and did something observable: whole subtrees nothing
	// the agent said accounts for. A baselined command is here too when events
	// beneath it are not what the controls' same command did
	// (Command.Unbaselined, V-38), and so is a declared harness command
	// whose subtree is not what the controls' same command did (V-43).
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
	// Baselined counts the events inside subtrees the baseline explains. A
	// baselined command's Unbaselined events are not counted: the command is
	// in UnexplainedSubtrees instead (V-38).
	Baselined int
	// BaselinedLevelZero counts the agent process's own (level-0) events the
	// baseline explains: those subtracted before alignment and those kept for
	// a claim on their path that stayed unpaired (V-30). Verify sets it;
	// CheckCoverage leaves it zero. Baselined does not include them.
	BaselinedLevelZero int
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
		case c.Baseline && len(c.Unbaselined) > 0:
			cov.Baselined += len(c.Content) - len(c.Unbaselined)
			cov.UnexplainedSubtrees = append(cov.UnexplainedSubtrees, c)
		case c.Baseline:
			cov.Baselined += len(c.Content)
		case c.Harness && len(c.Unbaselined) > 0:
			// A declared harness command whose subtree is not what the
			// controls' same command did (V-43).
			cov.UnexplainedSubtrees = append(cov.UnexplainedSubtrees, c)
		case c.Harness:
			// Reported apart in Verdict.UnexplainedHarnessCommands (V-43).
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

// setAsideHarnessCommands marks every level-1 command whose own exec the
// adapter's declaration recognises (Options.HarnessCommand), that no baseline
// rule explains and whose command line no process_exec claim names exactly
// (claimed), as a declared harness command, removes its exec and exit from
// the aligned sequence, and returns the marked commands (V-43). On each it
// sets Unbaselined to the events beneath it of a checked type
// (SubtreeChecked) that sub does not hold for it, so its subtree is explained
// only where it is what the controls' same command did, as V-38 has it for a
// baselined command; with a nil sub nothing is recorded and every checked
// event beneath it is unbaselined. A command whose exec is truncated is never
// marked. It copies the commands it changes.
func (p Partition) setAsideHarnessCommands(recognise func(models.GroundTruthEvent) bool, claimed map[string]bool, sub SubtreeBaseline) (Partition, []*Command) {
	if recognise == nil {
		return p, nil
	}
	out := p
	out.Commands = make([]*Command, len(p.Commands))
	copy(out.Commands, p.Commands)
	marked := map[*Command]bool{}
	var aside []*Command
	for i, c := range out.Commands {
		if c.Baseline || c.Exec == nil || c.Exec.TargetTruncated || claimed[c.Exec.Target] || !recognise(*c.Exec) {
			continue
		}
		cc := *c
		cc.Harness = true
		cc.Unbaselined = nil
		for _, e := range c.Content {
			if SubtreeChecked(e.ActionType) && (sub == nil || !sub(*c.Exec, e)) {
				cc.Unbaselined = append(cc.Unbaselined, e)
			}
		}
		out.Commands[i] = &cc
		marked[c] = true
		aside = append(aside, &cc)
	}
	if len(aside) == 0 {
		return p, nil
	}
	out.Observed, out.Owner = nil, nil
	for i, e := range p.Observed {
		if marked[p.Owner[i]] {
			continue // the declared command's own exec or exit
		}
		out.Observed = append(out.Observed, e)
		out.Owner = append(out.Owner, p.Owner[i])
	}
	return out, aside
}

// claimedCommands is the set of command lines the process_exec claims name.
func claimedCommands(claims models.Trajectory) map[string]bool {
	set := map[string]bool{}
	for _, c := range claims {
		if c.ActionType == models.ProcessExec {
			set[c.Target] = true
		}
	}
	return set
}
