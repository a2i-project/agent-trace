package verification

import (
	"sort"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// Command is one level-1 subtree: what the agent started, and everything that
// happened beneath it.
type Command struct {
	Process *Process
	// Exec is the command's own exec record, the observed action a claim is
	// aligned against. Nil if the process never exec'd (a fork with no exec).
	Exec *models.GroundTruthEvent
	// Exit is the command's own exit record, if one was captured.
	Exit *models.GroundTruthEvent
	// Content is every other claimable event in the subtree: later execs of
	// the same process, descendants' execs and exits, and every file and
	// network event of the subtree. Attributed and counted, never aligned
	// against a claim (08 D3).
	Content models.GroundTruth
	// Baseline is set when the harness baseline explains this command, so no
	// claim is needed for it (08 V7). See Partition.SubtractBaseline.
	Baseline bool
}

// AttributedEvent is an event with its place in the tree.
type AttributedEvent struct {
	Event models.GroundTruthEvent
	Attribution
}

// Partition splits ground truth into the part that is aligned against claims
// and the parts that are not.
type Partition struct {
	// Observed is the top-level sequence: the agent's own events (level 0) and
	// each command's own exec and exit, in time order, claimable types only.
	// This is what claims are aligned against (08 V4).
	Observed models.GroundTruth
	// Owner is parallel to Observed: the command whose own exec or exit an
	// observed event is, or nil for a level-0 event.
	Owner []*Command
	// Commands are the level-1 subtrees in creation order.
	Commands []*Command
	// Outside holds events whose process is not in the agent's tree. They do
	// not explain a claim and are not an omission by the agent.
	Outside models.GroundTruth
	// Unknown holds events carrying no pid, which cannot be placed.
	Unknown models.GroundTruth
	// Capability holds listener and socket events (unclaimable, not
	// structural) with their place in the tree. They are counted and kept as
	// the record of what a subtree could do, never aligned.
	Capability []AttributedEvent
}

// Partition attributes every event of g and sorts it into its part. Structural
// events (fork records) are consumed by the forest and appear nowhere here.
func (f *Forest) Partition(g models.GroundTruth) Partition {
	var part Partition
	byCommand := map[*Process]*Command{}
	for _, p := range f.Commands() {
		c := &Command{Process: p}
		byCommand[p] = c
		part.Commands = append(part.Commands, c)
	}

	events := make([]models.GroundTruthEvent, len(g))
	copy(events, g)
	sort.SliceStable(events, func(i, j int) bool { return events[i].Timestamp.Before(events[j].Timestamp) })

	for _, e := range events {
		if e.ActionType.IsStructural() {
			continue
		}
		a := f.Attribute(e)
		if !e.ActionType.IsClaimable() {
			part.Capability = append(part.Capability, AttributedEvent{Event: e, Attribution: a})
			continue
		}
		switch a.Zone {
		case ZoneUnknown:
			part.Unknown = append(part.Unknown, e)
		case ZoneOutside:
			part.Outside = append(part.Outside, e)
		case ZoneAgent:
			part.Observed = append(part.Observed, e)
			part.Owner = append(part.Owner, nil)
		case ZoneSubtree:
			c := byCommand[a.Command]
			own := a.Process == a.Command
			switch {
			case own && e.ActionType == models.ProcessExec && c.Exec == nil:
				ev := e
				c.Exec = &ev
				part.Observed = append(part.Observed, e)
				part.Owner = append(part.Owner, c)
			case own && e.ActionType == models.ProcessExit && c.Exit == nil:
				ev := e
				c.Exit = &ev
				part.Observed = append(part.Observed, e)
				part.Owner = append(part.Owner, c)
			default:
				c.Content = append(c.Content, e)
			}
		}
	}
	return part
}

// DropExits removes every process exit from the aligned sequence. A format
// that cannot state an exit has no claim to align them with, so each observed
// exit would read as an unreported action. Commands keep their Exit field: the
// exit is still known, it is only not checked against a claim.
func (p Partition) DropExits() Partition {
	out := p
	out.Observed, out.Owner = nil, nil
	for i, e := range p.Observed {
		if e.ActionType == models.ProcessExit {
			continue
		}
		out.Observed = append(out.Observed, e)
		out.Owner = append(out.Owner, p.Owner[i])
	}
	return out
}
