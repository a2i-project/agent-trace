package verification

import (
	"sort"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// Zone says where an observed event sits relative to the agent's process tree.
type Zone int

const (
	// ZoneUnknown: the event carries no pid, so it cannot be placed. Legacy
	// ground truth is entirely unknown.
	ZoneUnknown Zone = iota
	// ZoneOutside: the event's process is not a descendant of the agent, or
	// the chain to it is broken. Not the agent's activity as far as the tree
	// can tell.
	ZoneOutside
	// ZoneAgent: level 0, the agent process itself.
	ZoneAgent
	// ZoneSubtree: level 1 and below, inside the subtree of one command.
	ZoneSubtree
)

func (z Zone) String() string {
	switch z {
	case ZoneAgent:
		return "agent"
	case ZoneSubtree:
		return "subtree"
	case ZoneOutside:
		return "outside"
	default:
		return "unknown"
	}
}

// Process is one incarnation of a pid. A pid can be reused after its process
// exits, so a pid names several incarnations over a capture and time picks
// between them (see Forest.Resolve). Time is used for nothing else here.
type Process struct {
	PID   uint32
	PPID  uint32
	Start time.Time
	// Parent is the incarnation that created this one. Nil for the agent and
	// for a process whose parent was never observed.
	Parent *Process
	// Level is 0 for the agent, 1 for a child of the agent (the root of one
	// claimed command), 2 and below for its descendants. -1 means the chain
	// to the agent is broken.
	Level int
	// Command is the level-1 ancestor of this process (itself for level 1).
	// Nil for the agent and for processes outside the tree.
	Command *Process
	// Exec is the first exec event of this process, if it exec'd.
	Exec *models.GroundTruthEvent
}

// Attribution places one event in the tree.
type Attribution struct {
	Zone Zone
	// Level is 0 for the agent, >= 1 inside a command's subtree, -1 otherwise.
	Level int
	// Process is the incarnation that caused the event. Nil for the agent
	// itself, for outside events and for unknown ones.
	Process *Process
	// Command is the level-1 process whose subtree contains the event.
	Command *Process
}

// Forest is the process tree of one capture, rooted at the agent (V1).
type Forest struct {
	RootPID uint32
	agent   *Process
	procs   map[uint32][]*Process // per pid, ascending by Start
	ordered []*Process            // creation order
}

// BuildForest builds the tree from the structural events of g. A process
// enters the tree through its fork record, which every tracked child has,
// whether or not it ever execs. The parent edge is the one recorded at
// creation, so a process that outlives its parent, or is reparented, stays
// under the command that created it. An exec record fills in the command, and
// stands in for the fork record only in legacy ground truth that has none.
func BuildForest(g models.GroundTruth, rootPID uint32) *Forest {
	f := &Forest{
		RootPID: rootPID,
		agent:   &Process{PID: rootPID, Level: 0},
		procs:   map[uint32][]*Process{},
	}

	// Stable by time, so records with equal stamps keep their arrival order.
	events := make([]models.GroundTruthEvent, len(g))
	copy(events, g)
	sort.SliceStable(events, func(i, j int) bool { return events[i].Timestamp.Before(events[j].Timestamp) })

	var execs []models.GroundTruthEvent
	for _, e := range events {
		switch {
		case e.ActionType == models.ProcessFork && e.PID != 0:
			f.add(&Process{PID: e.PID, PPID: e.PPID, Start: e.Timestamp})
		case e.ActionType == models.ProcessExec && e.PID != 0:
			execs = append(execs, e)
		}
	}
	for _, e := range execs {
		if p := f.lookup(e.PID, e.Timestamp); p != nil {
			if p.Exec == nil {
				ev := e
				p.Exec = &ev
			}
			continue
		}
		// No fork record covers this exec (legacy ground truth, or a record
		// that was lost). The exec's own ppid is the best edge available.
		ev := e
		f.add(&Process{PID: e.PID, PPID: e.PPID, Start: e.Timestamp, Exec: &ev})
	}

	// Link in creation order so a parent is placed before its children. A
	// legacy exec-only process is appended after the fork-born ones, so the
	// order is restored by time first.
	sort.SliceStable(f.ordered, func(i, j int) bool { return f.ordered[i].Start.Before(f.ordered[j].Start) })
	for _, p := range f.ordered {
		f.link(p)
	}
	return f
}

func (f *Forest) add(p *Process) {
	p.Level = -1 // unlinked until link places it
	f.procs[p.PID] = append(f.procs[p.PID], p)
	f.ordered = append(f.ordered, p)
	list := f.procs[p.PID]
	sort.SliceStable(list, func(i, j int) bool { return list[i].Start.Before(list[j].Start) })
}

// lookup returns the incarnation of pid that was alive at ts: the latest one
// that started at or before ts. Nil when pid is unknown, or every incarnation
// started later than ts.
func (f *Forest) lookup(pid uint32, ts time.Time) *Process {
	var best *Process
	for _, p := range f.procs[pid] {
		if !p.Start.After(ts) {
			best = p
		}
	}
	return best
}

// Resolve returns the incarnation of pid that an event at ts belongs to. An
// event stamped before every known incarnation (clock skew between probes)
// goes to the earliest one rather than being dropped.
func (f *Forest) Resolve(pid uint32, ts time.Time) *Process {
	if p := f.lookup(pid, ts); p != nil {
		return p
	}
	if list := f.procs[pid]; len(list) > 0 {
		return list[0]
	}
	return nil
}

// link sets p's parent, level and command. It is called once per process in
// creation order, so a parent that started earlier is already linked.
func (f *Forest) link(p *Process) {
	if p.PPID == f.RootPID {
		p.Parent, p.Level, p.Command = f.agent, 1, p
		return
	}
	parent := f.lookup(p.PPID, p.Start)
	if parent == nil || parent == p || parent.Level < 1 {
		p.Level = -1
		return
	}
	p.Parent, p.Level, p.Command = parent, parent.Level+1, parent.Command
}

// Attribute places an event in the tree by the pid that caused it. The clock
// is consulted only to choose between incarnations of a reused pid, never to
// pair or to attribute (V6).
func (f *Forest) Attribute(e models.GroundTruthEvent) Attribution {
	switch e.PID {
	case 0:
		return Attribution{Zone: ZoneUnknown, Level: -1}
	case f.RootPID:
		return Attribution{Zone: ZoneAgent, Level: 0}
	}
	p := f.Resolve(e.PID, e.Timestamp)
	if p == nil || p.Level < 1 {
		return Attribution{Zone: ZoneOutside, Level: -1}
	}
	return Attribution{Zone: ZoneSubtree, Level: p.Level, Process: p, Command: p.Command}
}

// Commands returns the level-1 processes in creation order: the sequence of
// commands the agent started.
func (f *Forest) Commands() []*Process {
	var out []*Process
	for _, p := range f.ordered {
		if p.Level == 1 {
			out = append(out, p)
		}
	}
	return out
}

// Orphans returns the processes that name a parent the capture never saw,
// whose chain therefore does not reach the agent. A process outside the tree
// because it belongs to someone else also lands here, so a non-empty result
// is a question (was a fork record lost?) and not by itself a finding.
func (f *Forest) Orphans() []*Process {
	var out []*Process
	for _, p := range f.ordered {
		if p.Level < 0 {
			out = append(out, p)
		}
	}
	return out
}
