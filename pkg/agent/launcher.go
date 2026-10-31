package agent

import "github.com/agent-trace/agent-trace/pkg/models"

// Launcher is implemented by an adapter whose harness command is a launcher
// that starts the harness as its child and waits for it, rather than
// exec'ing it in place (I-81): Codex's npm entry point is a Node script that
// spawns the native binary. The capture's root is then the launcher, the
// harness a level-1 command, and everything the harness does the content of
// that command. HarnessProcess returns the pid of the harness process when
// the capture's root is such a launcher in the shape the adapter measured,
// and 0 otherwise.
type Launcher interface {
	HarnessProcess(g models.GroundTruthFile) uint32
}

// Rooted is the capture as the verifier and the baseline take it (I-81):
// for an adapter that declares a launcher, rooted at the harness process.
// The harness process becomes the agent process (level 0), and the records
// of its launch, which a harness exec'd in place leaves out of the capture,
// are dropped: the fork that created it, its execs before any other event
// of it, and its exits. The launcher's own events stay, outside the tree.
// The capture is returned as it is when the adapter declares no launcher,
// names no process, or the root does anything but launch: the process
// named must be the root's only child, and the root's own events may only
// be reads and local socket connects (a launcher resolving its user and
// loading its script), so nothing the root did moves out of the tree
// unseen. A capture left as it is reads with the harness as a command, so
// a launcher in another shape fails closed.
func Rooted(a Adapter, g models.GroundTruthFile) models.GroundTruthFile {
	l, ok := a.(Launcher)
	if !ok || g.RootPID == 0 {
		return g
	}
	pid := l.HarnessProcess(g)
	if pid == 0 || pid == g.RootPID || !onlyLaunches(g, pid) {
		return g
	}
	out := g
	out.RootPID = pid
	out.Events = make(models.GroundTruth, 0, len(g.Events))
	started := false
	for _, e := range g.Events {
		if e.PID == pid {
			switch {
			case e.ActionType == models.ProcessFork && e.PPID == g.RootPID:
				continue
			case e.ActionType == models.ProcessExit:
				continue
			case e.ActionType == models.ProcessExec && !started:
				continue
			case e.ActionType != models.ProcessFork:
				started = true
			}
		}
		out.Events = append(out.Events, e)
	}
	return out
}

// onlyLaunches reports whether the capture's root did nothing but start pid:
// pid is its only child, and its own events are reads and local socket
// connects.
func onlyLaunches(g models.GroundTruthFile, pid uint32) bool {
	children := 0
	for _, e := range g.Events {
		if e.ActionType == models.ProcessFork && e.PPID == g.RootPID {
			if e.PID != pid {
				return false
			}
			children++
			continue
		}
		if e.PID != g.RootPID {
			continue
		}
		switch e.ActionType {
		case models.FileOpen, models.FileRead, models.NetUnixConnect:
		default:
			return false
		}
	}
	return children == 1
}
