package claudecode

import (
	"path/filepath"
	"regexp"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// What a paired capture of Claude Code 2.1.286 showed at the kernel level
// (07 section 3, D6 and the file-tool shapes):
//
//   - Read opens the file once.
//   - Write and Edit replace a file atomically: a temporary named
//     <path>.tmp.<pid>.<12 hex> is created, opened, written, closed and renamed
//     over the target. fanotify reports it as a create on the directory, an open,
//     a write and a close on the temporary, and a rename on the directory, five
//     events for what the trajectory calls one write. The close carries the hash
//     of the final content, and when it is read after the rename it names the
//     target instead of the temporary.
//   - Edit, and Write over an existing file, first open the target one or more
//     times to check it has not changed.
//
// The claim is the tool call, so the observed side is rewritten into the same
// grain: an atomic replace becomes one write of the target with the final
// content hash, and a run of opens of one file by one process becomes one open.
// The claims are rewritten the same way (see claudecode.go), so the two sides
// stay comparable. An unseen variant, such as a direct write with no temporary,
// is left alone and shows as unexplained rather than being guessed at.

var tmpName = regexp.MustCompile(`^(.+)\.tmp\.\d+\.[0-9a-f]{12}$`)

func isFile(a models.ActionType) bool {
	switch a {
	case models.FileOpen, models.FileRead, models.FileWrite, models.FileClose, models.FileRename, models.FileDelete:
		return true
	}
	return false
}

// NormalizeStream folds atomic replaces and collapses runs of opens. Events are
// in time order, ties in the order the probe emitted them.
func (Adapter) NormalizeStream(g models.GroundTruth) models.GroundTruth {
	return collapseOpens(foldAtomicWrites(g))
}

// foldAtomicWrites replaces each complete temp-and-rename write with one
// FileWrite of the target.
func foldAtomicWrites(g models.GroundTruth) models.GroundTruth {
	used := make([]bool, len(g))
	replace := map[int]models.GroundTruthEvent{}

	for o, open := range g {
		if used[o] || open.ActionType != models.FileOpen || open.PID == 0 {
			continue
		}
		m := tmpName.FindStringSubmatch(open.Target)
		if m == nil {
			continue
		}
		target, dir, pid := m[1], filepath.Dir(m[1]), open.PID

		// The close and the rename arrive in either order, and the close can name
		// the temporary or the target: fanotify resolves a path when the event is
		// read, so a close read after the rename already names the target. The
		// paired captures showed both.
		closeIdx, renameIdx := -1, -1
		var burst []int
		for i := o + 1; i < len(g) && (closeIdx < 0 || renameIdx < 0); i++ {
			e := g[i]
			if used[i] || e.PID != pid {
				continue
			}
			switch {
			case e.Target == open.Target && e.ActionType == models.FileWrite:
				burst = append(burst, i)
			case e.ActionType == models.FileClose && closeIdx < 0 && (e.Target == open.Target || e.Target == target):
				closeIdx = i
			case e.ActionType == models.FileRename && renameIdx < 0 && (e.Target == dir || e.Target == target || e.Target == open.Target):
				renameIdx = i
			}
		}
		// Without a close and a rename this is not a finished replace: the
		// temporary was abandoned or the capture ended inside it.
		if closeIdx < 0 || renameIdx < 0 {
			continue
		}

		start := o
		// The create of the temporary is reported on the directory just before
		// its open. Take it only when it is the previous event of this process.
		for i := o - 1; i >= 0; i-- {
			if g[i].PID != pid || used[i] {
				continue
			}
			if g[i].ActionType == models.FileWrite && g[i].Target == dir && g[i].PathIsAmbiguous {
				start = i
				used[i] = true
			}
			break
		}

		used[o], used[closeIdx], used[renameIdx] = true, true, true
		for _, i := range burst {
			used[i] = true
		}
		replace[start] = models.GroundTruthEvent{
			Timestamp:  g[start].Timestamp,
			ActionType: models.FileWrite,
			Target:     target,
			PID:        pid,
			OutputHash: g[closeIdx].OutputHash,
		}
	}

	out := make(models.GroundTruth, 0, len(g))
	for i, e := range g {
		if r, ok := replace[i]; ok {
			out = append(out, r)
			continue
		}
		if !used[i] {
			out = append(out, e)
		}
	}
	return out
}

// collapseOpens keeps the first of a run of opens of one file by one process. A
// run is broken by any other file event of that process.
func collapseOpens(g models.GroundTruth) models.GroundTruth {
	last := map[uint32]*models.GroundTruthEvent{}
	out := make(models.GroundTruth, 0, len(g))
	for _, e := range g {
		if !isFile(e.ActionType) || e.PID == 0 {
			out = append(out, e)
			continue
		}
		if prev := last[e.PID]; prev != nil && e.ActionType == models.FileOpen && prev.ActionType == models.FileOpen && prev.Target == e.Target {
			continue
		}
		ev := e
		last[e.PID] = &ev
		out = append(out, e)
	}
	return out
}

// collapseOpenClaims is the claim-side twin of collapseOpens: adjacent opens of
// one file among the file claims become one. Claims of other kinds (a command, a
// connection) do not break a run, because the observed side only ever sees the
// agent's own file events.
func collapseOpenClaims(t models.Trajectory) models.Trajectory {
	out := make(models.Trajectory, 0, len(t))
	lastFile := -1
	for _, e := range t {
		if !isFile(e.ActionType) {
			out = append(out, e)
			continue
		}
		if lastFile >= 0 && e.ActionType == models.FileOpen && out[lastFile].ActionType == models.FileOpen && out[lastFile].Target == e.Target {
			if e.End != nil && (out[lastFile].End == nil || e.End.After(*out[lastFile].End)) {
				end := *e.End
				out[lastFile].End = &end
			}
			continue
		}
		out = append(out, e)
		lastFile = len(out) - 1
	}
	return out
}
