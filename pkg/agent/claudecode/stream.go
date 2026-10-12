package claudecode

import (
	"path/filepath"
	"regexp"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// What a paired capture of Claude Code 2.1.286 showed at the kernel level
// (D6, I-22):
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

// The file tools name the temporary <path>.tmp.<pid>.<12 hex>; the version
// lock and the session key name it <path>.tmp.<8 hex>, which Normalize has
// already rewritten to <path>.tmp.N by the time the fold runs.
var tmpName = regexp.MustCompile(`^(.+)\.tmp\.(?:\d+\.[0-9a-f]{12}|[0-9a-f]{8}|N)$`)

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
// FileWrite of the target. Two shapes reach the probe (I-22, I-32):
//
//   - read before the rename: a create on the directory, then open, write and
//     close on <path>.tmp.<pid>.<hex>, then the rename on the directory; the
//     close may already name the target, and so may the writes just before
//     it, when only the open was read before the rename (I-34);
//   - read after the rename, all in one batch: the directory's create and
//     rename merged into one notification ahead of the file's open, write
//     and close, every one of which names the target, since the temporary's
//     handle resolves to its final name by then.
//
// A direct write of the target has neither a create nor a rename on the
// directory around it and is left alone, so an unseen variant stays visible.
// A rename recorded as two directory renames, as captures made before P-18
// can hold, is folded whole (I-33).
func foldAtomicWrites(g models.GroundTruth) models.GroundTruth {
	used := make([]bool, len(g))
	replace := map[int]models.GroundTruthEvent{}
	foldRenamedFirst(g, used, replace)

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
		// pending holds writes that name the target, which belong to the
		// replace only when the close that follows them names it too (I-34).
		var burst, pending []int
		for i := o + 1; i < len(g) && (closeIdx < 0 || renameIdx < 0); i++ {
			e := g[i]
			if used[i] || e.PID != pid {
				continue
			}
			switch {
			case e.Target == open.Target && e.ActionType == models.FileWrite:
				burst = append(burst, i)
			case e.Target == target && e.ActionType == models.FileWrite && closeIdx < 0:
				pending = append(pending, i)
				continue
			case e.ActionType == models.FileClose && closeIdx < 0 && (e.Target == open.Target || e.Target == target):
				closeIdx = i
				// Writes and a close read after the rename name the target,
				// since the temporary's handle resolves to its final name by
				// then. Taken only as the events of this pid just before a
				// close of the target.
				if e.Target == target {
					burst = append(burst, pending...)
				}
			case e.ActionType == models.FileRename && renameIdx < 0 && (e.Target == dir || e.Target == target || e.Target == open.Target):
				renameIdx = i
			}
			pending = nil
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
		if i := splitRenameHalf(g, used, renameIdx, dir); i >= 0 {
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

// splitRenameHalf returns the index of the second directory-level rename one
// rename of a replace was reported as, or -1. Captures recorded before P-18,
// the checked-in P-17 capture among them, can hold a replace's rename as two
// ambiguous renames of the directory, back to back: the kernel's unmerged
// halves of one rename, which the probe now drops at emission (P-18). Taking
// the second here keeps such a capture reading as a current one (I-33). The
// condition is narrower than P-18's: only the next event of the pid, only one,
// and no event of any process on the directory between. So on a current
// capture it never applies, and on an old one it hides only what P-18 hides:
// two real renames of one directory by one process with nothing between.
func splitRenameHalf(g models.GroundTruth, used []bool, renameIdx int, dir string) int {
	first := g[renameIdx]
	if first.Target != dir || !first.PathIsAmbiguous {
		return -1
	}
	for i := renameIdx + 1; i < len(g); i++ {
		e := g[i]
		if e.Target == dir {
			if !used[i] && e.PID == first.PID && e.ActionType == models.FileRename && e.PathIsAmbiguous {
				return i
			}
			return -1
		}
		if used[i] || e.PID != first.PID {
			continue
		}
		return -1
	}
	return -1
}

// foldRenamedFirst folds the read-after-rename shape: for one pid, a create
// and a rename on the directory (either order, adjacent, the directory
// events the probe reports as ambiguous) immediately followed by open,
// write(s) and close of a file in that directory, all named by the final
// path. The close's hash is the content.
func foldRenamedFirst(g models.GroundTruth, used []bool, replace map[int]models.GroundTruthEvent) {
	for o, open := range g {
		if used[o] || open.ActionType != models.FileOpen || open.PID == 0 || tmpName.MatchString(open.Target) {
			continue
		}
		dir, pid := filepath.Dir(open.Target), open.PID
		// The directory events just before the open, by this pid: the create
		// and the rename, and sometimes an open of the directory itself (the
		// fsync of the directory an atomic write ends with), all reported as
		// ambiguous directory-level records.
		var dirIdx []int
		seen := map[models.ActionType]bool{}
		for i := o - 1; i >= 0 && len(dirIdx) < 3; i-- {
			if used[i] || g[i].PID != pid {
				continue
			}
			e := g[i]
			if e.Target == dir && e.PathIsAmbiguous && !seen[e.ActionType] && (e.ActionType == models.FileWrite || e.ActionType == models.FileRename || e.ActionType == models.FileOpen) {
				dirIdx = append(dirIdx, i)
				seen[e.ActionType] = true
				continue
			}
			break
		}
		if !seen[models.FileWrite] || !seen[models.FileRename] {
			continue
		}
		// Then the file's write(s) and close, with nothing else of this pid between.
		var burst []int
		closeIdx := -1
		for i := o + 1; i < len(g) && closeIdx < 0; i++ {
			if used[i] || g[i].PID != pid {
				continue
			}
			e := g[i]
			switch {
			case e.Target == open.Target && e.ActionType == models.FileWrite:
				burst = append(burst, i)
			case e.Target == open.Target && e.ActionType == models.FileClose:
				closeIdx = i
			default:
				i = len(g) // another event of this pid: not the shape
			}
		}
		if closeIdx < 0 {
			continue
		}
		start := dirIdx[len(dirIdx)-1]
		for _, i := range dirIdx {
			used[i] = true
		}
		used[o], used[closeIdx] = true, true
		for _, i := range burst {
			used[i] = true
		}
		replace[start] = models.GroundTruthEvent{
			Timestamp:  g[start].Timestamp,
			ActionType: models.FileWrite,
			Target:     open.Target,
			PID:        pid,
			OutputHash: g[closeIdx].OutputHash,
		}
	}
}

// collapseOpens keeps the first of a run of opens of one file by one process. A
// run is broken by any other file event of that process, except one on the
// harness's own files (I-30): the harness appends to its transcript and reads
// its configuration between the opens a tool makes, and a claim knows nothing
// of that.
func collapseOpens(g models.GroundTruth) models.GroundTruth {
	last := map[uint32]*models.GroundTruthEvent{}
	out := make(models.GroundTruth, 0, len(g))
	for _, e := range g {
		if !isFile(e.ActionType) || e.PID == 0 || harnessOwned.MatchString(e.Target) {
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
