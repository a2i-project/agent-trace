package claudecode

import (
	"path/filepath"
	"regexp"
	"time"

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
//     times to check it has not changed; NotebookEdit reads the notebook
//     (I-39).
//
// The claim is the tool call, so the observed side is rewritten into the same
// grain: an atomic replace becomes one write of the target with the final
// content hash, and a run of opens of one file by one process becomes one open.
// The claims are rewritten the same way (see claudecode.go), so the two sides
// stay comparable. The one direct write the harness makes, the in-place
// rewrite of a file whose temporary it cannot create (open, write, close, no
// rename), folds as narrowly as it was seen (foldInPlaceWrites, I-45); any
// other unseen variant is left alone and shows as unexplained rather than
// being guessed at.

// The file tools name the temporary <path>.tmp.<pid>.<12 hex>; the version
// lock and the session key name it <path>.tmp.<8 hex>. The fold sees the raw
// names: the per-run ids are replaced only where runs are compared (I-41).
var tmpName = regexp.MustCompile(`^(.+)\.tmp\.(?:\d+\.[0-9a-f]{12}|[0-9a-f]{8})$`)

func isFile(a models.ActionType) bool {
	switch a {
	case models.FileOpen, models.FileRead, models.FileWrite, models.FileClose, models.FileRename, models.FileDelete:
		return true
	}
	return false
}

// NormalizeStream folds atomic replaces and the harness's in-place rewrites,
// names the harness's read of its cwd file where the probe lost the name, and
// collapses runs of opens. Events are in time order, ties in the order the
// probe emitted them.
func (Adapter) NormalizeStream(g models.GroundTruth) models.GroundTruth {
	return collapseOpens(foldCwdFileRead(foldInPlaceWrites(foldAtomicWrites(g))))
}

// foldInPlaceWrites folds the harness's in-place rewrite of a file into one
// FileWrite carrying the close's hash, the form the atomic-replace folds give
// (I-45). The file tools rewrite the target in place (open, truncate, write,
// close, no rename) when the sibling temporary cannot be created or renamed;
// the probe then reports, by the agent's process, an open of the target, its
// write with no hash and its close with the hash of the final content.
//
// Narrow on purpose. A run of writes of one file folds with the close that
// follows it only when, for that process, the previous event is an open of the
// same file and the next event after the writes is the close, with no other
// event of the process between; every one names the file exactly; and no
// ambiguous event of the file's directory by the process comes just before
// its opens and writes of the file or just after the close (nextToDirEvent),
// since a create or a rename there is a replace in a shape no fold knows. It runs
// after foldAtomicWrites, so a write it produced (which carries a hash) and
// the temporary of an unfinished replace are not taken. The harness's own
// files (I-30) are left alone, so no baseline rule changes. A process the
// stream shows being forked or exec'd is a command the agent ran, never the
// agent's own process, whose start precedes the capture: its events are the
// command's content, explained by the command's claim, and are left as the
// probe reported them. The open stays: it is the claim's open.
func foldInPlaceWrites(g models.GroundTruth) models.GroundTruth {
	started := map[uint32]bool{}
	for _, e := range g {
		switch e.ActionType {
		case models.ProcessFork, models.ProcessExec, models.ProcessExit:
			started[e.PID] = true
		}
	}
	// prev holds, per process, the index of its last event seen so far.
	prev := map[uint32]int{}
	drop := make([]bool, len(g))
	var out models.GroundTruth
	for w, e := range g {
		p, seen := prev[e.PID]
		prev[e.PID] = w
		if drop[w] || e.ActionType != models.FileWrite || e.PID == 0 || e.PathIsAmbiguous || e.OutputHash != nil ||
			started[e.PID] || harnessOwned.MatchString(e.Target) || tmpName.MatchString(e.Target) || !seen {
			continue
		}
		if o := g[p]; o.ActionType != models.FileOpen || o.Target != e.Target || o.PathIsAmbiguous {
			continue
		}
		// The writes of the run, then the close, by this process.
		var burst []int
		closeIdx := -1
		for i := w + 1; i < len(g) && closeIdx < 0; i++ {
			n := g[i]
			if n.PID != e.PID {
				continue
			}
			if n.Target != e.Target || n.PathIsAmbiguous {
				break
			}
			if n.ActionType == models.FileWrite && n.OutputHash == nil {
				burst = append(burst, i)
				continue
			}
			if n.ActionType == models.FileClose {
				closeIdx = i
			}
			break
		}
		if closeIdx < 0 || nextToDirEvent(g, p, closeIdx, e) {
			continue
		}
		if out == nil {
			out = append(models.GroundTruth(nil), g...)
		}
		out[w].OutputHash = g[closeIdx].OutputHash
		for _, i := range append(burst, closeIdx) {
			drop[i] = true
		}
	}
	if out == nil {
		return g
	}
	kept := make(models.GroundTruth, 0, len(out))
	for i, e := range out {
		if !drop[i] {
			kept = append(kept, e)
		}
	}
	return kept
}

// nextToDirEvent reports whether the process of w, around its events on w's
// file from the open at o to the close at c, has an ambiguous event on the
// file's directory: the process's last event before its run of opens and
// writes of the file, or its first event after the close. A create or a rename
// of the directory there means a replace in a shape no fold knows, which stays
// visible; the in-place rewrite has neither.
func nextToDirEvent(g models.GroundTruth, o, c int, w models.GroundTruthEvent) bool {
	dir := filepath.Dir(w.Target)
	onDir := func(e models.GroundTruthEvent) bool { return e.Target == dir && e.PathIsAmbiguous }
	for i := o - 1; i >= 0; i-- {
		e := g[i]
		if e.PID != w.PID {
			continue
		}
		if e.Target == w.Target && (e.ActionType == models.FileOpen || e.ActionType == models.FileWrite) {
			continue
		}
		if onDir(e) {
			return true
		}
		break
	}
	for i := c + 1; i < len(g); i++ {
		if g[i].PID == w.PID {
			return onDir(g[i])
		}
	}
	return false
}

// cwdFileRead is the target an ambiguous read of the cwd file becomes: the
// canonical form of /tmp/claude-<id>-cwd (canonicalFileIDs leaves it as it
// is), so a baseline rule measured on a control that recorded the read by
// name explains it, and harnessOwned matches it. The harness names its cwd
// files with lower-case base-36 ids, so no file it writes, and no claim on
// one, carries the upper-case token (I-43).
const cwdFileRead = "/tmp/claude-N-cwd"

// batchSpan bounds the distance between two records of one fanotify batch.
// The probe stamps a batch with one clock reading plus one nanosecond per
// record (P-18); on the paired captures of 2.1.286 and 2.1.296 consecutive
// file records of one batch are at most 33 ns apart and those of two batches
// at least 17 microseconds.
const batchSpan = time.Microsecond

// foldCwdFileRead rewrites the harness's read of its cwd file when the probe
// reports it on /tmp (I-43). After each Bash call the harness reads and
// deletes /tmp/claude-<id>-cwd, which the wrapper wrote. When the read and the
// delete land in one batch, the file is gone before the batch is read, and
// both are ambiguous records of /tmp. So an ambiguous open of /tmp whose
// process's next event on /tmp, in the same batch, is an ambiguous delete of
// /tmp becomes an open of cwdFileRead. Nothing else on /tmp is touched: a
// named open, an open followed by another event of its process on /tmp (a
// write, say) or by nothing in the batch, and every write stay as they are.
func foldCwdFileRead(g models.GroundTruth) models.GroundTruth {
	var out models.GroundTruth
	for o, open := range g {
		if open.ActionType != models.FileOpen || open.Target != "/tmp" || !open.PathIsAmbiguous || open.PID == 0 {
			continue
		}
		for i := o + 1; i < len(g); i++ {
			e := g[i]
			if e.Timestamp.Sub(open.Timestamp) >= batchSpan {
				break
			}
			if e.PID != open.PID || e.Target != "/tmp" {
				continue
			}
			if e.ActionType == models.FileDelete && e.PathIsAmbiguous && !e.Timestamp.Before(open.Timestamp) {
				if out == nil {
					out = append(models.GroundTruth(nil), g...)
				}
				out[o].Target = cwdFileRead
				out[o].PathIsAmbiguous = false
			}
			break
		}
	}
	if out == nil {
		return g
	}
	return out
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
// The version lock has a third shape, read between the two
// (foldNamedLockRewrite, I-44).
//
// A direct write of the target has neither a create nor a rename on the
// directory around it and is left alone, so an unseen variant stays visible.
// A rename recorded as two directory renames, as captures made before P-18
// can hold, is folded whole (I-33).
func foldAtomicWrites(g models.GroundTruth) models.GroundTruth {
	used := make([]bool, len(g))
	// replace holds, at the index of a replace's first event, what the replace
	// becomes: one write, preceded by an open of the target when the batch held
	// the harness's read of it (I-39).
	replace := map[int]models.GroundTruth{}
	foldRenamedFirst(g, used, replace)
	foldNamedLockRewrite(g, used, replace)

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
		replace[start] = models.GroundTruth{{
			Timestamp:  g[start].Timestamp,
			ActionType: models.FileWrite,
			Target:     target,
			PID:        pid,
			OutputHash: g[closeIdx].OutputHash,
		}}
	}

	out := make(models.GroundTruth, 0, len(g))
	for i, e := range g {
		if r, ok := replace[i]; ok {
			out = append(out, r...)
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
//
// An ambiguous open of the directory ahead of both the create and the rename
// is the harness's read of the file it is about to replace, merged into the
// batch, likely because by the time the batch is read the rename has
// unlinked the inode that was opened, so only its directory resolves (I-39). It becomes an open of
// the target, with no input hash since none was measured for it, ahead of the
// folded write. An open of the directory after the create or the rename is
// absorbed as before (I-32).
func foldRenamedFirst(g models.GroundTruth, used []bool, replace map[int]models.GroundTruth) {
	for o, open := range g {
		if used[o] || open.ActionType != models.FileOpen || open.PID == 0 || tmpName.MatchString(open.Target) {
			continue
		}
		dir, pid := filepath.Dir(open.Target), open.PID
		// The directory events just before the open, by this pid: the create
		// and the rename, and sometimes an open reported on the directory (the
		// read of the replaced file when it comes first, I-39), all reported
		// as ambiguous directory-level records.
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
		var folded models.GroundTruth
		// dirIdx runs backwards, so the earliest directory event is last: a
		// read of the target is an open there, with the create and the rename
		// both after it.
		if first := g[start]; first.ActionType == models.FileOpen && len(dirIdx) == 3 {
			folded = append(folded, models.GroundTruthEvent{
				Timestamp:  first.Timestamp,
				ActionType: models.FileOpen,
				Target:     open.Target,
				PID:        pid,
			})
		}
		replace[start] = append(folded, models.GroundTruthEvent{
			Timestamp:  g[start].Timestamp,
			ActionType: models.FileWrite,
			Target:     open.Target,
			PID:        pid,
			OutputHash: g[closeIdx].OutputHash,
		})
	}
}

// versionLock matches the harness's version lock,
// ~/.local/state/claude/locks/<version>.lock.
var versionLock = regexp.MustCompile(`^/(?:home/[^/]+|root)/\.local/state/claude/locks/[^/]+\.lock$`)

// foldNamedLockRewrite folds the third shape the version lock's rewrite at
// start-up reaches the probe in (I-44). The harness replaces the lock through
// a temporary and a rename in every run; read before the rename it is the
// temporary shape of foldAtomicWrites, read after it the renamed-first shape
// of foldRenamedFirst. Read between the two, the create on the directory comes
// first, the temporary's open and writes already name the lock, and the
// directory's rename comes after the close, in either order with the close;
// a second open of the lock inside the span is the harness reading the lock
// back, which the temporary shape records as an open after the rename. The
// result is what those shapes fold to: one write of the lock with the close's
// hash, followed by one open of it when the span held a second open.
//
// Narrow on purpose: only the version lock, only when the create is this
// process's previous event and lands in one batch with the open, and only
// when every event of the process up to both the close and the rename is an
// open, write or close of the lock or the directory's ambiguous rename. An
// agent's file in this shape is not folded and stays visible.
func foldNamedLockRewrite(g models.GroundTruth, used []bool, replace map[int]models.GroundTruth) {
	for o, open := range g {
		if used[o] || open.ActionType != models.FileOpen || open.PID == 0 || !versionLock.MatchString(open.Target) {
			continue
		}
		target, dir, pid := open.Target, filepath.Dir(open.Target), open.PID
		create := -1
		for i := o - 1; i >= 0; i-- {
			if g[i].PID != pid || used[i] {
				continue
			}
			if e := g[i]; e.ActionType == models.FileWrite && e.Target == dir && e.PathIsAmbiguous && open.Timestamp.Sub(e.Timestamp) < batchSpan {
				create = i
			}
			break
		}
		if create < 0 {
			continue
		}
		closeIdx, renameIdx := -1, -1
		var burst, reads []int
		for i := o + 1; i < len(g) && (closeIdx < 0 || renameIdx < 0); i++ {
			e := g[i]
			if used[i] || e.PID != pid {
				continue
			}
			switch {
			case e.Target == target && e.ActionType == models.FileWrite && closeIdx < 0:
				burst = append(burst, i)
			case e.Target == target && e.ActionType == models.FileOpen:
				reads = append(reads, i)
			case e.Target == target && e.ActionType == models.FileClose && closeIdx < 0:
				closeIdx = i
			case e.Target == dir && e.ActionType == models.FileRename && e.PathIsAmbiguous && renameIdx < 0:
				renameIdx = i
			default:
				i = len(g) // another event of this pid: not the shape
			}
		}
		if closeIdx < 0 || renameIdx < 0 {
			continue
		}
		for _, i := range append(append([]int{create, o, closeIdx, renameIdx}, burst...), reads...) {
			used[i] = true
		}
		folded := models.GroundTruth{{
			Timestamp:  g[create].Timestamp,
			ActionType: models.FileWrite,
			Target:     target,
			PID:        pid,
			OutputHash: g[closeIdx].OutputHash,
		}}
		if len(reads) > 0 {
			folded = append(folded, models.GroundTruthEvent{
				Timestamp:  g[reads[0]].Timestamp,
				ActionType: models.FileOpen,
				Target:     target,
				PID:        pid,
			})
		}
		replace[create] = folded
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
// agent's own file events. A harness-implied open (I-46) merges only with
// another implied by the same command, so the agent's own open never becomes
// optional and an optional one never becomes the agent's.
func collapseOpenClaims(t models.Trajectory) models.Trajectory {
	out := make(models.Trajectory, 0, len(t))
	lastFile := -1
	for _, e := range t {
		if !isFile(e.ActionType) {
			out = append(out, e)
			continue
		}
		if lastFile >= 0 && e.ActionType == models.FileOpen && out[lastFile].ActionType == models.FileOpen && out[lastFile].Target == e.Target && out[lastFile].ImpliedBy == e.ImpliedBy {
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
