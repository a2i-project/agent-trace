package claudecode

import (
	"path/filepath"
	"regexp"
	"strings"
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
//
// The captures above were made before the probe named directory entries
// (P-25): a create, a rename or a delete named only its directory and was
// ambiguous. A capture made since names each, and a rename is two events, its
// source and its destination. Every fold below takes both: the older shapes
// for the checked-in captures, the named one, under stricter rules since the
// names are evidence, for new ones (I-56).

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
func (a Adapter) NormalizeStream(g models.GroundTruth) models.GroundTruth {
	return collapseOpens(foldCwdFileRead(foldInPlaceWrites(foldAtomicWrites(resolveFDSearches(pathSearches(g, a.root))))))
}

// pathSearchProgram is the file name of the search program a Claude Code
// build that does not search with its own executable runs from PATH (I-107,
// I-128).
const pathSearchProgram = "rg"

// pathSearches recognises the searches of a Claude Code build that runs its
// Grep and Glob through rg found on PATH, without --no-config (Reported,
// from the strings of the 2.1.306 binary, I-107), which searchOf does not
// know. A process is such a search only when it is the harness's own: a
// child the agent's process (root) forked, whose first exec that took
// effect runs a program the kernel resolved to a file named rg, from an
// absolute path naming rg, with the arguments of a Grep or a Glob
// (searchArgs), and no exec before it but failed attempts of rg in other
// directories with the same arguments (the PATH lookup). Those attempts,
// the exec and the process's exit then take the search's target
// (searchTarget), so the command the forest reads from the first exec is
// the search. An rg run through Bash is a child of the shell, or an exec
// after the shell's own, and keeps its command line; an rg reached through
// a link to another program, a script, a cut record or an exec the probe
// did not see take effect is not recognised. Without a root nothing is.
func pathSearches(g models.GroundTruth, root uint32) models.GroundTruth {
	if root == 0 {
		return g
	}
	type incarnation struct {
		pid uint32
		gen int
	}
	type search struct {
		kind, rest, line string
		// attempts are the stream indexes of the exec events up to and
		// including the one that took effect.
		attempts []int
		bad      bool
		done     bool
	}
	gen := map[uint32]int{}
	at := make([]incarnation, len(g))
	found := map[incarnation]*search{}
	for i, e := range g {
		if e.ActionType == models.ProcessFork && e.PID != 0 {
			gen[e.PID]++
		}
		inc := incarnation{e.PID, gen[e.PID]}
		at[i] = inc
		if e.ActionType != models.ProcessExec || e.PID == 0 || e.PID == root {
			continue
		}
		s := found[inc]
		if s == nil {
			s = &search{}
			found[inc] = s
		}
		if s.done || s.bad {
			continue
		}
		s.attempts = append(s.attempts, i)
		if e.Image == nil {
			continue // a failed attempt; checked once the exec that took effect is known
		}
		s.done = true
		prog, rest, ok := strings.Cut(e.Target, " ")
		im := e.Image
		if !ok || e.PPID != root || im.Truncated || im.FilenameChanged || im.Interpreter != "" ||
			!filepath.IsAbs(prog) || filepath.Base(prog) != pathSearchProgram || im.Filename != prog ||
			!filepath.IsAbs(im.Program) || filepath.Base(im.Program) != pathSearchProgram {
			s.bad = true
			continue
		}
		if s.kind, ok = searchArgs(rest); !ok {
			s.bad = true
			continue
		}
		s.rest, s.line = rest, e.Target
		for _, j := range s.attempts[:len(s.attempts)-1] {
			a := g[j]
			p, r, ok := strings.Cut(a.Target, " ")
			if !ok || a.PPID != root || !filepath.IsAbs(p) || filepath.Base(p) != pathSearchProgram || r != rest {
				s.bad = true
				break
			}
		}
	}
	var out models.GroundTruth
	for i, e := range g {
		s := found[at[i]]
		if s == nil || !s.done || s.bad {
			continue
		}
		switch {
		case e.ActionType == models.ProcessExec && i <= s.attempts[len(s.attempts)-1]:
		case e.ActionType == models.ProcessExit && i > s.attempts[len(s.attempts)-1] && e.Target == s.line:
		default:
			continue
		}
		if out == nil {
			out = append(models.GroundTruth(nil), g...)
		}
		out[i].Target, out[i].TargetTruncated = searchTarget(s.kind, s.rest, e)
	}
	if out == nil {
		return g
	}
	return out
}

// fdSearchWindow bounds how long before a single-file search's exec the
// agent's process opened the file it hands over. The pilots of 2.1.306 show
// about one millisecond (I-69).
const fdSearchWindow = time.Second

// resolveFDSearches names the file a single-file Grep searched (I-108). The
// 2.1.296 and 2.1.306 Grep tool opens the file in the agent's own process
// and starts ripgrep on /proc/self/fd/3 (I-69), so the search's command
// line names no path; searchTarget leaves it as <kind> /proc/self/fd/N.
// The file is the one both sides opened: the latest open, at most
// fdSearchWindow before the exec, by the search's parent of a path the
// search's own process opens after its exec, both named exactly. Every
// process event of the search then names that file as its folder. With no
// such file the target is the kind alone, marked truncated:
// unverified, as a search whose folder is not recorded (searchTarget).
func resolveFDSearches(g models.GroundTruth) models.GroundTruth {
	type search struct {
		at     time.Time
		parent uint32
	}
	fd := map[uint32]search{}
	for _, e := range g {
		if _, ok := fdSearchKind(e.Target); ok && e.ActionType == models.ProcessExec && e.PID != 0 {
			fd[e.PID] = search{e.Timestamp, e.PPID}
		}
	}
	if len(fd) == 0 {
		return g
	}
	// The paths each search's process opened after its exec.
	childOpens := map[uint32]map[string]bool{}
	for _, e := range g {
		s, ok := fd[e.PID]
		if !ok || e.ActionType != models.FileOpen || e.PathIsAmbiguous || e.TargetTruncated || e.Timestamp.Before(s.at) {
			continue
		}
		if childOpens[e.PID] == nil {
			childOpens[e.PID] = map[string]bool{}
		}
		childOpens[e.PID][e.Target] = true
	}
	file := map[uint32]string{}
	for pid, s := range fd {
		var best time.Time
		for _, e := range g {
			if e.PID != s.parent || e.ActionType != models.FileOpen || e.PathIsAmbiguous || e.TargetTruncated ||
				e.Timestamp.After(s.at) || s.at.Sub(e.Timestamp) > fdSearchWindow || !childOpens[pid][e.Target] {
				continue
			}
			if _, ok := file[pid]; !ok || !e.Timestamp.Before(best) {
				file[pid], best = e.Target, e.Timestamp
			}
		}
	}
	out := append(models.GroundTruth(nil), g...)
	for i, e := range out {
		kind, isFD := fdSearchKind(e.Target)
		if _, ok := fd[e.PID]; !ok || !isFD || (e.ActionType != models.ProcessExec && e.ActionType != models.ProcessExit) {
			continue
		}
		if f, ok := file[e.PID]; ok {
			out[i].Target = kind + " " + f
		} else {
			out[i].Target, out[i].TargetTruncated = kind, true
		}
	}
	return out
}

// fdSearchKind returns the kind of a normalized search target whose folder
// is a descriptor (searchTarget), and whether it is one.
func fdSearchKind(target string) (string, bool) {
	for _, kind := range []string{SearchGrep, SearchGlob} {
		if rest, ok := strings.CutPrefix(target, kind+" "); ok && strings.HasPrefix(rest, searchFD) {
			return kind, true
		}
	}
	return "", false
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
//
// A capture with names (P-25) reports a rename by name instead: a rename
// naming the file, or a temporary of it, in the same places is a replace too
// (I-56).
func nextToDirEvent(g models.GroundTruth, o, c int, w models.GroundTruthEvent) bool {
	dir := filepath.Dir(w.Target)
	onDir := func(e models.GroundTruthEvent) bool {
		if e.Target == dir && e.PathIsAmbiguous {
			return true
		}
		if e.ActionType != models.FileRename || e.PathIsAmbiguous {
			return false
		}
		m := tmpName.FindStringSubmatch(e.Target)
		return e.Target == w.Target || (m != nil && m[1] == w.Target)
	}
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
// Those shapes are what the probe reported before it named directory entries
// (P-25). Since then every event of a replace names its file: the create, the
// open, the writes and the close name the temporary, the rename is two events,
// one naming the temporary and one the target, and none is ambiguous
// (foldReplacesWithNames, I-56). The older shapes stay for the captures made
// before.
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
	foldReplacesWithNames(g, used, replace)
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
		// A temporary whose create the probe named comes from a capture with
		// names (P-25): foldReplacesWithNames judged it already, and what it
		// left stays as it is.
		if p := previousOnReplace(g, used, o, pid, open.Target, target); p >= 0 && g[p].Target == open.Target {
			continue
		}

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
			case e.ActionType == models.FileRename && renameIdx < 0 && e.Target == dir:
				// A capture made before P-25 reports a rename on the
				// directory only. A named rename belongs to the shape
				// foldReplacesWithNames takes, under its stricter rules.
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

// foldReplacesWithNames folds a replace through the temporary as the probe
// reports it when it names directory entries (P-25, I-56). For one process,
// with T the temporary <X>.tmp.<suffix> and X the target:
//
//   - the create of T, a file_write naming T;
//   - the open of T, its writes and its close with the hash of the content,
//     all naming T: the kernel takes the name when the event happens, so a
//     record read after the rename still names T;
//   - the rename's source, a file_rename naming T, after the close, or right
//     after the create in the same record when the kernel merged it into the
//     create's unread record (the read-after-rename case of I-32);
//   - the rename's destination, a file_rename naming X, the process's next
//     event on T or X after the close and the source.
//
// Names are evidence, so every one is required and must name exactly T or X.
// Events of the process on other paths may lie between (its other threads
// share its pid); any other event of the process on T or X, or an event on
// another temporary of X before the destination, ends the shape and leaves
// it as the probe reported it. One exception, for the destination only: the
// probe drops a rename that repeats the previous event on its path by the
// same process (P-18), and the kernel merges a rename into an unread one of
// the same name, so a second replace of X with no event on X since the
// previous one's destination has none. It is taken as present when the last
// event on X before the source (or the close, when the source was merged) is
// a rename of X by the same process. The result is one file_write of X at
// the create's time with the close's hash, which is what the older shapes
// fold to.
func foldReplacesWithNames(g models.GroundTruth, used []bool, replace map[int]models.GroundTruth) {
	for o, open := range g {
		if used[o] || open.ActionType != models.FileOpen || open.PID == 0 || open.PathIsAmbiguous {
			continue
		}
		m := tmpName.FindStringSubmatch(open.Target)
		if m == nil {
			continue
		}
		tmp, target, pid := open.Target, m[1], open.PID
		is := func(i int, typ models.ActionType, path string) bool {
			if i < 0 {
				return false
			}
			e := g[i]
			return e.PID == pid && e.ActionType == typ && e.Target == path && !e.PathIsAmbiguous
		}

		// Backwards: the create, and before the open the source when the
		// kernel merged it into the create's record (same record, same time).
		// Events of the process on other paths may lie between, as forwards
		// (I-76).
		create, source := previousOnReplace(g, used, o, pid, tmp, target), -1
		if create >= 0 && is(create, models.FileRename, tmp) {
			source = create
			create = previousOnReplace(g, used, create, pid, tmp, target)
		}
		if !is(create, models.FileWrite, tmp) || g[create].OutputHash != nil ||
			(source >= 0 && !g[source].Timestamp.Equal(g[create].Timestamp)) {
			continue
		}

		// Forwards: the writes and the close of T, then the source (unless
		// merged ahead) and the destination.
		var burst []int
		closeIdx, dest := -1, -1
	scan:
		for i := o + 1; i < len(g); i++ {
			e := g[i]
			if used[i] || e.PID != pid {
				continue
			}
			if e.Target != tmp && e.Target != target {
				if n := tmpName.FindStringSubmatch(e.Target); n != nil && n[1] == target {
					break // another replace of X begins: this one has no destination of its own
				}
				continue
			}
			switch {
			case closeIdx < 0 && is(i, models.FileWrite, tmp) && e.OutputHash == nil:
				burst = append(burst, i)
			case closeIdx < 0 && is(i, models.FileClose, tmp):
				closeIdx = i
			case closeIdx >= 0 && source < 0 && is(i, models.FileRename, tmp):
				source = i
			case closeIdx >= 0 && source >= 0 && is(i, models.FileRename, target):
				dest = i
				break scan
			default:
				break scan
			}
		}
		if closeIdx < 0 || source < 0 {
			continue
		}
		if dest < 0 && !destinationCollapsed(g, pid, target, max(source, closeIdx)) {
			continue
		}

		for _, i := range append([]int{create, source, o, closeIdx}, burst...) {
			used[i] = true
		}
		if dest >= 0 {
			used[dest] = true
		}
		replace[create] = models.GroundTruth{{
			Timestamp:  g[create].Timestamp,
			ActionType: models.FileWrite,
			Target:     target,
			PID:        pid,
			OutputHash: g[closeIdx].OutputHash,
		}}
	}
}

// previousOnReplace returns the index of pid's last event before i that no
// fold has taken and that names tmp or target, or -1. The process's events on
// other paths are passed over, since its other threads share its pid; an event
// of it on another temporary of target ends the search, as it ends the
// forward one (I-76).
func previousOnReplace(g models.GroundTruth, used []bool, i int, pid uint32, tmp, target string) int {
	for j := i - 1; j >= 0; j-- {
		e := g[j]
		if used[j] || e.PID != pid {
			continue
		}
		if e.Target == tmp || e.Target == target {
			return j
		}
		if n := tmpName.FindStringSubmatch(e.Target); n != nil && n[1] == target {
			return -1
		}
	}
	return -1
}

// destinationCollapsed reports whether a missing rename of target by pid is
// explained by an earlier one the probe or the kernel folded it into (P-18):
// the last event on target before index i, by any process, is a named rename
// of target by pid.
func destinationCollapsed(g models.GroundTruth, pid uint32, target string, i int) bool {
	for j := i - 1; j >= 0; j-- {
		if e := g[j]; e.Target == target {
			return e.ActionType == models.FileRename && e.PID == pid && !e.PathIsAmbiguous
		}
	}
	return false
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
//
// The one-batch bound stays, unlike the named shape's, which takes the
// create at any distance (I-104): this shape exists only in captures made
// before P-25, every one of which folds within it, and its open names the
// lock and carries the lock's hash, not the empty-content hash that shows
// an open created its file.
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
// of that. A run whose one open is the harness's copy of the file into its
// edit checkpoint ends at the copy (checkpointCopies, V-104): the next open
// of the file is a later access, not part of the copy.
func collapseOpens(g models.GroundTruth) models.GroundTruth {
	copies := checkpointCopies(g)
	last := map[uint32]*models.GroundTruthEvent{}
	single := map[uint32]bool{} // the run of last[pid] holds one open
	out := make(models.GroundTruth, 0, len(g))
	for i, e := range g {
		if !isFile(e.ActionType) || e.PID == 0 || harnessOwned.MatchString(e.Target) {
			if prev := last[e.PID]; prev != nil && single[e.PID] && prev.ActionType == models.FileOpen && copies[i].of(*prev) {
				delete(last, e.PID)
			}
			out = append(out, e)
			continue
		}
		if prev := last[e.PID]; prev != nil && e.ActionType == models.FileOpen && prev.ActionType == models.FileOpen && prev.Target == e.Target {
			single[e.PID] = false
			continue
		}
		ev := e
		last[e.PID] = &ev
		single[e.PID] = true
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
		if lastFile >= 0 && e.ActionType == models.FileOpen && out[lastFile].ActionType == models.FileOpen && out[lastFile].Target == e.Target && out[lastFile].ImpliedBy == e.ImpliedBy && out[lastFile].ImpliedBefore == e.ImpliedBefore {
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
