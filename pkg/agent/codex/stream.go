package codex

import (
	"path/filepath"
	"strings"
	"time"

	"github.com/agent-trace/agent-trace/pkg/content"
	"github.com/agent-trace/agent-trace/pkg/models"
)

// What the first capture of Codex 0.166.0 showed at the kernel level (I-82),
// with directory-entry names and no ambiguous event:
//
//   - apply_patch runs in the harness's own process and writes in place,
//     with no temporary and no rename. Adding a file is a file_write naming
//     it (the create), in the same batch its open with the input hash of
//     empty content, a write and the close with the content's hash.
//     Updating a file is three opens of it, a write and the close; the
//     harness's other threads make network events between the opens.
//   - The harness starts its helper commands (lsb_release, getconf, git)
//     through a PATH search: an exec of the program in the harness's per-run
//     arg0 directory, in its own install directory and in /usr/local/bin,
//     each failing, and then the one that takes effect, microseconds apart
//     with no other event of the process between.
//
// The claims are an open and a write per changed file, so the observed side
// is rewritten to that grain, and the failed attempts are dropped so a
// command's own exec is the program that ran. A shape not listed stays as
// the probe reported it.

// emptyHash is the input hash the probe gives the open that created a file
// (P-22).
var emptyHash = content.SHA256Bytes(nil)

// batchSpan bounds two records of one fanotify batch (P-18).
const batchSpan = time.Microsecond

// attemptSpan bounds the gap between two exec attempts of one PATH search:
// they were at most 15 microseconds apart in the capture.
const attemptSpan = time.Millisecond

// NormalizeStream drops the failed exec attempts of a PATH search
// (failedAttempts), the create of a file the agent's process creates
// (foldCreates), collapses its runs of opens of one file (collapseOpens)
// and folds its in-place rewrites into one write carrying the close's hash
// (foldInPlace). Events are in time order, ties in the order the probe
// emitted them.
func (Adapter) NormalizeStream(g models.GroundTruth) models.GroundTruth {
	g = failedAttempts(g)
	started := commands(g)
	return foldInPlace(collapseOpens(foldCreates(g, started), started), started)
}

// CollapsesOpenRuns: the claims count an update's opens as one access, and
// so does collapseOpens (V-49).
func (Adapter) CollapsesOpenRuns() bool { return true }

// commands returns the processes the stream shows being forked, exec'd or
// exiting: commands, never the agent's own process, whose start precedes the
// capture or was dropped with its launch (I-81). No file fold touches them.
func commands(g models.GroundTruth) map[uint32]bool {
	started := map[uint32]bool{}
	for _, e := range g {
		switch e.ActionType {
		case models.ProcessFork, models.ProcessExec, models.ProcessExit:
			started[e.PID] = true
		}
	}
	return started
}

func isFile(t models.ActionType) bool {
	switch t {
	case models.FileOpen, models.FileRead, models.FileWrite, models.FileClose, models.FileRename, models.FileDelete:
		return true
	}
	return false
}

// agentFile reports whether e is a file event of the agent's own process on
// a path that is not the harness's: the events the file folds may rewrite.
func agentFile(e models.GroundTruthEvent, started map[uint32]bool) bool {
	return isFile(e.ActionType) && e.PID != 0 && !started[e.PID] && !e.PathIsAmbiguous && !harnessOwned.MatchString(e.Target)
}

// failedAttempts drops an exec that the same process's next event follows
// within attemptSpan as another exec of the same program name and the same
// arguments from another absolute directory: an attempt of a PATH search
// that failed, since an exec that took effect would have loaded its program
// before anything else. The last exec of such a run is kept.
func failedAttempts(g models.GroundTruth) models.GroundTruth {
	next := map[int]int{} // index -> index of the same process's next event
	last := map[uint32]int{}
	for i, e := range g {
		if j, ok := last[e.PID]; ok {
			next[j] = i
		}
		last[e.PID] = i
	}
	drop := map[int]bool{}
	for i, e := range g {
		j, ok := next[i]
		if !ok || e.ActionType != models.ProcessExec || e.TargetTruncated || e.PID == 0 {
			continue
		}
		n := g[j]
		if n.ActionType == models.ProcessExec && !n.TargetTruncated && n.Timestamp.Sub(e.Timestamp) < attemptSpan && sameSearch(e.Target, n.Target) {
			drop[i] = true
		}
	}
	if len(drop) == 0 {
		return g
	}
	out := make(models.GroundTruth, 0, len(g)-len(drop))
	for i, e := range g {
		if !drop[i] {
			out = append(out, e)
		}
	}
	return out
}

// sameSearch reports whether two command lines run the same program name
// from two absolute directories with the same arguments.
func sameSearch(a, b string) bool {
	pa, aa, _ := strings.Cut(a, " ")
	pb, ab, _ := strings.Cut(b, " ")
	return aa == ab && strings.HasPrefix(pa, "/") && strings.HasPrefix(pb, "/") && pa != pb &&
		filepath.Base(pa) == filepath.Base(pb) && filepath.Dir(pa) != filepath.Dir(pb)
}

// foldCreates drops the create of a file by the agent's process when that
// process's next file event is the open that created it, in the same batch,
// with the input hash of empty content (P-22, as I-56 reads agy's creates).
func foldCreates(g models.GroundTruth, started map[uint32]bool) models.GroundTruth {
	drop := map[int]bool{}
	for i, e := range g {
		if e.ActionType != models.FileWrite || e.OutputHash != nil || !agentFile(e, started) {
			continue
		}
		for j := i + 1; j < len(g); j++ {
			n := g[j]
			if n.PID != e.PID || !isFile(n.ActionType) {
				continue
			}
			if n.ActionType == models.FileOpen && n.Target == e.Target && !n.PathIsAmbiguous &&
				n.InputHash != nil && *n.InputHash == emptyHash && n.Timestamp.Sub(e.Timestamp) < batchSpan {
				drop[i] = true
			}
			break
		}
	}
	return without(g, drop)
}

// collapseOpens keeps the first of a run of opens of one file by the
// agent's process: an open whose process's previous file event is an open
// of the same file is dropped. Only a file event of the process ends a run:
// its other threads' network events fall between an update's opens. The
// harness's own files do not end a run either, as for Claude Code (I-32).
func collapseOpens(g models.GroundTruth, started map[uint32]bool) models.GroundTruth {
	last := map[uint32]models.GroundTruthEvent{}
	drop := map[int]bool{}
	for i, e := range g {
		if !isFile(e.ActionType) || harnessOwned.MatchString(e.Target) {
			continue
		}
		prev, seen := last[e.PID]
		last[e.PID] = e
		if seen && e.ActionType == models.FileOpen && prev.ActionType == models.FileOpen && prev.Target == e.Target &&
			agentFile(e, started) && agentFile(prev, started) {
			drop[i] = true
		}
	}
	return without(g, drop)
}

// foldInPlace folds an in-place rewrite by the agent's process: an open of
// a file, then writes of it and its close, with no other file event of the
// process between (on the harness's own files neither), becomes the open
// and one file_write at the close carrying the close's hash, the grain of a
// file change's claims. A write already carrying a hash, and a shape with
// anything else between, are left alone.
func foldInPlace(g models.GroundTruth, started map[uint32]bool) models.GroundTruth {
	open := map[uint32]int{} // pid -> index of an open that may start a rewrite
	writes := map[uint32][]int{}
	drop := map[int]bool{}
	replace := map[int]models.GroundTruthEvent{}
	for i, e := range g {
		if !isFile(e.ActionType) {
			continue
		}
		o, ok := open[e.PID]
		switch {
		case !agentFile(e, started):
			delete(open, e.PID)
		case e.ActionType == models.FileOpen:
			open[e.PID], writes[e.PID] = i, nil
		case ok && e.Target == g[o].Target && e.ActionType == models.FileWrite && e.OutputHash == nil:
			writes[e.PID] = append(writes[e.PID], i)
		case ok && e.Target == g[o].Target && e.ActionType == models.FileClose && len(writes[e.PID]) > 0:
			for _, w := range writes[e.PID] {
				drop[w] = true
			}
			fold := e
			fold.ActionType = models.FileWrite
			replace[i] = fold
			delete(open, e.PID)
		default:
			delete(open, e.PID)
		}
	}
	if len(replace) == 0 {
		return g
	}
	out := make(models.GroundTruth, 0, len(g)-len(drop))
	for i, e := range g {
		if r, ok := replace[i]; ok {
			e = r
		}
		if !drop[i] {
			out = append(out, e)
		}
	}
	return out
}

// without returns g without the events at the indexes in drop.
func without(g models.GroundTruth, drop map[int]bool) models.GroundTruth {
	if len(drop) == 0 {
		return g
	}
	out := make(models.GroundTruth, 0, len(g)-len(drop))
	for i, e := range g {
		if !drop[i] {
			out = append(out, e)
		}
	}
	return out
}
