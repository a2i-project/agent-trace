package opencode

import (
	"time"

	"github.com/agent-trace/agent-trace/pkg/content"
	"github.com/agent-trace/agent-trace/pkg/models"
)

// What the first capture of OpenCode 1.19.5 showed at the kernel level
// (I-120), with directory-entry names and no ambiguous event: write and
// edit run in the harness's own process and write in place, with no
// temporary and no rename. A write that creates a file is a file_write
// naming it (the create), its open with the input hash of empty content,
// a write and the close with the content's hash; a write over a file and
// an edit are two opens of it (the harness reads it first), a write and
// the close. The claims are an open and a write per call, so the observed
// side is rewritten to that grain. A shape not listed stays as the probe
// reported it.

// emptyHash is the input hash the probe gives the open that created a file
// (P-22).
var emptyHash = content.SHA256Bytes(nil)

// rereadSpan bounds the gap between a write's close and the harness's
// read of what it wrote: 66 to 72 ms after the close on every write and edit of the first
// capture (I-120).
const rereadSpan = time.Second

// NormalizeStream drops the create of a file the agent's process creates
// (foldCreates), collapses its runs of opens of one file (collapseOpens)
// and folds its in-place rewrites into one write carrying the close's hash
// (foldInPlace), as the Codex adapter does (I-82, I-99): the same shapes,
// measured on OpenCode's write and edit (I-120). Events are in time order,
// ties in the order the probe emitted them. First it rewrites the exec of
// the harness's own ripgrep to its search (foldSearches, I-124). Before the opens are collapsed
// it drops the harness's read of a file it has just written (foldRereads),
// which would otherwise start a run with the next call's open of the file.
func (Adapter) NormalizeStream(g models.GroundTruth) models.GroundTruth {
	started := commands(g)
	g = foldSearches(g, started)
	return foldInPlace(collapseOpens(foldRereads(foldCreates(g, started), started), started), started)
}

// CollapsesOpenRuns: the claims count an update's opens as one access, and
// so does collapseOpens (V-49).
func (Adapter) CollapsesOpenRuns() bool { return false }

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

// agentFile reports whether e is a file event of the agent's own process on
// a path that is not the harness's: the events the file folds may rewrite.
func agentFile(e models.GroundTruthEvent, started map[uint32]bool) bool {
	return isFile(e.ActionType) && e.PID != 0 && !started[e.PID] && !e.PathIsAmbiguous && !isHarnessOwned(e.Target)
}

// foldCreates drops the create of a file by the agent's process when that
// process's next file event is the open that created it, with the input
// hash of empty content (P-22, as I-56 reads agy's creates). No time bound
// applies (I-99): the probe gives the empty hash only to the first open of a
// file born during the capture, so that open created the file wherever the
// reads split the batches, and the create states nothing it does not.
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
				n.InputHash != nil && *n.InputHash == emptyHash {
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
		if !isFile(e.ActionType) || isHarnessOwned(e.Target) {
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

// foldRereads drops the harness's read of what it has just written: after
// every write and edit, the harness's process opened the file again
// within rereadSpan of its close, as its next file event outside its own
// directories, with the input hash equal to the close's hash (I-120). Such an open states nothing the write did not. An open with
// other content, later, or after another file event of the process, stays.
func foldRereads(g models.GroundTruth, started map[uint32]bool) models.GroundTruth {
	drop := map[int]bool{}
	for i, e := range g {
		if e.ActionType != models.FileClose || e.OutputHash == nil || !agentFile(e, started) {
			continue
		}
		for j := i + 1; j < len(g); j++ {
			n := g[j]
			if n.PID != e.PID || !isFile(n.ActionType) || isHarnessOwned(n.Target) {
				continue
			}
			if n.ActionType == models.FileOpen && n.Target == e.Target && agentFile(n, started) &&
				n.InputHash != nil && *n.InputHash == *e.OutputHash && n.Timestamp.Sub(e.Timestamp) <= rereadSpan {
				drop[j] = true
			}
			break
		}
	}
	return without(g, drop)
}
