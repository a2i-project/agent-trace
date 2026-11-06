package opencode

import (
	"strings"
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
// ties in the order the probe emitted them. First it drops the harness's
// opens of the workspace's files before its first model response
// (dropStartupOpens, I-147) and rewrites the exec of the harness's own
// ripgrep to its search (foldSearches, I-124). Before the opens are
// collapsed it drops the harness's read of a file just written
// (foldRereads), which would otherwise start a run with the next call's
// open of the file, and the second open of each read that parallel calls
// interleaved with other reads (pairInterleavedOpens, I-148).
func (a Adapter) NormalizeStream(g models.GroundTruth) models.GroundTruth {
	started := commands(g)
	g = dropStartupOpens(g, a.root, a.workspace)
	g = foldSearches(g, started)
	g = pairInterleavedOpens(foldRereads(foldCreates(g, started), started), started)
	return foldInPlace(collapseOpens(g, started), started)
}

// startupAfterConnect is how long after the harness's first model
// connection a capture without request content still counts as before the
// model's first response (I-147): the start-up opens came at most 61 ms
// after that connection, and the first response at least 366 ms after it,
// on the 42 captures of the first parity campaign's fixtures.
const startupAfterConnect = 200 * time.Millisecond

// dropStartupOpens drops the harness's opens of the workspace's files
// before its first model response (I-147). OpenCode 1.19.5 opens every
// file of the workspace once as it starts, while its first model request
// is under way: on the six runs of the first parity campaign and their
// controls, between 25 ms before and 70 ms after the first connection to
// the model server and 0.4 to 1.7 s before the response. No call can run
// before the model's first response names it, so no open before it is the
// agent's. Left in, these opens make the baseline learn an open rule per
// seeded file, which pairs only with a claim on that file (V-55): a
// substituted read would read as a fabrication and an unclaimed read of a
// seeded file would be hidden. The bound is the first net_response of the
// agent's own process (root), or, in a capture without one (no request
// content), its first net_connect plus startupAfterConnect: the start-up
// opens can come after that connection, as on the parity campaign's
// parallel run, 61 ms after it. A capture with no root, no workspace or
// neither event is left as it is. Only an open by root itself of an
// exact, unambiguous path under the workspace is dropped; its other opens
// before the bound, the system files it reads at start, vary in number
// with the bound and stay for the baseline.
func dropStartupOpens(g models.GroundTruth, root uint32, workspace string) models.GroundTruth {
	if root == 0 || workspace == "" {
		return g
	}
	bound, ok := firstOf(g, root, models.NetResponse)
	if !ok {
		if bound, ok = firstOf(g, root, models.NetConnect); !ok {
			return g
		}
		bound = bound.Add(startupAfterConnect)
	}
	prefix := strings.TrimSuffix(workspace, "/") + "/"
	drop := map[int]bool{}
	for i, e := range g {
		if !e.Timestamp.Before(bound) {
			break
		}
		if e.ActionType == models.FileOpen && e.PID == root && !e.PathIsAmbiguous && !e.TargetTruncated && strings.HasPrefix(e.Target, prefix) {
			drop[i] = true
		}
	}
	return without(g, drop)
}

// firstOf is the time of the first event of type t by pid.
func firstOf(g models.GroundTruth, pid uint32, t models.ActionType) (time.Time, bool) {
	for _, e := range g {
		if e.ActionType == t && e.PID == pid {
			return e.Timestamp, true
		}
	}
	return time.Time{}, false
}

// pairInterleavedOpens drops the second open of a read whose two opens
// other reads interleaved (I-148). OpenCode's read opens its file twice,
// with the same content; the calls of one message run concurrently, so
// two reads of a and b can open a, b, a, b, which collapseOpens, keeping
// the first of adjacent opens only, leaves as four accesses where the
// claims state two. An open of a file by the agent's process is dropped
// when the process's previous file event on that file is an open of it
// with the same input hash that no earlier open was paired with, and
// every file event of the process between them is an open of another
// file. Events on the harness's own files are skipped, as collapseOpens
// skips them. An open the first of a pair can be only once, so two reads
// of one file, each opening it twice, stay two accesses; an open without a
// hash is never paired.
func pairInterleavedOpens(g models.GroundTruth, started map[uint32]bool) models.GroundTruth {
	type opened struct {
		at     int  // index of the process's last event on the file
		pairs  bool // that event is an open that may start a pair
		events int  // the process's file events up to it
	}
	last := map[uint32]map[string]opened{}
	events := map[uint32]int{}     // file events of each process so far
	sinceOther := map[uint32]int{} // file events of each process up to its last one that was not an open
	drop := map[int]bool{}
	for i, e := range g {
		if !isFile(e.ActionType) || isHarnessOwned(e.Target) {
			continue
		}
		events[e.PID]++
		if e.ActionType != models.FileOpen {
			sinceOther[e.PID] = events[e.PID]
		}
		files := last[e.PID]
		if files == nil {
			files = map[string]opened{}
			last[e.PID] = files
		}
		prev, seen := files[e.Target]
		pairs := e.ActionType == models.FileOpen && agentFile(e, started) && e.InputHash != nil
		if pairs && seen && prev.pairs && prev.events < events[e.PID]-1 && sinceOther[e.PID] <= prev.events &&
			g[prev.at].InputHash != nil && *g[prev.at].InputHash == *e.InputHash {
			drop[i] = true
			pairs = false
		}
		files[e.Target] = opened{at: i, pairs: pairs, events: events[e.PID]}
	}
	return without(g, drop)
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

// foldRereads drops the harness's read of a file that has just been
// written. After every write and edit, the harness's process opened the
// file again within rereadSpan of its close, with the input hash equal to
// the close's hash (I-120). It does the same after a command or any other
// process wrote a file of the workspace: on the first parity campaign it
// opened the file 56 to 72 ms after that process's close, with the content
// just written, also while no call ran (I-143). Such an open states
// nothing the write did not. The dropped open is, for a close with a hash
// by any process, each other harness-like process's first open of the
// file after the close, and the closing process's own first open of it
// when that process is the harness's, within rereadSpan, with the close's
// hash, when no write, close, rename or delete of the file by any process
// lies between. The harness's other file events may fall between: on the
// campaign its open of /etc/hosts for its next model request came first
// after some of its edits (I-148). An open with other content, later, or
// after another change of the file, stays; so does one after a close
// without a hash.
func foldRereads(g models.GroundTruth, started map[uint32]bool) models.GroundTruth {
	drop := map[int]bool{}
	for i, e := range g {
		if e.ActionType != models.FileClose || e.OutputHash == nil || e.PID == 0 || e.PathIsAmbiguous || isHarnessOwned(e.Target) {
			continue
		}
		own := agentFile(e, started)
		opened := map[uint32]bool{}
		for j := i + 1; j < len(g); j++ {
			n := g[j]
			if n.Timestamp.Sub(e.Timestamp) > rereadSpan {
				break
			}
			if n.Target != e.Target || !isFile(n.ActionType) {
				continue
			}
			if n.ActionType != models.FileOpen {
				break // the file changed again
			}
			if (n.PID == e.PID) != own || !agentFile(n, started) || opened[n.PID] {
				continue
			}
			opened[n.PID] = true
			if n.InputHash != nil && *n.InputHash == *e.OutputHash {
				drop[j] = true
			}
		}
	}
	return without(g, drop)
}
