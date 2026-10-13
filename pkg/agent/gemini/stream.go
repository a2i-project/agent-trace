package gemini

import (
	"path/filepath"
	"time"

	"github.com/agent-trace/agent-trace/pkg/content"
	"github.com/agent-trace/agent-trace/pkg/models"
)

// What the paired capture of the basic task with agy 1.3.4 showed at the
// kernel level (I-50), all by the agent's own process, with no temporary and
// no rename:
//
//   - view_file opens the file three times in a row.
//   - write_to_file of a new file: an ambiguous write of the file's directory
//     (the create, which fanotify reports without the name), then in the same
//     batch the file's open, whose input hash is that of empty content (the
//     probe stamps it on the open that created the file, P-22), its write and
//     its close with the hash of the content.
//   - write_to_file over an existing file and replace_file_content: an open
//     (the harness reads the file), then the open that truncates it, its write
//     and its close with the hash of the content.
//
// The claims are an open for view_file and an open, a write and a close for
// the other two, so the observed side is rewritten to that grain: the create
// is dropped and a run of opens of one file becomes one open. Nothing else is
// rewritten, and a shape not listed stays as the probe reported it.

// emptyHash is the input hash the probe gives the open that created a file.
var emptyHash = content.SHA256Bytes(nil)

// batchSpan bounds the distance between two records of one fanotify batch:
// the probe stamps a batch with one clock reading plus one nanosecond per
// record (P-18). The create and the creating open were one nanosecond apart
// in every case of the capture, the agent's and the harness's.
const batchSpan = time.Microsecond

// NormalizeStream rewrites the processes of a grep_search call to the
// claim's target, folding a failed ripgrep and its fallback grep into one
// search (I-54, foldSearches), drops the create of a file the agent's process
// creates and collapses its runs of opens of one file (I-50). Events are in
// time order, ties in the order the probe emitted them.
func (Adapter) NormalizeStream(g models.GroundTruth) models.GroundTruth {
	g = foldSearches(g)
	started := commands(g)
	return collapseOpens(foldCreates(g, started), started)
}

// commands returns the processes the stream shows being forked, exec'd or
// exiting. Those are commands the agent ran, never the agent's own process,
// whose start precedes the capture: their events are the command's content,
// which its claim explains, and no fold touches them. NormalizeStream does
// not receive the root pid (I-43).
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

// agentFile reports whether e is a file event of the agent's own process on a
// path that is not the harness's (I-48): the events the folds may rewrite.
// The harness's own files keep the shape the controls measured.
func agentFile(e models.GroundTruthEvent, started map[uint32]bool) bool {
	return isFile(e.ActionType) && e.PID != 0 && !started[e.PID] && !harnessOwned.MatchString(e.Target)
}

// foldCreates drops an ambiguous file_write of a directory by the agent's
// process when that process's next event is the open that created a file
// directly in that directory, in the same batch: the open is not ambiguous
// and carries the hash of empty content, which the probe stamps only on the
// first open of a file born during the capture (P-22). The create says
// nothing the open, write and close of the file do not, and no claim states
// it. An ambiguous write of a directory followed by anything else (another
// file's open, an open with content, a later batch, another event of the
// process) is kept and shows as it is.
func foldCreates(g models.GroundTruth, started map[uint32]bool) models.GroundTruth {
	var drop []int
	for i, e := range g {
		if e.ActionType != models.FileWrite || !e.PathIsAmbiguous || !agentFile(e, started) {
			continue
		}
		for j := i + 1; j < len(g); j++ {
			n := g[j]
			if n.PID != e.PID {
				continue
			}
			if n.ActionType == models.FileOpen && !n.PathIsAmbiguous && filepath.Dir(n.Target) == e.Target &&
				n.InputHash != nil && *n.InputHash == emptyHash && n.Timestamp.Sub(e.Timestamp) < batchSpan &&
				!harnessOwned.MatchString(n.Target) {
				drop = append(drop, i)
			}
			break
		}
	}
	if len(drop) == 0 {
		return g
	}
	out := make(models.GroundTruth, 0, len(g)-len(drop))
	k := 0
	for i, e := range g {
		if k < len(drop) && drop[k] == i {
			k++
			continue
		}
		out = append(out, e)
	}
	return out
}

// collapseOpens keeps the first of a run of opens of one file by the agent's
// process: an open whose process's previous event is an open of the same
// file, neither ambiguous, is dropped. Any other event of the process, on any
// path, the harness's own files included, ends the run. The harness writes
// its transcripts between two tool calls, so the opens of two calls on one
// file stay two; the claims are not collapsed.
func collapseOpens(g models.GroundTruth, started map[uint32]bool) models.GroundTruth {
	last := map[uint32]models.GroundTruthEvent{}
	out := make(models.GroundTruth, 0, len(g))
	for _, e := range g {
		prev, seen := last[e.PID]
		last[e.PID] = e
		if seen && e.ActionType == models.FileOpen && prev.ActionType == models.FileOpen && prev.Target == e.Target &&
			!e.PathIsAmbiguous && !prev.PathIsAmbiguous && agentFile(e, started) {
			continue
		}
		out = append(out, e)
	}
	return out
}
