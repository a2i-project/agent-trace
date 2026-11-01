package gemini

import (
	"path/filepath"

	"github.com/agent-trace/agent-trace/pkg/content"
	"github.com/agent-trace/agent-trace/pkg/models"
)

// What the paired capture of the basic task with agy 1.3.4 showed at the
// kernel level (I-50), all by the agent's own process, with no temporary and
// no rename:
//
//   - view_file opens the file three times in a row.
//   - write_to_file of a new file: an ambiguous write of the file's directory
//     (the create, which fanotify reported without the name before P-25, and
//     reports as a write naming the file since), then in the same batch the
//     file's open, whose input hash is that of empty content (the probe stamps
//     it on the open that created the file, P-22), its write and its close
//     with the hash of the content.
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

// foldCreates drops the create of a file by the agent's process when that
// process's next file event is the open that created the file: the open is
// not ambiguous and carries the hash of empty content, which the probe
// stamps only on the first open of a file born during the capture (P-22).
// The create says nothing the open, write and close of the file do not, and
// no claim states it. No time bound applies (I-99, as for Codex): that open
// created the file wherever the probe's reads split the batches. A capture
// made before the probe named directory entries (P-25) reports the create as
// an ambiguous file_write of the directory, and the open then names a file
// directly in it; a capture made since reports it as a file_write naming the
// file, with no hash, and the open must name that same file (I-56). A create
// whose process's next file event is anything else (another file's open, an
// open with content, a write) is kept and shows as it is.
func foldCreates(g models.GroundTruth, started map[uint32]bool) models.GroundTruth {
	var drop []int
	for i, e := range g {
		if e.ActionType != models.FileWrite || e.OutputHash != nil || !agentFile(e, started) {
			continue
		}
		for j := i + 1; j < len(g); j++ {
			n := g[j]
			if n.PID != e.PID || !isFile(n.ActionType) {
				continue
			}
			created := filepath.Dir(n.Target) == e.Target // before P-25: the create names the directory
			if !e.PathIsAmbiguous {
				created = n.Target == e.Target // since P-25: the create names the file
			}
			if n.ActionType == models.FileOpen && !n.PathIsAmbiguous && created &&
				n.InputHash != nil && *n.InputHash == emptyHash && !harnessOwned.MatchString(n.Target) {
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
