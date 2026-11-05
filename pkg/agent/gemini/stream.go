package gemini

import (
	"path/filepath"
	"regexp"

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
// search (I-54, I-133, foldSearches), drops the create of a file the agent's
// process creates and collapses its runs of opens of one file (I-50). Events
// are in time order, ties in the order the probe emitted them.
func (a Adapter) NormalizeStream(g models.GroundTruth) models.GroundTruth {
	g = foldSearches(g, a.root)
	started := commands(g)
	return collapseOpens(foldCreates(g, started), started)
}

// commands returns the processes the stream shows being forked, exec'd or
// exiting. Those are commands the agent ran, never the agent's own process,
// whose start precedes the capture: their events are the command's content,
// which its claim explains, and no fold touches them. This needs no root pid,
// so a capture without one folds alike.
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
// path, the harness's own files included, ends the run, except that a run
// of opens of a file outside ~/.gemini, or of a task log (I-135), passes
// over an open of the harness's project configuration (projectConfig,
// I-118), which is kept. The
// harness's start-up reads of its configuration keep their shape, and opens
// of the project configuration itself collapse as any file's. The harness
// writes its transcripts between two tool calls, so the opens of two calls
// on one file stay two; the claims are not collapsed.
func collapseOpens(g models.GroundTruth, started map[uint32]bool) models.GroundTruth {
	// last is each process's previous event; other its previous event that
	// is not an open of the project configuration.
	last := map[uint32]models.GroundTruthEvent{}
	other := map[uint32]models.GroundTruthEvent{}
	out := make(models.GroundTruth, 0, len(g))
	for i, e := range g {
		prev, seen := last[e.PID]
		if config := e.ActionType == models.FileOpen && !e.PathIsAmbiguous && projectConfig.MatchString(e.Target); !config {
			if !geminiHome.MatchString(e.Target) || taskLog.MatchString(e.Target) {
				prev, seen = other[e.PID]
			}
			other[e.PID] = e
		}
		last[e.PID] = e
		if seen && e.ActionType == models.FileOpen && prev.ActionType == models.FileOpen && prev.Target == e.Target &&
			!e.PathIsAmbiguous && !prev.PathIsAmbiguous && (agentFile(e, started) || taskLogRead(g, i, started)) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// taskLogRead reports whether g[i] is an open by the agent's own process of
// a background task's log (V-92) that only reads it: view_file reads the log
// in the three opens of I-50 while the harness keeps writing it (I-135). An
// open whose process's next event is a write of the log is the harness's,
// beginning that write, and is never collapsed, so a run of the agent's
// opens never takes the open of the harness's next write.
func taskLogRead(g models.GroundTruth, i int, started map[uint32]bool) bool {
	e := g[i]
	if e.ActionType != models.FileOpen || e.PID == 0 || started[e.PID] || !taskLog.MatchString(e.Target) {
		return false
	}
	for _, n := range g[i+1:] {
		if n.PID == e.PID {
			return n.ActionType != models.FileWrite || n.Target != e.Target
		}
	}
	return true
}

// taskLog is a background task's log under any home's conversation brain
// directory, the shape HarnessBookkeeping declares for 1.4.7.
var taskLog = regexp.MustCompile(`^` + homeRE + `/\.gemini/antigravity-cli/brain/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/\.system_generated/` + taskLogTail)

// projectConfig is the harness's project configuration, which agy's process
// opens, and only opens, before each file tool call. On the content capture
// of the basic task with agy 1.4.7 (I-118) its open fell between the first
// and the second of view_file's three opens of the file, 31 microseconds
// after the first, so it would have split their run; the probe records the
// process, not the thread. Only its open is passed over, and only in a run
// of opens of a file outside ~/.gemini (geminiHome): a write or a close of
// it, any other file and any other event still end a run.
var (
	projectConfig = regexp.MustCompile(`^/(?:home/[^/]+|root)/\.gemini/config/projects/[^/]+\.json$`)
	geminiHome    = regexp.MustCompile(`^/(?:home/[^/]+|root)/\.gemini/`)
)
