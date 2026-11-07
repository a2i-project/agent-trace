package claudecode

import (
	"path/filepath"
	"regexp"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// Trace declares the session's own trace (I-74): every session transcript
// of the workspace's project directory,
// ~/.claude/projects/<project>/<session id>.jsonl, and every session's
// subagents directory <project>/<session id>/subagents with what is beneath
// it, which Parse merges (D8). <project> is the workspace as the harness
// names it (I-70); a name over 200 characters is matched as the harness
// cuts it, the first 200 followed by a dash and its base-36 hash. The home
// is the one the capture resolved "~/" against, else any home I-30
// declares. Without a workspace nothing is declared, since the project
// directory cannot be named. Every session of the project is declared, not
// only the one verified: a campaign's workspace holds one session, and the
// session's id is unknown when its transcript is gone; SessionTrace
// narrows it when the capture recorded the id (V-81). The project
// directory's other contents (the auto-memory, tool results) are not trace
// files.
func (Adapter) Trace(workspace, home string) *verification.TraceDecl {
	return declareTrace(workspace, home, uuidPattern)
}

// SessionTrace narrows the trace to one session when its id is known from
// the capture (V-81, cmd/verify --session-id): its transcript
// <project>/<id>.jsonl and its subagents directory <project>/<id>/subagents
// with what is beneath it, as agy's and Codex's traces are one session's.
// The session's record states no id the declaration takes (Report.TraceSession
// stays empty), so without --session-id Trace decides, as I-74 does. An id
// that is not a session id (a UUID) declares nothing here, and Trace then
// decides. For a version in checkpointVersions it also declares the
// session's edit checkpoints (declareCheckpoint, V-104).
func (Adapter) SessionTrace(workspace, home string, s agent.TraceSession) *verification.TraceDecl {
	if !sessionIDPattern.MatchString(s.ID) {
		return nil
	}
	d := declareTrace(workspace, home, regexp.QuoteMeta(s.ID))
	if d != nil {
		d.Checkpoint = declareCheckpoint(home, s.ID, s.Version)
	}
	return d
}

// sessionIDPattern is a Claude Code session id, as its transcripts are named.
var sessionIDPattern = regexp.MustCompile(`^` + uuidPattern + `$`)

// declareTrace covers, in the workspace's project directory under home,
// the transcripts and subagents directories of the sessions id matches.
func declareTrace(workspace, home, id string) *verification.TraceDecl {
	if workspace == "" || workspace != filepath.Clean(workspace) || !filepath.IsAbs(workspace) {
		return nil
	}
	h := `/(?:home/[^/]+|root)`
	if home != "" {
		if home != filepath.Clean(home) || !homePattern.MatchString(home) {
			return nil
		}
		h = regexp.QuoteMeta(home)
	}
	name, ok := agent.MangledWorkspace(workspace)
	project := regexp.QuoteMeta(name)
	if !ok {
		project = regexp.QuoteMeta(name[:agent.MaxMangled]) + `-[0-9a-z]+`
	}
	dir := `^` + h + `/\.claude/projects/` + project + `/` + id
	main := regexp.MustCompile(dir + `\.jsonl$`)
	sub := regexp.MustCompile(dir + `/subagents(?:/|$)`)
	return &verification.TraceDecl{
		Covers: func(p string) bool { return main.MatchString(p) || sub.MatchString(p) },
		Main:   main.MatchString,
	}
}
