package gemini

import (
	"path/filepath"
	"regexp"

	"github.com/agent-trace/agent-trace/pkg/verification"
)

const homeRE = `/(?:home/[^/]+|root)`

// homePattern is a home a capture may record (I-30).
var homePattern = regexp.MustCompile(`^` + homeRE + `$`)

// Trace declares the session's own trace (I-102): every conversation
// database under ~/.gemini/antigravity-cli/conversations/ as a main session
// file, the database Parse reads. A subagent keeps a database of its own,
// <id>.db in the same directory (I-55), and the name holds no workspace, so
// every conversation of the account is declared, as Codex declares every
// rollout (I-84). The home is the capture's, else any home I-30 declares.
// Covers is nil: a stock SQLite client that only reads a database in
// write-ahead-log mode closes it after opening it for writing and creates,
// writes and deletes its -wal and -shm files, so which write-class events on
// these files are tampering (V-59) waits on a decision (O-37). Until then
// the declaration makes a missing or damaged database a trace that cannot be
// verified, and lists what the capture saw happen to the database, and
// nothing reads as tampering.
func (Adapter) Trace(_, home string) *verification.TraceDecl {
	h := homeRE
	if home != "" {
		if home != filepath.Clean(home) || !homePattern.MatchString(home) {
			return nil
		}
		h = regexp.QuoteMeta(home)
	}
	main := regexp.MustCompile(`^` + h + `/\.gemini/antigravity-cli/conversations/` + uuidRE.String() + `\.db$`)
	return &verification.TraceDecl{Main: main.MatchString}
}
