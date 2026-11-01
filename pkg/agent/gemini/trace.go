package gemini

import (
	"path/filepath"
	"regexp"

	"github.com/agent-trace/agent-trace/pkg/verification"
)

const homeRE = `/(?:home/[^/]+|root)`

// homePattern is a home a capture may record (I-30).
var homePattern = regexp.MustCompile(`^` + homeRE + `$`)

// Trace declares the session's own trace (I-102, V-75): every conversation
// database under ~/.gemini/antigravity-cli/conversations/ as a main session
// file, the database Parse reads. A subagent keeps a database of its own,
// <id>.db in the same directory (I-55), and the name holds no workspace, so
// every conversation of the account is declared, as Codex declares every
// rollout (I-84). The home is the capture's, else any home I-30 declares.
// Covers adds each database's write-ahead log and rollback journal, which
// hold steps not yet in the database, and not its -shm, an index every
// reader rebuilds from the log and writes through a shared mapping (V-75).
// The -wal and -journal are Transient: a stock SQLite client that reads a
// database no other process holds open creates its -wal and deletes it at
// the close (V-76).
func (Adapter) Trace(_, home string) *verification.TraceDecl {
	h := homeRE
	if home != "" {
		if home != filepath.Clean(home) || !homePattern.MatchString(home) {
			return nil
		}
		h = regexp.QuoteMeta(home)
	}
	db := `^` + h + `/\.gemini/antigravity-cli/conversations/` + uuidRE.String() + `\.db`
	main := regexp.MustCompile(db + `$`)
	covered := regexp.MustCompile(db + `(?:-wal|-journal)?$`)
	transient := regexp.MustCompile(db + `(?:-wal|-journal)$`)
	return &verification.TraceDecl{Covers: covered.MatchString, Main: main.MatchString, Transient: transient.MatchString}
}
