package gemini

import (
	"path/filepath"
	"regexp"

	"github.com/agent-trace/agent-trace/pkg/verification"
)

const homeRE = `/(?:home/[^/]+|root)`

// homePattern is a home a capture may record (I-30).
var homePattern = regexp.MustCompile(`^` + homeRE + `$`)

// Trace declares, when the conversation's id is not known, every
// conversation database under ~/.gemini/antigravity-cli/conversations/ as a
// main session file, the database Parse reads (I-102, V-75). SessionTrace
// declares the session's own database only, and Parse gives its id from the
// database (I-105); Trace is what a database that does not state its id
// gets, as the checked-in fixtures, which keep the steps only, do. The home
// is the capture's, else any home I-30 declares. Covers adds each
// database's write-ahead log and rollback journal, which hold steps not yet
// in the database, and not its -shm, an index every reader rebuilds from the
// log and writes through a shared mapping (V-75). The -wal and -journal are
// Transient: a stock SQLite client that reads a database no other process
// holds open creates its -wal and deletes it at the close (V-76).
func (Adapter) Trace(_, home string) *verification.TraceDecl {
	return declare(home, uuidRE.String())
}

// SessionTrace declares the conversation database of the session whose id
// the database states, ~/.gemini/antigravity-cli/conversations/<id>.db, as
// its main session file, covered with its -wal and -journal, both transient,
// as Trace does for every database (I-105). Every other conversation's
// database, the session's subagents' included, is an ordinary file: a
// claimed command's events on it are explained by that command, and an
// unclaimed one is a finding as on any file. An id that is not a
// conversation id declares nothing.
func (Adapter) SessionTrace(_, home, session string) *verification.TraceDecl {
	if !conversationID.MatchString(session) {
		return nil
	}
	return declare(home, regexp.QuoteMeta(session))
}

// declare covers the databases named id (a pattern) under home.
func declare(home, id string) *verification.TraceDecl {
	h := homeRE
	if home != "" {
		if home != filepath.Clean(home) || !homePattern.MatchString(home) {
			return nil
		}
		h = regexp.QuoteMeta(home)
	}
	db := `^` + h + `/\.gemini/antigravity-cli/conversations/` + id + `\.db`
	main := regexp.MustCompile(db + `$`)
	covered := regexp.MustCompile(db + `(?:-wal|-journal)?$`)
	transient := regexp.MustCompile(db + `(?:-wal|-journal)$`)
	return &verification.TraceDecl{Covers: covered.MatchString, Main: main.MatchString, Transient: transient.MatchString}
}
