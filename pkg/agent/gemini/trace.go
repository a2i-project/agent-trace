package gemini

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

const homeRE = `/(?:home/[^/]+|root)`

// homePattern is a home a capture may record (I-30).
var homePattern = regexp.MustCompile(`^` + homeRE + `$`)

// Trace declares, when the conversation's id is not known, every
// conversation database under ~/.gemini/antigravity-cli/conversations/ as a
// main session file, the database Parse reads (I-102, V-75). SessionTrace
// declares the session's own database and those of the subagents it names
// only, and Parse gives their ids from the databases (I-105, V-80); Trace is what a database that does not state its id
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

// SessionTrace declares the conversation database of the session,
// ~/.gemini/antigravity-cli/conversations/<id>.db, as its main session file,
// and the databases of the subagent conversations it names
// (Report.TraceSubagents), each covered with its -wal and -journal, both
// transient, as Trace does for every database (I-105, V-80). Every other
// conversation's database is an ordinary file: a claimed command's events on
// it are explained by that command, and an unclaimed one is a finding as on
// any file. An id that is not a conversation id declares nothing, and a
// subagent id that is not one is left out.
func (Adapter) SessionTrace(_, home string, s agent.TraceSession) *verification.TraceDecl {
	if !conversationID.MatchString(s.ID) {
		return nil
	}
	ids := []string{regexp.QuoteMeta(s.ID)}
	for _, id := range s.Subagents {
		if conversationID.MatchString(id) && id != s.ID {
			ids = append(ids, regexp.QuoteMeta(id))
		}
	}
	d := declare(home, `(?:`+strings.Join(ids, "|")+`)`)
	if d == nil {
		return nil
	}
	own := declare(home, regexp.QuoteMeta(s.ID))
	d.Main = own.Main
	return d
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
