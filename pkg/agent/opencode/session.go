package opencode

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver, no cgo

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/models"
)

// OpenCode 1.19.5 keeps every session of the account in one SQLite
// database (I-114). Of it the adapter reads the session table (id,
// parent_id, directory, version) and the part table (id, message_id,
// session_id, data), whose tool parts state each call: its tool, its call
// id and its state, with status, input, output, metadata and the start and
// end of its execution in milliseconds (I-120).

var sqliteMagic = []byte("SQLite format 3\x00")

// sessionIDRE is the form of a session id: ses_ and 26 letters and digits.
var sessionIDRE = regexp.MustCompile(`^ses_[0-9A-Za-z]{26}$`)

// Detect recognises an OpenCode database: the SQLite header, a session
// table with parent_id and version, and a part table with data.
func (Adapter) Detect(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	head := make([]byte, len(sqliteMagic))
	_, rerr := io.ReadFull(f, head)
	_ = f.Close()
	if rerr != nil || !bytes.Equal(head, sqliteMagic) {
		return false
	}
	db, done, err := openSnapshot(path)
	if err != nil {
		return false
	}
	defer done()
	return hasColumns(db, "session", "parent_id", "version", "directory") && hasColumns(db, "part", "data", "session_id", "message_id")
}

func hasColumns(db *sql.DB, table string, cols ...string) bool {
	rows, err := db.Query(`select name from pragma_table_info(?)`, table)
	if err != nil {
		return false
	}
	defer func() { _ = rows.Close() }()
	have := map[string]bool{}
	for rows.Next() {
		var n string
		if rows.Scan(&n) == nil {
			have[n] = true
		}
	}
	for _, c := range cols {
		if !have[c] {
			return false
		}
	}
	return true
}

// openSnapshot opens a private copy of the database and its write-ahead
// log, as the Gemini adapter does (I-51): reading in place would create the
// shared-memory index beside the evidence. done closes and removes it.
func openSnapshot(path string) (db *sql.DB, done func(), err error) {
	dir, err := os.MkdirTemp("", "agent-trace-opencode-")
	if err != nil {
		return nil, nil, err
	}
	remove := func() { _ = os.RemoveAll(dir) }
	snap := filepath.Join(dir, "opencode.db")
	if err := copyFile(path, snap); err != nil {
		remove()
		return nil, nil, err
	}
	if err := copyFile(path+"-wal", snap+"-wal"); err != nil && !errors.Is(err, fs.ErrNotExist) {
		remove()
		return nil, nil, err
	}
	db, err = sql.Open("sqlite", "file:"+url.PathEscape(snap)+"?mode=ro")
	if err != nil {
		remove()
		return nil, nil, err
	}
	return db, func() { _ = db.Close(); remove() }, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// Parse reads the database's one session: the session that no other
// session is the parent of and that has no parent, when there is exactly
// one, as in a fixture reduced to the run's session (I-120). A database of
// several sessions, as OpenCode keeps one for the account, needs the id the
// capture recorded (ParseSession, I-110).
func (a Adapter) Parse(path string) (models.Trajectory, agent.Report, error) {
	db, done, err := openSnapshot(path)
	if err != nil {
		return nil, agent.Report{}, err
	}
	defer done()
	rows, err := db.Query(`select id from session where parent_id is null order by id`)
	if err != nil {
		return nil, agent.Report{}, fmt.Errorf("read sessions: %w", err)
	}
	var roots []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, agent.Report{}, err
		}
		roots = append(roots, id)
	}
	_ = rows.Close()
	if len(roots) != 1 {
		return nil, agent.Report{}, fmt.Errorf("the database holds %d sessions without a parent: the session id the capture recorded names the run's (--session-id, I-110)", len(roots))
	}
	return readSession(db, roots[0])
}

// ParseSession reads the session id names and its subagents (I-110,
// I-120).
func (Adapter) ParseSession(path, id string) (models.Trajectory, agent.Report, error) {
	if !sessionIDRE.MatchString(id) {
		return nil, agent.Report{}, fmt.Errorf("%q is not an OpenCode session id", id)
	}
	db, done, err := openSnapshot(path)
	if err != nil {
		return nil, agent.Report{}, err
	}
	defer done()
	return readSession(db, id)
}

type session struct {
	id, parent, directory, version string
}

// toolPart is a tool part of a session, as the adapter reads it.
type toolPart struct {
	id, message, session string
	data                 struct {
		Type   string `json:"type"`
		Tool   string `json:"tool"`
		CallID string `json:"callID"`
		State  struct {
			Status   string          `json:"status"`
			Input    json.RawMessage `json:"input"`
			Output   json.RawMessage `json:"output"`
			Metadata json.RawMessage `json:"metadata"`
			Time     struct {
				Start *int64 `json:"start"`
				End   *int64 `json:"end"`
			} `json:"time"`
		} `json:"state"`
	}
	start, end time.Time
	dir        string // the session's directory, against which a relative path resolves
}

// maxSubagentDepth bounds the parent chain the adapter follows; a deeper
// session is reported, not read. OpenCode's subagents cannot start
// subagents (the task tool is denied to them), so one level is the shape.
const maxSubagentDepth = 8

func readSession(db *sql.DB, id string) (models.Trajectory, agent.Report, error) {
	rep := agent.Report{TraceSession: id}
	root, err := sessionRow(db, id)
	if err != nil {
		return nil, rep, err
	}
	if root.parent != "" {
		return nil, rep, fmt.Errorf("session %s is a subagent of %s, not a run's session", id, root.parent)
	}
	if root.version == "" {
		return nil, rep, fmt.Errorf("session %s states no version", id)
	}
	rep.AgentVersion = root.version
	sessions := []session{root}
	// The subagents: every session whose parent chain leads to the run's
	// session (I-114), breadth first.
	frontier := []string{id}
	seen := map[string]bool{id: true}
	for depth := 1; len(frontier) > 0; depth++ {
		var next []string
		for _, p := range frontier {
			kids, err := children(db, p)
			if err != nil {
				return nil, rep, err
			}
			for _, k := range kids {
				if seen[k.id] {
					continue
				}
				seen[k.id] = true
				if depth > maxSubagentDepth {
					rep.Degradations = append(rep.Degradations, fmt.Sprintf("subagent session %s is nested deeper than %d levels and is not read", k.id, maxSubagentDepth))
					continue
				}
				sessions = append(sessions, k)
				rep.TraceSubagents = append(rep.TraceSubagents, k.id)
				next = append(next, k.id)
			}
		}
		frontier = next
	}
	sort.Strings(rep.TraceSubagents)
	var parts []toolPart
	for _, s := range sessions {
		ps, perrs, err := toolParts(db, s)
		if err != nil {
			return nil, rep, err
		}
		parts = append(parts, ps...)
		rep.ParseErrors = append(rep.ParseErrors, perrs...)
	}
	// Execution order: a part's start, ties by its id (OpenCode's ids grow
	// with time).
	sort.SliceStable(parts, func(i, j int) bool {
		if !parts[i].start.Equal(parts[j].start) {
			return parts[i].start.Before(parts[j].start)
		}
		return parts[i].id < parts[j].id
	})
	tr := claimParts(parts, root.id, &rep)
	// The subagents the task calls name and the sessions the chain gives
	// must agree; a difference is reported, the chain decides (I-114).
	named := map[string]bool{}
	for _, p := range parts {
		if p.data.Tool == toolTask && p.data.State.Status == statusCompleted {
			var m struct {
				SessionID string `json:"sessionId"`
			}
			if json.Unmarshal(p.data.State.Metadata, &m) == nil && m.SessionID != "" {
				named[m.SessionID] = true
			}
		}
	}
	var notes []string
	for n := range named {
		if !seen[n] {
			notes = append(notes, fmt.Sprintf("a task call names subagent session %s, which the database does not hold under the session", n))
		}
	}
	for _, s := range rep.TraceSubagents {
		if !named[s] {
			notes = append(notes, fmt.Sprintf("subagent session %s is a child of the session that no completed task call names", s))
		}
	}
	sort.Strings(notes)
	rep.Degradations = append(rep.Degradations, notes...)
	rep.Entries = len(tr)
	return tr, rep, nil
}

func sessionRow(db *sql.DB, id string) (session, error) {
	var s session
	var parent, dir, version sql.NullString
	err := db.QueryRow(`select id, parent_id, directory, version from session where id = ?`, id).Scan(&s.id, &parent, &dir, &version)
	if errors.Is(err, sql.ErrNoRows) {
		return s, fmt.Errorf("the database holds no session %s", id)
	}
	if err != nil {
		return s, fmt.Errorf("read session %s: %w", id, err)
	}
	s.parent, s.directory, s.version = parent.String, dir.String, version.String
	return s, nil
}

func children(db *sql.DB, parent string) ([]session, error) {
	rows, err := db.Query(`select id, directory, version from session where parent_id = ? order by id`, parent)
	if err != nil {
		return nil, fmt.Errorf("read subagents of %s: %w", parent, err)
	}
	defer func() { _ = rows.Close() }()
	var out []session
	for rows.Next() {
		var s session
		var dir, version sql.NullString
		if err := rows.Scan(&s.id, &dir, &version); err != nil {
			return nil, err
		}
		s.parent, s.directory, s.version = parent, dir.String, version.String
		out = append(out, s)
	}
	return out, rows.Err()
}

// toolParts reads the session's tool parts. A part whose data does not
// parse, or a tool part without a tool, a status or a start time, is a
// parse error.
func toolParts(db *sql.DB, s session) ([]toolPart, []string, error) {
	rows, err := db.Query(`select id, message_id, data from part where session_id = ? order by id`, s.id)
	if err != nil {
		return nil, nil, fmt.Errorf("read parts of %s: %w", s.id, err)
	}
	defer func() { _ = rows.Close() }()
	var out []toolPart
	var perrs []string
	for rows.Next() {
		var p toolPart
		var data string
		if err := rows.Scan(&p.id, &p.message, &data); err != nil {
			return nil, nil, err
		}
		p.session, p.dir = s.id, s.directory
		if err := json.Unmarshal([]byte(data), &p.data); err != nil {
			perrs = append(perrs, fmt.Sprintf("part %s: %v", p.id, err))
			continue
		}
		if p.data.Type != "tool" {
			continue
		}
		st := p.data.State
		switch {
		case p.data.Tool == "":
			perrs = append(perrs, fmt.Sprintf("part %s: a tool part without a tool", p.id))
			continue
		case st.Status == "":
			perrs = append(perrs, fmt.Sprintf("part %s: a tool part without a status", p.id))
			continue
		}
		if st.Time.Start != nil {
			p.start = time.UnixMilli(*st.Time.Start)
		}
		if st.Time.End != nil {
			p.end = time.UnixMilli(*st.Time.End)
		}
		if (st.Status == statusCompleted || st.Status == statusError) && (st.Time.Start == nil || st.Time.End == nil || p.end.Before(p.start)) {
			perrs = append(perrs, fmt.Sprintf("part %s: a %s %s call without its execution's start and end", p.id, st.Status, p.data.Tool))
			continue
		}
		out = append(out, p)
	}
	return out, perrs, rows.Err()
}
