package gemini

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/content"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// The declaration names every conversation database of the home as a main
// session file, and covers each database with its -wal and -journal, both
// transient, not its -shm (I-102, V-75, V-76).
func TestTraceDeclaresTheConversationDatabases(t *testing.T) {
	const id = "0b18d7d3-41b4-4dfe-b649-e8ba776c383a"
	conv := "/home/u/.gemini/antigravity-cli/conversations/"
	d := Adapter{}.Trace("/ws/basic", "/home/u")
	if d == nil || d.Covers == nil || d.Main == nil || d.Transient == nil {
		t.Fatalf("declaration %+v, want Covers, Main and Transient", d)
	}
	type want struct{ main, covers, transient bool }
	for path, w := range map[string]want{
		conv + id + ".db":         {true, true, false},
		conv + id + ".db-wal":     {false, true, true},
		conv + id + ".db-journal": {false, true, true},
		conv + id + ".db-shm":     {false, false, false},
		conv + "x.db":             {false, false, false},
		conv + "x.db-wal":         {false, false, false},
		"/home/u/.gemini/antigravity-cli/conversation_summaries.db":                                {false, false, false},
		"/home/u/.gemini/antigravity-cli/brain/" + id + "/.system_generated/logs/transcript.jsonl": {false, false, false},
		"/home/v/.gemini/antigravity-cli/conversations/" + id + ".db":                              {false, false, false},
		"/home/v/.gemini/antigravity-cli/conversations/" + id + ".db-wal":                          {false, false, false},
		conv + id + ".db (deleted)":     {false, false, false},
		conv + id + ".db-wal (deleted)": {false, false, false},
	} {
		if got := (want{d.Main(path), d.Covers(path), d.Transient(path)}); got != w {
			t.Errorf("%s: main, covers, transient = %v, want %v", path, got, w)
		}
	}
	d = Adapter{}.Trace("", "")
	if !d.Main("/root/.gemini/antigravity-cli/conversations/"+id+".db") || !d.Main("/home/x/.gemini/antigravity-cli/conversations/"+id+".db") {
		t.Error("without a home, the database under any home should be declared")
	}
	for _, home := range []string{"/etc", "/home/u/", "/home/u/../v"} {
		if (Adapter{}).Trace("/ws", home) != nil {
			t.Errorf("home %q: want no declaration", home)
		}
	}
}

// Given the session's conversation id, the declaration names that
// conversation's database only, with its -wal and -journal, both transient,
// and not its -shm; every other conversation's database, a subagent's
// included, is not the session's trace (I-105). An id that is not a
// conversation id declares nothing.
func TestSessionTraceDeclaresTheSessionsOwnDatabaseOnly(t *testing.T) {
	const (
		id    = "0b18d7d3-41b4-4dfe-b649-e8ba776c383a"
		other = "11111111-2222-4333-8444-555555555555"
	)
	conv := "/home/u/.gemini/antigravity-cli/conversations/"
	d := Adapter{}.SessionTrace("/ws/basic", "/home/u", id)
	if d == nil || d.Covers == nil || d.Main == nil || d.Transient == nil {
		t.Fatalf("declaration %+v, want Covers, Main and Transient", d)
	}
	type want struct{ main, covers, transient bool }
	for path, w := range map[string]want{
		conv + id + ".db":            {true, true, false},
		conv + id + ".db-wal":        {false, true, true},
		conv + id + ".db-journal":    {false, true, true},
		conv + id + ".db-shm":        {false, false, false},
		conv + other + ".db":         {false, false, false},
		conv + other + ".db-wal":     {false, false, false},
		conv + other + ".db-journal": {false, false, false},
		"/home/v/.gemini/antigravity-cli/conversations/" + id + ".db": {false, false, false},
	} {
		if got := (want{d.Main(path), d.Covers(path), d.Transient(path)}); got != w {
			t.Errorf("%s: main, covers, transient = %v, want %v", path, got, w)
		}
	}
	if d := (Adapter{}).SessionTrace("", "", id); d == nil || !d.Main("/home/x/.gemini/antigravity-cli/conversations/"+id+".db") {
		t.Error("without a home, the session's database under any home should be declared")
	}
	for _, s := range []string{"x", id + ".db", "../" + id, id[:35], strings.ToUpper(id)} {
		if (Adapter{}).SessionTrace("", "/home/u", s) != nil {
			t.Errorf("session %q: want no declaration", s)
		}
	}
	if (Adapter{}).SessionTrace("", "/etc", id) != nil {
		t.Error("a home that is not a home declares a trace")
	}
	// agent.Trace takes the session's declaration when the record states its
	// id, and every database's without one.
	g := models.GroundTruthFile{Sensitive: &models.SensitiveSnapshot{Home: "/home/u"}}
	if d := agent.Trace(Adapter{}, g, id); d == nil || d.Covers(conv+other+".db") || !d.Covers(conv+id+".db") {
		t.Error("with the session's id, agent.Trace should cover its database only")
	}
	if d := agent.Trace(Adapter{}, g, ""); d == nil || !d.Covers(conv+other+".db") {
		t.Error("without an id, agent.Trace should cover every database")
	}
}

// A command's change of another conversation's database is not trace
// tampering when the session's id is known; the same change of the
// session's own database is (I-105). The shape is the 1.4.7 pilot's: a
// command that reads every conversation with Python's sqlite3 deletes the
// -wal another session left.
func TestAnotherConversationsDatabaseIsNotTheSessionsTrace(t *testing.T) {
	const (
		root  = 100
		id    = "0b18d7d3-41b4-4dfe-b649-e8ba776c383a"
		other = "11111111-2222-4333-8444-555555555555"
		cmd   = "/usr/bin/python3 -c inspect"
	)
	conv := "/home/u/.gemini/antigravity-cli/conversations/"
	t0 := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	run := func(target string) verification.Verdict {
		g := models.GroundTruth{
			{Timestamp: t0.Add(10 * time.Millisecond), ActionType: models.ProcessFork, Target: "x", PID: 200, PPID: root},
			{Timestamp: t0.Add(11 * time.Millisecond), ActionType: models.ProcessExec, Target: cmd, PID: 200, PPID: root},
			{Timestamp: t0.Add(20 * time.Millisecond), ActionType: models.FileOpen, Target: target, PID: 200, PPID: root},
			{Timestamp: t0.Add(21 * time.Millisecond), ActionType: models.FileClose, Target: target, PID: 200, PPID: root},
			{Timestamp: t0.Add(22 * time.Millisecond), ActionType: models.FileDelete, Target: target, PID: 200, PPID: root},
			{Timestamp: t0.Add(90 * time.Millisecond), ActionType: models.ProcessExit, Target: cmd, PID: 200, PPID: root},
		}
		return verification.Verify(verification.Input{Ground: g, RootPID: root, Trace: verification.TraceInput{Decl: Adapter{}.SessionTrace("", "/home/u", id)}})
	}
	if v := run(conv + other + ".db-wal"); len(v.TraceTampering) != 0 {
		t.Errorf("another conversation's -wal deleted: tampering %+v, want none", v.TraceTampering)
	}
	if v := run(conv + id + ".db-wal"); len(v.TraceTampering) != 1 {
		t.Errorf("the session's own -wal deleted: tampering %+v, want the delete", v.TraceTampering)
	}
}

// Parse gives the conversation id the database states in its one
// trajectory_meta row, and none when the database states none (the
// fixtures keep the steps only), more than one, or one that is not a
// conversation id (I-105).
func TestParseStatesTheConversationID(t *testing.T) {
	const id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	if _, rep, err := (Adapter{}).Parse(filepath.Join(pairedDir, "basic.conversation.db")); err != nil || rep.TraceSession != "" {
		t.Fatalf("fixture: session %q, err %v, want none", rep.TraceSession, err)
	}
	for name, c := range map[string]struct {
		rows []string
		want string
	}{
		"one id":     {[]string{id}, id},
		"no row":     {nil, ""},
		"two rows":   {[]string{id, "0b18d7d3-41b4-4dfe-b649-e8ba776c383a"}, ""},
		"not an id":  {[]string{"../x"}, ""},
		"upper case": {[]string{strings.ToUpper(id)}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "s.conversation.db")
			src, err := os.ReadFile(filepath.Join(pairedDir, "basic.conversation.db"))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, src, 0o600); err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`create table trajectory_meta (trajectory_id text, cascade_id text, trajectory_type integer, source integer)`); err != nil {
				t.Fatal(err)
			}
			for i, r := range c.rows {
				if _, err := db.Exec(`insert into trajectory_meta values (?, ?, 4, 17)`, fmt.Sprint(i), r); err != nil {
					t.Fatal(err)
				}
			}
			_ = db.Close()
			tr, rep, err := Adapter{}.Parse(path)
			if err != nil || len(tr) == 0 || rep.TraceSession != c.want {
				t.Errorf("session %q, %d claims, err %v, want %q", rep.TraceSession, len(tr), err, c.want)
			}
		})
	}
}

// ReadTrace reads a missing, empty or unreadable database as a trace that
// cannot be verified, never as an error, and hashes an intact one on request
// (V-59).
func TestReadTraceFailsClosed(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.conversation.db")
	garbled := filepath.Join(dir, "garbled.conversation.db")
	_ = os.WriteFile(empty, nil, 0o644)
	_ = os.WriteFile(garbled, []byte("SQLite format 3\x00 but nothing else"), 0o644)
	for path, want := range map[string]verification.TraceState{
		filepath.Join(dir, "gone.conversation.db"): verification.TraceMissing,
		empty:   verification.TraceEmpty,
		garbled: verification.TraceUnparsable,
	} {
		_, _, in, err := agent.ReadTrace(Adapter{}, path, true)
		if err != nil || in.State != want || in.Detail == "" || in.ReadHash != "" {
			t.Errorf("%s: state %q detail %q hash %q err %v, want %q", filepath.Base(path), in.State, in.Detail, in.ReadHash, err, want)
		}
	}
	db := filepath.Join(pairedDir, "basic.conversation.db")
	tr, _, in, err := agent.ReadTrace(Adapter{}, db, true)
	want, _ := content.SHA256File(db)
	if err != nil || in.State != verification.TraceRead || in.ReadHash != want || len(tr) == 0 {
		t.Errorf("intact: state %q hash %q err %v, %d claims", in.State, in.ReadHash, err, len(tr))
	}
}

// On the paired basic capture the declaration finds the database the
// harness wrote and closed with a hash, reads none of the harness's own
// events on it as tampering, and changes no verdict.
func TestPairedTheDeclarationChangesNoVerdict(t *testing.T) {
	g := pairedRun(t, "basic")
	tr, _, err := Adapter{}.Parse(filepath.Join(pairedDir, "basic.conversation.db"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := agent.Capture(Adapter{}, "1.3.4", pairedControls(t), time.Now(), agent.CaptureOptions{Exclude: []string{controlCommand}})
	if err != nil {
		t.Fatal(err)
	}
	in := agent.PrepareWithBaseline(Adapter{}, tr, g, &b, verification.Options{IntervalSlack: 500 * time.Millisecond})
	without := verification.Verify(in)
	in.Trace.Decl = agent.Trace(Adapter{}, g, "")
	v := verification.Verify(in)
	if len(v.TraceTampering) != 0 || !v.Trace.Declared {
		t.Fatalf("tampering %+v, declared %v, want none and covered paths", v.TraceTampering, v.Trace.Declared)
	}
	if len(v.Trace.Files) != 1 || !strings.HasSuffix(v.Trace.Files[0].Path, ".db") || v.Trace.Files[0].Last == nil ||
		v.Trace.Files[0].Last.ActionType != models.FileClose || v.Trace.Files[0].Last.OutputHash == nil {
		t.Fatalf("trace files %+v, want the database with a hashed last close", v.Trace.Files)
	}
	if v.Outcome != without.Outcome || v.Findings() != without.Findings() || len(v.Reasons) != len(without.Reasons) {
		t.Errorf("with the declaration %v/%d, without %v/%d", v.Outcome, v.Findings(), without.Outcome, without.Findings())
	}
	// The database gone: the run cannot be verified, whatever the probes saw.
	in.Trace.State, in.Trace.Detail = verification.TraceMissing, "gone"
	if v := verification.Verify(in); v.Outcome != verification.OutcomeInconclusive || !strings.Contains(v.Reasons[0], verification.TraceDeletedOrDamaged) {
		t.Errorf("missing: outcome %v, reasons %v", v.Outcome, v.Reasons)
	}
}
