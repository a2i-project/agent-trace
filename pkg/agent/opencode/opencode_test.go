package opencode

import (
	"database/sql"
	"encoding/json"
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

const (
	sesMain = "ses_aaaaaaaaaaaaaaaaaaaaaaaaaa"
	sesSub  = "ses_bbbbbbbbbbbbbbbbbbbbbbbbbb"
	sesUser = "ses_cccccccccccccccccccccccccc"
)

// part is a tool part of a synthetic session.
type part struct {
	session, message, tool, status string
	input, metadata                map[string]any
	output                         string
	start, end                     int64 // ms after t0; end < 0 for none
}

var t0 = time.Date(2026, 11, 3, 2, 0, 0, 0, time.UTC).UnixMilli()

// writeDB writes a database of OpenCode's two tables the adapter reads,
// with the given sessions (id -> parent) and parts.
func writeDB(t *testing.T, sessions map[string]string, parts []part) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "x.opencode.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	for _, q := range []string{
		"create table session (id text primary key, parent_id text, directory text not null, version text not null)",
		"create table part (id text primary key, message_id text not null, session_id text not null, data text not null)",
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	for id, parent := range sessions {
		var p any
		if parent != "" {
			p = parent
		}
		if _, err := db.Exec("insert into session values (?,?,?,?)", id, p, "/ws", "1.19.5"); err != nil {
			t.Fatal(err)
		}
	}
	for i, p := range parts {
		tm := map[string]any{"start": t0 + p.start}
		if p.end >= 0 {
			tm["end"] = t0 + p.end
		}
		st := map[string]any{"status": p.status, "input": p.input, "time": tm}
		if p.metadata != nil {
			st["metadata"] = p.metadata
		}
		if p.output != "" {
			st["output"] = p.output
		}
		data, _ := json.Marshal(map[string]any{"type": "tool", "tool": p.tool, "state": st})
		id := "prt_" + strings.Repeat("0", 3) + string(rune('a'+i))
		if _, err := db.Exec("insert into part values (?,?,?,?)", id, p.message, p.session, string(data)); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func done(session, tool string, start, end int64, input map[string]any) part {
	return part{session: session, message: "msg_" + session[4:8], tool: tool, status: statusCompleted, input: input, start: start, end: end}
}

func TestDetectRecognisesOnlyAnOpenCodeDatabase(t *testing.T) {
	path := writeDB(t, map[string]string{sesMain: ""}, nil)
	if !(Adapter{}).Detect(path) {
		t.Error("an OpenCode database is not detected")
	}
	other := filepath.Join(t.TempDir(), "other.db")
	db, _ := sql.Open("sqlite", other)
	_, _ = db.Exec("create table steps (idx integer, step_payload blob)")
	_ = db.Close()
	if (Adapter{}).Detect(other) {
		t.Error("another database is detected")
	}
	text := filepath.Join(t.TempDir(), "x.jsonl")
	_ = os.WriteFile(text, []byte("{}\n"), 0o600)
	if (Adapter{}).Detect(text) {
		t.Error("a text file is detected")
	}
}

// A database of several sessions needs the id the capture recorded
// (I-110, I-120); the id names the session, and its subagents come with it.
func TestTheSessionIDNamesTheRunInADatabaseOfSeveral(t *testing.T) {
	path := writeDB(t, map[string]string{sesMain: "", sesSub: sesMain, sesUser: ""}, []part{
		done(sesMain, toolBash, 0, 10, map[string]any{"command": "echo main"}),
		{session: sesMain, message: "m1", tool: toolTask, status: statusCompleted, input: map[string]any{}, metadata: map[string]any{"sessionId": sesSub}, start: 20, end: 90},
		done(sesSub, toolBash, 30, 40, map[string]any{"command": "echo sub"}),
		done(sesUser, toolBash, 50, 60, map[string]any{"command": "echo user"}),
	})
	if _, _, err := (Adapter{}).Parse(path); err == nil || !strings.Contains(err.Error(), "2 sessions") {
		t.Errorf("Parse of a database of two sessions: %v", err)
	}
	tr, rep, err := Adapter{}.ParseSession(path, sesMain)
	if err != nil {
		t.Fatal(err)
	}
	var cmds []string
	for _, c := range tr {
		cmds = append(cmds, c.Target+"@"+c.ThreadID)
	}
	if strings.Join(cmds, ";") != "echo main@;echo sub@"+sesSub || rep.TraceSession != sesMain || strings.Join(rep.TraceSubagents, ",") != sesSub {
		t.Errorf("claims %v, session %s, subagents %v", cmds, rep.TraceSession, rep.TraceSubagents)
	}
	if len(rep.Degradations) != 3 {
		t.Errorf("degradations %v", rep.Degradations)
	}
	if _, _, err := (Adapter{}).ParseSession(path, sesSub); err == nil {
		t.Error("a subagent's session read as a run's")
	}
	if _, _, err := (Adapter{}).ParseSession(path, "ses_dddddddddddddddddddddddddd"); err == nil {
		t.Error("a session the database lacks was read")
	}
	if _, _, err := (Adapter{}).ParseSession(path, "x"); err == nil {
		t.Error("an id of another form was read")
	}
	// ReadSessionTrace passes the id to the adapter.
	if tr, _, in, err := agent.ReadSessionTrace(Adapter{}, path, sesMain, false); err != nil || in.State != "" || len(tr) != 2 {
		t.Errorf("ReadSessionTrace: %v %+v %d", err, in, len(tr))
	}
	if _, _, in, err := agent.ReadTrace(Adapter{}, path, false); err != nil || in.State != verification.TraceUnparsable {
		t.Errorf("ReadTrace without the id: %v %+v", err, in)
	}
}

// A child session no task call names, and a task call naming a session
// that is not a child, are reported; the parent chain decides (I-114).
func TestSubagentsComeFromTheParentChain(t *testing.T) {
	path := writeDB(t, map[string]string{sesMain: "", sesSub: sesMain}, []part{
		{session: sesMain, message: "m1", tool: toolTask, status: statusCompleted, input: map[string]any{}, metadata: map[string]any{"sessionId": sesUser}, start: 0, end: 10},
	})
	_, rep, err := Adapter{}.Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(rep.Degradations, "\n")
	if strings.Join(rep.TraceSubagents, ",") != sesSub || !strings.Contains(joined, "names subagent session "+sesUser) || !strings.Contains(joined, sesSub+" is a child") {
		t.Errorf("subagents %v, degradations %v", rep.TraceSubagents, rep.Degradations)
	}
}

func TestParseMapsEachTool(t *testing.T) {
	path := writeDB(t, map[string]string{sesMain: ""}, []part{
		{session: sesMain, message: "m1", tool: toolRead, status: statusCompleted, input: map[string]any{"filePath": "sub/x.txt"},
			output: "<path>/ws/sub/x.txt</path>\n<type>file</type>", metadata: map[string]any{"loaded": []string{"/ws/sub/AGENTS.md"}}, start: 0, end: 5},
		{session: sesMain, message: "m1", tool: toolRead, status: statusCompleted, input: map[string]any{"filePath": "/ws/sub"}, output: "<type>directory</type>", start: 1, end: 5},
		done(sesMain, toolWebFetch, 10, 20, map[string]any{"url": "https://Example.com/a?b"}),
		done(sesMain, toolWebFetch, 11, 20, map[string]any{"url": "http://example.com/"}),
		done(sesMain, "todowrite", 21, 22, map[string]any{}),
		done(sesMain, toolGrep, 23, 24, map[string]any{"pattern": "x"}),
		done(sesMain, "skill", 25, 26, map[string]any{}),
		{session: sesMain, message: "m2", tool: toolBash, status: statusError, input: map[string]any{"command": "false"}, start: 30, end: 31},
		{session: sesMain, message: "m2", tool: toolBash, status: "running", input: map[string]any{"command": "sleep 9"}, start: 32, end: -1},
	})
	tr, rep, err := Adapter{}.Parse(path)
	if err != nil || len(rep.ParseErrors) != 0 {
		t.Fatal(err, rep.ParseErrors)
	}
	var got []string
	for _, c := range tr {
		got = append(got, string(c.ActionType)+" "+c.Target+" "+c.Tool)
	}
	want := "file_open /ws/sub/x.txt read;file_open /ws/sub/AGENTS.md read:loaded;net_connect example.com webfetch;process_exec opencode search:grep /ws grep"
	if strings.Join(got, ";") != want {
		t.Errorf("claims %v", got)
	}
	if rep.ToolCalls != 9 || rep.UnmappedByTool["read:directory"] != 1 || rep.UnmappedByTool["webfetch (no https host)"] != 1 ||
		rep.UnmappedByTool["bash (status error)"] != 1 || rep.UnmappedByTool["bash (status running)"] != 1 ||
		strings.Join(rep.UnknownTools, ",") != "skill" {
		t.Errorf("report %+v", rep)
	}
}

// A completed call without the fields its claims need is a parse error,
// and so is a tool part without its execution's times.
func TestParseRefusesIncompleteCalls(t *testing.T) {
	path := writeDB(t, map[string]string{sesMain: ""}, []part{
		done(sesMain, toolBash, 0, 1, map[string]any{}),
		done(sesMain, toolWrite, 2, 3, map[string]any{"filePath": "/ws/a"}),
		{session: sesMain, message: "m", tool: toolRead, status: statusCompleted, input: map[string]any{"filePath": "/ws/a"}, start: 4, end: -1},
	})
	_, rep, err := Adapter{}.Parse(path)
	if err != nil || len(rep.ParseErrors) != 3 {
		t.Errorf("%v, parse errors %v", err, rep.ParseErrors)
	}
}

const diffAB = "Index: /ws/a.txt\n" + "===================================================================" + "\n--- /ws/a.txt\n+++ /ws/a.txt\n@@ -1,1 +1,1 @@\n-hello\n\\ No newline at end of file\n+world\n\\ No newline at end of file\n"

// The content a write or an edit claims (I-121).
func TestContentIsClaimedOnlyWhenTheRecordStatesIt(t *testing.T) {
	h := func(s string) string { return content.SHA256Bytes([]byte(s)) }
	write := func(start int64, path, text string, exists bool) part {
		p := done(sesMain, toolWrite, start, start+2, map[string]any{"filePath": path, "content": text})
		p.metadata = map[string]any{"exists": exists}
		return p
	}
	edit := func(start int64, diff string) part {
		p := done(sesMain, toolEdit, start, start+2, map[string]any{"filePath": "/ws/a.txt", "oldString": "x", "newString": "y"})
		p.metadata = map[string]any{"diff": diff}
		return p
	}
	cases := map[string]struct {
		parts []part
		want  []string // the output hash of each write claim, "" for none
	}{
		"created, then edited":            {[]part{write(0, "/ws/a.txt", "hello", false), edit(10, diffAB)}, []string{h("hello"), h("world")}},
		"overwritten, prior unknown":      {[]part{write(0, "/ws/a.txt", "hello", true)}, []string{""}},
		"overwritten, prior known":        {[]part{write(0, "/ws/a.txt", "x", false), write(10, "/ws/a.txt", "hello", true)}, []string{h("x"), h("hello")}},
		"overwritten with a mark":         {[]part{write(0, "/ws/a.txt", bom+"hello", true)}, []string{h(bom + "hello")}},
		"over a file with a mark":         {[]part{write(0, "/ws/a.txt", bom+"x", false), write(10, "/ws/a.txt", "hello", true)}, []string{h(bom + "x"), ""}},
		"edit of unknown content":         {[]part{edit(10, diffAB)}, []string{""}},
		"edit whose diff does not apply":  {[]part{write(0, "/ws/a.txt", "other", false), edit(10, diffAB)}, []string{h("other"), ""}},
		"edit whose header names another": {[]part{write(0, "/ws/a.txt", "hello", false), edit(10, strings.ReplaceAll(diffAB, "/ws/a.txt", "/ws/b.txt"))}, []string{h("hello"), ""}},
		"a command between": {[]part{write(0, "/ws/a.txt", "hello", false),
			done(sesMain, toolBash, 5, 6, map[string]any{"command": "true"}), edit(10, diffAB)}, []string{h("hello"), ""}},
		"a command started before, ending after the source": {[]part{
			done(sesMain, toolBash, -5, 1, map[string]any{"command": "true"}), write(0, "/ws/a.txt", "hello", false), edit(10, diffAB)}, []string{h("hello"), ""}},
		"a command that ended before the source": {[]part{
			done(sesMain, toolBash, -9, -5, map[string]any{"command": "true"}), write(0, "/ws/a.txt", "hello", false), edit(10, diffAB)}, []string{h("hello"), h("world")}},
	}
	for name, c := range cases {
		tr, _, err := Adapter{}.Parse(writeDB(t, map[string]string{sesMain: ""}, c.parts))
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, e := range tr {
			if e.ActionType == models.FileWrite {
				s := ""
				if e.OutputHash != nil {
					s = *e.OutputHash
				}
				got = append(got, s)
				if (Adapter{}).Expresses(e, verification.DiffOutputHash) != (e.OutputHash != nil) {
					t.Errorf("%s: Expresses disagrees with the claim", name)
				}
			}
		}
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: hashes %v, want %v", name, got, c.want)
		}
	}
}

func TestExpressesAndProcess(t *testing.T) {
	a := Adapter{}
	for _, f := range []string{verification.DiffExitCode, verification.DiffRequestHash, verification.DiffInputHash} {
		if a.Expresses(models.TrajectoryEntry{Tool: toolRead}, f) {
			t.Errorf("%s expressed", f)
		}
	}
	if a.Expresses(models.TrajectoryEntry{Tool: toolRead, ActionType: models.FileOpen}, verification.DiffOutputHash) {
		t.Error("a read's output hash expressed")
	}
	p := a.Process()
	if !p.ShellPerCommand || !p.SubagentsInProcess || p.IntervalKind != agent.IntervalExecution || p.Concurrency != agent.Parallel || p.ExitsClaimed {
		t.Errorf("process %+v", p)
	}
}

func TestNormalizeRecoversTheCommand(t *testing.T) {
	for in, want := range map[string]string{
		"/bin/bash -c echo hi":     "echo hi",
		"/usr/bin/bash -c ls -la":  "ls -la",
		"/bin/sh -c echo hi":       "/bin/sh -c echo hi",
		"/bin/bash -c ":            "/bin/bash -c ",
		"/bin/bash -lc echo hi":    "/bin/bash -lc echo hi",
		"/usr/bin/git status":      "/usr/bin/git status",
		"/bin/bash -c a (deleted)": "a (deleted)",
	} {
		e, ok := Adapter{}.Normalize(models.GroundTruthEvent{ActionType: models.ProcessExec, Target: in})
		if !ok || e.Target != want {
			t.Errorf("%q: %q", in, e.Target)
		}
	}
	e, _ := Adapter{}.Normalize(models.GroundTruthEvent{ActionType: models.FileOpen, Target: "/ws/a (deleted)"})
	if e.Target != "/ws/a" {
		t.Errorf("deleted suffix kept: %q", e.Target)
	}
}

// The folds of NormalizeStream on the measured shapes (I-120), and what
// they leave alone.
func TestNormalizeStreamFoldsTheMeasuredShapes(t *testing.T) {
	at := time.Date(2026, 11, 3, 2, 0, 0, 0, time.UTC)
	hash := func(s string) *string { h := content.SHA256Bytes([]byte(s)); return &h }
	ev := func(ms int, pid uint32, a models.ActionType, target string, in, out *string) models.GroundTruthEvent {
		return models.GroundTruthEvent{Timestamp: at.Add(time.Duration(ms) * time.Millisecond), PID: pid, ActionType: a, Target: target, InputHash: in, OutputHash: out}
	}
	g := models.GroundTruth{
		// A create: the create, its open, a write and the close; the
		// harness's reread 70 ms later.
		ev(0, 1, models.FileWrite, "/ws/a", nil, nil),
		ev(0, 1, models.FileOpen, "/ws/a", hash(""), nil),
		ev(0, 1, models.FileWrite, "/ws/a", nil, nil),
		ev(0, 1, models.FileClose, "/ws/a", nil, hash("hello")),
		ev(70, 1, models.FileOpen, "/ws/a", hash("hello"), nil),
		// An edit: two opens, a write, the close, the reread.
		ev(1000, 1, models.FileOpen, "/ws/a", hash("hello"), nil),
		ev(1000, 1, models.FileOpen, "/ws/a", hash("hello"), nil),
		ev(1000, 1, models.FileWrite, "/ws/a", nil, nil),
		ev(1000, 1, models.FileClose, "/ws/a", nil, hash("world")),
		ev(1066, 1, models.FileOpen, "/ws/a", hash("world"), nil),
		// A later open with other content is no reread.
		ev(5000, 1, models.FileWrite, "/ws/b", nil, nil),
		ev(5000, 1, models.FileOpen, "/ws/b", hash(""), nil),
		ev(5000, 1, models.FileWrite, "/ws/b", nil, nil),
		ev(5000, 1, models.FileClose, "/ws/b", nil, hash("x")),
		ev(5070, 1, models.FileOpen, "/ws/b", hash("y"), nil),
	}
	var got []string
	for _, e := range (Adapter{}).NormalizeStream(g) {
		s := e.Timestamp.Sub(at).String() + " " + string(e.ActionType) + " " + e.Target
		if e.OutputHash != nil {
			s += " hash"
		}
		got = append(got, s)
	}
	want := []string{
		"0s file_open /ws/a", "0s file_write /ws/a hash",
		"1s file_open /ws/a", "1s file_write /ws/a hash",
		"5s file_open /ws/b", "5s file_write /ws/b hash",
		"5.07s file_open /ws/b",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestHarnessDeclarations(t *testing.T) {
	a := Adapter{}
	for path, want := range map[string]bool{
		"/home/u/.local/share/opencode/opencode.db": true,
		"/home/u/.local/state/opencode/locks/x":     true,
		"/home/u/.cache/opencode/bin/rg":            true,
		"/home/u/.config/opencode/opencode.json":    false,
		"/home/u/.local/share/opencodex/x":          false,
	} {
		if a.IsHarnessOwned(path) != want {
			t.Errorf("IsHarnessOwned(%s) != %v", path, want)
		}
	}
	bk := a.HarnessBookkeeping("1.19.5", "/home/u")
	for _, c := range []struct {
		a      models.ActionType
		target string
		want   bool
	}{
		{models.FileWrite, "/home/u/.local/share/opencode/opencode.db-wal", true},
		{models.FileDelete, "/home/u/.local/share/opencode/opencode.db-shm", true},
		{models.FileClose, "/home/u/.local/share/opencode/opencode.db", true},
		{models.FileOpen, "/home/u/.local/share/opencode/opencode.db", false},
		{models.FileWrite, "/home/v/.local/share/opencode/opencode.db", false},
		{models.FileWrite, "/home/u/.local/share/opencode/log/opencode.log", false},
	} {
		if bk(models.GroundTruthEvent{ActionType: c.a, Target: c.target}) != c.want {
			t.Errorf("bookkeeping %s %s != %v", c.a, c.target, c.want)
		}
	}
	if a.HarnessBookkeeping("1.19.4", "/home/u") != nil || a.HarnessBookkeeping("1.19.5", "/etc") != nil {
		t.Error("bookkeeping declared for another version or home")
	}
	d := a.Trace("/ws", "/home/u")
	for path, want := range map[string][3]bool{ // covers, main, transient
		"/home/u/.local/share/opencode/opencode.db":         {true, true, false},
		"/home/u/.local/share/opencode/opencode.db-wal":     {true, false, true},
		"/home/u/.local/share/opencode/opencode.db-journal": {true, false, true},
		"/home/u/.local/share/opencode/opencode.db-shm":     {false, false, false},
		"/home/u/.local/share/opencode/log/opencode.log":    {false, false, false},
	} {
		if got := [3]bool{d.Covers(path), d.Main(path), d.Transient(path)}; got != want {
			t.Errorf("trace %s: %v, want %v", path, got, want)
		}
	}
	if s := a.SessionTrace("/ws", "/home/u", agent.TraceSession{ID: sesMain}); s == nil || !s.Main("/home/u/.local/share/opencode/opencode.db") {
		t.Error("the session's trace is not the database")
	}
	if a.SessionTrace("/ws", "/home/u", agent.TraceSession{ID: "x"}) != nil {
		t.Error("an id of another form declared a trace")
	}
	if a.Trace("/ws", "/home/u/../v") != nil {
		t.Error("an unclean home declared a trace")
	}
	if len(a.SensitiveFiles()) == 0 || a.HarnessCommands() != nil || a.HarnessHosts() != nil {
		t.Error("declarations")
	}
}

func TestFetchHost(t *testing.T) {
	for in, want := range map[string]string{
		"https://Example.com/x":  "example.com",
		"https://a.b-c.org:8443": "a.b-c.org",
		"http://example.com":     "",
		"https://1.2.3.4/":       "",
		"https://u@example.com/": "",
		"https://exämple.com/":   "",
		"not a url":              "",
	} {
		got, ok := fetchHost(in)
		if got != want || ok != (want != "") {
			t.Errorf("%q: %q %v", in, got, ok)
		}
	}
}

// A search claims its kind and the folder ripgrep searched (I-124).
func TestASearchIsClaimedWithItsFolder(t *testing.T) {
	search := func(tool string, in map[string]any, out string) part {
		p := done(sesMain, tool, 0, 5, in)
		p.output = out
		return p
	}
	for name, c := range map[string]struct {
		p    part
		want string
	}{
		"grep, no path":             {search(toolGrep, map[string]any{"pattern": "x"}, "No files found"), SearchGrep + " /ws"},
		"grep of a directory":       {search(toolGrep, map[string]any{"pattern": "x", "path": "src"}, "Found 1 matches\n/ws/src/a.go:\n  Line 1: x"), SearchGrep + " /ws/src"},
		"grep of a matched file":    {search(toolGrep, map[string]any{"pattern": "x", "path": "src/a.go"}, "Found 1 matches\n/ws/src/a.go:\n  Line 1: x"), SearchGrep + " /ws/src"},
		"grep of an absolute path":  {search(toolGrep, map[string]any{"pattern": "x", "path": "/data/../data"}, ""), SearchGrep + " /data"},
		"glob, no path":             {search(toolGlob, map[string]any{"pattern": "*.txt"}, ""), SearchGlob + " /ws"},
		"glob of a relative folder": {search(toolGlob, map[string]any{"pattern": "*.txt", "path": "sub/"}, ""), SearchGlob + " /ws/sub"},
	} {
		tr, rep, err := Adapter{}.Parse(writeDB(t, map[string]string{sesMain: ""}, []part{c.p}))
		if err != nil || len(tr) != 1 || tr[0].ActionType != models.ProcessExec || tr[0].Target != c.want || len(rep.UnknownTools) != 0 {
			t.Errorf("%s: %v %+v %v", name, err, tr, rep.UnknownTools)
		}
	}
	_, rep, _ := Adapter{}.Parse(writeDB(t, map[string]string{sesMain: ""}, []part{search(toolGrep, map[string]any{}, "")}))
	if len(rep.ParseErrors) != 1 {
		t.Errorf("a grep without a pattern: %v", rep.ParseErrors)
	}
}

// Only the first exec of OpenCode's own ripgrep by the harness, in a
// measured shape, is a search; its exit follows (I-124).
func TestFoldSearchesRecognisesOnlyTheHarnesssOwnRipgrep(t *testing.T) {
	const rg = "/home/u/.cache/opencode/bin/rg"
	grep := rg + " --no-config --json --hidden --no-messages --glob=!**/.git/** -- seed ."
	glob := rg + " --no-config --files --glob=*.txt --glob=!**/.git/** ."
	ex := func(pid, ppid uint32, target, cwd string) models.GroundTruthEvent {
		return models.GroundTruthEvent{PID: pid, PPID: ppid, ActionType: models.ProcessExec, Target: target, Cwd: cwd}
	}
	type want struct {
		target string
		cut    bool
	}
	cases := map[string]struct {
		g    models.GroundTruth
		want want
	}{
		"grep":              {models.GroundTruth{ex(10, 1, grep, "/ws")}, want{SearchGrep + " /ws", false}},
		"grep, include":     {models.GroundTruth{ex(10, 1, rg+" --no-config --json --hidden --no-messages --glob=*.go --glob=!**/.git/** -- a b .", "/ws/src")}, want{SearchGrep + " /ws/src", false}},
		"glob":              {models.GroundTruth{ex(10, 1, glob, "/ws/sub/")}, want{SearchGlob + " /ws/sub", false}},
		"glob, hidden":      {models.GroundTruth{ex(10, 1, rg+" --no-config --files --hidden --follow --glob=*.txt --glob=!**/.git/** .", "/ws")}, want{SearchGlob + " /ws", false}},
		"no cwd":            {models.GroundTruth{ex(10, 1, grep, "")}, want{SearchGrep, true}},
		"the listing":       {models.GroundTruth{ex(10, 1, rg+" --no-config --files --glob=!**/.git/** .", "/ws")}, want{rg + " --no-config --files --glob=!**/.git/** .", false}},
		"rg from PATH":      {models.GroundTruth{ex(10, 1, "/usr/bin/rg --no-config --files --glob=*.txt --glob=!**/.git/** .", "/ws")}, want{"/usr/bin/rg --no-config --files --glob=*.txt --glob=!**/.git/** .", false}},
		"another shape":     {models.GroundTruth{ex(10, 1, rg+" --files .", "/ws")}, want{rg + " --files .", false}},
		"a cache rg in /ws": {models.GroundTruth{ex(10, 1, "/ws/.cache/opencode/bin/rg --no-config --files --glob=x --glob=!**/.git/** .", "/ws")}, want{"/ws/.cache/opencode/bin/rg --no-config --files --glob=x --glob=!**/.git/** .", false}},
		"through bash": {models.GroundTruth{
			{PID: 10, PPID: 1, ActionType: models.ProcessFork, Target: "10"},
			ex(10, 1, "/bin/bash -c sh", "/ws"),
			ex(11, 10, grep, "/ws")}, want{grep, false}},
		"a second exec": {models.GroundTruth{ex(10, 1, "/bin/bash -c "+grep, "/ws"), ex(10, 1, grep, "/ws")}, want{grep, false}},
	}
	for name, c := range cases {
		g := (Adapter{}).NormalizeStream(c.g)
		last := g[len(g)-1]
		if last.Target != c.want.target || last.TargetTruncated != c.want.cut {
			t.Errorf("%s: %q truncated %v", name, last.Target, last.TargetTruncated)
		}
	}
	exe := models.GroundTruthEvent{PID: 10, PPID: 1, ActionType: models.ProcessExec, Target: grep, Cwd: "/ws", Image: &models.ExecImage{Program: "/tmp/rg"}}
	if g := (Adapter{}).NormalizeStream(models.GroundTruth{exe}); g[0].Target != grep {
		t.Errorf("another program image: %q", g[0].Target)
	}
	cut := models.GroundTruthEvent{PID: 10, PPID: 1, ActionType: models.ProcessExec, Target: rg + " --no-config --js", TargetTruncated: true}
	exit := models.GroundTruthEvent{PID: 10, PPID: 1, ActionType: models.ProcessExit, Target: rg + " --no-config --js", TargetTruncated: true}
	if g := (Adapter{}).NormalizeStream(models.GroundTruth{cut, exit}); g[0].Target != SearchGrep || !g[0].TargetTruncated || g[1].Target != SearchGrep {
		t.Errorf("a cut command line: %+v", g)
	}
}
