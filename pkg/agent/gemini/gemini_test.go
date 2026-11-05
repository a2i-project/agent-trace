package gemini

import (
	"bytes"
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

// --- a protobuf encoder, enough to build step payloads like the real ones ---

func varint(v uint64) []byte {
	var b []byte
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

func fVarint(num int, v uint64) []byte { return append(varint(uint64(num)<<3), varint(v)...) }

func fBytes(num int, b []byte) []byte {
	out := append(varint(uint64(num)<<3|2), varint(uint64(len(b)))...)
	return append(out, b...)
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func tsMsg(t time.Time) []byte {
	return cat(fVarint(1, uint64(t.Unix())), fVarint(2, uint64(t.Nanosecond())))
}

var base = time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)

// toolCall is message 5.4: id, name, JSON arguments, and an opaque field 7.
func toolCall(id, name string, args map[string]any) []byte {
	j, _ := json.Marshal(args)
	return cat(fBytes(1, []byte(id)), fBytes(2, []byte(name)), fBytes(3, j), fBytes(7, []byte{0x12, 0x01, 0x02}))
}

// payload is a step payload: field 1 step type, field 5 holding created (5.1),
// started (5.6), completed (5.8) and the calls (5.4).
func payload(created, started, completed *time.Time, calls ...[]byte) []byte {
	var inner []byte
	if created != nil {
		inner = append(inner, fBytes(1, tsMsg(*created))...)
	}
	for _, c := range calls {
		inner = append(inner, fBytes(4, c)...)
	}
	if started != nil {
		inner = append(inner, fBytes(6, tsMsg(*started))...)
		inner = append(inner, fBytes(7, tsMsg(*started))...)
	}
	if completed != nil {
		inner = append(inner, fBytes(8, tsMsg(*completed))...)
	}
	return cat(fVarint(1, 132), fVarint(4, 3), fBytes(5, inner))
}

type step struct {
	typ, status int
	sub         bool
	payload     []byte
}

func writeDB(t *testing.T, steps []step) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "conv.db")
	writeDBAt(t, path, steps)
	return path
}

// writeDBAt writes a conversation database at path, creating its directory.
func writeDBAt(t *testing.T, path string, steps []step) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec("create table steps (idx integer, step_type integer, status integer, has_subtrajectory numeric, step_payload blob, primary key (idx))"); err != nil {
		t.Fatal(err)
	}
	for i, s := range steps {
		if _, err := db.Exec("insert into steps values (?,?,?,?,?)", i, s.typ, s.status, s.sub, s.payload); err != nil {
			t.Fatal(err)
		}
	}
}

func at(sec int) *time.Time { x := base.Add(time.Duration(sec) * time.Second); return &x }

func fixture(t *testing.T) string {
	return writeDB(t, []step{
		{typ: 14, status: 3, payload: cat(fVarint(1, 14), fBytes(19, []byte("the user prompt")))}, // no tool call
		{typ: 132, status: 3, payload: payload(at(1), at(2), at(5), toolCall("c1", "run_command", map[string]any{"CommandLine": "go test ./...", "Cwd": "/w", "WaitMsBeforeAsync": 5000}))},
		{typ: 132, status: 3, payload: payload(at(6), at(7), at(8), toolCall("c2", "view_file", map[string]any{"AbsolutePath": "/w/a.go"}))},
		{typ: 132, status: 3, payload: payload(at(9), at(10), at(11), toolCall("c3", "write_to_file", map[string]any{"TargetFile": "/w/b.go", "CodeContent": "package b\n", "Overwrite": true}))},
		{typ: 132, status: 3, payload: payload(at(12), at(13), at(14), toolCall("c4", "replace_file_content", map[string]any{"TargetFile": "/w/b.go", "ReplacementContent": "x"}))},
		{typ: 132, status: 3, payload: payload(at(15), at(16), at(17), toolCall("c5", "read_url_content", map[string]any{"Url": "https://example.com/docs"}))},
		{typ: 132, status: 3, payload: payload(at(18), at(19), at(20), toolCall("c6", "manage_task", map[string]any{"Action": "x"}))},
		{typ: 132, status: 3, payload: payload(at(21), at(22), at(23), toolCall("c7", "search_web", map[string]any{"query": "x"}))},
		{typ: 132, status: 7, payload: payload(at(24), at(25), at(26), toolCall("c8", "run_command", map[string]any{"CommandLine": "rm -rf /", "Cwd": "/"}))}, // not completed
		{typ: 132, status: 3, payload: payload(at(27), at(28), at(29), toolCall("c9", "run_command", map[string]any{"CommandLine": "echo hi", "Cwd": "/", "RunPersistent": true}))},
		// two calls in one step: a parallel block
		{typ: 132, status: 3, payload: payload(at(30), at(31), at(32),
			toolCall("c10", "view_file", map[string]any{"AbsolutePath": "/w/x"}),
			toolCall("c11", "view_file", map[string]any{"AbsolutePath": "/w/y"}))},
		// started missing: the created time stands in
		{typ: 132, status: 3, payload: payload(at(33), nil, nil, toolCall("c12", "run_command", map[string]any{"CommandLine": "date", "Cwd": "/"}))},
		{typ: 21, status: 3, sub: true, payload: payload(at(34), at(35), at(36), toolCall("c13", "view_file", map[string]any{"AbsolutePath": "/w/z"}))},
	})
}

func parse(t *testing.T, path string) (models.Trajectory, agent.Report) {
	t.Helper()
	tr, rep, err := Adapter{}.Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return tr, rep
}

func TestParseMapsCompletedToolCallsInOrder(t *testing.T) {
	tr, rep := parse(t, fixture(t))
	var got []string
	for _, e := range tr {
		got = append(got, e.Tool+":"+string(e.ActionType)+":"+e.Target)
	}
	want := []string{
		"run_command:process_exec:go test ./...",
		"view_file:file_open:/w/a.go",
		"write_to_file:file_open:/w/b.go", "write_to_file:file_write:/w/b.go", "write_to_file:file_close:/w/b.go",
		"replace_file_content:file_open:/w/b.go", "replace_file_content:file_write:/w/b.go", "replace_file_content:file_close:/w/b.go",
		"read_url_content:net_connect:example.com",
		"view_file:file_open:/w/x",
		"view_file:file_open:/w/y",
		"run_command:process_exec:date",
		"view_file:file_open:/w/z",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("claims =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if rep.ToolCalls != 13 || rep.Entries != len(tr) {
		t.Errorf("report: toolCalls=%d (want 13) entries=%d (want %d)", rep.ToolCalls, rep.Entries, len(tr))
	}
}

func TestParseUsesStartedAsTheClaimStartAndCompletedAsItsEnd(t *testing.T) {
	tr, _ := parse(t, fixture(t))
	e := tr[0]
	if !e.Timestamp.Equal(*at(2)) || e.End == nil || !e.End.Equal(*at(5)) {
		t.Errorf("run_command interval = [%v, %v], want started..completed", e.Timestamp, e.End)
	}
	for _, e := range tr {
		if e.Target == "date" {
			if !e.Timestamp.Equal(*at(33)) || e.End != nil {
				t.Errorf("no started: start=%v end=%v, want the created time and a point", e.Timestamp, e.End)
			}
		}
	}
}

func TestParseCountsAndNamesWhatItDoesNotClaim(t *testing.T) {
	_, rep := parse(t, fixture(t))
	for _, k := range []string{"manage_task", "search_web", "run_command (status 7)", "run_command (persistent shell)"} {
		if rep.UnmappedByTool[k] == 0 {
			t.Errorf("%q not counted: %v", k, rep.UnmappedByTool)
		}
	}
	if len(rep.UnknownTools) != 1 || rep.UnknownTools[0] != "search_web" {
		t.Errorf("UnknownTools = %v, want [search_web]", rep.UnknownTools)
	}
	joined := strings.Join(rep.Degradations, "|")
	for _, want := range []string{"persistent shell", "status other than completed", "subtrajectory", "created time", "search_web", "exit code", "block id"} {
		if !strings.Contains(joined, want) {
			t.Errorf("Degradations lack %q:\n%s", want, joined)
		}
	}
}

// A command that was not completed may not have run, and one that ran in a
// persistent shell has no process of its own. Neither is claimed, because a
// claim that nothing could witness is a false fabrication.
func TestParseDoesNotClaimWhatCannotBeWitnessed(t *testing.T) {
	tr, _ := parse(t, fixture(t))
	for _, e := range tr {
		if e.Target == "rm -rf /" || e.Target == "echo hi" {
			t.Errorf("claimed %q", e.Target)
		}
	}
}

func TestParseGivesParallelCallsOneBlockID(t *testing.T) {
	tr, _ := parse(t, fixture(t))
	var x, y, lone models.TrajectoryEntry
	for _, e := range tr {
		switch e.Target {
		case "/w/x":
			x = e
		case "/w/y":
			y = e
		case "/w/a.go":
			lone = e
		}
	}
	if x.BlockID == "" || x.BlockID != y.BlockID || lone.BlockID != "" {
		t.Errorf("block ids: x=%q y=%q lone=%q", x.BlockID, y.BlockID, lone.BlockID)
	}
}

func TestWriteClaimsTheHashOfItsContentAndReplaceDoesNot(t *testing.T) {
	tr, _ := parse(t, fixture(t))
	for _, e := range tr {
		if e.ActionType != models.FileClose {
			continue
		}
		switch e.Tool {
		case "write_to_file":
			// The content ends in a newline, so the harness writes it as it is.
			if e.OutputHash == nil || *e.OutputHash != content.SHA256Bytes([]byte("package b\n")) {
				t.Errorf("write_to_file close hash = %v", e.OutputHash)
			}
		case "replace_file_content":
			if e.OutputHash != nil {
				t.Errorf("replace_file_content close carries a hash %v", *e.OutputHash)
			}
		}
	}
}

func TestExpressesIsPerTool(t *testing.T) {
	a := Adapter{}
	if !a.Expresses(models.TrajectoryEntry{Tool: "write_to_file"}, verification.DiffOutputHash) ||
		a.Expresses(models.TrajectoryEntry{Tool: "replace_file_content"}, verification.DiffOutputHash) {
		t.Error("only write_to_file can state an output hash")
	}
	for _, f := range []string{verification.DiffExitCode, verification.DiffRequestHash} {
		if a.Expresses(models.TrajectoryEntry{Tool: "run_command"}, f) {
			t.Errorf("the format cannot state %s", f)
		}
	}
}

// The values measured with strace on agy 1.3.4 on 2026-10-13 (I-47).
func TestProcessModelIsTheMeasuredOne(t *testing.T) {
	m := Adapter{}.Process()
	want := agent.ProcessModel{ShellPerCommand: true, SubagentsInProcess: true, IntervalKind: agent.IntervalExecution, Concurrency: agent.Parallel}
	if m != want {
		t.Errorf("Process() = %+v, want %+v", m, want)
	}
}

// The harness adds a final newline to content that lacks one and writes
// content that has one as it is (I-47). Empty content was not measured, so it
// claims no hash, and the field is then not one the format states.
func TestWriteHashIsOfTheFileTheHarnessWrites(t *testing.T) {
	for body, file := range map[string]string{"hello": "hello\n", "one\ntwo\n": "one\ntwo\n", "a\r\n": "a\r\n", "x\n\n": "x\n\n"} {
		if h := writeHash(body); h == nil || *h != content.SHA256Bytes([]byte(file)) {
			t.Errorf("writeHash(%q) = %v, want the hash of %q", body, h, file)
		}
	}
	if h := writeHash(""); h != nil {
		t.Errorf("writeHash of empty content = %v, want none", *h)
	}
	a := Adapter{}
	if a.Expresses(models.TrajectoryEntry{Tool: "write_to_file", ActionType: models.FileClose}, verification.DiffOutputHash) {
		t.Error("a write_to_file close without a hash must not be read as an opt-out")
	}
	h := "sha256:x"
	if !a.Expresses(models.TrajectoryEntry{Tool: "write_to_file", ActionType: models.FileClose, OutputHash: &h}, verification.DiffOutputHash) {
		t.Error("a write_to_file close with a hash states it")
	}
}

// --- failing loudly (docs/architecture/30_agent_adapters.md) ---

func TestParseFailsWhenAPayloadDoesNotDecode(t *testing.T) {
	path := writeDB(t, []step{{typ: 132, status: 3, payload: []byte{0x2a, 0xff, 0xff}}}) // field 5, length past the end
	if _, _, err := (Adapter{}).Parse(path); err == nil || !strings.Contains(err.Error(), "step 0") {
		t.Errorf("Parse = %v, want an error naming the step", err)
	}
}

func TestParseFailsWhenAToolCallLosesAFieldNumber(t *testing.T) {
	// A call whose name moved from field 2 to field 9, as a version might do.
	moved := cat(fBytes(1, []byte("c")), fBytes(9, []byte("run_command")), fBytes(3, []byte(`{"CommandLine":"ls"}`)))
	path := writeDB(t, []step{{typ: 132, status: 3, payload: payload(at(1), at(2), at(3), moved)}})
	_, _, err := Adapter{}.Parse(path)
	if err == nil || !strings.Contains(err.Error(), "5.4.2") {
		t.Errorf("Parse = %v, want an error naming field 5.4.2", err)
	}

	noArgs := cat(fBytes(1, []byte("c")), fBytes(2, []byte("run_command")))
	path = writeDB(t, []step{{typ: 132, status: 3, payload: payload(at(1), at(2), at(3), noArgs)}})
	if _, _, err := (Adapter{}).Parse(path); err == nil || !strings.Contains(err.Error(), "5.4.3") {
		t.Errorf("Parse = %v, want an error naming field 5.4.3", err)
	}

	badJSON := cat(fBytes(1, []byte("c")), fBytes(2, []byte("run_command")), fBytes(3, []byte("{not json")))
	path = writeDB(t, []step{{typ: 132, status: 3, payload: payload(at(1), at(2), at(3), badJSON)}})
	if _, _, err := (Adapter{}).Parse(path); err == nil || !strings.Contains(err.Error(), "JSON") {
		t.Errorf("Parse = %v, want a JSON error", err)
	}
}

func TestParseFailsWhenTheTimestampsMoved(t *testing.T) {
	c := toolCall("c", "view_file", map[string]any{"AbsolutePath": "/w/a"})
	path := writeDB(t, []step{{typ: 132, status: 3, payload: payload(nil, nil, nil, c)}})
	if _, _, err := (Adapter{}).Parse(path); err == nil || !strings.Contains(err.Error(), "5.6") {
		t.Errorf("Parse = %v, want an error about the missing timestamps", err)
	}
}

func TestParseOfAnEmptyConversationIsAnError(t *testing.T) {
	if _, _, err := (Adapter{}).Parse(writeDB(t, nil)); err == nil {
		t.Error("a conversation with no steps must not parse to an empty trajectory silently")
	}
}

func TestParseOfAFileThatIsNotADatabase(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.db")
	_ = os.WriteFile(p, []byte("not sqlite"), 0o644)
	if _, _, err := (Adapter{}).Parse(p); err == nil {
		t.Error("a non-database must be an error")
	}
	if _, _, err := (Adapter{}).Parse(filepath.Join(t.TempDir(), "missing.db")); err == nil {
		t.Error("a missing file must be an error")
	}
}

func TestDetect(t *testing.T) {
	a := Adapter{}
	if !a.Detect(fixture(t)) {
		t.Error("the fixture database is a Gemini conversation")
	}
	dir := t.TempDir()
	other := filepath.Join(dir, "other.db")
	db, _ := sql.Open("sqlite", other)
	_, _ = db.Exec("create table steps (idx integer)")
	_ = db.Close()
	text := filepath.Join(dir, "x.db")
	_ = os.WriteFile(text, []byte("hello"), 0o644)
	for name, p := range map[string]string{"another schema": other, "not sqlite": text, "missing": filepath.Join(dir, "none.db")} {
		if a.Detect(p) {
			t.Errorf("Detect(%s) = true", name)
		}
	}
}

func TestRegistered(t *testing.T) {
	if a, ok := agent.Lookup(Name); !ok || a.Name() != Name {
		t.Error("gemini adapter is not registered")
	}
	if a, err := agent.Detect(fixture(t)); err != nil || a.Name() != Name {
		t.Errorf("Detect = %v, %v", a, err)
	}
}

// --- wire walker ---

func TestWireWalkerRoundTrip(t *testing.T) {
	msg := cat(fVarint(1, 300), fBytes(2, []byte("hi")), fBytes(5, cat(fBytes(4, []byte("deep")))))
	fs, err := fields(msg)
	if err != nil || len(fs) != 3 || fs[0].u != 300 || string(fs[1].b) != "hi" {
		t.Fatalf("fields = %+v, %v", fs, err)
	}
	subs, err := submessages(msg, 5, 4)
	if err != nil || len(subs) != 1 || string(subs[0]) != "deep" {
		t.Errorf("submessages = %q, %v", subs, err)
	}
	if subs, err := submessages(msg, 9, 1); err != nil || len(subs) != 0 {
		t.Errorf("an absent path = %v, %v, want none and no error", subs, err)
	}
}

func TestWireWalkerRejectsMalformedInput(t *testing.T) {
	for name, b := range map[string][]byte{
		"truncated varint":  {0x08, 0x80},
		"length past end":   {0x12, 0x05, 'a'},
		"field zero":        {0x00, 0x01},
		"unsupported group": {0x0b},
		"overlong varint":   append([]byte{0x08}, []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01}...),
	} {
		if _, err := fields(b); err == nil {
			t.Errorf("%s: fields accepted malformed input", name)
		}
	}
	// Fixed-width fields decode.
	if fs, err := fields([]byte{0x0d, 1, 0, 0, 0, 0x11, 2, 0, 0, 0, 0, 0, 0, 0}); err != nil || len(fs) != 2 || fs[0].u != 1 || fs[1].u != 2 {
		t.Errorf("fixed fields = %+v, %v", fs, err)
	}
}

// A robustness check against real conversations, for a developer machine only:
// set AGENT_TRACE_GEMINI_CORPUS to the conversations directory. It asserts that
// every readable database parses without error and reports no figure, because a
// design corpus with no paired ground truth is not an evaluation set.
func TestParseRealConversationsDoNotFail(t *testing.T) {
	dir := os.Getenv("AGENT_TRACE_GEMINI_CORPUS")
	if dir == "" {
		t.Skip("AGENT_TRACE_GEMINI_CORPUS not set")
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.db"))
	if len(files) == 0 {
		t.Skipf("no databases in %s", dir)
	}
	for _, f := range files {
		if !(Adapter{}).Detect(f) {
			t.Logf("%s: not detected as a conversation, skipped", filepath.Base(f))
			continue
		}
		if _, _, err := (Adapter{}).Parse(f); err != nil {
			t.Errorf("%s: %v", filepath.Base(f), err)
		}
	}
}

// withStatus sets the status (field 4) of a payload built by payload and
// appends fields to it.
func withStatus(p []byte, status int, extra ...[]byte) []byte {
	head := cat(fVarint(1, 132), fVarint(4, 3))
	if !bytes.HasPrefix(p, head) {
		panic("not a payload built by payload")
	}
	return cat(append([][]byte{fVarint(1, 132), fVarint(4, uint64(status)), p[len(head):]}, extra...)...)
}

// I-134: a run_command canceled after the harness moved it to the
// background (its step names a task, field 148) is claimed as a command
// that started; a canceled one with no task, and any other tool or status,
// stay unclaimed (I-17).
func TestParseClaimsACanceledBackgroundCommand(t *testing.T) {
	task := fBytes(148, fBytes(1, []byte("0b18d7d3-41b4-4dfe-b649-e8ba776c383a/task-1")))
	run := func(cmd string) []byte {
		return payload(at(1), at(2), at(9), toolCall("c", "run_command", map[string]any{"CommandLine": cmd, "WaitMsBeforeAsync": 5000}))
	}
	path := writeDB(t, []step{
		{typ: 132, status: 6, payload: withStatus(run("grep -r x /"), 6, task)},
		{typ: 132, status: 6, payload: withStatus(run("sleep 9"), 6)},
		{typ: 132, status: 7, payload: withStatus(run("false"), 7, task)},
		{typ: 132, status: 6, payload: withStatus(payload(at(3), at(4), at(5), toolCall("v", "view_file", map[string]any{"AbsolutePath": "/w/a"})), 6, task)},
	})
	tr, rep := parse(t, path)
	if len(tr) != 1 || tr[0].ActionType != models.ProcessExec || tr[0].Target != "grep -r x /" || tr[0].End == nil || !tr[0].End.Equal(*at(9)) {
		t.Fatalf("claims %+v, want the canceled background command from its start to its cancel", tr)
	}
	if rep.UnmappedByTool["run_command (status 6)"] != 1 || rep.UnmappedByTool["run_command (status 7)"] != 1 || rep.UnmappedByTool["view_file (status 6)"] != 1 {
		t.Errorf("unmapped %v", rep.UnmappedByTool)
	}
	if d := strings.Join(rep.Degradations, "|"); !strings.Contains(d, "1 run_command step(s) canceled") || !strings.Contains(d, "status other than completed (3)") {
		t.Errorf("degradations %v", rep.Degradations)
	}
}

// V-95: a completed manage_task status call is claimed as an open of the log
// its task's record names (field 148.2, a file:// URI); a kill claims
// nothing, and a status call of a task no record names, or whose record's
// log is not a task log, is counted and not claimed.
func TestParseClaimsAStatusCallAsAReadOfTheTaskLog(t *testing.T) {
	const id = "0b18d7d3-41b4-4dfe-b649-e8ba776c383a"
	log := "/home/u/.gemini/antigravity-cli/brain/" + id + "/.system_generated/tasks/task-0.log"
	record := func(task, uri string) []byte {
		return fBytes(148, cat(fBytes(1, []byte(task)), fBytes(2, []byte(uri))))
	}
	run := withStatus(payload(at(1), at(1), at(6), toolCall("c", "run_command", map[string]any{"CommandLine": "sleep 60", "WaitMsBeforeAsync": 5000})), 3,
		record(id+"/task-0", "file://"+log))
	odd := withStatus(payload(at(1), at(1), at(6), toolCall("c", "run_command", map[string]any{"CommandLine": "sleep 61", "WaitMsBeforeAsync": 5000})), 3,
		record(id+"/task-1", "file:///home/u/elsewhere.log"))
	task := func(sec int, action, task string) []byte {
		return payload(at(sec), at(sec), at(sec+1), toolCall("m", "manage_task", map[string]any{"Action": action, "TaskId": task}))
	}
	path := writeDB(t, []step{
		{typ: 132, status: 3, payload: run},
		{typ: 132, status: 3, payload: odd},
		{typ: 132, status: 3, payload: task(7, "status", id+"/task-0")},
		{typ: 132, status: 3, payload: task(9, "kill", id+"/task-0")},
		{typ: 132, status: 3, payload: task(10, "status", id+"/task-1")},
		{typ: 132, status: 3, payload: task(11, "status", id+"/task-9")},
	})
	tr, rep := parse(t, path)
	var opens models.Trajectory
	for _, e := range tr {
		if e.Tool == "manage_task" {
			opens = append(opens, e)
		}
	}
	if len(opens) != 1 || opens[0].ActionType != models.FileOpen || opens[0].Target != log || !opens[0].Timestamp.Equal(*at(7)) || opens[0].End == nil || !opens[0].End.Equal(*at(8)) {
		t.Fatalf("manage_task claims %+v, want the status call's open of the log", opens)
	}
	if rep.UnmappedByTool["manage_task"] != 3 {
		t.Errorf("unmapped %v, want the kill and the two unresolved status calls", rep.UnmappedByTool)
	}
	d := strings.Join(rep.Degradations, "|")
	if !strings.Contains(d, "1 manage_task status call(s) were claimed") || !strings.Contains(d, "2 manage_task status call(s) name a task") {
		t.Errorf("degradations %v", rep.Degradations)
	}
}

// V-95 end to end, through Prepare with the bookkeeping declarations of
// 1.4.7 and a scope that marks the root filesystem, as a real capture does:
// the harness's open of the log within an honest status call corroborates
// its claim, and a status call with no open is Unwitnessed.
func TestAStatusCallVerifiesOnItsOpenOfTheLog(t *testing.T) {
	log := brain + "/tasks/task-0.log"
	e := t0.Add(time.Second)
	claim := models.TrajectoryEntry{Tool: "manage_task", Timestamp: t0, End: &e, ActionType: models.FileOpen, Target: log}
	verify := func(g models.GroundTruth) verification.Verdict {
		cov := &models.Coverage{Schema: models.CoverageSchema, Probes: map[string]models.ProbeCoverage{"fs": {Ran: true}, "proc": {Ran: true}}}
		f := models.GroundTruthFile{Events: g, RootPID: agentPID, Workspace: ws, Coverage: cov, FSScope: &models.FSScope{Mounts: []string{"/"}}}
		harness := func(e models.GroundTruthEvent) bool { return harnessOwned.MatchString(e.Target) }
		in := agent.Prepare(Adapter{}, models.Trajectory{claim}, f, harness, verification.Options{IntervalSlack: 500 * time.Millisecond})
		in.Options.HarnessBookkeeping = agent.HarnessBookkeeping(Adapter{}, "1.4.7", f)
		in.Options.HarnessClaimedWrites = agent.HarnessClaimedWrites(Adapter{}, "1.4.7", f)
		return verification.Verify(in)
	}
	us := time.Microsecond
	appends := models.GroundTruth{
		ev(100*us, agentPID, models.FileOpen, log), ev(150*us, agentPID, models.FileWrite, log), ev(200*us, agentPID, models.FileClose, log),
	}
	honest := append(append(models.GroundTruth{}, appends...), ev(500000*us, agentPID, models.FileOpen, log))
	v := verify(honest)
	if v.Outcome != verification.OutcomeFaithful || len(v.Corroborated) != 1 || !v.Corroborated[0].Event.Timestamp.Equal(t0.Add(500*time.Millisecond)) {
		t.Errorf("honest: outcome %s, corroborated %v, unexplained harness %v", v.Outcome, v.Corroborated, v.UnexplainedHarness)
	}
	v = verify(appends)
	if v.Outcome != verification.OutcomeNotFaithful || len(v.Unwitnessed) != 1 {
		t.Errorf("no open: outcome %s, unwitnessed %v", v.Outcome, v.Unwitnessed)
	}
}
