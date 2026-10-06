package gemini

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
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("create table steps (idx integer, step_type integer, status integer, has_subtrajectory numeric, step_payload blob, primary key (idx))"); err != nil {
		t.Fatal(err)
	}
	for i, s := range steps {
		if _, err := db.Exec("insert into steps values (?,?,?,?,?)", i, s.typ, s.status, s.sub, s.payload); err != nil {
			t.Fatal(err)
		}
	}
	return path
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
		{typ: 132, status: 3, payload: payload(at(21), at(22), at(23), toolCall("c7", "grep_search", map[string]any{"Query": "x"}))},
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
	for _, k := range []string{"manage_task", "grep_search", "run_command (status 7)", "run_command (persistent shell)"} {
		if rep.UnmappedByTool[k] == 0 {
			t.Errorf("%q not counted: %v", k, rep.UnmappedByTool)
		}
	}
	if len(rep.UnknownTools) != 1 || rep.UnknownTools[0] != "grep_search" {
		t.Errorf("UnknownTools = %v, want [grep_search]", rep.UnknownTools)
	}
	joined := strings.Join(rep.Degradations, "|")
	for _, want := range []string{"unmeasured", "persistent shell", "status other than completed", "subtrajectory", "created time", "grep_search", "exit code"} {
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

func TestProcessModelSaysWhatIsUnmeasured(t *testing.T) {
	m := Adapter{}.Process()
	if m.IntervalKind != agent.IntervalExecution || m.Concurrency != agent.ConcurrencyUnmeasured || m.ExitsClaimed {
		t.Errorf("Process() = %+v", m)
	}
}

// --- failing loudly (07 section 4) ---

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
