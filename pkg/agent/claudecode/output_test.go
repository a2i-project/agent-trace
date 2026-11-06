package claudecode

import (
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
)

const (
	recBgCall   = `{"type":"assistant","timestamp":"2026-11-06T16:15:38.900Z","sessionId":"s","version":"2.1.306","cwd":"/ws","message":{"id":"m1","role":"assistant","content":[{"type":"tool_use","id":"toolu_01Bg","name":"Bash","input":{"command":"sleep 10","run_in_background":true}}]}}`
	recBgResult = `{"type":"user","timestamp":"2026-11-06T16:15:38.930Z","sessionId":"s","version":"2.1.306","cwd":"/ws","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_01Bg","content":"Command running in background with ID: big785dos."}]},"toolUseResult":{"stdout":"","stderr":"","interrupted":false,"isImage":false,"backgroundTaskId":"big785dos"}}`
	recBgNotice = `{"type":"queue-operation","operation":"enqueue","timestamp":"2026-11-06T16:15:48.957Z","sessionId":"s","content":"<task-notification>\n<task-id>big785dos</task-id>\n<tool-use-id>toolu_01Bg</tool-use-id>\n<output-file>/tmp/claude-1001/-ws/s/tasks/big785dos.output</output-file>\n<status>completed</status>\n</task-notification>"}`
	// The harness removes the notice from its queue once delivered: a later
	// record of the same notice, which does not move the end.
	recBgRemove = `{"type":"queue-operation","operation":"remove","timestamp":"2026-11-06T16:15:49.328Z","sessionId":"s","content":"<task-notification>\n<task-id>big785dos</task-id>\n<tool-use-id>toolu_01Bg</tool-use-id>\n<status>completed</status>\n</task-notification>"}`
	recFgCall   = `{"type":"assistant","timestamp":"2026-11-06T16:16:00.000Z","sessionId":"s","version":"2.1.306","cwd":"/ws","message":{"id":"m2","role":"assistant","content":[{"type":"tool_use","id":"toolu_01Fg","name":"Bash","input":{"command":"true"}}]}}`
	recFgResult = `{"type":"user","timestamp":"2026-11-06T16:16:00.250Z","sessionId":"s","version":"2.1.306","cwd":"/ws","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_01Fg","content":""}]},"toolUseResult":{"stdout":"","stderr":"","interrupted":false,"isImage":false}}`
)

func execClaim(t *testing.T, tr models.Trajectory, cmd string) models.TrajectoryEntry {
	t.Helper()
	for _, c := range tr {
		if c.ActionType == models.ProcessExec && c.Target == cmd {
			return c
		}
	}
	t.Fatalf("no claim of %q in %v", cmd, tr)
	return models.TrajectoryEntry{}
}

// A background call's claim names its output file by the result's task id
// and ends at the harness's enqueued notice, a foreground call's at its
// result, each at the latest moment the millisecond timestamp allows
// (V-101).
func TestParseStatesEachBashCallsOutputAndItsEnd(t *testing.T) {
	tr, rep, err := Adapter{}.Parse(writeLines(t, recBgCall, recBgResult, recFgCall, recFgResult, recBgNotice, recBgRemove))
	if err != nil || len(rep.ParseErrors) != 0 {
		t.Fatalf("parse: %v %v", err, rep.ParseErrors)
	}
	bg := execClaim(t, tr, "sleep 10")
	wantBg := time.Date(2026, 11, 6, 16, 15, 48, 957999999, time.UTC)
	if bg.OutputName != "big785dos.output" || bg.OutputDone == nil || !bg.OutputDone.Equal(wantBg) {
		t.Errorf("background call: name %q, end %v, want big785dos.output and %v", bg.OutputName, bg.OutputDone, wantBg)
	}
	fg := execClaim(t, tr, "true")
	wantFg := time.Date(2026, 11, 6, 16, 16, 0, 250999999, time.UTC)
	if fg.OutputName != "" || fg.OutputDone == nil || !fg.OutputDone.Equal(wantFg) {
		t.Errorf("foreground call: name %q, end %v, want none and %v", fg.OutputName, fg.OutputDone, wantFg)
	}
}

// With no notice, the background call still names its file and states no
// end; a call asked to run in the background whose result names no task
// states neither, so its file is never read as a foreground call's.
func TestParseStatesNoEndItCannotRead(t *testing.T) {
	tr, _, err := Adapter{}.Parse(writeLines(t, recBgCall, recBgResult))
	if err != nil {
		t.Fatal(err)
	}
	if bg := execClaim(t, tr, "sleep 10"); bg.OutputName != "big785dos.output" || bg.OutputDone != nil {
		t.Errorf("no notice: name %q, end %v", bg.OutputName, bg.OutputDone)
	}
	noID := `{"type":"user","timestamp":"2026-11-06T16:15:38.930Z","sessionId":"s","version":"2.1.306","cwd":"/ws","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_01Bg","content":""}]},"toolUseResult":{"interrupted":false,"isImage":false}}`
	tr, _, err = Adapter{}.Parse(writeLines(t, recBgCall, noID))
	if err != nil {
		t.Fatal(err)
	}
	if bg := execClaim(t, tr, "sleep 10"); bg.OutputName != "" || bg.OutputDone != nil {
		t.Errorf("background call with no task id: name %q, end %v", bg.OutputName, bg.OutputDone)
	}
	// A call with no result reports no end.
	tr, _, err = Adapter{}.Parse(writeLines(t, recFgCall))
	if err != nil {
		t.Fatal(err)
	}
	if fg := execClaim(t, tr, "true"); fg.OutputDone != nil {
		t.Errorf("a call with no result: end %v", fg.OutputDone)
	}
}

// Only an enqueued task notice naming a call is an end: another queued
// command, a removal or a malformed notice is not.
func TestEndNotice(t *testing.T) {
	ts := time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		op, content string
		want        string
	}{
		{"enqueue", `"<task-notification>\n<task-id>b1</task-id>\n<tool-use-id>toolu_01X</tool-use-id>\n</task-notification>"`, "toolu_01X"},
		{"remove", `"<task-notification>\n<task-id>b1</task-id>\n<tool-use-id>toolu_01X</tool-use-id>\n</task-notification>"`, ""},
		{"enqueue", `"please also run the tests"`, ""},
		{"enqueue", `"text <task-notification>\n<tool-use-id>toolu_01X</tool-use-id>\n"`, ""},
		{"enqueue", `{"not":"a string"}`, ""},
	} {
		got, ok := endNotice(record{Type: "queue-operation", Operation: c.op, Timestamp: ts, Content: []byte(c.content)})
		if got != c.want || ok != (c.want != "") {
			t.Errorf("%s %s: %q %v, want %q", c.op, c.content, got, ok, c.want)
		}
	}
}
