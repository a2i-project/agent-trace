package gemini

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// Synthetic conversation ids. Real ones are random UUIDs.
const (
	mainID = "00000000-0000-4000-8000-000000000000"
	subA   = "aaaaaaaa-0000-4000-8000-000000000001"
	subB   = "bbbbbbbb-0000-4000-8000-000000000002"
)

// invokeResult is an invoke_subagent step's result as agy 1.3.4 writes it
// (I-55): field 140, with the text for the model in 2.1 and, in the Step
// that 2.6 wraps as an Any, one 143.10 per subagent holding its id in 1.
func invokeResult(ids ...string) []byte {
	var subs, text []byte
	for _, id := range ids {
		subs = append(subs, fBytes(10, cat(fBytes(1, []byte(id)), fBytes(2, []byte("file:///x/"+id+"/transcript.jsonl"))))...)
		text = append(text, fmt.Sprintf("{\n  \"conversationId\": %q\n}\n", id)...)
	}
	step := cat(fVarint(1, 127), fBytes(143, cat(fBytes(9, []byte("role")), subs)))
	anyMsg := cat(fBytes(1, []byte("type.googleapis.com/gemini_coder.Step")), fBytes(2, step))
	return fBytes(140, fBytes(2, cat(fBytes(1, append([]byte("Created the following subagents:\n"), text...)), fBytes(6, anyMsg))))
}

// invokeStep is a completed invoke_subagent step at second sec whose result
// names ids.
func invokeStep(sec int, ids ...string) step {
	call := toolCall("inv", toolSubagent, map[string]any{"Subagents": []any{map[string]any{"TypeName": "child"}}})
	return step{typ: 132, status: 3, payload: cat(payload(at(sec), at(sec), at(sec), call), invokeResult(ids...))}
}

func commandStep(sec int, cmd string) step {
	return step{typ: 132, status: 3, payload: payload(at(sec), at(sec), at(sec+1), toolCall("c", toolRunCommand, map[string]any{"CommandLine": cmd, "Cwd": "/w"}))}
}

func describe(tr models.Trajectory) []string {
	var got []string
	for _, e := range tr {
		got = append(got, e.Target+"@"+e.ThreadID)
	}
	return got
}

func degradation(t *testing.T, path, want string) {
	t.Helper()
	_, rep := parse(t, path)
	if !strings.Contains(strings.Join(rep.Degradations, "|"), want) {
		t.Errorf("Degradations lack %q:\n%s", want, strings.Join(rep.Degradations, "\n"))
	}
}

// As agy keeps them: the subagent's database beside its caller's, named by
// its id. Its claims carry its id as thread and interleave with the main
// thread's by started time, ties in the main thread's favour, as the Claude
// Code adapter orders them (D9).
func TestASubagentBesideTheConversationIsFollowed(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, mainID+".db")
	writeDBAt(t, main, []step{commandStep(1, "first"), invokeStep(2, subA), commandStep(4, "after"), commandStep(6, "tie")})
	writeDBAt(t, filepath.Join(dir, subA+".db"), []step{
		{typ: 101, status: 3, payload: cat(fVarint(1, 101), fBytes(5, fBytes(1, tsMsg(*at(2)))))}, // the caller's message, no call
		commandStep(3, "sub-early"), commandStep(5, "sub-late"), commandStep(6, "sub-tie"),
	})
	tr, rep := parse(t, main)
	want := []string{"first@", "sub-early@" + subA, "after@", "sub-late@" + subA, "tie@", "sub-tie@" + subA}
	if got := describe(tr); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("claims = %v, want %v", got, want)
	}
	if rep.ToolCalls != 7 || rep.Entries != 6 || rep.UnmappedByTool[toolSubagent] != 1 || len(rep.ParseErrors) != 0 {
		t.Errorf("report: calls %d entries %d unmapped %v errors %v", rep.ToolCalls, rep.Entries, rep.UnmappedByTool, rep.ParseErrors)
	}
	joined := strings.Join(rep.Degradations, "|")
	if !strings.Contains(joined, "1 subagent conversation(s) followed") || strings.Contains(joined, "unexplained:") {
		t.Errorf("Degradations:\n%s", strings.Join(rep.Degradations, "\n"))
	}
}

// As the capture script copies them: <label>.conversation/subagents/<id>.db
// beside <label>.conversation.db. Nested subagents are found in the same
// directory.
func TestASubagentInTheCaptureLayoutIsFollowedWithItsOwnSubagent(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "task.conversation.db")
	subs := filepath.Join(dir, "task.conversation", "subagents")
	writeDBAt(t, main, []step{invokeStep(1, subA)})
	writeDBAt(t, filepath.Join(subs, subA+".db"), []step{commandStep(2, "in-a"), invokeStep(3, subB)})
	writeDBAt(t, filepath.Join(subs, subB+".db"), []step{commandStep(4, "in-b")})
	tr, rep := parse(t, main)
	want := []string{"in-a@" + subA, "in-b@" + subB}
	if got := describe(tr); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("claims = %v, want %v", got, want)
	}
	if rep.UnmappedByTool[toolSubagent] != 2 {
		t.Errorf("unmapped %v", rep.UnmappedByTool)
	}
	degradation(t, main, "2 subagent conversation(s) followed")
}

// A missing database is a degradation that names the subagent, never an
// error: the main thread's claims stay.
func TestAMissingSubagentIsADegradation(t *testing.T) {
	main := filepath.Join(t.TempDir(), mainID+".db")
	writeDBAt(t, main, []step{commandStep(1, "first"), invokeStep(2, subA)})
	tr, rep := parse(t, main)
	if got := describe(tr); len(got) != 1 || got[0] != "first@" {
		t.Errorf("claims = %v", got)
	}
	if len(rep.ParseErrors) != 0 {
		t.Errorf("parse errors %v", rep.ParseErrors)
	}
	degradation(t, main, "1 subagent conversation(s) named by an invoke_subagent result have no database beside the conversation or in its subagents directory, so what they did appears unexplained: "+subA)
}

// A result with no id, and an id that is not a conversation id (it comes from
// the trajectory, and a path in it would name a file elsewhere), name no
// subagent; the step is reported.
func TestAnInvokeWithNoUsableIDIsReported(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "x.db"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	call := toolCall("inv", toolSubagent, map[string]any{})
	main := filepath.Join(dir, "sub", mainID+".db")
	writeDBAt(t, main, []step{
		{typ: 132, status: 3, payload: payload(at(1), at(1), at(1), call)},
		{typ: 132, status: 3, payload: cat(payload(at(2), at(2), at(2), call), invokeResult("../x"))},
	})
	tr, rep := parse(t, main)
	if len(tr) != 0 || len(rep.ParseErrors) != 0 {
		t.Errorf("claims %v errors %v", describe(tr), rep.ParseErrors)
	}
	degradation(t, main, "2 invoke_subagent step(s) name no subagent conversation in their result")
}

// A subagent database that does not parse is a parse error naming the
// subagent, and adds nothing else; the main thread is unaffected.
func TestASubagentThatDoesNotParseIsAParseError(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, mainID+".db")
	writeDBAt(t, main, []step{commandStep(1, "first"), invokeStep(2, subA)})
	writeDBAt(t, filepath.Join(dir, subA+".db"), []step{{typ: 132, status: 3, payload: []byte{0x2a, 0x05, 0x01}}})
	tr, rep := parse(t, main)
	if got := describe(tr); len(got) != 1 || len(rep.ParseErrors) != 1 || !strings.HasPrefix(rep.ParseErrors[0], "subagent "+subA+": ") {
		t.Errorf("claims %v errors %v", got, rep.ParseErrors)
	}
	if rep.ToolCalls != 2 {
		t.Errorf("tool calls %d, want the main thread's 2", rep.ToolCalls)
	}
}

// Nesting is followed down to maxSubagentDepth levels; a deeper subagent is
// reported, not read. A subagent that names its caller, itself or the main
// conversation is read once.
func TestNestedSubagentsAreBoundedAndCyclesEnd(t *testing.T) {
	dir := t.TempDir()
	ids := make([]string, maxSubagentDepth+2)
	for i := range ids {
		ids[i] = fmt.Sprintf("%08d-0000-4000-8000-000000000000", i+1)
	}
	main := filepath.Join(dir, mainID+".db")
	writeDBAt(t, main, []step{invokeStep(1, ids[0])})
	for i, id := range ids {
		next := []string{id, mainID}
		if i+1 < len(ids) {
			next = append(next, ids[i+1])
		}
		writeDBAt(t, filepath.Join(dir, id+".db"), []step{commandStep(10*(i+1), "level-"+fmt.Sprint(i+1)), invokeStep(10*(i+1)+2, next...)})
	}
	tr, _ := parse(t, main)
	if len(tr) != maxSubagentDepth || tr[len(tr)-1].Target != fmt.Sprintf("level-%d", maxSubagentDepth) {
		t.Errorf("claims = %v, want levels 1 to %d", describe(tr), maxSubagentDepth)
	}
	degradation(t, main, fmt.Sprintf("1 subagent conversation(s) nested more than %d levels deep are not followed", maxSubagentDepth))
	degradation(t, main, fmt.Sprintf("%d subagent conversation(s) followed", maxSubagentDepth))
}

// A subagent's parallel block keeps a block id of its own: the blocks of two
// threads at the same step index must not merge (V-32).
func TestSubagentBlocksDoNotShareTheMainThreadsIDs(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, mainID+".db")
	two := func(sec int) step {
		return step{typ: 132, status: 3, payload: payload(at(sec), at(sec), at(sec+1),
			toolCall("x", toolViewFile, map[string]any{"AbsolutePath": "/w/x"}),
			toolCall("y", toolViewFile, map[string]any{"AbsolutePath": "/w/y"}))}
	}
	writeDBAt(t, main, []step{two(1), invokeStep(2, subA)})
	writeDBAt(t, filepath.Join(dir, subA+".db"), []step{two(3)})
	tr, _ := parse(t, main)
	if len(tr) != 4 || tr[0].BlockID != "step-0" || tr[2].BlockID != subA+"/step-0" || tr[2].BlockID != tr[3].BlockID {
		var b []string
		for _, e := range tr {
			b = append(b, e.BlockID)
		}
		t.Errorf("block ids %v", b)
	}
}

// The conversations of the parallel strace run (I-47), reduced with the
// subagent's: the subagent's command is claimed on its own thread, after the
// main thread's last command, where strace saw it run.
func TestARealSubagentIsFollowed(t *testing.T) {
	got, tr := realClaims(t, "parallel.conversation.db")
	last := tr[len(tr)-1]
	if got[len(got)-1] != "run_command:process_exec:echo from-subagent" || last.ThreadID != "cf10d29e-1624-451d-b923-e60943d3584a" {
		t.Errorf("last claim %s on thread %q", got[len(got)-1], last.ThreadID)
	}
	for _, e := range tr[:len(tr)-1] {
		if e.ThreadID != "" {
			t.Errorf("%s on thread %q", e.Target, e.ThreadID)
		}
	}
}
