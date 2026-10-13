package gemini

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/agent-trace/agent-trace/pkg/content"
	"github.com/agent-trace/agent-trace/pkg/models"
)

// testdata/agy-1.3.4-strace holds two conversations of agy 1.3.4 recorded in
// print mode under strace on 2026-10-13 (I-47), reduced by
// the Gemini reduction of scripts/make-capture-fixture.py: workspaces rewritten to /ws/1 and /ws/3,
// payloads cut to the fields the adapter reads. They have no ground truth; the
// observed side below is what strace recorded, in the form the process probe
// gives it (the executed path and argv[1:] joined by spaces).
const realDir = "testdata/agy-1.3.4-strace"

func realClaims(t *testing.T, name string) ([]string, models.Trajectory) {
	t.Helper()
	tr, rep, err := Adapter{}.Parse(filepath.Join(realDir, name))
	if err != nil {
		t.Fatalf("Parse(%s): %v", name, err)
	}
	if len(rep.ParseErrors) != 0 {
		t.Errorf("%s: parse errors %v", name, rep.ParseErrors)
	}
	var got []string
	for _, e := range tr {
		got = append(got, e.Tool+":"+string(e.ActionType)+":"+e.Target)
	}
	return got, tr
}

func TestARealConversationParses(t *testing.T) {
	got, tr := realClaims(t, "tools.conversation.db")
	want := []string{
		"run_command:process_exec:echo hi",
		"view_file:file_open:/ws/1/b.txt",
		"write_to_file:file_open:/ws/1/a.txt", "write_to_file:file_write:/ws/1/a.txt", "write_to_file:file_close:/ws/1/a.txt",
		"replace_file_content:file_open:/ws/1/a.txt", "replace_file_content:file_write:/ws/1/a.txt", "replace_file_content:file_close:/ws/1/a.txt",
		"run_command:process_exec:cat a.txt",
		"grep_search:process_exec:" + SearchGrep,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("claims =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// strace saw the harness write "hello\n" for CodeContent "hello".
	for _, e := range tr {
		if e.Tool == "write_to_file" && e.ActionType == models.FileClose {
			if e.OutputHash == nil || *e.OutputHash != content.SHA256Bytes([]byte("hello\n")) {
				t.Errorf("write_to_file close hash = %v, want the hash of hello and a newline", e.OutputHash)
			}
		}
	}
	// list_dir and find_by_name are non-effectful, grep_search is claimed
	// (I-54): no tool of the conversation is unknown.
	_, rep, _ := Adapter{}.Parse(filepath.Join(realDir, "tools.conversation.db"))
	if len(rep.UnknownTools) != 0 || rep.UnmappedByTool["list_dir"] != 1 || rep.UnmappedByTool["find_by_name"] != 1 {
		t.Errorf("UnknownTools = %v, unmapped %v", rep.UnknownTools, rep.UnmappedByTool)
	}
}

// Every command claim of the real conversations is recovered from the wrapper
// strace recorded for it, under the PATH of an interactive shell
// (/usr/bin/bash) and under the reset environment the capture script runs agy
// in (/bin/bash).
func TestTheObservedWrapperRecoversEveryRealCommand(t *testing.T) {
	observed := map[string]string{
		"echo hi":            "/usr/bin/bash -c echo hi",
		"cat a.txt":          "/usr/bin/bash -c cat a.txt",
		"sleep 2; echo slow": "/usr/bin/bash -c sleep 2; echo slow",
		"echo fast":          "/usr/bin/bash -c echo fast",
		"cat two.txt":        "/usr/bin/bash -c cat two.txt",
	}
	n := 0
	for _, name := range []string{"tools.conversation.db", "parallel.conversation.db"} {
		_, tr := realClaims(t, name)
		for _, e := range tr {
			if e.Tool != toolRunCommand {
				continue
			}
			o, ok := observed[e.Target]
			if !ok {
				t.Fatalf("no observed wrapper for %q", e.Target)
			}
			got, _ := Adapter{}.Normalize(models.GroundTruthEvent{ActionType: models.ProcessExec, Target: o})
			if got.Target != e.Target {
				t.Errorf("Normalize(%q) = %q, want the claim %q", o, got.Target, e.Target)
			}
			n++
		}
	}
	if n != 5 {
		t.Errorf("%d commands checked, want 5", n)
	}
	got, _ := Adapter{}.Normalize(models.GroundTruthEvent{ActionType: models.ProcessExec, Target: "/bin/bash -c : agent-trace-control-marker"})
	if got.Target != ": agent-trace-control-marker" {
		t.Errorf("the control's command under a reset environment = %q", got.Target)
	}
}

// Two run_command calls the model issued together are two steps with
// overlapping intervals and no block id; the subagent's own steps are not in
// this database, which the report says.
func TestARealParallelConversation(t *testing.T) {
	got, tr := realClaims(t, "parallel.conversation.db")
	want := []string{
		"run_command:process_exec:sleep 2; echo slow",
		"run_command:process_exec:echo fast",
		"write_to_file:file_open:/ws/3/two.txt", "write_to_file:file_write:/ws/3/two.txt", "write_to_file:file_close:/ws/3/two.txt",
		"run_command:process_exec:cat two.txt",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("claims =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	slow, fast := tr[0], tr[1]
	if slow.BlockID != "" || fast.BlockID != "" || slow.End == nil || !fast.Timestamp.Before(*slow.End) {
		t.Errorf("parallel steps: slow [%v, %v] %q, fast [%v] %q", slow.Timestamp, slow.End, slow.BlockID, fast.Timestamp, fast.BlockID)
	}
	if tr[4].OutputHash == nil || *tr[4].OutputHash != content.SHA256Bytes([]byte("one\ntwo\n")) {
		t.Errorf("two.txt close hash = %v", tr[4].OutputHash)
	}
	_, rep, _ := Adapter{}.Parse(filepath.Join(realDir, "parallel.conversation.db"))
	if rep.UnmappedByTool["invoke_subagent"] != 1 || !strings.Contains(strings.Join(rep.Degradations, "|"), "invoke_subagent") {
		t.Errorf("report: %v %v", rep.UnmappedByTool, rep.Degradations)
	}
}
