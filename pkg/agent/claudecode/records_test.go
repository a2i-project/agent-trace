package claudecode

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agent-trace/agent-trace/pkg/models"
)

func writeLines(t *testing.T, lines ...string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "s.jsonl")
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

const (
	recEdit   = `{"type":"assistant","timestamp":"2026-10-24T10:00:00Z","sessionId":"s","version":"2.1.306","message":{"id":"m1","role":"assistant","content":[{"type":"tool_use","id":"t1","name":"Edit","input":{"file_path":"/ws/n.txt","old_string":"a","new_string":"b","replace_all":false}}]}}`
	recResult = `{"type":"user","timestamp":"2026-10-24T10:00:01Z","sessionId":"s","version":"2.1.306","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"ok"}]},"toolUseResult":{"originalFile":"a\n","oldString":"a","newString":"b","replaceAll":false}}`
	// An API request copied into the transcript (2.1.306): the call and its
	// result again, with no timestamp and no structured result, and a call
	// that no assistant record states.
	recBlob = `{"type":"api-request-blob","sessionId":"s","hash":"h","message":{"role":"user","content":[{"type":"tool_use","id":"t1","name":"Edit","input":{"file_path":"/ws/n.txt","old_string":"a","new_string":"b"}},{"type":"tool_result","tool_use_id":"t1","content":"ok"},{"type":"tool_use","id":"t9","name":"Bash","input":{"command":"rm -rf /ws"}},{"type":"text","text":"go on"}]}}`
)

// Only an assistant record states a call and only a user record its result
// (I-62): a record of another type that repeats them claims nothing, does not
// replace the result the call's claims take their interval and content from,
// and a call only it holds is not a call.
func TestOnlyAssistantAndUserRecordsStateCalls(t *testing.T) {
	want, wantRep, err := Adapter{}.Parse(writeLines(t, recEdit, recResult))
	if err != nil {
		t.Fatal(err)
	}
	for name, lines := range map[string][]string{
		"copy after the result":  {recEdit, recResult, recBlob},
		"copy before the call":   {recBlob, recEdit, recResult},
		"copy between the two":   {recEdit, recBlob, recResult},
		"unknown type, no calls": {`{"type":"cost-state","sessionId":"s","totalCostUSD":0.1}`, recEdit, recResult},
	} {
		t.Run(name, func(t *testing.T) {
			tr, rep, err := Adapter{}.Parse(writeLines(t, lines...))
			if err != nil || len(rep.ParseErrors) != 0 || rep.ToolCalls != 1 || len(rep.UnmappedByTool) != 0 {
				t.Fatalf("parse: %v %+v", err, rep)
			}
			if len(tr) != 2 || len(tr) != len(want) || rep.Entries != wantRep.Entries {
				t.Fatalf("claims %v, want %v", tr, want)
			}
			for i, e := range tr {
				w := want[i]
				if e.ActionType != w.ActionType || e.Target != w.Target || !e.Timestamp.Equal(w.Timestamp) || e.End == nil || !e.End.Equal(*w.End) ||
					e.InputHash == nil && e.ActionType == models.FileOpen || e.OutputHash == nil && e.ActionType == models.FileWrite {
					t.Errorf("claim %d = %+v, want %+v with its content", i, e, w)
				}
			}
		})
	}
}

// A call or a result stated twice by the records that state them is claimed
// once, from the first, and each repeat is a parse error (I-62), in a
// subagent's transcript as in the main one.
func TestARepeatedCallIsAParseErrorNotASecondClaim(t *testing.T) {
	p := writeLines(t, recEdit, recResult, recEdit, recResult)
	tr, rep, err := Adapter{}.Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(tr) != 2 || rep.ToolCalls != 1 || len(rep.ParseErrors) != 2 ||
		rep.ParseErrors[0] != "s.jsonl:3: tool_use t1 repeated; the first is kept" ||
		rep.ParseErrors[1] != "s.jsonl:4: tool_result t1 repeated; the first is kept" {
		t.Errorf("%d claims of %d calls, parse errors %q; want 2 of 1 and the two repeats", len(tr), rep.ToolCalls, rep.ParseErrors)
	}

	sub := filepath.Join(strings.TrimSuffix(p, ".jsonl"), "subagents")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "agent-a1.jsonl"), []byte(recEdit+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tr, rep, err = Adapter{}.Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(tr) != 2 || rep.ToolCalls != 1 || len(rep.ParseErrors) != 3 || rep.ParseErrors[2] != "agent-a1.jsonl:1: tool_use t1 repeated; the first is kept" {
		t.Errorf("with the call repeated in a subagent: %d claims of %d calls, parse errors %q", len(tr), rep.ToolCalls, rep.ParseErrors)
	}
	for _, e := range tr {
		if e.ThreadID != "" {
			t.Errorf("a claim from the subagent's repeat: %+v", e)
		}
	}
}
