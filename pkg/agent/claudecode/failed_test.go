package claudecode

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// A Read, Write or Edit whose result is marked is_error claims nothing
// (I-68). Shapes from a long task on 2.1.306: a subagent's Write of a report
// file that the harness refused ("<tool_use_error>Subagents should return
// findings as text, ..."), whose transcript has no structured result, and a
// Read of a file that did not exist, whose structured result is the error
// text. Neither left an event; claimed, the Write was two Unwitnessed claims
// and the Read paired with an unrelated open.
func TestAFailedFileToolClaimsNothing(t *testing.T) {
	dir := t.TempDir()
	use := `{"type":"assistant","timestamp":"2026-10-26T10:00:00Z","sessionId":"s","version":"2.1.306","message":{"id":"m1","content":[{"type":"tool_use","id":"t1","name":%q,"input":%s}]}}`
	result := `{"type":"user","timestamp":"2026-10-26T10:00:01Z","sessionId":"s","version":"2.1.306","message":{"id":"m2","content":[{"type":"tool_result","tool_use_id":"t1","content":%q%s}]}%s}`
	inputs := map[string]string{
		toolRead:  `{"file_path":"/ws/REPORT.md"}`,
		toolWrite: `{"file_path":"/ws/REPORT.md","content":"44 tests ran.\n"}`,
		toolEdit:  `{"file_path":"/ws/a.py","old_string":"x","new_string":"y"}`,
	}
	ok := map[string]int{toolRead: 1, toolWrite: 2, toolEdit: 2}
	for _, tool := range []string{toolRead, toolWrite, toolEdit} {
		for name, tc := range map[string]struct {
			isError, structured, text string
			claims                    int
		}{
			"is_error, error text as the structured result": {`,"is_error":true`, `,"toolUseResult":"Error: File does not exist."`, "File does not exist.", 0},
			"is_error, no structured result":                {`,"is_error":true`, "", "<tool_use_error>Subagents should return findings as text, not write report files.</tool_use_error>", 0},
			"no error":                                      {"", "", "ok", ok[tool]},
		} {
			t.Run(tool+"/"+name, func(t *testing.T) {
				p := filepath.Join(dir, fmt.Sprintf("%s-%d.jsonl", tool, len(name)))
				body := fmt.Sprintf(use, tool, inputs[tool]) + "\n" + fmt.Sprintf(result, tc.text, tc.isError, tc.structured) + "\n"
				if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
				tr, rep, err := Adapter{}.Parse(p)
				if err != nil || len(rep.ParseErrors) != 0 {
					t.Fatalf("parse: %v %v", err, rep.ParseErrors)
				}
				if len(tr) != tc.claims {
					t.Fatalf("claims = %+v, want %d", tr, tc.claims)
				}
				if tc.claims == 0 && rep.UnmappedByTool[tool] != 1 {
					t.Errorf("a failed %s is not counted: %v", tool, rep.UnmappedByTool)
				}
				for _, d := range rep.Degradations {
					if tc.claims == 0 && d == "1 Write call(s) have no create or update result, so they are assumed to overwrite an existing file" {
						t.Errorf("a failed Write is counted as an assumed overwrite")
					}
				}
			})
		}
	}
}

// The verifier side of I-68: a failed Write leaves nothing to explain, so a
// session whose only file call failed and whose capture holds no event of
// the file has no finding.
func TestAFailedWriteIsNotUnwitnessed(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "s.jsonl")
	body := `{"type":"assistant","timestamp":"2026-10-26T10:00:00Z","sessionId":"s","version":"2.1.306","message":{"id":"m1","content":[{"type":"tool_use","id":"t1","name":"Write","input":{"file_path":"/ws/REPORT.md","content":"x"}}]}}
{"type":"user","timestamp":"2026-10-26T10:00:01Z","sessionId":"s","version":"2.1.306","message":{"id":"m2","content":[{"type":"tool_result","tool_use_id":"t1","content":"<tool_use_error>Subagents should return findings as text, not write report files.</tool_use_error>","is_error":true}]},"toolUseResult":"Error: Subagents should return findings as text, not write report files."}
`
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	tr, _, err := Adapter{}.Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	g := models.GroundTruth{{Timestamp: time.Date(2026, 10, 26, 9, 59, 59, 0, time.UTC), ActionType: models.FileOpen, Target: "/ws/other.txt", PID: 0}}
	v := verification.Verify(verification.Input{Claims: tr, Ground: g})
	if len(v.Unwitnessed) != 0 || len(v.Mismatched) != 0 {
		t.Errorf("unwitnessed %v, mismatched %v, want none", v.Unwitnessed, v.Mismatched)
	}
}
