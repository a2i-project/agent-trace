package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agent-trace/agent-trace/pkg/content"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

const tools306 = "../../pkg/agent/claudecode/testdata/paired-2.1.306-tools/"

// A Claude Code transcript that is gone, empty or garbled is a trace that
// cannot be verified: INCONCLUSIVE, exit 2, never a usage error and never
// FAITHFUL, with the capture's evidence of the transcript (V-59).
func TestAMissingOrDamagedTranscriptCannotBeVerified(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.session.jsonl")
	garbled := filepath.Join(dir, "garbled.session.jsonl")
	_ = os.WriteFile(empty, nil, 0o644)
	_ = os.WriteFile(garbled, []byte("{\n"), 0o644)
	for path, state := range map[string]verification.TraceState{
		filepath.Join(dir, "gone.session.jsonl"): verification.TraceMissing,
		empty:                                    verification.TraceEmpty,
		garbled:                                  verification.TraceDamaged,
	} {
		t.Run(string(state), func(t *testing.T) {
			js := filepath.Join(dir, string(state)+".json")
			code, out, errOut := verify(t, "--agent", "claude-code", "--trajectory", path, "--ground-truth", tools306+"tools.ground_truth.json", "--json", js)
			if code != 2 || errOut != "" {
				t.Fatalf("exit %d, stderr %q, want 2", code, errOut)
			}
			for _, want := range []string{"trace:        CANNOT VERIFY: the trace was deleted or damaged (" + string(state) + ")", "observed /home/user/.claude/projects/-ws-tools/", "VERDICT: INCONCLUSIVE", "  - cannot verify: the trace was deleted or damaged"} {
				if !strings.Contains(out, want) {
					t.Errorf("output lacks %q:\n%s", want, out)
				}
			}
			var rep struct {
				Outcome string                   `json:"outcome"`
				Trace   *verification.TraceCheck `json:"trace"`
			}
			data, _ := os.ReadFile(js)
			if err := json.Unmarshal(data, &rep); err != nil || rep.Trace == nil || rep.Trace.State != state || rep.Outcome != "INCONCLUSIVE" || len(rep.Trace.Files) != 1 {
				t.Errorf("JSON trace %+v outcome %q err %v", rep.Trace, rep.Outcome, err)
			}
		})
	}
}

// With --check-trace-hash the transcript is compared with the last content
// the probe hashed: the fixture's transcript was rewritten when it was made,
// so it differs, and a copy made to match reads as before.
func TestCheckTraceHash(t *testing.T) {
	g := tools306 + "tools.ground_truth.json"
	code, out, _ := verify(t, "--agent", "claude-code", "--trajectory", tools306+"tools.session.jsonl", "--ground-truth", g, "--check-trace-hash")
	if code != 2 || !strings.Contains(out, "CANNOT VERIFY: the trace was deleted or damaged (differs)") {
		t.Fatalf("exit %d, want the rewritten fixture to differ:\n%s", code, out)
	}
	// A ground truth whose last close of the transcript carries the hash of
	// the file read: the comparison holds and the verdict is the one without
	// the flag.
	data, _ := os.ReadFile(g)
	gt, err := models.ParseGroundTruthFile(data)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha(t, tools306+"tools.session.jsonl")
	last := -1
	for i, e := range gt.Events {
		if strings.HasSuffix(e.Target, ".jsonl") && strings.Contains(e.Target, "/.claude/projects/") && !strings.Contains(e.Target, "/subagents/") && e.ActionType == models.FileClose {
			last = i
		}
	}
	gt.Events[last].OutputHash = &sum
	matched := writeJSON(t, t.TempDir(), "g.json", gt)
	_, plain, _ := verify(t, "--agent", "claude-code", "--trajectory", tools306+"tools.session.jsonl", "--ground-truth", matched)
	code, out, _ = verify(t, "--agent", "claude-code", "--trajectory", tools306+"tools.session.jsonl", "--ground-truth", matched, "--check-trace-hash")
	if !strings.Contains(out, "trace:        the session file read is the content the probe hashed at its last write\n") {
		t.Fatalf("want the comparison reported:\n%s", out)
	}
	if strings.Replace(out, "trace:        the session file read is the content the probe hashed at its last write\n", "", 1) != plain {
		t.Error("a matching comparison changed the report beyond its line")
	}
	if want, _, _ := verify(t, "--agent", "claude-code", "--trajectory", tools306+"tools.session.jsonl", "--ground-truth", matched); code != want {
		t.Errorf("exit %d with the comparison, %d without", code, want)
	}
}

func sha(t *testing.T, path string) string {
	t.Helper()
	h, err := content.SHA256File(path)
	if err != nil {
		t.Fatal(err)
	}
	return h
}
