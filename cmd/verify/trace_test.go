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

const codexBasic = "../../pkg/agent/codex/testdata/paired-codex-0.166.0-basic/"

// --session-id names the session whose files are the trace (I-110): with
// the id the record states the verdict is the one without it, plus the
// line naming it; for a rollout that is gone it narrows the declaration to
// the session's rollout, where without it every rollout the capture
// observed is declared; an id other than the record's decides and is
// reported; Claude Code's trace depends on it as well (V-81).
func TestSessionIDFromTheCaptureDecidesTheTrace(t *testing.T) {
	const thread = "01a19455-d74e-72a2-99d3-367c07be5a85"
	g := codexBasic + "basic.ground_truth.json"
	dir := t.TempDir()
	_, plain, _ := verify(t, "--agent", "codex", "--trajectory", codexBasic+"basic.rollout.jsonl", "--ground-truth", g)
	js := filepath.Join(dir, "v.json")
	code, out, errOut := verify(t, "--agent", "codex", "--trajectory", codexBasic+"basic.rollout.jsonl", "--ground-truth", g, "--session-id", thread, "--json", js)
	line := "session id:   " + thread + " (recorded by the capture; it decides the trace, I-110)\n"
	if errOut != "" || strings.Replace(out, line, "", 1) != plain || !strings.Contains(out, line) {
		t.Fatalf("exit %d, stderr %q; with the record's own id the report should only gain the line:\n%s", code, errOut, out)
	}
	var rep struct {
		SessionID string                   `json:"session_id"`
		Trace     *verification.TraceCheck `json:"trace"`
	}
	data, _ := os.ReadFile(js)
	if err := json.Unmarshal(data, &rep); err != nil || rep.SessionID != thread {
		t.Errorf("JSON session_id %q, err %v", rep.SessionID, err)
	}

	gone := filepath.Join(dir, "gone.rollout.jsonl")
	files := func(args ...string) int {
		t.Helper()
		js := filepath.Join(dir, "gone.json")
		if code, _, errOut := verify(t, append([]string{"--agent", "codex", "--trajectory", gone, "--ground-truth", g, "--json", js}, args...)...); code != 2 || errOut != "" {
			t.Fatalf("exit %d, stderr %q", code, errOut)
		}
		rep.Trace = nil
		data, _ := os.ReadFile(js)
		if err := json.Unmarshal(data, &rep); err != nil || rep.Trace == nil {
			t.Fatalf("JSON trace %+v, err %v", rep.Trace, err)
		}
		return len(rep.Trace.Files)
	}
	if n := files(); n != 4 {
		t.Errorf("without the id, %d rollouts declared and observed, want the session's and three others", n)
	}
	if n := files("--session-id", thread); n != 1 {
		t.Errorf("with the id, %d rollouts declared and observed, want the session's only", n)
	}

	const other = "00000000-0000-0000-0000-000000000001"
	_, out, _ = verify(t, "--agent", "codex", "--trajectory", codexBasic+"basic.rollout.jsonl", "--ground-truth", g, "--session-id", other)
	if !strings.Contains(out, "limitation: the session's record states id "+thread+", the capture recorded "+other+": the capture's id decides the trace (I-110)") {
		t.Errorf("a differing id is not reported:\n%s", out)
	}
	_, out, _ = verify(t, "--agent", "claude-code", "--trajectory", tools306+"tools.session.jsonl", "--ground-truth", tools306+"tools.ground_truth.json", "--session-id", thread)
	// Claude Code's trace narrows to the session too (V-81).
	if !strings.Contains(out, "session id:   "+thread+" (recorded by the capture; it decides the trace, I-110)\n") {
		t.Errorf("Claude Code's report lacks the line:\n%s", out)
	}
}
