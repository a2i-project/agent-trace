package verification_test

import (
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/agent/claudecode"
	"github.com/agent-trace/agent-trace/pkg/agent/codex"
	"github.com/agent-trace/agent-trace/pkg/agent/gemini"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// The read rule (V-75) holds for every adapter's declared trace alike: a
// command that opens a covered file and closes it without writing it read
// it, and a command that writes or deletes it tampered with it.
func TestTrace_TheReadRuleHoldsOnEveryAdaptersTrace(t *testing.T) {
	const (
		root = 100
		cmd  = "/bin/sh -c inspect"
		id   = "0b18d7d3-41b4-4dfe-b649-e8ba776c383a"
	)
	t0 := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	ev := func(ms int, typ models.ActionType, target string, pid uint32) models.GroundTruthEvent {
		return models.GroundTruthEvent{Timestamp: t0.Add(time.Duration(ms) * time.Millisecond), ActionType: typ, Target: target, PID: pid, PPID: root}
	}
	traces := map[string]struct {
		decl *verification.TraceDecl
		path string
	}{
		"Claude Code transcript": {claudecode.Adapter{}.Trace("/ws/task", "/home/u"), "/home/u/.claude/projects/-ws-task/" + id + ".jsonl"},
		"Claude Code subagent":   {claudecode.Adapter{}.Trace("/ws/task", "/home/u"), "/home/u/.claude/projects/-ws-task/" + id + "/subagents/agent-a1.jsonl"},
		"Codex rollout":          {codex.Adapter{}.Trace("", "/home/u"), "/home/u/.codex/sessions/2026/11/01/rollout-2026-11-01T12-00-00-" + id + ".jsonl"},
		"Codex thread database":  {codex.Adapter{}.Trace("", "/home/u"), "/home/u/.codex/state_5.sqlite"},
		"agy conversation":       {gemini.Adapter{}.Trace("", "/home/u"), "/home/u/.gemini/antigravity-cli/conversations/" + id + ".db"},
		"agy session database":   {gemini.Adapter{}.SessionTrace("", "/home/u", id), "/home/u/.gemini/antigravity-cli/conversations/" + id + ".db"},
	}
	for name, tr := range traces {
		if tr.decl == nil || !tr.decl.Covers(tr.path) {
			t.Fatalf("%s: %s is not covered", name, tr.path)
		}
		for shape, c := range map[string]struct {
			events []models.GroundTruthEvent
			want   int
		}{
			"a read":            {[]models.GroundTruthEvent{ev(20, models.FileOpen, tr.path, 200), ev(21, models.FileClose, tr.path, 200)}, 0},
			"a write":           {[]models.GroundTruthEvent{ev(20, models.FileOpen, tr.path, 200), ev(21, models.FileWrite, tr.path, 200), ev(22, models.FileClose, tr.path, 200)}, 2},
			"a delete":          {[]models.GroundTruthEvent{ev(20, models.FileDelete, tr.path, 200)}, 1},
			"a read and delete": {[]models.GroundTruthEvent{ev(20, models.FileOpen, tr.path, 200), ev(21, models.FileClose, tr.path, 200), ev(22, models.FileDelete, tr.path, 200)}, 1},
		} {
			t.Run(name+"/"+shape, func(t *testing.T) {
				g := models.GroundTruth{
					{Timestamp: t0.Add(10 * time.Millisecond), ActionType: models.ProcessFork, Target: "x", PID: 200, PPID: root},
					{Timestamp: t0.Add(11 * time.Millisecond), ActionType: models.ProcessExec, Target: cmd, PID: 200, PPID: root},
				}
				g = append(g, c.events...)
				g = append(g, models.GroundTruthEvent{Timestamp: t0.Add(90 * time.Millisecond), ActionType: models.ProcessExit, Target: cmd, PID: 200, PPID: root})
				v := verification.Verify(verification.Input{Ground: g, RootPID: root, Trace: verification.TraceInput{Decl: tr.decl}})
				if len(v.TraceTampering) != c.want {
					t.Errorf("tampering %d events, want %d: %+v", len(v.TraceTampering), c.want, v.TraceTampering)
				}
			})
		}
	}
}
