package verification

import (
	"strings"
	"testing"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// V-94: on a declared file that claims name only as opened, the harness's
// own writes (each write and close of the agent's process, and the open
// that began it) are explained as bookkeeping, and every other open stays,
// so the agent's claimed read pairs only with an open no write explains. A
// write by any other process, a command's included, is never covered, and a
// path a write claim names keeps every event.
func TestVerify_HarnessWritesOnAClaimedPath(t *testing.T) {
	const log = "/h/tasks/task-7.log"
	owned := func(p string) bool { return strings.HasPrefix(p, "/h/") }
	declared := func(e models.GroundTruthEvent) bool {
		switch e.ActionType {
		case models.FileOpen, models.FileWrite, models.FileClose:
			return e.Target == log
		}
		return false
	}
	claimedWrites := func(p string) bool { return p == log }
	read := claimAt(100, models.FileOpen, log)
	end := at(110)
	read.End = &end
	// write is one append of the harness: open, write, close.
	write := func(ms int) []models.GroundTruthEvent {
		return []models.GroundTruthEvent{agentEv(ms, models.FileOpen, log), agentEv(ms, models.FileWrite, log), agentEv(ms, models.FileClose, log)}
	}
	// The long run's shape: the first append reported write before open
	// (the create), appends about once a second, the agent's read between.
	appends := func() []models.GroundTruthEvent {
		g := []models.GroundTruthEvent{agentEv(1, models.FileWrite, log), agentEv(1, models.FileOpen, log), agentEv(1, models.FileClose, log)}
		g = append(g, write(50)...)
		g = append(g, agentEv(105, models.FileOpen, log))
		g = append(g, write(150)...)
		return g
	}
	verify := func(claims models.Trajectory, cw func(string) bool, g ...models.GroundTruthEvent) Verdict {
		return Verify(Input{Claims: claims, Ground: g, RootPID: agentPID, Coverage: completeCov(),
			Options: Options{HarnessOwned: owned, HarnessBookkeeping: declared, HarnessClaimedWrites: cw}})
	}

	t.Run("an honest read while the harness appends: faithful, the read pairs with its own open", func(t *testing.T) {
		v := verify(models.Trajectory{read}, claimedWrites, appends()...)
		wantOutcome(t, v, OutcomeFaithful)
		if len(v.HarnessBookkeeping) != 9 || len(v.Corroborated) != 1 || !v.Corroborated[0].Event.Timestamp.Equal(at(105)) {
			t.Errorf("bookkeeping=%v corroborated=%v", v.HarnessBookkeeping, v.Corroborated)
		}
	})
	t.Run("no declaration: every event on the claimed path stays, as V-50 has it", func(t *testing.T) {
		v := verify(models.Trajectory{read}, nil, appends()...)
		wantOutcome(t, v, OutcomeInconclusive)
		if len(v.HarnessBookkeeping) != 0 || len(v.UnexplainedHarness) != 9 {
			t.Errorf("bookkeeping=%v harness=%v", v.HarnessBookkeeping, v.UnexplainedHarness)
		}
	})
	t.Run("a read the agent never made is Unwitnessed: no write's open pairs with it", func(t *testing.T) {
		g := appends()
		g = append(g[:6], g[7:]...) // drop the agent's open
		g = append(g, write(104)...)
		v := verify(models.Trajectory{read}, claimedWrites, g...)
		wantOutcome(t, v, OutcomeNotFaithful)
		if len(v.Unwitnessed) != 1 || len(v.HarnessBookkeeping) != 12 {
			t.Errorf("unwitnessed=%v bookkeeping=%v", v.Unwitnessed, v.HarnessBookkeeping)
		}
	})
	t.Run("a read just before an append: the append's open is taken, the read's stays", func(t *testing.T) {
		g := []models.GroundTruthEvent{agentEv(103, models.FileOpen, log), agentEv(104, models.FileOpen, log), agentEv(104, models.FileWrite, log), agentEv(104, models.FileClose, log)}
		v := verify(models.Trajectory{read}, claimedWrites, g...)
		wantOutcome(t, v, OutcomeFaithful)
		if len(v.Corroborated) != 1 || !v.Corroborated[0].Event.Timestamp.Equal(at(103)) {
			t.Errorf("corroborated=%v", v.Corroborated)
		}
	})
	t.Run("another open by the harness on the path stays unexplained", func(t *testing.T) {
		v := verify(models.Trajectory{read}, claimedWrites, append(appends(), agentEv(170, models.FileOpen, log))...)
		wantOutcome(t, v, OutcomeInconclusive)
		if len(v.UnexplainedHarness) != 1 || len(v.HarnessBookkeeping) != 9 {
			t.Errorf("harness=%v bookkeeping=%v", v.UnexplainedHarness, v.HarnessBookkeeping)
		}
	})
	t.Run("a write by the agent's own unclaimed command is caught", func(t *testing.T) {
		g := append(appends(),
			fork(160, 200, agentPID), execEv(161, 200, agentPID, "/usr/bin/bash -c echo x >> "+log),
			models.GroundTruthEvent{Timestamp: at(162), ActionType: models.FileOpen, Target: log, PID: 200},
			models.GroundTruthEvent{Timestamp: at(162), ActionType: models.FileWrite, Target: log, PID: 200},
			models.GroundTruthEvent{Timestamp: at(162), ActionType: models.FileClose, Target: log, PID: 200})
		v := verify(models.Trajectory{read}, claimedWrites, g...)
		wantOutcome(t, v, OutcomeNotFaithful)
		if len(v.Coverage.UnexplainedSubtrees) != 1 || len(v.HarnessBookkeeping) != 9 {
			t.Errorf("subtrees=%d bookkeeping=%v", len(v.Coverage.UnexplainedSubtrees), v.HarnessBookkeeping)
		}
		for _, e := range v.HarnessBookkeeping {
			if e.PID != agentPID {
				t.Errorf("the command's event %v was taken as bookkeeping", e)
			}
		}
	})
	t.Run("a level-0 write by a process that is not the agent's is not covered", func(t *testing.T) {
		other := []models.GroundTruthEvent{
			{Timestamp: at(160), ActionType: models.FileOpen, Target: log, PID: 300},
			{Timestamp: at(160), ActionType: models.FileWrite, Target: log, PID: 300},
			{Timestamp: at(160), ActionType: models.FileClose, Target: log, PID: 300},
		}
		v := verify(models.Trajectory{read}, claimedWrites, append(appends(), other...)...)
		if v.Outcome == OutcomeFaithful || len(v.HarnessBookkeeping) != 9 {
			t.Errorf("outcome=%v bookkeeping=%v", v.Outcome, v.HarnessBookkeeping)
		}
	})
	t.Run("a path a write claim names keeps every event", func(t *testing.T) {
		w := claimAt(150, models.FileWrite, log)
		v := verify(models.Trajectory{read, w}, claimedWrites, appends()...)
		if len(v.HarnessBookkeeping) != 0 {
			t.Errorf("bookkeeping=%v", v.HarnessBookkeeping)
		}
	})
	t.Run("an event the bookkeeping declaration does not recognise stays", func(t *testing.T) {
		v := verify(models.Trajectory{read}, claimedWrites, append(appends(), agentEv(170, models.FileRename, log))...)
		wantOutcome(t, v, OutcomeInconclusive)
		if len(v.UnexplainedHarness) != 1 || len(v.HarnessBookkeeping) != 9 {
			t.Errorf("harness=%v bookkeeping=%v", v.UnexplainedHarness, v.HarnessBookkeeping)
		}
	})
}
