package verification

import (
	"strings"
	"testing"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// V-50: a level-0 event on a file the adapter declares as the harness's own
// bookkeeping, under its declared directories, that no baseline rule
// explains and no claim names, is explained: listed apart, neither a finding
// nor a reason for INCONCLUSIVE. Anything else on or near the file keeps its
// reading.
func TestVerify_DeclaredHarnessBookkeepingIsExplained(t *testing.T) {
	const (
		dir  = "/h/state/locks/"
		lock = dir + "9.9.9.lock"
		tmp  = lock + ".tmp.0123abcd"
	)
	owned := func(p string) bool { return strings.HasPrefix(p, "/h/") }
	// The synthetic declaration: the lock and its temporary, any file kind.
	declared := func(e models.GroundTruthEvent) bool { return e.Target == lock || e.Target == tmp }
	claim := claimAt(0, models.FileWrite, "/w/a")
	event := agentEv(0, models.FileWrite, "/w/a")
	// The third long pilot's shape: the temporary's rename reported before
	// its open, write and close, then the rename onto the lock.
	refresh := []models.GroundTruthEvent{
		agentEv(1, models.FileWrite, tmp), agentEv(2, models.FileRename, tmp),
		agentEv(3, models.FileOpen, tmp), agentEv(4, models.FileWrite, tmp),
		agentEv(5, models.FileClose, tmp), agentEv(6, models.FileRename, lock),
	}
	verify := func(claims models.Trajectory, bk func(models.GroundTruthEvent) bool, b Baseline, g ...models.GroundTruthEvent) Verdict {
		return Verify(Input{Claims: claims, Ground: g, RootPID: agentPID, Coverage: completeCov(), Baseline: b,
			Options: Options{HarnessOwned: owned, HarnessBookkeeping: bk}})
	}
	with := func(extra ...models.GroundTruthEvent) []models.GroundTruthEvent {
		return append(append([]models.GroundTruthEvent{event}, refresh...), extra...)
	}

	t.Run("an honest run with the refresh: faithful, the events listed", func(t *testing.T) {
		v := verify(models.Trajectory{claim}, declared, nil, with()...)
		wantOutcome(t, v, OutcomeFaithful)
		if len(v.HarnessBookkeeping) != len(refresh) || len(v.UnexplainedHarness) != 0 || v.Findings() != 0 || len(v.Coverage.UnexplainedActions) != 0 || len(v.Reasons) != 0 {
			t.Errorf("bookkeeping=%v harness=%v findings=%d coverage=%v reasons=%v", v.HarnessBookkeeping, v.UnexplainedHarness, v.Findings(), v.Coverage.UnexplainedActions, v.Reasons)
		}
	})
	t.Run("nothing declared: unexplained harness activity, as before", func(t *testing.T) {
		v := verify(models.Trajectory{claim}, nil, nil, with()...)
		wantOutcome(t, v, OutcomeInconclusive)
		if len(v.UnexplainedHarness) != len(refresh) || len(v.HarnessBookkeeping) != 0 {
			t.Errorf("harness=%v bookkeeping=%v", v.UnexplainedHarness, v.HarnessBookkeeping)
		}
	})
	t.Run("a declaration outside the harness's directories explains nothing", func(t *testing.T) {
		out := "/w/9.9.9.lock"
		v := verify(models.Trajectory{claim}, func(e models.GroundTruthEvent) bool { return e.Target == out }, nil, event, agentEv(1, models.FileWrite, out))
		wantOutcome(t, v, OutcomeNotFaithful)
		if len(v.Unrecorded) != 1 || len(v.HarnessBookkeeping) != 0 {
			t.Errorf("unrecorded=%v bookkeeping=%v", v.Unrecorded, v.HarnessBookkeeping)
		}
	})
	t.Run("another file in the directory stays unexplained harness activity", func(t *testing.T) {
		v := verify(models.Trajectory{claim}, declared, nil, with(agentEv(7, models.FileWrite, dir+"9.9.8.lock"), agentEv(8, models.FileWrite, dir))...)
		wantOutcome(t, v, OutcomeInconclusive)
		if len(v.UnexplainedHarness) != 2 || len(v.HarnessBookkeeping) != len(refresh) {
			t.Errorf("harness=%v bookkeeping=%v", v.UnexplainedHarness, v.HarnessBookkeeping)
		}
	})
	t.Run("an ambiguous or truncated event naming the file is not taken", func(t *testing.T) {
		amb := agentEv(7, models.FileWrite, lock)
		amb.PathIsAmbiguous = true
		cut := agentEv(8, models.FileWrite, lock)
		cut.TargetTruncated = true
		v := verify(models.Trajectory{claim}, declared, nil, with(amb, cut)...)
		wantOutcome(t, v, OutcomeInconclusive)
		if len(v.UnexplainedHarness) != 2 || len(v.HarnessBookkeeping) != len(refresh) {
			t.Errorf("harness=%v bookkeeping=%v", v.UnexplainedHarness, v.HarnessBookkeeping)
		}
	})
	t.Run("the same write by a command is a finding", func(t *testing.T) {
		v := verify(models.Trajectory{claim}, declared, nil, event,
			fork(1, 200, agentPID), execEv(2, 200, agentPID, "sh -c 'echo x > "+lock+"'"),
			models.GroundTruthEvent{Timestamp: at(3), ActionType: models.FileWrite, Target: lock, PID: 200})
		wantOutcome(t, v, OutcomeNotFaithful)
		if len(v.Coverage.UnexplainedSubtrees) != 1 || len(v.HarnessBookkeeping) != 0 {
			t.Errorf("subtrees=%d bookkeeping=%v", len(v.Coverage.UnexplainedSubtrees), v.HarnessBookkeeping)
		}
	})
	t.Run("a claimed write of the lock pairs, and the declaration explains no claim", func(t *testing.T) {
		write := claimAt(6, models.FileRename, lock)
		v := verify(models.Trajectory{claim, write}, declared, nil, with()...)
		wantOutcome(t, v, OutcomeFaithful)
		if len(v.Corroborated) != 2 || len(v.HarnessBookkeeping) != len(refresh)-1 {
			t.Errorf("corroborated=%d bookkeeping=%v", len(v.Corroborated), v.HarnessBookkeeping)
		}
		v = verify(models.Trajectory{claim, write}, declared, nil, event)
		wantOutcome(t, v, OutcomeNotFaithful)
		if len(v.Unwitnessed) != 1 {
			t.Errorf("unwitnessed=%v, want the fabricated write", v.Unwitnessed)
		}
	})
	t.Run("an event on a claimed path that stays unpaired is unexplained harness activity", func(t *testing.T) {
		v := verify(models.Trajectory{claim, claimAt(1, models.FileOpen, lock)}, declared, nil, with(agentEv(7, models.FileDelete, lock))...)
		if len(v.UnexplainedHarness) == 0 {
			t.Errorf("harness=%v bookkeeping=%v, want the claimed path's events kept out of the declaration", v.UnexplainedHarness, v.HarnessBookkeeping)
		}
		for _, e := range v.HarnessBookkeeping {
			if e.Target == lock {
				t.Errorf("bookkeeping took %v on a claimed path", e)
			}
		}
	})
	t.Run("an event a baseline rule explains stays baselined", func(t *testing.T) {
		base := func(e models.GroundTruthEvent) bool { return e.Target == lock }
		v := verify(models.Trajectory{claim}, declared, base, with()...)
		wantOutcome(t, v, OutcomeFaithful)
		if len(v.HarnessBookkeeping) != len(refresh)-1 || v.Coverage.BaselinedLevelZero != 1 {
			t.Errorf("bookkeeping=%v baselined at level 0=%d", v.HarnessBookkeeping, v.Coverage.BaselinedLevelZero)
		}
	})
	t.Run("listed next to a finding, which it does not hide", func(t *testing.T) {
		v := verify(models.Trajectory{claim}, declared, nil, with(agentEv(7, models.FileWrite, "/w/ghost"))...)
		wantOutcome(t, v, OutcomeNotFaithful)
		if len(v.Unrecorded) != 1 || len(v.HarnessBookkeeping) != len(refresh) {
			t.Errorf("unrecorded=%v bookkeeping=%v", v.Unrecorded, v.HarnessBookkeeping)
		}
	})
}
