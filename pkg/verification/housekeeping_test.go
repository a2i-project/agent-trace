package verification

import (
	"testing"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// V-54: a level-0 connection or request that the adapter's housekeeping
// declaration recognises, that no baseline rule explains and whose target no
// claim names, is explained: listed apart, neither a finding nor a reason for
// INCONCLUSIVE. The same action by a command, on a claimed target, or with a
// truncated target keeps its reading.
func TestVerify_DeclaredHarnessHousekeepingIsExplained(t *testing.T) {
	const (
		host    = "auth.example"
		renew   = "POST https://auth.example/v1/token"
		profile = "GET https://api.example/profile"
	)
	body := "sha256:00"
	// The synthetic declaration: the connection, the POST with a body and
	// the GET with none, as agent.HarnessHousekeeping builds it.
	declared := func(e models.GroundTruthEvent) bool {
		switch e.ActionType {
		case models.NetConnect:
			return e.Target == host
		case models.NetRequest:
			return (e.Target == renew && e.RequestHash != nil) || (e.Target == profile && e.RequestHash == nil)
		}
		return false
	}
	claim := claimAt(0, models.FileWrite, "/w/a")
	event := agentEv(0, models.FileWrite, "/w/a")
	post := agentEv(2, models.NetRequest, renew)
	post.RequestHash = &body
	// With request content: the connection and both requests.
	content := []models.GroundTruthEvent{agentEv(1, models.NetConnect, host), post, agentEv(3, models.NetRequest, profile)}
	verify := func(claims models.Trajectory, hk func(models.GroundTruthEvent) bool, b Baseline, g ...models.GroundTruthEvent) Verdict {
		return Verify(Input{Claims: claims, Ground: g, RootPID: agentPID, Coverage: completeCov(), Baseline: b,
			Options: Options{HarnessHousekeeping: hk}})
	}
	with := func(extra ...models.GroundTruthEvent) []models.GroundTruthEvent {
		return append(append([]models.GroundTruthEvent{event}, content...), extra...)
	}

	t.Run("an honest run with the renewal: faithful, the events listed", func(t *testing.T) {
		v := verify(models.Trajectory{claim}, declared, nil, with()...)
		wantOutcome(t, v, OutcomeFaithful)
		if len(v.HarnessHousekeeping) != len(content) || v.Findings() != 0 || len(v.Coverage.UnexplainedActions) != 0 || len(v.Reasons) != 0 {
			t.Errorf("housekeeping=%v findings=%d coverage=%v reasons=%v", v.HarnessHousekeeping, v.Findings(), v.Coverage.UnexplainedActions, v.Reasons)
		}
	})
	t.Run("without request content only the connection, explained alone", func(t *testing.T) {
		v := verify(models.Trajectory{claim}, declared, nil, event, content[0])
		wantOutcome(t, v, OutcomeFaithful)
		if len(v.HarnessHousekeeping) != 1 || v.HarnessHousekeeping[0].Target != host {
			t.Errorf("housekeeping=%v", v.HarnessHousekeeping)
		}
	})
	t.Run("nothing declared: three unrecorded findings, as before", func(t *testing.T) {
		v := verify(models.Trajectory{claim}, nil, nil, with()...)
		wantOutcome(t, v, OutcomeNotFaithful)
		if len(v.Unrecorded) != len(content) || len(v.HarnessHousekeeping) != 0 {
			t.Errorf("unrecorded=%v housekeeping=%v", v.Unrecorded, v.HarnessHousekeeping)
		}
	})
	t.Run("another request to the declared host is a finding", func(t *testing.T) {
		v := verify(models.Trajectory{claim}, declared, nil, with(
			agentEv(4, models.NetRequest, "GET https://auth.example/v1/token"),
			agentEv(5, models.NetRequest, renew+"?x=1"),
			agentEv(6, models.NetRequest, "GET https://auth.example/docs"))...)
		wantOutcome(t, v, OutcomeNotFaithful)
		if len(v.Unrecorded) != 3 || len(v.HarnessHousekeeping) != len(content) {
			t.Errorf("unrecorded=%v housekeeping=%v", v.Unrecorded, v.HarnessHousekeeping)
		}
	})
	t.Run("a declared request with the wrong body shape is a finding", func(t *testing.T) {
		bare := agentEv(4, models.NetRequest, renew)
		withBody := agentEv(5, models.NetRequest, profile)
		withBody.RequestHash = &body
		v := verify(models.Trajectory{claim}, declared, nil, with(bare, withBody)...)
		wantOutcome(t, v, OutcomeNotFaithful)
		if len(v.Unrecorded) != 2 || len(v.HarnessHousekeeping) != len(content) {
			t.Errorf("unrecorded=%v housekeeping=%v", v.Unrecorded, v.HarnessHousekeeping)
		}
	})
	t.Run("a truncated target is not taken", func(t *testing.T) {
		cut := agentEv(4, models.NetConnect, host)
		cut.TargetTruncated = true
		v := verify(models.Trajectory{claim}, declared, nil, with(cut)...)
		wantOutcome(t, v, OutcomeNotFaithful)
		if len(v.Unrecorded) != 1 || len(v.HarnessHousekeeping) != len(content) {
			t.Errorf("unrecorded=%v housekeeping=%v", v.Unrecorded, v.HarnessHousekeeping)
		}
	})
	t.Run("the same requests by a command are a finding", func(t *testing.T) {
		cmdPost := models.GroundTruthEvent{Timestamp: at(3), ActionType: models.NetRequest, Target: renew, PID: 200, RequestHash: &body}
		v := verify(models.Trajectory{claim}, declared, nil, event,
			fork(1, 200, agentPID), execEv(2, 200, agentPID, "curl -X POST https://auth.example/v1/token"),
			models.GroundTruthEvent{Timestamp: at(3), ActionType: models.NetConnect, Target: host, PID: 200}, cmdPost)
		wantOutcome(t, v, OutcomeNotFaithful)
		if len(v.Coverage.UnexplainedSubtrees) != 1 || len(v.HarnessHousekeeping) != 0 {
			t.Errorf("subtrees=%d housekeeping=%v", len(v.Coverage.UnexplainedSubtrees), v.HarnessHousekeeping)
		}
	})
	t.Run("a claimed target pairs, and the declaration explains no claim", func(t *testing.T) {
		connect := claimAt(1, models.NetConnect, host)
		v := verify(models.Trajectory{claim, connect}, declared, nil, with()...)
		wantOutcome(t, v, OutcomeFaithful)
		if len(v.Corroborated) != 2 || len(v.HarnessHousekeeping) != len(content)-1 {
			t.Errorf("corroborated=%d housekeeping=%v", len(v.Corroborated), v.HarnessHousekeeping)
		}
		v = verify(models.Trajectory{claim, connect}, declared, nil, event)
		wantOutcome(t, v, OutcomeNotFaithful)
		if len(v.Unwitnessed) != 1 {
			t.Errorf("unwitnessed=%v, want the fabricated connection", v.Unwitnessed)
		}
	})
	t.Run("a declared event on a claimed target that stays unpaired is unrecorded", func(t *testing.T) {
		connect := claimAt(1, models.NetConnect, host)
		v := verify(models.Trajectory{claim, connect}, declared, nil, with(agentEv(4, models.NetConnect, host))...)
		wantOutcome(t, v, OutcomeNotFaithful)
		if len(v.Unrecorded) != 1 || v.Unrecorded[0].Target != host {
			t.Errorf("unrecorded=%v housekeeping=%v", v.Unrecorded, v.HarnessHousekeeping)
		}
		for _, e := range v.HarnessHousekeeping {
			if e.Target == host {
				t.Errorf("housekeeping took %v on a claimed target", e)
			}
		}
	})
	t.Run("an event a baseline rule explains stays baselined", func(t *testing.T) {
		base := func(e models.GroundTruthEvent) bool { return e.Target == host }
		v := verify(models.Trajectory{claim}, declared, base, with()...)
		wantOutcome(t, v, OutcomeFaithful)
		if len(v.HarnessHousekeeping) != len(content)-1 || v.Coverage.BaselinedLevelZero != 1 {
			t.Errorf("housekeeping=%v baselined at level 0=%d", v.HarnessHousekeeping, v.Coverage.BaselinedLevelZero)
		}
	})
	t.Run("listed next to a finding, which it does not hide", func(t *testing.T) {
		v := verify(models.Trajectory{claim}, declared, nil, with(agentEv(4, models.NetConnect, "evil.example"))...)
		wantOutcome(t, v, OutcomeNotFaithful)
		if len(v.Unrecorded) != 1 || len(v.HarnessHousekeeping) != len(content) {
			t.Errorf("unrecorded=%v housekeeping=%v", v.Unrecorded, v.HarnessHousekeeping)
		}
	})
}
