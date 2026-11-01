package verification

import (
	"testing"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// N-44: a request the probe recorded cut (its body written in a call larger
// than the copy) never confirms a claim, whatever the claim states: the pair
// is corroborated and unverified, so the run is INCONCLUSIVE, never
// FAITHFUL. Unclaimed and undeclared, it is unrecorded like any request.
func TestVerify_ACutRequestNeverConfirmsAClaim(t *testing.T) {
	const target = "POST https://api.example/v1/upload"
	stated := "sha256:aa"
	cut := agentEv(1, models.NetRequest, target)
	cut.RequestCut = true
	write := claimAt(0, models.FileWrite, "/w/a")
	written := agentEv(0, models.FileWrite, "/w/a")
	verify := func(claims models.Trajectory) Verdict {
		return Verify(Input{Claims: claims, Ground: []models.GroundTruthEvent{written, cut}, RootPID: agentPID, Coverage: completeCov()})
	}

	for _, tc := range []struct {
		name string
		hash *string
	}{{"a claim stating the body's hash", &stated}, {"a claim stating no body", nil}} {
		t.Run(tc.name, func(t *testing.T) {
			c := claimAt(1, models.NetRequest, target)
			c.RequestHash = tc.hash
			v := verify(models.Trajectory{write, c})
			wantOutcome(t, v, OutcomeInconclusive)
			if len(v.Unverified) != 1 || len(v.Unverified[0].Diffs) != 1 || v.Unverified[0].Diffs[0] != DiffRequestCut || v.Findings() != 0 {
				t.Errorf("unverified=%+v findings=%d", v.Unverified, v.Findings())
			}
		})
	}
	t.Run("unclaimed: unrecorded", func(t *testing.T) {
		v := verify(models.Trajectory{write})
		wantOutcome(t, v, OutcomeNotFaithful)
		if len(v.Unrecorded) != 1 || !v.Unrecorded[0].RequestCut {
			t.Errorf("unrecorded=%+v", v.Unrecorded)
		}
	})
	t.Run("the same request whole and claimed is faithful", func(t *testing.T) {
		whole := cut
		whole.RequestCut, whole.RequestHash = false, &stated
		c := claimAt(1, models.NetRequest, target)
		c.RequestHash = &stated
		v := Verify(Input{Claims: models.Trajectory{write, c}, Ground: []models.GroundTruthEvent{written, whole}, RootPID: agentPID, Coverage: completeCov()})
		wantOutcome(t, v, OutcomeFaithful)
	})
}

// N-44: housekeeping is recognised by process, target and request shape,
// never by content. A cut request has a body, so a declaration of the target
// with a body explains it, and one without a body does not; a claim of its
// target keeps it in the sequence.
func TestVerify_ACutHousekeepingRequestIsExplainedByItsShape(t *testing.T) {
	const metrics = "POST https://telemetry.example/v1/metrics"
	cut := agentEv(1, models.NetRequest, metrics)
	cut.RequestCut = true
	write := claimAt(0, models.FileWrite, "/w/a")
	written := agentEv(0, models.FileWrite, "/w/a")
	declare := func(body bool) func(models.GroundTruthEvent) bool {
		return func(e models.GroundTruthEvent) bool {
			return e.ActionType == models.NetRequest && e.Target == metrics && (e.RequestHash != nil) == body
		}
	}
	verify := func(claims models.Trajectory, hk func(models.GroundTruthEvent) bool, g ...models.GroundTruthEvent) Verdict {
		return Verify(Input{Claims: claims, Ground: g, RootPID: agentPID, Coverage: completeCov(), Options: Options{HarnessHousekeeping: hk}})
	}

	t.Run("declared with a body: explained, faithful", func(t *testing.T) {
		v := verify(models.Trajectory{write}, declare(true), written, cut)
		wantOutcome(t, v, OutcomeFaithful)
		if len(v.HarnessHousekeeping) != 1 || !v.HarnessHousekeeping[0].RequestCut || v.HarnessHousekeeping[0].RequestHash != nil {
			t.Errorf("housekeeping=%+v", v.HarnessHousekeeping)
		}
	})
	t.Run("declared without a body: a finding", func(t *testing.T) {
		v := verify(models.Trajectory{write}, declare(false), written, cut)
		wantOutcome(t, v, OutcomeNotFaithful)
		if len(v.Unrecorded) != 1 || len(v.HarnessHousekeeping) != 0 {
			t.Errorf("unrecorded=%v housekeeping=%v", v.Unrecorded, v.HarnessHousekeeping)
		}
	})
	t.Run("claimed: kept for the claim, which it does not confirm", func(t *testing.T) {
		v := verify(models.Trajectory{write, claimAt(1, models.NetRequest, metrics)}, declare(true), written, cut)
		wantOutcome(t, v, OutcomeInconclusive)
		if len(v.HarnessHousekeeping) != 0 || len(v.Unverified) != 1 {
			t.Errorf("housekeeping=%v unverified=%v", v.HarnessHousekeeping, v.Unverified)
		}
	})
	t.Run("a baseline rule of its target explains it", func(t *testing.T) {
		b := Baseline(func(e models.GroundTruthEvent) bool { return e.ActionType == models.NetRequest && e.Target == metrics })
		v := Verify(Input{Claims: models.Trajectory{write}, Ground: []models.GroundTruthEvent{written, cut}, RootPID: agentPID, Coverage: completeCov(), Baseline: b})
		wantOutcome(t, v, OutcomeFaithful)
	})
}
