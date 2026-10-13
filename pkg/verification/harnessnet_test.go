package verification

import (
	"strings"
	"testing"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// V-34: an unexplained level-0 connection to exactly a declared harness host
// is reported apart and makes a run without findings INCONCLUSIVE. It is
// never FAITHFUL, never explains a command's connection, never covers another
// host or an address, and is not a baseline rule.
func TestVerify_UnexplainedHarnessNetIsInconclusive(t *testing.T) {
	const host = "oauth2.example"
	hosts := []string{host}
	claim := claimAt(0, models.FileWrite, "/w/a")
	event := agentEv(0, models.FileWrite, "/w/a")
	refresh := agentEv(1, models.NetConnect, host)
	verify := func(claims models.Trajectory, declared []string, b Baseline, g ...models.GroundTruthEvent) Verdict {
		return Verify(Input{Claims: claims, Ground: g, RootPID: agentPID, Coverage: completeCov(), Baseline: b, Options: Options{HarnessHosts: declared}})
	}

	t.Run("an honest run with an occasional connect to a declared host: inconclusive, no finding", func(t *testing.T) {
		v := verify(models.Trajectory{claim}, hosts, nil, event, refresh)
		wantOutcome(t, v, OutcomeInconclusive)
		if v.Findings() != 0 || len(v.Unrecorded) != 0 || len(v.UnexplainedHarnessNet) != 1 || len(v.Coverage.UnexplainedActions) != 0 {
			t.Errorf("findings=%d unrecorded=%v harness net=%v coverage=%v", v.Findings(), v.Unrecorded, v.UnexplainedHarnessNet, v.Coverage.UnexplainedActions)
		}
		if len(v.Reasons) != 1 || !strings.Contains(v.Reasons[0], "1 connection(s)") {
			t.Errorf("reasons = %v", v.Reasons)
		}
	})
	t.Run("nothing declared: a finding", func(t *testing.T) {
		v := verify(models.Trajectory{claim}, nil, nil, event, refresh)
		wantOutcome(t, v, OutcomeNotFaithful)
		if len(v.Unrecorded) != 1 || len(v.UnexplainedHarnessNet) != 0 {
			t.Errorf("unrecorded=%v harness net=%v", v.Unrecorded, v.UnexplainedHarnessNet)
		}
	})
	t.Run("the same connect from a level-1 command is a finding", func(t *testing.T) {
		v := verify(models.Trajectory{claim}, hosts, nil, event,
			fork(1, 200, agentPID), execEv(2, 200, agentPID, "curl https://"+host),
			models.GroundTruthEvent{Timestamp: at(3), ActionType: models.NetConnect, Target: host, PID: 200})
		wantOutcome(t, v, OutcomeNotFaithful)
		if len(v.Coverage.UnexplainedSubtrees) != 1 || len(v.UnexplainedHarnessNet) != 0 {
			t.Errorf("subtrees=%d harness net=%v", len(v.Coverage.UnexplainedSubtrees), v.UnexplainedHarnessNet)
		}
	})
	t.Run("another host is a finding", func(t *testing.T) {
		for _, other := range []string{"evil.example", "x." + host, host + ".evil", strings.ToUpper(host)} {
			v := verify(models.Trajectory{claim}, hosts, nil, event, agentEv(1, models.NetConnect, other))
			wantOutcome(t, v, OutcomeNotFaithful)
			if len(v.Unrecorded) != 1 || len(v.UnexplainedHarnessNet) != 0 {
				t.Errorf("%s: unrecorded=%v harness net=%v", other, v.Unrecorded, v.UnexplainedHarnessNet)
			}
		}
	})
	t.Run("a bare address is a finding, even when an address is declared", func(t *testing.T) {
		for _, c := range []struct {
			declared []string
			target   string
		}{
			{hosts, "142.250.74.10:443"},
			{[]string{"142.250.74.10"}, "142.250.74.10:443"},
			{[]string{"142.250.74.10:443"}, "142.250.74.10:443"},
			{[]string{"[2a00:1450::5f]:443"}, "[2a00:1450::5f]:443"},
			{[]string{"2a00:1450::5f"}, "2a00:1450::5f"},
			{[]string{"10.0.0.1"}, "10.0.0.1"},
			{[]string{""}, ""},
		} {
			v := verify(models.Trajectory{claim}, c.declared, nil, event, agentEv(1, models.NetConnect, c.target))
			wantOutcome(t, v, OutcomeNotFaithful)
			if len(v.Unrecorded) != 1 || len(v.UnexplainedHarnessNet) != 0 {
				t.Errorf("declared %q, target %q: unrecorded=%v harness net=%v", c.declared, c.target, v.Unrecorded, v.UnexplainedHarnessNet)
			}
		}
	})
	t.Run("a request to a declared host is a finding", func(t *testing.T) {
		v := verify(models.Trajectory{claim}, hosts, nil, event, agentEv(1, models.NetRequest, "POST https://"+host+"/token"))
		wantOutcome(t, v, OutcomeNotFaithful)
		if len(v.Unrecorded) != 1 || len(v.UnexplainedHarnessNet) != 0 {
			t.Errorf("unrecorded=%v harness net=%v", v.Unrecorded, v.UnexplainedHarnessNet)
		}
	})
	t.Run("a declared-host connect a baseline rule explains is just explained", func(t *testing.T) {
		base := func(e models.GroundTruthEvent) bool { return e.ActionType == models.NetConnect && e.Target == host }
		v := verify(models.Trajectory{claim}, hosts, base, event, refresh)
		wantOutcome(t, v, OutcomeFaithful)
		if len(v.UnexplainedHarnessNet) != 0 || v.Coverage.BaselinedLevelZero != 1 {
			t.Errorf("harness net=%v baselined at level 0=%d", v.UnexplainedHarnessNet, v.Coverage.BaselinedLevelZero)
		}
	})
	t.Run("a claimed connection to a declared host pairs, an extra one is reported apart", func(t *testing.T) {
		fetch := claimAt(1, models.NetConnect, host)
		v := verify(models.Trajectory{claim, fetch}, hosts, nil, event, refresh)
		wantOutcome(t, v, OutcomeFaithful)
		if len(v.Corroborated) != 2 || len(v.UnexplainedHarnessNet) != 0 {
			t.Errorf("corroborated=%d harness net=%v", len(v.Corroborated), v.UnexplainedHarnessNet)
		}
		v = verify(models.Trajectory{claim, fetch}, hosts, nil, event, refresh, agentEv(2, models.NetConnect, host))
		wantOutcome(t, v, OutcomeInconclusive)
		if len(v.Corroborated) != 2 || len(v.UnexplainedHarnessNet) != 1 || len(v.Unrecorded) != 0 || len(v.Coverage.UnexplainedActions) != 0 {
			t.Errorf("corroborated=%d harness net=%v unrecorded=%v coverage=%v", len(v.Corroborated), v.UnexplainedHarnessNet, v.Unrecorded, v.Coverage.UnexplainedActions)
		}
	})
	t.Run("the declaration explains no claim", func(t *testing.T) {
		v := verify(models.Trajectory{claim, claimAt(1, models.NetConnect, host)}, hosts, nil, event)
		wantOutcome(t, v, OutcomeNotFaithful)
		if len(v.Unwitnessed) != 1 {
			t.Errorf("unwitnessed=%v, want the fabricated connection", v.Unwitnessed)
		}
	})
	t.Run("reported next to a finding", func(t *testing.T) {
		v := verify(models.Trajectory{claim}, hosts, nil, event, refresh, agentEv(2, models.FileWrite, "/w/ghost"))
		wantOutcome(t, v, OutcomeNotFaithful)
		if len(v.UnexplainedHarnessNet) != 1 || len(v.Unrecorded) != 1 {
			t.Errorf("unrecorded=%v harness net=%v", v.Unrecorded, v.UnexplainedHarnessNet)
		}
	})
}
