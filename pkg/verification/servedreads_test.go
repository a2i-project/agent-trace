package verification

import (
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// V-100: a level-0 open of a file the adapter declares the harness reads
// while serving a claim of one kind, inside the interval of such a claim,
// that no baseline rule explains and whose path no claim names, is
// explained: listed apart, neither a finding nor a reason for INCONCLUSIVE.
// The same open outside every such interval, by a command, beside a claim of
// another kind, beside a harness-implied claim, or on a path a claim names
// keeps its reading.
func TestVerify_DeclaredServedReadIsExplained(t *testing.T) {
	const (
		host = "example.com"
		gai  = "/etc/gai.conf"
	)
	fetch := func(from, to int) models.TrajectoryEntry {
		c := claimAt(from, models.NetConnect, host)
		c.Tool = "webfetch"
		end := at(to)
		c.End = &end
		return c
	}
	// The synthetic declaration, as agent.HarnessServedReads builds it: the
	// file for a webfetch's connection.
	served := func(c models.TrajectoryEntry) []string {
		if c.ActionType == models.NetConnect && c.Tool == "webfetch" && c.ImpliedBy == "" {
			return []string{gai}
		}
		return nil
	}
	verify := func(claims models.Trajectory, s func(models.TrajectoryEntry) []string, b Baseline, g ...models.GroundTruthEvent) Verdict {
		return Verify(Input{Claims: claims, Ground: g, RootPID: agentPID, Coverage: completeCov(), Baseline: b,
			Options: Options{HarnessServedReads: s}})
	}
	connect := agentEv(20, models.NetConnect, host)
	read := agentEv(15, models.FileOpen, gai)

	t.Run("an honest webfetch: faithful, the read listed", func(t *testing.T) {
		v := verify(models.Trajectory{fetch(10, 30)}, served, nil, read, connect)
		wantOutcome(t, v, OutcomeFaithful)
		if len(v.HarnessServedReads) != 1 || v.HarnessServedReads[0].Target != gai || v.Findings() != 0 ||
			len(v.Coverage.UnexplainedActions) != 0 || len(v.Reasons) != 0 {
			t.Errorf("served=%v findings=%d coverage=%v reasons=%v", v.HarnessServedReads, v.Findings(), v.Coverage.UnexplainedActions, v.Reasons)
		}
	})
	t.Run("nothing declared: the read is unrecorded, as before", func(t *testing.T) {
		v := verify(models.Trajectory{fetch(10, 30)}, nil, nil, read, connect)
		wantOutcome(t, v, OutcomeNotFaithful)
		if len(v.Unrecorded) != 1 || v.Unrecorded[0].Target != gai || len(v.HarnessServedReads) != 0 {
			t.Errorf("unrecorded=%v served=%v", v.Unrecorded, v.HarnessServedReads)
		}
	})
	t.Run("a read outside every webfetch's interval is a finding", func(t *testing.T) {
		v := verify(models.Trajectory{fetch(10, 30)}, served, nil, read, connect, agentEv(40, models.FileOpen, gai))
		wantOutcome(t, v, OutcomeNotFaithful)
		if len(v.Unrecorded) != 1 || !v.Unrecorded[0].Timestamp.Equal(at(40)) || len(v.HarnessServedReads) != 1 {
			t.Errorf("unrecorded=%v served=%v", v.Unrecorded, v.HarnessServedReads)
		}
	})
	t.Run("the interval is widened by the slack, as alignment's", func(t *testing.T) {
		v := Verify(Input{Claims: models.Trajectory{fetch(10, 30)}, Ground: models.GroundTruth{connect, agentEv(34, models.FileOpen, gai)},
			RootPID: agentPID, Coverage: completeCov(), Options: Options{HarnessServedReads: served, IntervalSlack: 5 * time.Millisecond}})
		wantOutcome(t, v, OutcomeFaithful)
		if len(v.HarnessServedReads) != 1 {
			t.Errorf("served=%v", v.HarnessServedReads)
		}
	})
	t.Run("a command's read inside the interval is not the harness's", func(t *testing.T) {
		cmd := models.GroundTruthEvent{Timestamp: at(16), ActionType: models.FileOpen, Target: gai, PID: 200}
		v := verify(models.Trajectory{fetch(10, 30)}, served, nil,
			fork(12, 200, agentPID), execEv(13, 200, agentPID, "/bin/cat /etc/gai.conf"), cmd, connect)
		wantOutcome(t, v, OutcomeNotFaithful)
		if len(v.HarnessServedReads) != 0 || len(v.Unrecorded) != 1 || v.Unrecorded[0].ActionType != models.ProcessExec {
			t.Errorf("served=%v unrecorded=%v", v.HarnessServedReads, v.Unrecorded)
		}
	})
	t.Run("a claim of another kind serves nothing", func(t *testing.T) {
		other := fetch(10, 30)
		other.Tool = "bash"
		v := verify(models.Trajectory{other}, served, nil, read, connect)
		wantOutcome(t, v, OutcomeNotFaithful)
		if len(v.HarnessServedReads) != 0 || len(v.Unrecorded) != 1 {
			t.Errorf("served=%v unrecorded=%v", v.HarnessServedReads, v.Unrecorded)
		}
	})
	t.Run("a harness-implied claim serves nothing", func(t *testing.T) {
		implied := fetch(10, 30)
		implied.ImpliedBy = "webfetch https://example.com"
		v := verify(models.Trajectory{implied}, func(models.TrajectoryEntry) []string { return []string{gai} }, nil, read, connect)
		if len(v.HarnessServedReads) != 0 {
			t.Errorf("served=%v", v.HarnessServedReads)
		}
	})
	t.Run("a claim without an end serves nothing", func(t *testing.T) {
		open := fetch(10, 30)
		open.End = nil
		v := verify(models.Trajectory{open}, served, nil, read, connect)
		wantOutcome(t, v, OutcomeNotFaithful)
		if len(v.HarnessServedReads) != 0 || len(v.Unrecorded) != 1 {
			t.Errorf("served=%v unrecorded=%v", v.HarnessServedReads, v.Unrecorded)
		}
	})
	t.Run("on a path a claim names the read stays for the claim", func(t *testing.T) {
		v := verify(models.Trajectory{fetch(10, 30), claimAt(14, models.FileOpen, gai)}, served, nil, read, connect)
		wantOutcome(t, v, OutcomeFaithful)
		if len(v.HarnessServedReads) != 0 || len(v.Corroborated) != 2 {
			t.Errorf("served=%v corroborated=%v", v.HarnessServedReads, v.Corroborated)
		}
	})
	t.Run("a read the baseline explains is baselined, not listed", func(t *testing.T) {
		b := func(e models.GroundTruthEvent) bool { return e.Target == gai }
		v := verify(models.Trajectory{fetch(10, 30)}, served, b, read, connect)
		wantOutcome(t, v, OutcomeFaithful)
		if len(v.HarnessServedReads) != 0 {
			t.Errorf("served=%v", v.HarnessServedReads)
		}
	})
	t.Run("an ambiguous or truncated path is not taken", func(t *testing.T) {
		amb := agentEv(16, models.FileOpen, gai)
		amb.PathIsAmbiguous = true
		cut := agentEv(17, models.FileOpen, gai)
		cut.TargetTruncated = true
		v := verify(models.Trajectory{fetch(10, 30)}, served, nil, amb, cut, connect)
		if len(v.HarnessServedReads) != 0 || len(v.Unrecorded) != 2 {
			t.Errorf("served=%v unrecorded=%v", v.HarnessServedReads, v.Unrecorded)
		}
	})
}
