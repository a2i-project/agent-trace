package verification

import (
	"testing"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// probeCmd stands for a command the adapter declares as the harness's own.
const probeCmd = "/usr/bin/sh -c uname -s"

// declaredExec recognises the exec of probeCmd, as agent.HarnessCommand does
// for the execs the harness itself made.
func declaredExec(e models.GroundTruthEvent) bool {
	return e.ActionType == models.ProcessExec && e.Target == probeCmd
}

// probeRecord is the controls' record of what probeCmd did beneath it.
func probeRecord(command, e models.GroundTruthEvent) bool {
	return command.Target == probeCmd && e.ActionType == models.ProcessExec && e.Target == "/usr/bin/uname -s"
}

// An occasional harness command no rule explains and no claim names is
// reported apart and makes the run INCONCLUSIVE, never a finding and never
// FAITHFUL; its subtree is explained only where it is what the controls' same
// command did (V-43).
func TestVerify_UnexplainedHarnessCommandIsInconclusive(t *testing.T) {
	probe := func(pid uint32, beneath ...models.GroundTruthEvent) models.GroundTruth {
		g := models.GroundTruth{
			fork(10, pid, agentPID), execEv(11, pid, agentPID, probeCmd),
			fork(12, pid+1, pid), execEv(13, pid+1, pid, "/usr/bin/uname -s"), exitEv(14, pid+1, pid, "/usr/bin/uname -s"),
		}
		g = append(g, beneath...)
		return append(g, exitEv(20, pid, agentPID, probeCmd))
	}
	claimed := models.GroundTruth{fork(1, 200, agentPID), execEv(2, 200, agentPID, "/bin/ls"), exitEv(3, 200, agentPID, "/bin/ls")}
	ls := claimsFor("/bin/ls")
	verify := func(claims models.Trajectory, g models.GroundTruth, sub SubtreeBaseline, recognise func(models.GroundTruthEvent) bool, b Baseline) Verdict {
		return Verify(Input{Claims: claims, Ground: g, RootPID: agentPID, Coverage: completeCov(),
			Baseline: b, BaselineSubtree: sub, Options: Options{HarnessCommand: recognise}})
	}
	with := func(g ...models.GroundTruth) models.GroundTruth {
		var out models.GroundTruth
		for _, x := range g {
			out = append(out, x...)
		}
		return out
	}

	t.Run("its subtree is what the controls did", func(t *testing.T) {
		v := verify(ls, with(claimed, probe(300)), probeRecord, declaredExec, nil)
		wantOutcome(t, v, OutcomeInconclusive)
		if v.Findings() != 0 || len(v.UnexplainedHarnessCommands) != 1 || !v.UnexplainedHarnessCommands[0].Harness || len(v.Corroborated) != 2 {
			t.Errorf("findings %d, harness commands %d, corroborated %d; want 0, 1, 2", v.Findings(), len(v.UnexplainedHarnessCommands), len(v.Corroborated))
		}
	})
	t.Run("it never makes a run FAITHFUL", func(t *testing.T) {
		if v := verify(ls, with(claimed, probe(300)), probeRecord, declaredExec, nil); v.Faithful {
			t.Error("FAITHFUL over an unexplained harness command")
		}
	})
	t.Run("a program, a write or a connection beneath it the controls never made is a finding", func(t *testing.T) {
		for _, extra := range []models.GroundTruthEvent{
			execEv(15, 301, 300, "/usr/bin/curl http://evil"),
			fsEv(15, 301, "/w/payload"),
			{Timestamp: at(15), ActionType: models.NetConnect, Target: "evil.example", PID: 300},
		} {
			v := verify(ls, with(claimed, probe(300, extra)), probeRecord, declaredExec, nil)
			wantOutcome(t, v, OutcomeNotFaithful)
			if len(v.Coverage.UnexplainedSubtrees) != 1 || len(v.Coverage.UnexplainedSubtrees[0].Unbaselined) != 1 || len(v.Unrecorded) != 0 {
				t.Errorf("%s: unexplained subtrees %d, unrecorded %v; want the probe's subtree with the one extra event", extra.ActionType, len(v.Coverage.UnexplainedSubtrees), v.Unrecorded)
			}
		}
	})
	t.Run("a read beneath it is not checked, as beneath a baselined command", func(t *testing.T) {
		read := models.GroundTruthEvent{Timestamp: at(15), ActionType: models.FileOpen, Target: "/etc/os-release", PID: 301}
		wantOutcome(t, verify(ls, with(claimed, probe(300, read)), probeRecord, declaredExec, nil), OutcomeInconclusive)
	})
	t.Run("without a record of the controls, its subtree is unexplained", func(t *testing.T) {
		v := verify(ls, with(claimed, probe(300)), nil, declaredExec, nil)
		wantOutcome(t, v, OutcomeNotFaithful)
		if v.Findings() != 1 || len(v.UnexplainedHarnessCommands) != 1 {
			t.Errorf("findings %d, harness commands %d; want the subtree as the one finding", v.Findings(), len(v.UnexplainedHarnessCommands))
		}
	})
	t.Run("a command the agent claims by that command line is aligned as any other", func(t *testing.T) {
		claims := append(claimsFor("/bin/ls"), claimAt(11, models.ProcessExec, probeCmd), claimAt(20, models.ProcessExit, probeCmd))
		v := verify(claims, with(claimed, probe(300)), probeRecord, declaredExec, nil)
		wantOutcome(t, v, OutcomeFaithful)
		if len(v.UnexplainedHarnessCommands) != 0 || len(v.Corroborated) != 4 {
			t.Errorf("harness commands %d, corroborated %d; want none and the claimed probe paired", len(v.UnexplainedHarnessCommands), len(v.Corroborated))
		}
		// The claim names it, so a second occurrence is the agent's to explain.
		v = verify(claims, with(claimed, probe(300), probe(400)), probeRecord, declaredExec, nil)
		if v.Outcome != OutcomeNotFaithful || len(v.UnexplainedHarnessCommands) != 0 {
			t.Errorf("outcome %s, harness commands %d; want the unclaimed second occurrence a finding", v.Outcome, len(v.UnexplainedHarnessCommands))
		}
	})
	t.Run("an exec the declaration does not recognise is the agent's", func(t *testing.T) {
		// The same command line, made by the agent's own shell call: the
		// adapter recognises only the harness's exec of it.
		v := verify(ls, with(claimed, probe(300)), probeRecord, func(models.GroundTruthEvent) bool { return false }, nil)
		wantOutcome(t, v, OutcomeNotFaithful)
		if len(v.Unrecorded) != 2 || len(v.Coverage.UnexplainedSubtrees) != 1 {
			t.Errorf("unrecorded %v, unexplained subtrees %d; want the exec and the exit and the subtree", v.Unrecorded, len(v.Coverage.UnexplainedSubtrees))
		}
	})
	t.Run("only a command's own exec, at level 1", func(t *testing.T) {
		// The command line beneath a claimed command is that command's content.
		g := with(claimed, models.GroundTruth{fork(5, 201, 200), execEv(6, 201, 200, probeCmd)})
		v := verify(ls, g, probeRecord, declaredExec, nil)
		wantOutcome(t, v, OutcomeFaithful)
		// A second exec of a level-1 process is content too, even when it is
		// the declared command line.
		g = models.GroundTruth{fork(1, 200, agentPID), execEv(2, 200, agentPID, "/bin/ls"), execEv(3, 200, agentPID, probeCmd)}
		v = verify(nil, g, probeRecord, declaredExec, nil)
		if len(v.UnexplainedHarnessCommands) != 0 || len(v.Unrecorded) != 1 {
			t.Errorf("harness commands %d, unrecorded %v; want the command's first exec unrecorded", len(v.UnexplainedHarnessCommands), v.Unrecorded)
		}
	})
	t.Run("a truncated exec is never set apart", func(t *testing.T) {
		g := probe(300)
		g[1].TargetTruncated = true
		v := verify(nil, g, probeRecord, func(models.GroundTruthEvent) bool { return true }, nil)
		if len(v.UnexplainedHarnessCommands) != 0 || v.Outcome != OutcomeNotFaithful {
			t.Errorf("outcome %s, harness commands %d; want a truncated exec read as any command", v.Outcome, len(v.UnexplainedHarnessCommands))
		}
	})
	t.Run("a rule explains it as before", func(t *testing.T) {
		rule := func(e models.GroundTruthEvent) bool {
			return e.ActionType == models.ProcessExec && e.Target == probeCmd
		}
		v := verify(ls, with(claimed, probe(300)), probeRecord, declaredExec, rule)
		wantOutcome(t, v, OutcomeFaithful)
		if len(v.UnexplainedHarnessCommands) != 0 || !v.Commands[1].Baseline {
			t.Errorf("harness commands %d; want the command baselined, not reported apart", len(v.UnexplainedHarnessCommands))
		}
	})
	t.Run("it witnesses no harness-implied claim", func(t *testing.T) {
		open := models.GroundTruthEvent{Timestamp: at(16), ActionType: models.FileOpen, Target: "/w/f", PID: 301}
		openAgent := agentEv(21, models.FileOpen, "/w/f")
		implied := claimAt(21, models.FileOpen, "/w/f")
		implied.ImpliedBy = probeCmd
		v := verify(append(claimsFor("/bin/ls"), implied), with(claimed, probe(300, open), models.GroundTruth{openAgent}), probeRecord, declaredExec, nil)
		if len(v.HarnessImplied) != 0 || len(v.Unrecorded) != 1 {
			t.Errorf("harness implied %v, unrecorded %v; want the open unrecorded", v.HarnessImplied, v.Unrecorded)
		}
	})
}
