package verification

import (
	"testing"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// exitCode is an exit event with its code.
func exitCode(ms int, pid, ppid uint32, target string, code int32) models.GroundTruthEvent {
	e := exitEv(ms, pid, ppid, target)
	e.ExitCode = &code
	return e
}

// exitClaim is a claimed exit with its code, or none for nil.
func exitClaim(ms int, target string, code *int32) models.TrajectoryEntry {
	c := claimAt(ms, models.ProcessExit, target)
	c.ExitCode = code
	return c
}

func i32(v int32) *int32 { return &v }

// A shell that execs its last command exits under that command's image
// (P-31). The exit claim names what the agent ran, which is the shell's
// command line; it is compared with the exit of the process the shell's exec
// started, so it is corroborated, not a substitution (V-44). A wrong exit
// code is still a mismatch, an exit claimed for a process that did not exit
// is still unwitnessed, and an exit that names another command is still a
// substitution.
func TestVerify_AnExitIsTheExitOfTheProcessItsExecStarted(t *testing.T) {
	const shell = "/bin/sh -c cd /w && exec cat a"
	twice := models.GroundTruth{
		fork(1, 200, agentPID), execEv(2, 200, agentPID, shell),
		execEv(3, 200, agentPID, "/usr/bin/cat a"), // the shell execs its last command
		exitCode(4, 200, agentPID, "/usr/bin/cat a", 0),
	}
	for _, c := range []struct {
		name   string
		claims models.Trajectory
		ground models.GroundTruth
		want   Outcome
		check  func(t *testing.T, v Verdict)
	}{
		{"the exit of a process that exec'd twice is corroborated", models.Trajectory{
			claimAt(2, models.ProcessExec, shell), exitClaim(4, shell, i32(0)),
		}, twice, OutcomeFaithful, func(t *testing.T, v Verdict) {
			if len(v.Corroborated) != 2 || v.Corroborated[1].Event.Target != shell {
				t.Errorf("corroborated %v, want the exec and the exit, the exit under the shell's command line", v.Corroborated)
			}
			if c := v.Commands[0]; c.Exit == nil || c.Exit.Target != "/usr/bin/cat a" || len(c.Content) != 1 {
				t.Errorf("command %+v: the forensic record keeps the exit as observed and the second exec as content", c)
			}
		}},
		{"a wrong exit code is a mismatch", models.Trajectory{
			claimAt(2, models.ProcessExec, shell), exitClaim(4, shell, i32(1)),
		}, twice, OutcomeNotFaithful, func(t *testing.T, v Verdict) {
			if len(v.Mismatched) != 1 || len(v.Mismatched[0].Diffs) != 1 || v.Mismatched[0].Diffs[0] != DiffExitCode {
				t.Errorf("mismatched %v, want one exit_code difference", v.Mismatched)
			}
		}},
		{"an exit the format could state and the claim omits is a mismatch", models.Trajectory{
			claimAt(2, models.ProcessExec, shell), exitClaim(4, shell, nil),
		}, twice, OutcomeNotFaithful, func(t *testing.T, v Verdict) {
			if len(v.Mismatched) != 1 || v.Mismatched[0].Diffs[0] != DiffExitCode {
				t.Errorf("mismatched %v, want the opted-out exit code", v.Mismatched)
			}
		}},
		{"an exit claimed for a process that did not exit is unwitnessed", models.Trajectory{
			claimAt(2, models.ProcessExec, shell), exitClaim(4, shell, i32(0)),
		}, twice[:3], OutcomeNotFaithful, func(t *testing.T, v Verdict) {
			if len(v.Unwitnessed) != 1 || v.Unwitnessed[0].ActionType != models.ProcessExit || len(v.Mismatched) != 0 {
				t.Errorf("unwitnessed %v, mismatched %v; want the exit claim unwitnessed", v.Unwitnessed, v.Mismatched)
			}
		}},
		{"an exit claim naming another command is a substitution", models.Trajectory{
			claimAt(2, models.ProcessExec, shell), exitClaim(4, "/usr/bin/cat a", i32(0)),
		}, twice, OutcomeNotFaithful, func(t *testing.T, v Verdict) {
			if len(v.Mismatched) != 1 || v.Mismatched[0].Diffs[0] != DiffTarget {
				t.Errorf("mismatched %v, want a target substitution", v.Mismatched)
			}
		}},
		{"the exit of another process does not answer the claim", models.Trajectory{
			claimAt(2, models.ProcessExec, shell), exitClaim(4, shell, i32(0)),
			claimAt(5, models.ProcessExec, "/bin/true"),
		}, models.GroundTruth{
			fork(1, 200, agentPID), execEv(2, 200, agentPID, shell), execEv(3, 200, agentPID, "/usr/bin/cat a"),
			fork(5, 201, agentPID), execEv(5, 201, agentPID, "/bin/true"), exitCode(6, 201, agentPID, "/bin/true", 0),
		}, OutcomeNotFaithful, func(t *testing.T, v Verdict) {
			if v.Findings() == 0 || len(v.Corroborated) != 2 {
				t.Errorf("findings %d, corroborated %v; want the two execs corroborated and the shell's exit claim a finding", v.Findings(), v.Corroborated)
			}
			for _, p := range v.Corroborated {
				if p.Event.ActionType == models.ProcessExit {
					t.Errorf("an exit claim corroborated by another process's exit: %+v", p)
				}
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			v := run(c.claims, c.ground)
			wantOutcome(t, v, c.want)
			c.check(t, v)
		})
	}
}

// The rewrite keeps the observed sequence of its input and touches only an
// owned exit whose target differs from its command's exec.
func TestPartition_ExitsByProcessCopiesAndKeepsTheRest(t *testing.T) {
	g := models.GroundTruth{
		fork(1, 200, agentPID), execEv(2, 200, agentPID, "/bin/sh -c x"), execEv(3, 200, agentPID, "/bin/x"),
		exitEv(4, 200, agentPID, "/bin/x"),
		fork(5, 201, agentPID), execEv(6, 201, agentPID, "/bin/y"), exitEv(7, 201, agentPID, "/bin/y"),
		exitEv(8, agentPID, 1, "/usr/bin/agent"),
	}
	part := BuildForest(g, agentPID).Partition(g)
	got := part.ExitsByProcess()
	var exits []string
	for _, e := range got.Observed {
		if e.ActionType == models.ProcessExit {
			exits = append(exits, e.Target)
		}
	}
	if len(exits) != 3 || exits[0] != "/bin/sh -c x" || exits[1] != "/bin/y" || exits[2] != "/usr/bin/agent" {
		t.Errorf("exits %v, want the shell's under its exec, the other unchanged, the level-0 one unchanged", exits)
	}
	for _, e := range part.Observed {
		if e.ActionType == models.ProcessExit && e.Target == "/bin/sh -c x" {
			t.Error("the input partition was changed")
		}
	}
}
