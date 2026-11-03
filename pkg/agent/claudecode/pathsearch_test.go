package claudecode

import (
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// The shape I-128 recognises, synthetic: no capture of a Claude Code build
// that searches with rg from PATH exists yet. The harness (pid 100) forks
// 101, whose PATH lookup fails in ~/.local/bin and runs /usr/bin/rg in the
// session's directory with a Grep's arguments and no --no-config.
const (
	pathGrepArgs = "--hidden --glob !.git -l --null seed ."
	pathGlobArgs = "--files --null --glob *.txt --sort=modified --no-ignore --hidden ."
	usrRg        = "/usr/bin/rg"
	localRg      = "/home/u/.local/bin/rg"
)

var pathT0 = time.Unix(1000, 0)

func pathAt(ms int) time.Time { return pathT0.Add(time.Duration(ms) * time.Millisecond) }

func rgImage(p string) *models.ExecImage { return &models.ExecImage{Filename: p, Program: p} }

// harnessRg is a search the harness runs: a fork of the agent's process, the
// failed attempts given, then the exec of prog that took effect, and its exit.
func harnessRg(pid uint32, ms int, prog, args string, img *models.ExecImage, failed ...string) models.GroundTruth {
	g := models.GroundTruth{{Timestamp: pathAt(ms), ActionType: models.ProcessFork, Target: "", PID: pid, PPID: 100}}
	for i, f := range failed {
		g = append(g, models.GroundTruthEvent{Timestamp: pathAt(ms + 1 + i), ActionType: models.ProcessExec, Target: f + " " + args, PID: pid, PPID: 100, Cwd: "/ws"})
	}
	n := ms + 1 + len(failed)
	g = append(g,
		models.GroundTruthEvent{Timestamp: pathAt(n), ActionType: models.ProcessExec, Target: prog + " " + args, PID: pid, PPID: 100, Cwd: "/ws", Image: img},
		models.GroundTruthEvent{Timestamp: pathAt(n + 5), ActionType: models.ProcessExit, Target: prog + " " + args, PID: pid, PPID: 100, ExitCode: new(int32)},
	)
	return g
}

func pathCapture(events models.GroundTruth) models.GroundTruthFile {
	return models.GroundTruthFile{
		RootPID: 100, Workspace: "/ws",
		Coverage: &models.Coverage{Schema: models.CoverageSchema, Probes: map[string]models.ProbeCoverage{"fs": {Ran: true}, "proc": {Ran: true}}},
		Events:   events,
	}
}

// I-128: which processes are the harness's search through rg from PATH.
// Only a child of the agent's process whose first exec that took effect is
// a file named rg, with a search's arguments, after nothing but failed rg
// attempts with the same arguments, takes the search's target; everything
// else keeps its command line.
func TestPathSearchesRecogniseOnlyTheHarnesssRg(t *testing.T) {
	bash := "/bin/bash -c source /home/u/.claude/shell-snapshots/snapshot-bash-1-ab.sh 2>/dev/null || true && eval 'rg seed .' < /dev/null && pwd -P >| /tmp/claude-1a2b-cwd"
	inPlace := models.GroundTruth{
		{Timestamp: pathAt(0), ActionType: models.ProcessFork, PID: 101, PPID: 100},
		{Timestamp: pathAt(1), ActionType: models.ProcessExec, Target: bash, PID: 101, PPID: 100, Cwd: "/ws", Image: rgImage("/usr/bin/bash")},
		{Timestamp: pathAt(2), ActionType: models.ProcessExec, Target: usrRg + " " + pathGrepArgs, PID: 101, PPID: 100, Cwd: "/ws", Image: rgImage(usrRg)},
	}
	underBash := models.GroundTruth{
		{Timestamp: pathAt(0), ActionType: models.ProcessFork, PID: 101, PPID: 100},
		{Timestamp: pathAt(1), ActionType: models.ProcessExec, Target: bash, PID: 101, PPID: 100, Cwd: "/ws", Image: rgImage("/usr/bin/bash")},
		{Timestamp: pathAt(2), ActionType: models.ProcessFork, PID: 102, PPID: 101},
		{Timestamp: pathAt(3), ActionType: models.ProcessExec, Target: usrRg + " " + pathGrepArgs, PID: 102, PPID: 101, Cwd: "/ws", Image: rgImage(usrRg)},
	}
	linked := &models.ExecImage{Filename: usrRg, Program: "/usr/bin/dash"}
	script := &models.ExecImage{Filename: usrRg, Program: "/usr/bin/rg", Interpreter: "/bin/sh"}
	cut := &models.ExecImage{Filename: usrRg, Program: "bin/rg", Truncated: true}
	for name, tc := range map[string]struct {
		g    models.GroundTruth
		root uint32
		// want is the target of every exec of the search process after
		// normalization (its exit's is the kind alone), "" for unchanged.
		want string
		pid  uint32
	}{
		"grep":                              {harnessRg(101, 0, usrRg, pathGrepArgs, rgImage(usrRg)), 100, SearchGrep + " /ws", 101},
		"glob":                              {harnessRg(101, 0, usrRg, pathGlobArgs, rgImage(usrRg)), 100, SearchGlob + " /ws", 101},
		"after the PATH lookup":             {harnessRg(101, 0, usrRg, pathGrepArgs, rgImage(usrRg), localRg, "/opt/bin/rg"), 100, SearchGrep + " /ws", 101},
		"the harness's own listing":         {harnessRg(101, 0, usrRg, "--files --hidden /ws", rgImage(usrRg)), 100, "", 101},
		"no root":                           {harnessRg(101, 0, usrRg, pathGrepArgs, rgImage(usrRg)), 0, "", 101},
		"another program named in argv":     {harnessRg(101, 0, "/ws/rg", pathGrepArgs, linked), 100, "", 101},
		"a link to another program":         {harnessRg(101, 0, usrRg, pathGrepArgs, linked), 100, "", 101},
		"a script named rg":                 {harnessRg(101, 0, usrRg, pathGrepArgs, script), 100, "", 101},
		"a cut record":                      {harnessRg(101, 0, usrRg, pathGrepArgs, cut), 100, "", 101},
		"no exec took effect":               {harnessRg(101, 0, usrRg, pathGrepArgs, nil), 100, "", 101},
		"another program tried first":       {harnessRg(101, 0, usrRg, pathGrepArgs, rgImage(usrRg), "/home/u/.local/bin/grep"), 100, "", 101},
		"another program named rg relative": {harnessRg(101, 0, "rg", pathGrepArgs, rgImage(usrRg)), 100, "", 101},
		"rg exec'd by Bash in place":        {inPlace, 100, "", 101},
		"rg run by Bash":                    {underBash, 100, "", 102},
	} {
		t.Run(name, func(t *testing.T) {
			got := agent.NormalizeCapture(Adapter{}, models.GroundTruthFile{RootPID: tc.root, Events: tc.g})
			raw := agent.NormalizeGround(Adapter{}, tc.g)
			for i, e := range got {
				if e.PID != tc.pid || (e.ActionType != models.ProcessExec && e.ActionType != models.ProcessExit) {
					continue
				}
				want := raw[i].Target
				if tc.want != "" {
					want = tc.want
					if e.ActionType == models.ProcessExit {
						// An exit records no working directory, so its
						// folder is unknown, as for the native search.
						want = strings.Join(strings.Fields(tc.want)[:2], " ")
					}
				}
				if e.ActionType == models.ProcessExec && e.Image != nil && e.Image.Program == "/usr/bin/bash" {
					want = raw[i].Target
				}
				if e.Target != want {
					t.Errorf("event %d (%s) = %q, want %q", i, e.ActionType, e.Target, want)
				}
			}
		})
	}
}

// End to end through agent.Prepare: a Grep and a Glob through rg from PATH
// are corroborated on their folder, a search of another folder is a
// mismatch, and an rg run through Bash pairs with the Bash claim only, so a
// Grep claimed for it is Unwitnessed.
func TestAPathSearchVerifiesEndToEnd(t *testing.T) {
	g := pathCapture(append(harnessRg(101, 1000, usrRg, pathGrepArgs, rgImage(usrRg), localRg),
		harnessRg(102, 2000, usrRg, pathGlobArgs, rgImage(usrRg))...))
	claims := models.Trajectory{
		{Timestamp: pathAt(1000), ActionType: models.ProcessExec, Target: SearchGrep + " /ws", Tool: toolGrep},
		{Timestamp: pathAt(2000), ActionType: models.ProcessExec, Target: SearchGlob + " /ws", Tool: toolGlob},
	}
	v := verification.Verify(agent.Prepare(Adapter{}, claims, g, nil, verification.Options{}))
	if v.Outcome != verification.OutcomeFaithful || len(v.Corroborated) != 2 {
		t.Fatalf("honest: %s, corroborated %d, reasons %v, unrecorded %v", v.Outcome, len(v.Corroborated), v.Reasons, v.Unrecorded)
	}

	other := append(models.Trajectory(nil), claims...)
	other[0].Target = SearchGrep + " /elsewhere"
	if v := verification.Verify(agent.Prepare(Adapter{}, other, g, nil, verification.Options{})); v.Outcome != verification.OutcomeNotFaithful || len(v.Mismatched) != 1 {
		t.Errorf("another folder: %s, mismatched %v, want one mismatch", v.Outcome, v.Mismatched)
	}

	// Bash runs rg: the Bash claim pairs with its wrapper, and a Grep
	// claimed beside it has no search to pair with.
	cmd := "rg seed ."
	wrapper := "/bin/bash -c source /home/u/.claude/shell-snapshots/snapshot-bash-1700000000-ab12cd.sh 2>/dev/null || true && shopt -u extglob 2>/dev/null || true && eval '" + cmd + "' < /dev/null && pwd -P >| /tmp/claude-1a2b-cwd"
	bg := pathCapture(models.GroundTruth{
		{Timestamp: pathAt(1000), ActionType: models.ProcessFork, PID: 101, PPID: 100},
		{Timestamp: pathAt(1001), ActionType: models.ProcessExec, Target: wrapper, PID: 101, PPID: 100, Cwd: "/ws", Image: rgImage("/usr/bin/bash")},
		{Timestamp: pathAt(1002), ActionType: models.ProcessFork, PID: 102, PPID: 101},
		{Timestamp: pathAt(1003), ActionType: models.ProcessExec, Target: usrRg + " " + pathGrepArgs, PID: 102, PPID: 101, Cwd: "/ws", Image: rgImage(usrRg)},
	})
	bashClaim := models.Trajectory{{Timestamp: pathAt(1000), ActionType: models.ProcessExec, Target: cmd, Tool: toolBash}}
	if v := verification.Verify(agent.Prepare(Adapter{}, bashClaim, bg, nil, verification.Options{})); v.Outcome != verification.OutcomeFaithful {
		t.Errorf("Bash's rg: %s %v", v.Outcome, v.Reasons)
	}
	withGrep := append(bashClaim, models.TrajectoryEntry{Timestamp: pathAt(1000), ActionType: models.ProcessExec, Target: SearchGrep + " /ws", Tool: toolGrep})
	if v := verification.Verify(agent.Prepare(Adapter{}, withGrep, bg, nil, verification.Options{})); v.Outcome != verification.OutcomeNotFaithful || len(v.Unwitnessed) != 1 {
		t.Errorf("a Grep claimed for Bash's rg: %s, unwitnessed %v, want it Unwitnessed", v.Outcome, v.Unwitnessed)
	}
}
