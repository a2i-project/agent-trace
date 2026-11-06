package verification

import (
	"strings"
	"testing"

	"github.com/agent-trace/agent-trace/pkg/models"
)

func withImage(e models.GroundTruthEvent) models.GroundTruthEvent {
	prog, _, _ := strings.Cut(e.Target, " ")
	e.Image = &models.ExecImage{Filename: prog, Program: prog}
	return e
}

// I-157: an imageless exec whose process's next event is an exec of the
// same program name and arguments from another directory, in a run that
// ends in an exec with an image, is a failed attempt of a PATH search. It
// is no command's exec and no program run beneath one; it goes to
// Partition.Attempts. Without the image at the end (a capture before P-36,
// or a different search) every exec stays as it was.
func TestAFailedPathSearchAttemptIsNoExec(t *testing.T) {
	const args = " remote -v"
	search := func(last func(models.GroundTruthEvent) models.GroundTruthEvent, dirs ...string) models.GroundTruth {
		g := models.GroundTruth{fork(1, 200, agentPID)}
		for i, d := range dirs {
			e := execEv(2+i, 200, agentPID, d+"/git"+args)
			if i == len(dirs)-1 {
				e = last(e)
			}
			g = append(g, e)
		}
		// A descendant's search of echo, as a login shell's systemd-cat
		// runs it.
		g = append(g, fork(10, 201, 200),
			withImage(execEv(11, 201, 200, "/usr/bin/systemd-cat -p 6 -t im-config echo hi")),
			execEv(12, 201, 200, "/home/u/.local/bin/echo hi"),
			last(execEv(13, 201, 200, "/usr/bin/echo hi")))
		return g
	}
	same := func(e models.GroundTruthEvent) models.GroundTruthEvent { return e }
	cases := []struct {
		name     string
		g        models.GroundTruth
		exec     string
		content  []string
		attempts []string
	}{
		{"the measured search", search(withImage, "/home/u/.codex/tmp/arg0", "/usr/local/bin", "/usr/bin"),
			"/usr/bin/git" + args,
			[]string{"/usr/bin/systemd-cat -p 6 -t im-config echo hi", "/usr/bin/echo hi"},
			[]string{"/home/u/.codex/tmp/arg0/git" + args, "/usr/local/bin/git" + args, "/home/u/.local/bin/echo hi"}},
		{"no image at all, as before P-36", search(same, "/home/u/.codex/tmp/arg0", "/usr/local/bin", "/usr/bin"),
			"/home/u/.codex/tmp/arg0/git" + args,
			[]string{"/usr/local/bin/git" + args, "/usr/bin/git" + args, "/usr/bin/systemd-cat -p 6 -t im-config echo hi", "/home/u/.local/bin/echo hi", "/usr/bin/echo hi"},
			nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := BuildForest(tc.g, agentPID)
			p := f.Partition(tc.g)
			if len(p.Commands) != 1 || p.Commands[0].Exec == nil || p.Commands[0].Exec.Target != tc.exec {
				t.Fatalf("command exec = %v, want %q", p.Commands[0].Exec, tc.exec)
			}
			if pr := f.Resolve(200, at(20)); pr == nil || pr.Exec == nil || pr.Exec.Target != tc.exec {
				t.Errorf("forest exec = %v, want %q", pr, tc.exec)
			}
			var content, attempts []string
			for _, e := range p.Commands[0].Content {
				content = append(content, e.Target)
			}
			for _, a := range p.Attempts {
				attempts = append(attempts, a.Event.Target)
				if a.Command != p.Commands[0].Process {
					t.Errorf("attempt %q is not attributed to the command", a.Event.Target)
				}
			}
			if strings.Join(content, "|") != strings.Join(tc.content, "|") {
				t.Errorf("content = %q, want %q", content, tc.content)
			}
			if strings.Join(attempts, "|") != strings.Join(tc.attempts, "|") {
				t.Errorf("attempts = %q, want %q", attempts, tc.attempts)
			}
		})
	}
}

// I-157: what is not a failed attempt of a PATH search: an imageless exec
// followed by an exec with an image of another program, other arguments,
// the same path, a relative path, or with another event of the process
// between.
func TestOnlyASameSearchEndingInAnImageIsAnAttempt(t *testing.T) {
	cases := []struct {
		name string
		g    models.GroundTruth
	}{
		{"another program", models.GroundTruth{execEv(2, 200, agentPID, "/a/git x"), withImage(execEv(3, 200, agentPID, "/b/gitx x"))}},
		{"other arguments", models.GroundTruth{execEv(2, 200, agentPID, "/a/git x"), withImage(execEv(3, 200, agentPID, "/b/git y"))}},
		{"the same path", models.GroundTruth{execEv(2, 200, agentPID, "/a/git x"), withImage(execEv(3, 200, agentPID, "/a/git x"))}},
		{"a relative path", models.GroundTruth{execEv(2, 200, agentPID, "a/git x"), withImage(execEv(3, 200, agentPID, "/b/git x"))}},
		{"an event between", models.GroundTruth{execEv(2, 200, agentPID, "/a/git x"), fsEv(3, 200, "/w/f"), withImage(execEv(4, 200, agentPID, "/b/git x"))}},
		{"a truncated exec", models.GroundTruth{func() models.GroundTruthEvent {
			e := execEv(2, 200, agentPID, "/a/git x")
			e.TargetTruncated = true
			return e
		}(), withImage(execEv(3, 200, agentPID, "/b/git x"))}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := append(models.GroundTruth{fork(1, 200, agentPID)}, tc.g...)
			p := BuildForest(g, agentPID).Partition(g)
			if len(p.Attempts) != 0 || p.Commands[0].Exec.Target != tc.g[0].Target {
				t.Errorf("attempts = %v, exec = %q, want none and %q", p.Attempts, p.Commands[0].Exec.Target, tc.g[0].Target)
			}
		})
	}
}
