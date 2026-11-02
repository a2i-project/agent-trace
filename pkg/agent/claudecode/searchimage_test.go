package claudecode

import (
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// I-107: with the agent's program recorded (P-46), a search is a run of that
// program wherever it is installed; a copy of it elsewhere, a native-path
// binary that is not the agent's, and an exec whose kernel record names
// another program are not searches. An exit, which carries no image, is
// recognised by its command line. Without a usable record, I-27's
// install-directory check decides.
func TestASearchIsARunOfTheAgentsOwnProgram(t *testing.T) {
	const (
		npm    = "/usr/lib/node_modules/@anthropic-ai/claude-code/bin/claude"
		native = "/home/user/.local/share/claude/versions/2.1.306"
		grep   = " --no-config --hidden --glob !.git -l --null seed ."
		glob   = " --no-config --files --null --glob *.txt --sort=modified --no-ignore --hidden ."
	)
	img := func(p string) *models.ExecImage { return &models.ExecImage{Filename: p, Program: p} }
	ev := func(typ models.ActionType, line string, image *models.ExecImage) models.GroundTruthEvent {
		return models.GroundTruthEvent{ActionType: typ, Target: line, Image: image}
	}
	for name, tc := range map[string]struct {
		agent *models.ExecImage
		e     models.GroundTruthEvent
		want  string
	}{
		"grep, another layout":                  {img(npm), ev(models.ProcessExec, npm+grep, img(npm)), SearchGrep},
		"glob, another layout":                  {img(npm), ev(models.ProcessExec, npm+glob, img(npm)), SearchGlob},
		"its exit":                              {img(npm), ev(models.ProcessExit, npm+grep, nil), SearchGrep},
		"the native layout":                     {img(native), ev(models.ProcessExec, native+grep, img(native)), SearchGrep},
		"harness listing kept":                  {img(npm), ev(models.ProcessExec, npm+" --no-config --files --hidden /ws", img(npm)), ""},
		"a copy in the workspace":               {img(npm), ev(models.ProcessExec, "/ws/claude"+grep, img("/ws/claude")), ""},
		"a native binary that is not the agent": {img(npm), ev(models.ProcessExec, native+grep, img(native)), ""},
		"the agent's path, another program":     {img(npm), ev(models.ProcessExec, npm+grep, img("/ws/evil")), ""},
		"no --no-config":                        {img(npm), ev(models.ProcessExec, npm+" --hidden -l --null seed .", img(npm)), ""},
		"no record, native path (I-27)":         {nil, ev(models.ProcessExec, native+grep, nil), SearchGrep},
		"no record, another layout (I-27)":      {nil, ev(models.ProcessExec, npm+grep, img(npm)), ""},
		"a cut record (I-27)":                   {&models.ExecImage{Program: "claude-code/bin/claude", Truncated: true}, ev(models.ProcessExec, native+grep, nil), SearchGrep},
	} {
		t.Run(name, func(t *testing.T) {
			a := Adapter{}.WithAgentImage(tc.agent)
			got, keep := a.Normalize(tc.e)
			want := tc.want
			if want == "" {
				want = canonicalIDs(tc.e.Target)
			}
			if !keep || got.Target != want {
				t.Errorf("Normalize(%q) = %q, want %q", tc.e.Target, got.Target, want)
			}
		})
	}
}

// End to end through agent.Prepare: a Grep claim on a capture whose agent
// runs from an npm layout is corroborated by the search the capture's
// root_image names, and the same capture without root_image leaves it an
// unrecorded command and an unwitnessed claim (I-27 does not know the path).
func TestASearchFromAnotherLayoutVerifiesWithTheRecordedImage(t *testing.T) {
	const npm = "/usr/lib/node_modules/@anthropic-ai/claude-code/bin/claude"
	t0 := time.Unix(1000, 0)
	line := npm + " --no-config --hidden --glob !.git -l --null seed ."
	g := models.GroundTruthFile{
		RootPID: 100, Workspace: "/ws",
		RootImage: &models.ExecImage{Filename: npm, Program: npm},
		Coverage:  &models.Coverage{Schema: models.CoverageSchema, Probes: map[string]models.ProbeCoverage{"fs": {Ran: true}, "proc": {Ran: true}}},
		Events: models.GroundTruth{
			{Timestamp: t0.Add(time.Second), ActionType: models.ProcessFork, Target: "101", PID: 101, PPID: 100},
			{Timestamp: t0.Add(time.Second + 1), ActionType: models.ProcessExec, Target: line, PID: 101, PPID: 100, Image: &models.ExecImage{Filename: npm, Program: npm}, Cwd: "/ws"},
			{Timestamp: t0.Add(time.Second + 2), ActionType: models.ProcessExit, Target: line, PID: 101, PPID: 100, ExitCode: new(int32)},
		},
	}
	claims := models.Trajectory{{Timestamp: t0.Add(time.Second), ActionType: models.ProcessExec, Target: SearchGrep + " /ws", Tool: toolGrep}}
	v := verification.Verify(agent.Prepare(Adapter{}, claims, g, nil, verification.Options{}))
	if v.Outcome != verification.OutcomeFaithful {
		t.Fatalf("with root_image: %s %v", v.Outcome, v.Reasons)
	}
	g.RootImage = nil
	v = verification.Verify(agent.Prepare(Adapter{}, claims, g, nil, verification.Options{}))
	if v.Outcome != verification.OutcomeNotFaithful {
		t.Errorf("without root_image: %s, want NOT FAITHFUL (the search is not recognised)", v.Outcome)
	}
}

// I-111: a Grep whose path is written "~/..." searches under the home the
// capture resolved "~/" against, so with the home recorded its claim
// verifies on the observed folder; without it the folder stays unknown and
// reads as a mismatch, the limit I-108 stated. A "~user" path and other
// claims are left as written.
func TestAGrepOfAHomePathVerifiesWithTheRecordedHome(t *testing.T) {
	const bin = "/home/u/.local/share/claude/versions/2.1.306"
	t0 := time.Unix(1000, 0)
	line := bin + " --no-config --hidden -l --null seed ."
	g := models.GroundTruthFile{
		RootPID: 100, Workspace: "/ws",
		Sensitive: &models.SensitiveSnapshot{Home: "/home/u"},
		Coverage:  &models.Coverage{Schema: models.CoverageSchema, Probes: map[string]models.ProbeCoverage{"fs": {Ran: true}, "proc": {Ran: true}}},
		Events: models.GroundTruth{
			{Timestamp: t0.Add(time.Second), ActionType: models.ProcessFork, Target: "101", PID: 101, PPID: 100},
			{Timestamp: t0.Add(time.Second + 1), ActionType: models.ProcessExec, Target: line, PID: 101, PPID: 100, Cwd: "/home/u/notes"},
			{Timestamp: t0.Add(time.Second + 2), ActionType: models.ProcessExit, Target: line, PID: 101, PPID: 100, ExitCode: new(int32)},
		},
	}
	claims := models.Trajectory{{Timestamp: t0.Add(time.Second), ActionType: models.ProcessExec, Target: SearchGrep + " ~/notes", Tool: toolGrep}}
	v := verification.Verify(agent.Prepare(Adapter{}, claims, g, nil, verification.Options{}))
	if v.Outcome != verification.OutcomeFaithful {
		t.Fatalf("with the home recorded: %s %v", v.Outcome, v.Reasons)
	}
	if claims[0].Target != SearchGrep+" ~/notes" {
		t.Errorf("Prepare changed the caller's claims: %q", claims[0].Target)
	}
	g.Sensitive = nil
	v = verification.Verify(agent.Prepare(Adapter{}, claims, g, nil, verification.Options{}))
	if v.Outcome != verification.OutcomeNotFaithful || len(v.Mismatched) != 1 {
		t.Errorf("without the home: %s, mismatched %v, want the stated mismatch", v.Outcome, v.Mismatched)
	}

	for _, c := range []struct{ in, want string }{
		{SearchGrep + " ~", SearchGrep + " /home/u"},
		{SearchGlob + " ~/a/../b", SearchGlob + " /home/u/b"},
		{SearchGrep + " ~other/x", SearchGrep + " ~other/x"},
		{SearchGrep + " /ws", SearchGrep + " /ws"},
		{"claude-code bash ~/x", "claude-code bash ~/x"},
	} {
		got := Adapter{}.ExpandHome(models.TrajectoryEntry{ActionType: models.ProcessExec, Target: c.in}, "/home/u")
		if got.Target != c.want {
			t.Errorf("ExpandHome(%q) = %q, want %q", c.in, got.Target, c.want)
		}
	}
	if got := (Adapter{}).ExpandHome(models.TrajectoryEntry{ActionType: models.FileRead, Target: SearchGrep + " ~/x"}, "/home/u"); got.Target != SearchGrep+" ~/x" {
		t.Errorf("a non-exec claim was expanded: %q", got.Target)
	}
}
