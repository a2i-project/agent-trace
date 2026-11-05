package gemini

import (
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// The command lines of agy 1.4.7's searches (I-133), as the parity captures
// show them: MatchPerLine true gives --line-number and -nH, and a search of
// one file runs the grep on the file's absolute path without -r.
const (
	rgLines       = rgProgram + " --no-heading --with-filename --line-number --fixed-strings --ignore-file=" + ws + "/.antigravityignore -- seed"
	grepLines     = "/usr/bin/grep -nH --binary-files=without-match -F -r -- seed ."
	fileGrepLine  = "/usr/bin/grep -nH --binary-files=without-match -F -- seed " + ws + "/b.txt"
	grepImagePath = "/usr/bin/grep"
)

func TestSearchOfRecognisesThe147Forms(t *testing.T) {
	for name, c := range map[string]struct {
		line  string
		want  search
		match bool
	}{
		"ripgrep by line":           {rgLines, search{form: ripgrepSearch, lines: true, query: "seed", path: ws + "/"}, true},
		"ripgrep by file":           {rgLine, search{form: ripgrepSearch, query: "seed", path: ws + "/"}, true},
		"grep by line":              {grepLines, search{form: grepSearch, lines: true, query: "seed"}, true},
		"grep of a file":            {fileGrepLine, search{form: fileSearch, lines: true, query: "seed", path: ws + "/b.txt"}, true},
		"a query with spaces":       {"/usr/bin/grep -nH --binary-files=without-match -F -- two words /w/a.txt", search{form: fileSearch, lines: true, query: "two words", path: "/w/a.txt"}, true},
		"grep of a relative file":   {"/usr/bin/grep -nH --binary-files=without-match -F -- seed b.txt", search{}, false},
		"grep of a file by name":    {"/usr/bin/grep -l --binary-files=without-match -F -- seed /w/b.txt", search{}, false},
		"grep of a file, recursive": {"/usr/bin/grep -nH --binary-files=without-match -F -r -- seed /w/b.txt", search{}, false},
		"grep ignoring case":        {"/usr/bin/grep -nHi --binary-files=without-match -F -r -- seed .", search{}, false},
		"ripgrep with another mode": {strings.Replace(rgLines, "--line-number", "-c", 1), search{}, false},
		"grep from the workspace":   {ws + "/grep -nH --binary-files=without-match -F -- seed /w/b.txt", search{}, false},
		"a regular expression grep": {"/usr/bin/grep -nH --binary-files=without-match -E -r -- seed .", search{}, false},
		"a file path with a space":  {"/usr/bin/grep -nH --binary-files=without-match -F -- seed /w/a b.txt", search{}, false},
	} {
		got := searchOf(c.line)
		if c.match && got != c.want {
			t.Errorf("%s: searchOf = %+v, want %+v", name, got, c.want)
		}
		if !c.match && got.form != notSearch {
			t.Errorf("%s: searchOf = %+v, want no search", name, got)
		}
	}
}

func withImage(e models.GroundTruthEvent, file string) models.GroundTruthEvent {
	e.Image = &models.ExecImage{Filename: file, Program: file}
	return e
}

func withCwd(e models.GroundTruthEvent, cwd string) models.GroundTruthEvent {
	e.Cwd = cwd
	return e
}

// search147Shape is the session's first grep_search on agy 1.4.7 as the
// parity search run shows it (I-133): the quiet pidfd fork, the embedded
// ripgrep's failed exec, which opens its program and, since P-31, has no
// exit record and no image, then the fallback grep, whose exec took effect
// and carries its image and working directory.
func search147Shape() models.GroundTruth {
	us := time.Microsecond
	return models.GroundTruth{
		ev(0, agentPID, models.FileWrite, brain+"/logs/transcript.jsonl"),
		child(30000*us, 300, models.ProcessFork, "300"),
		child(30200*us, 301, models.ProcessFork, "301"),
		withCwd(child(30270*us, 301, models.ProcessExec, rgLine), ws),
		ev(30320*us, 301, models.FileOpen, rgProgram),
		child(36200*us, 302, models.ProcessFork, "302"),
		withImage(withCwd(child(36260*us, 302, models.ProcessExec, grepLine), ws), grepImagePath),
		ev(36300*us, 302, models.FileOpen, "/usr/bin/grep"),
		ev(37090*us, 302, models.FileOpen, ws+"/b.txt"),
		withExit(child(37140*us, 302, models.ProcessExit, grepLine), 0),
		ev(40000*us, agentPID, models.FileWrite, brain+"/logs/transcript.jsonl"),
	}
}

// A ripgrep whose exec failed and that never exits is folded with its
// fallback when the probe recorded which execs took effect: the grep's did,
// the ripgrep's did not.
func TestFoldSearchesFoldsARipgrepWithNoExitRecord(t *testing.T) {
	got := renderProcs(foldSearches(search147Shape(), agentPID))
	want := strings.Join([]string{
		"process_fork 300<100 300",
		"process_fork 301<100 301",
		"process_exec 301<100 " + SearchGrep + " " + ws,
		"process_fork 302<301 302",
		"process_exec 302<301 " + grepLine,
		"process_exit 302<301 " + grepLine,
	}, "\n") + "\n"
	if got != want {
		t.Errorf("folded:\n%s\nwant\n%s", got, want)
	}
	for name, mutate := range map[string]func(models.GroundTruth) models.GroundTruth{
		// Without images nothing tells a failed exec from a ripgrep still
		// running, so the two stay two commands.
		"no images": func(g models.GroundTruth) models.GroundTruth {
			g[6].Image = nil
			return g
		},
		"the ripgrep's exec took effect": func(g models.GroundTruth) models.GroundTruth {
			g[3] = withImage(g[3], rgProgram)
			return g
		},
		"another output mode": func(g models.GroundTruth) models.GroundTruth {
			g[6].Target = grepLines
			g[9].Target = grepLines
			return g
		},
	} {
		var under int
		for _, e := range foldSearches(mutate(search147Shape()), agentPID) {
			if e.ActionType == models.ProcessExec && e.PPID != agentPID {
				under++
			}
		}
		if under != 0 {
			t.Errorf("%s: the grep was folded under the ripgrep", name)
		}
	}
}

// Only a search the harness itself started is rewritten (I-133): the first
// exec of a child of the agent's process, whose image, when recorded, is its
// own program. The same grep line run by a run_command (bash -c first, then
// grep in place) keeps its text, and so does one from another parent or one
// whose image is another file.
func TestFoldSearchesTakesOnlyTheHarnesssOwnRun(t *testing.T) {
	us := time.Microsecond
	lone := func() models.GroundTruth {
		return models.GroundTruth{
			child(1000*us, 400, models.ProcessFork, "400"),
			withImage(withCwd(child(1100*us, 400, models.ProcessExec, grepLines), ws), grepImagePath),
			withExit(child(2000*us, 400, models.ProcessExit, grepLines), 0),
		}
	}
	if g := foldSearches(lone(), agentPID); g[1].Target != SearchGrep+" "+ws || g[2].Target != SearchGrep+" "+ws {
		t.Errorf("a lone grep by the harness: %s", renderProcs(g))
	}
	for name, mutate := range map[string]func(models.GroundTruth) models.GroundTruth{
		"under a run_command's shell": func(g models.GroundTruth) models.GroundTruth {
			shell := withImage(withCwd(child(1050*us, 400, models.ProcessExec, "/usr/bin/bash -c "+strings.TrimPrefix(grepLines, "/usr/bin/")), ws), "/usr/bin/bash")
			return append(models.GroundTruth{g[0], shell}, g[1:]...)
		},
		"from another parent": func(g models.GroundTruth) models.GroundTruth {
			for i := range g {
				g[i].PPID = 99
			}
			return g
		},
		"an image of another file": func(g models.GroundTruth) models.GroundTruth {
			g[1].Image = &models.ExecImage{Filename: grepImagePath, Program: ws + "/fake"}
			return g
		},
		"a script": func(g models.GroundTruth) models.GroundTruth {
			g[1].Image.Interpreter = "/usr/bin/python3"
			return g
		},
		"a renamed program": func(g models.GroundTruth) models.GroundTruth {
			g[1].Image.FilenameChanged = true
			return g
		},
	} {
		for _, e := range foldSearches(mutate(lone()), agentPID) {
			if isSearchTarget(e.Target) {
				t.Errorf("%s: rewritten to %q", name, e.Target)
			}
		}
	}
	// Without a root the parent is not checked, as before I-133.
	g := lone()
	for i := range g {
		g[i].PPID = 99
	}
	if out := foldSearches(g, 0); out[1].Target != SearchGrep+" "+ws {
		t.Errorf("no root: %s", renderProcs(out))
	}
}

func verifySearch(t *testing.T, a agent.Adapter, tr models.Trajectory, g models.GroundTruth) verification.Verdict {
	t.Helper()
	cov := &models.Coverage{Schema: models.CoverageSchema, Probes: map[string]models.ProbeCoverage{"fs": {Ran: true}, "proc": {Ran: true}}}
	harness := func(e models.GroundTruthEvent) bool { return harnessOwned.MatchString(e.Target) }
	return verification.Verify(agent.Prepare(a, tr, models.GroundTruthFile{Events: g, RootPID: agentPID, Workspace: ws, Coverage: cov}, harness,
		verification.Options{IntervalSlack: 500 * time.Millisecond}))
}

// End to end through Prepare, which gives the adapter the root: the first
// search folds and verifies on its folder, a later search of one file runs
// the grep alone and verifies on the file, and a claim of another file is a
// substitution.
func TestA147SearchVerifiesEndToEnd(t *testing.T) {
	ms := time.Millisecond
	us := time.Microsecond
	g := search147Shape()
	g = append(g[:len(g)-1],
		child(60000*us, 500, models.ProcessFork, "500"),
		withImage(withCwd(child(60100*us, 500, models.ProcessExec, fileGrepLine), ws), grepImagePath),
		ev(60200*us, 500, models.FileOpen, ws+"/b.txt"),
		withExit(child(60300*us, 500, models.ProcessExit, fileGrepLine), 1),
		g[len(g)-1])
	g[len(g)-1].Timestamp = t0.Add(70 * ms)
	claims := func(file string) models.Trajectory {
		e1, e2 := t0.Add(45*ms), t0.Add(65*ms)
		return models.Trajectory{
			{Tool: toolGrepSearch, Timestamp: t0.Add(10 * ms), End: &e1, ActionType: models.ProcessExec, Target: searchClaim(ws)},
			{Tool: toolGrepSearch, Timestamp: t0.Add(55 * ms), End: &e2, ActionType: models.ProcessExec, Target: searchClaim(file)},
		}
	}
	v := verifySearch(t, Adapter{}, claims(ws+"/b.txt"), g)
	if v.Outcome != verification.OutcomeFaithful || len(v.Corroborated) != 2 || v.Findings() != 0 {
		t.Errorf("outcome %s, corroborated %d, unrecorded %v, mismatched %v", v.Outcome, len(v.Corroborated), v.Unrecorded, v.Mismatched)
	}
	if v := verifySearch(t, Adapter{}, claims(ws+"/c.txt"), g); v.Outcome != verification.OutcomeNotFaithful || len(v.Mismatched) != 1 {
		t.Errorf("another file: outcome %s, mismatched %v", v.Outcome, v.Mismatched)
	}
}
