package gemini

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

const (
	rgProgram = "/home/u/.cache/antigravity/bin/rg_embedded-14d1066b44c4f6b7"
	rgLine    = rgProgram + " --no-heading --with-filename -l --fixed-strings --ignore-file=" + ws + "/.antigravityignore -- seed"
	grepLine  = "/usr/bin/grep -l --binary-files=without-match -F -r -- seed ."
)

// Only the two command lines of the paired search capture are a search
// (I-54): the ripgrep in the harness's cache with its option shape, and grep
// from /usr/bin or /bin with its. Another program, path or option shape keeps
// its text, as I-27 narrowed I-25.
func TestSearchOfRecognisesOnlyTheMeasuredForms(t *testing.T) {
	for name, c := range map[string]struct {
		line  string
		form  searchForm
		query string
	}{
		"embedded ripgrep":                 {rgLine, ripgrepSearch, "seed"},
		"embedded ripgrep of root":         {strings.Replace(rgLine, "/home/u", "/root", 1), ripgrepSearch, "seed"},
		"a query with spaces":              {strings.TrimSuffix(rgLine, "seed") + "two words", ripgrepSearch, "two words"},
		"fallback grep":                    {grepLine, grepSearch, "seed"},
		"fallback grep from /bin":          {"/bin/grep -l --binary-files=without-match -F -r -- seed .", grepSearch, "seed"},
		"ripgrep outside the cache":        {strings.Replace(rgLine, "/home/u/.cache/antigravity/bin", "/tmp", 1), notSearch, ""},
		"ripgrep in the workspace":         {strings.Replace(rgLine, "/home/u/.cache/antigravity/bin", ws, 1), notSearch, ""},
		"ripgrep with another hash length": {strings.Replace(rgLine, "14d1066b44c4f6b7", "14d1066b", 1), notSearch, ""},
		"ripgrep with another option":      {strings.Replace(rgLine, " -l ", " -i -l ", 1), notSearch, ""},
		"ripgrep without its ignore file":  {strings.Replace(rgLine, " --ignore-file="+ws+"/.antigravityignore", "", 1), notSearch, ""},
		"ripgrep with another ignore file": {strings.Replace(rgLine, ".antigravityignore", ".gitignore", 1), notSearch, ""},
		"grep from elsewhere":              {"/usr/local/bin/grep -l --binary-files=without-match -F -r -- seed .", notSearch, ""},
		"grep from the workspace":          {ws + "/grep -l --binary-files=without-match -F -r -- seed .", notSearch, ""},
		"grep with another option":         {"/usr/bin/grep -l -i --binary-files=without-match -F -r -- seed .", notSearch, ""},
		"grep of another directory":        {"/usr/bin/grep -l --binary-files=without-match -F -r -- seed /etc", notSearch, ""},
		"grep cut by the probe":            {"/usr/bin/grep -l --binary-files=without-match -F -r -- se", notSearch, ""},
		"a command":                        {"/usr/bin/bash -c grep -r seed .", notSearch, ""},
	} {
		form, q := searchOf(c.line)
		if form != c.form || q != c.query {
			t.Errorf("%s: searchOf = %v %q, want %v %q", name, form, q, c.form, c.query)
		}
	}
}

func withExit(e models.GroundTruthEvent, code int32) models.GroundTruthEvent {
	e.ExitCode = &code
	return e
}

func child(at time.Duration, pid uint32, a models.ActionType, target string) models.GroundTruthEvent {
	e := ev(at, pid, a, target)
	e.PPID = agentPID
	return e
}

// searchShape is a grep_search call as the paired search capture shows it:
// Go's pidfd probe (a quiet fork), the embedded ripgrep's failed exec (it
// opens its program and exits with no exit code), then the fallback grep,
// which reads the workspace and exits 0.
func searchShape() models.GroundTruth {
	us := time.Microsecond
	return models.GroundTruth{
		ev(0, agentPID, models.FileWrite, brain+"/logs/transcript.jsonl"),
		child(30000*us, 300, models.ProcessFork, "300"),
		child(30200*us, 301, models.ProcessFork, "301"),
		child(30270*us, 301, models.ProcessExec, rgLine),
		ev(30320*us, 301, models.FileOpen, rgProgram),
		child(30770*us, 301, models.ProcessExit, rgLine),
		child(31140*us, 302, models.ProcessFork, "302"),
		child(31210*us, 302, models.ProcessExec, grepLine),
		ev(31250*us, 302, models.FileOpen, "/usr/bin/grep"),
		ev(33090*us, 302, models.FileOpen, ws+"/b.txt"),
		withExit(child(33140*us, 302, models.ProcessExit, grepLine), 0),
		ev(35000*us, agentPID, models.FileWrite, brain+"/logs/transcript.jsonl"),
	}
}

func renderProcs(g models.GroundTruth) string {
	var b strings.Builder
	for _, e := range g {
		switch e.ActionType {
		case models.ProcessFork, models.ProcessExec, models.ProcessExit:
			fmt.Fprintf(&b, "%s %d<%d %s\n", e.ActionType, e.PID, e.PPID, e.Target)
		}
	}
	return b.String()
}

// The failed ripgrep and its fallback are one search: the ripgrep's process
// takes the claim's target, and the grep becomes its content, under it, with
// its own command line kept.
func TestFoldSearchesFoldsTheFallbackIntoTheFailedRipgrep(t *testing.T) {
	got := renderProcs(foldSearches(searchShape()))
	want := strings.Join([]string{
		"process_fork 300<100 300",
		"process_fork 301<100 301",
		"process_exec 301<100 " + SearchGrep,
		"process_exit 301<100 " + SearchGrep,
		"process_fork 302<301 302",
		"process_exec 302<301 " + grepLine,
		"process_exit 302<301 " + grepLine,
	}, "\n") + "\n"
	if got != want {
		t.Errorf("folded:\n%s\nwant\n%s", got, want)
	}
}

// Each condition of the fold, broken, leaves two commands, each rewritten:
// a ripgrep that ran (an exit code), one that did more than open its program,
// a parent event or another child between them, another query, another
// program after it.
func TestFoldSearchesIsNarrow(t *testing.T) {
	us := time.Microsecond
	for name, mutate := range map[string]func(models.GroundTruth) models.GroundTruth{
		"the ripgrep ran": func(g models.GroundTruth) models.GroundTruth {
			g[5] = withExit(g[5], 1)
			return g
		},
		"the ripgrep read the workspace": func(g models.GroundTruth) models.GroundTruth {
			g[4].Target = ws + "/b.txt"
			return g
		},
		"the parent acted between them": func(g models.GroundTruth) models.GroundTruth {
			return append(g[:6], append(models.GroundTruth{ev(31000*us, agentPID, models.FileOpen, ws+"/b.txt")}, g[6:]...)...)
		},
		"the parent started another child between them": func(g models.GroundTruth) models.GroundTruth {
			return append(g[:6], append(models.GroundTruth{child(31000*us, 299, models.ProcessFork, "299")}, g[6:]...)...)
		},
		"another query": func(g models.GroundTruth) models.GroundTruth {
			g[7].Target = strings.Replace(grepLine, "seed", "other", 1)
			g[10].Target = g[7].Target
			return g
		},
	} {
		g := mutate(searchShape())
		var execs, under int
		for _, e := range foldSearches(g) {
			if e.ActionType == models.ProcessExec {
				if e.Target == SearchGrep {
					execs++
				}
				if e.PPID != agentPID {
					under++
				}
			}
		}
		if execs != 2 || under != 0 {
			t.Errorf("%s: %d execs rewritten and %d placed under another, want 2 and 0", name, execs, under)
		}
	}
	// A grep of another shape after the ripgrep is not folded and keeps its
	// text: it shows as an unclaimed command.
	g := searchShape()
	other := "/usr/bin/grep -r seed ."
	g[7].Target, g[10].Target = other, other
	out := foldSearches(g)
	if out[7].Target != other || out[7].PPID != agentPID || out[3].Target != SearchGrep {
		t.Errorf("another program after the ripgrep: %s", renderProcs(out))
	}
}

// Alone, either form is one search: a ripgrep that works (with an exit code)
// is the whole call, and so is the fallback grep.
func TestFoldSearchesRewritesEitherFormAlone(t *testing.T) {
	g := searchShape()
	rg := models.GroundTruth{g[2], g[3], g[4], withExit(g[5], 0)}
	gr := models.GroundTruth{g[6], g[7], g[8], g[9], g[10]}
	for name, s := range map[string]models.GroundTruth{"ripgrep": rg, "grep": gr} {
		var n int
		for _, e := range foldSearches(s) {
			if (e.ActionType == models.ProcessExec || e.ActionType == models.ProcessExit) && e.Target == SearchGrep && e.PPID == agentPID {
				n++
			}
		}
		if n != 2 {
			t.Errorf("%s alone: %d of its exec and exit rewritten:\n%s", name, n, renderProcs(foldSearches(s)))
		}
	}
}

// End to end, one grep_search claim explains the search: it is corroborated,
// nothing is unrecorded and no command is unexplained. Without the fold the
// fallback grep is an unclaimed command.
func TestASearchVerifiesEndToEnd(t *testing.T) {
	ms := time.Millisecond
	end := t0.Add(40 * ms)
	tr := models.Trajectory{{Tool: toolGrepSearch, Timestamp: t0.Add(10 * ms), End: &end, ActionType: models.ProcessExec, Target: SearchGrep}}
	harness := func(e models.GroundTruthEvent) bool { return harnessOwned.MatchString(e.Target) }
	cov := &models.Coverage{Schema: models.CoverageSchema, Probes: map[string]models.ProbeCoverage{"fs": {Ran: true}, "proc": {Ran: true}}}
	run := func(a agent.Adapter) verification.Verdict {
		return verification.Verify(agent.Prepare(a, tr, models.GroundTruthFile{Events: searchShape(), RootPID: agentPID, Workspace: ws, Coverage: cov}, harness,
			verification.Options{IntervalSlack: 500 * time.Millisecond}))
	}
	v := run(Adapter{})
	if v.Findings() != 0 || len(v.Corroborated) != 1 || len(v.Unrecorded) != 0 || v.Outcome != verification.OutcomeFaithful {
		t.Errorf("outcome %s, corroborated %d, unrecorded %v, unwitnessed %v, mismatched %v", v.Outcome, len(v.Corroborated), v.Unrecorded, v.Unwitnessed, v.Mismatched)
	}
	if raw := run(rawAdapter{}); raw.Outcome != verification.OutcomeNotFaithful || len(raw.Corroborated) != 0 {
		t.Errorf("without the stream normalization: outcome %s, corroborated %d", raw.Outcome, len(raw.Corroborated))
	}
}

// grep_search claims one search; list_dir and find_by_name are non-effectful
// and claim nothing, without being reported as unknown (I-54).
func TestParseClaimsASearchAndNotAListing(t *testing.T) {
	path := writeDB(t, []step{
		{typ: 132, status: 3, payload: payload(at(1), at(2), at(3), toolCall("c1", "list_dir", map[string]any{"DirectoryPath": "/w"}))},
		{typ: 132, status: 3, payload: payload(at(4), at(5), at(6), toolCall("c2", "grep_search", map[string]any{"Query": "seed", "SearchPath": "/w"}))},
		{typ: 132, status: 3, payload: payload(at(7), at(8), at(9), toolCall("c3", "find_by_name", map[string]any{"Pattern": "*.txt", "SearchDirectory": "/w"}))},
	})
	tr, rep := parse(t, path)
	if len(tr) != 1 || tr[0].ActionType != models.ProcessExec || tr[0].Target != SearchGrep || tr[0].Tool != toolGrepSearch {
		t.Errorf("claims %+v, want one process_exec of %q", tr, SearchGrep)
	}
	if len(rep.UnknownTools) != 0 || rep.UnmappedByTool["list_dir"] != 1 || rep.UnmappedByTool["find_by_name"] != 1 {
		t.Errorf("unknown %v, unmapped %v", rep.UnknownTools, rep.UnmappedByTool)
	}
	if strings.Contains(strings.Join(rep.Degradations, "|"), "no mapping") {
		t.Errorf("degradations %v", rep.Degradations)
	}
}
