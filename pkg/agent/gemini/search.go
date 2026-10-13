package gemini

import (
	"regexp"
	"strings"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// SearchGrep is the claimed and the normalized target of a grep_search call
// (I-54): the call claims that a search ran, not its pattern or path, as a
// Claude Code Grep does (I-25).
const SearchGrep = "agy search:grep"

// What a grep_search call runs, measured on the paired capture of the search
// task with agy 1.3.4 (2026-10-13), the agy process's own children:
//
//	~/.cache/antigravity/bin/rg_embedded-<16 hex> --no-heading --with-filename -l --fixed-strings --ignore-file=<dir>/.antigravityignore -- <query>
//
// the ripgrep embedded in the binary, which the harness extracts to its cache
// directory. On the capture's machine that exec fails (the binary names an
// interpreter under /usr/grte, I-47), and the child exits with no exit code
// (Go's child of a failed exec ends with exit, not exit_group, so the probe
// records none). The harness then runs, as a new child, about one millisecond
// later and with no event of its own between,
//
//	/usr/bin/grep -l --binary-files=without-match -F -r -- <query> .
//
// with grep found on PATH (/usr/bin/grep under the reset environment the
// capture script gives; /bin/grep is the same file on a merged-/usr system).
// Only these two option shapes are recognised; another program, another
// option shape or a ripgrep outside the harness's cache keeps its text.
var (
	embeddedRipgrep = regexp.MustCompile(`^(?:/home/[^/\s]+|/root)/\.cache/antigravity/bin/rg_embedded-[0-9a-f]{16} --no-heading --with-filename -l --fixed-strings --ignore-file=/(?:\S+/)?\.antigravityignore -- (.+)$`)
	fallbackGrep    = regexp.MustCompile(`^(?:/usr)?/bin/grep -l --binary-files=without-match -F -r -- (.+) \.$`)
)

type searchForm int

const (
	notSearch searchForm = iota
	ripgrepSearch
	grepSearch
)

// searchOf classifies an observed command line as one of the two forms of a
// grep_search call, with the query it names.
func searchOf(target string) (searchForm, string) {
	if m := embeddedRipgrep.FindStringSubmatch(target); m != nil {
		return ripgrepSearch, m[1]
	}
	if m := fallbackGrep.FindStringSubmatch(target); m != nil {
		return grepSearch, m[1]
	}
	return notSearch, ""
}

// program is the executed path of an observed command line: the probe
// records the path and argv[1:] joined by spaces.
func program(target string) string {
	if i := strings.IndexByte(target, ' '); i >= 0 {
		return target[:i]
	}
	return target
}

// foldSearches rewrites the processes of grep_search calls to the claim's
// grain (I-54). The exec of either form, and the exit of the same process,
// become SearchGrep. When the embedded ripgrep's exec failed and the fallback
// grep follows from the same parent, the two are one search: the grep is
// placed under the ripgrep's process (its fork, exec and exit name the
// ripgrep's pid as parent), so it is the content of the one command the claim
// explains, and its own command line is kept. The fold takes only the shape
// the capture showed:
//
//   - the ripgrep's process does nothing after its exec but open its own
//     program and exit with no exit code (the failed exec);
//   - the parent's next fork after that exec is the grep's, and the grep's
//     exec, from that parent, names the same query;
//   - from the ripgrep's exec to the grep's exec, the parent has no event of
//     its own and forks or execs nothing else.
//
// Anything else is left as two commands, each rewritten, so a second process
// shows as an unclaimed command. Events are in time order.
func foldSearches(g models.GroundTruth) models.GroundTruth {
	var out models.GroundTruth
	rewritten := map[uint32]bool{}  // pids whose exit is rewritten
	reparent := map[uint32]uint32{} // fallback pid -> the ripgrep's pid
	for i, e := range g {
		if e.ActionType != models.ProcessExec || e.PID == 0 {
			continue
		}
		form, query := searchOf(e.Target)
		if form == notSearch {
			continue
		}
		if _, folded := reparent[e.PID]; folded {
			continue
		}
		if out == nil {
			out = append(models.GroundTruth(nil), g...)
		}
		out[i].Target = SearchGrep
		rewritten[e.PID] = true
		if form == ripgrepSearch {
			if b, ok := fallbackAfter(g, i, query); ok {
				reparent[b] = e.PID
			}
		}
	}
	if out == nil {
		return g
	}
	for i, e := range out {
		switch e.ActionType {
		case models.ProcessFork, models.ProcessExec, models.ProcessExit:
			if a, ok := reparent[e.PID]; ok {
				out[i].PPID = a
				continue
			}
		}
		if e.ActionType == models.ProcessExit && rewritten[e.PID] {
			out[i].Target = SearchGrep
			delete(rewritten, e.PID)
		}
	}
	return out
}

// fallbackAfter returns the pid of the fallback grep that follows the failed
// ripgrep exec at g[i] in the shape foldSearches describes.
func fallbackAfter(g models.GroundTruth, i int, query string) (uint32, bool) {
	rg := g[i]
	prog := program(rg.Target)
	exited := false
	var fallback uint32
	for _, e := range g[i+1:] {
		switch {
		case e.PID == rg.PID && !exited:
			switch {
			case e.ActionType == models.FileOpen && e.Target == prog:
			case e.ActionType == models.ProcessExit && e.ExitCode == nil:
				exited = true
			default:
				return 0, false
			}
		case e.PID == rg.PPID:
			return 0, false // an event of the parent's own
		case e.PPID == rg.PPID && e.ActionType == models.ProcessFork:
			if !exited || fallback != 0 {
				return 0, false
			}
			fallback = e.PID
		case e.PPID == rg.PPID && e.ActionType == models.ProcessExec:
			if fallback == 0 || e.PID != fallback {
				return 0, false
			}
			if form, q := searchOf(e.Target); form != grepSearch || q != query {
				return 0, false
			}
			return fallback, true
		}
	}
	return 0, false
}
