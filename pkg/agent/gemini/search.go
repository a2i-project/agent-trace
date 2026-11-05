package gemini

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/agent-trace/agent-trace/pkg/models"
)

// SearchGrep is the kind of search a grep_search call claims (I-54). The
// claimed and the normalized target is the kind followed by the folder
// searched (I-108); the pattern is not claimed, as a Claude Code Grep's is
// not (I-25).
const SearchGrep = "agy search:grep"

// What a grep_search call runs, measured on the paired capture of the search
// task with agy 1.3.4 (2026-10-13), the agy process's own children:
//
//	~/.cache/antigravity/bin/rg_embedded-<16 hex> --no-heading --with-filename -l --fixed-strings --ignore-file=<dir>/.antigravityignore -- <query>
//
// the ripgrep embedded in the binary, which the harness extracts to its cache
// directory. On the capture's machine that exec fails (the binary names an
// interpreter under /usr/grte, I-47). The harness then runs, as a new child,
// about one millisecond later and with no event of its own between,
//
//	/usr/bin/grep -l --binary-files=without-match -F -r -- <query> .
//
// with grep found on PATH (/usr/bin/grep under the reset environment the
// capture script gives; /bin/grep is the same file on a merged-/usr system).
//
// agy 1.4.7 (the parity captures of the search and long tasks, 2026-11-05,
// and the long pilot, I-133) runs the same two lines for a search whose
// MatchPerLine is false. With MatchPerLine true the ripgrep takes
// --line-number in place of -l and the grep -nH in place of -l. Only the
// session's first search tries the ripgrep: once it failed, every later
// search runs the grep alone. A search of one file runs the grep without -r
// on the file's absolute path,
//
//	/usr/bin/grep -nH --binary-files=without-match -F -- <query> <file>
//
// in the file's directory. Only these shapes are recognised; another
// program, another option shape (an Includes, CaseInsensitive or IsRegex
// argument, none measured) or a ripgrep outside the harness's cache keeps
// its text.
var (
	embeddedRipgrep = regexp.MustCompile(`^(?:/home/[^/\s]+|/root)/\.cache/antigravity/bin/rg_embedded-[0-9a-f]{16} --no-heading --with-filename (-l|--line-number) --fixed-strings --ignore-file=(/(?:\S+/)?)\.antigravityignore -- (.+)$`)
	fallbackGrep    = regexp.MustCompile(`^(?:/usr)?/bin/grep (-l|-nH) --binary-files=without-match -F -r -- (.+) \.$`)
	fileGrep        = regexp.MustCompile(`^(?:/usr)?/bin/grep -nH --binary-files=without-match -F -- (.+) (/\S+)$`)
)

type searchForm int

const (
	notSearch searchForm = iota
	ripgrepSearch
	grepSearch
	fileSearch
)

// search is an observed command line read as a grep_search: its form, its
// output mode (lines or file names, the call's MatchPerLine), its query and,
// for the ripgrep its ignore file's directory, for a file search the file.
type search struct {
	form  searchForm
	lines bool
	query string
	path  string
}

// searchOf classifies an observed command line as one of the forms of a
// grep_search call.
func searchOf(target string) search {
	if m := embeddedRipgrep.FindStringSubmatch(target); m != nil {
		return search{form: ripgrepSearch, lines: m[1] != "-l", path: m[2], query: m[3]}
	}
	if m := fallbackGrep.FindStringSubmatch(target); m != nil {
		return search{form: grepSearch, lines: m[1] != "-l", query: m[2]}
	}
	if m := fileGrep.FindStringSubmatch(target); m != nil {
		return search{form: fileSearch, lines: true, query: m[1], path: m[2]}
	}
	return search{}
}

// searchFolder is the normalized target of an observed search's exec
// (I-108): the kind and the folder searched. The embedded ripgrep is given
// the search path's ignore file, <folder>/.antigravityignore, which names
// the folder (on the search capture of 1.3.4 it is the call's SearchPath);
// the fallback grep searches "." in the working directory the probe
// recorded; a file search names its file, which is the call's SearchPath
// (I-133). When the folder cannot be read (a fallback grep in a capture made
// before P-36, or a command line the probe cut) the target is the kind
// alone, marked truncated, and pairs by prefix, unverified (V-26).
func searchFolder(e models.GroundTruthEvent, s search) (string, bool) {
	if !e.TargetTruncated {
		switch s.form {
		case ripgrepSearch, fileSearch:
			return SearchGrep + " " + filepath.Clean(s.path), false
		case grepSearch:
			if e.Cwd != "" && !e.CwdTruncated && filepath.IsAbs(e.Cwd) {
				return SearchGrep + " " + filepath.Clean(e.Cwd), false
			}
		}
	}
	return SearchGrep, true
}

// searchClaim is the target of a grep_search call: the kind and its
// SearchPath, cleaned when it is absolute. A relative or missing path is
// kept as written, and a search observed with a folder then reads as a
// mismatch.
func searchClaim(path string) string {
	switch {
	case path == "":
		return SearchGrep
	case filepath.IsAbs(path):
		return SearchGrep + " " + filepath.Clean(path)
	}
	return SearchGrep + " " + path
}

// program is the executed path of an observed command line: the probe
// records the path and argv[1:] joined by spaces.
func program(target string) string {
	if i := strings.IndexByte(target, ' '); i >= 0 {
		return target[:i]
	}
	return target
}

// harnessRun reports whether a search's exec is one the harness itself
// started (I-133): the first exec of its process since its fork, and, when
// the capture names the agent's process (root), a child of it. A
// run_command's program runs under the harness's bash -c, whose own exec
// comes first, so a grep the agent ran is never its process's first exec.
// When the exec took effect and the probe recorded what the kernel ran
// (P-36), that is the command line's own program, not cut, unchanged, with
// no interpreter, and a file of the program's name.
func harnessRun(e models.GroundTruthEvent, first bool, root uint32) bool {
	if !first || (root != 0 && e.PPID != root) {
		return false
	}
	im := e.Image
	if im == nil {
		return true
	}
	prog := program(e.Target)
	return !im.Truncated && !im.FilenameChanged && im.Interpreter == "" && im.Filename == prog &&
		filepath.IsAbs(im.Program) && filepath.Base(im.Program) == filepath.Base(prog)
}

// foldSearches rewrites the processes of grep_search calls to the claim's
// grain (I-54, I-133). The exec of any recognised form that the harness ran
// (harnessRun), and the exit of the same process, become SearchGrep. When
// the embedded ripgrep's exec failed and the fallback grep follows from the
// same parent, the two are one search: the grep is placed under the
// ripgrep's process (its fork, exec and exit name the ripgrep's pid as
// parent), so it is the content of the one command the claim explains, and
// its own command line is kept. The fold takes only the shape the captures
// showed:
//
//   - the ripgrep's process does nothing after its exec but open its own
//     program, and either exits with no exit code (the failed exec, before
//     P-31) or, when the probe recorded that its exec did not take effect
//     (no image, while the grep's exec has one), does not exit at all (a
//     process whose exec failed has no exit record since P-31);
//   - the parent's next fork after that exec is the grep's, and the grep's
//     exec, from that parent, names the same query in the same output mode;
//   - from the ripgrep's exec to the grep's exec, the parent has no event of
//     its own and forks or execs nothing else.
//
// Anything else is left as two commands, each rewritten, so a second process
// shows as an unclaimed command. Events are in time order.
func foldSearches(g models.GroundTruth, root uint32) models.GroundTruth {
	var out models.GroundTruth
	type rewrite struct {
		target    string
		truncated bool
	}
	rewritten := map[uint32]rewrite{} // pids whose exit is rewritten
	reparent := map[uint32]uint32{}   // fallback pid -> the ripgrep's pid
	execd := map[uint32]bool{}        // pids that exec'd since their fork
	for i, e := range g {
		if e.PID == 0 {
			continue
		}
		if e.ActionType == models.ProcessFork {
			delete(execd, e.PID)
			continue
		}
		if e.ActionType != models.ProcessExec {
			continue
		}
		first := !execd[e.PID]
		execd[e.PID] = true
		s := searchOf(e.Target)
		if s.form == notSearch || !harnessRun(e, first, root) {
			continue
		}
		if _, folded := reparent[e.PID]; folded {
			continue
		}
		if out == nil {
			out = append(models.GroundTruth(nil), g...)
		}
		r := rewrite{}
		r.target, r.truncated = searchFolder(e, s)
		out[i].Target, out[i].TargetTruncated = r.target, r.truncated
		rewritten[e.PID] = r
		if s.form == ripgrepSearch {
			if b, ok := fallbackAfter(g, i, s, root); ok {
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
		if r, ok := rewritten[e.PID]; ok && e.ActionType == models.ProcessExit {
			out[i].Target, out[i].TargetTruncated = r.target, r.truncated
			delete(rewritten, e.PID)
		}
	}
	return out
}

// fallbackAfter returns the pid of the fallback grep that follows the failed
// ripgrep exec at g[i] in the shape foldSearches describes.
func fallbackAfter(g models.GroundTruth, i int, rgs search, root uint32) (uint32, bool) {
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
			if fallback != 0 || (!exited && rg.Image != nil) {
				return 0, false
			}
			fallback = e.PID
		case e.PPID == rg.PPID && e.ActionType == models.ProcessExec:
			if fallback == 0 || e.PID != fallback {
				return 0, false
			}
			s := searchOf(e.Target)
			if s.form != grepSearch || s.query != rgs.query || s.lines != rgs.lines || !harnessRun(e, true, root) {
				return 0, false
			}
			// A ripgrep that never exited is a failed exec only when the
			// probe records which execs took effect: the grep's did.
			if !exited && e.Image == nil {
				return 0, false
			}
			return fallback, true
		}
	}
	return 0, false
}
