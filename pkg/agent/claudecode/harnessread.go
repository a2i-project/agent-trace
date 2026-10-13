package claudecode

import (
	"path/filepath"
	"regexp"
	"strings"
)

// After a Bash call that was not interrupted, not sent to the background and
// returned no image, Claude Code reads the file a simple read command named,
// to record its state, unless the file is already in that record, is not a
// regular file or exceeds 10 MiB (I-46). Which commands count is decided by a
// parser in the binary (F1r in 2.1.296), read here from its strings:
//
//   - a command holding |, < or > anywhere names no file;
//   - the command is split into its simple commands; each must be one of the
//     read forms below, or, when there are several, echo, printf, true or a
//     colon followed by a word character (/^\s*(echo|printf|true|:)\b/);
//     any other part cancels them all;
//   - sed with -n (or another short flag holding n and no i, or --quiet or
//     --silent), no -i, -e, --in-place or --expression, and exactly a
//     script 'N,Mp' or 'Np' and one file;
//   - cat with only -n or --number, nl with no flag, bat and batcat with
//     only -n, --number, -p or --plain, and exactly one file, not -;
//   - head and tail with only -n N, --lines N, --lines=N, -nN or -N (N not
//     0) and exactly one file, not -;
//   - grep, egrep, fgrep or rg with a pattern and one file, not - and with
//     no *, ?, [ or {, only as the whole command and only on exit 0, with
//     the context flags (-A, -B, -C N, -A3, --context=3 and, for rg,
//     --context 3) and the flags of a fixed list.
//
// The same parser, but for whether cat, nl and bat number their output, is
// in 2.1.284 and 2.1.286, and the call is made under the same conditions.
// readCommandFiles implements a subset of it: where it is unsure (shell
// syntax it does not read itself, a flag outside its list), it names no file,
// so the adapter derives nothing.

// harnessReadVersions are the versions whose binary was read for the rule.
var harnessReadVersions = map[string]bool{"2.1.284": true, "2.1.286": true, "2.1.296": true}

// harnessRead is one file the harness reads after a Bash call.
type harnessRead struct {
	path string
	// exitZero is set for the search forms, which the harness reads only
	// when the command exited 0.
	exitZero bool
}

// readCommandFiles returns the files the harness reads after a Bash call of
// command, as the command names them (relative or absolute), or nil when it
// reads none or the command uses shell syntax this reader does not follow.
func readCommandFiles(command string) []harnessRead {
	if strings.ContainsAny(command, "|<>") {
		return nil
	}
	parts, ok := simpleCommands(command)
	if !ok || len(parts) == 0 {
		return nil
	}
	var out []harnessRead
	for _, p := range parts {
		if r, ok := readForm(p.words, len(parts) == 1); ok && p.plainCommand {
			out = append(out, r)
			continue
		}
		if len(parts) > 1 && noOutput(p) {
			continue
		}
		return nil
	}
	return out
}

// part is one simple command: its words with the quoting undone, and whether
// its first word was written without quotes.
type part struct {
	words        []string
	plainCommand bool
}

// simpleCommands splits a command line at unquoted ;, && and newlines (a |
// never reaches it). ok is false when the line holds anything else the shell
// gives a meaning to (expansions, substitutions, globs, a tilde, escapes,
// background &, grouping, a comment, history expansion), an empty word, an
// unterminated quote, or an empty command anywhere but after a final ; or
// newline.
func simpleCommands(s string) ([]part, bool) {
	var parts []part
	var cur part
	var word strings.Builder
	inWord, quoted := false, false
	endWord := func() bool {
		if !inWord {
			return true
		}
		w := word.String()
		if w == "" {
			return false
		}
		if len(cur.words) == 0 {
			cur.plainCommand = !quoted
		}
		cur.words = append(cur.words, w)
		word.Reset()
		inWord, quoted = false, false
		return true
	}
	endPart := func() bool {
		if !endWord() || len(cur.words) == 0 {
			return false
		}
		parts = append(parts, cur)
		cur = part{}
		return true
	}
	// afterAnd is set from a && until the next word starts: a line may end
	// after a ; or a newline, not after a &&.
	afterAnd := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\'', '"':
			j := strings.IndexByte(s[i+1:], c)
			if j < 0 {
				return nil, false
			}
			body := s[i+1 : i+1+j]
			if c == '"' && strings.ContainsAny(body, "$`\\!") {
				return nil, false
			}
			word.WriteString(body)
			inWord, quoted, afterAnd = true, true, false
			i += j + 1
		case ' ', '\t':
			if !endWord() {
				return nil, false
			}
		case ';', '\n':
			if !endPart() {
				return nil, false
			}
		case '&':
			if i+1 >= len(s) || s[i+1] != '&' || !endPart() {
				return nil, false
			}
			i++
			afterAnd = true
		case '$', '`', '\\', '(', ')', '{', '}', '*', '?', '[', ']', '~', '#', '!':
			return nil, false
		default:
			word.WriteByte(c)
			inWord, afterAnd = true, false
		}
	}
	if !endWord() {
		return nil, false
	}
	if len(cur.words) > 0 {
		parts = append(parts, cur)
	} else if afterAnd {
		return nil, false
	}
	return parts, true
}

// noOutput reports whether a part is one the harness lets stand beside a read
// form: echo, printf or true written plainly as the command. A colon counts
// for the harness only when a word character follows it, so it is left out.
func noOutput(p part) bool {
	if !p.plainCommand || len(p.words) == 0 {
		return false
	}
	switch p.words[0] {
	case "echo", "printf", "true":
		return true
	}
	return false
}

var (
	sedRange  = regexp.MustCompile(`^(\d+),(\d+)p$`)
	sedLine   = regexp.MustCompile(`^(\d+)p$`)
	digits    = regexp.MustCompile(`^\d+$`)
	catFlags  = map[string]map[string]bool{"cat": {"-n": true, "--number": true}, "nl": {}, "bat": {"-n": true, "--number": true, "-p": true, "--plain": true}, "batcat": {"-n": true, "--number": true, "-p": true, "--plain": true}}
	ctxShort  = regexp.MustCompile(`^-[ABC]\d+$`)
	ctxLong   = regexp.MustCompile(`^--(?:after-context|before-context|context)=\d+$`)
	grepShort = regexp.MustCompile(`^-[niwxEFGPHh]+$`)
	rgShort   = regexp.MustCompile(`^-[iSswxFnNHUP]+$`)
	grepLong  = map[string]bool{"--line-number": true, "--ignore-case": true, "--word-regexp": true, "--line-regexp": true, "--extended-regexp": true, "--fixed-strings": true, "--basic-regexp": true, "--perl-regexp": true, "--with-filename": true, "--no-filename": true, "--color=never": true, "--color=auto": true}
	rgLong    = map[string]bool{"--ignore-case": true, "--smart-case": true, "--case-sensitive": true, "--word-regexp": true, "--line-regexp": true, "--fixed-strings": true, "--line-number": true, "--no-line-number": true, "--with-filename": true, "--no-filename": true, "--multiline": true, "--pcre2": true}
)

// readForm reports whether words are one of the read forms, and the file it
// names. The search forms count only when the part is the whole command.
func readForm(w []string, whole bool) (harnessRead, bool) {
	if len(w) == 0 {
		return harnessRead{}, false
	}
	switch w[0] {
	case "sed":
		return sedForm(w)
	case "cat", "nl", "bat", "batcat":
		return catForm(w)
	case "head", "tail":
		return headForm(w)
	case "grep", "egrep", "fgrep", "rg":
		if whole {
			return searchForm(w)
		}
	}
	return harnessRead{}, false
}

// sedForm: sed -n 'N,Mp' FILE or sed -n 'Np' FILE, -n also as --quiet or
// --silent, and no other flag.
func sedForm(w []string) (harnessRead, bool) {
	quiet := false
	var args []string
	for _, a := range w[1:] {
		switch {
		case a == "-n" || a == "--quiet" || a == "--silent":
			quiet = true
		case strings.HasPrefix(a, "-"):
			return harnessRead{}, false
		default:
			args = append(args, a)
		}
	}
	if !quiet || len(args) != 2 || !sedRange.MatchString(args[0]) && !sedLine.MatchString(args[0]) {
		return harnessRead{}, false
	}
	return harnessRead{path: args[1]}, true
}

func catForm(w []string) (harnessRead, bool) {
	allowed := catFlags[w[0]]
	file := ""
	for _, a := range w[1:] {
		if strings.HasPrefix(a, "-") && a != "-" {
			if !allowed[a] {
				return harnessRead{}, false
			}
			continue
		}
		if file != "" {
			return harnessRead{}, false
		}
		file = a
	}
	if file == "" || file == "-" {
		return harnessRead{}, false
	}
	return harnessRead{path: file}, true
}

func headForm(w []string) (harnessRead, bool) {
	file := ""
	for i := 1; i < len(w); i++ {
		a := w[i]
		n := ""
		switch {
		case a == "-n" || a == "--lines":
			if i+1 >= len(w) {
				return harnessRead{}, false
			}
			i++
			n = w[i]
		case strings.HasPrefix(a, "--lines="):
			n = strings.TrimPrefix(a, "--lines=")
		case strings.HasPrefix(a, "-n") && digits.MatchString(a[2:]):
			n = a[2:]
		case strings.HasPrefix(a, "-") && digits.MatchString(a[1:]):
			n = a[1:]
		case strings.HasPrefix(a, "-"):
			return harnessRead{}, false
		default:
			if file != "" {
				return harnessRead{}, false
			}
			file = a
			continue
		}
		if !digits.MatchString(n) || strings.Trim(n, "0") == "" {
			return harnessRead{}, false
		}
	}
	if file == "" {
		return harnessRead{}, false
	}
	return harnessRead{path: file}, true
}

func searchForm(w []string) (harnessRead, bool) {
	rg := w[0] == "rg"
	short, long := grepShort, grepLong
	if rg {
		short, long = rgShort, rgLong
	}
	var args []string
	for i := 1; i < len(w); i++ {
		a := w[i]
		if !strings.HasPrefix(a, "-") || a == "-" {
			args = append(args, a)
			continue
		}
		if a == "-A" || a == "-B" || a == "-C" || rg && (a == "--after-context" || a == "--before-context" || a == "--context") {
			if i+1 >= len(w) || !digits.MatchString(w[i+1]) {
				return harnessRead{}, false
			}
			i++
			continue
		}
		if ctxShort.MatchString(a) || ctxLong.MatchString(a) || short.MatchString(a) || long[a] {
			continue
		}
		return harnessRead{}, false
	}
	if len(args) != 2 || args[1] == "-" || strings.ContainsAny(args[1], "*?[{") {
		return harnessRead{}, false
	}
	return harnessRead{path: args[1], exitZero: true}, true
}

// resolveRead is the absolute path the harness reads for a file a command
// names, relative to the session's working directory.
func resolveRead(cwd, path string) string {
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Join(cwd, path)
}
