package codex

import (
	"regexp"
	"strings"
)

// The command wrapper of Codex 0.166.0 under danger-full-access, as the
// first capture shows it (I-82). Each exec_command call is a new child of
// the harness process whose first exec is the harness binary's process
// setup,
//
//	/proc/self/exe --codex-run-as-process-setup <fd> <pid> pipe '' <cwd> /bin/bash /bin/bash -c <script>
//
// which then execs /bin/bash -c <script> and, through the script's last
// line, /bin/bash -c <command> in the same process: the rollout records the
// call as ["/bin/bash", "-lc", <command>], but no login shell runs. The
// script restores the shell snapshot's environment: lines that save and
// restore a fixed set of variables, a source of the snapshot file under
// ~/.codex/shell_snapshots, a prefix of the harness's own directory to
// PATH, and finally
//
//	exec '/bin/bash' -c '<command>'
//
// with the command as one single-quoted shell word. recoverCommand reads the
// command only when every line before the last is one of those shapes, so a
// command run before or after the payload, a second payload or another
// program that merely contains the marker is never recovered and shows as a
// mismatch (D6).

var (
	setupPrefix = regexp.MustCompile(`^/proc/self/exe --codex-run-as-process-setup [0-9]+ [0-9]+ pipe  .*? /bin/bash /bin/bash -c `)
	shellPrefix = "/bin/bash -c "
	execLine    = "exec '/bin/bash' -c "

	ident    = `[A-Za-z_][A-Za-z0-9_]*`
	override = `__CODEX_SNAPSHOT_(?:PROXY_)?OVERRIDE`
	// One whole line of the restoring script; the variable a line names
	// twice is checked to be the same one by sameVariable.
	scriptLines = []*regexp.Regexp{
		regexp.MustCompile(`^$`),
		regexp.MustCompile(`^` + override + `_SET_[0-9]+="\$\{` + ident + `\+x\}"$`),
		regexp.MustCompile(`^` + override + `_[0-9]+="\$\{` + ident + `-\}"$`),
		regexp.MustCompile(`^__CODEX_SNAPSHOT_PROXY_ENV_SET="\$\{` + ident + `\+x\}"$`),
		regexp.MustCompile(`^if \. '/(?:home/[^/']+|root)/\.codex/shell_snapshots/[0-9a-f-]{36}\.[0-9]+\.sh' >/dev/null 2>&1; then :; fi$`),
		regexp.MustCompile(`^if \[ -n "\$\{` + override + `_SET_[0-9]+\}" \]; then$`),
		regexp.MustCompile(`^if \[ -n "\$__CODEX_SNAPSHOT_PROXY_ENV_SET" \] \|\| \[ -n "\$\{` + ident + `\+x\}" \]; then$`),
		regexp.MustCompile(`^builtin unset (` + override + `_SET_[0-9]+ ` + override + `_[0-9]+) 2>/dev/null \|\| command unset (` + override + `_SET_[0-9]+ ` + override + `_[0-9]+)$`),
		regexp.MustCompile(`^else builtin unset (` + ident + `) 2>/dev/null \|\| command unset (` + ident + `); fi$`),
		regexp.MustCompile(`^  if \[ -z "\$\{(` + ident + `)\+x\}" \] \|\| \[ "\$\{(` + ident + `)-\}" != "\$\{` + override + `_[0-9]+\}" \]; then export (` + ident + `)="\$\{` + override + `_[0-9]+\}"; else export (` + ident + `); fi$`),
		regexp.MustCompile(`^fi$`),
		regexp.MustCompile(`^if \[ -n "\$\{PATH:-\}" \]; then export PATH='([^']*)':"\$PATH"; else export PATH='([^']*)'; fi$`),
	}
)

// sameVariable reports whether every group a line's pattern captured names
// the same thing, as each of those lines names one variable (or one pair of
// override variables, or one directory) several times.
func sameVariable(groups []string) bool {
	for _, g := range groups[1:] {
		if g != groups[0] {
			return false
		}
	}
	return true
}

// scriptLineOK reports whether line is one of the restoring script's shapes.
func scriptLineOK(line string) bool {
	for _, re := range scriptLines {
		if m := re.FindStringSubmatch(line); m != nil {
			return len(m) < 2 || sameVariable(m[1:])
		}
	}
	return false
}

// recoverCommand returns the command an exec of the wrapper runs: target is
// the process setup's command line or the restoring shell's, as the proc
// probe joins its argv. With truncated, the line is a prefix of the real one
// (P-19), and what the probe kept of the command word is returned as a
// prefix of the command (V-26).
func recoverCommand(target string, truncated bool) (string, bool) {
	var script string
	if loc := setupPrefix.FindStringIndex(target); loc != nil {
		script = target[loc[1]:]
	} else if s, ok := strings.CutPrefix(target, shellPrefix); ok {
		script = s
	} else {
		return "", false
	}
	// The payload follows the last line of the script that is the exec
	// line's start; every line before it must be the script's.
	at := strings.LastIndex(script, "\n"+execLine)
	if at < 0 {
		return "", false
	}
	// A command word may itself hold a newline followed by the exec line's
	// text, so the split is taken at the first such line whose prefix is the
	// script and whose rest reads as one word.
	for start := 0; start <= at; {
		i := strings.Index(script[start:], "\n"+execLine)
		if i < 0 {
			break
		}
		i += start
		if scriptOK(script[:i]) {
			word := script[i+1+len(execLine):]
			if cmd, ok := shellWord(word); ok {
				return cmd, true
			}
			if truncated {
				if cmd, ok := shellWordPrefix(word); ok {
					return cmd, true
				}
			}
			return "", false
		}
		start = i + 1
	}
	return "", false
}

func scriptOK(script string) bool {
	for _, line := range strings.Split(script, "\n") {
		if !scriptLineOK(line) {
			return false
		}
	}
	return true
}

// safeBare is a word the quoting leaves bare.
var safeBare = regexp.MustCompile(`^[A-Za-z0-9_@%+=:,./-]+$`)

// shellWord reads s as exactly one POSIX shell word made of single-quoted
// segments and backslash-escaped single quotes, as the harness quotes the
// command, or a bare word of characters that need no quoting.
func shellWord(s string) (string, bool) {
	if safeBare.MatchString(s) {
		return s, true
	}
	out, rest, ok := quoted(s)
	return out, ok && rest == "" && s != ""
}

// shellWordPrefix reads what is left of a word the probe cut: the segments
// read whole and the open segment's text.
func shellWordPrefix(s string) (string, bool) {
	out, rest, _ := quoted(s)
	if strings.HasPrefix(rest, "'") && !strings.Contains(rest[1:], "'") {
		return out + rest[1:], true
	}
	if rest == "\\" {
		return out, true
	}
	return out, rest == "" && s != ""
}

// quoted reads single-quoted segments and \' escapes from the start of s,
// returning their text and what is left.
func quoted(s string) (string, string, bool) {
	var b strings.Builder
	for s != "" {
		switch {
		case strings.HasPrefix(s, `\'`):
			b.WriteByte('\'')
			s = s[2:]
		case s[0] == '\'':
			end := strings.IndexByte(s[1:], '\'')
			if end < 0 {
				return b.String(), s, false
			}
			b.WriteString(s[1 : 1+end])
			s = s[2+end:]
		default:
			return b.String(), s, false
		}
	}
	return b.String(), "", true
}
