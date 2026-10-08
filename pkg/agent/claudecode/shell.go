package claudecode

import (
	"regexp"
	"strings"
)

// Claude Code runs every Bash call as
//
//	<shell> -c [-l] source <snapshot> ... && eval '<command>' < /dev/null && pwd -P >| /tmp/claude-<n>-cwd
//
// so the argv the process probe sees is the wrapper, not the command the agent
// claimed (D6). The wrapper is specific to the harness version, which is why
// recovering the command lives here and not in pkg/matching.

const snapshotMarker = "shell-snapshots/snapshot-"

// wrapperHead is everything a Claude Code wrapper says before the eval word:
// the shell, `-c` with an optional `-l`, the snapshot source and a preamble of
// known clauses. The id patterns are the raw ones (canonicalIDs runs later),
// because the payload itself must not be rewritten. A preamble clause not in
// the allowlist, any other program, or anything after the suffix means the
// line is not the wrapper, and the command is not recovered.
var wrapperHead = regexp.MustCompile(
	`^(?:/bin/bash|/usr/bin/bash|/bin/zsh|/usr/bin/zsh|/bin/sh|/usr/bin/sh) -c (?:-l )?` +
		`source \S+/\.claude/shell-snapshots/snapshot-bash-\d+-[0-9a-z]+\.sh 2>/dev/null \|\| true` +
		`(?: && (?:shopt -u extglob 2>/dev/null \|\| true|\{ \\builtin unalias -- '[^']*'; \\builtin unset -f -- '[^']*'; \} >/dev/null 2>&1 \|\| true))*` +
		` && eval `)

// wrapperTail is what follows the eval word, to the end of the line.
var wrapperTail = regexp.MustCompile(`^ < /dev/null && pwd -P >\| /tmp/claude-[0-9a-z]+-cwd$`)

// evalPayload recovers the command from an observed wrapper command line. ok is
// false when the line is not exactly a Claude Code wrapper around one eval
// word, in which case the caller leaves the line alone: a line that does not
// normalize shows up as a mismatch rather than being guessed at. Checking the
// whole shape matters: a wrapper with a command appended after the suffix, or
// run before the source, or a different program that merely contains the
// marker, would otherwise normalize to the claimed command and hide the rest
// (I-26).
func evalPayload(line string) (payload string, ok bool) {
	if !strings.Contains(line, snapshotMarker) {
		return "", false
	}
	loc := wrapperHead.FindStringIndex(line)
	if loc == nil {
		return "", false
	}
	rest := line[loc[1]:]
	word, n, ok := shellWord(rest)
	if !ok || !wrapperTail.MatchString(rest[n:]) {
		return "", false
	}
	return word, true
}

// shellWord reads one word from the start of s the way a POSIX shell would,
// undoing single quotes, double quotes and backslash escapes, and stopping at
// the first unquoted blank. It returns the word and how many bytes of s it
// spans, and reports false for an unterminated quote.
func shellWord(s string) (string, int, bool) {
	var b strings.Builder
	i := 0
	for i < len(s) {
		c := s[i]
		switch c {
		case ' ', '\t', '\n':
			if i == 0 {
				return "", 0, false
			}
			return b.String(), i, true
		case '\'':
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				return "", 0, false
			}
			b.WriteString(s[i+1 : i+1+j])
			i += j + 2
		case '"':
			i++
			closed := false
			for i < len(s) {
				if s[i] == '\\' && i+1 < len(s) && strings.ContainsRune("\"\\$`\n", rune(s[i+1])) {
					if s[i+1] != '\n' {
						b.WriteByte(s[i+1])
					}
					i += 2
					continue
				}
				if s[i] == '"' {
					closed = true
					i++
					break
				}
				b.WriteByte(s[i])
				i++
			}
			if !closed {
				return "", 0, false
			}
		case '\\':
			if i+1 >= len(s) {
				return "", 0, false
			}
			if s[i+1] != '\n' {
				b.WriteByte(s[i+1])
			}
			i += 2
		default:
			b.WriteByte(c)
			i++
		}
	}
	if b.Len() == 0 {
		return "", 0, false
	}
	return b.String(), len(s), true
}

// The harness's own commands name a per-session snapshot file and a per-call
// working-directory file by ids that differ every run, so two runs of the same
// harness behaviour would never match. The ids are replaced by a fixed token on
// the observed side, which is the only side they appear on: a claim names the
// agent's command, never these.
var (
	snapshotID = regexp.MustCompile(`snapshot-bash-\d+-[0-9a-z]+\.sh`)
	cwdFileID  = regexp.MustCompile(`/tmp/claude-[0-9a-z]+-cwd`)
	// The snapshot command writes a heredoc whose delimiter is random.
	heredocID = regexp.MustCompile(`PATH_END_[0-9a-z]+`)
)

func canonicalIDs(s string) string {
	s = snapshotID.ReplaceAllString(s, "snapshot-bash-N.sh")
	s = cwdFileID.ReplaceAllString(s, "/tmp/claude-N-cwd")
	return heredocID.ReplaceAllString(s, "PATH_END_N")
}

// Grep and Glob run as ripgrep, which Claude Code embeds in its own binary and
// starts as a child of the agent, so each search is a level-1 command whose
// program is <install dir>/claude/versions/<version> and whose first argument is
// --no-config. A paired capture of 2.1.286 showed three shapes:
//
//	... --no-config --files --hidden <workspace>                        harness startup
//	... --no-config --files --hidden --no-ignore --max-depth 4 ...      harness startup
//	... --no-config --hidden --glob !.git ... -l --null <pattern> .     Grep
//	... --no-config --files --null --glob <pattern> --sort=modified ... Glob
//
// A search's pattern is not recoverable from the arguments in general (options
// take values, the pattern can follow -e), and what a search reads is not
// something a claim is verified against, so a search is claimed and observed as
// the kind of search only. The harness's own startup listings keep their exact
// text, so a baseline names them.
const (
	// SearchGrep and SearchGlob are the claimed and normalized targets of a
	// Grep and a Glob call.
	SearchGrep = "claude-code search:grep"
	SearchGlob = "claude-code search:glob"
)

var embeddedRipgrep = regexp.MustCompile(`^\S*/claude/versions/[0-9][0-9.]* --no-config (.*)$`)

// searchKind classifies an observed command line as a Grep or a Glob. ok is
// false for anything else, including the harness's own listings.
func searchKind(line string) (target string, ok bool) {
	m := embeddedRipgrep.FindStringSubmatch(line)
	if m == nil {
		return "", false
	}
	args := " " + m[1] + " "
	switch {
	case strings.Contains(args, " --files ") && strings.Contains(args, " --null "):
		return SearchGlob, true
	case !strings.Contains(args, " --files "):
		return SearchGrep, true
	}
	return "", false
}
