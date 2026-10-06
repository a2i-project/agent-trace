package claudecode

import "strings"

// Claude Code runs every Bash call as
//
//	<shell> -c [-l] source <snapshot> ... && eval '<command>' < /dev/null && pwd -P >| /tmp/claude-<n>-cwd
//
// so the argv the process probe sees is the wrapper, not the command the agent
// claimed (07 D6). The wrapper is specific to the harness version, which is why
// recovering the command lives here and not in pkg/matching.

const snapshotMarker = "shell-snapshots/snapshot-"

// evalPayload recovers the command from an observed wrapper command line. ok is
// false when the line is not a Claude Code wrapper or the payload cannot be
// parsed, in which case the caller leaves the line alone: a line that does not
// normalize shows up as a mismatch rather than being guessed at.
func evalPayload(line string) (payload string, ok bool) {
	if !strings.Contains(line, snapshotMarker) {
		return "", false
	}
	const needle = "&& eval "
	i := strings.Index(line, needle)
	if i < 0 {
		return "", false
	}
	word, ok := shellWord(line[i+len(needle):])
	if !ok {
		return "", false
	}
	return word, true
}

// shellWord reads one word from the start of s the way a POSIX shell would,
// undoing single quotes, double quotes and backslash escapes, and stopping at
// the first unquoted blank. It reports false for an unterminated quote.
func shellWord(s string) (string, bool) {
	var b strings.Builder
	i := 0
	for i < len(s) {
		c := s[i]
		switch c {
		case ' ', '\t', '\n':
			if i == 0 {
				return "", false
			}
			return b.String(), true
		case '\'':
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				return "", false
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
				return "", false
			}
		case '\\':
			if i+1 >= len(s) {
				return "", false
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
		return "", false
	}
	return b.String(), true
}
