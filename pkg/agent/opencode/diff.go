package opencode

import (
	"math"
	"regexp"
	"strconv"
	"strings"
)

// The edit's diff is applied as the Codex adapter applies an update's
// (I-87): the same rule, kept here since the two packages share no code.
// OpenCode's diff (the jsdiff library's) writes its hunk headers in the
// same form.

// hunkHeader is a hunk's header, with nothing after the second @@.
var hunkHeader = regexp.MustCompile(`^@@ -([0-9]+)(?:,([0-9]+))? \+([0-9]+)(?:,([0-9]+))? @@$`)

const noNewline = `\ No newline at end of file`

// applyDiff applies a unified diff of hunks only (no file headers) to old,
// and reports false unless every hunk applies exactly: hunks in order and
// apart, every context and removed line equal to the file's line at its
// place, the counts of each header equal to its lines, and the new start
// equal to where the hunk lands.
func applyDiff(old, diff string) (string, bool) {
	if diff == "" || !strings.HasSuffix(diff, "\n") {
		return "", false
	}
	oldLines := splitLines(old)
	dl := strings.Split(strings.TrimSuffix(diff, "\n"), "\n")
	var out []string
	pos := 0 // the next line of old to copy
	for i := 0; i < len(dl); {
		m := hunkHeader.FindStringSubmatch(dl[i])
		if m == nil {
			return "", false
		}
		i++
		oldStart, oldCount, ok1 := hunkRange(m[1], m[2])
		newStart, newCount, ok2 := hunkRange(m[3], m[4])
		if !ok1 || !ok2 || (oldCount == 0 && newCount == 0) {
			return "", false
		}
		start := oldStart - 1
		if oldCount == 0 {
			start = oldStart
		}
		if start < pos || start > len(oldLines) {
			return "", false
		}
		out = append(out, oldLines[pos:start]...)
		landed := len(out) + 1
		if newCount == 0 {
			landed = len(out)
		}
		if newStart != landed {
			return "", false
		}
		// The hunk's lines, each with its newline unless a marker follows.
		type line struct {
			op   byte
			text string
		}
		var body []line
		seenOld, seenNew := 0, 0
		for i < len(dl) {
			l := dl[i]
			if l != noNewline && seenOld == oldCount && seenNew == newCount {
				break
			}
			i++
			if l == noNewline {
				if len(body) == 0 || !strings.HasSuffix(body[len(body)-1].text, "\n") {
					return "", false
				}
				body[len(body)-1].text = strings.TrimSuffix(body[len(body)-1].text, "\n")
				continue
			}
			if l == "" {
				return "", false
			}
			op := l[0]
			switch op {
			case ' ':
				seenOld++
				seenNew++
			case '-':
				seenOld++
			case '+':
				seenNew++
			default:
				return "", false
			}
			body = append(body, line{op, l[1:] + "\n"})
		}
		if seenOld != oldCount || seenNew != newCount {
			return "", false
		}
		at := start
		for _, l := range body {
			switch l.op {
			case ' ', '-':
				if at >= len(oldLines) || oldLines[at] != l.text {
					return "", false
				}
				at++
				if l.op == ' ' {
					out = append(out, l.text)
				}
			case '+':
				out = append(out, l.text)
			}
		}
		pos = at
	}
	out = append(out, oldLines[pos:]...)
	return strings.Join(out, ""), true
}

func hunkRange(start, count string) (int, int, bool) {
	s, err := strconv.Atoi(start)
	if err != nil {
		return 0, 0, false
	}
	c := 1
	if count != "" {
		if c, err = strconv.Atoi(count); err != nil {
			return 0, 0, false
		}
	}
	if (c > 0 && s < 1) || s > math.MaxInt32 || c > math.MaxInt32 {
		return 0, 0, false
	}
	return s, c, true
}

// splitLines splits content into lines that keep their newline; a last
// line without one is kept as it is.
func splitLines(s string) []string {
	var out []string
	for s != "" {
		i := strings.IndexByte(s, '\n')
		if i < 0 {
			out = append(out, s)
			break
		}
		out = append(out, s[:i+1])
		s = s[i+1:]
	}
	return out
}
