package codex

import (
	"math"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/agent-trace/agent-trace/pkg/content"
)

// An update by apply_patch is recorded as a unified diff only (I-82). When
// the session's own record already holds the whole content of the file
// before the update, the diff applied to it is the content the update
// wrote, and the update's write claims its hash (I-87). The record holds it
// after an add of the file, after an update whose content was known, and
// after a command that is exactly `cat <path>` whose recorded output is
// complete. Nothing is guessed: a diff that does not apply exactly, an
// output that may be cut, or anything that may have changed the file
// between leaves the update without a hash, as before.

// stepKind is what one item of the rollout says about file content.
type stepKind int

const (
	stepRead    stepKind = iota // a whole-file cat: the file's content
	stepAdd                     // an add: the file's content
	stepUpdate                  // an update: a diff of the file
	stepForget                  // a delete or a move: the file's content is no longer known
	stepDisturb                 // anything that may write any file: a command that is not a whole-file read, a failed change, an unknown item
)

// step is one item's statement about file content, in record order.
type step struct {
	kind      stepKind
	paths     []string // the file (two for a move)
	text      string   // the content (read, add) or the diff (update)
	hasDiff   bool
	turn      string
	completed time.Time  // the item's completion
	started   *time.Time // the item's start (started_at_ms), when recorded
	command   bool       // the item is a CommandExecution
	effect    int        // the update's effect, -1 for none
	claim     int        // the index of the update's write among its effect's claims
}

// parsedCmd is one entry of a command item's parsed_cmd: Codex's own
// reading of what the command does.
type parsedCmd struct {
	Type string `json:"type"`
	Cmd  string `json:"cmd"`
	Path string `json:"path"`
}

// catWord is the one path word a whole-file read may name: no quoting, no
// option, no glob, no variable.
var catWord = regexp.MustCompile(`^[A-Za-z0-9_./+][A-Za-z0-9_./+-]*$`)

// cutMarkers are the strings Codex 0.166.0 writes where it cuts a command's
// output (**Reported**, the strings of its binary: "tokens truncated",
// "chars truncated", "... command output truncated for persistence ...",
// "[omitted ... items ...]"). An output holding any of them, or the
// replacement character a lossy UTF-8 conversion leaves, may not be the
// file's bytes.
var cutMarkers = []string{"truncated", "[omitted ", "�"}

// wholeFileRead is the file and the content a command item states when it
// is exactly `cat <word>`, completed with exit code 0, which Codex parsed
// as one read of that word, run in a recorded working directory (for a
// relative word), with an output that holds no cut marker and is valid
// UTF-8. Anything else is not a whole-file read.
func wholeFileRead(it item) (string, string, bool) {
	if it.Status != "completed" || it.ExitCode == nil || *it.ExitCode != 0 || it.AggregatedOutput == nil {
		return "", "", false
	}
	cmd, ok := commandOf(it.Command)
	if !ok {
		return "", "", false
	}
	word, ok := strings.CutPrefix(cmd, "cat ")
	if !ok || !catWord.MatchString(word) || len(it.ParsedCmd) != 1 {
		return "", "", false
	}
	if pc := it.ParsedCmd[0]; pc.Type != "read" || pc.Cmd != cmd || pc.Path != word {
		return "", "", false
	}
	for _, seg := range strings.Split(word, "/") {
		if seg == ".." {
			return "", "", false
		}
	}
	path := word
	if !filepath.IsAbs(word) {
		cwd, ok := itemCwd(it.Cwd)
		if !ok {
			return "", "", false
		}
		path = filepath.Join(cwd, word)
	}
	path = filepath.Clean(path)
	out := *it.AggregatedOutput
	if !utf8.ValidString(out) {
		return "", "", false
	}
	for _, m := range cutMarkers {
		if strings.Contains(out, m) {
			return "", "", false
		}
	}
	return path, out, true
}

// itemCwd is a command item's working directory, recorded as a file URI
// (or an absolute path); one with a percent escape is not read.
func itemCwd(cwd string) (string, bool) {
	p := strings.TrimPrefix(cwd, "file://")
	if p == "" || !filepath.IsAbs(p) || strings.Contains(p, "%") || filepath.Clean(p) != p {
		return "", false
	}
	return p, true
}

// hunkHeader is a hunk's header as Codex 0.166.0 writes it, with nothing
// after the second @@.
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

// hunkRange reads a header's start and count (one when the count is left
// out).
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

// reconstruct claims the hash of each update whose file's whole prior
// content the rollout records (I-87), walking the steps in record order.
// The content before an update is known from the latest step on the file:
// an add, a whole-file read, or an update whose content was known. It is
// used only when that step completed before the update started (their
// recorded milliseconds, strictly) and when no step that may write any
// file may have run between them: a disturbing step is ruled out only when
// it completed before the cell of the content's step started, or when the
// cell it is joined to started after the update started. A step joined to
// no single cell may have run at any time. cellStart gives the start of
// the cell a step is joined to: for a command that outlived its cell, the
// cell that started it (I-94). It returns how many updates claim a hash
// and how many do not.
func reconstruct(steps []step, effects []effect, cellStart func(step) (time.Time, bool)) (claimed, unclaimed int) {
	type known struct {
		text string
		from int // the step that stated it
	}
	state := map[string]known{}
	quiet := func(from, upd int) bool {
		src, u := steps[from], steps[upd]
		if u.started == nil || !src.completed.Before(*u.started) {
			return false
		}
		lo, srcJoined := cellStart(src)
		for _, d := range steps {
			if d.kind != stepDisturb {
				continue
			}
			if srcJoined && d.completed.Before(lo) {
				continue
			}
			if dStart, ok := cellStart(d); ok && dStart.After(*u.started) {
				continue
			}
			return false
		}
		return true
	}
	for i, s := range steps {
		switch s.kind {
		case stepRead, stepAdd:
			state[s.paths[0]] = known{s.text, i}
		case stepUpdate:
			p := s.paths[0]
			k, ok := state[p]
			delete(state, p)
			if !ok || !s.hasDiff || s.effect < 0 || !quiet(k.from, i) {
				unclaimed++
				continue
			}
			text, ok := applyDiff(k.text, s.text)
			if !ok {
				unclaimed++
				continue
			}
			h := content.SHA256Bytes([]byte(text))
			effects[s.effect].claims[s.claim].OutputHash = &h
			state[p] = known{text, i}
			claimed++
		case stepForget:
			for _, p := range s.paths {
				delete(state, p)
			}
		}
	}
	return claimed, unclaimed
}
