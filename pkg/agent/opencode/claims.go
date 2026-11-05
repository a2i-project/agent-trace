package opencode

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/content"
	"github.com/agent-trace/agent-trace/pkg/models"
)

// The tools of OpenCode 1.19.5 that Qwen3-235B-A22B is offered (I-115),
// and the statuses of a tool part.
const (
	toolBash     = "bash"
	toolRead     = "read"
	toolWrite    = "write"
	toolEdit     = "edit"
	toolTask     = "task"
	toolWebFetch = "webfetch"
	toolGrep     = "grep"
	toolGlob     = "glob"

	// toolLoaded is the claim of an instruction file a read added to the
	// model's context (the read's metadata.loaded).
	toolLoaded = "read:loaded"

	statusCompleted = "completed"
	statusError     = "error"
)

// nonEffectful are tools that act on nothing the probes see: todowrite
// writes the session's todo rows into the database, invalid is the
// harness's answer to a malformed call, and question, plan_enter and
// plan_exit are denied in a run (I-112). task starts a subagent session,
// whose own calls are read from its session.
var nonEffectful = map[string]bool{
	"todowrite": true, "todoread": true, "invalid": true, "question": true,
	"plan_enter": true, "plan_exit": true, toolTask: true,
}

// claimParts turns the session's tool parts, in execution order, into
// claims, counting every call that claims nothing.
func claimParts(parts []toolPart, root string, rep *agent.Report) models.Trajectory {
	var tr models.Trajectory
	unknown := map[string]bool{}
	known := newContents(disturbers(parts))
	var claimed, unclaimedContent, dirReads, httpFetches int
	// knownFiles are the paths an earlier completed read, write or edit
	// showed to be a file (I-142).
	knownFiles := map[string]bool{}
	for _, p := range parts {
		rep.ToolCalls++
		tool, st := p.data.Tool, p.data.State
		if st.Status != statusCompleted {
			rep.Count(fmt.Sprintf("%s (status %s)", tool, st.Status))
			continue
		}
		base := models.TrajectoryEntry{Timestamp: p.start, Tool: tool, BlockID: p.message}
		end := p.end
		base.End = &end
		if p.session != root {
			base.ThreadID = p.session
		}
		mk := func(a models.ActionType, target string) models.TrajectoryEntry {
			e := base
			e.ActionType, e.Target = a, target
			return e
		}
		switch {
		case tool == toolBash:
			var in struct {
				Command string `json:"command"`
			}
			if json.Unmarshal(st.Input, &in) != nil || in.Command == "" {
				rep.ParseErrors = append(rep.ParseErrors, fmt.Sprintf("part %s: a bash call without a command", p.id))
				continue
			}
			tr = append(tr, mk(models.ProcessExec, in.Command))
		case tool == toolRead:
			path, ok := filePath(p)
			if !ok {
				rep.ParseErrors = append(rep.ParseErrors, fmt.Sprintf("part %s: a read call without a file path", p.id))
				continue
			}
			var out string
			_ = json.Unmarshal(st.Output, &out)
			if strings.Contains(out, "<type>directory</type>") {
				rep.Count("read:directory")
				dirReads++
				continue
			}
			tr = append(tr, mk(models.FileOpen, path))
			knownFiles[path] = true
			var md struct {
				Loaded []string `json:"loaded"`
			}
			_ = json.Unmarshal(st.Metadata, &md)
			for _, l := range md.Loaded {
				if !filepath.IsAbs(l) {
					continue
				}
				e := mk(models.FileOpen, filepath.Clean(l))
				e.Tool = toolLoaded
				tr = append(tr, e)
			}
		case tool == toolWrite:
			path, ok := filePath(p)
			var in struct {
				Content *string `json:"content"`
			}
			if !ok || json.Unmarshal(st.Input, &in) != nil || in.Content == nil {
				rep.ParseErrors = append(rep.ParseErrors, fmt.Sprintf("part %s: a write call without a file path or content", p.id))
				continue
			}
			var md struct {
				Exists *bool `json:"exists"`
			}
			_ = json.Unmarshal(st.Metadata, &md)
			w := mk(models.FileWrite, path)
			if h, ok := known.write(path, *in.Content, md.Exists, p); ok {
				w.OutputHash = &h
				claimed++
			} else {
				unclaimedContent++
			}
			tr = append(tr, mk(models.FileOpen, path), w)
			knownFiles[path] = true
		case tool == toolEdit:
			path, ok := filePath(p)
			if !ok {
				rep.ParseErrors = append(rep.ParseErrors, fmt.Sprintf("part %s: an edit call without a file path", p.id))
				continue
			}
			var md struct {
				Diff string `json:"diff"`
			}
			_ = json.Unmarshal(st.Metadata, &md)
			w := mk(models.FileWrite, path)
			if h, ok := known.edit(path, md.Diff, p); ok {
				w.OutputHash = &h
				claimed++
			} else {
				unclaimedContent++
			}
			tr = append(tr, mk(models.FileOpen, path), w)
			knownFiles[path] = true
		case tool == toolWebFetch:
			var in struct {
				URL string `json:"url"`
			}
			_ = json.Unmarshal(st.Input, &in)
			host, ok := fetchHost(in.URL)
			if !ok {
				rep.Count("webfetch (no https host)")
				httpFetches++
				continue
			}
			tr = append(tr, mk(models.NetConnect, host))
		case nonEffectful[tool]:
			rep.Count(tool)
		case tool == toolGrep || tool == toolGlob:
			folder, ok := searchFolder(p, knownFiles)
			if !ok {
				rep.ParseErrors = append(rep.ParseErrors, fmt.Sprintf("part %s: a %s call without a pattern or a folder", p.id, tool))
				continue
			}
			kind := SearchGrep
			if tool == toolGlob {
				kind = SearchGlob
			}
			tr = append(tr, mk(models.ProcessExec, kind+" "+folder))
		default:
			rep.Count(tool)
			unknown[tool] = true
		}
	}
	for t := range unknown {
		rep.UnknownTools = append(rep.UnknownTools, t)
	}
	sort.Strings(rep.UnknownTools)
	rep.Degradations = append(rep.Degradations,
		"a claim's interval is its call's recorded execution, in milliseconds (IntervalExecution)",
		"exit codes are recorded and not claimed",
		fmt.Sprintf("writes and edits that claim their content: %d; that do not: %d (I-121)", claimed, unclaimedContent))
	if dirReads > 0 {
		rep.Degradations = append(rep.Degradations, fmt.Sprintf("%d read(s) of a directory claim nothing", dirReads))
	}
	if httpFetches > 0 {
		rep.Degradations = append(rep.Degradations, fmt.Sprintf("%d webfetch(es) of a URL that is not https with a host name claim nothing", httpFetches))
	}
	return collapseOpenClaims(tr)
}

// collapseOpenClaims is the claim-side twin of collapseOpens (I-141), as
// Claude Code's (I-32): adjacent opens of one file among the file claims
// become one, across calls, sessions and messages, keeping the first and
// widening its end to the latest. The observed side keeps one open of a
// run of opens of one file by the harness's process that no other file
// event of it breaks, so a read and a later write or edit of the file
// with no other file call between are one open there. Claims of other
// kinds do not break a run: the observed side only ever sees the
// harness's own file events.
func collapseOpenClaims(t models.Trajectory) models.Trajectory {
	out := make(models.Trajectory, 0, len(t))
	lastFile := -1
	for _, e := range t {
		if !isFile(e.ActionType) {
			out = append(out, e)
			continue
		}
		if lastFile >= 0 && e.ActionType == models.FileOpen && out[lastFile].ActionType == models.FileOpen &&
			out[lastFile].Target == e.Target && out[lastFile].ImpliedBy == e.ImpliedBy {
			if e.End != nil && (out[lastFile].End == nil || e.End.After(*out[lastFile].End)) {
				end := *e.End
				out[lastFile].End = &end
			}
			continue
		}
		out = append(out, e)
		lastFile = len(out) - 1
	}
	return out
}

// filePath is a file tool's filePath, absolute, or relative and joined to
// the session's directory as the harness joins it.
func filePath(p toolPart) (string, bool) {
	var in struct {
		FilePath string `json:"filePath"`
	}
	if json.Unmarshal(p.data.State.Input, &in) != nil || in.FilePath == "" {
		return "", false
	}
	if filepath.IsAbs(in.FilePath) {
		return filepath.Clean(in.FilePath), true
	}
	if !filepath.IsAbs(p.dir) {
		return "", false
	}
	return filepath.Join(p.dir, in.FilePath), true
}

// fetchHost is the host a webfetch connects to: an https URL whose host is
// a name, lowercased. The net probe names a TLS connection by its SNI; an
// http URL or an address names none, so neither is claimed.
func fetchHost(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil {
		return "", false
	}
	h := strings.ToLower(u.Hostname())
	if h == "" || net.ParseIP(h) != nil {
		return "", false
	}
	for _, c := range h {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '.', c == '-':
		default:
			return "", false
		}
	}
	return h, true
}

// bom is the byte order mark the write tool keeps or adds.
const bom = "\uFEFF"

// contents is the whole content of each file the session wrote, as far as
// the record states it, with the start of the call that wrote it (I-121).
// A content is used only when no call that may write a file ran at any
// time between that start and the end of the call that uses it.
type contents struct {
	files   map[string]known
	disturb []interval
}

type known struct {
	text string
	from time.Time
}

type interval struct {
	start, end time.Time
	open       bool // no recorded end: it may still run
}

func newContents(d []interval) *contents { return &contents{files: map[string]known{}, disturb: d} }

// disturbers are the calls that may write a file the record does not
// name: a bash command, a call of a tool the adapter does not map and a
// call that did not complete, over their recorded execution. A search
// only reads.
func disturbers(parts []toolPart) []interval {
	var out []interval
	for _, p := range parts {
		t, st := p.data.Tool, p.data.State
		mapped := t == toolRead || t == toolWrite || t == toolEdit || t == toolWebFetch || t == toolGrep || t == toolGlob || nonEffectful[t]
		if st.Status == statusCompleted && mapped {
			continue
		}
		iv := interval{start: p.start, end: p.end, open: st.Time.End == nil}
		if st.Time.Start == nil {
			iv = interval{open: true} // from the beginning, to the end
		}
		out = append(out, iv)
	}
	return out
}

// usable reports whether k may stand for the file's content when the call
// p ends: no disturbing call overlaps [k.from, p.end].
func (c *contents) usable(k known, p toolPart) bool {
	for _, d := range c.disturb {
		if d.start.After(p.end) || (!d.open && d.end.Before(k.from)) {
			continue
		}
		return false
	}
	return true
}

// write records a write of text to path and returns the hash of the bytes
// written, when the record states them. OpenCode writes the content
// without its byte order mark, and adds one when the content or the file
// it replaces had one; so the bytes are the content exactly when the file
// was new (metadata.exists false), when the content starts with the mark,
// or when the session knows the prior content and it has none.
func (c *contents) write(path, text string, exists *bool, p toolPart) (string, bool) {
	prior, knownPrior := c.files[path]
	delete(c.files, path)
	switch {
	case exists == nil:
		return "", false
	case !*exists, strings.HasPrefix(text, bom):
	case knownPrior && c.usable(prior, p) && !strings.HasPrefix(prior.text, bom):
	default:
		return "", false
	}
	c.files[path] = known{text: text, from: p.start}
	return content.SHA256Bytes([]byte(text)), true
}

// edit records an edit of path whose recorded diff is diff and returns the
// hash of the result, when the session knows the file's whole content
// before it, without a byte order mark, and the diff applies to it exactly
// (I-121): the change is taken from the diff, never from the call's
// input, since the edit tool matches its old string loosely.
func (c *contents) edit(path, diff string, p toolPart) (string, bool) {
	prior, ok := c.files[path]
	delete(c.files, path)
	if !ok || !c.usable(prior, p) || strings.HasPrefix(prior.text, bom) {
		return "", false
	}
	hunks, ok := hunksOf(path, diff)
	if !ok {
		return "", false
	}
	next, ok := applyDiff(prior.text, hunks)
	if !ok {
		return "", false
	}
	c.files[path] = known{text: next, from: prior.from}
	return content.SHA256Bytes([]byte(next)), true
}

// hunksOf is the hunks of the edit's diff: OpenCode's diff starts with the
// four header lines "Index: <path>", a line of 67 "=", "--- <path>" and
// "+++ <path>", each naming the edited file. Any other header is refused.
func hunksOf(path, diff string) (string, bool) {
	header := "Index: " + path + "\n" + strings.Repeat("=", 67) + "\n--- " + path + "\n+++ " + path + "\n"
	rest, ok := strings.CutPrefix(diff, header)
	return rest, ok && rest != ""
}

// searchFolder is the folder a grep or glob call searched (I-124, I-142),
// as the 1.19.5 binary chooses ripgrep's working directory: the call's
// path, absolute or joined to the session's directory, or that directory
// when the call names none. A glob's path must be a directory. A grep's
// may be a file, and ripgrep then searches the file's whole directory with
// "." (confirmed on the parity campaign), so the folder is the path's
// directory when the path was a file. The record says so in two ways: the
// output names each matched file as "<path>:" on a line of its own, and a
// matched file that is the path itself or lies outside it shows the path
// was a file; or an earlier completed read, write or edit of the path
// (knownFiles) showed it to be one. A grep of a file that matched nothing
// and that no earlier call touched is claimed with the file as its folder
// (a known limit).
func searchFolder(p toolPart, knownFiles map[string]bool) (string, bool) {
	var in struct {
		Pattern string  `json:"pattern"`
		Path    *string `json:"path"`
	}
	if json.Unmarshal(p.data.State.Input, &in) != nil || in.Pattern == "" || !filepath.IsAbs(p.dir) {
		return "", false
	}
	f := p.dir
	if in.Path != nil && *in.Path != "" {
		f = *in.Path
		if !filepath.IsAbs(f) {
			f = filepath.Join(p.dir, f)
		}
	}
	f = filepath.Clean(f)
	if p.data.Tool != toolGrep || f == p.dir {
		return f, true
	}
	if knownFiles[f] {
		return filepath.Dir(f), true
	}
	var out string
	_ = json.Unmarshal(p.data.State.Output, &out)
	for _, line := range strings.Split(out, "\n") {
		m, ok := strings.CutSuffix(line, ":")
		if !ok || !filepath.IsAbs(m) || m != filepath.Clean(m) {
			continue
		}
		if m == f || !strings.HasPrefix(m, f+"/") {
			return filepath.Dir(f), true
		}
	}
	return f, true
}
