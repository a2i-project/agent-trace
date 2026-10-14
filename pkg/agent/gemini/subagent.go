package gemini

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/models"
)

// A subagent started with invoke_subagent runs in the agy process and keeps
// its steps in a conversation database of its own, <id>.db in the same
// directory as its caller's (I-47). Measured on agy 1.3.4 (I-55): the
// invoke_subagent step's has_subtrajectory stays 0, and the step's payload
// holds the call's result in field 140. Its field 2.6 is a
// google.protobuf.Any whose value (2.6.2) is a Step, and that Step's field
// 143.10 is repeated, one per subagent created, with the subagent's
// conversation id in 143.10.1. The result's text (140.2.1) names the same ids
// in prose for the model; the adapter reads only the typed field. One call
// that created four subagents named all four, in the order of its arguments.

// maxSubagentDepth bounds how deep nested subagents are followed: a
// subagent's own invoke_subagent results are followed too, down to this many
// levels below the main conversation. Nesting was not seen on 1.3.4; a deeper
// subagent is reported, not read.
const maxSubagentDepth = 4

// conversationID is the form agy names its conversations by. An id of any
// other form is not looked up: it comes from the trajectory, and a path
// separator in it would name a file elsewhere.
var conversationID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// subagentLinks returns the conversation ids an invoke_subagent step's result
// names, in their order, keeping only ids of the form agy uses. A step with
// no result, or a result in another layout, names none, which the caller
// reports; a result that does not decode is an error.
func subagentLinks(payload []byte) ([]string, error) {
	subs, err := submessages(payload, 140, 2, 6, 2, 143, 10)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, m := range subs {
		id, ok, err := bytesField(m, 1)
		if err != nil {
			return nil, &pathError{path: []int{140, 2, 6, 2, 143, 10, 1}, why: err.Error()}
		}
		if ok && conversationID.Match(id) {
			ids = append(ids, string(id))
		}
	}
	return ids, nil
}

// subagentDirs are where a subagent's database is looked for: beside the
// conversation, as agy keeps them, and in <conversation without .db>/subagents,
// where the capture script copies them beside <label>.conversation.db, as it
// copies Claude Code's subagent transcripts into <label>.session/subagents.
// Nested subagents are looked for in the same two directories.
func subagentDirs(path string) []string {
	return []string{filepath.Dir(path), filepath.Join(strings.TrimSuffix(path, filepath.Ext(path)), "subagents")}
}

func locateSubagent(dirs []string, id string) (string, bool) {
	for _, d := range dirs {
		p := filepath.Join(d, id+".db")
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			return p, true
		}
	}
	return "", false
}

// followed is what following a conversation's subagents gave.
type followed struct {
	tr       models.Trajectory
	read     int      // subagent conversations read
	missing  []string // named, but no database found
	unlinked int      // invoke_subagent steps whose result names no subagent
	tooDeep  int      // named deeper than maxSubagentDepth
}

// followSubagents reads, breadth first, every subagent conversation that main
// and the subagents it reaches name, and returns their claims, each carrying
// its subagent's id as ThreadID (D9). Each id is read once, so a cycle ends.
// A subagent's counts join rep and tl; a database that is missing is
// reported, and one that does not parse is a parse error naming the
// subagent, and adds nothing else.
func followSubagents(path string, main *conversation, rep *agent.Report, tl *tally) followed {
	var f followed
	f.unlinked = main.unlinked
	dirs := subagentDirs(path)
	seen := map[string]bool{}
	if self := strings.TrimSuffix(filepath.Base(path), ".db"); conversationID.MatchString(self) {
		seen[self] = true
	}
	type link struct {
		id    string
		depth int
	}
	var queue []link
	for _, id := range main.links {
		queue = append(queue, link{id, 1})
	}
	for len(queue) > 0 {
		l := queue[0]
		queue = queue[1:]
		if seen[l.id] {
			continue
		}
		seen[l.id] = true
		if l.depth > maxSubagentDepth {
			f.tooDeep++
			continue
		}
		p, ok := locateSubagent(dirs, l.id)
		if !ok {
			f.missing = append(f.missing, l.id)
			continue
		}
		c, err := readConversation(p, l.id)
		if err != nil {
			rep.ParseErrors = append(rep.ParseErrors, fmt.Sprintf("subagent %s: %v", l.id, err))
			continue
		}
		f.read++
		f.tr = append(f.tr, c.tr...)
		f.unlinked += c.unlinked
		mergeReport(rep, c.rep)
		tl.add(c.tl)
		for _, id := range c.links {
			queue = append(queue, link{id, l.depth + 1})
		}
	}
	return f
}

func mergeReport(into *agent.Report, r agent.Report) {
	into.ToolCalls += r.ToolCalls
	for n, k := range r.UnmappedByTool {
		for i := 0; i < k; i++ {
			into.Count(n)
		}
	}
	into.ParseErrors = append(into.ParseErrors, r.ParseErrors...)
}

func (f followed) degradations() []string {
	var d []string
	if f.read > 0 {
		d = append(d, fmt.Sprintf("%d subagent conversation(s) followed: their claims carry the subagent's conversation id as thread id and are ordered with the main thread's by started time, as one sequence (D9, O-29)", f.read))
	}
	if len(f.missing) > 0 {
		d = append(d, fmt.Sprintf("%d subagent conversation(s) named by an invoke_subagent result have no database beside the conversation or in its subagents directory, so what they did appears unexplained: %s", len(f.missing), strings.Join(f.missing, ", ")))
	}
	if f.unlinked > 0 {
		d = append(d, fmt.Sprintf("%d invoke_subagent step(s) name no subagent conversation in their result, so what a subagent they started did appears unexplained", f.unlinked))
	}
	if f.tooDeep > 0 {
		d = append(d, fmt.Sprintf("%d subagent conversation(s) nested more than %d levels deep are not followed, so what they did appears unexplained", f.tooDeep, maxSubagentDepth))
	}
	return d
}
