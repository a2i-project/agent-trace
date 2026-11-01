package codex

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/content"
	"github.com/agent-trace/agent-trace/pkg/models"
)

// A rollout is one JSON record per line (I-82): the first is the thread's
// session_meta; the model's calls are response_item records (a code-mode
// cell is a custom_tool_call named exec whose JavaScript calls the nested
// tools, a direct tool a function_call), each with its output record; and
// what the nested tools did is an event_msg item_completed record per
// effect, joined to the cell that made it only by the turn and the cell's
// time window. A subagent keeps a rollout of its own whose first records
// replay its parent's history, up to subagent_history_start_ordinal.

type record struct {
	Timestamp string          `json:"timestamp"`
	Ordinal   *int            `json:"ordinal"`
	Type      string          `json:"type"`
	Payload   json.RawMessage `json:"payload"`
}

type sessionMeta struct {
	ID                     string `json:"id"`
	SessionID              string `json:"session_id"`
	CLIVersion             string `json:"cli_version"`
	Cwd                    string `json:"cwd"`
	ParentThreadID         string `json:"parent_thread_id"`
	SubagentHistoryOrdinal *int   `json:"subagent_history_start_ordinal"`
}

type responseItem struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	CallID   string `json:"call_id"`
	Status   string `json:"status"`
	Metadata struct {
		TurnID string `json:"turn_id"`
	} `json:"internal_chat_message_metadata_passthrough"`
}

type eventMsg struct {
	Type        string          `json:"type"`
	ThreadID    string          `json:"thread_id"`
	TurnID      string          `json:"turn_id"`
	Item        json.RawMessage `json:"item"`
	StartedAt   *int64          `json:"started_at_ms"`
	CompletedAt *int64          `json:"completed_at_ms"`
}

type item struct {
	Type          string          `json:"type"`
	ID            string          `json:"id"`
	Kind          string          `json:"kind"`
	Command       []string        `json:"command"`
	Status        string          `json:"status"`
	ExitCode      *int32          `json:"exit_code"`
	Changes       json.RawMessage `json:"changes"`
	AgentThreadID string          `json:"agent_thread_id"`
}

type change struct {
	Type     string  `json:"type"`
	Content  *string `json:"content"`
	MovePath *string `json:"move_path"`
}

// cell is one model call: a code-mode cell or a direct tool call.
type cell struct {
	callID, name, turn string
	start, end         time.Time
	ended              bool
	effects            int
}

// effect is one item that claims something, before its interval is known.
type effect struct {
	claims []models.TrajectoryEntry
	turn   string
	at     time.Time // the item's completion
	order  int
}

// nonEffectfulCalls are the direct tools that act on nothing the probes
// see: waiting on a cell, the collaboration tools (a subagent's own
// rollout says what it did), the clock and questions to the user.
var nonEffectfulCalls = map[string]bool{
	"wait": true, "spawn_agent": true, "wait_agent": true, "send_message": true, "followup_task": true,
	"list_agents": true, "interrupt_agent": true, "request_user_input": true, "request_user_input_async": true,
	"sleep": true, "update_plan": true,
}

// nonEffectfulItems are the item types that state no effect on the host.
var nonEffectfulItems = map[string]bool{
	"UserMessage": true, "AgentMessage": true, "Reasoning": true, "SubAgentActivity": true, "CollabAgentToolCall": true,
}

// Detect: a .jsonl file whose first record is a session_meta naming the
// thread and the CLI version.
func (Adapter) Detect(path string) bool {
	if !strings.HasSuffix(path, ".jsonl") {
		return false
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	r := bufio.NewReader(f)
	line, err := r.ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return false
	}
	meta, ok := readMeta(line)
	return ok && meta.ID != "" && meta.CLIVersion != ""
}

func readMeta(line []byte) (sessionMeta, bool) {
	var rec record
	var meta sessionMeta
	if json.Unmarshal(line, &rec) != nil || rec.Type != "session_meta" || json.Unmarshal(rec.Payload, &meta) != nil {
		return meta, false
	}
	return meta, true
}

// Parse reads the rollout and the rollouts of its subagents, which the
// capture copies to <rollout without .jsonl>/subagents (I-82), and claims
// each command and each file change the items record, in the order of the
// cells that made them.
func (Adapter) Parse(path string) (models.Trajectory, agent.Report, error) {
	rep := agent.Report{}
	main, err := readRollout(path, &rep)
	if err != nil {
		return nil, rep, err
	}
	rep.AgentVersion = main.meta.CLIVersion
	if main.meta.SubagentHistoryOrdinal != nil {
		rep.Degradations = append(rep.Degradations, "the rollout given is a subagent's; its parent's actions are not read")
	}
	claims := main.claims
	started := main.subagents
	subs, _ := filepath.Glob(filepath.Join(strings.TrimSuffix(path, ".jsonl"), "subagents", "*.jsonl"))
	sort.Strings(subs)
	found := map[string]bool{}
	for _, s := range subs {
		sub, err := readRollout(s, &rep)
		if err != nil {
			rep.ParseErrors = append(rep.ParseErrors, fmt.Sprintf("subagent rollout %s: %v", filepath.Base(s), err))
			continue
		}
		root := main.meta.SessionID
		if root == "" {
			root = main.meta.ID
		}
		if sub.meta.SessionID != root || sub.meta.ID == main.meta.ID || sub.meta.SubagentHistoryOrdinal == nil {
			rep.Degradations = append(rep.Degradations, fmt.Sprintf("rollout %s is not a subagent of session %s and is not read", filepath.Base(s), root))
			continue
		}
		if sub.meta.CLIVersion != main.meta.CLIVersion {
			rep.ParseErrors = append(rep.ParseErrors, fmt.Sprintf("subagent rollout %s states version %q, the session %q", filepath.Base(s), sub.meta.CLIVersion, main.meta.CLIVersion))
		}
		found[sub.meta.ID] = true
		for i := range sub.claims {
			sub.claims[i].ThreadID = sub.meta.ID
		}
		claims = append(claims, sub.claims...)
		started = append(started, sub.subagents...)
	}
	missing := 0
	for _, id := range started {
		if !found[id] {
			missing++
		}
	}
	if missing > 0 {
		rep.Degradations = append(rep.Degradations, fmt.Sprintf("%d subagent(s) started with no rollout found; their actions are not claimed", missing))
	}
	if len(found) > 0 {
		rep.Degradations = append(rep.Degradations, fmt.Sprintf("%d subagent rollout(s) followed; their claims are ordered with the main thread's by the start of the cell that made them", len(found)))
	}
	sort.SliceStable(claims, func(i, j int) bool { return claims[i].Timestamp.Before(claims[j].Timestamp) })
	rep.Entries = len(claims)
	rep.Degradations = append(rep.Degradations,
		"a claim starts when the cell that made it was recorded, before it ran (D13), and its effects are joined to the cell by turn and time window",
		"exit codes are recorded but not claimed, so exits are not aligned",
		"an update by apply_patch is recorded as a diff, so its write states no content hash")
	return claims, rep, nil
}

type rollout struct {
	meta      sessionMeta
	claims    models.Trajectory
	subagents []string // the threads its SubAgentActivity items started
}

// readRollout reads one rollout's own records: for a subagent, those from
// its history start ordinal on.
func readRollout(path string, rep *agent.Report) (rollout, error) {
	var out rollout
	f, err := os.Open(path)
	if err != nil {
		return out, err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	name := filepath.Base(path)
	var cells []*cell
	byCall := map[string]*cell{}
	var effects []effect
	unjoined, line := 0, 0
	haveMeta := false
	for sc.Scan() {
		line++
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 {
			continue
		}
		var rec record
		if err := json.Unmarshal(raw, &rec); err != nil {
			rep.ParseErrors = append(rep.ParseErrors, fmt.Sprintf("%s:%d: %v", name, line, err))
			continue
		}
		if !haveMeta {
			meta, ok := readMeta(raw)
			if !ok {
				return out, fmt.Errorf("%s: the first record is not a session_meta", name)
			}
			if meta.ID == "" || meta.CLIVersion == "" {
				return out, fmt.Errorf("%s: the session_meta names no thread id or CLI version", name)
			}
			out.meta, haveMeta = meta, true
			continue
		}
		if rec.Type == "session_meta" {
			continue // a subagent's copy of its parent's metadata
		}
		if s := out.meta.SubagentHistoryOrdinal; s != nil && (rec.Ordinal == nil || *rec.Ordinal < *s) {
			continue // the parent's history the subagent starts with
		}
		ts, err := time.Parse(time.RFC3339Nano, rec.Timestamp)
		if err != nil {
			rep.ParseErrors = append(rep.ParseErrors, fmt.Sprintf("%s:%d: timestamp %q: %v", name, line, rec.Timestamp, err))
			continue
		}
		switch rec.Type {
		case "response_item":
			var ri responseItem
			if err := json.Unmarshal(rec.Payload, &ri); err != nil {
				rep.ParseErrors = append(rep.ParseErrors, fmt.Sprintf("%s:%d: %v", name, line, err))
				continue
			}
			switch ri.Type {
			case "custom_tool_call", "function_call":
				if ri.CallID == "" || ri.Name == "" {
					rep.ParseErrors = append(rep.ParseErrors, fmt.Sprintf("%s:%d: a %s with no call id or name", name, line, ri.Type))
					continue
				}
				if byCall[ri.CallID] != nil {
					rep.ParseErrors = append(rep.ParseErrors, fmt.Sprintf("%s:%d: call %s stated twice", name, line, ri.CallID))
					continue
				}
				c := &cell{callID: ri.CallID, name: ri.Name, turn: ri.Metadata.TurnID, start: ts}
				cells = append(cells, c)
				byCall[ri.CallID] = c
			case "custom_tool_call_output", "function_call_output":
				if c := byCall[ri.CallID]; c != nil && !c.ended && !ts.Before(c.start) {
					c.end, c.ended = ts, true
				}
			}
		case "event_msg":
			var ev eventMsg
			if err := json.Unmarshal(rec.Payload, &ev); err != nil {
				rep.ParseErrors = append(rep.ParseErrors, fmt.Sprintf("%s:%d: %v", name, line, err))
				continue
			}
			if ev.Type != "item_completed" {
				continue
			}
			if ev.ThreadID != out.meta.ID {
				rep.ParseErrors = append(rep.ParseErrors, fmt.Sprintf("%s:%d: an item of thread %s in the rollout of %s", name, line, ev.ThreadID, out.meta.ID))
				continue
			}
			var it item
			if err := json.Unmarshal(ev.Item, &it); err != nil {
				rep.ParseErrors = append(rep.ParseErrors, fmt.Sprintf("%s:%d: %v", name, line, err))
				continue
			}
			at := ts
			if ev.CompletedAt != nil {
				at = time.UnixMilli(*ev.CompletedAt).UTC()
			}
			claims, err := itemClaims(it, rep, &out)
			if err != nil {
				rep.ParseErrors = append(rep.ParseErrors, fmt.Sprintf("%s:%d: %v", name, line, err))
				continue
			}
			if len(claims) > 0 {
				effects = append(effects, effect{claims: claims, turn: ev.TurnID, at: at, order: len(effects)})
			}
		}
	}
	if err := sc.Err(); err != nil {
		return out, err
	}
	if !haveMeta {
		return out, fmt.Errorf("%s: no records", name)
	}
	// Each effect takes the interval of the one cell of its turn whose
	// window holds its completion; the effects of one cell form a block.
	joined := make([]*cell, len(effects))
	for i, ef := range effects {
		var in []*cell
		for _, c := range cells {
			if c.ended && (c.turn == "" || ef.turn == "" || c.turn == ef.turn) && !ef.at.Before(c.start) && !ef.at.After(c.end) {
				in = append(in, c)
			}
		}
		if len(in) == 1 {
			joined[i] = in[0]
			in[0].effects++
		} else {
			unjoined++
		}
	}
	for i, ef := range effects {
		c := joined[i]
		for _, cl := range ef.claims {
			if c != nil {
				end := c.end
				cl.Timestamp, cl.End = c.start, &end
				if c.effects > 1 {
					cl.BlockID = out.meta.ID + "/" + c.callID
				}
			} else {
				cl.Timestamp = ef.at
			}
			out.claims = append(out.claims, cl)
		}
	}
	if unjoined > 0 {
		rep.Degradations = append(rep.Degradations, fmt.Sprintf("%s: %d effect(s) joined to no single cell, claimed at their completion with no interval", name, unjoined))
	}
	for _, c := range cells {
		rep.ToolCalls++
		switch {
		case c.name == "exec":
			if c.effects == 0 {
				rep.Count("exec (no effect joined)")
			}
		case nonEffectfulCalls[c.name]:
			rep.Count(c.name)
		default:
			rep.Count(c.name)
			rep.UnknownTools = append(rep.UnknownTools, c.name)
		}
	}
	return out, nil
}

// itemClaims maps one completed item to its claims, in kernel order, or
// counts it.
func itemClaims(it item, rep *agent.Report, out *rollout) (models.Trajectory, error) {
	switch it.Type {
	case "CommandExecution":
		if it.ExitCode == nil {
			rep.Count(fmt.Sprintf("%s (status %s)", toolCommand, it.Status))
			return nil, nil
		}
		target, ok := commandOf(it.Command)
		if !ok {
			return nil, fmt.Errorf("command %q is not /bin/bash -lc with one command", it.Command)
		}
		return models.Trajectory{{ActionType: models.ProcessExec, Target: target, Tool: toolCommand}}, nil
	case "FileChange":
		if it.Status != "completed" {
			rep.Count(fmt.Sprintf("apply_patch (status %s)", it.Status))
			return nil, nil
		}
		return changeClaims(it.Changes, rep)
	case "Extension":
		// web.search runs on the model API's side; the host sees no request
		// of it (verified once, in the survey of 0.166.0).
		rep.Count("extension " + it.Kind)
		if it.Kind != "web.search" {
			rep.UnknownTools = append(rep.UnknownTools, "extension "+it.Kind)
		}
		return nil, nil
	}
	if it.Type == "SubAgentActivity" && it.Kind == "started" && it.AgentThreadID != "" {
		out.subagents = append(out.subagents, it.AgentThreadID)
	}
	if !nonEffectfulItems[it.Type] {
		rep.Count("item " + it.Type)
		rep.UnknownTools = append(rep.UnknownTools, "item "+it.Type)
	}
	return nil, nil
}

// commandOf is the command a CommandExecution states: the rollout records
// every exec_command call as ["/bin/bash", "-lc", <command>].
func commandOf(argv []string) (string, bool) {
	if len(argv) == 3 && argv[0] == "/bin/bash" && argv[1] == "-lc" && argv[2] != "" {
		return argv[2], true
	}
	return "", false
}

// changeClaims maps a FileChange's changes, in the record's order: an add
// is an open and a write with the content's hash, an update an open and a
// write, a delete a delete. A move is not claimed.
func changeClaims(raw json.RawMessage, rep *agent.Report) (models.Trajectory, error) {
	paths, changes, err := orderedChanges(raw)
	if err != nil {
		return nil, err
	}
	var out models.Trajectory
	for i, p := range paths {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return nil, fmt.Errorf("file change of %q, not an absolute clean path", p)
		}
		c := changes[i]
		switch c.Type {
		case "add":
			if c.Content == nil {
				return nil, fmt.Errorf("add of %s holds no content", p)
			}
			h := content.SHA256Bytes([]byte(*c.Content))
			out = append(out,
				models.TrajectoryEntry{ActionType: models.FileOpen, Target: p, Tool: toolAdd},
				models.TrajectoryEntry{ActionType: models.FileWrite, Target: p, OutputHash: &h, Tool: toolAdd})
		case "update":
			if c.MovePath != nil {
				rep.Count("apply_patch:move")
				rep.Degradations = append(rep.Degradations, fmt.Sprintf("an update that moves %s is not claimed (its shape was not measured)", p))
				continue
			}
			out = append(out,
				models.TrajectoryEntry{ActionType: models.FileOpen, Target: p, Tool: toolUpdate},
				models.TrajectoryEntry{ActionType: models.FileWrite, Target: p, Tool: toolUpdate})
		case "delete":
			out = append(out, models.TrajectoryEntry{ActionType: models.FileDelete, Target: p, Tool: toolDelete})
			rep.Degradations = append(rep.Degradations, fmt.Sprintf("the delete of %s is claimed in a shape not measured", p))
		default:
			return nil, fmt.Errorf("file change of %s of unknown type %q", p, c.Type)
		}
	}
	if len(out) == 0 && len(paths) == 0 {
		return nil, fmt.Errorf("a completed file change with no change")
	}
	return out, nil
}

// orderedChanges decodes the changes object keeping its keys' order.
func orderedChanges(raw json.RawMessage) ([]string, []change, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, nil, fmt.Errorf("changes is not an object")
	}
	var paths []string
	var changes []change
	seen := map[string]bool{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, nil, err
		}
		k, _ := t.(string)
		var c change
		if err := dec.Decode(&c); err != nil {
			return nil, nil, err
		}
		if seen[k] {
			return nil, nil, fmt.Errorf("file %s changed twice in one item", k)
		}
		seen[k] = true
		paths, changes = append(paths, k), append(changes, c)
	}
	return paths, changes, nil
}
