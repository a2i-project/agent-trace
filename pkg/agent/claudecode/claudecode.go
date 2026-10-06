// Package claudecode adapts Claude Code sessions (JSONL transcripts) to the
// verifier. See docs/plan/07_trajectory_formats.md section 3 for the design and
// the measurements behind it.
package claudecode

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// Name is the adapter's registered name.
const Name = "claude-code"

func init() { agent.Register(Adapter{}) }

// Adapter implements agent.Adapter for Claude Code.
type Adapter struct{}

func (Adapter) Name() string { return Name }

// Process: every Bash call execs its own shell (level 1), subagents run in the
// agent's own process (07 D9), and the start timestamp is the moment the model
// emitted the call, which includes approval latency (D13). The format records
// no process exit, only an is_error flag that conflates a failed command with
// one that never ran, so exits are not claimed (08 section 6.2).
func (Adapter) Process() agent.ProcessModel {
	return agent.ProcessModel{
		ShellPerCommand:    true,
		SubagentsInProcess: true,
		IntervalKind:       agent.IntervalDecision,
		Concurrency:        agent.Parallel,
		ExitsClaimed:       false,
	}
}

// Expresses declares what the format can state. It states no exit code ever.
// It states an output hash only for Write, the one file tool whose input holds
// the final content: Edit carries fragments, so a nil there is nil by format
// and not an opt-out (08 section 3.7). It states no request body for WebFetch.
func (Adapter) Expresses(e models.TrajectoryEntry, field string) bool {
	switch field {
	case verification.DiffExitCode, verification.DiffRequestHash:
		return false
	case verification.DiffOutputHash:
		return e.Tool == toolWrite
	}
	return true
}

// IsHarnessNoise declares nothing. The harness does generate unclaimed events
// (two persistent connections from the agent process, a read and a write per
// shell call), but the membership changes by version and endpoint, so it is
// measured by a null-task run and supplied as the baseline, never hardcoded
// here (07 D11). A static list would rot into false omissions, and a filter
// that matched a path an attacker could write to would hide the write.
func (Adapter) IsHarnessNoise(models.GroundTruthEvent) bool { return false }

// Normalize recovers the claimed command from the wrapper argv of a process
// event (D6). Every other event passes through.
func (Adapter) Normalize(e models.GroundTruthEvent) (models.GroundTruthEvent, bool) {
	if e.ActionType == models.ProcessExec || e.ActionType == models.ProcessExit {
		if payload, ok := evalPayload(e.Target); ok {
			e.Target = payload
		}
	}
	return e, true
}

// Tool names.
const (
	toolBash     = "Bash"
	toolRead     = "Read"
	toolWrite    = "Write"
	toolEdit     = "Edit"
	toolWebFetch = "WebFetch"
)

// nonEffectful tools perform no syscall of their own, so they must not become
// entries: emitting them would be a permanent false fabrication signal (D10).
// WebSearch is here because Claude Code runs it server-side, so the host never
// sees it (verified once, 07 section 3.1 and the hardening notes).
var nonEffectful = map[string]bool{
	"Agent": true, "Task": true, "AskUserQuestion": true, "ToolSearch": true,
	"Skill": true, "ScheduleWakeup": true, "TodoWrite": true, "ExitPlanMode": true,
	"EnterPlanMode": true, "WebSearch": true, "TaskOutput": true, "TaskStop": true,
	"SendMessage": true, "TaskCreate": true, "TaskUpdate": true, "TaskGet": true, "TaskList": true,
}

// Detect recognises a main session transcript: a .jsonl file whose first
// records are self-describing Claude Code records.
func (Adapter) Detect(path string) bool {
	if filepath.Ext(path) != ".jsonl" {
		return false
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for n := 0; n < 20 && sc.Scan(); n++ {
		var r struct {
			SessionID string `json:"sessionId"`
			Type      string `json:"type"`
			Version   string `json:"version"`
		}
		if json.Unmarshal(sc.Bytes(), &r) == nil && r.SessionID != "" && r.Type != "" && r.Version != "" {
			return true
		}
	}
	return false
}

// record is the part of a transcript line the adapter reads.
type record struct {
	Type      string    `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	SessionID string    `json:"sessionId"`
	Message   *struct {
		ID      string          `json:"id"`
		Content json.RawMessage `json:"content"`
	} `json:"message"`
}

type block struct {
	Type      string          `json:"type"`
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Input     json.RawMessage `json:"input"`
	ToolUseID string          `json:"tool_use_id"`
}

type toolUse struct {
	id, name  string
	input     json.RawMessage
	ts        time.Time
	messageID string
	thread    string
	seq       int // position in the merged read, to keep ties in file order
}

// Parse reads a main session transcript and merges its subagents directory
// (D8). Subagent turns are never inline: they live in
// <session>/subagents/agent-<id>.jsonl, so a parse of the main file alone
// would miss every subagent action, which would then read as an omission.
func (Adapter) Parse(path string) (models.Trajectory, agent.Report, error) {
	var rep agent.Report
	var uses []toolUse
	results := map[string]time.Time{}

	read := func(file, thread string) error {
		f, err := os.Open(file)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 64<<20)
		line := 0
		for sc.Scan() {
			line++
			var r record
			if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
				rep.ParseErrors = append(rep.ParseErrors, fmt.Sprintf("%s:%d: %v", filepath.Base(file), line, err))
				continue
			}
			if r.Message == nil || len(r.Message.Content) == 0 || r.Message.Content[0] != '[' {
				continue
			}
			var blocks []block
			if err := json.Unmarshal(r.Message.Content, &blocks); err != nil {
				rep.ParseErrors = append(rep.ParseErrors, fmt.Sprintf("%s:%d: content: %v", filepath.Base(file), line, err))
				continue
			}
			for _, b := range blocks {
				switch b.Type {
				case "tool_use":
					uses = append(uses, toolUse{id: b.ID, name: b.Name, input: b.Input, ts: r.Timestamp, messageID: r.Message.ID, thread: thread, seq: len(uses)})
				case "tool_result":
					results[b.ToolUseID] = r.Timestamp
				}
			}
		}
		return sc.Err()
	}

	if err := read(path, ""); err != nil {
		return nil, rep, err
	}
	subDir := filepath.Join(strings.TrimSuffix(path, filepath.Ext(path)), "subagents")
	if files, _ := filepath.Glob(filepath.Join(subDir, "agent-*.jsonl")); len(files) > 0 {
		sort.Strings(files)
		for _, f := range files {
			id := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(f), "agent-"), ".jsonl")
			if err := read(f, id); err != nil {
				rep.ParseErrors = append(rep.ParseErrors, fmt.Sprintf("subagent %s: %v", id, err))
			}
		}
	}
	rep.ToolCalls = len(uses)

	// One message can hold several tool_use blocks: a parallel block (V2).
	perMessage := map[string]int{}
	for _, u := range uses {
		if u.messageID != "" {
			perMessage[u.messageID]++
		}
	}
	sort.SliceStable(uses, func(i, j int) bool {
		if !uses[i].ts.Equal(uses[j].ts) {
			return uses[i].ts.Before(uses[j].ts)
		}
		return uses[i].seq < uses[j].seq
	})

	var tr models.Trajectory
	unknown := map[string]bool{}
	for _, u := range uses {
		base := models.TrajectoryEntry{Timestamp: u.ts, ThreadID: u.thread, Tool: u.name}
		if end, ok := results[u.id]; ok && !end.Before(u.ts) {
			e := end
			base.End = &e
		}
		if perMessage[u.messageID] > 1 {
			base.BlockID = u.messageID
		}
		entries, why := claimsFor(u, base)
		switch why {
		case "":
			tr = append(tr, entries...)
		case reasonNonEffectful:
			rep.Count(u.name)
		case reasonUnknown:
			rep.Count(u.name)
			unknown[u.name] = true
		default:
			rep.Count(u.name)
			rep.ParseErrors = append(rep.ParseErrors, fmt.Sprintf("%s %s: %s", u.name, u.id, why))
		}
	}
	for n := range unknown {
		rep.UnknownTools = append(rep.UnknownTools, n)
	}
	sort.Strings(rep.UnknownTools)
	rep.Entries = len(tr)
	rep.Degradations = []string{
		"claim start is the moment the model emitted the call and includes approval latency, so the interval cannot bound execution (D13)",
		"the format records no process exit code, so exits are not aligned (08 section 6.2)",
		"file-tool claim shapes (which kernel events a Read, Write or Edit produces) are a hypothesis until checked against a paired capture",
	}
	if len(unknown) > 0 {
		rep.Degradations = append(rep.Degradations, fmt.Sprintf("tools with no mapping and not declared non-effectful: %s; their effects, if any, will appear unexplained", strings.Join(rep.UnknownTools, ", ")))
	}
	return tr, rep, nil
}

const (
	reasonNonEffectful = "non-effectful"
	reasonUnknown      = "unknown"
)

// claimsFor maps one tool call to its claims. A non-empty reason means no entry
// was produced and says why.
func claimsFor(u toolUse, base models.TrajectoryEntry) ([]models.TrajectoryEntry, string) {
	if nonEffectful[u.name] {
		return nil, reasonNonEffectful
	}
	var in struct {
		Command  string `json:"command"`
		FilePath string `json:"file_path"`
		Content  string `json:"content"`
		URL      string `json:"url"`
		Unparsed string `json:"__unparsedToolInput"`
	}
	if len(u.input) > 0 {
		if err := json.Unmarshal(u.input, &in); err != nil {
			return nil, "unreadable input: " + err.Error()
		}
	}
	if in.Unparsed != "" {
		return nil, "input was not parsed by the harness (__unparsedToolInput)"
	}
	mk := func(a models.ActionType, target string) models.TrajectoryEntry {
		e := base
		e.ActionType, e.Target = a, target
		return e
	}
	switch u.name {
	case toolBash:
		if in.Command == "" {
			return nil, "no command"
		}
		return []models.TrajectoryEntry{mk(models.ProcessExec, in.Command)}, ""
	case toolRead:
		if in.FilePath == "" {
			return nil, "no file_path"
		}
		return []models.TrajectoryEntry{mk(models.FileOpen, in.FilePath)}, ""
	case toolWrite, toolEdit:
		if in.FilePath == "" {
			return nil, "no file_path"
		}
		closeEntry := mk(models.FileClose, in.FilePath)
		if u.name == toolWrite {
			closeEntry.OutputHash = models.StringPtr(contentHash(in.Content))
		}
		return []models.TrajectoryEntry{mk(models.FileOpen, in.FilePath), mk(models.FileWrite, in.FilePath), closeEntry}, ""
	case toolWebFetch:
		host := hostOf(in.URL)
		if host == "" {
			return nil, "no usable url"
		}
		return []models.TrajectoryEntry{mk(models.NetConnect, host)}, ""
	}
	return nil, reasonUnknown
}
