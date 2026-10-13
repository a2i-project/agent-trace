// Package gemini adapts Gemini (antigravity-cli) conversations to the verifier.
// A conversation is a SQLite database whose steps table holds an undocumented
// protobuf payload per step. See docs/architecture/30_agent_adapters.md.
package gemini

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver, no cgo

	"github.com/agent-trace/agent-trace/pkg/agent"
	"github.com/agent-trace/agent-trace/pkg/content"
	"github.com/agent-trace/agent-trace/pkg/models"
	"github.com/agent-trace/agent-trace/pkg/verification"
)

// Name is the adapter's registered name.
const Name = "gemini"

func init() { agent.Register(Adapter{}) }

// Adapter implements agent.Adapter for Gemini.
type Adapter struct{}

func (Adapter) Name() string { return Name }

// Process is measured on agy 1.3.4 (I-47): strace -f of three print-mode runs
// on 2026-10-13, one of them under a reset environment as the capture script
// runs it. Every run_command execs its own `bash -c <CommandLine>` as a child
// of the agy process (a call with RunPersistent was not seen, and is not
// claimed, I-17). A subagent started with invoke_subagent runs in the same agy
// process: its command was a child of that process like the main thread's.
// Steps overlap: two run_command calls the model issued together were two
// steps whose started-to-completed intervals overlapped (the harness ran the
// second command after the first had exited), and the subagent's command ran
// after a later command of the main thread. A step's started time preceded
// the exec of its command and its completed time followed the command's exit
// on every call measured, so the interval brackets execution (D13).
func (Adapter) Process() agent.ProcessModel {
	return agent.ProcessModel{
		ShellPerCommand:    true,
		SubagentsInProcess: true,
		IntervalKind:       agent.IntervalExecution,
		Concurrency:        agent.Parallel,
		ExitsClaimed:       false,
	}
}

// Expresses: the format records no exit code and no request body, and carries
// final content only for write_to_file, and there only when the content is
// not empty (writeHash). replace_file_content carries a target and
// replacement fragments, so no output hash is stated there.
func (Adapter) Expresses(e models.TrajectoryEntry, field string) bool {
	switch field {
	case verification.DiffExitCode, verification.DiffRequestHash:
		return false
	case verification.DiffOutputHash:
		return e.Tool == toolWriteFile && (e.ActionType != models.FileClose || e.OutputHash != nil)
	}
	return true
}

// IsHarnessNoise declares nothing: the baseline is measured per version (D11).
func (Adapter) IsHarnessNoise(models.GroundTruthEvent) bool { return false }

// Normalize recovers the CommandLine of a run_command from the `bash -c`
// wrapper the harness execs it with (I-47), in the exec and the exit of the
// process. A truncated wrapper recovers a prefix of the command, which the
// verifier pairs as such (V-26). It drops the " (deleted)" the kernel
// appends to the path of a file unlinked before its event was read, which
// names the same file. Nothing else is rewritten.
func (Adapter) Normalize(e models.GroundTruthEvent) (models.GroundTruthEvent, bool) {
	switch {
	case e.ActionType == models.ProcessExec || e.ActionType == models.ProcessExit:
		if cmd, ok := commandOf(e.Target); ok {
			e.Target = cmd
		}
	case isFile(e.ActionType):
		e.Target = deletedSuffix.ReplaceAllString(e.Target, "")
	}
	return e, true
}

// Canonical replaces the per-run ids in the harness's own file paths with
// fixed tokens (I-48). It is applied only where runs are compared
// (agent.Canonicalizer, I-41): a claim and the event it pairs with keep their
// exact paths.
func (Adapter) Canonical(e models.GroundTruthEvent) models.GroundTruthEvent {
	if isFile(e.ActionType) {
		e.Target = canonicalPath(e.Target)
	}
	return e
}

func isFile(a models.ActionType) bool {
	switch a {
	case models.FileOpen, models.FileRead, models.FileWrite, models.FileClose, models.FileRename, models.FileDelete:
		return true
	}
	return false
}

const (
	toolRunCommand  = "run_command"
	toolViewFile    = "view_file"
	toolWriteFile   = "write_to_file"
	toolReplace     = "replace_file_content"
	toolMultiRepl   = "multi_replace_file_content"
	toolReadURL     = "read_url_content"
	toolSubagent    = "invoke_subagent"
	statusCompleted = 3
)

// nonEffectful tools perform no syscall of their own (D10). search_web is not
// here: whether it runs server-side is unverified for Gemini.
var nonEffectful = map[string]bool{
	"manage_task": true, "send_message": true, "ask_question": true, "ask_permission": true,
	"list_permissions": true, "schedule": true, "invoke_subagent": true, "define_subagent": true,
	"manage_subagents": true,
}

var sqliteMagic = []byte("SQLite format 3\x00")

// Detect recognises a conversation database: the SQLite header and a steps
// table with a step_payload column.
func (Adapter) Detect(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	head := make([]byte, len(sqliteMagic))
	_, rerr := f.Read(head)
	_ = f.Close()
	if rerr != nil || !bytes.Equal(head, sqliteMagic) {
		return false
	}
	db, err := openReadOnly(path)
	if err != nil {
		return false
	}
	defer func() { _ = db.Close() }()
	rows, err := db.Query(`select name from pragma_table_info('steps')`)
	if err != nil {
		return false
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var n string
		if rows.Scan(&n) == nil && n == "step_payload" {
			return true
		}
	}
	return false
}

func openReadOnly(path string) (*sql.DB, error) {
	return sql.Open("sqlite", "file:"+url.PathEscape(path)+"?mode=ro")
}

// Parse decodes every step and returns the tool calls of the completed ones in
// step order. It fails, naming the field, when a payload does not decode or a
// tool call lacks the fields the adapter depends on: a version that moves a
// field number must produce an error, never an empty trajectory.
func (Adapter) Parse(path string) (models.Trajectory, agent.Report, error) {
	var rep agent.Report
	db, err := openReadOnly(path)
	if err != nil {
		return nil, rep, err
	}
	defer func() { _ = db.Close() }()
	rows, err := db.Query(`select idx, step_type, status, has_subtrajectory, step_payload from steps order by idx`)
	if err != nil {
		return nil, rep, fmt.Errorf("read steps: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var tr models.Trajectory
	unknown := map[string]bool{}
	var steps, sub, persistent, subagents int
	var fallbackTime bool
	statuses := map[int]int{}

	for rows.Next() {
		var idx, stepType, status int
		var hasSub sql.NullBool
		var payload []byte
		if err := rows.Scan(&idx, &stepType, &status, &hasSub, &payload); err != nil {
			return nil, rep, fmt.Errorf("scan step: %w", err)
		}
		steps++
		if hasSub.Valid && hasSub.Bool {
			sub++
		}
		if len(payload) == 0 {
			continue
		}
		calls, err := submessages(payload, 5, 4)
		if err != nil {
			return nil, rep, fmt.Errorf("step %d: payload does not decode: %w", idx, err)
		}
		for _, call := range calls {
			rep.ToolCalls++
			c, err := decodeCall(call)
			if err != nil {
				return nil, rep, fmt.Errorf("step %d: tool call: %w", idx, err)
			}
			if c.name == toolSubagent {
				subagents++
			}
			if status != statusCompleted {
				rep.Count(fmt.Sprintf("%s (status %d)", c.name, status))
				statuses[status]++
				continue
			}
			start, end, usedCreated, err := stepTimes(payload)
			if err != nil {
				return nil, rep, fmt.Errorf("step %d: %w", idx, err)
			}
			fallbackTime = fallbackTime || usedCreated
			base := models.TrajectoryEntry{Timestamp: start, Tool: c.name}
			if !end.IsZero() && !end.Before(start) {
				e := end
				base.End = &e
			}
			if len(calls) > 1 {
				base.BlockID = fmt.Sprintf("step-%d", idx)
			}
			entries, why := claimsFor(c, base)
			switch why {
			case "":
				tr = append(tr, entries...)
			case reasonNonEffectful:
				rep.Count(c.name)
			case reasonUnknown:
				rep.Count(c.name)
				unknown[c.name] = true
			case reasonPersistent:
				rep.Count(c.name + " (persistent shell)")
				persistent++
			default:
				rep.Count(c.name)
				rep.ParseErrors = append(rep.ParseErrors, fmt.Sprintf("step %d %s: %s", idx, c.name, why))
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, rep, fmt.Errorf("read steps: %w", err)
	}
	if steps == 0 {
		return nil, rep, fmt.Errorf("%s has no steps", path)
	}

	sort.SliceStable(tr, func(i, j int) bool { return tr[i].Timestamp.Before(tr[j].Timestamp) })
	for n := range unknown {
		rep.UnknownTools = append(rep.UnknownTools, n)
	}
	sort.Strings(rep.UnknownTools)
	rep.Entries = len(tr)
	rep.Degradations = []string{
		"the format records no process exit code, so exits are not aligned",
		"file-tool claim shapes (which kernel events a view_file, write_to_file or replace_file_content produces) are a hypothesis until checked against a paired capture",
		"calls the model issues together are separate steps with no block id, ordered by their started time; whether the harness always executes them in that order is unmeasured",
	}
	if subagents > 0 {
		rep.Degradations = append(rep.Degradations, fmt.Sprintf("%d invoke_subagent call(s): a subagent's steps are in a conversation database of its own, which is not read, so what it did appears unexplained", subagents))
	}
	if sub > 0 {
		rep.Degradations = append(rep.Degradations, fmt.Sprintf("%d step(s) have a subtrajectory, which is not followed", sub))
	}
	if persistent > 0 {
		rep.Degradations = append(rep.Degradations, fmt.Sprintf("%d command(s) ran in a persistent shell and produce no level-1 process, so they are not claimed (D7)", persistent))
	}
	if len(statuses) > 0 {
		rep.Degradations = append(rep.Degradations, fmt.Sprintf("steps with a status other than completed (%d) were not claimed, whether they executed is unknown", sum(statuses)))
	}
	if fallbackTime {
		rep.Degradations = append(rep.Degradations, "some steps lack a started timestamp, so the created time is used as the claim start")
	}
	if len(unknown) > 0 {
		rep.Degradations = append(rep.Degradations, fmt.Sprintf("tools with no mapping and not declared non-effectful: %s; their effects, if any, will appear unexplained", strings.Join(rep.UnknownTools, ", ")))
	}
	return tr, rep, nil
}

func sum(m map[int]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

type call struct {
	id, name string
	args     map[string]json.RawMessage
}

// decodeCall reads a tool call message: field 1 the call id, field 2 the tool
// name, field 3 the arguments as a JSON string nested in the protobuf.
func decodeCall(m []byte) (call, error) {
	var c call
	id, _, err := bytesField(m, 1)
	if err != nil {
		return c, &pathError{path: []int{5, 4, 1}, why: err.Error()}
	}
	name, ok, err := bytesField(m, 2)
	if err != nil {
		return c, &pathError{path: []int{5, 4, 2}, why: err.Error()}
	}
	if !ok || len(name) == 0 {
		return c, &pathError{path: []int{5, 4, 2}, why: "tool name not found"}
	}
	args, ok, err := bytesField(m, 3)
	if err != nil {
		return c, &pathError{path: []int{5, 4, 3}, why: err.Error()}
	}
	if !ok {
		return c, &pathError{path: []int{5, 4, 3}, why: "tool arguments not found"}
	}
	c.id, c.name = string(id), string(name)
	if err := json.Unmarshal(args, &c.args); err != nil {
		return c, &pathError{path: []int{5, 4, 3}, why: "arguments are not JSON: " + err.Error()}
	}
	return c, nil
}

// stepTimes returns the claim start and end of a step. Started (5.6) is the
// execution anchor; created (5.1) is the fallback, reported by the caller.
// Completed (5.8) is the end, and is zero when absent.
func stepTimes(payload []byte) (start, end time.Time, usedCreated bool, err error) {
	toTime := func(s, n int64) time.Time { return time.Unix(s, n).UTC() }
	s, n, ok, err := timestampAt(payload, 5, 6)
	if err != nil {
		return
	}
	if !ok {
		s, n, ok, err = timestampAt(payload, 5, 1)
		if err != nil {
			return
		}
		if !ok {
			err = &pathError{path: []int{5, 6}, why: "no started or created timestamp"}
			return
		}
		usedCreated = true
	}
	start = toTime(s, n)
	if es, en, eok, eerr := timestampAt(payload, 5, 8); eerr != nil {
		err = eerr
	} else if eok {
		end = toTime(es, en)
	}
	return
}

const (
	reasonNonEffectful = "non-effectful"
	reasonUnknown      = "unknown"
	reasonPersistent   = "persistent"
)

func str(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

// writeHash is the hash of the file a write_to_file leaves: the harness adds a
// final newline to content that lacks one ("hello" was written as "hello\n")
// and writes content that ends in one as it is ("one\ntwo\n"), measured with
// strace on agy 1.3.4 on 2026-10-13 (I-47). What it writes for empty content
// was not seen, so none is claimed.
func writeHash(body string) *string {
	if body == "" {
		return nil
	}
	if !strings.HasSuffix(body, "\n") {
		body += "\n"
	}
	return models.StringPtr(content.SHA256Bytes([]byte(body)))
}

func claimsFor(c call, base models.TrajectoryEntry) ([]models.TrajectoryEntry, string) {
	if nonEffectful[c.name] {
		return nil, reasonNonEffectful
	}
	mk := func(a models.ActionType, target string) models.TrajectoryEntry {
		e := base
		e.ActionType, e.Target = a, target
		return e
	}
	fileClaims := func(path string, hash *string) []models.TrajectoryEntry {
		cl := mk(models.FileClose, path)
		cl.OutputHash = hash
		return []models.TrajectoryEntry{mk(models.FileOpen, path), mk(models.FileWrite, path), cl}
	}
	switch c.name {
	case toolRunCommand:
		var persistent bool
		if raw, ok := c.args["RunPersistent"]; ok {
			_ = json.Unmarshal(raw, &persistent)
		}
		if persistent {
			return nil, reasonPersistent
		}
		cmd := str(c.args["CommandLine"])
		if cmd == "" {
			return nil, "no CommandLine"
		}
		return []models.TrajectoryEntry{mk(models.ProcessExec, cmd)}, ""
	case toolViewFile:
		p := str(c.args["AbsolutePath"])
		if p == "" {
			return nil, "no AbsolutePath"
		}
		return []models.TrajectoryEntry{mk(models.FileOpen, p)}, ""
	case toolWriteFile:
		p := str(c.args["TargetFile"])
		if p == "" {
			return nil, "no TargetFile"
		}
		var h *string
		if raw, ok := c.args["CodeContent"]; ok {
			var body string
			if json.Unmarshal(raw, &body) == nil {
				h = writeHash(body)
			}
		}
		return fileClaims(p, h), ""
	case toolReplace, toolMultiRepl:
		p := str(c.args["TargetFile"])
		if p == "" {
			return nil, "no TargetFile"
		}
		return fileClaims(p, nil), ""
	case toolReadURL:
		u, err := url.Parse(str(c.args["Url"]))
		if err != nil || u.Hostname() == "" {
			return nil, "no usable Url"
		}
		return []models.TrajectoryEntry{mk(models.NetConnect, u.Hostname())}, ""
	}
	return nil, reasonUnknown
}
