// Package gemini adapts Gemini (antigravity-cli) conversations to the verifier.
// A conversation is a SQLite database whose steps table holds an undocumented
// protobuf payload per step. See docs/architecture/30_agent_adapters.md.
package gemini

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
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
type Adapter struct {
	// root is the pid of the agent's own process, which WithAgentProcess
	// sets for normalizing one capture: a search is a program the harness
	// itself starts (I-133). Zero when the capture has no root.
	root uint32
}

// WithAgentProcess returns the adapter that normalizes a capture whose
// agent process is pid (agent.AgentProcessUser, I-133).
func (a Adapter) WithAgentProcess(pid uint32) agent.Adapter {
	a.root = pid
	return a
}

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

// RecoversCommand is agent.CommandRecoverer: Normalize recovers a
// run_command's CommandLine from raw (V-102).
func (Adapter) RecoversCommand(raw models.GroundTruthEvent) bool {
	if raw.ActionType != models.ProcessExec && raw.ActionType != models.ProcessExit {
		return false
	}
	_, ok := commandOf(raw.Target)
	return ok
}

// Normalize recovers the CommandLine of a run_command from the `bash -c`
// wrapper the harness execs it with (I-47), in the exec and the exit of the
// process. A truncated wrapper recovers a prefix of the command, which the
// verifier pairs as such (V-26). It drops the " (deleted)" the kernel
// appends to the path of a file unlinked before its event was read, which
// names the same file. Nothing else is rewritten here; a grep_search's
// processes are rewritten by NormalizeStream, which sees them together (I-54).
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
	toolGrepSearch  = "grep_search"
	toolSubagent    = "invoke_subagent"
	statusCompleted = 3
	statusCanceled  = 6
	// fieldTask is the step's background task (148): the task id, its log
	// file and the command, written once a run_command outlives its
	// WaitMsBeforeAsync and the harness moves it to the background.
	fieldTask = 148
)

// nonEffectful tools perform no syscall of their own (D10), or, for list_dir
// and find_by_name, read in the agent's own process and start nothing: on the
// paired capture of the search task with agy 1.3.4 neither left an event no
// rule explained, and they are not claimed (I-54). If a version makes them
// start a process, it shows as an unclaimed command. search_web is not here:
// whether it runs server-side is unverified for Gemini.
var nonEffectful = map[string]bool{
	"manage_task": true, "send_message": true, "ask_question": true, "ask_permission": true,
	"list_permissions": true, "schedule": true, "invoke_subagent": true, "define_subagent": true,
	"manage_subagents": true, "list_dir": true, "find_by_name": true,
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
	db, done, err := openSnapshot(path)
	if err != nil {
		return false
	}
	defer done()
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

// openSnapshot opens a private copy of the conversation database (I-51). agy
// keeps the database in write-ahead-log mode: steps not yet checkpointed are
// in <path>-wal, and SQLite reads them only through a shared-memory index,
// <path>-shm, which it creates next to the database when there is none, even
// for a read-only connection, and without which it cannot open the database
// in a directory it may not write. Reading the session in place would
// therefore write into the directory that holds the evidence, and fail where
// that directory is read-only. The copy is the database and its log, when one
// exists, in a new temporary directory; SQLite rebuilds the index there from
// the log, so a step that only the log holds is read. done closes the
// database and removes the copy.
func openSnapshot(path string) (db *sql.DB, done func(), err error) {
	dir, err := os.MkdirTemp("", "agent-trace-gemini-")
	if err != nil {
		return nil, nil, err
	}
	remove := func() { _ = os.RemoveAll(dir) }
	snap := filepath.Join(dir, "conversation.db")
	if err := copyFile(path, snap); err != nil {
		remove()
		return nil, nil, err
	}
	if err := copyFile(path+"-wal", snap+"-wal"); err != nil && !errors.Is(err, fs.ErrNotExist) {
		remove()
		return nil, nil, err
	}
	db, err = sql.Open("sqlite", "file:"+url.PathEscape(snap)+"?mode=ro")
	if err != nil {
		remove()
		return nil, nil, err
	}
	return db, func() { _ = db.Close(); remove() }, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// Parse decodes every step and returns the tool calls of the completed ones in
// step order. It fails, naming the field, when a payload does not decode or a
// tool call lacks the fields the adapter depends on: a version that moves a
// field number must produce an error, never an empty trajectory. It then
// follows the subagents the conversation's invoke_subagent results name and
// merges their claims, each carrying its subagent's conversation id as its
// thread (I-55, followSubagents); the ids it named, read or not, are the
// report's TraceSubagents (V-80).
func (Adapter) Parse(path string) (models.Trajectory, agent.Report, error) {
	c, err := readConversation(path, "")
	if err != nil {
		return nil, c.rep, err
	}
	rep, tl, tr := c.rep, c.tl, c.tr
	fol := followSubagents(path, c, &rep, &tl)
	tr = append(tr, fol.tr...)
	if len(fol.named) > 0 {
		rep.TraceSubagents = append([]string(nil), fol.named...)
		sort.Strings(rep.TraceSubagents)
	}

	sort.SliceStable(tr, func(i, j int) bool { return tr[i].Timestamp.Before(tr[j].Timestamp) })
	for n := range tl.unknown {
		rep.UnknownTools = append(rep.UnknownTools, n)
	}
	sort.Strings(rep.UnknownTools)
	rep.Entries = len(tr)
	rep.Degradations = []string{
		"the format records no process exit code, so exits are not aligned",
		"calls the model issues together are separate steps with no block id, ordered by their started time; whether the harness always executes them in that order is unmeasured",
	}
	if tl.multi > 0 {
		rep.Degradations = append(rep.Degradations, fmt.Sprintf("%d multi_replace_file_content call(s): its kernel events are unmeasured and it is claimed like replace_file_content (I-50)", tl.multi))
	}
	if tl.subagents > 0 {
		rep.Degradations = append(rep.Degradations, fol.degradations()...)
	}
	if tl.sub > 0 {
		rep.Degradations = append(rep.Degradations, fmt.Sprintf("%d step(s) have a subtrajectory, which is not followed", tl.sub))
	}
	if tl.persistent > 0 {
		rep.Degradations = append(rep.Degradations, fmt.Sprintf("%d command(s) ran in a persistent shell and produce no level-1 process, so they are not claimed (D7)", tl.persistent))
	}
	if tl.canceled > 0 {
		rep.Degradations = append(rep.Degradations, fmt.Sprintf("%d run_command step(s) canceled after the harness moved them to the background were claimed as commands that started (I-134)", tl.canceled))
	}
	if tl.statusReads > 0 {
		rep.Degradations = append(rep.Degradations, fmt.Sprintf("%d manage_task status call(s) were claimed as an open of their task's log, the file the step's task record names (V-95)", tl.statusReads))
	}
	if tl.statusUnresolved > 0 {
		rep.Degradations = append(rep.Degradations, fmt.Sprintf("%d manage_task status call(s) name a task no step of the conversation records, so they are not claimed (V-95)", tl.statusUnresolved))
	}
	if len(tl.statuses) > 0 {
		rep.Degradations = append(rep.Degradations, fmt.Sprintf("steps with a status other than completed (%d) were not claimed, whether they executed is unknown", sum(tl.statuses)))
	}
	if tl.fallbackTime {
		rep.Degradations = append(rep.Degradations, "some steps lack a started timestamp, so the created time is used as the claim start")
	}
	if len(tl.unknown) > 0 {
		rep.Degradations = append(rep.Degradations, fmt.Sprintf("tools with no mapping and not declared non-effectful: %s; their effects, if any, will appear unexplained", strings.Join(rep.UnknownTools, ", ")))
	}
	return tr, rep, nil
}

// tally is what Parse counts across the conversations it reads, for the
// report's degradations.
type tally struct {
	unknown                           map[string]bool
	sub, persistent, subagents, multi int
	canceled                          int
	// statusReads counts the manage_task status calls claimed as an open
	// of their task's log, statusUnresolved those whose task the
	// conversation's records do not name (V-95).
	statusReads, statusUnresolved int
	fallbackTime                  bool
	statuses                      map[int]int
}

func (t *tally) add(o tally) {
	for n := range o.unknown {
		t.unknown[n] = true
	}
	for s, n := range o.statuses {
		t.statuses[s] += n
	}
	t.sub += o.sub
	t.persistent += o.persistent
	t.subagents += o.subagents
	t.multi += o.multi
	t.canceled += o.canceled
	t.statusReads += o.statusReads
	t.statusUnresolved += o.statusUnresolved
	t.fallbackTime = t.fallbackTime || o.fallbackTime
}

// conversation is what one database holds: its claims in step order, what
// it did not claim, and the subagents its invoke_subagent results name.
type conversation struct {
	tr  models.Trajectory
	rep agent.Report
	tl  tally
	// links are the subagent conversation ids the invoke_subagent results
	// name, in step order; unlinked counts the invoke_subagent steps whose
	// result names none.
	links    []string
	unlinked int
}

// statedID is the conversation id the database states, the
// cascade_id of its one trajectory_meta row, which is the id agy prints and
// names the database by (I-105); empty when the database states none, more
// than one, or one that is not a conversation id. The fixtures keep it
// (I-110).
func statedID(db *sql.DB) string {
	rows, err := db.Query(`select cascade_id from trajectory_meta`)
	if err != nil {
		return ""
	}
	defer func() { _ = rows.Close() }()
	id := ""
	for n := 0; rows.Next(); n++ {
		var s sql.NullString
		if n > 0 || rows.Scan(&s) != nil || !s.Valid {
			return ""
		}
		id = s.String
	}
	if rows.Err() != nil || !conversationID.MatchString(id) {
		return ""
	}
	return id
}

// readConversation reads one conversation database. thread is empty for the
// main conversation and the subagent's conversation id otherwise: it becomes
// each claim's ThreadID and prefixes its BlockID, so the blocks of two
// threads never share an id.
func readConversation(path, thread string) (*conversation, error) {
	c := &conversation{tl: tally{unknown: map[string]bool{}, statuses: map[int]int{}}}
	rep := &c.rep
	db, done, err := openSnapshot(path)
	if err != nil {
		return c, err
	}
	defer done()
	if thread == "" {
		rep.TraceSession = statedID(db)
	}
	rows, err := db.Query(`select idx, step_type, status, has_subtrajectory, step_payload from steps order by idx`)
	if err != nil {
		return c, fmt.Errorf("read steps: %w", err)
	}
	defer func() { _ = rows.Close() }()

	steps := 0
	// logs are the task logs the steps' task records name, by task id, for
	// the manage_task status calls of later steps (V-95).
	logs := map[string]string{}
	for rows.Next() {
		var idx, stepType, status int
		var hasSub sql.NullBool
		var payload []byte
		if err := rows.Scan(&idx, &stepType, &status, &hasSub, &payload); err != nil {
			return c, fmt.Errorf("scan step: %w", err)
		}
		steps++
		if hasSub.Valid && hasSub.Bool {
			c.tl.sub++
		}
		if len(payload) == 0 {
			continue
		}
		calls, err := submessages(payload, 5, 4)
		if err != nil {
			return c, fmt.Errorf("step %d: payload does not decode: %w", idx, err)
		}
		if id, log, ok, err := taskRecord(payload); err != nil {
			return c, fmt.Errorf("step %d: task record: %w", idx, err)
		} else if ok {
			logs[id] = log
		}
		invokes := false
		for _, call := range calls {
			rep.ToolCalls++
			cl, err := decodeCall(call)
			if err != nil {
				return c, fmt.Errorf("step %d: tool call: %w", idx, err)
			}
			switch cl.name {
			case toolSubagent:
				c.tl.subagents++
				invokes = true
			case toolMultiRepl:
				c.tl.multi++
			}
			if status != statusCompleted {
				if !startedTask(cl, status, payload) {
					rep.Count(fmt.Sprintf("%s (status %d)", cl.name, status))
					c.tl.statuses[status]++
					continue
				}
				c.tl.canceled++
			}
			start, end, usedCreated, err := stepTimes(payload)
			if err != nil {
				return c, fmt.Errorf("step %d: %w", idx, err)
			}
			c.tl.fallbackTime = c.tl.fallbackTime || usedCreated
			base := models.TrajectoryEntry{Timestamp: start, Tool: cl.name, ThreadID: thread}
			if !end.IsZero() && !end.Before(start) {
				e := end
				base.End = &e
			}
			if len(calls) > 1 {
				base.BlockID = fmt.Sprintf("step-%d", idx)
				if thread != "" {
					base.BlockID = thread + "/" + base.BlockID
				}
			}
			entries, why := claimsFor(cl, base)
			if log, status := statusRead(cl, logs); status {
				if log == "" {
					c.tl.statusUnresolved++
				} else {
					e := base
					e.ActionType, e.Target = models.FileOpen, log
					entries, why = []models.TrajectoryEntry{e}, ""
					c.tl.statusReads++
				}
			}
			switch why {
			case "":
				c.tr = append(c.tr, entries...)
			case reasonNonEffectful:
				rep.Count(cl.name)
			case reasonUnknown:
				rep.Count(cl.name)
				c.tl.unknown[cl.name] = true
			case reasonPersistent:
				rep.Count(cl.name + " (persistent shell)")
				c.tl.persistent++
			default:
				rep.Count(cl.name)
				rep.ParseErrors = append(rep.ParseErrors, fmt.Sprintf("step %d %s: %s", idx, cl.name, why))
			}
		}
		if invokes {
			ids, err := subagentLinks(payload)
			if err != nil {
				return c, fmt.Errorf("step %d: invoke_subagent result: %w", idx, err)
			}
			if len(ids) == 0 {
				c.unlinked++
			}
			c.links = append(c.links, ids...)
		}
	}
	if err := rows.Err(); err != nil {
		return c, fmt.Errorf("read steps: %w", err)
	}
	if steps == 0 {
		return c, fmt.Errorf("%s has no steps", path)
	}
	return c, nil
}

// startedTask reports whether a step that did not complete is a command
// that started all the same (I-134): a run_command canceled (status 6) after
// the harness moved it to the background, which the step's task record
// (fieldTask) states. Such a command ran for at least its
// WaitMsBeforeAsync; on agy 1.4.7's long parity run every one was killed by
// the agent's own manage_task call. Any other status, and a canceled step
// with no task record, stays unclaimed (I-17).
func startedTask(cl call, status int, payload []byte) bool {
	if cl.name != toolRunCommand || status != statusCanceled {
		return false
	}
	task, ok, err := bytesField(payload, fieldTask)
	return err == nil && ok && len(task) > 0
}

// toolManageTask is the tool the agent lists, checks and kills its
// background tasks with.
const toolManageTask = "manage_task"

// taskRecord reads a step's background task record (fieldTask): its id
// (148.1, <conversation id>/task-<step>) and its log (148.2, a file:// URI
// of the log under the conversation's brain directory). ok is false when the
// step has none, or when either field is missing or not of that form: such a
// task's status calls are then not claimed.
func taskRecord(payload []byte) (id, log string, ok bool, err error) {
	task, has, err := bytesField(payload, fieldTask)
	if err != nil || !has {
		return "", "", false, err
	}
	idb, hasID, err := bytesField(task, 1)
	if err != nil {
		return "", "", false, err
	}
	uri, hasLog, err := bytesField(task, 2)
	if err != nil {
		return "", "", false, err
	}
	p, isFile := strings.CutPrefix(string(uri), "file://")
	if !hasID || !hasLog || !isFile || !taskID.Match(idb) || strings.Contains(p, "%") || filepath.Clean(p) != p || !taskLog.MatchString(p) {
		return "", "", false, nil
	}
	return string(idb), p, true, nil
}

// taskID is a task's id as its record and manage_task name it.
var taskID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/task-[0-9]+$`)

// statusRead reports whether cl is a manage_task status call (V-95) and,
// if so, the log of the task it names, as a record of the conversation
// states it, or "" when none does. The harness opens the log to answer the
// call: on agy 1.4.7's long parity run each of the two status calls opened
// its task's log once, within the call, and no kill opened it. Every other
// action claims nothing.
func statusRead(cl call, logs map[string]string) (string, bool) {
	if cl.name != toolManageTask || str(cl.args["Action"]) != "status" {
		return "", false
	}
	return logs[str(cl.args["TaskId"])], true
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
	case toolGrepSearch:
		// One search, whichever program the harness ran for it (I-54), in
		// the folder it names (I-108).
		return []models.TrajectoryEntry{mk(models.ProcessExec, searchClaim(str(c.args["SearchPath"])))}, ""
	case toolReadURL:
		u, err := url.Parse(str(c.args["Url"]))
		if err != nil || u.Hostname() == "" {
			return nil, "no usable Url"
		}
		return []models.TrajectoryEntry{mk(models.NetConnect, u.Hostname())}, ""
	}
	return nil, reasonUnknown
}
