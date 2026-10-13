// Package claudecode adapts Claude Code sessions (JSONL transcripts) to the
// verifier. See docs/architecture/30_agent_adapters.md for the design and
// the measurements behind it.
package claudecode

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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
// agent's own process (D9), and the start timestamp is the moment the model
// emitted the call, which includes approval latency (D13). The format records
// no process exit, only an is_error flag that conflates a failed command with
// one that never ran, so exits are not claimed (I-15).
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
// the final content: an Edit's final content is known only when its result
// record carries the file before and the applied replacement (I-31), and a
// NotebookEdit's only when its result carries the notebook it wrote (I-37),
// so a nil there is a result the format did not keep, not an opt-out (V-20).
// It states no request body for WebFetch.
// The hash is the final content of the replaced file, which the observed side
// takes from the close of the temporary (see stream.go).
// A Read states the content it read only when it read the whole file as text
// (I-40), which is exactly when its claim carries an input hash; a partial
// read, a notebook, an image or a PDF states none, and its nil is the
// format's.
func (Adapter) Expresses(e models.TrajectoryEntry, field string) bool {
	switch field {
	case verification.DiffExitCode, verification.DiffRequestHash:
		return false
	case verification.DiffOutputHash:
		return e.Tool == toolWrite
	case verification.DiffInputHash:
		if e.Tool == toolRead {
			return e.InputHash != nil
		}
	}
	return true
}

// IsHarnessNoise declares nothing. The harness does generate unclaimed events
// (two persistent connections from the agent process, a read and a write per
// shell call), but the membership changes by version and endpoint, so it is
// measured by a null-task run and supplied as the baseline, never hardcoded
// here (D11). A static list would rot into false omissions, and a filter
// that matched a path an attacker could write to would hide the write.
func (Adapter) IsHarnessNoise(models.GroundTruthEvent) bool { return false }

// Normalize recovers the claimed command from the wrapper argv of a process
// event (D6), replaces the per-run ids in the harness's own commands (I-23)
// and drops the kernel's " (deleted)" suffix from a file path. A file path
// keeps its per-run ids, so a claim pairs with the one file it names; they
// are replaced only where runs are compared (Canonical, I-41). Every other
// event passes through.
func (Adapter) Normalize(e models.GroundTruthEvent) (models.GroundTruthEvent, bool) {
	switch {
	case e.ActionType == models.ProcessExec || e.ActionType == models.ProcessExit:
		if payload, ok := evalPayload(e.Target); ok {
			e.Target = payload
		} else if prefix, ok := evalPayloadPrefix(e.Target); e.TargetTruncated && ok {
			// The probe cut the wrapper: what it kept of the eval word is a
			// prefix of the claimed command, and the verifier pairs it as such
			// (V-26). The flag stays on the event.
			e.Target = prefix
		} else if search, ok := searchKind(e.Target); ok {
			e.Target = search
		} else {
			e.Target = canonicalIDs(e.Target)
		}
	case isFile(e.ActionType):
		e.Target = withoutDeletedSuffix(e.Target)
	}
	return e, true
}

// Canonical replaces the per-run ids in the harness's own file paths with
// fixed tokens (I-29, I-38), so a baseline rule built from control runs names
// the same file in every run. It is applied only where runs are compared
// (agent.Canonicalizer, I-41); a claim and the event it pairs with keep their
// exact paths.
func (Adapter) Canonical(e models.GroundTruthEvent) models.GroundTruthEvent {
	if isFile(e.ActionType) {
		e.Target = canonicalFileIDs(e.Target)
	}
	return e
}

// ControlCommand is the no-op command the control runs of
// scripts/capture-claude-code.sh are told to run, so that the harness performs
// its first-Bash-call setup. It is excluded from the baseline (I-28); the
// fixture tests exclude it the same way the script does.
const ControlCommand = ": agent-trace-control-marker"

// harnessOwned matches the directories Claude Code keeps its own files in,
// the directories themselves included (a rename inside one is reported on
// the directory),
// measured on the captures of 2.1.286: the configuration file and directory
// under the home directory, the version locks under the state directory, the
// MCP logs under the cache directory, and the per-user temporary directory
// that holds the cwd files, the task outputs and the fswatch probe. An
// unexplained level-0 file event there is unexplained harness activity, not
// an agent's unreported action (V-24, I-30). The list names where the
// harness keeps files, not what it does; it explains nothing.
var harnessOwned = regexp.MustCompile(`^(?:/(?:home/[^/]+|root)/(?:\.claude(?:/|$)|\.claude\.json(?:$|\.tmp\.)|\.local/state/claude(?:/|$)|\.cache/claude-cli-nodejs(?:/|$))|/tmp/claude-(?:\d+/|[0-9a-zA-Z]+-cwd$))`)

// IsHarnessOwned reports whether path is under one of the harness's own
// directories.
func (Adapter) IsHarnessOwned(path string) bool { return harnessOwned.MatchString(path) }

// capturedVersion is the Claude Code version whose kernel-level behaviour the
// claim shapes were checked against (scripts/capture-claude-code.sh).
const capturedVersion = "2.1.286"

// Tool names.
const (
	toolBash     = "Bash"
	toolRead     = "Read"
	toolWrite    = "Write"
	toolEdit     = "Edit"
	toolWebFetch = "WebFetch"
	toolGrep     = "Grep"
	toolGlob     = "Glob"
	// toolNotebookEdit is deferred in 2.1.296: the model first loads it
	// through ToolSearch, which acts on nothing.
	toolNotebookEdit = "NotebookEdit"
)

// nonEffectful tools perform no syscall of their own, so they must not become
// entries: emitting them would be a permanent false fabrication signal (D10).
// WebSearch is here because Claude Code runs it server-side, so the host never
// sees it (verified once, I-16).
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
	Version   string    `json:"version"`
	// Cwd is the session's working directory when the record was written,
	// against which a Bash command's relative paths resolve (I-46).
	Cwd string `json:"cwd"`
	// ToolUseResult is the harness's structured result of the tool call, on the
	// user record that carries the tool_result. For Write it says whether the
	// file was created or updated, which decides whether the harness first
	// opened the existing file.
	ToolUseResult json.RawMessage `json:"toolUseResult"`
	Message       *struct {
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
	// Content is a tool_result's text, a string or a list of text blocks.
	Content json.RawMessage `json:"content"`
	IsError bool            `json:"is_error"`
}

// toolResult is what a call's result record held: when it came back and, for
// tools that report one, what kind of result it was. For Edit it also holds
// the file before the edit and the replacement the harness applied, from
// which the final content follows (I-31).
type toolResult struct {
	ts   time.Time
	kind string
	edit *editResult
	// text is the result's text, kept only when the record has no
	// structured result and the text is the one a Write reports (I-35).
	text string
	// isError is the tool_result's is_error flag.
	isError  bool
	notebook *notebookResult
	// read is the content a Read returned, kept only when the result says it
	// is the whole file as text (I-40).
	read *string
	// cwd is the result record's working directory, bash a Bash call's
	// structured result (I-46).
	cwd  string
	bash *bashResult
}

// bashResult is the part of a Bash call's structured result that says
// whether the harness went on to read the file the command read (I-46).
type bashResult struct {
	// interrupted is nil when the result does not carry the field, which a
	// transcript cut to the result's type does not.
	interrupted    *bool
	isImage        bool
	backgroundTask string
	// interpretation is the harness's reading of a non-zero exit, such as
	// "No matches found" for a search that exited 1.
	interpretation string
}

// readFile is the file part of a Read's structured result (2.1.296): the
// text returned, where it started, how many lines it held and how many the
// file has, and whether the harness cut it to fit its token budget.
type readFile struct {
	Content             *string `json:"content"`
	StartLine           int     `json:"startLine"`
	NumLines            int     `json:"numLines"`
	TotalLines          int     `json:"totalLines"`
	TruncatedByTokenCap bool    `json:"truncatedByTokenCap"`
}

// whole reports whether the result is the whole file: from its first line,
// every line, and not cut by the harness.
func (f readFile) whole() bool {
	return f.Content != nil && f.StartLine == 1 && f.NumLines == f.TotalLines && !f.TruncatedByTokenCap
}

// notebookResult is the structured result of a NotebookEdit call (I-37):
// the notebook's text before and after, as the harness read and wrote it,
// and whether it reported an error. The harness leaves both texts empty
// when it did not edit the file itself.
type notebookResult struct {
	path              string
	original, updated string
	failed            bool
}

// editResult is the structured result of an Edit call.
type editResult struct {
	original   string
	oldString  string
	newString  string
	replaceAll bool
}

// apply returns the file's content after the edit, as the harness applies
// it: the first occurrence of the old string replaced, or every occurrence
// with replace_all.
func (r editResult) apply() string {
	if r.replaceAll {
		return strings.ReplaceAll(r.original, r.oldString, r.newString)
	}
	return strings.Replace(r.original, r.oldString, r.newString, 1)
}

type toolUse struct {
	id, name  string
	input     json.RawMessage
	ts        time.Time
	messageID string
	thread    string
	cwd       string
	seq       int // position in the merged read, to keep ties in file order
}

// Parse reads a main session transcript and merges its subagents directory
// (D8). Subagent turns are never inline: they live in
// <session>/subagents/agent-<id>.jsonl, so a parse of the main file alone
// would miss every subagent action, which would then read as an omission.
func (Adapter) Parse(path string) (models.Trajectory, agent.Report, error) {
	var rep agent.Report
	var uses []toolUse
	results := map[string]toolResult{}

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
			if rep.AgentVersion == "" && r.Version != "" && thread == "" {
				rep.AgentVersion = r.Version
			}
			if r.Message == nil || len(r.Message.Content) == 0 || r.Message.Content[0] != '[' {
				continue
			}
			var blocks []block
			if err := json.Unmarshal(r.Message.Content, &blocks); err != nil {
				rep.ParseErrors = append(rep.ParseErrors, fmt.Sprintf("%s:%d: content: %v", filepath.Base(file), line, err))
				continue
			}
			nResults := 0
			for _, b := range blocks {
				if b.Type == "tool_result" {
					nResults++
				}
			}
			for _, b := range blocks {
				switch b.Type {
				case "tool_use":
					uses = append(uses, toolUse{id: b.ID, name: b.Name, input: b.Input, ts: r.Timestamp, messageID: r.Message.ID, thread: thread, cwd: r.Cwd, seq: len(uses)})
				case "tool_result":
					res := toolResult{ts: r.Timestamp}
					// One structured result per record: with several tool
					// results in one record it cannot be attributed to a call.
					if nResults == 1 {
						var tr struct {
							Type         string  `json:"type"`
							OriginalFile *string `json:"originalFile"`
							OldString    *string `json:"oldString"`
							NewString    *string `json:"newString"`
							ReplaceAll   bool    `json:"replaceAll"`
							// NotebookEdit's result (I-37).
							NotebookPath *string `json:"notebook_path"`
							Original     *string `json:"original_file"`
							Updated      *string `json:"updated_file"`
							Error        string  `json:"error"`
							// Read's result (I-40).
							File *readFile `json:"file"`
							// Bash's result (I-46).
							Interrupted              *bool  `json:"interrupted"`
							IsImage                  bool   `json:"isImage"`
							BackgroundTaskID         string `json:"backgroundTaskId"`
							ReturnCodeInterpretation string `json:"returnCodeInterpretation"`
						}
						if json.Unmarshal(r.ToolUseResult, &tr) == nil {
							res.kind = tr.Type
							if tr.OriginalFile != nil && tr.OldString != nil && tr.NewString != nil {
								res.edit = &editResult{original: *tr.OriginalFile, oldString: *tr.OldString, newString: *tr.NewString, replaceAll: tr.ReplaceAll}
							}
							if tr.NotebookPath != nil {
								nb := &notebookResult{path: *tr.NotebookPath, failed: tr.Error != ""}
								if tr.Original != nil {
									nb.original = *tr.Original
								}
								if tr.Updated != nil {
									nb.updated = *tr.Updated
								}
								res.notebook = nb
							}
							if tr.Type == "text" && tr.File != nil && tr.File.whole() {
								res.read = tr.File.Content
							}
							res.bash = &bashResult{interrupted: tr.Interrupted, isImage: tr.IsImage, backgroundTask: tr.BackgroundTaskID, interpretation: tr.ReturnCodeInterpretation}
						}
					}
					res.isError = b.IsError
					res.cwd = r.Cwd
					if len(r.ToolUseResult) == 0 || string(r.ToolUseResult) == "null" {
						if t := resultText(b.Content); !b.IsError && (strings.HasPrefix(t, writeCreated) || strings.HasPrefix(t, writeUpdatedHead)) {
							res.text = t
						}
					}
					results[b.ToolUseID] = res
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
	writeUnknown := 0
	for _, u := range uses {
		base := models.TrajectoryEntry{Timestamp: u.ts, ThreadID: u.thread, Tool: u.name}
		res, hasResult := results[u.id]
		if u.name == toolWrite && res.kind == "" && res.text != "" {
			res.kind = writeKindFromText(res.text, inputPath(u.input))
		}
		if hasResult && !res.ts.Before(u.ts) {
			e := res.ts
			base.End = &e
		}
		if perMessage[u.messageID] > 1 {
			base.BlockID = u.messageID
		}
		entries, why := claimsFor(u, base, res)
		if why == "" && u.name == toolBash && hasResult && harnessReadVersions[rep.AgentVersion] {
			entries = append(entries, harnessReadClaims(u, base, res)...)
		}
		if u.name == toolWrite && why == "" && res.kind != "create" && res.kind != "update" {
			writeUnknown++
		}
		switch why {
		case "":
			tr = append(tr, entries...)
		case reasonNonEffectful, reasonFailed:
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
	// Adjacent opens of one file are one access, on the observed side too.
	tr = collapseOpenClaims(tr)
	rep.Entries = len(tr)
	rep.Degradations = []string{
		"claim start is the moment the model emitted the call and includes approval latency, so the interval cannot bound execution (D13)",
		"the format records no process exit code, so exits are not aligned (I-15)",
		"file-tool claim shapes follow one paired capture of version " + capturedVersion + ": a Write or Edit is claimed as one atomic replace (temp file and rename) or, as one capture of 2.1.296 showed, one in-place rewrite of an existing file (I-45), and a variant not seen, such as a direct write in another shape, will show as unexplained",
	}
	if writeUnknown > 0 {
		rep.Degradations = append(rep.Degradations, fmt.Sprintf("%d Write call(s) have no create or update result, so they are assumed to overwrite an existing file", writeUnknown))
	}
	if len(unknown) > 0 {
		rep.Degradations = append(rep.Degradations, fmt.Sprintf("tools with no mapping and not declared non-effectful: %s; their effects, if any, will appear unexplained", strings.Join(rep.UnknownTools, ", ")))
	}
	return tr, rep, nil
}

// harnessReadClaims are the harness-implied claims of a Bash call (I-46,
// V-33): one open of each file the harness reads after the call when its
// command is a simple read command, after the call's own claim and in its
// block, marked with the command. The harness reads only some of them (not a
// file already in its record of file state), so each is optional and the
// verifier lets it pair only with the exact open the command made first.
// None when the transcript shows that the read did not happen (the call was
// interrupted, sent to the background or returned an image, or a search did
// not exit 0), when a search's exit is not shown, or when the working
// directory is not recorded, or changed, between the call and its result.
func harnessReadClaims(u toolUse, base models.TrajectoryEntry, res toolResult) []models.TrajectoryEntry {
	var in struct {
		Command    string `json:"command"`
		Background bool   `json:"run_in_background"`
	}
	if json.Unmarshal(u.input, &in) != nil || in.Command == "" || in.Background {
		return nil
	}
	if u.cwd == "" || res.cwd != u.cwd || !filepath.IsAbs(u.cwd) {
		return nil
	}
	if b := res.bash; b != nil && (b.interrupted != nil && *b.interrupted || b.isImage || b.backgroundTask != "") {
		return nil
	}
	var out []models.TrajectoryEntry
	seen := map[string]bool{}
	for _, r := range readCommandFiles(in.Command) {
		// A search reads only on exit 0, which the transcript shows as a
		// full Bash result with no interpretation of the exit and no error.
		if r.exitZero && (res.bash == nil || res.bash.interrupted == nil || res.bash.interpretation != "" || res.isError) {
			continue
		}
		path := resolveRead(u.cwd, r.path)
		if seen[path] {
			continue
		}
		seen[path] = true
		e := base
		e.ActionType, e.Target, e.ImpliedBy = models.FileOpen, path, in.Command
		out = append(out, e)
	}
	return out
}

const (
	reasonNonEffectful = "non-effectful"
	reasonUnknown      = "unknown"
	// reasonFailed is a call whose result says it failed, so it claims no
	// effect (I-37).
	reasonFailed = "failed"
)

// notebookClaims maps a NotebookEdit (I-37, I-39). The harness reads the
// notebook and replaces it atomically, as an Edit does, so the call claims an
// open and a write of notebook_path. Its result holds the notebook before and
// after; the text after is the content written (checked on one capture of
// 2.1.296, where its hash equals the observed close's) and becomes the
// write's output hash. A failed call, marked by is_error or a non-empty
// error, claims nothing.
func notebookClaims(path string, res toolResult, mk func(models.ActionType, string) models.TrajectoryEntry) ([]models.TrajectoryEntry, string) {
	if path == "" {
		return nil, "no notebook_path"
	}
	if res.isError || (res.notebook != nil && res.notebook.failed) {
		return nil, reasonFailed
	}
	open, write := mk(models.FileOpen, path), mk(models.FileWrite, path)
	// An empty text is what the harness reports when it did not write the
	// file itself, and is never a notebook: no claim of content.
	if nb := res.notebook; nb != nil && nb.path == path && nb.updated != "" {
		write.OutputHash = models.StringPtr(contentHash(nb.updated))
	}
	return []models.TrajectoryEntry{open, write}, ""
}

// What a Write's tool_result says, in the harness's own words (2.1.296):
// "File created successfully at: <path>" or "The file <path> has been
// updated successfully.", either followed by notes that start with a space.
// A subagent's transcript keeps only this text: it has no structured result.
const (
	writeCreated     = "File created successfully at: "
	writeUpdatedHead = "The file "
	writeUpdatedTail = " has been updated successfully."
)

// writeKindFromText reads a Write's create or update from its result text
// (I-35). The text must name exactly the claimed path; anything else is no
// kind, and the Write is assumed to overwrite as before.
func writeKindFromText(text, path string) string {
	if path == "" {
		return ""
	}
	if c := writeCreated + path; text == c || strings.HasPrefix(text, c+" ") {
		return "create"
	}
	if strings.HasPrefix(text, writeUpdatedHead+path+writeUpdatedTail) {
		return "update"
	}
	return ""
}

// resultText returns a tool_result's text: the content string, or the text
// of its blocks joined. Anything else is no text.
func resultText(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &blocks) != nil {
		return ""
	}
	var b strings.Builder
	for _, x := range blocks {
		if x.Type == "text" {
			b.WriteString(x.Text)
		}
	}
	return b.String()
}

// isAbsent reports whether an optional input field was left out or null.
func isAbsent(raw json.RawMessage) bool {
	return len(raw) == 0 || string(raw) == "null"
}

// inputPath returns a call's file_path input, or "".
func inputPath(raw json.RawMessage) string {
	var in struct {
		FilePath string `json:"file_path"`
	}
	_ = json.Unmarshal(raw, &in)
	return in.FilePath
}

// claimsFor maps one tool call to its claims. A non-empty reason means no entry
// was produced and says why.
func claimsFor(u toolUse, base models.TrajectoryEntry, res toolResult) ([]models.TrajectoryEntry, string) {
	resultKind := res.kind
	if nonEffectful[u.name] {
		return nil, reasonNonEffectful
	}
	var in struct {
		Command  string `json:"command"`
		FilePath string `json:"file_path"`
		Notebook string `json:"notebook_path"`
		Content  string `json:"content"`
		URL      string `json:"url"`
		// A Read's range; either one makes the read partial (I-40).
		Offset   json.RawMessage `json:"offset"`
		Limit    json.RawMessage `json:"limit"`
		Unparsed string          `json:"__unparsedToolInput"`
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
		// A claim keeps the exact path it names, ids included, as the
		// observed event does, so it pairs with that file and no other (I-41).
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
		open := mk(models.FileOpen, in.FilePath)
		// A Read of the whole file as text returns the file's content, so the
		// open claims its hash (I-40). A range, a notebook, an image, a PDF or
		// a result the harness cut claims none.
		if res.read != nil && isAbsent(in.Offset) && isAbsent(in.Limit) {
			open.InputHash = models.StringPtr(contentHash(*res.read))
		}
		return []models.TrajectoryEntry{open}, ""
	case toolWrite, toolEdit:
		if in.FilePath == "" {
			return nil, "no file_path"
		}
		write := mk(models.FileWrite, in.FilePath)
		open := mk(models.FileOpen, in.FilePath)
		if u.name == toolWrite {
			write.OutputHash = models.StringPtr(contentHash(in.Content))
		}
		// An Edit's result holds the file before the edit and the replacement
		// the harness applied, so the final content is known: its hash is the
		// write's, and the file before is the open's (I-31). A result without
		// them (a transcript cut to the type, or several results in one
		// record) leaves both nil, which the verifier reads permissively.
		if u.name == toolEdit && res.edit != nil {
			open.InputHash = models.StringPtr(contentHash(res.edit.original))
			write.OutputHash = models.StringPtr(contentHash(res.edit.apply()))
		}
		// Edit, and Write over an existing file, first open the target. A Write
		// that created the file did not.
		if u.name == toolWrite && resultKind == "create" {
			return []models.TrajectoryEntry{write}, ""
		}
		return []models.TrajectoryEntry{open, write}, ""
	case toolNotebookEdit:
		return notebookClaims(in.Notebook, res, mk)
	case toolGrep:
		return []models.TrajectoryEntry{mk(models.ProcessExec, SearchGrep)}, ""
	case toolGlob:
		return []models.TrajectoryEntry{mk(models.ProcessExec, SearchGlob)}, ""
	case toolWebFetch:
		host := hostOf(in.URL)
		if host == "" {
			return nil, "no usable url"
		}
		return []models.TrajectoryEntry{mk(models.NetConnect, host)}, ""
	}
	return nil, reasonUnknown
}
