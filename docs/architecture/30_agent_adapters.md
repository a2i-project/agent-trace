# Agent adapters

Checked against commit c4df56f on 2026-10-07.

## Objective

An adapter isolates everything one agent harness does differently from the core verifier: how its session file is read into claims, how observed events are rewritten into the form claims use, what the harness does on its own, and which content fields its format can state. `pkg/matching` and `pkg/verification` contain no agent knowledge; adding an agent means adding a package under `pkg/agent` that implements `agent.Adapter` and registers itself. The design reasons are in [decisions/integration.md](../decisions/integration.md) (D6 to D13) and [decisions/verification.md](../decisions/verification.md) (V2, V7).

The Claude Code adapter has been checked against one paired capture of version 2.1.286 (a real session recorded by `watch` and verified with its own transcript): **Verified** on one five-step task, one machine, three control runs. The capture is a fixture (`pkg/agent/claudecode/testdata/paired-2.1.286`, reduced by `scripts/make-capture-fixture.py`), and an honest trajectory verifies FAITHFUL while six altered ones do not. That is a check that the pipeline works, not an evaluation. The Gemini adapter has not seen a real capture: it is tested on synthetic fixtures, which kernel events its file tools produce is a hypothesis, and it reports that as a degradation. An opt-in test per adapter (`AGENT_TRACE_CLAUDE_CORPUS`, `AGENT_TRACE_GEMINI_CORPUS` naming a directory of session files) checks that real sessions parse without failure.

## Structure

| File | Main symbols |
|---|---|
| `pkg/agent/agent.go` | `Adapter`, `StreamNormalizer`, `ProcessModel`, `IntervalKind`, `Concurrency`, `Report`, `Report.Count`, `Prepare` |
| `pkg/agent/registry.go` | `Register`, `Lookup`, `Names`, `Detect`, `ErrNoMatch` |
| `pkg/agent/generic.go` | `Generic`, `GenericName` (`"generic"`) |
| `pkg/agent/baseline.go` | `Baseline`, `Rule`, `Capture`, `CaptureOptions`, `WorkspacePlaceholder`, `Baseline.Predicate`, `SaveBaseline`, `LoadBaseline`, `BaselineSchema` |
| `pkg/agent/claudecode/` | `Adapter` registered as `"claude-code"`; `claudecode.go` (parse, mapping), `shell.go` (`evalPayload`, `shellWord`, `canonicalIDs`), `stream.go` (`NormalizeStream`, `collapseOpenClaims`), `hash.go` |
| `pkg/agent/gemini/` | `Adapter` registered as `"gemini"`; `gemini.go` (SQLite reading, mapping), `wire.go` (protobuf wire-format walker) |

### The Adapter interface

```go
type Adapter interface {
	Name() string
	Detect(path string) bool
	Parse(path string) (models.Trajectory, Report, error)
	Normalize(models.GroundTruthEvent) (models.GroundTruthEvent, bool)
	IsHarnessNoise(models.GroundTruthEvent) bool
	Expresses(entry models.TrajectoryEntry, field string) bool
	Process() ProcessModel
}
```

`StreamNormalizer` is an optional second interface, `NormalizeStream(models.GroundTruth) models.GroundTruth`, for an adapter whose observed events are comparable only when several are looked at together (I-22). `Name` keys the registry and the baseline file. `Parse` returns entries in claim order, each with its interval (`Timestamp`, `End`), its `ThreadID` where subagents were flattened, its `BlockID` where the format issued several calls at once, and its `Tool`. `Normalize` returns false to drop an event. `IsHarnessNoise` is what the adapter knows statically; the measured baseline is supplied separately. `Expresses` answers for one of the `verification.Diff*` field names.

### ProcessModel

| Field | Meaning |
|---|---|
| `ShellPerCommand` | Each shell claim execs its own process, so claims align at level 1. False means a persistent shell, where both checks lose their subject. |
| `SubagentsInProcess` | Subagent actions are indistinguishable from main-thread ones in G, which forces flattening (D9). |
| `Containerized` | Observed paths and pids live in another namespace. No adapter handles it. |
| `IntervalKind` | `IntervalNone` (a point), `IntervalDecision` (start is when the model decided, includes approval latency), `IntervalExecution` (start is when execution began). |
| `Concurrency` | `Sequential`, `Parallel` (entries sharing a `BlockID` have no order among themselves), `ConcurrencyUnmeasured`. |
| `ExitsClaimed` | The format records process exits. False makes `Prepare` set `Options.IgnoreExits`. |

Only `ExitsClaimed` changes verifier behaviour today. The other fields are declarations; `Concurrency` in particular is not consumed, because the verifier does not implement the partial order ([20_verifier.md](20_verifier.md), Known limits).

### Report

`Report` makes what was not measured visible: `ToolCalls` (invocations in the session), `Entries` (claims produced), `UnmappedByTool` (tool calls that produced no entry, by name), `UnknownTools` (tools neither mapped nor declared non-effectful, which may have acted unseen), `ParseErrors`, and `Degradations` (each precision loss in words). `cmd/verify` prints all of them before the verdict.

## Technologies

Go. The Claude Code adapter reads JSONL with `bufio.Scanner` (lines up to 64 MiB) and `encoding/json`. The Gemini adapter opens the conversation database read-only through `modernc.org/sqlite` (pure Go, no cgo) and decodes the undocumented protobuf step payload with a hand-written wire-format walker (`wire.go`), since no `.proto` is available. Content hashes use `pkg/content.SHA256Bytes` (`sha256:<hex>`).

## Workflow

### Registry and detection

Each adapter package calls `agent.Register` from `init`. `Register` panics on an empty or duplicate name. A command makes an adapter available by importing its package (`cmd/verify` and `cmd/baseline` blank-import `claudecode` and `gemini`).

`agent.Detect(path)` asks every registered adapter, in sorted name order, whether it recognises the path. Exactly one match returns that adapter. No match returns an error wrapping `ErrNoMatch`, so a caller can fall back to the generic adapter. Several matches return an error naming them; the caller must choose with `--agent`. The generic adapter never detects.

### From session to verifier input

`agent.Prepare(a, claims, groundTruthFile, measured, opts)` builds a `verification.Input`: it runs every observed event through `a.Normalize` (dropping those it rejects), then through `NormalizeStream` when the adapter implements it, combines `a.IsHarnessNoise` and the measured baseline into one predicate (an event is harness activity if either says so), sets `opts.Expresses = a.Expresses` and `opts.IgnoreExits = !a.Process().ExitsClaimed`, and copies `RootPID` and `Coverage` from the file. Caller options such as `IntervalSlack` are kept.

### Generic

`Generic` reads a trajectory already in the normalized JSON form (`models.ParseTrajectory`, which rejects unclaimable action types). It normalizes nothing, declares no noise, treats every field as expressible, and declares `ShellPerCommand`, `IntervalNone`, `Sequential` and `ExitsClaimed: true`. Its report carries one degradation saying so. It is the adapter for `cmd/simagent` output and for an agent whose format has been converted elsewhere.

### Claude Code (`claude-code`)

Detect: a `.jsonl` file in which one of the first 20 lines decodes with non-empty `sessionId`, `type` and `version`.

Parse reads the main transcript, then every `<session>/subagents/agent-*.jsonl` in sorted order (D8), with the file's id as `ThreadID`. It collects `tool_use` blocks and the timestamp of each matching `tool_result`. Calls are sorted by `tool_use` timestamp, ties in file order. A message holding more than one `tool_use` gives its entries `BlockID` = the message id. `End` is the `tool_result` timestamp when it is not before the start.

| Tool | Claims (in order) | Target | Content |
|---|---|---|---|
| `Bash` | `process_exec` | `input.command` | none |
| `Read` | `file_open` | `input.file_path` | none |
| `Write`, result `create` | `file_write` | `input.file_path` | `output_hash` of `input.content` |
| `Write`, result `update` (or no result kind, assumed) | `file_open`, `file_write` | `input.file_path` | `output_hash` of `input.content` on the write |
| `Edit` | `file_open`, `file_write` | `input.file_path` | none (fragments only) |
| `WebFetch` | `net_connect` | hostname of `input.url` | none |
| Non-effectful: `Agent`, `Task`, `AskUserQuestion`, `ToolSearch`, `Skill`, `ScheduleWakeup`, `TodoWrite`, `ExitPlanMode`, `EnterPlanMode`, `WebSearch`, `TaskOutput`, `TaskStop`, `SendMessage`, `TaskCreate`, `TaskUpdate`, `TaskGet`, `TaskList` | none, counted in `UnmappedByTool` | | |
| Any other tool (for example `Grep`, `Glob`) | none, counted and listed in `UnknownTools` | | |

`WebSearch` is non-effectful because Claude Code runs it server-side, so the host never sees it (verified once). An input marked `__unparsedToolInput`, an unreadable input or a missing target field produces no entry and a parse error.

| Declaration | Value |
|---|---|
| `Process` | `ShellPerCommand: true`, `SubagentsInProcess: true`, `IntervalDecision`, `Parallel`, `ExitsClaimed: false` |
| `Expresses` | `exit_code`: never. `request_hash`: never. `output_hash`: only for `Tool == "Write"`. Other fields: yes. |
| `Normalize` | For `process_exec` and `process_exit`, if the target contains `shell-snapshots/snapshot-` and `&& eval `, replaces it with the eval payload read as one POSIX shell word (`evalPayload`). Otherwise it replaces the per-run ids (snapshot file, working-directory file, heredoc delimiter) with fixed tokens (I-23) and leaves the rest unchanged, so an unrecognised wrapper shows as a mismatch rather than a guess (D6). |
| `NormalizeStream` | Folds a finished temp-and-rename (`<path>.tmp.<pid>.<12 hex>`: create on the directory, open, write, close and rename, the close and rename in either order) into one `file_write` of the target carrying the close's hash, and collapses a run of opens of one file by one process into one. Events of other processes, an unfinished replace and a name that is not the harness's pattern are left alone (I-22). |
| `IsHarnessNoise` | Declares nothing; harness activity comes from the measured baseline (D11). |
| Degradations | Decision-time start (D13); no exit codes, so exits are not aligned; file-tool claims are one atomic replace as measured on 2.1.286, and a variant not seen shows as unexplained; Write calls with no create or update result assumed to overwrite; unknown tools when present. |

Claims are rewritten the same way: `collapseOpenClaims` merges adjacent opens of one file among the file claims, since commands and connections are other lanes and do not break a run. The structured result of the call (`toolUseResult.type`, on the user record that carries the `tool_result`) is read only when the record holds a single result.

The exit code is not expressible because the format records only an `is_error` flag, which conflates a failed command with one that never ran.

### Gemini (`gemini`)

Detect: a file starting with the SQLite header whose `steps` table has a `step_payload` column.

Parse reads `steps` ordered by `idx` and decodes each payload. Tool calls are the submessages at protobuf path 5.4: field 1 the call id, 2 the tool name, 3 the arguments as a JSON string. The claim start is the started timestamp (5.6), falling back to created (5.1) with a degradation; `End` is completed (5.8) when present. Entries are sorted stably by start. A step with more than one call gives its entries `BlockID` = `step-<idx>`. Parse fails loudly, naming the field path, when a payload does not decode, a call lacks its name or arguments, the arguments are not JSON, a step has no timestamp, or the database has no steps: a version that moves a field number must produce an error, never an empty trajectory.

| Tool | Claims (in order) | Target | Content |
|---|---|---|---|
| `run_command` | `process_exec` | `CommandLine` | none |
| `run_command` with `RunPersistent: true` | none, counted as persistent shell (D7) | | |
| `view_file` | `file_open` | `AbsolutePath` | none |
| `write_to_file` | `file_open`, `file_write`, `file_close` | `TargetFile` | `output_hash` of `CodeContent` on `file_close` |
| `replace_file_content`, `multi_replace_file_content` | `file_open`, `file_write`, `file_close` | `TargetFile` | none |
| `read_url_content` | `net_connect` | hostname of `Url` | none |
| Non-effectful: `manage_task`, `send_message`, `ask_question`, `ask_permission`, `list_permissions`, `schedule`, `invoke_subagent`, `define_subagent`, `manage_subagents` | none, counted | | |
| Any other tool (for example `list_dir`, `grep_search`, `find_by_name`, `search_web`) | none, counted and listed in `UnknownTools` | | |

A call in a step whose status is not completed (3) is counted as `<tool> (status N)` and not claimed, since whether it executed is unknown.

| Declaration | Value |
|---|---|
| `Process` | `ShellPerCommand: true` (unverified), `SubagentsInProcess: false`, `IntervalExecution`, `ConcurrencyUnmeasured`, `ExitsClaimed: false` |
| `Expresses` | `exit_code`: never. `request_hash`: never. `output_hash`: only for `Tool == "write_to_file"`. Other fields: yes. |
| `Normalize` | Identity: how Gemini wraps the commands it runs is unmeasured. |
| `IsHarnessNoise` | Declares nothing. |
| Degradations | Process model unmeasured; wrapping unmeasured; no exit codes; file-tool claim shapes a hypothesis; plus, when present, subtrajectory steps not followed, persistent-shell commands not claimed, non-completed steps not claimed, created time used as start, unknown tools. |

### Baseline construction

A baseline is the harness's own activity, measured by control runs in which the agent is given a task that claims nothing, so everything it does is the harness (D11, V7).

`agent.Capture(a, version, runs, now, opts)` requires at least one run and a root pid in each. For each run it normalizes events with the adapter, builds the forest and partition, and takes the distinct `(action_type, target)` pairs of `Partition.Observed`: the agent's own level-0 events and each command's own exec and exit. Descendants of a command are not rules, since a command explains its subtree. A pair seen in at least `opts.MinAgreement` of the runs (default 1, every run) becomes a `Rule`; a pair seen in fewer goes to `Unstable`, which is recorded for the reader and subtracts nothing. The run's own workspace (recorded by `watch` in the ground truth file) is replaced by `{workspace}` in each target (I-24). Both lists are sorted. The `Baseline` records `Schema`, `Agent`, `AgentVersion`, `Captured` (UTC), `Runs` and `MinAgreement`.

`Baseline.Predicate(workspace)` recognises an event when a rule has exactly its action type and target, with the placeholder expanded to the workspace of the run being verified (a rule that names the placeholder matches nothing when no workspace is known). There is no pattern matching, since a wildcard would explain whatever an attacker made it match. `LoadBaseline` rejects an unknown schema and a baseline that names no agent. `cmd/baseline` additionally refuses a control run with no coverage record or with any loss counter set, since a short baseline reads as false omissions later; `cmd/verify` refuses a baseline captured for a different adapter name ([40_tools.md](40_tools.md)).

### Onboarding a new agent

Answer these questions, then encode each answer in the named place.

| Question | Encoded in |
|---|---|
| Where do session artifacts live, and what is the encoding? How is one recognised? | `Detect`, `Parse` |
| Which tools are effectful, and which are not? | `Parse` mapping; a non-effectful set; everything else to `UnknownTools` |
| For each effectful tool, which field holds the target, and which kernel events does it produce, in kernel order? | `Parse` claim shapes (fs claims must follow fanotify order) |
| Does a shell claim exec its own process, or is the shell persistent? (D7) | `ProcessModel.ShellPerCommand`; persistent calls counted, not claimed |
| Is the observed command line the claimed command, or a wrapper? (D6) | `Normalize` |
| Is the trajectory one stream, or split across files? (D8) | `Parse` merging |
| Are subagents separate processes or in-process? (D9) | `ProcessModel.SubagentsInProcess`, `ThreadID` |
| What does the harness do on its own? (D11) | A measured baseline via `cmd/baseline`; `IsHarnessNoise` only for what is static |
| Where do start and end timestamps come from, and does the start mean decision or execution? (D12, D13) | `Timestamp`, `End`, `ProcessModel.IntervalKind` |
| Which content fields can the format state, per tool? Does it record exits? | `Expresses`, `ProcessModel.ExitsClaimed` |
| Do observed paths and pids share a namespace with the trajectory's? | `ProcessModel.Containerized` (unhandled) |
| Can the agent issue several calls at once? (V2) | `ProcessModel.Concurrency`, `BlockID` |

Then: create `pkg/agent/<name>`, register from `init`, blank-import the package in `cmd/verify` and `cmd/baseline`, list every precision loss in `Report.Degradations`, and test `Detect`, the mapping, the `Expresses` table, the process model, loud failure on malformed input, and an honest synthetic session that verifies FAITHFUL after normalization. Finally capture a baseline from several control runs and check the adapter against a real paired capture.

## Guarantees and loss accounting

- No tool call is dropped silently: in both real adapters every call either produces entries or is counted in `UnmappedByTool`, and an unknown tool is also listed in `UnknownTools` (`TestParseCountsWhatItDoesNotMap`, `TestParseCountsAndNamesWhatItDoesNotClaim`).
- A format limit is never read as an opt-out: `Expresses` turns a nil that the format cannot state into no finding, and `ExitsClaimed: false` removes exits from both sides rather than reporting every exit as an omission.
- Detection never guesses between adapters (`TestDetectRefusesToGuessBetweenAdapters`).
- The Gemini adapter fails with the field path rather than returning a partial trajectory when the payload layout changes.
- A baseline only subtracts exact `(action_type, target)` pairs that enough control runs produced, from loss-free runs, for the adapter it was captured with.

## Known limits

- The Claude Code claim shapes rest on one paired capture of one version on one task. A write that does not use a temporary file, a different version, or a tool not exercised (`NotebookEdit`, `MultiEdit`, parallel calls, subagents) is unchecked. The Gemini adapter has not seen a real capture.
- Some harness activity is occasional (a package-manager probe appeared in two of three control runs). At full agreement it is left out of the baseline and can read as unexplained in a later run.
- `Concurrency`, `SubagentsInProcess`, `ShellPerCommand` and `IntervalKind` are declarations only; the verifier does not read them.
- The Claude Code adapter's command recovery and id canonicalisation depend on the current wrapper and snapshot shapes (`shell-snapshots/snapshot-`, `&& eval`, `PATH_END_`), which are harness-version-specific.
- Collapsing opens loses the count of repeated reads of one file, on both sides.
- The Gemini adapter does no wrapper recovery, so a wrapped command shows as a mismatch.
- The Gemini adapter does not follow subtrajectories and does not set `ThreadID`.
- The Gemini process model (shell per command, subagents, ordering) is unmeasured.
- Gemini commands run with `RunPersistent` and calls in non-completed steps are not claimed.
- Neither real adapter maps search tools (`Grep`, `Glob`, `list_dir`, `grep_search`, `find_by_name`) or Gemini's `search_web`; they are reported as unknown tools.
- A baseline records `AgentVersion` but `cmd/verify` checks only the agent name, not the version.
- `Containerized` is not handled by any adapter.
