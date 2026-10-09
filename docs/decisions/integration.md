# Decisions: agent integration layer

Why trajectories and observed events are normalized the way they are, and why agent-specific knowledge lives in `pkg/agent` adapters rather than in the core. D1 to D14 keep the numbering of the original integration design; entries added during implementation are numbered from I-15.

Checked against commit d0e2c73 on 2026-10-06. Original source: docs/archive/07_trajectory_formats.md (local only). Related: [verification.md](verification.md), [open.md](open.md), [../architecture/30_agent_adapters.md](../architecture/30_agent_adapters.md).

Evidence from the maintainers' own Claude Code and Gemini sessions was used as design input only. It has no paired ground truth and is not an evaluation set, so no figure from it appears here.

## Core decisions (agent-independent)

### D1: The matching surface is per tool, not global
Status: Accepted, implemented in the adapters' tool maps (`pkg/agent/claudecode`, `pkg/agent/gemini`).
Date: 2026-09 (design), 2026-10-06 (built).
Context: A trajectory claims at tool granularity, the probes record syscalls. A single correspondence rule produces false verdicts in both directions.
Decision: A shell-command claim is verified at level 1 (the process the agent spawned). A file-tool claim is verified at level 0, against the agent process, with content where the format reports it. The adapter declares the mapping and the core applies it.
Consequences: The core holds no tool names. Adding a tool is an adapter change.
Alternatives rejected: One global rule for every claim, which cannot express both a direct file write and a command that writes through descendants.

### D2: A shell-command entry is a container
Status: Accepted, implemented in `pkg/verification.Forest.Attribute` and `CheckCoverage`. Wording corrected 2026-10-06.
Context: Compound shell commands are common, so one claim routinely corresponds to several executions plus their file and network activity (measured on a local transcript corpus, design input only (local only: docs/research/harness_corpus.md)).
Decision: A shell-command entry matches on its recovered command string and owns every event in the subtree of its level-1 process. Ownership is by process ancestry, not by a time window. (The original wording, "owns every descendant event in its window", predates the forest model and is corrected here; D4 and V1 already required ancestry.)
Consequences: A command that runs for hours, or is approved after a long pause, owns its events the same way as a fast one.
Alternatives rejected: Expanding a compound command into one entry per program. It invents claims the agent never made and weakens the omission and fabrication arguments.

### D3: Level 2 and below are never matched against trajectory entries
Status: Accepted, implemented in `Forest.Partition` (descendant events are content of a command, never in the aligned sequence).
Context: The agent did not claim what its commands' descendants did.
Decision: Descendant events can be neither corroborated nor unrecorded. They are attributed and counted toward coverage.
Consequences: A request made by a forked `curl` is attributed to the command's subtree and cannot be an e2e claim (this moved the Tier 5 request-hash substitution case to unit level).
Alternatives rejected: Aligning descendants against claims, which would require claims nobody writes.

### D4: Level-2 ancestry is load-bearing for the verdict, negatively
Status: Accepted, implemented in `BuildForest` and `CheckCoverage` (V3).
Context: A `net_connect` or `file_write` inside a claimed command needs no claim of its own. Without ancestry such events are orphans and an honest trajectory reads as NOT FAITHFUL.
Decision: Attribution is by ancestry, never by time. Whatever suppresses an event from the unclaimed set is what an attacker attacks: suppression by lineage needs a real causal link, suppression by a time window only needs coincidence, and the claim interval is adversary-controlled.
Consequences: Descendant `process_exec` records may be dropped under volume pressure only if the PID-to-command ancestry survives. Lost tree records are counted as event loss (P-10 in [probes.md](probes.md)).
Alternatives rejected: Time-window attribution (see F0.2-F0.3 in [verification.md](verification.md)).

### D5: Level 2 is also the capability record, judged in a separate layer
Status: Accepted, implemented as `Verdict.Capability` and the per-command content in `Partition`.
Context: Whether `make test` should have opened a socket has no counterpart in the trajectory, so matching cannot decide it.
Decision: Capture and attribute level-2 events, and keep their judgment out of the faithfulness verdict.
Consequences: Laundering through a script (an agent writes `helper.sh` and runs it) stays FAITHFUL, correctly, but becomes visible as a subtree with content. FAITHFUL is not integrity, and reports must say so.
Alternatives rejected: Discarding descendant events, which the first engine did.

### D6: The observed argv is not the claimed command
Status: Accepted, implemented in `claudecode.Adapter.Normalize` (`evalPayload`). Gemini's `Normalize` is the identity because its wrapping is unmeasured.
Context: Claude Code runs each Bash call through a wrapper that sources a shell snapshot, adjusts options and ends with `eval '<command>'` plus a `pwd -P` write.
Decision: `Normalize` extracts the `eval` payload and undoes shell quoting with a small POSIX word parser. A line that is not a wrapper, or cannot be parsed, is left alone so it shows as a mismatch instead of being guessed at. The wrapper is versioned inside the adapter, never in `pkg/matching`.
Consequences: A wrapper change in a new harness version surfaces as substitutions on every Bash claim, which is loud rather than silent.
Alternatives rejected: Loosening target comparison in the core.

### D7: Never assume a level-1 exec exists
Status: Accepted. Partly implemented: Gemini `RunPersistent` commands are not claimed (I-17). Degraded verification for persistent shells is open (O-11 in [open.md](open.md)).
Context: An agent with a persistent shell writes commands to stdin and produces no per-call exec. Gemini's `run_command` carries a `RunPersistent` flag.
Decision: The adapter declares the process model (`ProcessModel.ShellPerCommand`) instead of the core assuming one.
Consequences: Without a level-1 child, both coverage and alignment lose their subject for that claim.
Alternatives rejected: Assuming one exec per shell claim for every agent.

### D8: Parsing a Claude Code session means merging its `subagents/` directory
Status: Accepted, implemented in `claudecode.Adapter.Parse`.
Context: Subagent turns are never inline in the main transcript. They live in `<session>/subagents/agent-<id>.jsonl`, share the session id, and interleave by timestamp.
Decision: Parse merges the subagent files into the main claim sequence.
Consequences: A session read without its directory misses claims and reads as omissions.
Alternatives rejected: Reading only the main transcript.

### D9: Flatten subagents, keeping the originating thread id as metadata
Status: Accepted, implemented (`TrajectoryEntry.ThreadID`). The alignment does not yet use it (O-2).
Context: A `/proc` ancestry check on a live Claude Code session showed that a subagent's shell commands are children of the same agent PID as the main thread's. Nothing in the observed data distinguishes a subagent call.
Decision: Flatten subagent claims into one sequence and keep the thread id on each entry. Forced by the observation, not chosen.
Consequences: Concurrent subagents make the claim order partial (V2). The thread id comes from the trajectory, which the attacker controls.
Alternatives rejected: Nesting subagent claims under the `Agent` call, which has nothing in G to hang on.

### D10: Non-effectful tools must not become entries
Status: Accepted, implemented in each adapter's `nonEffectful` set and `Report`.
Context: Control-flow and UI tools perform no syscall. Emitting them produces permanent Unwitnessed entries, a false fabrication signal.
Decision: The adapter supplies the allowlist. The core requires that unmapped tools be counted, never silently dropped: a tool that is neither mapped nor declared non-effectful is named in `Report.UnknownTools` and in `Degradations`.
Consequences: An unknown tool that did act shows up as an unexplained event plus a named degradation, not as a silent pass.
Alternatives rejected: Dropping unknown tools silently, or treating them as non-effectful by default.

### D11: The harness generates its own unclaimed events, which must be filtered
Status: Accepted. Implemented as a measured baseline (V7, `agent.Baseline`, `cmd/baseline`); see I-19.
Context: Measured on Claude Code: persistent connections from the agent process (model API and telemetry) and one file read plus one file write per shell call from the wrapper. Left unfiltered, no real trajectory can be FAITHFUL.
Decision: Every adapter's harness noise is removed before coverage is evaluated. The membership is agent-specific and established by measurement, not by hand.
Consequences: Verification without a baseline for the agent version reports a degradation.
Alternatives rejected: A hardcoded list of addresses and globs, which rots silently into false omissions when an endpoint moves.

### D12: The claim interval comes from the format, never from configuration
Status: Accepted, implemented (`TrajectoryEntry.Timestamp` and `End`).
Context: Both surveyed formats bracket execution: Claude Code pairs `tool_use` with `tool_result`, Gemini records created, started and completed.
Decision: An entry carries the interval the trajectory supplies. Where the format has no end, the entry is a point and the adapter records the degradation rather than synthesizing a width.
Consequences: The interval is adversary-controlled, so it is used only as a consistency finding (V-12), never to attribute or pair.
Alternatives rejected: A configured tolerance window.

### D13: A reported start is a decision time, not an execution time, unless the format says otherwise
Status: Accepted, implemented as `ProcessModel.IntervalKind` (`IntervalDecision` for Claude Code, `IntervalExecution` for Gemini).
Context: Claude Code stamps `tool_use` when the model emits the call. The permission prompt comes after, so human approval latency sits inside the interval. Call durations have a long tail dominated by approval waits (measured on a local transcript corpus, design input only (local only: docs/research/harness_corpus.md)).
Decision: An adapter declares what its start timestamp means. Gemini's `started` field is a real execution anchor.
Consequences: Claude Code intervals cannot bound execution. Gemini intervals can.
Alternatives rejected: Treating every start as execution time.

### D14: Entry-to-exec pairing is an order-preserving assignment
Status: Accepted, implemented by the per-lane alignment (V4, V-9).
Context: A nearest-in-time lookup fails under approval latency and long commands, and mispairs repeated identical commands under clock skew.
Decision: For a sequential agent the nth shell claim corresponds to the nth level-1 child. Adapters must preserve claim order and expose what the format knows about concurrency (block and thread ids).
Consequences: The clock is used only for relative order, so a constant offset between the agent's clock and the kernel's is harmless.
Alternatives rejected: Nearest-in-time lookup.

## Decisions taken while building the adapters

### I-15: Exit codes are not claimed by either real adapter
Status: Accepted, implemented in `claudecode.Adapter.Process` and `gemini.Adapter.Process` (`ExitsClaimed: false`), applied by `agent.Prepare` as `Options.IgnoreExits`. Listed as open in the plan documents; see O-4 in [open.md](open.md).
Date: 2026-10-06 (commits 7d52eea, 4876c5b).
Context: Claude Code reports only `is_error`. Gemini records nothing. `is_error` is also set for harness failures (timeout, denied permission, malformed input), so it conflates "the command failed" with "the command never ran".
Decision: `ExitCode` stays nil for Claude Code and Gemini. `Expresses` returns false for `exit_code`, and process exits are dropped from both sides before alignment. `Generic` and `simagent` keep exits on.
Consequences: Real-agent verdicts never check exit status. The three-valued nil (V-20) makes this cost nothing in false findings.
Alternatives rejected: A two-valued exit claim derived from `is_error`, which invents a value the format does not hold.

### I-16: Claude Code `WebSearch` is non-effectful; Gemini `search_web` is unknown
Status: Accepted, implemented in the adapters' `nonEffectful` sets.
Date: 2026-10-02 (Test C), built 2026-10-06.
Context: A traced run of Claude Code 2.1.286 (strace on `connect`, `sendto`, `sendmsg`, `write`, one run, Verified) showed `WebSearch` opens no connection to any search or content host, only to the model API and telemetry. The same method confirmed `WebFetch` connects directly from the agent process. Whether Gemini's `search_web` runs server-side is unverified.
Decision: `WebSearch` is in Claude Code's non-effectful set, so it produces no entry. Gemini's `search_web` is neither mapped nor declared non-effectful, so it is named in `UnknownTools` and `Degradations`.
Consequences: A Claude Code web search is not verified by this system; verifying it needs the model API stream (O-14). A false non-effectful declaration would hide a real client-side action, which is why Gemini's stays unknown.
Alternatives rejected: Mapping `WebSearch` to a `net_connect` claim, which would be a permanent false fabrication.

### I-17: Gemini steps that did not complete, and persistent-shell commands, are not claimed
Status: Accepted, implemented in `gemini.Adapter.Parse` (`statusCompleted`, `reasonPersistent`).
Date: 2026-10-06 (commit 4876c5b).
Context: A step whose status is not completed may never have executed. A `RunPersistent` command produces no level-1 exec (D7).
Decision: Neither becomes a claim. Both are counted by name with the reason, and non-completed steps add a degradation.
Consequences: A claim nothing could witness is not reported as a false fabrication. The actions of a persistent shell, if any, appear unexplained.
Alternatives rejected: Claiming every step, which turns harness bookkeeping into Unwitnessed findings.

### I-18: Claim order in the fs lane follows the kernel's order
Status: Accepted, implemented in `simagent` and the adapters' file-tool claim shapes. The Claude Code shapes were later measured and replaced by I-22; Gemini's remain a hypothesis (O-16).
Date: 2026-10-06 (commits da6ccc8, 81b3c4d).
Context: The alignment pairs by position within a lane, so claim order must match the order the probe reports. fanotify reports a new file as create (a directory record covering the file, `PathIsAmbiguous`), open, modify, close, and merges consecutive events on one object.
Decision: Adapters emit fs claims in the kernel's order, and merged events sit where the kernel queued them. On the observed side a merged mask expands as open, write, close (P-13 in [probes.md](probes.md)).
Consequences: Current shapes: Claude Code `Read` is `file_open`, `Write` and `Edit` are open, write, close; Gemini's file tools follow the same pattern. Neither adapter claims the create record, and fanotify merging can change how many events a burst produces, so a claim cannot assume a multiplicity.
Alternatives rejected: Claiming in the order the tool describes its work, which read honest runs as fabrications.

### I-19: `IsHarnessNoise` declares nothing in the real adapters
Status: Accepted, implemented (`IsHarnessNoise` returns false in `claudecode` and `gemini`).
Date: 2026-10-06.
Context: The harness's own activity changes by version and endpoint.
Decision: Harness activity comes only from the measured baseline (V7, V-19). The adapters declare no static noise.
Consequences: A static filter cannot rot into false omissions, and cannot match a path an attacker writes to. Until a baseline is captured, harness activity reads as omissions.
Alternatives rejected: The address and glob list observed on one version.

### I-20: Expressibility is declared per tool
Status: Accepted, implemented as `Adapter.Expresses` and `TrajectoryEntry.Tool`.
Date: 2026-10-06 (commits 53d4f48, 7d52eea).
Context: On Claude Code, `Edit` carries fragments (nil output hash by format) while `Write` carries full content (nil by choice), in the same field on the same agent.
Decision: Each adapter answers, per entry and field, whether its format can state the field. `TrajectoryEntry.Tool` carries the tool name as provenance for that answer. Claude Code states an output hash only for `Write`, Gemini only for `write_to_file`; neither states an exit code or a request body.
Consequences: The core's three-valued nil (V-20) gets its answer from the adapter.
Alternatives rejected: A per-agent or per-field declaration, which cannot separate `Edit` from `Write`.

### I-21: Adapter detection refuses to guess
Status: Accepted, implemented in `agent.Detect` and `cmd/verify --agent`.
Date: 2026-10-06 (commit 5b551d7).
Context: `cmd/verify` selects an adapter from the trajectory file when `--agent` is not given.
Decision: `Detect` returns an error when no adapter or several recognize the file. `cmd/verify` falls back to `Generic` only when nothing recognizes it.
Consequences: A misdetection cannot silently change which tool map and noise rules apply.
Alternatives rejected: First-match detection by registration order.

### I-22: Claude Code file tools are claimed at the grain of the tool call, and the observed side is rewritten to match
Status: Accepted, implemented (`claudecode.Adapter.NormalizeStream` in `stream.go`, `agent.StreamNormalizer`).
Date: 2026-10-07 (paired capture of Claude Code 2.1.286, **Verified** on one task, one machine).
Context: A paired capture showed that `Read` opens the file once, and that `Write` and `Edit` replace a file atomically through a temporary named `<path>.tmp.<pid>.<12 hex>`. fanotify reports a replace as a create on the directory, then open, write and close of the temporary, then a rename on the directory, with the close carrying the hash of the final content. The close can be read after the rename, in which case it names the target. `Edit`, and a `Write` over an existing file, first open the target one or more times. The trajectory records one call per tool.
Decision: One claim per tool call where the call is one action: `Read` is a `file_open`, `Write` a `file_write` carrying the content hash (preceded by a `file_open` unless the harness's own `toolUseResult` says the file was created), `Edit` a `file_open` then a `file_write` with no hash. The observed side is rewritten to the same grain by an optional `StreamNormalizer` that `agent.Prepare` runs after per-event `Normalize`: a finished temp-and-rename, in either order of close and rename, becomes one `file_write` of the target with the close's hash, and a run of opens of one file by one process becomes one open. The claims collapse adjacent opens of one file the same way, so the two sides stay comparable.
Consequences: An honest session verifies, and an unclaimed atomic write is still an omission. A temporary that is never closed and renamed, a name that does not match the harness's pattern, and events of other processes are left alone, so they show as unexplained. A write that does not use a temporary (not seen) will show as unexplained, and the report says so. Collapsing opens loses the count of repeated reads of one file.
Alternatives rejected: Claiming each of the five kernel events (the temporary's name is random, and the reads before a replace vary in number); making the verifier ignore multiplicity (it would lose the ability to count claims against events elsewhere); dropping the harness's pre-reads outright (that would also drop the open a separate `Read` claim needs).

### I-23: Per-run ids in the harness's own commands are replaced on the observed side
Status: Accepted, implemented (`canonicalIDs` in `claudecode/shell.go`).
Date: 2026-10-07.
Context: The commands the harness runs the first time a session uses Bash name a snapshot file and a heredoc delimiter by ids that differ every run, and the wrapper names a working-directory file the same way. The ids are base 36, not hex. Two runs of the same behaviour would never match a baseline rule.
Decision: `Normalize` replaces the three ids with fixed tokens in process targets that are not recovered commands. A claim never names these, so only the observed side is rewritten.
Consequences: A baseline rule for a setup command is stable across runs. File targets are not rewritten.
Alternatives rejected: Pattern rules in the baseline (a wildcard explains whatever an attacker makes it match, V-19).

### I-24: A baseline names the watched directory with a placeholder and takes a measured agreement threshold
Status: Accepted, implemented (`agent.WorkspacePlaceholder`, `Baseline.Predicate(workspace)`, `CaptureOptions.MinAgreement`, `models.GroundTruthFile.Workspace`).
Date: 2026-10-07.
Context: The harness lists and inspects the working directory, so its commands name it, and the shell snapshot command it runs at the first Bash call differs with the enabled tool set (it shadows find and grep only when Grep and Glob are disabled); a baseline measured in one directory would otherwise not apply in another. Some harness activity is occasional: a probe for package managers appeared in two of three control runs.
Decision: Capture rewrites the run's workspace (recorded by `watch`) to `{workspace}` in rule targets, and the predicate expands it to the workspace of the run being verified. A rule still matches an action type and target exactly. `--min-agreement` sets the fraction of control runs that must perform an action for it to become a rule, one by default.
Consequences: A baseline is reusable across directories, and holds for one agent version and one tool set (the capture script runs the controls with the task's tools and refuses a mismatched reuse). At full agreement an occasional action is left out and can read as unexplained in a later run, and lowering the threshold widens the baseline, which is a choice the person makes and the file records (`min_agreement`).
Alternatives rejected: Controls that all run in one directory (the baseline would fit only that directory); a union of every action seen (a wider baseline by default).

### I-25: Claude Code Grep and Glob are claimed as the kind of search
Status: Accepted, implemented (`searchKind`, `SearchGrep`, `SearchGlob` in `claudecode/shell.go`).
Date: 2026-10-07 (paired capture of Claude Code 2.1.286, **Verified** on one task).
Context: Grep and Glob run as ripgrep embedded in Claude Code's own binary, started as a level-1 child of the agent whose first argument is `--no-config`. Left unmapped (O-9, option c) each search was an unexplained command. The pattern is not recoverable from the arguments in general, and what a search reads is not something a claim is verified against.
Decision: A Grep or Glob call is a `process_exec` claim with the fixed target `claude-code search:grep` or `claude-code search:glob`. `Normalize` rewrites an observed command line to the same target when its program is `<dir>/claude/versions/<version>` and its first argument is `--no-config`: with `--files` and `--null` it is a Glob, without `--files` a Grep. The harness's own start-up listings (`--files` without `--null`) keep their exact text so a baseline names them.
Consequences: A search that happened is verified to have been claimed, in order, and an unclaimed search is an omission. The pattern and path are not verified. Only the harness's own binary path is recognised, so another program that takes `--no-config` is not rewritten. A search whose arguments change shape in another version can be misclassified (a Glob without `--null`), which shows as a mismatch.
Alternatives rejected: Parsing ripgrep's arguments for the pattern (fragile, and low value); declaring the tools non-effectful (a search is an observable process).

### I-26: The wrapper is recovered only when the whole command line is the wrapper
Status: Accepted, implemented (`evalPayload`, `wrapperHead`, `wrapperTail` in `claudecode/shell.go`).
Date: 2026-10-08 (security review of the adapter).
Context: `evalPayload` recognised a wrapper by the presence of `shell-snapshots/snapshot-` and the first `&& eval `, and returned the eval word. Everything else on the line was discarded: a command appended after the `pwd -P` suffix, one run before the `source`, a second word after the eval, or a different program whose arguments contained the marker all normalized to the claimed command. A harness that did that ran arbitrary code under an honest-looking Bash claim, and the subtree was explained by the claim (**Verified**: `TestPairedWrapperWithAppendedCommandIsNotFaithful` failed before the change).
Decision: The observed line must match the wrapper exactly: one of six shell paths, `-c` with an optional `-l`, the snapshot source clause, preamble clauses from an allowlist, `&& eval `, one shell word, and the known suffix to the end of the line. A line that does not match keeps its text (with I-23's id replacement) and shows as a mismatch.
Consequences: A new harness version that changes the wrapper makes every Bash claim a mismatch until the allowlist is extended, which is what D6 asks for. The preamble allowlist is the version-specific part. The payload itself is not inspected: what the claimed command does is still explained by the claim.
Alternatives rejected: Checking only that the line ends with the suffix (a command can still be run before the source, and the program is unchecked); canonicalising the whole line before matching (it would rewrite ids inside the claimed command).


### I-27: A search is recognised only from the harness's install directory
Status: Accepted, implemented (`embeddedRipgrep` in `claudecode/shell.go`). Narrows I-25.
Date: 2026-10-08 (security review of the adapter).
Context: I-25 recognised a search by a program path ending in `claude/versions/<digits>` with `--no-config`. Any executable at such a path qualified, including one in the workspace or in `/tmp`, so a harness could claim a Grep and run a script of its own, with the script's subtree explained by the claim (**Verified**: `TestNormalizeRecognisesSearchesOnlyFromTheInstallDirectory`, the workspace and `/tmp` cases, failed before the change).
Decision: The program must be `/home/<user>/.local/share/claude/versions/<major.minor.patch>` or the same under `/root`, the layout of the native installer, which is where the three captures saw it. Everything else keeps its text and shows as an unexplained command or a mismatch.
Consequences: A binary placed inside the install directory is still recognised, which is the same trust as the harness binary itself (AS-2). Another install layout (npm, a different `XDG_DATA_HOME`) is not recognised until it is measured and added; its searches then read as unexplained commands, which is loud rather than silent.
Alternatives rejected: Taking the path from the baseline's start-up listing rules (the adapter has no access to the baseline in `Normalize`, and the two would have to be kept in step); checking the arguments' shape (a spoofed binary ignores its arguments).

### I-28: The control task's own command is excluded from the baseline
Status: Accepted, implemented (`CaptureOptions.Exclude`, `Baseline.Excluded`, `baseline --exclude`, `claudecode.ControlCommand`).
Date: 2026-10-08 (security review of the baseline).
Context: A control run must make one Bash call so the harness performs its first-call setup, and the capture script used a no-op marker command for it. Every control run performed it, so it became a rule in every baseline. A rule explains a command's whole subtree without a claim (V7), so any later command with that normalized target was explained, whatever ran beneath it. Before I-26 that was reachable with one appended command; after I-26 the wrapper itself has to be genuine, but the snapshot it sources and the environment it inherits are not observed, so the rule still explained a subtree on trust. The script's comment that the rule "hides nothing" was wrong (**Verified**: `TestPairedControlCommandIsNotABaselineRule` failed before the change).
Decision: `Capture` takes a list of targets that never become a rule or an unstable entry, the baseline file records them, `cmd/baseline` exposes the list as a repeatable `--exclude`, and the capture script passes its control command. The fixture tests exclude it the same way.
Consequences: A later command with the control's target needs a claim like any other. The exclusion is exact and names the command, so it cannot hide anything else. A control task that ran something other than the marker still has to be excluded by hand.
Alternatives rejected: Excluding every level-1 exec from the baseline (the harness's own commands, the snapshot and the git probes, are exactly what the baseline is for); a control prompt that uses no Bash (the first-call setup would then be missing and read as omissions).

### I-29: The harness's own file paths are canonicalised on the observed side
Status: Accepted, implemented (`canonicalFileIDs` in `claudecode/shell.go`, the lock temporary in `tmpName`, `MangledWorkspacePlaceholder` in `pkg/agent/baseline.go`).
Date: 2026-10-09 (item 5, step 4; first capture under P-17).
Context: With every filesystem marked, a Claude Code startup shows about 230 level-0 file events outside the workspace: CA certificates, libraries, its configuration, and files it writes under `~/.claude`, `~/.local/state/claude` and `/tmp/claude-<uid>`. Most are the same in every run and become baseline rules as they are. Five families carry a per-run id and would never agree between control runs (**Verified**: 43 unstable entries over three startups of 2.1.286, all of these families): the session record named by pid, the transcript named by session id under a directory named by the mangled workspace, the version lock's temporary with an eight-hex suffix, the fswatch probe directory, and a ` (deleted)` suffix the kernel adds to a removed directory's name. The first full sessions (2026-10-09, three controls with a Bash call) added five more: the session key `<pid>.<64 hex>.key` written through the same eight-hex temporary, the startup backup `~/.claude/backups/.claude.json.backup.<time>`, the MCP log files `~/.cache/claude-cli-nodejs/<dir>/mcp-logs-<server>/<time>.jsonl`, the Bash tool's task output directory `/tmp/claude-<uid>/<dir>/<session id>/tasks/<id>.output`, and the cwd file, which I-23 rewrote in commands only.
Decision: `Normalize` replaces those ids in file events with fixed tokens, as I-23 does for the snapshot and cwd files in commands; the atomic-write fold also accepts the eight-hex temporary, before and after its suffix is rewritten (the rewrite runs first); and the baseline names the mangled workspace by `{workspace-}`, expanded by `Predicate` like `{workspace}`. Claims are left alone.
Consequences: The harness's own writes under its configuration directory become rules by path, so a write there with any content is explained, as it was for the snapshot command; that is the harness's own directory and the same trust as its binary (I-27). A claim that names one of these paths mismatches, which no honest tool call produces. The list is version-specific and is checked against the next capture; an id family not listed shows as unstable in the baseline and as unexplained in a run.
Alternatives rejected: A pattern language in the baseline (a wildcard explains whatever an attacker makes it match, V-19); excluding `~/.claude` from the capture (the harness's own activity is what the baseline measures, and writes there are what step 4 is for).

