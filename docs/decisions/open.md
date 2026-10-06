# Open decisions

The single list of decisions not yet taken. Each entry states the question, the options, what the code does today, and what blocks a decision. When one is decided, it moves to the area file ([probes.md](probes.md), [network.md](network.md), [verification.md](verification.md), [integration.md](integration.md)) and is deleted here.

Checked against commit d0e2c73 on 2026-10-06.

Entries O-1 to O-4 are **contradictions**: a design document says one thing and the code does another. Each is recorded as the code currently behaves, and needs an explicit ruling.

Entries are grouped by area, so IDs are not in sequence. Entries O-18 to O-23 are **proposals** from the observer status review of 2026-10-06 (docs/archive/10_observer_status.md, local only). None is decided.

## Contradictions

### O-1: Default of `Options.Expresses` when no declaration is given
Status: Open. Contradiction.
Date: 2026-10-06.
Question: When `Verify` receives no expressibility declaration, is every field expressible or none?
Options: (a) nil means everything expressible (strict, catches opt-outs in `simagent`); (b) nil means nothing expressible (conservative, never manufactures a mismatch from a format limit).
Current behaviour: (a). `Expresses.can` returns true for nil, and `Generic.Expresses` returns true (V-21). The original migration plan (docs/archive/08_verification_model.md section 7, local only) asked for (b).
Blocked by: Nothing technical. Real adapters always pass a declaration through `agent.Prepare`, so the question affects direct callers, `Generic` and tests.

### O-2: Partial claim order (V2) versus an alignment that ignores it
Status: Open. Contradiction.
Date: 2026-10-06.
Question: How should the alignment treat parallel tool calls and flattened subagents, which make the claim order partial?
Options: (a) linearization checking over the partial order induced by `BlockID` and `ThreadID`; (b) keep two-sequence alignment and report claims sharing a block or thread as a degradation; (c) per-thread alignment, accepting that the thread id is attacker-controlled.
Current behaviour: V2 requires (a). `Align` reads neither `BlockID` nor `ThreadID`; it aligns claims in slice order. Adapters do set both fields. Gemini's `WaitMsBeforeAsync` (a command outliving its step) also weakens the order assumption and is not handled.
Blocked by: A paired capture with parallel calls or concurrent subagents; Gemini's concurrency is unmeasured.

### O-3: P5 says the verdict is binary; the code has three outcomes plus ambiguity
Status: Open. Contradiction.
Date: 2026-10-06.
Question: Is P5 (deterministic, binary verdict) restated, or is the outcome set reduced?
Options: (a) restate P5 as "deterministic given G and its coverage record", with INCONCLUSIVE as a precondition failure on G and `Ambiguous` as a statement about localization only; (b) keep P5 literal and fold INCONCLUSIVE into NOT FAITHFUL.
Current behaviour: Three outcomes (FAITHFUL, NOT FAITHFUL, INCONCLUSIVE, exit codes 0, 1, 2), an `Advisory` flag on NOT FAITHFUL under loss, and `Verdict.Ambiguous` when several minimum-cost alignments exist (V-11, V-13, V-15). The verification model argued for (a) but P5's text was never changed.
Blocked by: A wording decision for [../architecture/00_overview.md](../architecture/00_overview.md).

### O-4: Exit codes, listed open but decided in code
Status: Open in the plan documents; decided in code (I-15). Contradiction.
Date: raised 2026-09; decided in code 2026-10-06.
Question: Does `ExitCode` stay nil for real agents, or is a two-valued claim derived from Claude Code's `is_error`?
Options: (a) stays nil, exits not aligned; (b) derive success or failure from `is_error`.
Current behaviour: (a) for Claude Code and Gemini (`ExitsClaimed: false`, `Expresses` false for `exit_code`). Reason recorded in the adapter: `is_error` also marks harness failures, so it conflates "failed" with "never ran". The status log and the formats and verification documents still list it as open.
Blocked by: Ratification only. Revisit if a format starts recording exit status.

## Verification model

### O-5: Should G carry an observed interval?
Status: Open (deferred).
Date: raised 2026-09; recommendation to defer.
Question: Should exec-to-exit (or first exec to last descendant exit) be compared with the claimed interval?
Options: (a) add it as a consistency finding on claims with a subtree; (b) do not add it.
Current behaviour: Not built. Ancestry attribution already makes a widened interval suppress nothing; what remains is catching duration misreports and interval evasion of V-12.
Blocked by: Nothing; the forest now exists, which was the stated trigger. Needs a priority call.

### O-6: Does ancestry attribution expire?
Status: Open.
Question: A background server started by one command is still its descendant an hour later, or after the session ends. Should its events stay attributed to that claim?
Options: (a) never expire (current); (b) expire at session end; (c) expire after the command's claim interval, reported as a finding.
Current behaviour: (a).
Blocked by: Real sessions with long-lived descendants.

### O-7: Should overlapping claim intervals be a finding?
Status: Open.
Question: A sequential agent cannot produce overlapping intervals, so overlap is an anomaly. Flattened subagents make it legitimate per thread, but the thread id is attacker-controlled.
Options: (a) finding per thread id; (b) report only; (c) ignore.
Current behaviour: (c).
Blocked by: O-2.

### O-8: Is the V7 baseline sufficient at level 0?
Status: Open.
Question: Level 0 has no lineage discriminator and is also where harness activity lives. Can exact-match baseline rules separate harness activity from agent actions there?
Options: (a) exact rules only (current, V-19); (b) add structure, such as per-phase baselines; (c) accept level-0 findings as advisory.
Current behaviour: (a). No baseline has been captured for a real agent.
Blocked by: Null-task baseline capture per agent and version (needs root).

### O-12: Can any finding survive event loss?
Status: Open.
Question: Which findings are robust enough to keep NOT FAITHFUL without the `Advisory` mark under loss?
Options: Candidates are an unexplained event whose full ancestry chain was observed, and a content mismatch on a pair whose lane neighbours are intact.
Current behaviour: Every finding under loss is NOT FAITHFUL marked `Advisory` (V-15).
Blocked by: A proof per finding kind that it does not depend on a missing event.

## Integration

### O-9: Many-target search tools
Status: Open.
Question: `Glob`, `Grep`, `list_dir`, `grep_search` and `find_by_name` claim a pattern and touch many files. How are they claimed?
Options: (a) containers with no enumerable claim, like D2; (b) non-effectful; (c) unknown, named in the report (current).
Current behaviour: (c). Their file opens at level 0 read as unexplained.
Blocked by: A paired capture showing what these tools produce.

### O-10: Containers and PID namespace translation
Status: Open.
Question: When the agent or its commands run in another PID namespace, how does `Normalize` translate PIDs and paths so V1's walk works?
Options: Not yet designed beyond `ProcessModel.Containerized` and `Normalize`.
Current behaviour: No translation. Both supported agents are host-native.
Blocked by: An integrated containerized agent.

### O-11: Degraded verification for persistent-shell agents
Status: Open.
Question: With no level-1 exec per command (D7), what does a command claim verify against?
Options: (a) declare the degradation and verify only level 0; (b) align level-2 roots against command claims; (c) refuse to verify.
Current behaviour: Gemini `RunPersistent` commands are not claimed (I-17), so their effects appear unexplained.
Blocked by: An agent that uses a persistent shell in practice.

### O-16: File-tool claim shapes and fanotify multiplicity
Status: Open.
Date: 2026-10-06.
Question: Which kernel events does a real `Read`, `Write` or `Edit` produce, and how many?
Options: (a) observed-side coalescing of consecutive same-path, same-PID fs events in `Normalize`; (b) adapter claims that tolerate repeats; (c) both.
Current behaviour: Claims are `Read` = open, `Write`/`Edit` = open, write, close (I-18), a hypothesis. The create record of a new file is not claimed, and fanotify merging changes multiplicity.
Blocked by: A paired capture (needs root). A planned strace experiment hit an account session limit.

### O-17: Is replaying a partial edit ever worth doing?
Status: Open (low priority).
Question: `Edit` and `replace_file_content` carry fragments, not final content. Should the verifier replay the edit to obtain an output hash?
Options: (a) no, nil by format (current); (b) replay, which is reconstruction rather than report.
Current behaviour: (a), declared through `Expresses` (I-20).
Blocked by: Nothing; low value.

## Probes and network

### O-13: Out-of-tree tagging (delegation, part 3)
Status: Open. Premise changed.
Date: deferred 2026-10-02.
Question: Should events outside the agent's tree be captured, tagged and surfaced as findings, to catch delegation to daemons?
Options: (a) as planned: keep out-of-tree fs, net and proc events, tag them, surface them as findings, never let them suppress an unclaimed event; (b) keep them as report-only (current for fs); (c) do nothing more.
Current behaviour: The plan assumed the fs probe would filter by the tracked set, which would make delegated writes vanish. It does not (P-6), so out-of-tree fs events are already in G, placed in `Partition.Outside` (`ZoneOutside`) and reported, not findings (P-15). Out-of-tree proc and net events are not captured.
Blocked by: The baseline (whole-host capture brings noise) and a decision on whether `Outside` events can be findings without making every honest run fail.

### O-14: Verifying Claude Code `WebSearch`
Status: Open.
Question: `WebSearch` runs server-side inside the model API exchange (I-16). How is it verified?
Options: (a) capture the API stream with an `SSL_read` uretprobe plus SSE reassembly (O-19); (b) an N2 proxy, which gives framed responses but is detectable and fails on pinning.
Current behaviour: Not verified; `WebSearch` is non-effectful.
Blocked by: Design choice between (a) and (b), offsets per Bun release for (a), and the unverified join between the transcript `requestId` and the response `request-id` header.

### O-15: The port-53 filter
Status: Open (questioned).
Question: Should DNS stay filtered from ground truth (N-13)?
Options: (a) keep the filter; (b) record DNS queries and names as unclaimable capability evidence, like listeners; (c) at minimum count what the filter drops.
Current behaviour: (a). The filter hides DNS exfiltration and has no counter.
Blocked by: Nothing technical; (b) is part of O-20.

## Proposals (not decided)

### O-18: Move net hooks to the kernel socket layer (fentry or LSM)
Status: Proposed.
Question: Should `net.bpf.c` hook `tcp_connect`, `inet_sendmsg`, `udp_sendmsg` and the `security_socket_connect`/`bind`/`listen` LSM hooks instead of syscall tracepoints?
Options: Rewrite the net probe; or at minimum detect io_uring use by tracked PIDs and mark the run INCONCLUSIVE.
Current behaviour: `sys_enter_*` tracepoints only. `IORING_OP_CONNECT` and `IORING_OP_SEND` bypass them, so an io_uring network action reads as no action. `writev` and multi-iovec sends are not fully read.
Blocked by: Whether Bun uses io_uring for sockets (Unverified); cost of the rewrite.

### O-19: `SSL_read` uretprobe and SSE reassembly
Status: Proposed.
Question: Add the read side to N1 and port SSE handling into `pkg/tlsparse`?
Options: Reuse the `ssl_lib.cc` offset machinery for `SSL_read`, which also gives a structural cross-check for offsets.
Current behaviour: `SSL_write` only (N-16).
Blocked by: O-14.

### O-20: DNS and UDP as capability evidence, larger ClientHello capture
Status: Proposed.
Question: Record DNS and UDP `sendto`/`sendmsg` with an address as unclaimable capability evidence, and grow the hello capture beyond 1 KiB or parse SNI across writes?
Current behaviour: DNS dropped (N-13), UDP not observed, hello capture 1024 bytes of the first write or first iovec.
Blocked by: Whether Claude Code's ClientHello pushes SNI past 1024 bytes (Unverified).

### O-21: Synchronous in-kernel file hashing
Status: Proposed.
Question: Hash at the moment a change becomes visible (an LSM hook on file release with `bpf_ima_file_hash`, or fentry on `vfs_write` plus a synchronous hash) instead of reopening after `FAN_CLOSE_WRITE`?
Current behaviour: Userspace hash after close, with a generation check; the race is known (a flaky tier 4 test).
Blocked by: Whether `bpf_ima_file_hash` is usable on the target kernel configuration (Unverified). Would also put the fs lane on the eBPF clock.

### O-22: A stdio and pipe probe
Status: Proposed.
Question: Capture reads and writes on stdio fds of tracked processes, covering MCP stdio servers and programs fed through stdin?
Current behaviour: Not observed; `bash -s`, `python -` and heredocs hide the program.
Blocked by: Priority.

### O-23: Process context at exec
Status: Proposed.
Question: Capture cwd at exec, and count argv truncation (64 args or 8 KiB) as a coverage counter?
Current behaviour: No cwd, no truncation signal (P-3).
Blocked by: Priority.
