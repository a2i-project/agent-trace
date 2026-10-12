# Open decisions

The single list of decisions not yet taken. Each entry states the question, the options, what the code does today, and what blocks a decision. When one is decided, it moves to the area file ([probes.md](probes.md), [network.md](network.md), [verification.md](verification.md), [integration.md](integration.md), [evaluation.md](evaluation.md)) and is deleted here.

Statuses reconciled with the code at commit 1391cbe on 2026-10-11.

Entries O-1 and O-2 are **contradictions**: a design document says one thing and the code does another. Each is recorded as the code currently behaves, and needs an explicit ruling. On 2026-10-11 the user ruled on O-3 (now V-27), O-4 (I-15), O-26 (V-28) and O-27 (N-23).

Closed: O-3 (V-27), O-4 (I-15), O-15 (N-20), O-17 (I-31), O-26 (V-28), O-27 (N-23), O-28 (P-22, V-29).

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
Blocked by: A paired capture in which the members of a parallel block complete out of order, or subagents run concurrently. The parallel fixture (`paired-2.1.286-parallel`) has a parallel block and a subagent, but they ran in an order a total-order alignment accepts. Gemini's concurrency is unmeasured.

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
Date: raised 2026-09 (in the archived integration design, before 2026-09-19).
Question: A background server started by one command is still its descendant an hour later, or after the session ends. Should its events stay attributed to that claim?
Options: (a) never expire (current); (b) expire at session end; (c) expire after the command's claim interval, reported as a finding.
Current behaviour: (a).
Blocked by: Real sessions with long-lived descendants.

### O-7: Should overlapping claim intervals be a finding?
Status: Open.
Date: raised 2026-09 (in the archived integration design, before 2026-09-19).
Question: A sequential agent cannot produce overlapping intervals, so overlap is an anomaly. Flattened subagents make it legitimate per thread, but the thread id is attacker-controlled.
Options: (a) finding per thread id; (b) report only; (c) ignore.
Current behaviour: (c).
Blocked by: O-2.

### O-8: Is the V7 baseline sufficient at level 0?
Status: Open.
Date: raised 2026-09 (in the archived integration design, before 2026-09-19).
Question: Level 0 has no lineage discriminator and is also where harness activity lives. For level-0 events other than file events in the harness's own directories (connections, commands), can exact-match baseline rules separate harness activity from agent actions? Occasional activity of that kind is O-25.
Options: (a) exact rules only (current, V-19); (b) add structure, such as per-phase baselines; (c) accept level-0 findings as advisory.
Current behaviour: (a), with two additions. Six paired captures of Claude Code (five of 2.1.286, one of 2.1.296) on one machine carry baselines measured from control runs. The capture script keeps an action seen in any one control (a 1/N threshold, V-24) while `cmd/baseline` keeps what every run did by default (I-24). An unexplained level-0 file event under the harness's own directories makes the run INCONCLUSIVE instead of being a finding (V-24); a level-0 connection that sent data, or a command, is still a finding. Since N-22 a connection that sent nothing is capability evidence and never a finding.
Blocked by: Baselines exist for Claude Code 2.1.286 and 2.1.296 (V7); what blocks a ruling is a measurement of how much harness activity at level 0 those exact rules leave unexplained across more sessions (more captures, needs root).

### O-12: Can any finding survive event loss?
Status: Open.
Date: 2026-10-02 (raised with the coverage record, V-13 and V-14).
Question: Which findings are robust enough to keep NOT FAITHFUL without the `Advisory` mark under loss?
Options: Candidates are an unexplained event whose full ancestry chain was observed, and a content mismatch on a pair whose lane neighbours are intact.
Current behaviour: Every finding under loss is NOT FAITHFUL marked `Advisory` (V-15).
Blocked by: A proof per finding kind that it does not depend on a missing event.

### O-25: Occasional harness activity outside file events
Status: Open.
Date: 2026-10-11.
Question: V-24 turns unexplained harness activity into INCONCLUSIVE only for level-0 file events under the harness's own directories. How should occasional harness network and process activity be treated, such as a telemetry connection seen in only some control runs?
Options: (a) leave it to the agreement threshold (current); (b) extend V-24 to declared harness endpoints or commands, reported apart and INCONCLUSIVE; (c) more control runs only.
Current behaviour: (a). At full agreement (the `cmd/baseline` default, I-24) such an action is left out of the baseline and reads as a finding in a run where it occurs; at the capture script's 1/N threshold (V-24) one occurrence in any control makes it a rule that explains it in every later run. A connection that sent nothing (`net_dial`, N-22) or one to port 53 (`net_dns`, N-20) is capability evidence and needs no rule.
Blocked by: Measurements of how often the harness's network and process activity varies across control runs.

### O-9: Many-target search tools
Status: Partly decided. Claude Code `Grep` and `Glob` are settled by I-25. Gemini's search tools are open.
Date: raised 2026-09 (in the archived integration design, before 2026-09-19).
Question: `list_dir`, `grep_search` and `find_by_name` (Gemini) claim a pattern and touch many files. How are they claimed?
Options: (a) containers with no enumerable claim, like D2; (b) non-effectful; (c) unknown, named in the report (current for Gemini); (d) the kind-of-search claim of I-25, if they also run as a child process.
Current behaviour: Claude Code, (d). Gemini, (c).
Blocked by: A paired capture of Gemini.

### O-10: Containers and PID namespace translation
Status: Open.
Date: raised 2026-09 (in the archived integration design, before 2026-09-19).
Question: When the agent or its commands run in another PID namespace, how does `Normalize` translate PIDs and paths so V1's walk works?
Options: Not yet designed beyond `ProcessModel.Containerized` and `Normalize`.
Current behaviour: No translation. Both supported agents are host-native.
Blocked by: An integrated containerized agent.

### O-11: Degraded verification for persistent-shell agents
Status: Open.
Date: raised 2026-09 (in the archived integration design, before 2026-09-19), with D7.
Question: With no level-1 exec per command (D7), what does a command claim verify against?
Options: (a) declare the degradation and verify only level 0; (b) align level-2 roots against command claims; (c) refuse to verify.
Current behaviour: Gemini `RunPersistent` commands are not claimed (I-17), so their effects appear unexplained.
Blocked by: An agent that uses a persistent shell in practice.

### O-16: File-tool claim shapes and fanotify multiplicity
Status: Partly decided. Claude Code is settled by I-22 and I-23. Gemini is open.
Date: 2026-10-06, updated 2026-10-07.
Question: Which kernel events does a real file tool produce, and how many?
Current behaviour: For Claude Code 2.1.286 the shapes were measured on the first paired capture (**Verified**, see I-22) and hold on the five later ones (six fixtures in all, versions 2.1.286 and 2.1.296, one machine), including five Edits whose content hashes are corroborated (I-31). Gemini's file tools still use the guessed open, write, close sequence, and its adapter reports that. Whether other Claude Code versions, or a write that does not use a temporary file, behave the same is **Unverified**.
Blocked by: A paired capture of Gemini (needs root and a working Gemini CLI, which has no headless authentication here), and captures of other Claude Code versions.

### O-13: Out-of-tree tagging (part 3 of P-14, delegation)
Status: Open. Premise changed.
Date: deferred 2026-10-02.
Question: To catch delegation to daemons, should out-of-tree process and network events be captured and tagged, and can an `Outside` event ever be a finding?
Options: (a) as planned: keep out-of-tree fs, net and proc events, tag them, surface them as findings, never let them suppress an unclaimed event; (b) keep them as report-only (current for fs); (c) do nothing more.
Current behaviour: The plan assumed the fs probe would filter by the tracked set, which would make delegated writes vanish. It does not (P-6). Since P-17, out-of-tree fs events are kept only under the workspace; they are placed in `Partition.Outside` (`ZoneOutside`) and reported, not findings (P-15). Since V-25, a write-class outside event under the workspace makes a run without findings INCONCLUSIVE. Out-of-tree proc and net events are not captured.
Blocked by: The baseline (whole-host capture brings noise) and a decision on whether `Outside` events can be findings without making every honest run fail.

### O-14: Verifying Claude Code `WebSearch`
Status: Open.
Date: 2026-10-02 (with the traced `WebSearch` run of I-16).
Question: `WebSearch` runs server-side inside the model API exchange (I-16). How is it verified?
Options: (a) capture the API stream with an `SSL_read` uretprobe plus SSE reassembly (O-19); (b) an N2 proxy, which gives framed responses but is detectable and fails on pinning.
Current behaviour: Not verified; `WebSearch` is non-effectful.
Blocked by: Design choice between (a) and (b), offsets per Bun release for (a), and the unverified join between the transcript `requestId` and the response `request-id` header.

### O-24: Break ties between equal alignments by interval consistency?
Status: Open.
Date: 2026-10-07.
Question: When an alignment has several minimum-cost readings (V-11), the verifier reports one by a fixed rule. If claims are missing, identical observed actions (the same file opened twice by two Edits) leave a truthful claim paired with the wrong occurrence, and the claim then reads as outside its interval, a finding about a claim that is true. Should the choice among equal-cost readings prefer the one with fewer interval violations?
Options: (a) leave it, since `Ambiguous` is reported and the unrecorded findings are right (current); (b) a secondary cost of one per interval violation among minimum-cost readings, so the interval only chooses between readings that are equally good on content; (c) report interval findings only when the alignment is unambiguous.
Current behaviour: (a). Found by the project capture: omitting two claims of a nineteen-claim session left one interval finding in 2 of 100 runs of two omissions and 7 of 100 of three, always with an ambiguous alignment, and detection, classification and localization were unaffected. No honest run has this, since honest alignments are unique.
Blocked by: Nothing technical. A claim interval comes from the trajectory and is adversary-controlled, so (b) lets an attacker steer which equal reading is reported, never whether a finding exists.

## Proposals (not decided)

### O-18: Move net hooks to the kernel socket layer (fentry or LSM)
Status: Proposed.
Date: 2026-10-06.
Question: Should `net.bpf.c` hook `tcp_connect`, `inet_sendmsg`, `udp_sendmsg` and the `security_socket_connect`/`bind`/`listen` LSM hooks instead of syscall tracepoints?
Options: Rewrite the net probe; or at minimum detect io_uring use by tracked PIDs and mark the run INCONCLUSIVE.
Current behaviour: `sys_enter_*` tracepoints only. `IORING_OP_CONNECT` and `IORING_OP_SEND` bypass them, so an io_uring network action reads as no action. `writev` and multi-iovec sends are not fully read. Since N-22 a connection without a name whose data went only through an unhooked path (io_uring, `writev`, `sendfile`, `splice`, `sendmmsg`) or through another process holding the descriptor reads as `net_dial`, capability evidence rather than a connection a claim must explain ([../architecture/13_probe_net.md](../architecture/13_probe_net.md), Known limits).
Blocked by: Whether Bun uses io_uring for sockets (Unverified); cost of the rewrite.

### O-19: `SSL_read` uretprobe and SSE reassembly
Status: Proposed.
Date: 2026-10-06.
Question: Add the read side to N1 and port SSE handling into `pkg/tlsparse`?
Options: Reuse the `ssl_lib.cc` offset machinery for `SSL_read`, which also gives a structural cross-check for offsets.
Current behaviour: `SSL_write` only (N-16).
Blocked by: O-14.

### O-20: Unconnected UDP and DNS names as capability evidence, larger ClientHello capture
Status: Proposed. Narrowed on 2026-10-11: N-20 records every connection to port 53 as `net_dns` capability evidence, which settles the connection part of the DNS question.
Date: 2026-10-06.
Question: Record UDP `sendto`/`sendmsg` with an address on an unconnected socket (DNS included), and the names looked up, as unclaimable capability evidence, and grow the hello capture beyond 1 KiB or parse SNI across writes?
Current behaviour: A `connect()` to port 53, TCP or UDP, is `net_dns` with the `ip:port` target (N-20); the query and its name are not recorded. A datagram sent with an address on an unconnected socket creates no connection and is not observed. Hello capture is 1024 bytes of the first write or first iovec.
Blocked by: Whether Claude Code's ClientHello pushes SNI past 1024 bytes (Unverified).

### O-21: Synchronous in-kernel file hashing
Status: Proposed.
Date: 2026-10-06.
Question: To close the residual race after a close, hash at the moment a change becomes visible (an LSM hook on file release with `bpf_ima_file_hash`, or fentry on `vfs_write` plus a synchronous hash) instead of reopening after `FAN_CLOSE_WRITE`?
Current behaviour: Userspace hash after close, with a generation check. P-16 fixed the flaky tier 4 test by publishing a close without a hash when a write-class event follows it. The residual race (a write after the close and outside the generation check's window) is described in the known limits of [../architecture/12_probe_fs.md](../architecture/12_probe_fs.md).
Blocked by: Whether `bpf_ima_file_hash` is usable on the target kernel configuration (Unverified). Would also put the fs lane on the eBPF clock.

### O-22: A stdio and pipe probe
Status: Proposed.
Date: 2026-10-06.
Question: Capture reads and writes on stdio fds of tracked processes, covering MCP stdio servers and programs fed through stdin?
Current behaviour: Not observed; `bash -s`, `python -` and heredocs hide the program.
Blocked by: Priority.

### O-23: Process context at exec
Status: Proposed.
Date: 2026-10-06.
Question: Capture cwd at exec? And should argv truncation, already flagged per event (P-19), also be counted in the coverage record?
Current behaviour: No cwd. Since P-19 a command line cut at 64 arguments or 128 KiB is flagged per event (`args_truncated` in the record, `TargetTruncated` on the event), not counted, and a cut target is paired by prefix and unverified (V-26).
Blocked by: Priority.
