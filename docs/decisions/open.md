# Open decisions

The single list of decisions not yet taken. Each entry states the question, the options, what the code does today, and what blocks a decision. When one is decided, it moves to the area file ([probes.md](probes.md), [network.md](network.md), [verification.md](verification.md), [integration.md](integration.md), [evaluation.md](evaluation.md)) and is deleted here.

Statuses reconciled with the code at commit 1391cbe on 2026-10-11.

Entries O-1 and O-29 are **contradictions**: a design document says one thing and the code does another. Each is recorded as the code currently behaves, and needs an explicit ruling. On 2026-10-11 the user ruled on O-3 (now V-27), O-4 (I-15), O-26 (V-28) and O-27 (N-23).

Closed: O-2 (V-32), O-3 (V-27), O-4 (I-15), O-9 (I-25, I-54), O-15 (N-20), O-17 (I-31), O-24 (V-31), O-25 (V-34, its process part is O-30), O-26 (V-28), O-27 (N-23), O-28 (P-22, V-29).

Entries are grouped by area, so IDs are not in sequence. Entries O-18 to O-23 are **proposals** from the observer status review of 2026-10-06 (docs/archive/10_observer_status.md, local only). None is decided.

## Contradictions

### O-1: Default of `Options.Expresses` when no declaration is given
Status: Open. Contradiction.
Date: 2026-10-06.
Question: When `Verify` receives no expressibility declaration, is every field expressible or none?
Options: (a) nil means everything expressible (strict, catches opt-outs in `simagent`); (b) nil means nothing expressible (conservative, never manufactures a mismatch from a format limit).
Current behaviour: (a). `Expresses.can` returns true for nil, and `Generic.Expresses` returns true (V-21). The original migration plan (docs/archive/08_verification_model.md section 7, local only) asked for (b).
Blocked by: Nothing technical. Real adapters always pass a declaration through `agent.Prepare`, so the question affects direct callers, `Generic` and tests.

### O-29: Partial claim order across threads (V2): concurrent subagents
Status: Open. Contradiction.
Date: 2026-10-13 (the thread part of O-2, whose parallel-block part is decided as V-32 in [verification.md](verification.md)).
Question: How should the alignment treat claims of different threads (`ThreadID`, flattened subagents, D9) that run concurrently with the main thread or with each other, and a command that keeps running after the step that started it?
Options: (a) linearization checking over the order `ThreadID` induces: each thread's claims in order, threads interleaved freely; (b) keep the total order and report claims of several threads as a degradation; (c) per-thread alignment, accepting that the thread id is attacker-controlled.
Current behaviour: `Align` does not read `ThreadID`. Claims of all threads are aligned in the adapter's sort order (the Claude Code adapter sorts by timestamp), with V-32's freedom inside each parallel block only, so a subagent whose actions interleave with the main thread's in an order other than the sorted claims' reads as order findings. Gemini's `WaitMsBeforeAsync` lets a command keep running after its step: its later subtree is its command's content, not a position, and Gemini claims no exits, so this is harmless while the command starts inside its step, which the fence of V-32 still requires.
Blocked by: A paired capture in which a subagent's actions and the main thread's, or two subagents', run concurrently and are observed in an order the sorted claims do not give. The parallel and tools fixtures each have a subagent, but it ran in an order a total-order alignment accepts. Gemini's concurrency is unmeasured (no real capture).

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
Blocked by: O-29 (the thread part of O-2; the parallel-block part is decided as V-32).

### O-8: Is the V7 baseline sufficient at level 0?
Status: Open.
Date: raised 2026-09 (in the archived integration design, before 2026-09-19).
Question: Level 0 has no lineage discriminator and is also where harness activity lives. For level-0 events other than file events in the harness's own directories (connections, commands), can exact-match baseline rules separate harness activity from agent actions? Occasional activity of that kind is decided for connections to the harness's declared hosts (V-34) and open for commands (O-30).
Options: (a) exact rules only (current, V-19); (b) add structure, such as per-phase baselines; (c) accept level-0 findings as advisory.
Current behaviour: (a), with two additions. Eight paired captures of Claude Code (five of 2.1.286, three of 2.1.296) on one machine carry baselines measured from control runs. The capture script keeps an action seen in any one control (a 1/N threshold, V-24) while `cmd/baseline` keeps what every run did by default (I-24). An unexplained level-0 file event under the harness's own directories makes the run INCONCLUSIVE instead of being a finding (V-24), and so does an unexplained level-0 connection to a host the adapter declares as the harness's own service (V-34); any other level-0 connection that sent data, and a command, is still a finding. Since N-22 a connection that sent nothing is capability evidence and never a finding.
Blocked by: Baselines exist for Claude Code 2.1.286 and 2.1.296 (V7); what blocks a ruling is a measurement of how much harness activity at level 0 those exact rules leave unexplained across more sessions (more captures, needs root).

### O-12: Can any finding survive event loss?
Status: Open.
Date: 2026-10-02 (raised with the coverage record, V-13 and V-14).
Question: Which findings are robust enough to keep NOT FAITHFUL without the `Advisory` mark under loss?
Options: Candidates are an unexplained event whose full ancestry chain was observed, and a content mismatch on a pair whose lane neighbours are intact.
Current behaviour: Every finding under loss is NOT FAITHFUL marked `Advisory` (V-15).
Blocked by: A proof per finding kind that it does not depend on a missing event.

### O-30: Occasional harness commands
Status: Open.
Date: 2026-10-13 (the process part of O-25, whose network part is decided as V-34 in [verification.md](verification.md)).
Question: V-24 and V-34 set apart unexplained level-0 file events under the harness's own directories and level-0 connections to its declared hosts. How should a command the harness itself starts only sometimes be treated, when no control showed it?
Options: (a) leave it to the agreement threshold (current); (b) an adapter-declared set of harness commands whose unexplained occurrence is reported apart and INCONCLUSIVE, with the rules of V-34 (exact, never a command the agent's claims name, never a baseline rule); (c) more control runs only.
Current behaviour: (a). A harness command is a level-1 subtree; one no rule explains is an Unrecorded exec and an unexplained subtree, two findings. Measured on 2026-10-13 (**Verified**): Claude Code's package-manager probe (`sh -c uname -s ... for c in npm yarn pnpm`) ran in 30 of 33 controls of 2.1.286 and 2.1.296 and in none of 9 task runs, so it is a rule at every agreement below full and never a finding in a kept run; no run of Claude Code or agy has an unexplained subtree at any agreement. agy's auto-updater, started only when its last check is more than 15 minutes old, would read as an unexplained command (**Verified** under `strace` only, I-47); no capture under the probes shows it.
Blocked by: A capture in which an occasional harness command is a finding.

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
Status: Partly decided. Claude Code is settled by I-22 and I-23. Gemini is settled by I-50 for `view_file`, `write_to_file` and `replace_file_content`; `multi_replace_file_content` is open.
Date: 2026-10-06, updated 2026-10-07 and 2026-10-14.
Question: Which kernel events does a real file tool produce, and how many?
Current behaviour: For Claude Code 2.1.286 the shapes were measured on the first paired capture (**Verified**, see I-22) and hold on the eight later ones (nine fixtures in all, versions 2.1.286 and 2.1.296, one machine), including five Edits whose content hashes are corroborated (I-31). Whether other Claude Code versions behave the same is **Unverified**. For agy 1.3.4 the shapes of `view_file`, `write_to_file` (creating a file and over an existing one) and `replace_file_content` were measured on the paired `basic` capture (I-50). `multi_replace_file_content` is claimed like `replace_file_content` and its session reports that its shape is unmeasured. The paired `search` capture of agy 1.3.4 (2026-10-13) asked for one call of it: the custom agent listed the tool, but the CLI declared to the model only the agent's other five tools and `manage_task`, and the call failed tool validation (`unknown tool: "multi_replace_file_content"`), so no shape was measured (**Verified** on that run). The 1.3.4 binary still holds the tool's converter and schema and a configured variant of the replace tool (`REPLACE_TOOL_VARIANT_SINGLE_MULTI` among others), and conversations of an earlier agy version on the development machine, with another model, declared it next to `replace_file_content` (design input only): the CLI may offer it under a configuration the capture did not have (**Unverified**: which setting, model or server flag selects the variant).
Blocked by: A paired capture of agy in which the CLI declares `multi_replace_file_content` (needs root and a configuration that offers it), and captures of other Claude Code versions.

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

## Proposals (not decided)

### O-18: Move net hooks to the kernel socket layer (fentry or LSM)
Status: Proposed.
Date: 2026-10-06.
Question: Should `net.bpf.c` hook `tcp_connect`, `inet_sendmsg`, `udp_sendmsg` and the `security_socket_connect`/`bind`/`listen` LSM hooks instead of syscall tracepoints?
Options: Rewrite the net probe; or at minimum detect io_uring use by tracked PIDs and mark the run INCONCLUSIVE.
Current behaviour: `sys_enter_*` tracepoints only. `IORING_OP_CONNECT` and `IORING_OP_SEND` bypass them, so an io_uring network action is not recorded. Since N-25 (option 1, detect and degrade) the probe counts io_uring network operations by tracked processes in `IOURingNetOps`, and `Assess` makes such a run INCONCLUSIVE; on 2026-10-13 Claude Code 2.1.296 (Bun) made no io_uring call and Node.js 20 submitted only `EPOLL_CTL`, which does not count (N-25). Since N-23 and N-24 the tracepoints cover `writev`, `pwritev2`, `sendmmsg`, `sendfile`, `splice` and multi-iovec sends, and follow a connection by socket to any tracked process that writes it. A connection without a name whose data went only through io_uring or Linux AIO, or was written only by a process outside the tracked tree, still reads as `net_dial`, capability evidence rather than a connection a claim must explain ([../architecture/13_probe_net.md](../architecture/13_probe_net.md), Known limits).
Blocked by: Cost of the rewrite. Whether runtimes use io_uring for sockets is measured in N-25: Claude Code 2.1.296 (Bun) makes no io_uring call, Node.js 20 children submit only `EPOLL_CTL`, and python, curl and git use none; since N-25 a tracked socket operation through io_uring makes the run INCONCLUSIVE.

### O-19: `SSL_read` uretprobe and SSE reassembly
Status: Proposed.
Date: 2026-10-06.
Question: Add the read side to N1 and port SSE handling into `pkg/tlsparse`?
Options: Reuse the `ssl_lib.cc` offset machinery for `SSL_read`, which also gives a structural cross-check for offsets.
Current behaviour: `SSL_write` only (N-16).
Blocked by: O-14.

### O-20: A ClientHello beyond 1 KiB or split across writes
Status: Proposed. Narrowed on 2026-10-11: N-20 records every connection to port 53 as `net_dns` capability evidence, which settles the connection part of the DNS question. Narrowed on 2026-10-15: N-27 records the question of every DNS query in the `net_dns` target, and N-28 records datagrams sent to an explicit address, which settles the DNS-name and unconnected-UDP parts.
Date: 2026-10-06.
Question: Grow the hello capture beyond 1 KiB, or parse SNI across writes?
Current behaviour: Hello capture is 1024 bytes of the first send, from up to eight iovecs; an SNI extension beyond that is lost and the connection is reported by address.
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
