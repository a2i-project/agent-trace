# Open decisions

The single list of decisions not yet taken. Each entry states the question, the options, what the code does today, and what blocks a decision. When one is decided, it moves to the area file ([probes.md](probes.md), [network.md](network.md), [verification.md](verification.md), [integration.md](integration.md), [evaluation.md](evaluation.md)) and is deleted here.

Statuses reconciled with the code at commit 1391cbe on 2026-10-11.

Entries O-1 and O-29 are **contradictions**: a design document says one thing and the code does another. Each is recorded as the code currently behaves, and needs an explicit ruling. On 2026-10-11 the user ruled on O-3 (now V-27), O-4 (I-15), O-26 (V-28) and O-27 (N-23).

Closed: O-2 (V-32), O-3 (V-27), O-4 (I-15), O-9 (I-25, I-54), O-15 (N-20), O-17 (I-31), O-19 (N-29), O-20 (N-27, N-28, N-31), O-24 (V-31), O-25 (V-34, its process part is O-30), O-26 (V-28), O-27 (N-23), O-28 (P-22, V-29), O-30 (V-43), O-31 (P-33, V-46), O-32 (I-66).

Entries are grouped by area, so IDs are not in sequence. Entries O-18 to O-23 are **proposals** from the observer status review of 2026-10-06 (docs/archive/10_observer_status.md, local only). O-19 (N-29) and O-20 (N-31) are closed; the others are undecided.

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
Question: Level 0 has no lineage discriminator and is also where harness activity lives. For level-0 events other than file events in the harness's own directories (connections, commands), can exact-match baseline rules separate harness activity from agent actions? Occasional activity of that kind is decided for connections to the harness's declared hosts (V-34) and for commands the adapter declares (V-43).
Options: (a) exact rules only (current, V-19); (b) add structure, such as per-phase baselines; (c) accept level-0 findings as advisory.
Current behaviour: (a), with two additions. Eight paired captures of Claude Code (five of 2.1.286, three of 2.1.296) on one machine carry baselines measured from control runs. The capture script keeps an action seen in any one control (a 1/N threshold, V-24) while `cmd/baseline` keeps what every run did by default (I-24). An unexplained level-0 file event under the harness's own directories makes the run INCONCLUSIVE instead of being a finding (V-24), and so does an unexplained level-0 connection to a host the adapter declares as the harness's own service (V-34) and an unexplained level-1 command whose exec the adapter declares as the harness's own (V-43); any other level-0 connection that sent data, and any other command, is still a finding. Since N-22 a connection that sent nothing is capability evidence and never a finding.
Blocked by: Baselines exist for Claude Code 2.1.286 and 2.1.296 (V7); what blocks a ruling is a measurement of how much harness activity at level 0 those exact rules leave unexplained across more sessions (more captures, needs root).

### O-12: Can any finding survive event loss?
Status: Open.
Date: 2026-10-02 (raised with the coverage record, V-13 and V-14).
Question: Which findings are robust enough to keep NOT FAITHFUL without the `Advisory` mark under loss?
Options: Candidates are an unexplained event whose full ancestry chain was observed, and a content mismatch on a pair whose lane neighbours are intact.
Current behaviour: Every finding under loss is NOT FAITHFUL marked `Advisory` (V-15).
Blocked by: A proof per finding kind that it does not depend on a missing event.

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
Status: Partly decided. Claude Code is settled by I-22 and I-23. Gemini is settled by I-50 for `view_file`, `write_to_file` and `replace_file_content`; for `multi_replace_file_content` I-61 found that agy 1.3.4 offers it under no configuration and proposes closing the Gemini part.
Date: 2026-10-06, updated 2026-10-07, 2026-10-14 and 2026-10-17.
Question: Which kernel events does a real file tool produce, and how many?
Current behaviour: For Claude Code 2.1.286 the shapes were measured on the first paired capture (**Verified**, see I-22) and hold on the eight later ones (nine fixtures in all, versions 2.1.286 and 2.1.296, one machine), including five Edits whose content hashes are corroborated (I-31). Whether other Claude Code versions behave the same is **Unverified**. For agy 1.3.4 the shapes of `view_file`, `write_to_file` (creating a file and over an existing one) and `replace_file_content` were measured on the paired `basic` capture (I-50). `multi_replace_file_content` is claimed like `replace_file_content` and its session reports that its shape is unmeasured. The paired `search` capture of agy 1.3.4 (2026-10-13) asked for one call of it: the custom agent listed the tool, but the CLI declared to the model only the agent's other five tools and `manage_task`, and the call failed tool validation (`unknown tool: "multi_replace_file_content"`), so no shape was measured (**Verified** on that run). The 1.3.4 binary registers the tool as deprecated with no effect, whatever the replace-tool variant, and every run of that capture logged so; the user's conversations show the same model with the same variant (`SINGLE_MULTI`) declaring the tool in June 2026 and not in September, so a version removed it, not a setting, model or server flag (I-61, **Verified** on the logs and conversations, **Reported** from the binary).
Blocked by: For Gemini, a ruling on I-61's proposal to close it (no capture can measure the tool on agy 1.3.4; a later version that declares it again would need a paired capture); for Claude Code, captures of other versions.

### O-13: Out-of-tree tagging (part 3 of P-14, delegation)
Status: Open. Premise changed.
Date: deferred 2026-10-02.
Question: To catch delegation to daemons, should out-of-tree process and network events be captured and tagged, and can an `Outside` event ever be a finding?
Options: (a) as planned: keep out-of-tree fs, net and proc events, tag them, surface them as findings, never let them suppress an unclaimed event; (b) keep them as report-only (current for fs); (c) do nothing more.
Current behaviour: The plan assumed the fs probe would filter by the tracked set, which would make delegated writes vanish. It does not (P-6). Since P-17, out-of-tree fs events are kept only under the workspace; they are placed in `Partition.Outside` (`ZoneOutside`) and reported, not findings (P-15). Since V-25, a write-class outside event under the workspace makes a run without findings INCONCLUSIVE. Out-of-tree proc and net events are not captured.
Blocked by: The baseline (whole-host capture brings noise) and a decision on whether `Outside` events can be findings without making every honest run fail.

### O-14: Verifying Claude Code `WebSearch`
Status: Open, narrowed on 2026-10-26: option (d) is decided and built as V-45 in [verification.md](verification.md); what remains is its confirmation on a live capture.
Date: 2026-10-02 (with the traced `WebSearch` run of I-16).
Question: `WebSearch` runs server-side inside the model API exchange (I-16). N-29 captures the API stream's responses as `net_response`, and V-45 corroborates a `WebSearch` call as a call when the transcript's `requestId` joins one complete status-200 event stream of the harness's own process from the model API host, in a capture whose response reading validated. Does that join hold on a live capture of Claude Code: does its `SSL_read` validate on the Bun build of the configured version, is its stream readable (content coding, HTTP/1.1), and is the transcript's `requestId` on the record holding the call the `request-id` header of the response that streamed it? Does the search's own exchange, if separate, appear as a response the transcript could be joined to?
Options: (a) confirm on a live capture and keep V-45 as built; (b) if the `requestId` names another exchange, change the join (V-45's rule) or withdraw it.
Current behaviour: V-45: each `WebSearch` call is reported with its join or the reason it fails, never changing the outcome; on the checked captures no call and no response exist, so nothing is corroborated. A corroborated call says that the response which issued it was received whole, nothing about whether the search ran or what it returned, and any call inserted into the same response shares its id.
Blocked by: a live capture of Claude Code with response reading active (pending with the user), and the offsets per Bun release.

### O-33: Verifying a `git_commit` claim from the fs probe's ground truth
Status: Open.
Date: 2026-10-26.
Question: Can a `git_commit` claim be checked against the file events of the commit instead of being set aside (V-47)? The claimed commit id would be compared with the observed write to `.git/refs/heads/<branch>`, whose closed-file hash is the hash of the ref's content (the new commit id and a newline), and the object writes under `.git/objects` would show the commit's objects were written.
Options: (a) keep V-47; (b) pair a `git_commit` claim with the close of the ref file whose content hash equals the hash of the claimed id's ref line, in the fs lane, and require the commit's object write; (c) as (b) without the object check.
Current behaviour: V-47: a `git_commit` claim is set aside as out of capture, never aligned and never a finding, and the run is at best INCONCLUSIVE. The fs probe already records the ref and object writes inside the workspace with their closed-file hashes, so no new kernel probe is needed. A packed ref (`.git/packed-refs`), a commit made by a `git` outside the tracked tree, or a repository outside the fs scope would need their own rules.
Blocked by: An agent that emits `git_commit` claims. No current adapter does.

## Proposals (not decided)

### O-34: Capture `SSL_write` at its return, with the number of bytes the call wrote
Status: Open.
Date: 2026-10-27 (the first `long` pilot of Claude Code 2.1.306).
Question: Should `probe_ssl_write` copy the buffer at the call's return, as many bytes as it returned, instead of at its entry, as many as it was asked to write?
Options: (a) keep the entry probe (N-16, N-D1), and rely on N-34 to drop a request line that stray bytes precede; (b) a uprobe at entry stores `ssl` and `buf`, a uretprobe at return copies the returned count, as `SSL_read` does since N-29; (c) both, the entry frame only when the return frame is missing.
Current behaviour: (a). A call that writes part of its buffer, or fails with a retry the caller makes with the same bytes, would put those bytes in the request stream twice; on the pilot a request came out whose method was a run of JSON ahead of `POST`, which fits a body tail repeated past its `Content-Length` (**Unverified**: the plaintext is not kept).
Blocked by: Evidence: a privileged run that counts, per `SSL_write` of the hooked harness, the bytes asked and returned (for example a test against a TLS client that sets partial writes and a slow peer), to show whether Bun's BoringSSL returns short or retries; and a CI run of the privileged net tests after the change. Option (b) also changes the order of a write frame against the reads of the same thread, which response pairing needs (N-29).

### O-18: Move net hooks to the kernel socket layer (fentry or LSM)
Status: Proposed.
Date: 2026-10-06.
Question: Should `net.bpf.c` hook `tcp_connect`, `inet_sendmsg`, `udp_sendmsg` and the `security_socket_connect`/`bind`/`listen` LSM hooks instead of syscall tracepoints?
Options: Rewrite the net probe; or at minimum detect io_uring use by tracked PIDs and mark the run INCONCLUSIVE.
Current behaviour: `sys_enter_*` tracepoints only. `IORING_OP_CONNECT` and `IORING_OP_SEND` bypass them, so an io_uring network action is not recorded. Since N-25 (option 1, detect and degrade) the probe counts io_uring network operations by tracked processes in `IOURingNetOps`, and `Assess` makes such a run INCONCLUSIVE; on 2026-10-13 Claude Code 2.1.296 (Bun) made no io_uring call and Node.js 20 submitted only `EPOLL_CTL`, which does not count (N-25). Since N-23 and N-24 the tracepoints cover `writev`, `pwritev2`, `sendmmsg`, `sendfile`, `splice` and multi-iovec sends, and follow a connection by socket to any tracked process that writes it. A connection without a name whose data went only through io_uring or Linux AIO, or was written only by a process outside the tracked tree, still reads as `net_dial`, capability evidence rather than a connection a claim must explain ([../architecture/13_probe_net.md](../architecture/13_probe_net.md), Known limits).
Blocked by: Cost of the rewrite. Whether runtimes use io_uring for sockets is measured in N-25: Claude Code 2.1.296 (Bun) makes no io_uring call, Node.js 20 children submit only `EPOLL_CTL`, and python, curl and git use none; since N-25 a tracked socket operation through io_uring makes the run INCONCLUSIVE.

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
