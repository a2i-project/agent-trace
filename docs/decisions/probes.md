# Decisions: probes

Why the process, filesystem and network-identity probes observe what they observe, and how they account for loss. Network content capture (TLS, offsets, proxies) is in [network.md](network.md).

Checked against commit d0e2c73 on 2026-10-06. Original sources: docs/archive/02_tiers_0_to_2.md, docs/archive/04_design_tradeoffs.md, docs/archive/09_observer_hardening_todo.md, docs/archive/10_observer_status.md (all local only), and commit messages. As-built descriptions: [../architecture/10_probes_common.md](../architecture/10_probes_common.md), [../architecture/11_probe_proc.md](../architecture/11_probe_proc.md), [../architecture/12_probe_fs.md](../architecture/12_probe_fs.md), [../architecture/13_probe_net.md](../architecture/13_probe_net.md).

AgentSight (arXiv 2508.02736) was compared with these probes on 2026-10-01 by reading its source. Its file probe reads paths from user pointers at syscall entry and aggregates writes per `(pid, event_type, detail)`; it is a profiler with no verdict and no loss accounting. Several entries below cite that comparison.

### P-1: Files are observed with fanotify in FID mode, filesystem-wide
Status: Accepted, implemented in `pkg/probe/fs` (`markFilesystem`, `watchMask`).
Date: Tier 1 (2026-09); reaffirmed 2026-10-01 after the AgentSight comparison.
Context: The original trade-off study recommended eBPF for files. eBPF syscall tracepoints read the path from a user pointer at `sys_enter`, which is a TOCTOU window (another thread can change the buffer), and leave relative paths unresolved.
Decision: fanotify with `FAN_REPORT_FID` and a `FAN_MARK_FILESYSTEM` mark on the filesystem containing the workspace, mask open, modify, close-write, create, delete, moved-from, moved-to. The kernel resolves the object, and every writer on the filesystem is seen.
Consequences: Delivery is asynchronous and uses a different clock from eBPF, so the verifier aligns lanes separately (V-9 in [verification.md](verification.md)). Content hashes are computed in userspace after `FAN_CLOSE_WRITE`, which leaves a race. Writes through mmap, attribute changes and other mounts (tmpfs `/tmp`) are not seen.
Alternatives rejected: `openat`/`unlink`/`rename` tracepoints as in AgentSight (user-pointer TOCTOU, unresolved relative paths); eBPF-primary file capture as first recommended.

### P-2: One record per event, no in-kernel aggregation
Status: Accepted, implemented in all three probes.
Date: 2026-10-01.
Context: AgentSight accumulates counts and byte totals per process and event type. That suits a profiler.
Decision: Every probe emits one record per observed event.
Consequences: Omission detection and positional alignment need individual events; an aggregate cannot be aligned against a claim. Ring buffers must be sized for bursts, and loss is counted (P-10).
Alternatives rejected: Aggregation maps; also AgentSight's single-PID TLS scoping and prologue-only offset discovery, each of which would weaken an existing guarantee.

### P-3: Process records use CO-RE and a ring buffer with variable-length argv
Status: Accepted, implemented in `proc.bpf.c` (`MAX_ARGS` 64, `MAX_ARGS_BYTES` 8192).
Date: 2026-09-11 (commit 9ac657c).
Context: A fixed-slot design let an agent pad a command with harmless arguments and push the payload past the last captured slot.
Decision: BPF CO-RE through `vmlinux.h`, argv streamed as a NUL-separated byte slice through `BPF_MAP_TYPE_RINGBUF`, up to 64 arguments or 8 KiB, with per-CPU array buffers to stay under the 512-byte stack limit. Sizes passed to `bpf_probe_read_user` are compile-time constants.
Consequences: Portable across kernel header changes. Truncation beyond the limits is not flagged by any counter (proposed in O-23 of [open.md](open.md)).
Alternatives rejected: Fixed argument slots; auditd parsing; userspace `/proc` polling, which misses short-lived processes.

### P-4: Hook `sys_enter_execve` to see failed attempts
Status: Accepted, implemented in `proc.bpf.c`.
Date: Tier 2 (2026-09-08).
Context: AgentSight hooks `sched_process_exec`, which fires only for successful execs.
Decision: Hook syscall entry, so an attempted exec that fails is still recorded. Exit codes come from `sys_enter_exit_group` and `sched_process_exit`.
Consequences: Filename and argv are read from user memory before the kernel copies them, a TOCTOU window. The exit record copies the latest exec's command line.
Alternatives rejected: `sched_process_exec` alone. Adding it alongside, to pair the attempt with the post-exec truth, is a proposed improvement, not decided.

### P-5: Descendants are tracked in the kernel through `task_newtask`, threads excluded
Status: Accepted, implemented in `proc.bpf.c`, `net.bpf.c` and `tls.bpf.c` (`handle_fork`, `tracked_pids`).
Date: proc 2026-09; net and tls 2026-09-15 (commit 22763f5); `CLONE_THREAD` guard 2026-10-06 (commit 8e5171c).
Context: Userspace scoping races short-lived children. Cgroup scoping adds little over fork tracking and does not catch delegation, since containers and `systemd-run` scopes have their own cgroups.
Decision: A tracked parent's new child joins `tracked_pids` inside the kernel, and exit removes it. A clone with `CLONE_THREAD` is skipped. Each BPF object keeps its own map, and a failed insert is counted (`untracked_count`).
Consequences: Every fork is followed, including reparenting and double forks. Without the guard, thread ids leaked into the map (exit deletes only on tid == tgid) and recycled tids tracked unrelated processes; a mutation check on 2026-10-06 confirmed the proc and net tests fail without it. The tls thread fix has no test.
Alternatives rejected: AgentSight-style cgroup or single-PID scoping.

### P-6: The fs probe does not filter by the tracked set
Status: Accepted, implemented in `fs.Observer` (PID from fanotify metadata on every event). Deviates from the original retrofit plan.
Date: 2026-10-06 (commit c0e8d3f).
Context: The plan was for the fs probe to consume `tracked_pids`. A fanotify event is read some time after the access, and a short-lived child has usually left the set by then.
Decision: Emit the causing PID on every event and filter nothing; scoping moves to attribution in the verifier's forest. A close keeps the PID of the process that caused it through supersession and settling. `PIDFilter` keeps its exact-PID meaning for in-process agents.
Consequences: Filtering at read time would be silent event loss that no counter sees. G now contains other processes' file activity, which the verifier places outside the tree (P-15).
Alternatives rejected: Tracked-set filtering at read time.

### P-7: Fork records make processes that never exec part of the tree (Option A)
Status: Accepted, implemented in `proc.bpf.c` (`KIND_FORK`) and `models.ProcessFork`.
Date: 2026-10-06 (decided as Option A; commit 09c51ed).
Context: A subshell or a pipeline element running a builtin forks without exec. With only exec records, its file writes cannot be attributed.
Decision: `handle_fork` emits a header-only record (child PID, parent PID) for every non-thread child of a tracked process. `ProcessFork` is structural and unclaimable: consumed by the tree builder, never aligned, not counted as capability.
Consequences: A lost fork record is ring loss and is counted. Not emitted under `CommandFilter`.
Alternatives rejected: Inferring the edge from the next exec, which never comes for a builtin subshell.

### P-8: A listener is level-2 capability evidence and unclaimable
Status: Accepted, implemented (`net_bind`, `net_listen`, `ActionType.IsClaimable`, `Verdict.Capability`, `models.ClassifyBindTarget`).
Date: 2026-10-02 (decided by the user), built 2026-10-06 (commit ec68569).
Context: A reverse shell or local server opens a listening socket that no probe saw, and no surveyed trajectory format can claim one.
Decision: `sys_enter_bind` and `sys_enter_listen`, gated on `tracked_pids`, recorded at syscall entry (a failed bind is reported). Two types, because a bind alone is not a listener; a `binds` map carries the address to the later listen, and a listen on an unbound socket reports target `unbound`. Neither type can be claimed; both are reported as capability and never become `Unrecorded`. Exposure (loopback, wildcard, interface) is derived from the target.
Consequences: A listener inside a command's subtree makes laundering visible without making a run unfaithful. Harness listeners at level 0 are absorbed by the baseline.
Alternatives rejected: A claim path for listeners; AgentSight's version (AF_INET only, fd only on listen, aggregated).

### P-9: AF_UNIX connect, bind and listen are observed with the socket name
Status: Accepted, implemented (`NET_UNIX_CONNECT`, `net_unix_connect`, AF_UNIX through `net_bind`/`net_listen`).
Date: 2026-10-06 (commit 89f8ec0; item 5 part 2 of P-14).
Context: A connect to `/var/run/docker.sock` is the usual channel for delegating work to a daemon, and the connect hook returned early for every family but AF_INET and AF_INET6.
Decision: Target form `unix:<path>` for pathname sockets and `unix:@<name>` for abstract ones; `unix:<unknown>` when the name cannot be read (the event is still emitted). Pathnames are read with `bpf_probe_read_user_str`, abstract names with a constant 108-byte read trimmed by `addrlen`. The name travels in the record payload. `net_unix_connect` is unclaimable capability evidence.
Consequences: Not observed: datagram `sendto`/`sendmsg` with an address, sockets inherited or received over `SCM_RIGHTS`, and loopback TCP daemons (an ordinary `net_connect`). Relative paths are reported as written.
Alternatives rejected: Ignoring non-IP families.

### P-10: Loss is counted per cause, and event loss blocks FAITHFUL
Status: Accepted, implemented (`drop_count`, `untracked_count`, `state_lost_count` per BPF object; `ProbeCoverage`; `verification.Assess`).
Date: `drop_count` 2026-10-01 (commit 9379ac7); coverage record 2026-10-02; `untracked_count` and `state_lost_count` 2026-10-06 (commits 8e5171c, bd8112e).
Context: A full ring buffer, a full `tracked_pids` map, or a full `execs` or `conns` map each silently removed events from G, which the verifier read as the agent not acting, or as fabrication. AgentSight's code claims its ring buffer cannot lose events, which is wrong for reserve and output failures.
Decision: Separate counters so a report can tell the causes apart: ring drops, untracked children, state-map overflow, Go channel drops, and fanotify queue overflow. Each is snapshotted in `Stop()` before the maps close and written to the coverage record. `Assess` treats every one as event loss. Rule for a new counter: add a `ProbeCoverage` field, fill it in `CaptureCoverage()`, snapshot it in `Stop()`, and classify it in `Assess` as event loss or as a content note.
Consequences: Event loss makes FAITHFUL unavailable: a run with no findings is INCONCLUSIVE, and findings are NOT FAITHFUL marked Advisory (V-15 in [verification.md](verification.md)). A probe that does not implement `CoverageReporter` is refused by `cmd/watch`.
Alternatives rejected: One shared counter; printing warnings without surfacing them to the verifier.

### P-11: Faulted SSL reads and a failed TLS attach are notes, not loss
Status: Accepted, implemented (`FaultedReads`, `ContentAttachFailed` in `Assess.Notes`).
Date: 2026-09-14 (N-D5 in [network.md](network.md)), classified 2026-10-02.
Context: A faulting read loses the request content of one frame, not the connection event.
Decision: Report as a content-level gap that limits what content checks can say, without making the event set incomplete.
Consequences: A request whose content was lost compares as a probe gap (benefit of the doubt), never as a finding.
Alternatives rejected: Treating content gaps as event loss, which would make every run with one unreadable frame INCONCLUSIVE.

### P-12: The `binds` map has no loss counter
Status: Accepted.
Date: 2026-10-06.
Context: `binds` only carries a bound address to a later `listen`.
Decision: A full map costs an address, never an event, so it is not counted.
Consequences: A listener may report `unbound` when its address was dropped. Revisit only if listener addresses become load-bearing.
Alternatives rejected: A counter that would make the run INCONCLUSIVE for a missing address.

### P-13: A merged fanotify mask expands in causal order
Status: Accepted, implemented in `fs.maskToActionTypes`.
Date: 2026-10-06 (commit 81b3c4d).
Context: The kernel merges consecutive events on one object into one notification whose mask has no order. A fixed expansion put the write before the open, so whether the kernel merged them decided whether an honest run read as a fabrication.
Decision: Expand as open, then write (create or modify), then close, then delete and rename.
Consequences: Merged and separate deliveries produce the same sequence. Merging still changes multiplicity (several modifies can become one), which is open for the real-agent claim shapes (O-16).
Alternatives rejected: Expanding in bit order.

### P-14: Delegation to daemons is in scope, in three parts
Status: Accepted. Parts 1 and 2 implemented; part 3 open (O-13).
Date: 2026-10-02 (decided by the user).
Context: An action delegated to a process the agent did not fork (`docker run`, `systemd-run`, `at`, `cron`, a request over a daemon socket) runs outside the tracked tree. The asking command is visible through its argv; the effects are not attributable by ancestry.
Decision: (1) Document the limitation in the verification model. (2) Observe the channel: AF_UNIX connect, bind and listen (P-9). (3) Decide out-of-tree tagging after the fs probe change: keep out-of-tree events, tag them, surface them, and never let them suppress an unclaimed event.
Consequences: This is a stronger form of the laundering limit: the effects are absent or unattributed, not an opaque subtree.
Alternatives rejected: Cgroup scoping, which does not catch containers or `systemd-run` scopes.

### P-15: Out-of-tree events are kept and reported, never used to attribute
Status: Accepted, implemented (`ZoneOutside`, `Partition.Outside`, `Coverage.Outside`).
Date: 2026-10-06 (commits 4f83cfb, 2130154).
Context: Since P-6, G contains file events from processes outside the agent's tree.
Decision: The forest places such events in `Outside`. They are reported and do not block coverage: they are not the agent's as far as the tree can tell.
Consequences: fs events from a delegated daemon are already present in G and visible, but not findings. Out-of-tree proc and net events are not captured, since those probes scope in the kernel.
Alternatives rejected: Dropping them, or letting them explain an unclaimed event.

### P-16: A close followed by a write-class event on its path is published without a hash
Status: Accepted, implemented (`pendingClose.gen`, `resolveSettled`; `TestObserver_OpenAfterCloseDropsHash`, `TestObserver_ModifyAfterCloseDropsHash`, `TestObserver_RewriteLoopHashesOnlyTheLastClose`).
Date: 2026-10-07.
Context: `TestTier4_E2E_RacedRewriteDropsStaleHash` failed intermittently in CI with an `OutputHash` equal to the SHA-256 of empty content (2 runs in about 6). The first hypothesis, a second reader dequeuing the `FAN_OPEN` the drain was meant to find, was wrong: `readLoop` is the only reader. The cause: a close is registered, the writer's next iteration opens the file (open with `O_TRUNC` truncates it, and fanotify does not report open flags), and the writer is descheduled before it writes. The open updates `lastWriteAt`, so the path is "quiet" once 20 ms pass with the file empty. The open was processed before the hash read began, so the generation did not change during the read, and the empty digest was trusted. A deterministic unit test reproduces it (**Verified**, it failed before the fix).
Decision: Each pending close records the path's write generation at registration. At settle time a changed generation means a write-class event followed the close, and the close is published with no `OutputHash` and no read.
Consequences: A published hash is always the content as of the close, with nothing after it. The test that caught this passes by construction. The cost is dropped hashes where an open follows a close within the settle window, including read-only opens (a pipeline whose next command reads the file just written); an absent observed hash is read as the probe not having captured it, so such a pair gets the benefit of the doubt. Older tests that expected a hash after a later modify or in-batch write now expect none.
Alternatives rejected: Tainting only on an open (a stall between two writes can still hash partial content); comparing `st_mtime` and size at registration and at hash time (timestamp granularity can hide two changes in one tick); lengthening the settle window (it moves the race, and it breaks `TestObserver_CloseHashSurvivesQuickRename`).

### P-17: The fs probe marks every real filesystem, and `watch` keeps the agent's tree anywhere plus the workspace for everyone else
Status: Accepted, implemented (`Config.AllFilesystems`, `markAll`, `Scope` in `pkg/probe/fs`; `scopeFSEvents` and `models.FSScope` in `cmd/watch`).
Date: 2026-10-08 (security review; demonstration with a two-file agent).
Context: `watch` marked the filesystem holding the workspace and set a path prefix filter to it, and nothing recorded the filter. An agent's file claims may name any path (Claude Code's Read, Write and Edit take an absolute path and are not confined to the working directory), so a truthful Write to `~/.bashrc` had no event to pair with and read as Unwitnessed, while the same write unreported read as nothing at all. On a host where `/tmp` is a separate tmpfs, writes there were invisible even without the filter (**Verified**: a shell writing one file inside and one next to the workspace; the honest trajectory was NOT FAITHFUL with four Unwitnessed entries, the one hiding the write FAITHFUL).
Decision: Two levels, matching what honest trajectories contain. The claim level: the agent's own process tree is observed wherever it goes, on every real filesystem the probe can mark, so a file claim is always in scope. The forensic level: what a claimed command's subtree touches is attributed and recorded, never aligned (D3, unchanged). Processes outside the tree are kept only inside the workspace, so another user's activity elsewhere does not swell the capture. The probe filters nothing by path or pid; `watch` applies the rule once the fork records are complete, and writes `fs_scope` with the marked and unmarked filesystems, the rule and the dropped count, so the verifier can tell an event that did not happen from one outside the scope.
Consequences: The level-0 sequence gains the harness's own activity outside the workspace, which the baseline must explain; existing baselines predate this and a new control capture is needed before the rules are written (the ids in the harness's own paths will need canonicalising as the snapshot name is). Files outside the workspace are not hashed at start, so their first open carries the empty-content hash. Fuse mounts, read-only images and any filesystem that refuses the mark stay invisible and are listed. The kernel queue carries the whole host's events for the capture's duration; overflow is counted and makes the run INCONCLUSIVE. Reading the verifier's side of the scope record is the next step.
Alternatives rejected: Named extra prefixes (a list of where an attacker might write is a guess, and the attacker picks the path); filtering by the live tracked set in the probe (the race V1 rejected: a short-lived child has often exited before its event is read); no filter at all for other processes (every process on the host in the capture, for no claim that could use it).

### P-18: The fs probe's emitted sequence does not depend on kernel merging or settle timing
Status: Accepted, implemented (`repeats`, `lastEmitted`, the per-record offset in `drainNonBlocking`, `pkg/probe/fs/observer.go`).
Date: 2026-10-09 (item 9 of the security review).
Context: fanotify merges consecutive notifications on one object into a single mask when nothing reads the queue between them, and delivers them separately otherwise. One `echo > f` reached the verifier as one `file_write` in one capture and two in the next (the truncating open and the write); one rename reached it as one `file_rename` when merged and two when not, which failed an end-to-end tier on CI once in fifteen runs. And a close is emitted only after its settle window, stamped with its batch's time, so under the verifier's stable sort by timestamp it fell after every later record of the same batch: an honest write of two files back to back paired the first file's close in the wrong place (**Verified**: the two-file shell agent of P-17's demonstration, one Unwitnessed plus one Unrecorded close). The verifier pairs by position, so a count or an order that depends on timing is a false finding on an honest run.
Decision: At emission, a `file_write` that follows a `file_write`, or a `file_rename` that follows a `file_rename`, on the same path by the same pid with no other event on that path between is dropped: the unmerged half of one operation. Any other event on the path, or another process's event, resets it. Each record in a batch is stamped with the batch's reading plus its index in nanoseconds, so a deferred close keeps the place of the record that produced it.
Consequences: One operation is one event whether or not the kernel merged it, and a close sorts where its record was read. Two writes through one descriptor with nothing between them are one event, which the probe cannot distinguish from the unmerged halves of one write; claims are per operation, so that is the right grain. The Claude Code adapter's burst fold is unaffected. The timestamps within a batch are now strictly increasing and still not comparable with the other probes' clocks (V6).
Alternatives rejected: Folding in the verifier or the generic adapter (every adapter would repeat it, and the artefact is the probe's); a longer read interval to let the kernel merge more (merging would still depend on load); emitting a rename on `FAN_MOVED_TO` only (a cross-directory rename would lose its source).

### P-19: The proc probe keeps 128 KiB of a command line and says when it cut one
Status: Accepted, implemented (`MAX_ARGS_BYTES`, `args_truncated` in `proc.bpf.c`; `execs` holds the header; `lastExec` in `observer.go`; `models.GroundTruthEvent.TargetTruncated`).
Date: 2026-10-09 (item 8 of the security review).
Context: The probe copied at most 8 KiB of argv at `execve` entry and recorded nothing when it stopped. A Bash command longer than that, a heredoc that writes a file for instance, reached the verifier as a different command line: the wrapper lost its closing quote, the adapter refused it, and the honest claim mismatched (**Verified**: `TestP8_LongCommandLineTruncatedByArgvCapMismatches` in the audit, a 9 KiB heredoc). The kernel copy is the only trustworthy one: `/proc/<pid>/cmdline` is the process's current argv, which it can rewrite, and is gone with a short-lived process. An eBPF program needs a compile-time bound, so a cap is unavoidable.
Decision: The args area is 128 KiB, the size Linux allows for a single argument string, so one command of a harness always fits and only a line of many large arguments is cut. The header carries `args_truncated`, set when a string did not fit, the total did, there were more than 64 arguments, or the filename exceeded 256 bytes; the event carries it as `TargetTruncated`. The ring buffer grows to 8 MiB for 128 KiB records. The per-process `execs` map keeps only the header, because 4096 entries of the full record would be a gigabyte preallocated; the exit record is that header and userspace joins it to the command line of the exec it read for the pid, dropping an exit whose exec it never saw, as the kernel did when it had no entry.
Consequences: A long command verifies; a cut one is paired by prefix and reported unverified (V-26) instead of mismatched. The scratch record is 256 KiB, which exceeds the kernel's 32 KiB cap on a per-CPU array value, so `heap` is a plain array with one slot per possible CPU, sized at load and indexed by the running CPU (a tracepoint program cannot migrate while it runs); the first privileged run failed to load with the per-CPU map. An exit after a ring drop of its exec is not emitted; the drop is counted. The e2e tiers and the paired captures are unchanged.
Alternatives rejected: Reading argv from procfs (spoofable and racy); chunked records reassembled in userspace (more code and more ways to lose a piece, for a gap nothing reaches); keeping the full record in `execs` with on-demand allocation (256 KiB per live process and allocation failures under pressure).

