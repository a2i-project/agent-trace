# Decisions: probes

Why the process, filesystem and network-identity probes observe what they observe, and how they account for loss. Network content capture (TLS, offsets, proxies) is in [network.md](network.md).

Entries carry their own dates. Statuses reconciled with the code at commit 1391cbe on 2026-10-11. Original sources: docs/archive/02_tiers_0_to_2.md, docs/archive/04_design_tradeoffs.md, docs/archive/09_observer_hardening_todo.md, docs/archive/10_observer_status.md (all local only), and commit messages. As-built descriptions: [../architecture/10_probes_common.md](../architecture/10_probes_common.md), [../architecture/11_probe_proc.md](../architecture/11_probe_proc.md), [../architecture/12_probe_fs.md](../architecture/12_probe_fs.md), [../architecture/13_probe_net.md](../architecture/13_probe_net.md).

AgentSight (arXiv 2508.02736) was compared with these probes on 2026-10-01 by reading its source. Its file probe reads paths from user pointers at syscall entry and aggregates writes per `(pid, event_type, detail)`; it is a profiler with no verdict and no loss accounting. Several entries below cite that comparison.

### P-1: Files are observed with fanotify in FID mode, filesystem-wide
Status: Accepted, implemented in `pkg/probe/fs` (`markFilesystem`, `watchMask`). Amended by P-17: every real filesystem is marked, not only the one holding the workspace.
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
Status: Superseded by P-19 (128 KiB args area, a plain-array scratch heap with one slot per CPU, and an `args_truncated` flag). Kept as taken: implemented in `proc.bpf.c` (`MAX_ARGS` 64, `MAX_ARGS_BYTES` 8192) until P-19.
Date: 2026-09-11 (commit 9ac657c).
Context: A fixed-slot design let an agent pad a command with harmless arguments and push the payload past the last captured slot.
Decision: BPF CO-RE through `vmlinux.h`, argv streamed as a NUL-separated byte slice through `BPF_MAP_TYPE_RINGBUF`, up to 64 arguments or 8 KiB, with per-CPU array buffers to stay under the 512-byte stack limit. Sizes passed to `bpf_probe_read_user` are compile-time constants.
Consequences: Portable across kernel header changes. Truncation beyond the limits is not flagged by any counter (proposed in O-23 of [open.md](open.md)).
Alternatives rejected: Fixed argument slots; auditd parsing; userspace `/proc` polling, which misses short-lived processes.

### P-4: Hook `sys_enter_execve` to see failed attempts
Status: Accepted, implemented in `proc.bpf.c`. Extended by P-21 (`sys_enter_execveat`, through the same recording routine).
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

### P-7: Fork records make processes that never exec part of the tree
Status: Accepted, implemented in `proc.bpf.c` (`KIND_FORK`) and `models.ProcessFork`.
Date: 2026-10-06 (commit 09c51ed).
Context: A subshell or a pipeline element running a builtin forks without exec. With only exec records, its file writes cannot be attributed.
Decision: `handle_fork` emits a header-only record (child PID, parent PID) for every non-thread child of a tracked process. `ProcessFork` is structural and unclaimable: consumed by the tree builder, never aligned, not counted as capability.
Consequences: A lost fork record is ring loss and is counted. Not emitted under `CommandFilter`.
Alternatives rejected: Inferring the edge from the next exec, which never comes for a builtin subshell.

### P-8: A listener is level-2 capability evidence and unclaimable
Status: Accepted, implemented (`net_bind`, `net_listen`, `ActionType.IsClaimable`, `Verdict.Capability`, `models.ClassifyBindTarget`).
Date: 2026-10-02 (decided by the user), built 2026-10-06 (commit ec68569).
Context: A reverse shell or local server opens a listening socket that no probe saw, and no surveyed trajectory format can claim one.
Decision: `sys_enter_bind` and `sys_enter_listen`, gated on `tracked_pids`, recorded at syscall entry (a failed bind is reported). Two types, because a bind alone is not a listener; a `binds` map carries the address to the later listen, and a listen on an unbound socket reports target `unbound`. Neither type can be claimed; both are reported as capability and never become `Unrecorded`. Exposure (loopback, wildcard, interface) is derived from the target.
Consequences: A listener inside a command's subtree makes laundering visible without making a run unfaithful. Harness listeners at level 0 are absorbed by the baseline. Amended 2026-10-11 (docs review): baseline rules are built from the aligned sequence (`Partition.Observed`), which holds no capability evidence, so a harness listener at level 0 is reported as capability evidence and never needs a baseline rule.
Alternatives rejected: A claim path for listeners; AgentSight's version (AF_INET only, fd only on listen, aggregated).

### P-9: AF_UNIX connect, bind and listen are observed with the socket name
Status: Accepted, implemented (`NET_UNIX_CONNECT`, `net_unix_connect`, AF_UNIX through `net_bind`/`net_listen`).
Date: 2026-10-06 (commit 89f8ec0; part 2 of P-14).
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
Status: Accepted, implemented (`ZoneOutside`, `Partition.Outside`, `Coverage.Outside`). Amended by V-25: an outside write under the workspace blocks FAITHFUL (the run is INCONCLUSIVE); other outside events still do not.
Date: 2026-10-06 (commits 4f83cfb, 2130154).
Context: Since P-6, G contains file events from processes outside the agent's tree.
Decision: The forest places such events in `Outside`. They are reported and do not block coverage: they are not the agent's as far as the tree can tell.
Consequences: fs events from a delegated daemon are already present in G and visible, but not findings. Out-of-tree proc and net events are not captured, since those probes scope in the kernel.
Alternatives rejected: Dropping them, or letting them explain an unclaimed event.

### P-16: A close followed by a write-class event on its path is published without a hash
Status: Accepted, implemented (`pendingClose.gen`, `resolveSettled`; `TestObserver_OpenAfterCloseDropsHash`, `TestObserver_ModifyAfterCloseDropsHash`, `TestObserver_RewriteLoopHashesOnlyTheLastClose`).
Date: 2026-10-07.
Context: An end-to-end test of a raced rewrite (`TestTier4_E2E_RacedRewriteDropsStaleHash`) failed intermittently in CI with an `OutputHash` equal to the hash of empty content. After a close was registered, the writer reopened the file with `O_TRUNC` (fanotify does not report open flags) and was descheduled before writing. The path then stayed quiet for the settle window with the file empty, and since the open came before the hash read, the generation check passed and the empty digest was trusted (**Verified**: a deterministic unit test failed before the fix).
Decision: Each pending close records the path's write generation at registration. At settle time a changed generation means a write-class event followed the close, and the close is published with no `OutputHash` and no read.
Consequences: A published hash is always the content as of the close, with nothing after it. The cost is dropped hashes where an open follows a close within the settle window, including read-only opens (a pipeline whose next command reads the file just written). An absent observed hash was read as a probe gap, so such a pair got the benefit of the doubt.
Note 2026-10-11: the last consequence is amended by V-22: a claim that states a value the probe did not capture is unverified, and with no finding the run is INCONCLUSIVE. Since commit c89cc84 (2026-10-09) the probe counts these closes (`HashlessCloses`, a note in the coverage record).
Alternatives rejected: Tainting only on an open (a stall between two writes can still hash partial content); comparing `st_mtime` and size at registration and at hash time (timestamp granularity can hide two changes in one tick); lengthening the settle window (it moves the race, and it breaks `TestObserver_CloseHashSurvivesQuickRename`).

### P-17: The fs probe marks every real filesystem, and `watch` keeps the agent's tree anywhere plus the workspace for everyone else
Status: Accepted, implemented (`Config.AllFilesystems`, `markAll`, `Scope` in `pkg/probe/fs`; `scopeFSEvents` and `models.FSScope` in `cmd/watch`). The verifier reads the scope record through V-23, and I-29 canonicalises the harness's per-run path ids it exposes. Amended by P-22 (an open carries an input hash only when the content was measured).
Date: 2026-10-08 (from a security review on 2026-10-08, local only).
Context: `watch` marked only the filesystem holding the workspace, filtered events to the workspace prefix, and recorded neither. An agent's file claims may name any path (Claude Code's Read, Write and Edit take an absolute path), so a truthful Write to `~/.bashrc` read as Unwitnessed while the same write unreported read as nothing, and a separate tmpfs `/tmp` was invisible even without the filter (**Verified**: a shell agent writing one file inside and one next to the workspace; the honest trajectory was NOT FAITHFUL, the one hiding the write FAITHFUL).
Decision: Two levels, matching what honest trajectories contain. The agent's own process tree is observed wherever it goes, on every real filesystem the probe can mark, so a file claim is always in scope; what a command's subtree touches is attributed and recorded, never aligned (D3). Processes outside the tree are kept only inside the workspace. The probe filters nothing by path or pid; `watch` applies this tree-or-workspace rule once the fork records are complete, and records the rule, the marked and unmarked filesystems and the dropped count in `fs_scope`, so the verifier can tell an event that did not happen from one outside the scope.
Consequences: The aligned sequence gains the harness's own activity outside the workspace, which the baseline must explain, so baselines taken before this change had to be captured again. Files outside the workspace are not hashed at start. Filesystems that refuse the mark (fuse mounts, read-only images) stay invisible and are listed. The kernel queue carries the whole host's events; overflow is counted and makes the run INCONCLUSIVE.
Alternatives rejected: Named extra prefixes (a list of where an attacker might write is a guess, and the attacker picks the path); filtering by the live tracked set in the probe (the race P-6 rejected); no filter at all for other processes (every process on the host in the capture, for no claim that could use it).

### P-18: The fs probe's emitted sequence does not depend on kernel merging or settle timing
Status: Accepted, implemented (`repeats`, `lastEmitted`, the per-record offset in `drainNonBlocking`, `pkg/probe/fs/observer.go`). Amended by P-25: with entry names the two halves of one rename name two paths and are two events, and the rename collapse acts on renames that name one path.
Date: 2026-10-09 (audit item 9 of a security review on 2026-10-08, local only).
Context: fanotify merges consecutive notifications on one object into one mask when nothing reads the queue between them, and delivers them separately otherwise. So one `echo > f` reached the verifier as one `file_write` or two (the truncating open and the write), and one rename as one `file_rename` or two, depending on timing; an end-to-end test failed on CI once in fifteen runs. A close is also emitted only after its settle window, stamped with its batch's time, so under the verifier's stable sort it fell behind every later record of that batch (**Verified**: the two-file shell agent of P-17 wrote two files back to back and got one Unwitnessed claim plus one Unrecorded close). The verifier pairs by position, so a count or an order that depends on timing is a false finding on an honest run.
Decision: A `file_write` that follows a `file_write`, or a `file_rename` that follows a `file_rename`, on the same path by the same pid with no other event on that path between, is dropped at emission as the unmerged half of one operation. Each record in a batch is stamped with the batch's time plus its index in nanoseconds, so a deferred close keeps the place of the record that produced it.
Consequences: One operation is one event whether or not the kernel merged it, and a close sorts where its record was read. Two writes through one descriptor with nothing between them are one event; claims are per operation, so that is the right grain. Timestamps within a batch are strictly increasing and still not comparable with the other probes' clocks (V6).
Alternatives rejected: Folding in the verifier or the generic adapter (every adapter would repeat it, and the artefact is the probe's); a longer read interval to let the kernel merge more (merging would still depend on load); emitting a rename on `FAN_MOVED_TO` only (a cross-directory rename would lose its source).
Amended 2026-10-14 (commit c502f8f): the guarantee holds for merges of records on one path. The kernel also merges a directory-entry record into an earlier unread record for the same directory and process across records for other files (measured, see [12_probe_fs.md](../architecture/12_probe_fs.md#known-limits)), which moves a rename before the open, write and close of the file it renamed; that case is not covered.

### P-19: The proc probe keeps 128 KiB of a command line and says when it cut one
Status: Accepted, supersedes P-3; implemented (`MAX_ARGS_BYTES`, `args_truncated` in `proc.bpf.c`; `lastExec` in `observer.go`; `models.GroundTruthEvent.TargetTruncated`).
Date: 2026-10-09 (audit item 8 of a security review on 2026-10-08, local only).
Context: The probe copied at most 8 KiB of argv at `execve` entry and recorded nothing when it stopped. A longer Bash command, such as a heredoc that writes a file, reached the verifier cut, so the adapter could not recover it and the honest claim mismatched (**Verified** with a 9 KiB heredoc; regression tests `TestObserver_LongCommandLineIsRecordedWhole`, `TestObserver_OverlongCommandLineIsFlagged`, `TestVerify_TruncatedCommandLinePairsByPrefix`). Only the kernel's copy is trustworthy (`/proc/<pid>/cmdline` can be rewritten by the process and is gone with it), and an eBPF program needs a compile-time bound.
Decision: The args area is 128 KiB, the size Linux allows for one argument string, so a single harness command always fits. A flag says when anything did not fit (a string, more than 64 arguments, a filename over 256 bytes), and the event carries it as `TargetTruncated`. To afford the record, the ring buffer grows to 8 MiB and the per-process `execs` map keeps only the header; userspace joins an exit to the exec it read for that pid.
Consequences: A long command verifies; a cut one is paired by prefix and reported unverified (V-26 in [verification.md](verification.md)) instead of mismatched. The scratch record no longer fits a per-CPU array value and lives in a plain array indexed by CPU ([../architecture/11_probe_proc.md](../architecture/11_probe_proc.md)). An exit whose exec was lost to a ring drop is not emitted; the drop is counted.
Alternatives rejected: Reading argv from procfs (spoofable and racy); chunked records reassembled in userspace (more ways to lose a piece, for a gap nothing reaches); keeping the full record in `execs` (256 KiB per live process).

### P-20: The shadow hash of an opened file is looked up by inode before by path
Status: Accepted, implemented (`lookupShadowHash` in `pkg/probe/fs/observer.go`).
Date: 2026-10-11 (the capture for I-31's gate).
Context: The probe remembers a settled content hash per path and per inode, and looked the path up first. After an atomic replace the path names a new inode whose hash settled under the temporary's name, while the path's entry still holds the replaced file's hash, so the next open of the target carried the old content (**Verified**: two Edit pre-check opens of the `edits` capture reported the content of two edits earlier, and mismatched the claims that stated the file before the edit).
Decision: The inode is looked up first, the path is the fallback for a handle that cannot be resolved, and a hit refreshes the path's entry.
Consequences: An open after a replace carries the replaced content's hash, so a claim of the file before an edit (I-31) can be checked. A capture made before this change carries the stale hashes and cannot be the gate's fixture.
Alternatives rejected: Dropping the path entry on a rename of the directory (the rename record does not name the file).

### P-21: `execveat` is hooked, and an exec through a descriptor is named `(fexecve)`
Status: Accepted, implemented (`handle_execveat`, `record_exec` in `proc.bpf.c`).
Date: 2026-10-11 (security review).
Context: Only `sys_enter_execve` was hooked. A process that exec'd through `execveat` (glibc's `fexecve`, Python's `os.execv` on a descriptor) produced no exec record: at level 1 it showed as a fork with content, an unexplained subtree if it did anything observable, so not a silent pass, but with no command line to read.
Decision: `sys_enter_execveat` is hooked by the same recording routine. With `AT_EMPTY_PATH` or an empty pathname the descriptor is the program and no path exists, so the filename is the literal `(fexecve)`; a pathname is recorded as given, and one relative to a directory descriptor stays unresolved.
Consequences: Every exec attempt has a record and an exit. A `(fexecve)` command line has no path to compare, so a claim of it matches only by its arguments; a harness that execs this way would need its adapter to say so. The proc bindings are regenerated.
Alternatives rejected: Resolving the descriptor to a path in the kernel (a `d_path` from a tracepoint is not available to this program type); leaving it unhooked (a command line missing from the record).
Amended 2026-10-11 (commit a1c95a9): Python's descriptor form is `os.execve`, not `os.execv` as Context says; `os.execv` rejects a descriptor before any exec. The test uses `os.execve`. The probe also records `(fexecve)` when the pathname's first byte cannot be read.
Amended 2026-10-15 (commit df547a5): `AT_EMPTY_PATH` makes the descriptor the program only when the pathname is empty; with a pathname the kernel looks it up whatever the flags (**Verified** with `strace`: `execveat(AT_FDCWD, "/bin/true", ..., AT_EMPTY_PATH)` runs `/bin/true`). The probe treated the flag alone as an exec through the descriptor, so a process could hide the program it ran behind `(fexecve)`. It now records `(fexecve)` only for an empty or unreadable pathname, with or without the flag, and the pathname as given otherwise (`TestObserver_ExecveatWithAPathNamesIt`).

### P-22: An open carries an input hash only when the probe measured the file's content
Status: Accepted, implemented (`inputHash`, `identify`, `lookupShadowHash` returning whether it found a hash, `Observer.startedAt`, `openedInodes` in `pkg/probe/fs/observer.go`). Amends P-17. The user's ruling on O-28, option (a).
Date: 2026-10-12.
Context: The fs probe hashes the walked directory at start (P-17) and the closes it settles. For any other file it stamped the open with the hash of empty content, which is not a measurement. An Edit states the file's content before it (I-31), so an honest Edit of a pre-existing file outside the workspace was a mismatch and the run NOT FAITHFUL, reproduced on the edits capture.
Decision: An open carries an `InputHash` only when the probe measured the content: the settled hash of the file (by inode, then by path), or, for the first open of a file whose birth time is at or after `Start`, the hash of empty content, because that open created the file. Every other open carries none.
Consequences: A stated input is either checked against a real measurement or, with the verifier's half of the ruling (V-29), unverified and INCONCLUSIVE. A created file keeps its empty input, so a claim about it stays checkable. Each open costs a handle resolution and a `statx`. On a filesystem with no birth time, and for a file deleted before its open event is read, the creating open carries no input hash either, which errs towards unverified. A hard link made during the capture is not a new file, since its inode has an older birth time.
Alternatives rejected: Keeping the stamp and flagging it as not measured (O-28 option b, a second field for one fact); hashing every file on its first open (option c, it reads files the agent only opened and races their content); recognising a creation by the `FAN_CREATE` record, which usually arrives with no name (a directory-only record).

### P-23: `watch` registers the agent's pid with the probes before the agent execs
Status: Accepted, implemented (`holdScript`, `startHeld` in `cmd/watch/main.go`; `TestRunWatch_ImmediateForkIsTracked`, `TestStartHeld_RunsTheAgentOnlyAfterReleaseUnderTheSamePID`).
Date: 2026-10-12.
Context: In exec-wrap mode `watch` started the agent with `exec.Command` and inserted its pid into the proc and net tracked sets after `Start` returned. A process the agent forked in that window was outside the tree and no counter recorded it. An end-to-end test whose agent forks a child failed once on CI with no events and passed on rerun, consistent with this race.
Decision: `watch` starts `/bin/sh` with a script that blocks reading a pipe on descriptor 3, then closes it and execs the agent in place. `watch` registers that pid with both probes (`SetRootPID`, `TrackPID`) and then writes to the pipe. The exec keeps the pid, so the agent is tracked from its first instruction. The program is resolved with `exec.LookPath` before the start, so a missing program is still a start error.
Consequences: No fork of the launched agent can precede its registration. The root's exec of the agent is recorded in the kernel and dropped by pid in userspace, as the root's own exec was before; the shell's exec happens while its pid is untracked and is not recorded. The agent's `argv[0]` is the resolved path, and a file the kernel refuses to exec for lack of a `#!` line is run by the shell as a script. `--root-pid` is unchanged and keeps its race.
Alternatives rejected: Tracking the `watch` process itself before the start (its own activity would join the tree); re-executing `watch` with a hidden flag as the holding process (it would keep `argv[0]` but needs a dispatch in the test binary as well, since the tests call `runWatch` directly).

### P-24: The fs probe drains its queue at `Stop` within a time budget and counts what it cannot read
Status: Accepted, implemented (`drainAtStop`, `readReady`, `countRecords`, `stopDrainBudget`, `stopCountBudget` in `pkg/probe/fs/observer.go`; `ProbeCoverage.UndrainedRecords`; `TestReadLoop_DrainsRecordsQueuedAtStop`, `TestReadLoop_CountsRecordsLeftWhenTheStopDrainRunsOut`).
Date: 2026-10-14.
Context: On the stop signal `readLoop` resolved the pending closes and returned without reading the fanotify fd again, so the records the kernel had queued for the last moments of a run were discarded and nothing counted them. A capture could then be short at its end and still read as complete.
Decision: After the stop signal the read loop processes queued records like any other batch for at most 2 s. Records left after that are read for at most 250 ms more without being processed and counted in `UndrainedRecords`, leaving out the observer's own records and those `PIDFilter` excludes. `Assess` reads the count as event loss.
Consequences: Records queued before the stop are in the capture whenever the drain empties the queue in time; that a full default queue of 16384 records empties within 2 s is expected from the per-record cost (a handle resolution and a `statx`) but not measured (**Unverified**). A process that keeps writing after the stop can hold the drain for the full budget and then makes the run INCONCLUSIVE, although its last records may postdate the recording; `Stop` takes up to 2.25 s longer in that case. The count is a lower bound and ignores `PathFilter`. The field is omitted when zero, so older captures parse and verify as before.
Alternatives rejected: Counting every queued record without reading it (the events are readable, so dropping them would be needless loss); draining until the queue is empty with no bound (a writer that never stops would hang `Stop`); stamping the stop time and dropping later records (fanotify records carry no timestamp).

### P-25: The fs probe names directory entries, and a rename is two events, its source and its destination
Status: Accepted, implemented (`reportFlags`, `initFanotify` in `pkg/probe/fs/fanotify.go`; `TestReportFlagsRequestEntryNames`, `TestKernelNamesEveryDirectoryEntryRecord`, `TestProcessRawEvent_NamedRenames`; `cmd/simagent` claims both halves of its rename). Amends P-18 (what its rename collapse acts on).
Date: 2026-10-14.
Context: The probe asked fanotify for `0x2400`, meant as `FAN_REPORT_DFID_NAME` but equal to `FAN_REPORT_FD_ERROR | FAN_REPORT_DIR_FID`: no entry name, and a bit that exists only from kernel 6.13 (**Reported**, `include/uapi/linux/fanotify.h`). A create, a delete or a rename therefore named only its directory and was ambiguous. The verifier accepts an ambiguous directory as covering any claimed file in it (V-18), and the adapters read which file a directory event was about from the order of events around it (I-22, I-32, I-33, I-39, I-43, I-44, I-50). Measured on kernel 6.17.0 on 2026-10-14 with an unprivileged inode mark on directories in tmpfs and in ext4, which gave the same records (**Verified**, a scratch program that dumps the info records and resolves each handle by `name_to_handle_at` of the paths that exist when the record is read): with `FAN_REPORT_FID | FAN_REPORT_DFID_NAME`, every create, delete, moved-from and moved-to record carries one DFID_NAME record, the directory's handle and the entry's name, and no FID record; every open, modify and close-write record carries a DFID_NAME record and a FID record. No record carried a directory handle without a name. The name is the one the entry had when the event happened: the close of a file renamed before the record was read still names the old name, while its FID record resolves to the new one. A rename gives a moved-from record naming the source and a moved-to record naming the destination, and nothing links the two. Only records of one process on one directory and one name merge: a temporary created and renamed away before the read gives `FAN_CREATE | FAN_MOVED_FROM` on the temporary's name, ahead of its open, modify and close; a file renamed away and back gives one `FAN_MOVED_FROM | FAN_MOVED_TO` record per name; two renames onto one name read late give one moved-to record. A record whose directory was removed before the read resolves through neither handle. Directory entries that are themselves directories (`mkdir`, `rmdir`, a directory's rename) give no record, since the mask has no `FAN_ONDIR`, as before.
Decision: The probe requests `FAN_REPORT_FID | FAN_REPORT_DFID_NAME` (`0xe00`), with the named constants of `golang.org/x/sys/unix`. `resolveEventPath` keeps its order, DFID_NAME first, so every event names the entry as it was named when the event happened. A rename is two `file_rename` events in kernel order, one naming the source (moved-from) and one naming the destination (moved-to); a record with both bits on one name is one event, as before. A trajectory that claims a rename claims both. P-18's collapse of a repeated rename stays: it now acts on renames that name one path, so two renames onto one name with nothing on it between are one event, which is what the kernel delivers when it merges them, and a rename away and back is one event per name merged or not.
Consequences: Creates, deletes and renames name their file, so a directory event no longer covers a claimed file by the fallback, and an adapter can require names where it inferred them from order. Ambiguous events, the fallback (V-18) and the adapters' older shapes stay for the captures made before; the adapters accept both shapes (I-56). `FAN_REPORT_NAME` needs kernel 5.9 (**Reported**, `fanotify_init(2)`), and the 6.13 bit is gone. Merging still depends on timing, now per name: a rename's source can come before the open, write and close of the file it renamed (P-18's amendment of 2026-10-14). `UnresolvedPaths` (V-35) counts the same records as before. A rename of a directory, and creating or removing one, stay invisible.
Alternatives rejected: Keeping directory grain and dropping only the stray bit (a directory event keeps covering any file in it, and the adapters keep inferring files from order); one event per rename naming only the destination (a cross-directory rename loses its source, as P-18 already says) or only the source (it loses where the file went); pairing the two halves into one event (nothing links them, and other records can lie between); `FAN_RENAME`, which reports both names in one record from kernel 5.17 (an event carries one target, so a second target field would change `pkg/models` and the verifier for what two events already express).
