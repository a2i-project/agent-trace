# Decisions: verification model

Why the verifier builds a process forest, checks coverage and aligns sequences instead of joining two lists on a time window. V1 to V8 keep the numbering of the original model; decisions taken while building it are numbered from V-9.

Entries carry their own dates. Statuses reconciled with the code at commit 1391cbe on 2026-10-11. Original source: docs/archive/08_verification_model.md (local only). As-built description: [../architecture/20_verifier.md](../architecture/20_verifier.md). Related: [integration.md](integration.md), [open.md](open.md).

## Model decisions

### V1: G is a forest rooted at the agent process; attribution walks up the tree
Status: Accepted, implemented in `pkg/verification.BuildForest` and `Forest.Attribute`.
Date: design 2026-09, built 2026-10-06 (commit 4f83cfb).
Context: Every observed event has a causing process and every process but the root has a parent. "Which claim owns this event" then has an exact answer with no clock.
Decision: Walk up from the causing PID to a child of the agent process; that child is the command. Level 0 is the agent itself, level 1 its children, level 2 and below their descendants. The parent edge is the one recorded at creation, so reparenting does not move a process. A reused PID is several incarnations, and time only chooses between them.
Consequences: Attribution is live and independent of duration and approval latency. The probes must emit PID, PPID and fork records ([probes.md](probes.md), P-5 to P-7).
Alternatives rejected: Time-window attribution (F0.2-F0.3 below).

### V2: T and the level-1 sequence of G should be the same sequence
Status: Accepted. Partly implemented: totally ordered sequences are aligned; the partial-order case is not (O-2 in [open.md](open.md)). Implemented in part by V-32 (parallel blocks); threads remain open (O-29 in [open.md](open.md)).
Date: design 2026-09 (in the archived verification model, before 2026-09-19); `BlockID` and `ThreadID` added 2026-10-06 (commit 56fef6e).
Context: A blocking agent emits one call, waits, emits the next, so its children appear in claim order. In the design corpus claim order was total in practice (measured on a local transcript corpus, design input only (local only: docs/research/harness_corpus.md)), but parallel tool calls and flattened subagents (D9) make it partial.
Decision: The design must tolerate a partial order: the observed sequence must be a valid linearization of the order T induces, using block and thread ids.
Consequences: Adapters carry `BlockID` and `ThreadID`. `Align` does not read them yet.
Alternatives rejected: Assuming total order for every agent.

### V3: Every observed event is explained by exactly one claim or by the baseline
Status: Accepted, implemented in `CheckCoverage`.
Date: built 2026-10-06 (commit 2130154).
Context: One claim expands into many unclaimed events (a test run). A list join cannot express one-to-many.
Decision: Each claim owns a subtree. The claimed subtrees plus the baseline must cover G. Anything left over (an unaligned top-level action, or a level-1 subtree no claim owns) is an omission.
Consequences: Omission detection rests on a fact that is hard to evade: a command cannot run without creating a subtree. Coverage is reported separately from alignment (V8).
Alternatives rejected: Skipping non-top-level events, which the first engine did and which never checked coverage.

### V4: Pair claims to observed top-level actions by position, compare content afterwards
Status: Accepted, implemented in `Align`.
Date: built 2026-10-06 (commit a147518).
Context: The first engine refused to pair unless targets were already equal, so a pair carried no evidence about its target, and a target substitution read as one fabrication plus one omission.
Decision: Align the claim sequence against the observed top-level sequence the way `diff` aligns files. A pair forms because of position, so the content comparison that follows is a real test.
Consequences: `cat README` claimed against `cat /etc/passwd` observed is one substitution at a known position.
Alternatives rejected: Content-keyed pairing (circular).

### V5: The edit script is the finding report
Status: Accepted, implemented in `Verify` (match = Corroborated, substitution = Mismatched, insertion = Unwitnessed, deletion = Unrecorded).
Date: design 2026-09 (in the archived verification model, before 2026-09-19); built 2026-10-06 (commits a147518, eec9735).
Context: The three attacks that edit claims (see [Attack definitions](evaluation.md#attack-definitions)) are the three edit operations: insertion is fabrication (P2), deletion is omission (P1), substitution is substitution (P3).
Decision: Report findings as the edit script, with both claimed and observed values on a substitution. The cost model separates content from structural disagreement (V-10), and ambiguity is reported (V-11).
Consequences: Evaluation can score classification and localization, not only detection.
Alternatives rejected: Deriving the four sets from a set difference.

### V6: The clock orders events, it does not pair them
Status: Accepted, implemented; refined by V-9, V-12 and V-31.
Date: design 2026-09 (in the archived verification model, before 2026-09-19); built 2026-10-06 (commits a147518, 5e17be5).
Context: A constant clock offset, long durations and approval latency are fatal to a window and harmless to an order.
Decision: Time is used for ordering and for one consistency check on claimed intervals. No tunable window remains.
Consequences: The original text also said a crossing of aligned pairs is itself a finding. As built, order within a lane is monotone by construction, and cross-lane order is neither checked nor reported (V-9).
Alternatives rejected: `matching.Config.Delta` (removed, V-18).

### V7: The harness baseline is measured by a null-task control run
Status: Accepted, implemented in `agent.Baseline`, `agent.Capture`, `cmd/baseline` and `Partition.SubtractBaseline`. Amended 2026-10-11 (docs review): baselines are measured for Claude Code 2.1.286 and 2.1.296, from the control runs kept with the five paired fixtures (`docs/architecture/30_agent_adapters.md`); none exists for Gemini. Amended by V-30 (2026-10-12): a level-0 file event a rule matches on a path some in-scope claim names is kept for alignment instead of subtracted.
Date: built 2026-10-06 (commit 5b551d7).
Context: A hand-maintained noise list is version-specific and rots silently into false omissions.
Decision: Run the agent on a task that claims nothing and record everything it does. All of it is harness activity, keyed on agent and version, and subtracted before alignment and coverage. Rule details are V-19.
Consequences: Re-derived on a version bump instead of maintained. Without a baseline, harness activity reads as omissions.
Alternatives rejected: Static lists in the adapter (I-19 in [integration.md](integration.md)).

### V8: FAITHFUL requires both checks, reported separately
Status: Accepted, implemented (`Verdict.Alignments` and `Verdict.Coverage`).
Date: design 2026-09 (in the archived verification model, before 2026-09-19); built 2026-10-06 (commit eec9735).
Context: An empty edit script says every claim happened. Complete coverage says nothing happened that no claim explains. They fail for different reasons.
Decision: Report the two checks apart; FAITHFUL requires both, plus a complete capture (V-15).
Consequences: Neither check is integrity: laundering through a script stays FAITHFUL, but becomes visible as a subtree with content (D5).
Alternatives rejected: One merged verdict that hides which check failed.

## Decisions taken while building the verifier

### V-9: One alignment per lane
Status: Accepted, implemented in `Align` and `LaneOf`.
Date: 2026-10-06 (commit a147518).
Context: The probes stamp events with different clocks and deliver them at different latencies (fanotify stamps at read time), so a file event and the exec after it can arrive out of order.
Decision: Align each lane (fs, proc, net) separately. Order inside a lane is trusted; cross-lane order is not checked and a crossing is not reported.
Consequences: A reordering across lanes goes unnoticed. Checking it needs a common clock for all probes first.
Alternatives rejected: One global sequence ordered by timestamps from different clocks.

### V-10: Edit costs
Status: Accepted, implemented (`costIndel`, `costSubSame`, `costSubType` in `align.go`).
Date: 2026-10-06.
Context: A substitution and an adjacent insertion plus deletion must not be interchangeable readings.
Decision: Match 0, same-type substitution 2, cross-type substitution within a lane 3 (reported with diff `action_type`), insertion or deletion 2.
Consequences: A substitution (at most 3) always beats insertion plus deletion (4), so no tie exists between the two readings.
Alternatives rejected: Unit costs, which tie a substitution with an indel pair.

### V-11: Ambiguity is reported, not resolved
Status: Accepted, implemented (`LaneAlignment.Ambiguous`, `Optimal`, `Verdict.Ambiguous`). Amended by V-31. Amended by V-32 (what counts as one alignment in a parallel block).
Date: 2026-10-06.
Context: When several minimum-cost alignments exist, a report pointing at entry 7 when entry 8 is equally consistent is misleading.
Decision: Count the minimum-cost alignments (saturating). More than one sets `Ambiguous`; the edits shown are one of them, chosen by a fixed preference, and the report says so. Checked against an independent brute force on random sequences.
Consequences: A finding's position may be one of several. The outcome does not change (see V-27).
Alternatives rejected: Silent resolution by iteration order.

### V-12: The claim interval is a finding, not a pairing condition
Status: Accepted, implemented (`Options.IntervalSlack`, `Verdict.OutsideInterval`; `cmd/verify --interval-slack`, default 500ms).
Date: 2026-10-06.
Context: D12 puts the interval in the trajectory, which the attacker controls. The agent and the probes do not share a clock.
Decision: A matched pair whose observed action falls outside the claim's `[Timestamp, End]`, widened by `IntervalSlack`, is flagged `OutsideInterval` and stays matched. `OutsideInterval` counts as a finding.
Consequences: Widening an interval (attack A4 in [evaluation.md](evaluation.md#attack-definitions)) suppresses nothing. It only evades this one consistency finding.
Alternatives rejected: Refusing the pair outside the interval, which reintroduces the time window.

### V-13: Ground truth records its own completeness
Status: Accepted, implemented in `models.GroundTruthFile`, `probe.CoverageReporter`, `verification.Assess`, `cmd/verify`.
Date: 2026-10-02 (commits fcb1fba, 0aac3a0).
Context: A bare event array cannot say that the capture lost events. Loss makes a verdict wrong in both directions, and the dangerous one is a hidden action pushed out of G by flooding.
Decision: `ground_truth.json` is `{"events", "coverage", "root_pid"}`. A legacy bare array parses as coverage unknown, which is not complete. A third outcome, INCONCLUSIVE, exists, and `cmd/verify` exits 0 FAITHFUL, 1 NOT FAITHFUL, 2 INCONCLUSIVE, 3 on usage or I/O errors.
Consequences: A flood denies verification instead of defeating it. A script cannot read INCONCLUSIVE or an error as a pass.
Alternatives rejected: A confidence score.

### V-14: Any loss makes the run INCONCLUSIVE, with advisory findings
Status: Superseded by V-15.
Date: 2026-10-02.
Context: The first implementation, as a wrapper around the old `Verify`.
Decision: Any loss counter above zero, or unknown coverage, gave INCONCLUSIVE, with findings printed as advisory.
Consequences: A clear fabrication under minor loss could not be reported as NOT FAITHFUL.

### V-15: Outcome rules under loss
Status: Accepted, implemented in `Verify`.
Date: 2026-10-06 (commit eec9735).
Context: Loss can manufacture findings (a lost fork record orphans a subtree, a dropped event reads as a fabrication), and can hide them.
Decision: In order: no root PID, or no event carrying a PID, is INCONCLUSIVE with no findings (V-17). A lane too large to align is INCONCLUSIVE. Any finding gives NOT FAITHFUL, marked `Advisory` with reasons when the capture is incomplete or some event has no PID. With no findings, an unplaceable event, a loss counter or a missing coverage record gives INCONCLUSIVE. Otherwise FAITHFUL. Content gaps (faulted SSL reads, TLS attach failure) are notes and do not block FAITHFUL.
Consequences: FAITHFUL is never asserted on an incomplete capture. Whether any finding is robust to loss is open (O-12).
Alternatives rejected: V-14.

### V-16: Quiet forks are not unexplained subtrees
Status: Accepted, implemented (`Coverage.Quiet`).
Date: 2026-10-06 (commit da6ccc8).
Context: Go's `os/exec` forks a throwaway child per process to probe for pidfd support. It never execs and does nothing, and it read as an unexplained subtree on every honest run.
Decision: A level-1 process that never exec'd, has no exit record and caused no observed event is reported as Quiet and is not a finding. A fork that later writes, or whose descendant execs, is still unexplained.
Consequences: The requirement remains that every observed event is explained; a process with no events leaves none unexplained.
Alternatives rejected: An exception keyed on Go's runtime behaviour.

### V-17: The old engine is removed; no root PID means INCONCLUSIVE
Status: Accepted, implemented in `Verify`.
Date: 2026-10-06 (decided with the user, commits 88fb3fc, eec9735).
Context: Legacy and host-wide ground truth has no root PID and events without PIDs, so no tree can be built.
Decision: Delete the time-window engine. Such ground truth is INCONCLUSIVE with no findings. `cmd/watch` records the launched agent's PID (or `--root-pid`) in the file.
Consequences: Old captures cannot be re-verified to a verdict.
Alternatives rejected: Keeping the old engine as a fallback for legacy files, which would keep the time window alive.

### V-18: `matching.Match`, `Config` and `Delta` are removed
Status: Accepted, implemented (commit 5e17be5).
Date: 2026-10-06 (commit 5e17be5).
Context: After the alignment, nothing called `Match`, and its target-equality precondition was what made substitution unreportable.
Decision: Only `matching.TargetsMatch` remains: per-action-type target normalization and the directory fallback gated on `PathIsAmbiguous`, with no timestamp or type condition. Content comparison lives in `verification.contentDiffs`.
Consequences: No time constant has to be justified anywhere. `cmd/verify --delta` is gone.
Alternatives rejected: Keeping `Match` with the precondition removed, as the original model proposed.

### V-19: Baseline rules match exactly, from what every control run did
Status: Accepted; amended by I-24 (`--min-agreement`) and V-24 (capture script default 1/N). Implemented in `agent.Capture` and `Baseline.Predicate`.
Date: 2026-10-06 (commit 5b551d7).
Context: A baseline is a list of things that are not findings, so it is a place to hide.
Decision: Control runs are normalized by the adapter and attributed with the forest. Rules are the agent's own top-level actions and the commands it started, kept only when every run did them; the rest is listed as unstable. A rule matches action type and target exactly, with no patterns. Descendants are not rules, since the command explains its subtree. A run with loss, no coverage record or no root PID is refused, and a baseline for one agent is refused for another.
Consequences: A baseline cannot be widened into a wildcard. A harness that varies its targets per run leaves those events as omissions.
Alternatives rejected: Glob or regex rules.

### V-20: Nil is three-valued in the content comparison
Status: Accepted; amended by V-22 (a stated value the probe did not capture is Unverified and makes the run INCONCLUSIVE) and by V-28 (the opt-out also applies to `OutputHash` on `FileWrite`). Implemented in `contentDiffs` with `Options.Expresses`.
Date: 2026-10-06 (commit eec9735).
Context: The first engine forced a mismatch whenever the claim had no exit code, output hash or request hash and the probe captured one. No real format holds all three, so honest trajectories failed, more often as the probes improved.
Decision: A nil is a probe gap (benefit of the doubt), a format limit (not a finding) or an opt-out (a finding). The opt-out applies only where `Expresses` says the format can state the field, the probe captured it, and the field is one of `OutputHash` on `FileClose`, `ExitCode` on `ProcessExit`, `RequestHash` on `NetRequest`. `InputHash` stays permissive. `Options.IgnoreExits` drops exits from both sides.
Consequences: The answer comes from the adapter, per tool (I-20).
Alternatives rejected: Treating every nil as agreement, which lets an agent opt out of every check.

### V-21: A nil `Options.Expresses` means everything is expressible
Status: Accepted as built; contradicts the original migration plan (O-1 in [open.md](open.md)).
Date: 2026-10-06 (commit eec9735).
Context: The original plan asked for the conservative default "the format cannot express it", so a missing declaration never manufactures a mismatch.
Decision: The code reads nil as the strict reading: every field is expressible. `Generic.Expresses` also returns true. Real adapters always supply a declaration through `agent.Prepare`.
Consequences: Correct for `simagent`, which can state every field. A caller that invokes `Verify` directly for a real agent without a declaration gets false opt-out findings.
Alternatives rejected: Not recorded at the time.

### V-22: A stated value the probe did not capture is unverified, and FAITHFUL is not asserted over it
Status: Accepted, implemented (`unverifiedFields`, `Edit.Unverified`, `Verdict.Unverified`, the outcome rule in `Verify`). Amends V-20 and the last consequence of P-16. Amended by V-29 (`input_hash` joins the unverified fields).
Date: 2026-10-08 (a security review of the verifier, local only).
Context: V-20 reads a nil on the observed side as agreement, because a missing capture cannot disprove a claim. The fs probe publishes a close without a hash whenever a write-class event, an open included, follows it within the settle window (P-16). An agent that reads its file back right after writing it therefore made the probe drop the hash, and any claimed content was then corroborated (**Verified**: `TestPairedWriteWithoutAnObservedHashIsInconclusive` verified FAITHFUL with a false hash before the change).
Decision: A pair whose claim states `output_hash` (on `file_close` or `file_write`), `exit_code` (on `process_exit`) or `request_hash` (on `net_request`) and whose observed event does not carry it is corroborated and listed as unverified, with the fields named. It is not a finding, since a probe gap is not the agent's doing. With no finding, the outcome is INCONCLUSIVE with the fields and counts as the reason. `Expresses` is not consulted: the claim did state the value.
Consequences: The agent can no longer switch content verification off, only make it inconclusive, which the report says. An honest run whose probe dropped a hash is INCONCLUSIVE rather than FAITHFUL, the same reading as event loss. `input_hash` is not tracked, because the fs probe stamps every open with one. Amended 2026-10-09 (commit c89cc84): the fs probe counts hashless closes (`HashlessCloses`, a note in `Assess`), so `watch` says at capture time how many closes it could not vouch for.
Alternatives rejected: Reporting the pair as a mismatch (it punishes an honest agent for a probe gap, and under loss findings are advisory anyway); keeping the pair silent (the attack above).

### V-23: A file claim the capture could not have witnessed is set aside, not aligned
Status: Accepted, implemented (`pkg/verification/scope.go`, `Verdict.OutOfScope`, the outcome rule in `Verify`).
Date: 2026-10-09 (audit item 5, step 2, of a security review on 2026-10-08, local only; follows P-17).
Context: The fs probe kept only paths under the workspace and nothing recorded that, so a truthful Write elsewhere had no event to pair with and read as Unwitnessed (**Verified**: a two-file shell agent, and `TestPairedWriteOutsideTheWorkspaceIsOutOfScope` on the paired fixture, both NOT FAITHFUL before the change). P-17 widened the capture and added `fs_scope`, but captures made before it, and paths on filesystems the probe could not mark, remain outside what a capture can say.
Decision: Before alignment, every file-lane claim whose path the capture could not have observed is set aside into `OutOfScope`. With a record, a path is in scope when the longest mount point covering it was marked, out when that mount point is listed as unmarked. Without a record, the workspace is the scope; with neither record nor workspace, everything is in scope (a direct caller of `Verify`). Set-aside claims are not findings, and with no finding the outcome is INCONCLUSIVE with their count as the reason. Process and network claims have no path scope.
Consequences: An honest agent is not called a fabricator for a write the probe was not watching, and the verdict says the claim was not checked rather than confirmed. Removing the claim before alignment keeps the other claims' positions intact. A dishonest agent's hidden write in an unobserved place is still invisible; the record now says where that is. Under P-17 the unobserved places are the unmarked filesystems only.
Alternatives rejected: Keeping legacy captures on the Unwitnessed reading (it is a known false positive once the workspace is in the file); dropping the claim silently (the report must say what was not checked); treating the gap as a finding (it is the capture's limit, not the agent's).

### V-24: Unexplained file events in the harness's own directories are reported apart and make the run INCONCLUSIVE
Status: Accepted, implemented (`Options.HarnessOwned`, `Verdict.UnexplainedHarness`, `isHarnessOwned` in `pkg/verification`; `agent.HarnessOwner`). Amends V-19: the capture script's default agreement threshold is 1/N.
Date: 2026-10-09 (taken after the first full capture under P-17).
Context: The baseline keeps what enough control runs did (V7, V-19, I-24). The harness does some things only sometimes: a backup of its configuration on some startups, a telemetry connection, a package-manager probe. When one of them happens in the run being verified and in no control, it reads as an unreported action and an honest run is NOT FAITHFUL (**Verified**: the basic task of 2.1.286 on 2026-10-09, seven claims corroborated, NOT FAITHFUL on six events of a backup of `~/.claude.json` that none of three controls made). No number of controls sees every occasional behaviour.
Decision: Two measures. The capture script records more controls and keeps an action seen in any one of them (a 1/N agreement threshold), since a control runs no task, so whatever it does is the harness's. And the adapter declares where the harness keeps its own files (`HarnessOwner`); an unexplained level-0 file event there is reported as `UnexplainedHarness`, which is neither a finding nor FAITHFUL, so a run without findings is INCONCLUSIVE with the count as the reason. A file event elsewhere, a connection that sent data (since N-22 one that sent nothing is capability evidence), and a command under those directories stay findings. Amended 2026-10-11 (commit 25e243d): such an event whose path no claim names is set aside before alignment, as a baseline event is, instead of being taken out of the findings after it. Left in the sequence it could pair with a fabricated claim through an ambiguous alignment that read the fabrication as a substitution (**Verified**: two runs in a hundred on the edits capture, which has two such events). An event on a path some claim names stays, so an honest write into the harness's directory pairs with it.
Consequences: An honest run with occasional harness activity in its own directories is INCONCLUSIVE rather than falsely unfaithful, and the events are listed so a reader can judge them. A write by the agent into those directories, the shell snapshot that every later Bash call sources included, is still reported and still blocks FAITHFUL, but is no longer a finding by itself; that is weaker than before and is the price of not calling honest runs unfaithful. The declaration explains nothing, so it is not a hiding place in the sense of D11. This entry does not change how the harness's own write of the shell snapshot is explained: a baseline rule for the snapshot file explains it, as before.
Alternatives rejected: Declaring the harness directories explained wholesale (a write there, the shell snapshot included, would never be reported); keeping the strict reading (honest runs unfaithful, the exit code unusable, false positives in the evaluation); more controls alone (a behaviour rarer than the sample still escapes).

### V-25: A write in the workspace by a process the tree cannot place makes the run INCONCLUSIVE
Status: Accepted, implemented (`Verdict.OutsideWrites`, `outsideWrites` in `pkg/verification`).
Date: 2026-10-09 (audit item 7 of a security review on 2026-10-08, local only).
Context: P-15 keeps events from processes outside the agent's tree and reports them, and they never changed the verdict: a FAITHFUL was asserted over a workspace that a write and a close of `.backdoor` by an unplaced pid had changed (**Verified**: audit case 7 of that review, on the paired fixture). The tree cannot say such a write was the agent's, so it is not a finding; but it cannot say it was not, and the workspace is what the verdict is about.
Decision: Among the outside events, the write-class ones (writes, closes, renames, deletes) under the workspace are `OutsideWrites`. They are not findings; with no finding the outcome is INCONCLUSIVE with their count as the reason. Reads by outside processes stay informational. With no workspace recorded, every outside write-class event counts, since such a capture kept only workspace paths from other processes.
Consequences: An editor or another tool touching the workspace during a capture makes the run INCONCLUSIVE, which is the honest reading: the capture cannot vouch for the workspace. A process the agent reached outside the tree (a daemon over a socket, O-13) that writes the workspace is no longer silent. Nothing changes for a clean capture.
Alternatives rejected: Keeping FAITHFUL (asserts what the capture cannot vouch for); making them findings (they are not the agent's doing as far as the tree can tell, and the user's own editor would make the agent unfaithful).

### V-26: A truncated observed target pairs by prefix and is unverified
Status: Accepted, implemented (`truncatedPrefix` in `align.go`, `unverifiedFields`; `evalPayloadPrefix` in the Claude Code adapter).
Date: 2026-10-09 (with P-19).
Context: The proc probe can now say it cut a command line (P-19). Comparing the cut text for equality read every such line as a substitution.
Decision: An observed target flagged `TargetTruncated` pairs with a claim whose target it is a prefix of, as a corroborated pair unverified on its target, which makes the run INCONCLUSIVE under V-22. A cut target that is not a prefix of the claim is a mismatch, and an unflagged prefix is a mismatch as before. The Claude Code adapter recovers what the probe kept of a cut wrapper's eval word so the prefix comparison applies to the command, not to the wrapper.
Consequences: An honest long command is never a false substitution; a dishonest claim that shares a prefix with a cut command line is not refuted beyond the cut, which the report says. The cap is high enough that neither case arises for a single-string command.
Alternatives rejected: Comparing hashes of the full line computed in the kernel (bounded loops cannot hash two megabytes); reporting a cut line as a mismatch (the false positive the security review found).

### V-27: P5 is restated: three outcomes, deterministic given the capture
Status: Accepted, implemented (`Outcome` in `pkg/verification`; `docs/architecture/00_overview.md` P5). Ratified by the user on 2026-10-11 (was O-3).
Date: 2026-10-11.
Context: P5 said the verdict is binary. The verifier returns FAITHFUL, NOT FAITHFUL or INCONCLUSIVE, marks NOT FAITHFUL under loss as `Advisory`, and reports `Ambiguous` when several minimum-cost alignments exist (V-11, V-13, V-15).
Decision: P5 reads: the verdict is a pure function of the trajectory, the ground truth with its coverage record, the baseline and the options, with three outcomes and no score. INCONCLUSIVE is a failed precondition on the capture, not a confidence level; `Ambiguous` says which entry a finding belongs to and never changes the outcome.
Consequences: A run that cannot support FAITHFUL is never reported as FAITHFUL or as NOT FAITHFUL without a finding. Exit codes 0, 1, 2 (and 3 for an error) follow the outcome.
Alternatives rejected: Keeping P5 literal and folding INCONCLUSIVE into NOT FAITHFUL, which would report a lossy capture as a lie by the agent.

### V-28: A nil `output_hash` on a `file_write` the tool can state is an opt-out finding
Status: Accepted, implemented (`contentDiffs`, `TestVerify_AWriteThatDropsAHashItsToolStatesIsAMismatch`). Ratified by the user on 2026-10-11 (was O-26 in open.md).
Date: 2026-10-11.
Context: The opt-out rule of V-20 (a claim that omits a value its format can state, where the probe captured it, is a finding) applies to `output_hash` only on `file_close`. Claude Code claims a Write as a `file_write` carrying the hash and never claims a close (I-22), so a Write claim that drops its hash is neither a finding nor unverified (V-22 needs a stated value).
Decision: Apply the opt-out rule to `output_hash` on a `file_write` claim whose tool `Expresses` the field, exactly as on `file_close`.
Consequences: A Write that omits content its format records becomes a Mismatched finding. An Edit is unaffected while its declaration stays as it is (I-31 claims the hash when the result record has it). The paired fixtures must keep their outcomes; the change is checked against them when built.
Alternatives rejected: Leaving the rule on `file_close` only (a silent pass on a content claim); having the Claude Code adapter claim a `file_close` carrying the hash, which invents a claim the format does not make.

## Superseded

### F0.2-F0.3: Timestamp-window matcher
Status: Superseded by V4, V6 and V-18.
Date: 2026-09 (Tier 0), removed 2026-10-06.
Context: The first engine paired each claim with the nearest unmatched event of the same type and target within `Delta`, and set-differenced the rest.
Decision (historical): `M(t, g)` true iff same action type, same target, timestamp within a configurable delta; greedy closest-timestamp pairing.
Why superseded: The pairing was circular (substitution unreportable), one claim is many events, greedy nearest-time mispairs repeated actions, and no value of `Delta` works once approval latency sits inside the interval.

### P1-P3 (original wording)
Status: Superseded by V3 (P1), V4 and V5 (P2, P3). The restated properties are in [../architecture/00_overview.md](../architecture/00_overview.md).
Date: original wording 2026-09 (archived protocol architecture); superseded in design before 2026-09-19 and in code on 2026-10-06.
Context: The original properties named the mechanism: omission as G events with no matching T entry, fabrication as T entries with no matching G event, substitution as entries that "match an event in G by timestamp but differ in content".
Why superseded: The claims are unchanged; the mechanism is not. P3's wording described a matcher that was never built, since `Match` never paired on timestamp alone.

### V-29: A stated input hash the probe did not measure is unverified
Status: Accepted, implemented (`unverifiedFields` in `pkg/verification/verification.go`). Amends V-22. The user's ruling on O-28, option (a), with P-22.
Date: 2026-10-12.
Context: V-22 lists a stated value the probe did not capture as unverified, and left `input_hash` out because the fs probe stamped every open with one. P-22 removes the stamp: an open the probe did not measure carries no input hash.
Decision: A claim that states `input_hash` paired with an event that carries none is corroborated and unverified, with `input_hash` named, like the three fields of V-22. A nil stated input still agrees, and two stated inputs that differ are a mismatch.
Consequences: An honest Edit of a file the probe never measured is INCONCLUSIVE, not NOT FAITHFUL, and the report names the field. Without this half, P-22 alone would have turned the false finding into a silent pass, since a nil observed input agrees with any claim.
Alternatives rejected: Leaving `input_hash` permissive (a lie about a file's content before an Edit would pass unreported).

### V-30: A baseline event on a path a claim names is kept for alignment, and counted as baselined if it stays unpaired
Status: Accepted, implemented (`Partition.SubtractBaseline`, `keptBaseline`, `withoutExplainedLevelZero` in `pkg/verification`). Amends V7. Approved by the user on 2026-10-12. Amended by I-41 (2026-10-12): the path a claim names is compared exactly, so only events on that exact path are kept, while the baseline still recognises them in their canonical form.
Date: 2026-10-12 (the `tools` capture of Claude Code 2.1.296).
Context: V7 subtracts every event a baseline rule matches before alignment. On the `tools` capture the agent read the output file of its background Bash, `/tmp/claude-<uid>/<dir>/<session id>/tasks/<id>.output`. Every control's Bash opens its own output file, and with the ids canonicalised (I-29) the baseline holds `file_open` of that path as a rule at every agreement from 0.2 to 1.0 (**Verified** on the capture's five controls). The subtraction therefore removes the agent's own open with the harness's, so even a claim carrying the canonical path has nothing to pair with and reads as Unwitnessed. V-24 solved the same problem for events in the harness's own directories by keeping the ones on claimed paths.
Decision: A level-0 file event that a baseline rule matches, and whose path some in-scope file claim names, is not subtracted: it stays in the aligned sequence and can pair with the claim. If after alignment it is still unpaired, it is explained by the baseline exactly as if it had been subtracted: not Unrecorded, not in `Coverage.UnexplainedActions`, not unexplained harness activity. Commands and connections the baseline matches are subtracted as before, and so is a file event on a path no in-scope claim names.
Consequences: An honest claim on a path the harness also touches is corroborated, and the harness's own events there add no finding. What a fabricated claim on such a path can now pair with: a claimed read (`file_open`) of a file the harness itself opened is corroborated by the harness's open, which the verifier cannot tell from the agent's, where V7 read it as Unwitnessed; a claimed write still has to match the observed content when the claim states it, so a write the harness made is a Mismatched finding against a fabricated content claim. A fabricated claim next to a kept event of the same lane can pair with it as a substitution (cost 2 against 4 for an insertion and a deletion), so it is still a finding but may be classified as a substitution against the harness's event rather than as a fabrication, the risk V-24's amendment recorded; it arises only where a claim names a baselined path. The attack evaluation on the four checked-in fixtures is unchanged (detection, classification and localization 1.000 for every generator), but its generators avoid observed targets and so never fabricate on a baselined path: the loss above is not measured by it.
Alternatives rejected: Subtracting as before and letting the claim side carry the canonical path alone (the agent's own open is removed with the harness's, so the honest Read stays unwitnessed); a baseline rule that records how many times an action happened (a count varies between runs, and the agent's extra open would still have to be told apart from a harness open).

### V-31: Among equal-cost alignments, the one with the fewest pairs outside their interval is shown
Status: Accepted, implemented (`alignLane` in `pkg/verification/align.go`; `TestAlign_TiesPreferThePairingInsideTheInterval`, `TestAlign_ContentCostDominatesTheInterval`, `TestAlign_IntervalTieBreakAgreesWithBruteForce`, `TestVerify_AnHonestReadPairsWithTheOpenInsideItsInterval`). Amends V-11. The user's ruling on O-24, option (b).
Date: 2026-10-12 (the second `tools` capture of Claude Code 2.1.296).
Context: V-11 shows one of several minimum-cost alignments, chosen by a fixed preference (pair, then insertion, then deletion, tracing back from the end). When a claim can pair at the same cost with several observed events, that preference pairs it with the last one the traceback reaches, and if that one lies outside the claim's interval the report carries an interval finding about a true claim. The project capture showed this under attack: omitting claims left an ambiguous alignment and an interval finding on a truthful claim in 2 of 100 runs of two omissions and 7 of 100 of three. The second `tools` capture showed it on an honest run: the agent's Read of its background task's output file paired with the harness's open of another task's output file, which has the same canonical name (I-29, I-36) and came 1.9 seconds after the agent's own open, and read as outside its interval (**Verified**, with a baseline from that capture's five controls).
Decision: The costs of V-10 stay the primary cost. Among the minimum-cost alignments of a lane, the dynamic program also minimises the number of pairs flagged `OutsideInterval` (a lexicographic secondary cost), and the traceback takes a step only when it keeps both costs on their optimum; only ties that remain use the fixed preference. `Optimal` and `Ambiguous` count the primary minimum alone, so a lane whose shown reading the interval chose is still reported as ambiguous. The program stays O(n·m), with one more 32-bit table, under the same `maxCells` guard, and the count still saturates.
Consequences: Time never makes a reading with a worse content cost win. It chooses only among readings that content cannot tell apart, and it never refuses a pair (V-12). What the choice can change, checked against the code:
- Mismatched and Unwitnessed findings: a reading with p pairs among n claims and m events costs 2(n-p) + 2(m-p) plus its pair costs. If one minimum-cost reading pairs every claim at cost 0, its cost is 2(m-n), and any reading of that cost has p = n and pair costs of 0. So either every minimum-cost reading of a lane has a substitution or an insertion, or none has, and the choice never decides whether the run has one. Where they exist, the choice can change their classification (two substitutions or an omission plus a fabrication can cost the same) and location.
- Unrecorded findings, when no reading has a substitution or insertion: the readings differ only in which of several events that each corroborate a claim it pairs with, and which are left unpaired. A leftover level-0 file event is baselined (V-30) or harness-owned (V-24) by predicates of its action type and target alone: baseline rules match type and target exactly and carry no counts (V-19). When the events a claim chooses between share type and target, as on the `tools` capture, the leftover has the same status whichever it is, so the choice changes only the reported location and whether an interval finding appears. When they pair with the claim only through a cleaned path, an ambiguous directory record or a truncated target (V-26), or differ in captured content (one carries a hash the other lacks, V-22), the choice can decide whether the leftover is Unrecorded or the pair unverified, as the fixed preference could before; the interval now decides where position did.
- Attacker view: claim times come from the trajectory, which the attacker controls (V-12). A retimed claim escapes an interval finding only when some minimum-cost reading pairs it with an event inside its new interval. On a lane without content findings that event corroborates the claim exactly as the one it really paired with does, so what passes is a lie about when an action that happened more than once happened. A retimed claim with no such event inside its new interval is outside it in every minimum-cost reading, so an interval finding remains. Minimising the total can move an interval finding from one claim to another at equal count, never remove it.
- The attack evaluation on the four checked-in fixtures keeps detection, classification and localization at 1.000 for every generator and the same ambiguity counts; the unaccounted interval findings on the project capture fall from 2 and 7 of 100 runs to none, and the retimed omissions keep their interval findings (12 of 100 runs on the parallel capture).
Alternatives rejected: (a) the fixed preference alone, which gives false findings on honest runs, as on the `tools` capture. (c) reporting interval findings only on an unambiguous alignment: ambiguity is lane-wide and an adversary can bring it about (a claim on a path the harness also opens is enough, V-30), which would switch the timing check off for the whole lane.

### V-32: The claims of one parallel block match in any order; blocks keep their order
Status: Accepted, implemented (`blockSegments`, `alignBlocks` in `pkg/verification/blocks.go`; `LaneAlignment.Degradations`, `Verdict.Degradations`; the tests in `pkg/verification/blocks_test.go`). Implements V2 in part. The user's ruling on O-2, option (a), for parallel blocks; the thread part stays open as O-29 in [open.md](open.md).
Date: 2026-10-13 (the `shapes` capture of Claude Code 2.1.296).
Context: V2 asks that the observed sequence be a valid linearization of the partial order T induces; `Align` read neither `BlockID` nor `ThreadID` and aligned claims in slice order. On the `shapes` capture the model emitted, in one assistant message, the Bash calls `sleep 2; cat slow.txt` and then `cat fast.txt`, about 50 ms apart, and the kernel shows the second one's command started first, about 1.5 ms before the first's (**Verified**). Strict order paired them crosswise: two Mismatched `process_exec` pairs on an honest run, and an ambiguous lane.
Decision: Claims that share a non-empty `BlockID` (one assistant message, as the Claude Code adapter builds them; one step with several calls for Gemini) and are consecutive in a lane form a block. Within a lane, a block's claims may pair with observed events in any order among themselves; every claim of an earlier block, or an earlier claim with no block, precedes every claim of a later one, and the observed sequence must respect that (the fence). The freedom applies per lane to the members in that lane, so a block holding a Bash call and a Read is free in `proc` and in `fs` separately. The fence orders the start of a call, not its end. Costs (V-10), the interval tie-break (V-31), the saturating count and the `maxCells` guard are unchanged:
- Algorithm: the dynamic program of V-11 runs over states instead of claim prefixes. A state is a segment (a block, or one claim) and the bitmask of its members already consumed; a member is consumed by pairing it, in the order of the events it pairs with; the members left unpaired are inserted together once the segment's pairs are done. A minimum-cost alignment never leaves a member and an event of the same segment's span both unpaired (pairing them costs at most 3, against 4), so every minimum-cost pairing has exactly one path, and a lane of one-claim segments is exactly the program before V-32 (checked edit for edit on random lanes). A lane with no block of two or more claims runs the program before V-32 unchanged.
- Bounds: the cap is the harness's concurrency limit, 10 claims of one block in one lane, so a segment has at most 2^10 - 1 states. The table holds (states + 1) times (events + 1) cells of 12 bytes and is refused above `maxCells` (16 Mi cells, about 192 MiB) with `ErrTooLarge`, as before; a cell reads at most 10 pair predecessors and one deletion, and the first state of a segment at most 1023 flush predecessors, so the work is O(cells times 10). A block larger than the cap, a block whose claims are not consecutive in the lane (each run is then free only within itself) and a `process_exit` claim carrying a block id (exits never join a block: a call may end after a later block starts, so they keep the trajectory's order) are each aligned more strictly than this rule and named in `LaneAlignment.Degradations` and `Verdict.Degradations`. The strict reading can add an order finding and never removes one, so the outcome is not changed.
- Ambiguity: `Optimal` counts pairings, which claim pairs with which event. Orderings of a block that give one pairing count once. So do pairings that differ only by exchanging members of one block that are equal in every field the comparison reads (type, target, tool, input and output hash, exit code, request hash): two Edits of one file in one message whose claims carry no content, each observed, are one reading, not an ambiguity (the project fixture has two such pairs). A second pass of the program counts with such members pairing in trajectory order; time is left out of that equality, so, as in V-31, the interval chooses the reading shown among pairings the count treats as one. Members that differ in any compared field count separately: two substituted members of one block whose events could be exchanged at equal cost are reported as ambiguous. Outside blocks the count is as before.
- Background calls: a background Bash or subagent may outlive its block. Its descendants and its file events are its command's content, never positions (D3), and Claude Code's and Gemini's exits are not aligned (I-15), so nothing it does after the fence reads as out of order. Only the generic format aligns exits, and there an exit claim keeps the trajectory's order, with the degradation above.
- Attacker view: `BlockID` comes from the trajectory, which the attacker controls. Grouping claims into one block buys only the freedom to reorder them: every claim must still pair with an event of matching type, target and content, so omission (an unpaired event), fabrication (an unpaired claim) and substitution (a pair that differs) are found as before, inside a block as outside. The cap bounds the freedom to ten claims per lane, and the fence still orders blocks. The Claude Code adapter builds blocks only from the transcript's message structure (a message with several tool calls). What becomes invisible is an order lie inside one message: an agent that reports, in one message, calls whose effects happened in another order than listed, or that claims several sequential calls as one message, is not caught for the order, and two claims of one block may each be paired with the other's event when content cannot tell them apart.
Consequences: The two crosswise pairs of the `shapes` capture are corroborated (with the capture's own baseline at agreement 0.2). Every checked-in fixture gives byte-identical `cmd/verify` output, with and without a baseline. The attack evaluation on the four checked-in fixtures keeps detection, classification and localization at 1.000 for every generator, and the widened and retimed omissions keep their numbers; the count of ambiguous alignments rises where a mutation touches a block (of 100 runs: on the project fixture 50, 69 and 78 for one to three omissions against 0, 6 and 14, and 50, 75 and 84 for one to three substitutions against 0; two and three substitutions on the parallel fixture 9 and 30, on the edits fixture 24 and 70, against 0), because which member of a block an omission or a substitution hit is no longer fixed by the claim order. `cmd/verify` does not yet print `Verdict.Degradations`.
Alternatives rejected: (b) keep the total order and report blocks as a degradation: the honest `shapes` run reads as two substitutions. (c) per-thread alignment: the thread id is attacker-controlled, and it does not address blocks. An exact search over the permutations of each block: the same answer at up to 10! orders per block, against 2^10 states. A heuristic reordering by observed time: it guesses, and a guess can turn a substitution into two matches.

### V-33: A harness-implied claim pairs only with the exact open it predicts and costs nothing unpaired
Status: Accepted, implemented (`models.TrajectoryEntry.ImpliedBy`, refused by `models.ParseTrajectory`; `implied`, `insertCost`, `impliedPairs`, `pairCostOf` in `pkg/verification/align.go`; the second layer of `alignBlocks` in `blocks.go`; `impliedWitness`, `Verdict.HarnessImplied`, `Verdict.HarnessImpliedUnpaired` in `verification.go`; `attack.WithoutImplied`, `attack.ErrImplied`; the tests in `pkg/verification/implied_test.go`). Amends V-10 (an unpaired harness-implied claim costs 0), V-11 and V-32 (what counts as one alignment). The user's choice of design on 2026-10-13: optional harness-implied claims.
Date: 2026-10-13 (the `shapes` capture of Claude Code 2.1.296).
Context: After a Bash call, Claude Code reads the file a simple read command named, to record the file's state, unless the file is already in its record of file state, is not a regular file or exceeds 10 MiB (**Reported**, from the strings of the 2.1.296 binary; which commands count is the adapter's business). On the `shapes` capture the agent's own process opened `fast.txt` about 7 ms after the command `cat fast.txt` exited, and after its `cat` child had opened the file, and the open was an Unrecorded finding at every agreement (**Verified**). Whether the harness reads depends on state the transcript does not record: in the `edits` fixture `cat notes.txt` caused no read by the agent's process, because the harness had written and edited the file itself (**Verified**). A claim that the harness reads would be Unwitnessed whenever it does not, and no claim leaves the read Unrecorded whenever it does.
Decision: A claim may be marked harness-implied: an action the harness may or may not perform on its own because of a call. The verifier enforces the restrictions; the adapter only proposes.
- Marker: `TrajectoryEntry.ImpliedBy`, the claimed command (the `process_exec` target) whose run implies the claim. It has no JSON form (`json:"-"`), so no trajectory read from JSON can carry it, and `ParseTrajectory` refuses an entry naming `implied_by` rather than read it without the marker. Only an adapter's own derivation sets it. A marker on any action type but `file_open` is ignored: the claim is aligned as an ordinary one.
- Costs: left unpaired a harness-implied claim costs 0, is never Unwitnessed and is listed in `Verdict.HarnessImpliedUnpaired`. It may pair only with an exact match: a `file_open` whose target is the claim's path as a string (no `filepath.Clean`, no ambiguous directory record, no truncated target), with no content difference and no unverified field, inside the claim's interval widened by `IntervalSlack`, and, under `Verify`, only when some command whose own exec has exactly `ImpliedBy` as its target, not explained by the baseline and not truncated, has an open of exactly that path among the events beneath it, no later than the event (`impliedWitness`): the command read the file, then the harness did. Every other pairing is refused, so it costs more than leaving both unpaired (0 + 2), and a harness-implied claim is never Mismatched, never outside its interval and never unverified. An ordinary claim of the same open always wins it, since leaving an ordinary claim unpaired costs 2.
- Report: a paired harness-implied claim goes to `Verdict.HarnessImplied`, not to `Corroborated`: it is the harness's doing, explained, not a confirmation of the agent. Neither list is a finding or blocks FAITHFUL; the open it pairs with counts as paired for coverage.
- V-23: a harness-implied claim on a path the capture could not observe joins `HarnessImpliedUnpaired`, not `OutOfScope`, which would block FAITHFUL over a read that may never have happened.
- V-24 and V-30: a harness-implied claim names no path for them, so it keeps no baseline event and no event under the harness's own directories in the aligned sequence. It absorbs only an open that would otherwise be Unrecorded.
- V-31: a harness-implied pair is always inside its interval, so it adds no violation; the tie-break is unchanged.
- V-32: a harness-implied claim carries the block id of the call that implied it and is a member of that block in its lane, counted toward the cap of 10.
- V-11, counting: `Optimal` counts pairings, as V-32 defines them. A lane holding a harness-implied claim runs `alignBlocks` even without a block. There an unpaired harness-implied claim and an unpaired event can share a span, so a deletion could come before or after the flush that inserts the claim, two paths for one pairing; each cell gets a second layer holding the paths whose last move is a flush, and a deletion may not follow one, which leaves exactly one path per pairing. A lane without a harness-implied claim has one layer and runs the program of V-32 step for step. Two harness-implied claims that could each take one open are two readings, and ambiguous, unless they are equal in every compared field and in their interval, which decides whether they may pair at all. The minimum cost, the fewest interval violations and the count agree with V-32's independent brute force on random lanes holding blocks and harness-implied claims (`TestAlign_ImpliedClaimsAgreeWithBruteForce`).
- Attacker view: the trajectory's own fields can never make a claim harness-implied, since the marker has no JSON form and an adapter must not read one from its input. `pkg/attack` refuses to mutate a trajectory holding one (`ErrImplied`), and `cmd/attack` drops them before mutating (`WithoutImplied`), so no generator produces an attacker-made one. What a harness-implied claim the adapter derived can absorb is one open, by the agent's own process, of exactly a file the named command opened, after that command opened it and inside the call's interval. An agent that read that file again in that window with an unreported tool call, for example a Read in the same parallel block, is not caught for it; the content is what the claimed command had already read. It can absorb no write, no rename or delete, no process and no connection, and no open of another path.
Consequences: No checked-in fixture carries a harness-implied claim (the adapter does not derive one in the commit that builds this), so every fixture gives byte-identical `cmd/verify` output, with and without a baseline, and the attack evaluation on the four checked-in fixtures is unchanged, Retime included. `cmd/verify` prints a count and a list only when a harness-implied claim exists. A trajectory converted to normalized JSON, by `cmd/attack` among others, carries none, so under `verify --normalized` a harness read after a Bash read command is Unrecorded, as before this decision.
Alternatives rejected: modelling the harness's record of file state in the adapter (every misprediction becomes an Unwitnessed finding, and the record holds files the transcript does not show it learned); a baseline rule (a rule names a path a control run touched, not a file a task's command read); dropping every level-0 open that follows a command's read of the same file without a claim (it would not be bounded by a call, its interval or its command); a marker with a JSON form, checked only by the adapter (an attacker writing normalized JSON would set it); letting a harness-implied claim pair with any open at substitution cost (it would turn an unrelated open into a Mismatched pair the agent never claimed).
