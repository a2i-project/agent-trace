# Decisions: verification model

Why the verifier builds a process forest, checks coverage and aligns sequences instead of joining two lists on a time window. V1 to V8 keep the numbering of the original model; decisions taken while building it are numbered from V-9.

Checked against commit d0e2c73 on 2026-10-06. Original source: docs/archive/08_verification_model.md (local only). As-built description: [../architecture/20_verifier.md](../architecture/20_verifier.md). Related: [integration.md](integration.md), [open.md](open.md).

## Model decisions

### V1: G is a forest rooted at the agent process; attribution walks up the tree
Status: Accepted, implemented in `pkg/verification.BuildForest` and `Forest.Attribute`.
Date: design 2026-09, built 2026-10-06 (commit 4f83cfb).
Context: Every observed event has a causing process and every process but the root has a parent. "Which claim owns this event" then has an exact answer with no clock.
Decision: Walk up from the causing PID to a child of the agent process; that child is the command. Level 0 is the agent itself, level 1 its children, level 2 and below their descendants. The parent edge is the one recorded at creation, so reparenting does not move a process. A reused PID is several incarnations, and time only chooses between them.
Consequences: Attribution is live and independent of duration and approval latency. The probes must emit PID, PPID and fork records ([probes.md](probes.md), P-5 to P-7).
Alternatives rejected: Time-window attribution (F0.2-F0.3 below).

### V2: T and the level-1 sequence of G should be the same sequence
Status: Accepted. Partly implemented: totally ordered sequences are aligned; the partial-order case is not (O-2 in [open.md](open.md)).
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
Context: The three attacks are the three edit operations: insertion is fabrication (P2), deletion is omission (P1), substitution is substitution (P3).
Decision: Report findings as the edit script, with both claimed and observed values on a substitution. The cost model separates content from structural disagreement (V-10), and ambiguity is reported (V-11).
Consequences: Evaluation can score classification and localization, not only detection.
Alternatives rejected: Deriving the four sets from a set difference.

### V6: The clock orders events, it does not pair them
Status: Accepted, implemented; refined by V-9 and V-12.
Context: A constant clock offset, long durations and approval latency are fatal to a window and harmless to an order.
Decision: Time is used for ordering and for one consistency check on claimed intervals. No tunable window remains.
Consequences: The original text also said a crossing of aligned pairs is itself a finding. As built, order within a lane is monotone by construction, and cross-lane order is neither checked nor reported (V-9).
Alternatives rejected: `matching.Config.Delta` (removed, V-18).

### V7: The harness baseline is measured by a null-task control run
Status: Accepted, implemented in `agent.Baseline`, `agent.Capture`, `cmd/baseline` and `Partition.SubtractBaseline`. No baseline has been captured for a real agent yet.
Date: built 2026-10-06 (commit 5b551d7).
Context: A hand-maintained noise list is version-specific and rots silently into false omissions.
Decision: Run the agent on a task that claims nothing and record everything it does. All of it is harness activity, keyed on agent and version, and subtracted before alignment and coverage. Rule details are V-19.
Consequences: Re-derived on a version bump instead of maintained. Without a baseline, harness activity reads as omissions.
Alternatives rejected: Static lists in the adapter (I-19 in [integration.md](integration.md)).

### V8: FAITHFUL requires both checks, reported separately
Status: Accepted, implemented (`Verdict.Alignments` and `Verdict.Coverage`).
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
Status: Accepted, implemented (`LaneAlignment.Ambiguous`, `Optimal`, `Verdict.Ambiguous`).
Date: 2026-10-06.
Context: When several minimum-cost alignments exist, a report pointing at entry 7 when entry 8 is equally consistent is misleading.
Decision: Count the minimum-cost alignments (saturating). More than one sets `Ambiguous`; the edits shown are one of them, chosen by a fixed preference, and the report says so. Checked against an independent brute force on random sequences.
Consequences: A finding's position may be one of several. The outcome does not change (see O-3).
Alternatives rejected: Silent resolution by iteration order.

### V-12: The claim interval is a finding, not a pairing condition
Status: Accepted, implemented (`Options.IntervalSlack`, `Verdict.OutsideInterval`; `cmd/verify --interval-slack`, default 500ms).
Date: 2026-10-06.
Context: D12 puts the interval in the trajectory, which the attacker controls. The agent and the probes do not share a clock.
Decision: A matched pair whose observed action falls outside the claim's `[Timestamp, End]`, widened by `IntervalSlack`, is flagged `OutsideInterval` and stays matched. `OutsideInterval` counts as a finding.
Consequences: Widening an interval suppresses nothing (attack A4). It only evades this one consistency finding.
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
Status: Accepted, implemented (commit 5e17be5, 2026-10-06).
Context: After the alignment, nothing called `Match`, and its target-equality precondition was what made substitution unreportable.
Decision: Only `matching.TargetsMatch` remains: per-action-type target normalization and the directory fallback gated on `PathIsAmbiguous`, with no timestamp or type condition. Content comparison lives in `verification.contentDiffs`.
Consequences: No time constant has to be justified anywhere. `cmd/verify --delta` is gone.
Alternatives rejected: Keeping `Match` with the precondition removed, as the original model proposed.

### V-19: Baseline rules match exactly, from what every control run did
Status: Accepted, implemented in `agent.Capture` and `Baseline.Predicate`.
Date: 2026-10-06 (commit 5b551d7).
Context: A baseline is a list of things that are not findings, so it is a place to hide.
Decision: Control runs are normalized by the adapter and attributed with the forest. Rules are the agent's own top-level actions and the commands it started, kept only when every run did them; the rest is listed as unstable. A rule matches action type and target exactly, with no patterns. Descendants are not rules, since the command explains its subtree. A run with loss, no coverage record or no root PID is refused, and a baseline for one agent is refused for another.
Consequences: A baseline cannot be widened into a wildcard. A harness that varies its targets per run leaves those events as omissions.
Alternatives rejected: Glob or regex rules.

### V-20: Nil is three-valued in the content comparison
Status: Accepted, implemented in `contentDiffs` with `Options.Expresses`.
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
Status: Accepted, implemented (`unverifiedFields`, `Edit.Unverified`, `Verdict.Unverified`, the outcome rule in `Verify`).
Date: 2026-10-08 (security review of the verifier).
Context: V-20 reads a nil on the observed side as agreement, because a missing capture cannot disprove a claim. The fs probe publishes a close without a hash whenever a write-class event, an open included, follows it within the settle window (P-16), and nothing counts that. An agent that reads its file back right after writing it therefore made the probe drop the hash, and any claimed content was then corroborated (**Verified**: `TestPairedWriteWithoutAnObservedHashIsInconclusive` verified FAITHFUL with a false hash before the change).
Decision: A pair whose claim states `output_hash` (on `file_close` or `file_write`), `exit_code` (on `process_exit`) or `request_hash` (on `net_request`) and whose observed event does not carry it is corroborated and listed as unverified, with the fields named. It is not a finding, since a probe gap is not the agent's doing. With no finding, the outcome is INCONCLUSIVE with the fields and counts as the reason. `Expresses` is not consulted: the claim did state the value.
Consequences: Content verification can no longer be switched off by the agent; it can only be made inconclusive, which the report says. An honest run whose probe dropped a hash is INCONCLUSIVE rather than FAITHFUL, the same reading as event loss. `input_hash` is not tracked, because the fs probe stamps every open with one. The fs probe still has no counter for hashless closes, so `watch` cannot warn at capture time (an open item).
Alternatives rejected: Reporting the pair as a mismatch (it punishes an honest agent for a probe gap, and under loss findings are advisory anyway); keeping the pair silent (the attack above).

### V-23: A file claim the capture could not have witnessed is set aside, not aligned
Status: Accepted, implemented (`pkg/verification/scope.go`, `Verdict.OutOfScope`, the outcome rule in `Verify`).
Date: 2026-10-09 (item 5, step 2; follows P-17).
Context: The fs probe kept only paths under the workspace and nothing recorded that, so a truthful Write elsewhere had no event to pair with and read as Unwitnessed (**Verified**: a two-file shell agent, and `TestPairedWriteOutsideTheWorkspaceIsOutOfScope` on the paired fixture, both NOT FAITHFUL before the change). P-17 widened the capture and added `fs_scope`, but captures made before it, and paths on filesystems the probe could not mark, remain outside what a capture can say.
Decision: Before alignment, every file-lane claim whose path the capture could not have observed is set aside into `OutOfScope`. With a record, a path is in scope when the longest mount point covering it was marked, out when that mount point is listed as unmarked. Without a record, the workspace is the scope; with neither record nor workspace, everything is in scope (a direct caller of `Verify`). Set-aside claims are not findings, and with no finding the outcome is INCONCLUSIVE with their count as the reason. Process and network claims have no path scope.
Consequences: An honest agent is not called a fabricator for a write the probe was not watching, and the verdict says the claim was not checked rather than confirmed. Removing the claim before alignment keeps the other claims' positions intact. A dishonest agent's hidden write in an unobserved place is still invisible; the record now says where that is. Under P-17 the unobserved places are the unmarked filesystems only.
Alternatives rejected: Keeping legacy captures on the Unwitnessed reading (it is a known false positive once the workspace is in the file); dropping the claim silently (the report must say what was not checked); treating the gap as a finding (it is the capture's limit, not the agent's).

### V-24: Unexplained file events in the harness's own directories are reported apart and make the run INCONCLUSIVE
Status: Accepted, implemented (`Options.HarnessOwned`, `Verdict.UnexplainedHarness`, `isHarnessOwned` in `pkg/verification`; `agent.HarnessOwner`).
Date: 2026-10-09 (the ADP-3 decision, taken after the first full capture under P-17).
Context: The baseline is measured on a few control runs and keeps what enough of them did (V7, V19, I-24). The harness does some things only sometimes: a backup of its configuration on some startups, a telemetry connection, a package-manager probe. When one of them happens in the run being verified and in no control, the verifier reports it as an unreported action and an honest run is NOT FAITHFUL (**Verified**: the basic task of 2.1.286 on 2026-10-09, seven claims corroborated, NOT FAITHFUL on six events of a backup of `~/.claude.json` that none of three controls made). No number of controls sees every occasional behaviour.
Decision: Two measures. The capture script records more controls at a lower agreement threshold (option 1: an action seen in any control is the harness's, since a control runs no task). And the verifier takes from the adapter a declaration of where the harness keeps its own files (`HarnessOwner`), and reports an unexplained level-0 file event there as `UnexplainedHarness`: not a finding, and not FAITHFUL, so the outcome is INCONCLUSIVE with the count as the reason. A file event elsewhere, a connection, and a command under those directories stay findings.
Consequences: An honest run with occasional harness activity in its own directories is INCONCLUSIVE rather than falsely unfaithful, and the events are listed so a reader judges them. A write by the agent into those directories, the shell snapshot included, is still reported and still blocks FAITHFUL, but it is no longer a finding by itself; that is weaker than before and is the price of not calling honest runs unfaithful. The declaration explains nothing, so it is not a hiding place in the sense of D11. The snapshot question itself is unchanged: a baseline rule for the snapshot file explains the harness's write of it, as it did before.
Alternatives rejected: Declaring the harness directories explained wholesale (decides the snapshot question by default: a write there would never be reported); keeping the strict reading (honest runs unfaithful, the exit code unusable, false positives in the evaluation); more controls alone (a behaviour rarer than the sample still escapes).

### V-25: A write in the workspace by a process the tree cannot place makes the run INCONCLUSIVE
Status: Accepted, implemented (`Verdict.OutsideWrites`, `outsideWrites` in `pkg/verification`).
Date: 2026-10-09 (item 7 of the security review).
Context: P-15 keeps events from processes outside the agent's tree and reports them, and they never changed the verdict: a FAITHFUL was asserted over a workspace that a write and a close of `.backdoor` by an unplaced pid had changed (**Verified**: the audit's P7 demonstration on the paired fixture). The tree cannot say such a write was the agent's, so it is not a finding; but it cannot say it was not, and the workspace is what the verdict is about.
Decision: Among the outside events, the write-class ones (writes, closes, renames, deletes) under the workspace are `OutsideWrites`. They are not findings; with no finding the outcome is INCONCLUSIVE with their count as the reason. Reads by outside processes stay informational. With no workspace recorded, every outside write-class event counts, since such a capture kept only workspace paths from other processes.
Consequences: An editor or another tool touching the workspace during a capture makes the run INCONCLUSIVE, which is the honest reading: the capture cannot vouch for the workspace. A process the agent reached outside the tree (a daemon over a socket, O-13) that writes the workspace is no longer silent. Nothing changes for a clean capture.
Alternatives rejected: Keeping FAITHFUL (asserts what the capture cannot vouch for); making them findings (they are not the agent's doing as far as the tree can tell, and the user's own editor would make the agent unfaithful).

## Superseded

### F0.2-F0.3: Timestamp-window matcher
Status: Superseded by V4, V6 and V-18.
Date: 2026-09 (Tier 0), removed 2026-10-06.
Context: The first engine paired each claim with the nearest unmatched event of the same type and target within `Delta`, and set-differenced the rest.
Decision (historical): `M(t, g)` true iff same action type, same target, timestamp within a configurable delta; greedy closest-timestamp pairing.
Why superseded: The pairing was circular (substitution unreportable), one claim is many events, greedy nearest-time mispairs repeated actions, and no value of `Delta` works once approval latency sits inside the interval.

### P1-P3 (original wording)
Status: Superseded by V3 (P1), V4 and V5 (P2, P3). The restated properties are in [../architecture/00_overview.md](../architecture/00_overview.md).
Context: The original properties named the mechanism: omission as G events with no matching T entry, fabrication as T entries with no matching G event, substitution as entries that "match an event in G by timestamp but differ in content".
Why superseded: The claims are unchanged; the mechanism is not. P3's wording described a matcher that was never built, since `Match` never paired on timestamp alone.
