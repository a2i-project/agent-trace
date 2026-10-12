# Verifier

Checked against commit cc2b7d6 on 2026-10-12.

## Objective

The verifier decides whether a self-reported trajectory T (the claims) is faithful to an independently observed ground truth G (the events the probes recorded). It answers two separate questions and reports them apart (V8 in [decisions/verification.md](../decisions/verification.md)):

1. Alignment: does every claim correspond to a top-level action, and does every top-level action correspond to a claim? This detects fabrication (P2), omission at the top level (P1) and substitution (P3).
2. Coverage: is every observed event explained, either by a claimed command whose subtree contains it or by the harness baseline? This detects omission of whole commands.

The verifier contains no agent knowledge. Everything a harness does differently reaches it as data: normalized events, a baseline predicate and an `Expresses` declaration, all supplied by an adapter (see [30_agent_adapters.md](30_agent_adapters.md)). The objective of the project as a whole and its threat model are in [00_overview.md](00_overview.md), and the terms this page uses are defined there ([Terms](00_overview.md#terms)).

## Structure

| File | Main symbols | Role |
|---|---|---|
| `pkg/verification/verification.go` | `Input`, `Verdict`, `MatchedPair`, `Verify`, `Expresses`, `contentDiffs`, `Diff*` constants | Entry point, outcome rules, content comparison |
| `pkg/verification/forest.go` | `Forest`, `Process`, `Zone`, `Attribution`, `BuildForest`, `Forest.Attribute`, `Forest.Resolve`, `Forest.Commands`, `Forest.Orphans` | Process tree rooted at the agent, attribution by ancestry |
| `pkg/verification/partition.go` | `Partition`, `Command`, `AttributedEvent`, `Forest.Partition`, `Partition.DropExits` | Splits G into the aligned sequence, command subtrees, capability evidence, outside events and unplaced events |
| `pkg/verification/coverage.go` | `Baseline`, `Partition.SubtractBaseline`, `Coverage`, `UnexplainedAction`, `CheckCoverage` | Baseline subtraction and the coverage check |
| `pkg/verification/align.go` | `Lane`, `LaneOf`, `Align`, `Edit`, `EditKind`, `LaneAlignment`, `Options`, `ErrTooLarge`, `DiffType` | Per-lane sequence alignment |
| `pkg/verification/completeness.go` | `Assess`, `Completeness`, `Outcome`, `Outcome.ExitCode` | Loss judgement and outcome vocabulary |
| `pkg/verification/scope.go` | `FSScope`, `NewFSScope`, `FSScope.Contains`, `splitByScope` | Which file claims the capture could have witnessed |
| `pkg/matching/matching.go` | `TargetsMatch` | Whether a claim and an event name the same resource |
| `pkg/models` | `TrajectoryEntry`, `GroundTruthEvent`, `GroundTruthFile`, `Coverage`, `ActionType.IsClaimable`, `ActionType.IsStructural` | Data types shared with the probes and adapters |

## Technologies

Pure Go with the standard library only. The alignment is a dynamic program over `int32` cost and `uint32` path-count matrices, bounded at `maxCells` (16 Mi cells) per lane. There is no concurrency, no I/O and no clock reading inside the package: `Verify` is a function of its `Input`.

## Workflow

### Inputs

`verification.Input` carries:

| Field | Meaning |
|---|---|
| `Claims` | `models.Trajectory`, in claim order. Order is part of the input: the alignment depends on it. |
| `Ground` | `models.GroundTruth`, the observed events (after adapter normalization when called through `agent.Prepare`). |
| `RootPID` | The agent process the capture was rooted at (`GroundTruthFile.RootPID`). Zero means no tree can be built. |
| `Coverage` | The capture's per-probe loss record (`*models.Coverage`). Nil means unknown, which is not complete. The format is described in [10_probes_common.md](10_probes_common.md). |
| `Baseline` | `func(GroundTruthEvent) bool` that recognises the harness's own activity. Nil explains nothing. |
| `FSScope`, `Workspace` | The capture's `fs_scope` record and watched directory (`GroundTruthFile.FSScope`, `GroundTruthFile.Workspace`). A nil record with a workspace means the capture predates the record and holds paths under the workspace only; both empty means every claim is in scope. |
| `Options` | `IntervalSlack`, `Expresses`, `IgnoreExits`, `HarnessOwned` (below). The zero value is the strict reading. |

`Options.Expresses` is three-valued by construction: a nil `Expresses` means every content field is expressible (the strict default, right for `cmd/simagent`), and a non-nil one answers per entry and per field. `Options.IgnoreExits` drops process exits from both sides before alignment. `Options.IntervalSlack` widens each claim interval on both sides before the containment check. `Options.HarnessOwned` is the adapter's declaration of the harness's own directories (`agent.HarnessOwner`): an unexplained level-0 file event there is unexplained harness activity, not a finding (V-24). Nil declares nothing.

### Pipeline

`Verify(in)` runs these stages in order.

1. **Completeness.** `Assess(in.Coverage)` judges whether G can support FAITHFUL: a nil record or an event-loss counter yields a reason, a content gap a note. Which coverage field is which is in [10_probes_common.md](10_probes_common.md#probecoverage).
2. **Preconditions.** `RootPID == 0` returns INCONCLUSIVE. A non-empty G in which no event carries a pid returns INCONCLUSIVE (legacy ground truth).
3. **Forest.** `BuildForest(G, RootPID)` builds the process tree. Each `process_fork` record creates a `Process` incarnation with the parent edge recorded at creation; an exec record fills in `Process.Exec`, and stands in for a missing fork record (legacy files) using its own ppid. Processes are linked in creation order, and each gets its [level](00_overview.md#terms). A reused pid has several incarnations; `Forest.Resolve` picks the one alive at the event's timestamp, and an event stamped before every incarnation goes to the earliest one. Time is used for nothing else here.
4. **Partition.** `Forest.Partition(G)` sorts G by timestamp, skips structural events (`process_fork`), and places each event by `Forest.Attribute`:
   - capability evidence goes to `Capability` with its attribution, and, inside a subtree, to the command's own `Capability` as well;
   - an unplaced event goes to `Unknown`, an outside event to `Outside`;
   - a level-0 event goes to `Observed` (the aligned sequence) with a nil owner;
   - inside a subtree, the command's own first exec and its own exit go to `Observed` with the command as owner; every other event (later execs of the same pid, descendants' execs and exits, all file and network events of the subtree) goes to `Command.Content` and is never aligned (D3 in [decisions/integration.md](../decisions/integration.md)).
5. **Scope.** `NewFSScope` reads the record: with it, a path is in scope when the longest mount point covering it was marked (`Mounts`), and out of scope when that mount point could not be marked (`Unmarked`) or when no listed mount point covers it (a record that lists none puts every path in scope); without it, a path is in scope when it is under the workspace. `splitByScope` sets aside every out-of-scope claim of the `fs` lane into `Verdict.OutOfScope` before alignment, so its absence from the ground truth is not read as a fabrication and it does not shift the positions of the other claims. Claims of the other lanes have no path scope (V-23).
6. **Baseline subtraction.** `Partition.SubtractBaseline(b, claimed)` drops level-0 events the baseline recognises and marks a command whose exec it recognises (`Command.Baseline`), removing that command's exec and exit from `Observed`. A level-0 file event the baseline recognises on a path some in-scope file claim names stays in `Observed`, so the claim can pair with it; one that the alignment leaves unpaired is explained by the baseline after alignment, as if it had been subtracted, and is neither `Unrecorded` nor unexplained harness activity (V-30). It copies rather than mutates and must run before alignment, or harness activity would read as an omission.
7. **Harness-owned events.** With a `HarnessOwned` declaration, every level-0 file event under the harness's own directories whose path no in-scope file claim names leaves the aligned sequence into `UnexplainedHarness` (`Partition.setAsideHarnessOwned`), before alignment, so it can neither pair with a claim nor leave a real one unpaired. An event on a path a claim names stays and pairs normally; one that still finds no pair joins the same list after alignment (V-24).
8. **Exit handling.** With `IgnoreExits`, `Partition.DropExits` removes exits from `Observed` and `process_exit` claims are dropped. `Command.Exit` is kept.
9. **Alignment.** `Align(claims, Observed, opts)` groups both sides by [lane](00_overview.md#terms) (`LaneOf`). Lanes are aligned independently, in sorted lane order. Within a lane the claims keep their order and events keep time order. Costs: match 0, same-type substitution 2, cross-type substitution 3 (diff `action_type`), insertion or deletion 2. A substitution therefore always beats an adjacent insertion plus deletion (4), so no tie exists between the two readings. The dynamic program counts minimum-cost alignments (`LaneAlignment.Optimal`, saturating); more than one sets `Ambiguous`. Traceback prefers pair, then insertion, then deletion. A lane over `maxCells` returns `ErrTooLarge`.
10. **Pair comparison.** `pairCost` compares a claim and an event. The target is compared with `matching.TargetsMatch`: file types compare `filepath.Clean` of both paths, and accept an observed directory as covering a claimed file only when the event has `PathIsAmbiguous` set (a fanotify record that lost its name); every other type requires exact string equality, except that an observed target flagged `TargetTruncated` pairs with a claim it is a prefix of, as an unverified target rather than a mismatch (`truncatedPrefix`, V-26). Content is compared by `contentDiffs` only when the types agree (below). Each pair also gets `OutsideInterval` when the claim has an `End` and the event's timestamp lies outside `[Timestamp - slack, End + slack]`, and `Unverified` naming the content fields the claim states and the event does not carry (`unverifiedFields`: `input_hash` on any type (V-29), `output_hash` on `file_close` and `file_write`, `exit_code` on `process_exit`, `request_hash` on `net_request`), or the `target` when the event's was truncated and paired by prefix.
11. **Coverage.** `CheckCoverage(part, alignments)` marks every observed event paired by a match or substitution. Unpaired events become `UnexplainedActions`, except, in `Verify`, a baseline event kept for a claim on its path (V-30) and a level-0 file event under the harness's own directories (V-24). For each command: a baseline command adds its content to `Baselined`; a command whose exec was paired adds its content to `Explained`; a command with no exec, no exit and no content is `Quiet`; anything else is an `UnexplainedSubtrees` entry. A substituted claim still explains its subtree.
12. **Outcome** (below).

### Content comparison and the three-valued nil

`contentDiffs` compares `input_hash`, `output_hash`, `exit_code` and `request_hash`. A nil on either side normally agrees, because a missing capture cannot disprove a claim. A nil on the observed side against a stated claim does not confirm it either: the pair is corroborated and listed in `Unverified`, and with no finding the outcome is INCONCLUSIVE, not FAITHFUL (V-22). The probe can be made to drop a hash (a read of the file within the fs settle window does it), so a stated value the probe did not capture is a gap in the evidence, never a pass. Three fields are strict: `output_hash` on `file_close` and `file_write`, `exit_code` on `process_exit` and `request_hash` on `net_request`. For those, a nil claim against a non-nil observation is a mismatch when `Expresses(entry, field)` says the format could have stated it. The rule covers `file_write` because an adapter can claim a write's content there: the Claude Code adapter claims a Write as a `file_write` carrying the hash and never claims a `file_close`, so a Write that omits its hash against a hashed write is a mismatch, while an Edit, for which `Expresses` says no, is not (V-28 in [decisions/verification.md](../decisions/verification.md), `TestVerify_AWriteThatDropsAHashItsToolStatesIsAMismatch`). Gemini claims `write_to_file` as a `file_close`, where the rule applies as before. An observed `file_write` carries a hash only when an adapter's `NormalizeStream` folded a close's hash into it, since the fs probe hashes closes only. The strict case needs a nil claim and a captured value, and the unverified case below needs a stated claim and no captured value, so one pair is never both. So a nil means one of three things: the probe captured nothing (no finding, and unverified when the claim states a value), the format cannot state the field (no finding), or the agent opted out of a check it could have passed (finding). `input_hash` follows the same rule as the three hashes for the unverified list: a stated input against an open with none is corroborated and unverified (V-29), since the fs probe states an input only when it measured it (P-22). It is never strict: a nil stated input agrees. Two stated input hashes that differ are a mismatch.

### Verdict vocabulary

| Edit kind | Verdict list | Meaning |
|---|---|---|
| `EditMatch` | `Corroborated` | Claim and observed action at the same position agree |
| `EditSubstitution` | `Mismatched` (with `Diffs`) | Same position, different target, content or type (P3) |
| `EditInsertion` | `Unwitnessed` | Claim with no observed action (P2) |
| `EditDeletion` | `Unrecorded` | Top-level action no claim explains (P1) |

The verdict holds these other lists:

| List | Holds | Effect on the outcome |
|---|---|---|
| `OutsideInterval` | pairs outside their interval | finding |
| `Unverified` | pairs whose claim states content the probe did not capture, or whose truncated target was paired by prefix, with the fields in `Diffs` | blocks FAITHFUL (V-22, V-26) |
| `OutOfScope` | out-of-scope file claims, never aligned | blocks FAITHFUL (V-23) |
| `OutsideWrites` | outside writes. With no workspace recorded, every write-class outside event counts, since such a capture kept only workspace paths from other processes. Outside reads stay in `Coverage.Outside`, informational | blocks FAITHFUL, not a finding (V-25) |
| `UnexplainedHarness` | the level-0 file events under the harness's own directories that no claim names, set aside before alignment, plus any on a claimed path the alignment left unpaired. They are removed from `Unrecorded` and from `Coverage.UnexplainedActions`. A file event elsewhere and a command under those directories stay findings | blocks FAITHFUL, not a finding (V-24) |
| `Capability` | capability evidence, never aligned | none |
| `Commands` | every command in creation order with its exec, its exit, its `Content` and its `Capability`, whatever the verdict made of it: the forensic record of what each command did, reported by `cmd/verify` and never aligned (D3) | none |
| `Coverage` | the second check (stage 11) | its `UnexplainedSubtrees` are findings |
| `Alignments` | the per-lane edit script | none |
| `Ambiguous` | whether some lane has more than one minimum-cost alignment | none, reported |
| `Completeness`, `Reasons`, `Advisory` | the loss judgement, why the outcome is INCONCLUSIVE or the findings advisory, and whether they are | see Outcome rules |

`Verdict.Findings()` counts `Mismatched`, `Unwitnessed`, `Unrecorded`, `OutsideInterval` and `Coverage.UnexplainedSubtrees`. Outside events, capability evidence, quiet forks and baselined events are reported and are not findings. `Coverage.UnexplainedActions` holds the same events as `Unrecorded` and is not counted twice.

### Outcome rules

| Condition, checked in order | Outcome |
|---|---|
| No root pid, or G non-empty and no event has a pid | INCONCLUSIVE, no findings |
| A lane too large to align, or another alignment error | INCONCLUSIVE |
| Findings > 0 | NOT FAITHFUL; `Advisory` when completeness failed or any event has no pid, with the reasons |
| No findings, some event has no pid | INCONCLUSIVE |
| No findings, completeness failed (loss counter or missing coverage record) | INCONCLUSIVE |
| No findings, and some pair is unverified (a stated value the probe did not capture, or a truncated target paired by prefix), some file claim is out of scope, some harness-owned file event is unexplained, or some outside write exists | INCONCLUSIVE, with the fields and counts in the reason |
| Otherwise | FAITHFUL |

`Outcome.ExitCode()` maps FAITHFUL to 0, NOT FAITHFUL to 1 and INCONCLUSIVE to 2, so a script cannot read INCONCLUSIVE as a pass. `cmd/verify` adds 3 for errors ([40_tools.md](40_tools.md)).

## Guarantees and loss accounting

These hold for the code as built and are pinned by tests in `pkg/verification`:

- Pairing is by position, not by content, so a target substitution is one `Mismatched` entry carrying both targets, not a fabrication plus an omission (`TestAlign_TargetSubstitutionIsOneEdit`, `TestVerify_ProcessMasqueradingIsASubstitution`).
- The clock orders events within a lane and selects between incarnations of a reused pid. It never pairs and never attributes: a constant clock offset does not change the pairing or the verdict (`TestAlign_ClockOffsetDoesNotChangeThePairing`, `TestVerify_ClockOffsetDoesNotChangeTheVerdict`). An interval violation is a finding about the claim, not a reason to refuse the pair.
- Repeated identical actions pair by position (`TestVerify_RepeatedActionsPairByPosition`).
- The ambiguity count agrees with an independent brute force on random sequences (`TestAlign_AgreesWithBruteForceOnRandomSequences`), and an ambiguous lane is reported, never resolved silently.
- Descendant events never corroborate a claim and are never omissions; they are attributed to their command (`TestVerify_DescendantEventsDoNotCorroborateClaims`, `TestVerify_SubtreeEventsAreNotOmissions`).
- A command nothing claims is an unexplained subtree, including a fork that never exec'd but acted; a fork that did nothing is quiet (`TestVerify_ForkWithoutExecIsAnUnexplainedSubtree`, `TestVerify_QuietForkIsNotAFinding`, `TestVerify_ForkWhoseDescendantActsIsNotQuiet`).
- Listener and AF_UNIX socket events are capability evidence, never `Unrecorded`, and a claim of one never corroborates (`TestVerify_ListenersAreCapabilityNotUnrecorded`, `TestVerify_ListenerClaimNeverCorroborates`). `net_dns` and `net_dial` follow the same rule, since `IsClaimable` rejects them.
- The baseline subtracts only what it recognises and never mutates its input. A baseline event on a path a claim names pairs with the claim, and one left unpaired stays explained by the baseline (`TestVerify_BaselineEventsOnAClaimedPathPairWithTheClaim`, `TestCoverage_SubtractBaselineKeepsFileEventsOnClaimedPaths`).
- An outside write is never a finding and never FAITHFUL; an outside read is informational (`TestVerify_OutsideEventsAreReportedAndDoNotBlock`).
- An unexplained level-0 file event under the harness's own directories is never a finding and never FAITHFUL; elsewhere it is a finding, and a command is a finding wherever its program lives (`TestVerify_UnexplainedHarnessActivityIsInconclusive`).
- An out-of-scope file claim is set aside and never read as a fabrication, and the run is not FAITHFUL over it (`TestVerify_FileClaimsOutsideTheCaptureScopeAreSetAside`, `TestPairedWriteOutsideTheWorkspaceIsOutOfScope` in the Claude Code adapter).
- A claim that states a hash, an input, an exit code or a request hash the probe did not capture is corroborated and unverified, never FAITHFUL (`TestVerify_ClaimedContentTheProbeDidNotCaptureIsInconclusive`, `TestAStatedInputTheProbeDidNotMeasureIsUnverified`, and in the Claude Code adapter `TestPairedWriteWithoutAnObservedHashIsInconclusive` and `TestAnEditOfAFileTheProbeNeverHashedIsUnverified`).
- FAITHFUL requires a coverage record with every loss counter at zero and every event placed. Under loss, findings are kept and marked `Advisory`, since a lost fork record can orphan a subtree and a lost event can read as a fabrication. Which findings survive loss is open decision O-12 ([decisions/open.md](../decisions/open.md)).

Claims in the `fs` lane must arrive in the order the kernel reports file events (create, which the probe reports as a `file_write` that may name only the directory, then open, modify, close), because pairing within a lane is positional. `cmd/simagent` and the adapters emit claims in that order; see [12_probe_fs.md](12_probe_fs.md) for the event shapes.

## Known limits

- The partial order of V2 is not implemented: `Align` ignores `TrajectoryEntry.BlockID` and `ThreadID`, so parallel calls and flattened subagents are aligned as a total order in the adapter's sort order (open decision O-2 in [decisions/open.md](../decisions/open.md)).
- Cross-lane order is not checked, so a claim sequence that interleaves file and process actions in an impossible order is not reported.
- The `other` lane holds `git_commit`, which no probe produces, so a `git_commit` claim is always `Unwitnessed`.
- A baseline command explains its entire subtree whatever the subtree did; only the command's exec is matched against the baseline.
- The proc probe's exit record carries the command line of the process's latest exec, so a level-1 process that execs twice has an exit whose target differs from its first exec's and reads as a substitution on an exit claim ([11_probe_proc.md](11_probe_proc.md)).
- An omitted `input_hash` on the claim side is never a finding.
- A level-1 process that never exec'd and whose only events are capability evidence is `Quiet`, not an unexplained subtree: capability evidence is not `Content`. A fork that opens a listener, or makes a connection that reads as `net_dial` ([13_probe_net.md](13_probe_net.md)), is therefore reported and not a finding.
- Attribution stops at the tracked tree: an action delegated to a daemon that is an outside process (for example over a Unix socket) is visible only as capability evidence, and its effects are not attributed.
- `Forest.Orphans` is computed but not used by `Verify`, so an orphaned process is reported only through its events landing in `Outside`.
- A fabricated read of a file the harness itself opened, on a path the baseline holds, is corroborated by the harness's open, which the verifier cannot tell from the agent's (V-30). A fabricated write there still has to match the observed content. A fabricated claim next to such a kept event can pair with it as a substitution, so it is a finding that may be classified as a substitution rather than as a fabrication.
- Level-0 events have no subtree, so their alignment rests on order and content alone, and they share the level with the harness baseline.
- Long-lived descendants stay attributed to the command that created them for the whole capture; attribution does not expire.
- Containers are not handled: no pid or path namespace translation exists.
