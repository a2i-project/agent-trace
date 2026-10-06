# Verifier

Checked against commit d0e2c73 on 2026-10-06.

## Objective

The verifier decides whether a self-reported trajectory T (the claims) is faithful to an independently observed ground truth G (the events the probes recorded). It answers two separate questions and reports them apart (V8 in [decisions/verification.md](../decisions/verification.md)):

1. Alignment: does every claim correspond to an observed top-level action, and does every observed top-level action correspond to a claim? This detects fabrication (P2), omission at the top level (P1) and substitution (P3).
2. Coverage: is every observed event explained, either by a claimed command whose subtree contains it or by the harness baseline? This detects omission of whole commands.

The verifier contains no agent knowledge. Everything a harness does differently reaches it as data: normalized events, a baseline predicate and an `Expresses` declaration, all supplied by an adapter (see [30_agent_adapters.md](30_agent_adapters.md)). The objective of the project as a whole and its threat model are in [00_overview.md](00_overview.md).

## Structure

| File | Main symbols | Role |
|---|---|---|
| `pkg/verification/verification.go` | `Input`, `Verdict`, `MatchedPair`, `Verify`, `Expresses`, `contentDiffs`, `Diff*` constants | Entry point, outcome rules, content comparison |
| `pkg/verification/forest.go` | `Forest`, `Process`, `Zone`, `Attribution`, `BuildForest`, `Forest.Attribute`, `Forest.Resolve`, `Forest.Commands`, `Forest.Orphans` | Process tree rooted at the agent, attribution by ancestry |
| `pkg/verification/partition.go` | `Partition`, `Command`, `AttributedEvent`, `Forest.Partition`, `Partition.DropExits` | Splits G into the aligned sequence, command subtrees, capability, outside and unknown |
| `pkg/verification/coverage.go` | `Baseline`, `Partition.SubtractBaseline`, `Coverage`, `UnexplainedAction`, `CheckCoverage` | Baseline subtraction and the coverage check |
| `pkg/verification/align.go` | `Lane`, `LaneOf`, `Align`, `Edit`, `EditKind`, `LaneAlignment`, `Options`, `ErrTooLarge`, `DiffType` | Per-lane sequence alignment |
| `pkg/verification/completeness.go` | `Assess`, `Completeness`, `Outcome`, `Outcome.ExitCode` | Loss judgement and outcome vocabulary |
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
| `Options` | `IntervalSlack`, `Expresses`, `IgnoreExits` (below). The zero value is the strict reading. |

`Options.Expresses` is three-valued by construction: a nil `Expresses` means every content field is expressible (the strict default, right for `cmd/simagent`), and a non-nil one answers per entry and per field. `Options.IgnoreExits` drops process exits from both sides before alignment. `Options.IntervalSlack` widens each claim interval on both sides before the containment check.

### Pipeline

`Verify(in)` runs these stages in order.

1. **Completeness.** `Assess(in.Coverage)` judges whether G can support FAITHFUL. A nil record yields a reason. For each probe that ran, a non-zero `RingbufDrops`, `UntrackedChildren`, `StateMapFull` or `ChannelDrops`, or a `QueueOverflow`, yields a reason. `FaultedReads` and `Content == attach_failed` yield notes only: they limit content checks, not the event set.
2. **Preconditions.** `RootPID == 0` returns INCONCLUSIVE. A non-empty G in which no event carries a pid returns INCONCLUSIVE (legacy ground truth).
3. **Forest.** `BuildForest(G, RootPID)` builds the process tree. Each `process_fork` record creates a `Process` incarnation with the parent edge recorded at creation; an exec record fills in `Process.Exec`, and stands in for a missing fork record (legacy files) using its own ppid. Processes are linked in creation order: level 0 is the agent, level 1 a child of the agent (the root of one command), level 2 and below its descendants, and -1 a process whose chain does not reach the agent. A reused pid has several incarnations; `Forest.Resolve` picks the one alive at the event's timestamp, and an event stamped before every incarnation goes to the earliest one. Time is used for nothing else here.
4. **Partition.** `Forest.Partition(G)` sorts G by timestamp, skips structural events (`process_fork`), and places each event by `Forest.Attribute`:
   - unclaimable types (`net_bind`, `net_listen`, `net_unix_connect`) go to `Capability` with their attribution;
   - no pid goes to `Unknown`; a process outside the tree goes to `Outside`;
   - a level-0 event goes to `Observed` (the aligned sequence) with a nil owner;
   - inside a subtree, the command's own first exec and its own exit go to `Observed` with the command as owner; every other event (later execs of the same pid, descendants' execs and exits, all file and network events of the subtree) goes to `Command.Content` and is never aligned (D3 in [decisions/integration.md](../decisions/integration.md)).
5. **Baseline subtraction.** `Partition.SubtractBaseline(b)` drops level-0 events the baseline recognises and marks a command whose exec it recognises (`Command.Baseline`), removing that command's exec and exit from `Observed`. It copies rather than mutates and must run before alignment, or harness activity would read as an omission.
6. **Exit handling.** With `IgnoreExits`, `Partition.DropExits` removes exits from `Observed` and `process_exit` claims are dropped. `Command.Exit` is kept.
7. **Alignment.** `Align(claims, Observed, opts)` groups both sides by lane (`LaneOf`): `fs` (file types), `proc` (`process_exec`, `process_exit`), `net` (`net_request`, `net_dns`, `net_connect`), and `other`. Lanes are aligned independently, in sorted lane order. Within a lane the claims keep their order and events keep time order. Costs: match 0, same-type substitution 2, cross-type substitution 3 (diff `action_type`), insertion or deletion 2. A substitution therefore always beats an adjacent insertion plus deletion (4), so no tie exists between the two readings. The dynamic program counts minimum-cost alignments (`LaneAlignment.Optimal`, saturating); more than one sets `Ambiguous`. Traceback prefers pair, then insertion, then deletion. A lane over `maxCells` returns `ErrTooLarge`.
8. **Pair comparison.** `pairCost` compares a claim and an event. The target is compared with `matching.TargetsMatch`: file types compare `filepath.Clean` of both paths, and accept an observed directory as covering a claimed file only when the event has `PathIsAmbiguous` set (a fanotify record that lost its name); every other type requires exact string equality. Content is compared by `contentDiffs` only when the types agree (below). Each pair also gets `OutsideInterval` when the claim has an `End` and the event's timestamp lies outside `[Timestamp - slack, End + slack]`.
9. **Coverage.** `CheckCoverage(part, alignments)` marks every observed event paired by a match or substitution. Unpaired events become `UnexplainedActions`. For each command: a baseline command adds its content to `Baselined`; a command whose exec was paired adds its content to `Explained`; a command with no exec, no exit and no content is `Quiet`; anything else is an `UnexplainedSubtrees` entry. A substituted claim still explains its subtree.
10. **Outcome** (below).

### Content comparison and the three-valued nil

`contentDiffs` compares `input_hash`, `output_hash`, `exit_code` and `request_hash`. A nil on either side normally agrees, because a missing capture cannot disprove a claim. Three fields are strict: `output_hash` on `file_close`, `exit_code` on `process_exit` and `request_hash` on `net_request`. For those, a nil claim against a non-nil observation is a mismatch when `Expresses(entry, field)` says the format could have stated it. So a nil means one of three things: the probe captured nothing (benefit of the doubt), the format cannot state the field (no finding), or the agent opted out of a check it could have passed (finding). `input_hash` stays permissive in all cases.

### Verdict vocabulary

| Edit kind | Verdict list | Meaning |
|---|---|---|
| `EditMatch` | `Corroborated` | Claim and observed action at the same position agree |
| `EditSubstitution` | `Mismatched` (with `Diffs`) | Same position, different target, content or type (P3) |
| `EditInsertion` | `Unwitnessed` | Claim with no observed action (P2) |
| `EditDeletion` | `Unrecorded` | Observed top-level action no claim explains (P1) |

Further lists: `OutsideInterval` (pairs outside their claim interval), `Capability` (unclaimable events, never aligned), `Coverage` (the second check), `Alignments` (the per-lane edit script), `Ambiguous`, `Completeness`, `Reasons`, `Advisory`.

`Verdict.Findings()` counts `Mismatched`, `Unwitnessed`, `Unrecorded`, `OutsideInterval` and `Coverage.UnexplainedSubtrees`. Outside events, capability events, quiet forks and baselined events are reported and are not findings. `Coverage.UnexplainedActions` holds the same events as `Unrecorded` and is not counted twice.

### Outcome rules

| Condition, checked in order | Outcome |
|---|---|
| No root pid, or G non-empty and no event has a pid | INCONCLUSIVE, no findings |
| A lane too large to align, or another alignment error | INCONCLUSIVE |
| Findings > 0 | NOT FAITHFUL; `Advisory` when completeness failed or any event has no pid, with the reasons |
| No findings, some event has no pid | INCONCLUSIVE |
| No findings, completeness failed (loss counter or missing coverage record) | INCONCLUSIVE |
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
- Listener and AF_UNIX socket events are capability evidence, never `Unrecorded`, and a claim of one never corroborates (`TestVerify_ListenersAreCapabilityNotUnrecorded`, `TestVerify_ListenerClaimNeverCorroborates`).
- The baseline subtracts only what it recognises and never mutates its input.
- FAITHFUL requires a coverage record with every loss counter at zero and every event placed. Under loss, findings are kept and marked `Advisory`, since a lost fork record can orphan a subtree and a lost event can read as a fabrication. Which findings survive loss is an open question ([decisions/open.md](../decisions/open.md)).

Claims in the `fs` lane must arrive in the order the kernel reports file events (create as a directory-level record, open, modify, close), because pairing within a lane is positional. `cmd/simagent` and the adapters emit claims in that order; see [12_probe_fs.md](12_probe_fs.md) for the event shapes.

## Known limits

- The partial order of V2 is not implemented: `Align` ignores `TrajectoryEntry.BlockID` and `ThreadID`, so parallel calls and flattened subagents are aligned as a total order in the adapter's sort order.
- Cross-lane order is not checked, so a claim sequence that interleaves file and process actions in an impossible order is not reported.
- The `other` lane holds `git_commit`, which no probe produces, so a `git_commit` claim is always `Unwitnessed`.
- A baseline command explains its entire subtree whatever the subtree did; only the command's exec is matched against the baseline.
- The proc probe's exit record carries the command line of the process's latest exec, so a level-1 process that execs twice has an exit whose target differs from its first exec's and reads as a substitution on an exit claim ([11_probe_proc.md](11_probe_proc.md)).
- `input_hash` is compared permissively in every case, so an omitted input hash is never a finding.
- Attribution stops at the tracked tree: an action delegated to a daemon outside it (for example over a Unix socket) is visible only as capability evidence, and its effects are not attributed.
- `Forest.Orphans` is computed but not used by `Verify`, so an orphaned process is reported only through its events landing in `Outside`.
- Level-0 actions have no subtree, so their alignment rests on order and content alone, and they share the level with the harness baseline.
- Long-lived descendants stay attributed to the command that created them for the whole capture; attribution does not expire.
- Containers are not handled: no pid or path namespace translation exists.
