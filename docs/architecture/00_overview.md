# Architecture Overview

Checked against commit d223e7d on 2026-10-28.

This page states what agent-trace is for, the threat model it assumes, the
properties it claims, and how its components fit together. Each component has
its own page in this folder. The reasons behind each design choice are in
[`../decisions/`](../decisions/).

## Objective

An AI agent reports what it did in a trajectory log. A compromised, confused or
dishonest agent can write a log that differs from what it did. Agent-trace
checks a trajectory against ground truth recorded on the host by kernel probes
that run independently of the agent, and returns a verdict on whether the
trajectory is faithful.

The project addresses threat model TM-A from
[`../related_work/01_threat_models.md`](../related_work/01_threat_models.md):
the operator controls the host and does not trust its own agent. The attacks it
detects target the trajectory, not the host:

| Attack | Meaning | Detected as |
|---|---|---|
| T1 omission | the agent acted and did not report it | an unexplained subtree or level-0 event (coverage), or an unrecorded top-level action |
| T2 fabrication | the agent reported an action it never performed | an insertion in the alignment |
| T3 substitution | the agent reported A and performed B | a substitution at an aligned position, in target or in content |

## Assumptions

* **AS-1, observable boundary.** Every security-relevant action crosses a
  kernel boundary that a probe can observe: a file operation, a process
  creation, or a socket operation.
* **AS-2, no evasion.** The agent misreports its trajectory but does not detect
  or subvert the recorder. An evasion-aware agent is out of scope
  ([`../decisions/network.md`](../decisions/network.md)).
* **AS-3, trusted host.** The host kernel and the probes form the trust
  boundary. An attacker with root on the host can defeat them.
* **AS-4, local execution.** The agent runs on a host the operator controls.
  Agents executed on vendor infrastructure are out of scope.

## Terms

Every architecture page uses these terms in the sense given here, each named
after its code identifier. Identifiers without a package are in
`pkg/verification`.

| Term | Meaning | Code |
|---|---|---|
| claim | one action the agent's trajectory (T) reports, as an adapter produced it | `models.TrajectoryEntry` |
| observed event | one event a probe recorded; the ground truth (G) is the list of them | `models.GroundTruthEvent` |
| capture | the file `watch` writes: the observed events, the coverage record, the root pid, the workspace, the fs scope record and the snapshot of the harness's sensitive files | `models.GroundTruthFile` |
| fs scope record, scope rule | the capture's `fs_scope`: which filesystems the fs probe marked and which rule `watch` applied to file events ([10_probes_common.md](10_probes_common.md#ground_truthjson)) | `models.FSScope` |
| level | a process's depth in the agent's process tree: level 0 is the agent process, level 1 a command it started, level 2 and below that command's descendants, -1 a process whose chain does not reach the agent | `Process.Level` |
| command | a level-1 process with everything beneath it (its subtree) | `Command` |
| zone | where an observed event sits, by the level of the process that caused it: `ZoneAgent` (level 0), `ZoneSubtree` (level 1 and below), `ZoneOutside` (level -1, or a pid the tree never recorded), `ZoneUnknown` (no pid) | `Zone`, `Attribution` |
| outside process, outside event | a process the agent's tree does not reach, and an event it caused (`ZoneOutside`) | `Partition.Outside`, `Coverage.Outside` |
| unplaced event | an observed event with no pid (`ZoneUnknown`) | `Partition.Unknown`, `Coverage.Unknown` |
| aligned sequence | the observed events claims are aligned against: level-0 events and each command's own first exec and exit, in time order | `Partition.Observed` |
| top-level action | one event of the aligned sequence | an element of `Partition.Observed` |
| lane | a group of action types aligned on its own: `fs` (the file types), `proc` (`process_exec`, `process_exit`), `net` (`net_request`, `net_connect`, `net_dns`), `other` (every other type; of the claimable ones only `git_commit`, which is set aside before alignment, V-47) | `Lane`, `LaneOf` |
| capability evidence | observed events of the unclaimable types `net_bind`, `net_listen`, `net_unix_connect`, `net_dns`, `net_dial` and `net_response`: listeners, Unix socket connections, connections to port 53, connections that sent nothing and responses read over TLS. Reported, never aligned, never a finding | `Verdict.Capability`, `Command.Capability`, `models.ActionType.IsClaimable` |
| structural event | `process_fork`: builds the tree, neither aligned nor counted as capability evidence | `models.ActionType.IsStructural` |
| outside write | a write-class file event (`file_write`, `file_close`, `file_rename`, `file_delete`) under the workspace by an outside process | `Verdict.OutsideWrites` |
| outside its interval | a pair whose claim has an end and whose observed event lies outside the claim's interval widened by the slack | `Verdict.OutsideInterval` |
| outside the workspace | a path not under the directory the capture watched | `models.GroundTruthFile.Workspace` |
| out of scope | a file claim on a path the capture could not observe, by its fs scope record | `Verdict.OutOfScope`, `FSScope` |
| out of capture | a claim of a type no probe observes (`git_commit`) | `Verdict.OutOfCapture` |
| dropped by the scope rule | a file event `watch` left out of the capture: caused by no process of the agent's tree, on a path outside the workspace | `models.FSScope.DroppedOutside` |
| finding | a discrepancy counted against the agent: a mismatched pair, an unwitnessed claim, an unrecorded top-level action, a pair outside its interval, an unexplained subtree, or an unexplained change to a sensitive file of the harness | `Verdict.Findings` |
| outcome | the conclusion of a run: FAITHFUL, NOT FAITHFUL or INCONCLUSIVE | `Outcome` |
| verdict | the whole result of a run: the outcome, the finding lists, the coverage check, the commands and the reasons | `Verdict` |

`net_dns` belongs to the `net` lane but, being unclaimable, never reaches the
alignment. "Level" describes a process and "zone" the placement of an event;
a level-0 event is one caused by the agent process.

## Properties

| ID | Property | Mechanism |
|---|---|---|
| P1 | Omission detection | coverage check: an observed subtree or level-0 event that no claim and no baseline rule explains (V3) |
| P2 | Fabrication detection | insertion in the alignment of claims against the aligned sequence (V4, V5) |
| P3 | Substitution detection | substitution at an aligned position. Pairing by position, not by target equality, makes a changed target reportable (V4, V5) |
| P4 | Agent independence | verification uses host observations only. Adapters read the agent's own session files and require no change to the agent |
| P5 | Deterministic verdict | the verdict is a pure function of the trajectory, the ground truth, the baseline and the options. It has three outcomes, FAITHFUL, NOT FAITHFUL and INCONCLUSIVE, and no score |
| P6 | Composability | agent-trace provides recording-time faithfulness. Integrity of the stored record, anomaly detection and authorization are separate layers it composes with |
| P7 | Content-level verification | file content hashes, command lines as the process passed them to the kernel, and request body hashes for HTTP/1.x over a hookable TLS library. Coverage of content is partial and is reported per probe |

P5 is worded as restated in V-27
([`../decisions/verification.md`](../decisions/verification.md)).

## What a verdict does not prove

A FAITHFUL outcome says that the agent's claims are true and that
nothing observable happened that they and the harness baseline do not explain. It does not
say that what a claimed command did was benign. An agent that writes
`helper.sh` and runs it produces a faithful trajectory whatever the script
does. The report lists the command's subtree and its
[capability evidence](#terms), and judging them is out of scope.

## Components

| Component | Code | Page |
|---|---|---|
| Probe contract, coverage record, ground truth file | `pkg/probe`, `pkg/models` | [10_probes_common.md](10_probes_common.md) |
| Process probe | `pkg/probe/proc` | [11_probe_proc.md](11_probe_proc.md) |
| Filesystem probe | `pkg/probe/fs`, `pkg/content` | [12_probe_fs.md](12_probe_fs.md) |
| Network probe | `pkg/probe/net`, `pkg/tlsoffset`, `pkg/tlsparse` | [13_probe_net.md](13_probe_net.md) |
| Verifier | `pkg/verification`, `pkg/matching` | [20_verifier.md](20_verifier.md) |
| Agent adapters, baseline and configured agent versions | `pkg/agent`, `pkg/config`, `config/agents.json` | [30_agent_adapters.md](30_agent_adapters.md) |
| Command-line tools | `cmd/watch`, `cmd/verify`, `cmd/baseline`, `cmd/status`, `cmd/attack`, `cmd/simagent`, `cmd/analyze` | [40_tools.md](40_tools.md) |
| Attack generators and scoring | `pkg/attack`, `cmd/attack` | [50_attack_generators.md](50_attack_generators.md) |

## End-to-end workflow

1. **Record.** `watch` loads the requested probes, launches the agent (or
   attaches to `--root-pid`), and tracks its process tree in the kernel. When
   the agent exits it writes `ground_truth.json`: every observed event with the
   pid that caused it, a coverage record of what each probe may have lost, the
   root pid, the fs scope record and the snapshot of the harness's sensitive
   files.
2. **Read the claims.** An adapter reads the agent's native session file into
   an ordered list of claims, each with a time interval, and declares which
   fields its format can express. It also rewrites observed events into the
   form claims use (for example, it recovers the real command from a harness
   wrapper).
3. **Measure the harness.** `baseline` turns several control runs of a task
   that claims nothing into exact rules for what the harness does on its own,
   such as its model API connection.
4. **Verify.** `verify` builds the process forest from fork and exec records,
   attributes every event by ancestry, removes baseline events, sets aside
   out-of-scope file claims and claims no probe observes, aligns the other claims against the aligned
   sequence one lane at a time (`fs`, `proc`, `net`, `other`), and checks that
   every observed event is explained.
5. **Conclude.** `verify` prints the verdict: the outcome, the edit script,
   the coverage report, the capability evidence and every limitation the
   adapter declared. The rules that decide the outcome are in
   [20_verifier.md](20_verifier.md#outcome-rules), and the exit codes in
   [40_tools.md](40_tools.md#verify).

Three rules cut across all components:

* **Attribution is by process ancestry, never by time.** Whatever suppresses an
  event from the unexplained set is what an attacker attacks, and only a real
  causal link should suppress it.
* **Pair by position, compare by content.** Pairing must not depend on the
  field being verified.
* **Time orders events within a lane and never decides a pairing on content.** A
  claim interval is a constraint whose violation is a finding; among pairings of
  equal content cost it only chooses the one with the fewest violations (V-31).

## Status

The probes, the verifier, the Claude Code and Gemini adapters, the baseline
builder and the attack generators are implemented and tested against a
simulated agent (`cmd/simagent`) and against fixtures. Paired captures of real
Claude Code sessions and two of Gemini (agy 1.3.4) are checked in; each one,
its agent version and its outcome are listed in
[30_agent_adapters.md](30_agent_adapters.md#objective). Two fixtures, both Claude Code captures, were recorded with the filesystem
probe's entry names (P-25); otherwise those shapes are checked by the probe's
and end-to-end tests. Still
unchecked: Gemini beyond those two tasks, Claude Code versions other than
those captured, tools and shapes the captures do not exercise (listed in
[30_agent_adapters.md](30_agent_adapters.md#known-limits)), and any population
of real sessions. Known limits of each component are listed on its page.
