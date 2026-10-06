# Architecture Overview

Checked against commit d0e2c73 on 2026-10-06.

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
| T1 omission | the agent acted and did not report it | an unexplained subtree or level-0 event (coverage), or an unrecorded aligned position |
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

## Properties

| ID | Property | Mechanism |
|---|---|---|
| P1 | Omission detection | coverage check: an observed subtree or level-0 event that no claim and no baseline rule explains (V3) |
| P2 | Fabrication detection | insertion in the alignment of claims against the observed top-level sequence (V4, V5) |
| P3 | Substitution detection | substitution at an aligned position. Pairing by position, not by target equality, makes a changed target reportable (V4, V5) |
| P4 | Agent independence | verification uses host observations only. Adapters read the agent's own session files and require no change to the agent |
| P5 | Deterministic verdict | the verdict is a pure function of the trajectory, the ground truth, the baseline and the options. It has three outcomes, FAITHFUL, NOT FAITHFUL and INCONCLUSIVE, and no score |
| P6 | Composability | agent-trace provides recording-time faithfulness. Integrity of the stored record, anomaly detection and authorization are separate layers it composes with |
| P7 | Content-level verification | file content hashes, command lines as the kernel resolved them, and request body hashes for HTTP/1.x over a hookable TLS library. Coverage of content is partial and is reported per probe |

P5 originally said the verdict is binary. The code adds INCONCLUSIVE for a
capture that lost events or cannot be attributed, and reports an ambiguous
alignment without resolving it. The open decision is recorded in
[`../decisions/open.md`](../decisions/open.md).

## What a verdict does not prove

A FAITHFUL verdict says that the agent's top-level claims are true and that
nothing observable happened outside them and the harness baseline. It does not
say that what a claimed command did was benign. An agent that writes
`helper.sh` and runs it produces a faithful trajectory whatever the script
does. The report lists the command's subtree and its capability evidence
(listeners, Unix socket connections), and judging them is out of scope.

## Components

| Component | Code | Page |
|---|---|---|
| Probe contract, coverage record, ground truth file | `pkg/probe`, `pkg/models` | [10_probes_common.md](10_probes_common.md) |
| Process probe | `pkg/probe/proc` | [11_probe_proc.md](11_probe_proc.md) |
| Filesystem probe | `pkg/probe/fs`, `pkg/content` | [12_probe_fs.md](12_probe_fs.md) |
| Network probe | `pkg/probe/net`, `pkg/tlsoffset`, `pkg/tlsparse` | [13_probe_net.md](13_probe_net.md) |
| Verifier | `pkg/verification`, `pkg/matching` | [20_verifier.md](20_verifier.md) |
| Agent adapters and baseline | `pkg/agent` | [30_agent_adapters.md](30_agent_adapters.md) |
| Command-line tools | `cmd/watch`, `cmd/verify`, `cmd/baseline`, `cmd/simagent` | [40_tools.md](40_tools.md) |

## End-to-end workflow

1. **Record.** `watch` loads the requested probes, launches the agent (or
   attaches to `--root-pid`), and tracks its process tree in the kernel. When
   the agent exits it writes `ground_truth.json`: every observed event with the
   pid that caused it, a coverage record of what each probe may have lost, and
   the root pid.
2. **Read the claims.** An adapter reads the agent's native session file into
   an ordered list of claims, each with a time interval, and declares which
   fields its format can express. It also rewrites observed events into the
   form claims use (for example, it recovers the real command from a harness
   wrapper).
3. **Measure the harness.** `baseline` turns several control runs of a task
   that claims nothing into exact rules for what the harness does on its own,
   such as its model API connection.
4. **Verify.** `verify` builds the process forest from fork and exec records,
   attributes every event by ancestry, removes baseline events, aligns claims
   against the observed top-level sequence one lane at a time (files,
   processes, network), and checks that every observed event is explained.
5. **Conclude.** FAITHFUL (exit 0), NOT FAITHFUL (exit 1), INCONCLUSIVE
   (exit 2) or error (exit 3), with the edit script, the coverage report, the
   capability evidence and every limitation the adapter declared.

Three rules cut across all components:

* **Attribution is by process ancestry, never by time.** Whatever suppresses an
  event from the unexplained set is what an attacker attacks, and only a real
  causal link should suppress it.
* **Pair by position, compare by content.** Pairing must not depend on the
  field being verified.
* **Time orders events within a lane and never pairs them.** A claim interval is
  a constraint whose violation is a finding.

## Status

The probes, the verifier, the Claude Code and Gemini adapters, and the baseline
builder are implemented and tested against a simulated agent
(`cmd/simagent`) and against fixtures. No real agent session has yet been
captured and verified end to end, so the adapters' assumptions about which
kernel events a file tool produces remain hypotheses. Known limits of each
component are listed on its page.
