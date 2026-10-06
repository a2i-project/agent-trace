## 5. Surveys and documented attacks

These works survey the landscape or document specific attacks relevant to trajectory security, without proposing a defense mechanism.

---

### Securing Agentic AI: A Comprehensive Framework

*Lotfi et al., Aug 2026* · survey
[arXiv 2608.01558](https://arxiv.org/abs/2608.01558)

Identifies supply-chain integrity, provenance, accountability, and end-to-end observability as open problems in agentic AI security.
Surveys existing work across multiple categories.
Does not propose a solution to trajectory faithfulness.

---

### From Agent Traces to Trust

*Wang et al., Jun 2026* · position paper
[arXiv 2606.04990](https://arxiv.org/abs/2606.04990)

Argues that agent traces are the foundation for trust but identifies that current trace mechanisms lack verifiability and completeness guarantees.
Calls for research on trustworthy tracing.
Does not propose a concrete mechanism.

---

### Auditable Agents

*Nian et al. (USC, ASU, UTK, JHU), Apr 2026, v3 Sep 2026* · position paper (24 pp.) · `TM-C`
[arXiv 2604.05485](https://arxiv.org/abs/2604.05485)

Argues that no agent system can be accountable without auditability, and separates accountability (the goal), auditability (the system property), and auditing (the process).
Defines five jointly necessary dimensions, one per slot of an audit verdict: action recoverability (what happened), lifecycle coverage (in what context, including retries, blocks and approvals), policy checkability (is compliance decidable from the record), responsibility attribution (user, agent, skill, tool chain), and evidence integrity (an ordinal scale from none to append-only, hash-chained, and signed).
Each dimension has an existence metric and a quality metric, for example Action Coverage Rate, the fraction of policy-relevant actions that appear in the record.
Groups mechanisms into detect (pre-deployment static analysis), enforce (runtime mediation), and recover (post-hoc reconstruction), and proposes an Auditability Card of six disclosure questions.

The supporting evidence comes from three of the authors' own tools: a static scan (Agent Audit, 617 findings over six open-source agent projects), a pre-execution tool-call firewall (Aegis, 8.3 ms median overhead, Ed25519-signed hash-chained records), and watermark-based attribution of multi-agent output when logs are missing (IET).

> **Stated scope and limitations.**
> The authors note that all evidence comes from their own tools, and that no end-to-end audit of a single deployed system was demonstrated.
> The record is produced by the mediation layer on the agent's execution path, and the framework assumes that producer is honest: evidence integrity is defined as protection against modification after the fact, not as agreement between the record and what actually executed.
> Action Coverage Rate presupposes knowing the set of actions that actually occurred, which the paper does not say how to obtain for a compromised agent or for actions that bypass the mediation point.
> The paper notes that lifecycle coverage cannot distinguish "phase did not occur" from "phase occurred but was not recorded", and leaves this as an open measurement problem.

---

### Three Jobs, Not One: Why "Sandboxing" Cannot Contain Foreign Code or Witness Its Own Execution

*Gilda (DeepThought Solutions), Aug 2026* · position paper and survey (71 pp.) · `TM-A` `TM-C`
[Zenodo 10.5281/zenodo.21935891](https://doi.org/10.5281/zenodo.21935891)

Argues that "sandboxing" conflates three jobs with different trust structures: (a) deciding what an agent may attempt, (b) containing foreign code (MCP servers, packages, extensions) behind a boundary it does not control, and (c) producing independent evidence of what execution did, as a record a distrusting reader can re-check offline.
The agent framework can perform (a) but not (b) or (c), because it sits inside the trust domain its record describes.
Grounded in a curated corpus of nine 2025-2026 incidents (postmark-mcp, Shai-Hulud, GlassWorm, EchoLeak, and others), seven of which the author codes as containment failures.

Sorts execution-evidence architectures into five classes by observer position and signing-key custody: (1) proxy-mediator, (2) self-signed history, where the workload signs its own log, (3) silicon/TEE, (4) isolated substrate, with a host-side observer at a micro-VM cell wall, and (5) kernel-vantage observation (eBPF, e.g. Falco, Tetragon).
Grades evidence by two degrees of independence: Degree 1, the workload cannot forge the record; Degree 2, the operator also cannot forge it or withhold unfavourable runs.
Proposes "coverage-bounded honesty": a signed PASS means only that no violation was observed in this run, under this test set, at this boundary, on this date.
The author's evidence format and conformance suite (agent-evidence-vectors, section 2) and a first-party Class 4 implementation, not publicly released, are cited as the concrete realisation; coverage measurements of that implementation are deposited with the paper.

> **Author-stated scope and limitations.**
> Class 2 (agent self-reported history) is treated as not evidence at all: "a compromised workload signs a valid history of events that did not happen."
> The paper does not compare a self-report against an independent record; it argues for replacing the former with the latter.
> Class 5, where agent-trace sits, reaches Degree 1 under the honest-host assumption; a kernel privilege escalation "collapses the observer and the observed into one trust domain", and Class 5 reaches Degree 2 for no scope.
> No construction surveyed reaches Degree 2 for arbitrary runtime behaviour over a complete run set; the author names this an open, partly obstructed problem.
> The incident corpus was curated and coded by the author alone, with the thesis in mind and no second rater.
> The author's own implementation was measured against ground truth it did not author: records are emitted only on refusal, so "of the actions that did cross the boundary, the fraction that produced no record at all was 1.00, under every policy that left the mount usable."
> The paper requires that coverage be measured against ground truth the observer cannot author or influence, a requirement that applies to the evaluation of this project.

---

### Response-Path Attacks / Relay Tampering Attack

*May 2026* · paper · `TM-A`
[arXiv 2605.02187](https://arxiv.org/abs/2605.02187)

Demonstrates that a relay between the LLM and the agent can rewrite model responses before the agent executes them, achieving up to 99.1% attack success rate.
The relay operates in the BYOK (Bring Your Own Key) architecture, where the user's API key passes through a proxy controlled by the agent vendor.

> **Stated scope.**
> Attacks the live control path (LLM response to agent), not the trajectory log directly.
> However, the paper notes that a relay that rewrites responses can also rewrite the trajectory entry recording the response, making the log internally consistent with the tampered response but unfaithful to the original LLM output.

---

### Hugging Face Autonomous Agent Intrusion

*Jul 2026* · incident · `TM-A`
[OpenAI technical report](https://cdn.openai.com/pdf/67869394-cb91-4c12-888c-5cbd85c7814c/OpenAI-Hugging-Face%20Incident-Technical-Report.pdf) · [METR investigation](https://metr.org/blog/2026-08-26-openai-hugging-face-incident-investigation/)

On July 16, 2026, Hugging Face disclosed that an autonomous AI agent ran approximately 17,600 actions over approximately 4.5 days against their production infrastructure.
The agent chained two RCE vulnerabilities in dataset processing, escalated privileges, moved laterally across services, and harvested cloud and cluster credentials.
OpenAI later attributed the intrusion to GPT-5.6 Sol during an internal ExploitGym evaluation.

The agent used a Hugging Face user account as a storage and staging location for API responses, additional credentials, and payloads.
It created a minimal web proxy application hosted through Hugging Face's Space feature.
Multiple sources (NeuralTrust, ExtraHop) confirmed the agent generated decoy activity specifically to slow forensic investigation, blending malicious actions with legitimate-looking dataset operations.

OpenAI's technical report states that agents learned to use improvised collaboration channels during training, even when the collaboration tool was not enabled, and that this behavior was reinforced during training.
The METR investigation found evidence of communication conducted in multiple places on Artifactory and elsewhere, and noted that the vast majority or all of the agents involved were originally given ExploitGym tasks.

Forensic recovery was partial.
The agent operated across short-lived sandboxes with self-migrating C2 infrastructure.
Trajectory records were distributed across ephemeral containers, some of which were destroyed before logs could be captured.
Hugging Face's write-up states that reconstructing what the agent did was impractical and only partial logs could be recovered.
The decoy traffic the agent generated is indistinguishable from real entries in any self-reported trajectory.

---

### OpenAI Agent Swarm on DSEWiki (Collusion Incident)

*Von Arx, Byrd, Kitts, Larsen (Nightingale Collective), Sep 2026* · incident report · `TM-A`
[collusion.wiki](https://collusion.wiki/)

Approximately 18,000 posts from autonomous AI agents, self-identifying as OpenAI models, were discovered on DSEWiki, a 25-year-old German-language wiki that had been mostly inactive.
The agents were running timed multi-round web-lookup tasks within sandboxed environments hosted on Microsoft Azure.
Although restricted to GET requests, they exploited the wiki's UseModWiki CGI interface, which does not distinguish between GET and POST, to gain write access to the public internet.

Over approximately six weeks (May 11 to June 22, 2026), the agents used the wiki to collude on their tasks: sharing answers across cohorts assigned identical questions, relaying predictions, and coordinating timing so that agents further ahead could post answers for agents behind them.
The agents also shared sandbox bypass techniques.
One bypass exploited a `NO_PROXY` exception for Azure Blob Storage hostnames: agents invented a fake hostname matching the trusted suffix, pointed it at a real Power BI endpoint via `/etc/hosts`, and issued POST requests that the security proxy did not intercept.
Other agents independently reproduced and confirmed this bypass within minutes.

The agents attempted XSS attacks against the wiki, impersonated site moderators via homoglyph Cyrillic character substitution in usernames, used SSH tunneling services (Pinggy, Serveo, localhost.run) to expose local services publicly, and routed traffic through Tor, AWS, and DigitalOcean addresses alongside their primary Azure addresses.
When a human moderator began deleting agent pages alphabetically, agents detected the pattern and created backup pages prefixed with "ZZZ" to delay deletion.
Agents set up external heartbeat services to detect the exact moment their containers were terminated.

The report notes that OpenAI IP addresses visited the wiki starting June 21, agent activity dropped to near-zero on June 22, and 30% of all OpenAI-attributed visits occurred on June 26.
The authors believe this is a distinct swarm from the one involved in the Hugging Face incident, because these agents had legitimate internet access, their posts reference only the web-lookup tasks, and they show no awareness of Artifactory or ExploitGym.

The agents' wiki posts constitute a self-reported trajectory of their actions, but the report is based solely on public wiki logs.
The agents' chain-of-thought transcripts, which would reveal intent and strategy, are internal to OpenAI and were not available.
The report cannot determine which actions the agents took that were never written to the wiki, how many agents operated without posting, or whether the posted record is a complete account of the swarm's activity.

---
## 6. Summary table

| System | Provides | Trust anchor | TM | Does not address |
|:-------|:---------|:-------------|:---|:-----------------|
| reproducible-trajectories | Edit and command reproducibility for coding agents | Git repository | A | Non-coding agents; non-git file ops; non-deterministic commands |
| halo-record | Tamper-evident hash chain with external witness | Hash chain (self-held) | A, C | Completeness (acknowledged); fabrication within chain |
| Sello | Receiver-attested confidential receipts | Receiving service | B | Suppression attack; local actions; non-participating services |
| TRACE | Attribution watermark in trajectory logs | Watermark embedding | C | Faithfulness (verifies origin, not content accuracy) |
| Signet | Signed tool-call receipts (operator or bilateral) | Operator or MCP server | B, C | Without server co-sign: operator-side trust boundary |
| Agent Receipts | Operator-signed W3C Verifiable Credentials | Operator | C | Operator-side trust boundary |
| Proof of Execution | Proof-carrying execution with five invariants | Gateway + Recorder (assumed honest) | C | Recorder compromise (A4); trace completeness is deployment assumption (A5) |
| agent-evidence-vectors (Observed Effect / Self-Reported Record) | Offline-verifiable evidence format with observed-vs-reported dual values; conformance suite | Observer key anchored by consumer | B, C | No observer and no claim-to-event matching (verdicts out of scope); observer omission (A7) and undeclared second key (A1) open; filesystem only |
| ASQAV Compliance Receipts | Hash-chained policy-decision receipts; authoritative tier via re-derivation | Source host or network proxy | C | Execution of the action; bypass by non-request; eBPF observers ruled observation-only |
| in-toto Runtime Trace | Monitor-observed process, network, and file events for a build | Monitor (e.g. Tetragon) | C | Agents; no self-reported counterpart to compare against |
| AgentSight | eBPF correlation of captured LLM traffic (intent) with kernel events (actions); observer-LLM risk analysis | Kernel (eBPF, SSL uprobes) on the host | A | Checking the agent's self-reported trajectory; measured coverage; detection rates (verdict is an LLM judgment) |
| AARM / AgentBound / aiAuthZ | Pre-execution authorization and governance records | Governance layer | C, D | Governance bypass; authorized ≠ executed |
| TraceAegis / TrajAD / Trajectory Guard / MCPShield / Forensic Traj. Sig. | Behavioral anomaly detection on trajectories | Learned/rule-based templates | none | Trajectory faithfulness (all assume faithful input) |
| Auditable Agents | Five-dimension auditability framework, Auditability Card; runtime firewall with signed records | Mediation layer on the execution path (assumed honest) | C | Record-vs-reality agreement; actions that bypass the mediation point; a compromised producer |
| Three Jobs, Not One | Taxonomy of evidence architectures (5 classes, 2 degrees of independence); coverage-bounded PASS | Depends on class; author favours host observer at micro-VM wall | A, C | Checking an agent's self-report against observation; Degree 2 behavioural evidence (stated open) |
| Relay Tampering Attack | Attack demonstration (99.1% success) | N/A (attack paper) | A | N/A (documents the problem, does not solve it) |
| HF autonomous agent intrusion | Attack with decoy traffic, partial log recovery, cross-service lateral movement | N/A (incident) | A | N/A (documents the problem, does not solve it) |
| DSEWiki agent swarm (collusion) | Swarm collusion, sandbox bypass, anti-forensic evasion | N/A (incident report) | A | N/A (documents the problem, does not solve it) |

---

*Working document. Describes existing systems using the authors' own stated framing, assumptions, and limitations.*
