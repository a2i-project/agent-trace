## 2. Execution evidence and assurance

These systems verify that a trajectory faithfully reflects what happened, or provide cryptographic evidence binding trajectory entries to real events.

---

### Reproducible Coding Agent Trajectories

*Monperrus, Jul 2026* · tool · `TM-A`
[blog post](https://www.monperrus.net/martin/reproducible-agent-trajectory) · [GitHub](https://github.com/ASSERT-KTH/reproducible-trajectories)

Defines execution-reproducibility for coding-agent trajectories via two verification criteria.
The *edit criterion* replays file edits from a known git parent commit and checks that the resulting file states exactly match the committed files.
The *command criterion* re-executes shell commands and checks that stdout/stderr are byte-identical to what was recorded.
Implemented as a Python package (~120 lines) in the `reproducible-trajectories` repository.

The trust anchor is the git repository.
The edit criterion uses commit history as ground truth for file state.
The command criterion uses deterministic re-execution as ground truth for command output.

> **Scope and stated constraints.**
> Scoped to coding agents that operate within a git repository.
> The edit criterion requires git-tracked files; file operations outside the repository (e.g., reading `/etc/passwd`, writing to `/tmp`) are not covered.
> The command criterion requires deterministic commands; non-deterministic commands (API calls, time-dependent output) fail verification even when faithfully recorded.
> No paper formalizes the concept; it exists as a tool and a blog post.

---

### halo-record

*Kuan, Aug 2026* · tool · `TM-A` `TM-C`
[GitHub](https://github.com/bkuan001/halo-record) · [Help Net Security interview](https://www.helpnetsecurity.com/2026/08/31/halo-record-open-source-ai-agent-audit-trail/)

An append-only, hash-chained JSONL log for agent actions.
Each record contains the hash of the previous record, forming a tamper-evident chain.
External witnesses (remote services) periodically store the chain's record count and head hash.
If the chain is later truncated or rewritten from a point, the witness's stored state reveals the discrepancy.

> **Author-acknowledged limitations.**
> The project documentation explicitly states: "A self-held chain proves integrity: nothing was edited or reordered after the fact. It cannot prove completeness."
> The witness detects chain truncation (removing entries from the tail) but does not detect selective omission within the chain if the chain is re-sealed after dropping entries from the middle.
> The agent itself writes the chain, so fabricated entries hash correctly and are indistinguishable from real ones within the chain structure.

---

### Sello: Receiver-Attested Confidential Receipts for AI Agent Actions

*Figuera et al., Jun 2026* · paper (22 pp.) · `TM-B`
[arXiv 2606.04193](https://arxiv.org/abs/2606.04193)

The Sello protocol addresses the problem of agents or their operators controlling their own activity logs.
It moves the trust boundary to the service receiving the agent's request.
The protocol works in four steps: the agent sends a request to a service; the service signs a receipt describing the action it observed; the receipt is encrypted to the agent owner via HPKE (so the agent and operator cannot read or suppress it in transit); and the receipt is published to a witness-cosigned transparency log.

The paper defines four security properties:

| Property | Definition |
|:---------|:-----------|
| P1 (Completeness) | If an agent contacts a participating service, the owner will eventually learn about it via a receipt |
| P2 (Confidentiality) | Only the owner can read receipt contents |
| P3 (Non-repudiation) | Once published, neither the service nor the agent can deny the interaction |
| P4 (Integrity) | The receipt accurately reflects what the service observed |

The paper includes a comparison table evaluating seven other receipt-based protocols (Signet, Agent Receipts, AgentBound, Pipelock, Openterms, and others) against these four properties.
Sello is the only protocol in the comparison that achieves all four simultaneously, primarily because it places the signing authority at the receiver rather than the operator or agent.

> **Author-acknowledged limitations (from the paper's discussion).**
>
> *Suppression attack:* The agent contacts a service and obtains a receipt, but suppresses it before it reaches the transparency log.
> The paper notes this is partially mitigated by the service's own publication of the receipt, but requires the service to independently publish.
> If the service only responds to the agent and does not independently publish, suppression is possible.
>
> *Service collusion:* If the receiving service colludes with the agent, the service can sign a false receipt or refuse to sign a true one.
> The protocol does not protect against collusion between the agent and the receiver.
>
> *Adoption-incentive problem:* Sello requires services to implement the receipt protocol.
> The paper acknowledges that services have no inherent incentive to do so, creating a deployment barrier.
> Coverage is limited to participating services.
>
> *Local actions:* Actions that do not involve an external service (file reads, computation, internal reasoning) have no receiver to sign a receipt.
> These actions are outside Sello's coverage by design.

---

### TRACE: Trajectory Attribution via Watermarking

*Gao et al., Jul 2026* · paper · `TM-C`
[arXiv 2607.08400](https://arxiv.org/abs/2607.08400)

Embeds attribution watermarks into agent trajectory logs.
The watermarks survive deletion, rewriting, and re-ordering of entries.
The purpose is to answer "whose agent produced this trajectory" for accountability and IP protection.

> **Stated scope.**
> Addresses attribution (provenance of the trajectory document), not faithfulness (whether the trajectory reflects what actually happened).
> A compromised runtime that controls the recording process can embed a valid watermark into a fabricated trajectory.
> The watermark authenticates the trajectory's origin, not its content.

---

### Signet

*Hou, 2025-2026* · tool · `TM-B` `TM-C`
[GitHub](https://github.com/Prismer-AI/signet)

MCP-focused middleware that produces cryptographically signed records of agent tool calls.
Supports two signing modes: operator-side signing (the operator's infrastructure signs the receipt) and bilateral co-signing (both the operator and the MCP server sign).
Co-signing provides stronger guarantees because the server independently attests to the interaction.

> **Stated scope and constraints.**
> Bilateral co-signing requires the MCP server to be instrumented with Signet.
> Without server co-signing, the operator alone signs, placing the trust boundary at the operator.
> An operator who controls the signing key can fabricate signed receipts.
> The Sello paper's comparison table (Section 2.2) identifies this as the operator-side trust boundary limitation shared by several receipt protocols.

---

### Agent Receipts

*Jongerius, 2025-2026* · tool/spec · `TM-C`
[agentreceipts.ai](https://agentreceipts.ai/)

Operator-side signing of agent actions via W3C Verifiable Credentials.
Each action produces a signed receipt that can be independently verified.
Designed for compliance and audit trails.

> **Stated constraints.**
> The operator signs.
> If the operator is the adversary (TM-C threat model), the operator can fabricate signed receipts.
> The Sello paper's analysis places Agent Receipts in the operator-side trust class, noting it does not achieve receiver-side attestation.

---

### Proof of Execution

*Rhodes & Kang, Apr 2026* · paper · `TM-C`
[arXiv 2607.05397](https://arxiv.org/abs/2607.05397)

Formalizes agent execution as a proof-carrying object.
Defines a Contract (pre/post-conditions), an Execution Certification Evidence Set (ECES), and a Replay Context.
The framework specifies five invariants that a valid proof must satisfy:

| Invariant | What it checks |
|:----------|:---------------|
| I1 (Plan consistency) | Execution follows the declared plan |
| I2 (Precondition satisfaction) | Each step's preconditions are met |
| I3 (Sequential validity) | Steps execute in declared order |
| I4 (Post-condition verification) | Each step's post-conditions hold after execution |
| I5a/I5b (Deterministic replay) | Re-execution produces the same result |

The Prime Execution Model separates four concerns: planning (what to do), enforcement (checking authorization), effect (executing the action), and recording (logging the result).
The paper provides a soundness proof: if all invariants hold, the proof correctly represents the execution.

> **Author-stated assumptions and scope.**
>
> *Assumption A4 (Recorder integrity):* The recording component is assumed to be honest.
> The paper states that recorder compromise is a deployment concern, not an in-scope threat.
> If the recorder is compromised, it can fabricate valid-looking proof objects.
>
> *Assumption A5 (Trace completeness, ε_tc):* The paper treats trace completeness as a deployment assumption, not a verified property.
> The completeness parameter ε_tc represents the fraction of execution events successfully captured.
> The paper acknowledges that achieving ε_tc = 1 (perfect completeness) depends on the deployment environment.
>
> *Planner compromise:* The paper explicitly states: "Planner compromise is out of scope."
> If the planning component is compromised, it may generate a plan that appears valid but serves adversarial goals.
> The proof system verifies that the execution matches the plan, not that the plan is benign.

---

### agent-evidence-vectors (Observed Effect and Self-Reported Record predicates)

*Gilda (probityai), Jul-Sep 2026* · spec + conformance suite · `TM-B` `TM-C`
[GitHub](https://github.com/probityai/agent-evidence-vectors) · [Zenodo 10.5281/zenodo.22758687](https://doi.org/10.5281/zenodo.22758687)

A conformance test suite and stdlib-only reference verifiers (Go and Python) for in-toto attestation predicates.
The main corpora certify the Adversarial Execution Evidence predicate (a tool or MCP server executed in a containment substrate against an attack corpus) and the AI Agent Action predicate proposed in in-toto/attestation#588 (tool calls observed by a protocol intermediary, hash-chained).
The design goal is that a consumer who distrusts the producer can check a statement offline, from its own bytes: canonical JSON, Merkle roots, signatures, and recomputation of every derived field.

Two self-hosted predicates in the repository address the closest ground to this project.
*Observed Effect* records a mutation interval (state-tree root before and after, a path scope, an authority digest) from a declared vantage, where `below-observed` means "a layer the observed party cannot address" and is the only vantage that grades as authoritative.
It carries per-file read and write digests, and a `dualValues` array in which each fact has an `observedValue`, a `reportedValue`, and a three-valued `agreement` (`agree`, `disagree`, `one-sided`).
*Self-Reported Record* is the counterpart for runtimes with no such vantage: a signed record of the agent's own turns, with rules that make specific internal inconsistencies refusable (for example, two ledgers naming different change sets).

The repository contains no observer and no comparison engine.
It defines the envelope an observer's output travels in and the gates a verifier runs over that envelope.
The `dualValues` rows are written by the producer; the verifier checks only that `agreement` is derivable from the two carried strings, and recomputes the observed side for six facts the statement determines about itself (row counts, roots, authority digest).
Deciding which claimed action corresponds to which observed event is out of scope by design.

> **Author-stated scope and limitations.**
> "Verdicts are out of scope. They belong downstream, computed over this evidence."
> The trust model targets a lying producer or assembler of the statement, not a lying agent under a trusted observer.
> Attack A1 (a self-observing producer holding a second, undeclared key) is documented as open: `vantage: below-observed` is "coherent with the vantage it claims" rather than proven.
> Attack A7 (observer omits a read it saw) is documented as open: "This attack works and there is no version of this predicate in which it does not."
> Observed Effect covers filesystem state only; it has no process or network model.
> The author states that the five first-party implementations share one reading of the specification and counts one independent implementation.

---

### ASQAV Compliance Receipts Profile

*Gomes Marques, Aug 2026* · IETF Internet-Draft (-08) · `TM-C`
[draft-marques-asqav-compliance-receipts-08](https://datatracker.ietf.org/doc/draft-marques-asqav-compliance-receipts/08/)

A compliance profile for signed action receipts that record a policy decision taken before an AI agent acts, mapped to the EU AI Act, DORA, and several US regimes.
Receipts are hash-chained and anchored with RFC 3161 or OpenTimestamps.
Section 8 defines two attestation tiers: *observation*, where the platform signs a caller-supplied digest, and *authoritative*, where the platform re-derives the digest from independent evidence (for code, by re-fetching the diff from the source host) and fails closed if it cannot.
Appendix C catalogues capture topologies, including an eBPF SNI observer (C.4) that records the TLS ClientHello SNI, addresses, and timestamp below the application process.

> **Author-stated scope and limitations.**
> Only re-derivation and a network proxy count as independent evidence. Section 8.3: emission topologies "(browser_extension, ebpf_observer, mcp_proxy) can never mint an authoritative attestation"; Section 8.5: "The eBPF-observer and passive-telemetry topologies catalogued in Appendix C remain observation-only evidence classes."
> Section 8.2: "Reproducibility does NOT make the attestation unbypassable: a client that never requests an attestation bypasses it entirely."
> Section 11.14: a receipt does not prove "That the Action was executed, completed, or produced any outcome."
> This is the ruling agent-evidence-vectors' Observed Effect predicate is written against: it inverts the ordering and treats an observer below the agent as the strongest vantage.

---

### in-toto Runtime Trace predicate

*Patel, Nadgowda, Yelgundhalli, v0.1.0* · attestation predicate · `TM-C`
[spec](https://github.com/in-toto/attestation/blob/main/spec/predicates/runtime-trace.md)

An in-toto predicate for system events observed during a supply-chain operation such as a build.
A monitor (the spec names Cilium Tetragon) records a `monitorLog` of spawned processes, network activity, and file accesses with digests, identifies itself and its trace policy in `monitor`, and identifies the observed job in `monitoredProcess`.
The stated use case is supporting SLSA requirements, for example that a build was script-invoked and ran hermetically without network access.

> **Stated scope and constraints.**
> Scoped to build and supply-chain operations, not agents; there is no self-reported counterpart to compare the trace against.
> File digest accuracy depends on the monitoring approach: the spec notes that synchronous monitors (ptrace) give stronger guarantees than asynchronous ones (eBPF).

---

### AgentSight: System-Level Observability for AI Agents Using eBPF

*Zheng, Hu, Yu, Quinn (UC Santa Cruz, ShanghaiTech, eunomia-bpf), Aug 2025* · paper (6 pp.) + tool · `TM-A`
[arXiv 2508.02736](https://arxiv.org/abs/2508.02736) · [DOI 10.1145/3766882.3767169](https://doi.org/10.1145/3766882.3767169) · [GitHub](https://github.com/eunomia-bpf/agentsight)

An observability framework that monitors an agent from outside its application code, at what the authors call "stable system boundaries" (*boundary tracing*).
Two eBPF streams are captured.
The *intent stream* comes from uprobes on `SSL_read`/`SSL_write` that recover decrypted LLM prompts and responses, with userspace reassembly of SSE streaming.
The *action stream* comes from the `sched_process_exec` tracepoint and kprobes on `openat2`, `connect`, and `execve`, filtered in-kernel to the agent's process lineage (fork/execve tracking).
A Rust daemon (about 6,000 lines of Rust/C) joins the two streams with three signals: process lineage, temporal proximity (a 100-500 ms window after an LLM response), and argument matching (filenames, URLs, or commands in the LLM response that reappear in syscall arguments).
A secondary "observer" LLM then receives the correlated trace, acting as a security analyst, and returns a natural-language analysis with a confidence score.

The evaluation measures runtime overhead on three Claude Code workflows (3 runs each, 0.4% to 4.9%, 2.9% on average) and presents three case studies: an indirect prompt injection that exfiltrates `/etc/passwd` (521 raw events merged into 37, flagged by the observer LLM), a CrewAI retry loop, and coordination bottlenecks among six Claude Code subagents.
The authors state that boundary tracing "shifts the trust model from assuming a cooperative agent to enforcing observation at tamper-proof boundaries."
The repository has since grown into a general tool (`agentsight record`, `top`, `report audit`) whose README lists "Agent-Controlled Logs: logs can be incomplete, disabled, or modified" as the gap kernel-level events close.

This is the closest system to agent-trace in mechanism: the same probe classes (SSL uprobes, exec tracepoints, connect), the same lineage scoping, and a claim-to-event join over paths, URLs, and commands.
The difference is what the kernel stream is compared against.
AgentSight's "intent" is the LLM traffic it captures itself, not the trajectory the agent or its runtime reports, so it never checks a self-report for omitted, fabricated, or substituted entries.
Its correlation is a heuristic time-window and argument join feeding an LLM judgment, not a verdict over a declared set of entries.

> **Stated scope and constraints.**
> The paper has no limitations or threat-model section; the constraints below follow from its stated design and evaluation.
> "Comprehensiveness, as kernel-level monitoring ensures no system action ... goes unobserved" is asserted, not measured: there is no coverage or loss measurement against ground truth.
> The case studies report no detection rate, false-positive rate, or baseline; the final verdict is the observer LLM's output.
> The intent stream depends on hooking the TLS library; the README notes that agents that statically link BoringSSL or OpenSSL (Claude Code, Node.js, Gemini CLI) need binary discovery or `--binary-path`, and that IDE agents such as Cursor cannot be captured through eBPF at all.
> Capture requires root or `CAP_BPF`/`CAP_SYS_ADMIN`, placing the observer in the operator's trust domain.

---
