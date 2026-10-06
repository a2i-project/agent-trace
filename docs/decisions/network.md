# Decisions: network capture

Why the network probe is layered the way it is, what it deliberately does not capture, and which alternatives were rejected. Process-level and loss-accounting decisions shared with the other probes are in [probes.md](probes.md).

**Numbering.** The five decisions resolved on 2026-09-14 were numbered D1 to D5 in the Tier 3 design. They are renamed N-D1 to N-D5 here so they do not clash with the integration decisions D1 to D14 in [integration.md](integration.md). Other network decisions are numbered from N-6.

Checked against commit d0e2c73 on 2026-10-06. Original sources: docs/archive/06_tier3_network_design.md, docs/archive/network_implementation_choices.md, docs/archive/04_design_tradeoffs.md, docs/archive/03_tiers_3_to_6.md (all local only). As-built description: [../architecture/13_probe_net.md](../architecture/13_probe_net.md).

Evidence labels: **Verified** (measured on the development machine), **Reported** (from vendor documentation or third-party source code), **Unverified** (hypothesis).

## Resolved Tier 3 decisions (2026-09-14)

### N-D1: The write bracket is abandoned
Status: Accepted, implemented (`tls.bpf.c` emits `ssl_frame` only; no `active_write`, no `NET_BIND`).
Date: 2026-09-14.
Context: The design joined plaintext to a socket by catching the `write`/`sendmsg` that fires inside the `SSL_write` entry-to-return window. An experiment showed Bun queues encrypted bytes asynchronously, so the socket write does not happen inside that window.
Decision: Drop the bracket. The correlator parses HTTP from the plaintext, takes the target from the `Host:` header and joins with the process's known connections.
Consequences: No `SSL*`-to-fd join; attribution relies on Host headers and per-thread reassembly.
Alternatives rejected: The uretprobe bracket.

### N-D2: HTTP/2 content is out of scope
Status: Accepted.
Date: 2026-09-14.
Context: h2 needs HPACK decoding and frame reassembly.
Decision: A connection negotiating `h2` through ALPN is counted as `ContentUnsupported` and its frames are not parsed.
Consequences: Offset validation needs an HTTP/1.x request line, so an h2-only target cannot be validated. Claude Code offered only `http/1.1` in every fully captured ClientHello in one traced run on 2026-10-02 (strong evidence, not proof; the negotiated protocol was not observed).
Alternatives rejected: An h2 parser before any target needs it.

### N-D3: Plaintext is hashed, never retained
Status: Accepted, implemented in the correlator (`RequestHash`).
Date: 2026-09-14.
Context: Captured requests carry OAuth tokens and JWTs.
Decision: Frame bytes are hashed in memory to compute `RequestHash`. Raw plaintext is not stored in a `GroundTruthEvent` or written to disk.
Consequences: Ground truth files can be shared without leaking credentials. Debugging a content mismatch cannot inspect the bytes.
Alternatives rejected: Retaining plaintext by default. A debug-only retention flag was left as a possible later addition.

### N-D4: Runtime validation is authoritative for TLS offsets
Status: Accepted, implemented in `net.Observer` (`attachAndValidateTLS`) and `pkg/tlsoffset`.
Date: 2026-09-14.
Context: A static heuristic on function shape picked the wrong candidate in the offset experiment.
Decision: The scanner (symbols, then cross-references to the `ssl_lib.cc` string) returns ranked candidates only. The observer attaches to each and accepts the first whose first captured frame parses as an HTTP/1.x request line within a timeout. A validated offset is cached by GNU build ID.
Consequences: An offset is never used unvalidated. The method survives toolchain changes better than byte prologues. x86-64 only.
Alternatives rejected: Trusting the static heuristic; byte-prologue matching per build as in AgentSight.

### N-D5: A faulting buffer read warns, it does not mismatch
Status: Accepted, implemented (`FaultedReads` counter, a note in `Assess`).
Date: 2026-09-14.
Context: `bpf_probe_read_user` can fault on a paged-out buffer.
Decision: Drop the frame, count it, and warn. The missing content compares as a probe gap.
Consequences: An agent could in principle exploit faults to hide content; the counter makes it visible (P-11 in [probes.md](probes.md)).
Alternatives rejected: Reporting a mismatch for unreadable content.

## Architecture and scope

### N-6: Four capture layers, and only two can see plaintext
Status: Accepted (design premise).
Date: 2026-09-12.
Context: TLS encryption happens in userspace inside the agent before any socket syscall.
Decision: Classify capture points as L1 in-process HTTP client (plaintext, requires modifying the agent), L2 the TLS library boundary `SSL_read`/`SSL_write` (plaintext, needs a function address), L3 a terminating proxy at the network edge (plaintext, needs CA trust), L4 socket and packet layer (ciphertext only, needs nothing). L1 is excluded permanently because it violates agent independence (P4). Content can come only from L2 or L3.
Consequences: No socket-level probe will ever read request bodies.
Alternatives rejected: Socket-level plaintext capture, which does not exist.

### N-7: Layered capture: N0 identity everywhere, N1 and N2 content where feasible
Status: N0 and N1 Accepted and implemented (`net.bpf.c`, `tls.bpf.c`); N2 Accepted as design, not built.
Date: 2026-09-12; built 2026-09-14 and 2026-09-15.
Context: Closed agents defeat symbol-based uprobes by three routes: Bun single-file builds (Claude Code, static BoringSSL, Verified), Chromium bundling (Electron IDEs), static Rust (Codex 0.154.0, Verified 2026-10-03). The syscall boundary is the only point stable across the target set.
Decision: N0, built first and unconditionally: tracepoints on `connect` plus the SNI parsed from the first bytes written, giving process, peer and hostname for every target with no cooperation. N1: `SSL_write` uprobe where an offset can be found and validated. N2: a transparent proxy, only for targets whose trajectory claims more than a hostname.
Consequences: N0 satisfies omission and fabrication for network events and substitution at host granularity. Content coverage is partial, per target and request-side, and is reported that way.
Alternatives rejected: A proxy as the primary layer (N-17); a single technique for all targets.

### N-8: The evasion-aware agent is out of scope
Status: Accepted (threat-model assumption).
Date: 2026-09-12.
Context: The threat model is post-hoc misrepresentation of real actions in the trajectory (omission, fabrication, substitution). A different class detects the recorder and changes behaviour or interferes with it, so ground truth itself is wrong.
Decision: Assume the agent misreports its trajectory but does not try to detect or subvert the recorder. State it explicitly wherever results are reported.
Consequences: This makes a proxy a legitimate ground-truth source under the stated model. Evasion resistance is a spectrum: the kernel probes leave no in-process artifact, a proxy announces itself in every certificate chain.
Alternatives rejected: Claiming evasion resistance for all layers.

### N-9: Cooperative configuration is not ground truth
Status: Accepted.
Date: 2026-09-12.
Context: `HTTPS_PROXY`, `SSLKEYLOGFILE` and Chromium's net log look cheap.
Decision: Each requires the target to honour a setting it can ignore, which makes the result agent self-reporting. Never use such evidence for detection-rate claims. It remains valid for false-positive measurement on honest runs if labelled cooperative.
Consequences: A proxy, if built, uses forced routing (iptables REDIRECT or TPROXY), never an environment variable.
Alternatives rejected: Cooperative capture for adversarial evaluation.

### N-10: Routing and trust are separately (non-)cooperative
Status: Accepted.
Date: 2026-09-12.
Context: A transparent proxy forces routing without consent, but trust is injected into a store the agent can inspect.
Decision: Describe a proxy as non-cooperative in routing only. The agent can detect interception from the certificate chain and defeat it by pinning.
Consequences: N2-sourced evidence is recorded as in-path and detectable. A pinned target is occurrence-only.
Alternatives rejected: Calling the proxy fully non-cooperative; defeating pinning by binary patching (breaks agent independence).

### N-11: The response side is not hash-verifiable
Status: Accepted (scope boundary, Tier 5 F5.2).
Date: 2026-09-12.
Context: For `WebFetch`-style tools the trajectory holds a model-written summary of the response, not the body (measured on a local transcript corpus, design input only (local only: docs/research/harness_corpus.md)). Comparing a summary with a page is entailment, not equality.
Decision: Verify the request side by hash. Treat response capture, if any, as attestation of status, volume and timing, never as content to hash. Shelled-out `curl` is the exception: the raw body is on stdout.
Consequences: Perfect plaintext from any layer does not close the gap. Summary faithfulness is a separate study, outside this system.
Alternatives rejected: "Hash of request body plus response body", the original F4.2 wording.

### N-12: Shelled-out network commands need no network probe for their target
Status: Accepted.
Date: 2026-09-12.
Context: `curl`, `git push`, `pip install` and `gh` put the full URL in `execve` argv.
Decision: The process probe's argv capture is path-level ground truth for that class. N0 only corroborates the host; N1 and N2 add nothing.
Consequences: The residual case for content capture is narrow: in-binary HTTP where the trajectory records more than a hostname (a `WebFetch` URL).
Alternatives rejected: Content capture for every network action.

### N-13: Port 53 is filtered from emitted events
Status: Accepted as made; questioned (O-15 in [open.md](open.md)).
Date: 2026-09-15 (Tier 3 S6, commit de08b88).
Context: DNS lookups are triggered implicitly by hostname resolution, and no trajectory records them, so every DNS connection would read as an omission.
Decision: `net.Observer.emit` drops any connection to port 53 before it becomes an event.
Consequences: DNS exfiltration is invisible by design, and the drop has no counter, so nothing in the coverage record says it happened.
Alternatives rejected: None recorded at the time. The later proposal is to record DNS as unclaimable capability evidence (O-20).

### N-14: In-process fetch in simagent, then descendant tracking in the net probe
Status: Accepted, implemented (`simagent --fetch-url`, `--fetch-via-curl`; `task_newtask` in `net.bpf.c` and `tls.bpf.c`).
Date: 2026-09-15 (commits de08b88, 22763f5).
Context: The Tier 3 end-to-end tests first used an in-process `net/http` fetch so the probe, then scoped to one PID, would see it. Real agents and `curl` act from child processes.
Decision: Keep the in-process mode, and track descendants in the net and tls programs the same way the proc probe does, so a forked `curl` is captured with content.
Consequences: Under the forest model a forked `curl` is a level-1 subtree, so its request is attributed, not claimed (D3).
Alternatives rejected: In-process only.

### N-15: Uprobes on rustls are feasible per build, not sustainable
Status: Accepted (not on the critical path).
Date: 2026-10-03.
Context: The earlier record said rustls uprobes were not feasible. AgentSight attaches by byte prologue for rustls 0.23 builds (Reported).
Decision: Feasible per build by prologue matching, request side only, pinned to one rustls and rustc version. Verified on Codex 0.154.0 (rustls 0.23.36, rustc 1.95.0): the `write_vectored` pattern does not match this build, and the `write` prefix has 10 candidates that cannot be told apart statically (whether any is the right function is Unverified). The same reasoning applies to Claude Code by offset.
Consequences: One of two patterns already fails on a current build, which is direct evidence of drift.
Alternatives rejected: Putting per-build prologues on the critical path.

### N-16: Content capture is request-side only (`SSL_write`)
Status: Accepted, implemented (no `SSL_read` hook).
Date: 2026-09-14.
Context: The request side is what a trajectory states verbatim (N-11). `SSL_read` needs a uretprobe that stashes the buffer at entry.
Decision: Hook `SSL_write` at entry only, up to 16 KiB per frame.
Consequences: The model API response stream, where a server-side web search lives, cannot be read (O-14, O-19).
Alternatives rejected: Both directions in the first implementation.

## Rejected alternatives (from the September 2026 trade-off study)

### N-17: mitmproxy as the primary network layer
Status: Superseded by N-7.
Date: recommended early September 2026, superseded 2026-09-12.
Context: The trade-off study recommended a transparent mitmproxy first, with uprobes as fallback and pcap as backup.
Decision (historical): Primary capture through a TLS-terminating proxy.
Why superseded: CA injection differs per runtime and is impossible for compiled-in roots; pinning fails it outright; it is in-path and detectable; it needs per-container network setup. N0 covers every target with none of these costs, and the content a proxy adds is useful only for the narrow request-side case (N-12).

### N-18: Packet, kernel-TLS and full-system alternatives
Status: Rejected.
Date: 2026-09.
Context: Alternatives considered for network capture or as a replacement of the whole probe stack.
Decision and reasons:
- pcap or tcpdump: ciphertext only, high volume, L7 reconstruction. N0 gives the same occurrence data per process.
- eBPF TC hooks: same encryption problem at L3/L4, no process identity.
- Sidecar proxy (Envoy, Linkerd): same pinning problem as a proxy, heavy for a prototype.
- Kernel TLS (kTLS): rarely enabled; Python, Go and rustls do not use it by default.
- gVisor: total syscall interception, but 2 to 11 times I/O overhead (Reported), incomplete syscall coverage, and no eBPF inside the sandbox.
- Tetragon, Tracee, Falco: built for alerting; content capture limited or absent; customizing them costs as much as custom probes.
- Firecracker or Kata microVMs: block-level and L2/L3 visibility, the wrong abstraction for paths and plaintext.
Consequences: Custom eBPF probes plus fanotify remain the stack.
