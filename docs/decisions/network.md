# Decisions: network capture

Why the network probe is layered the way it is, what it deliberately does not capture, and which alternatives were rejected. Process-level and loss-accounting decisions shared with the other probes are in [probes.md](probes.md).

**Numbering.** The five decisions resolved on 2026-09-14 were numbered D1 to D5 in the Tier 3 design. They are renamed N-D1 to N-D5 here so they do not clash with the integration decisions D1 to D14 in [integration.md](integration.md). Other network decisions are numbered from N-6.

Entries carry their own dates. Statuses reconciled with the code at commit 1391cbe on 2026-10-11. Original sources: docs/archive/06_tier3_network_design.md, docs/archive/network_implementation_choices.md, docs/archive/04_design_tradeoffs.md, docs/archive/03_tiers_3_to_6.md (all local only). As-built description: [../architecture/13_probe_net.md](../architecture/13_probe_net.md).

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
Consequences: An agent could in principle exploit faults to hide content; the counter makes it visible (P-11 in [probes.md](probes.md)). Amended 2026-10-14: the same rule covers the ClientHello read in `net.bpf.c`. A faulted hello read marks the connection written (`NET_SEND`, N-23) and is counted in `HelloFaults`, a note in `Assess`: the hostname is missing, no event is.
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
Status: Accepted (scope boundary: the response side is attested by status, volume and timing, never hashed).
Date: 2026-09-12.
Context: For `WebFetch`-style tools the trajectory holds a model-written summary of the response, not the body (measured on a local transcript corpus, design input only (local only: docs/research/harness_corpus.md)). Comparing a summary with a page is entailment, not equality.
Decision: Verify the request side by hash. Treat response capture, if any, as attestation of status, volume and timing, never as content to hash. Shelled-out `curl` is the exception: the raw body is on stdout.
Consequences: Perfect plaintext from any layer does not close the gap. Summary faithfulness is a separate study, outside this system.
Alternatives rejected: "Hash of request body plus response body", the original plan's wording for network content verification.

### N-12: Shelled-out network commands need no network probe for their target
Status: Accepted.
Date: 2026-09-12.
Context: `curl`, `git push`, `pip install` and `gh` put the full URL in `execve` argv.
Decision: The process probe's argv capture is path-level ground truth for that class. N0 only corroborates the host; N1 and N2 add nothing.
Consequences: The residual case for content capture is narrow: in-binary HTTP where the trajectory records more than a hostname (a `WebFetch` URL).
Alternatives rejected: Content capture for every network action.

### N-13: Port 53 is filtered from emitted events
Status: Superseded by N-20 on 2026-10-11: a connection to port 53 is emitted as `net_dns` capability evidence and counted. Kept as taken; it was questioned as O-15, which N-20 decided.
Date: 2026-09-15 (the privileged integration step of the network probe, commit de08b88).
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

### N-19: Port-0 connects are not emitted
Status: Accepted, implemented (`net.Observer.emit`, `TestEmitSkipsAddressSelectionAndReportsDNS`). Amended 2026-10-11 (commit 4343878): port-0 connects are now counted in `Coverage.AddressProbes`, and port 53 is no longer dropped (N-20), so the comparisons with the DNS drop and the last consequence (no counter) no longer hold.
Date: 2026-10-07.
Context: In a paired capture of Claude Code every real connection was preceded by connects to port 0 of the destination's IPv4 and IPv6 addresses, and nothing was sent on them. The resolver connects a datagram socket to each candidate address to ask the kernel which source address it would use (RFC 3484 address selection; **Reported**, glibc behaviour; the twin pattern is **Verified** in that capture). They name addresses that change with DNS, so no trajectory can claim them and a baseline cannot list them. A fetch of a new host left one as an unrecorded action.
Decision: `emit` drops a connection to port 0, like port 53 (N-13), and marks it emitted so its close does not retry.
Consequences: Ground truth no longer holds the `IP:0` events, so baselines measured earlier carry rules that match nothing (harmless). A real connection to port 0 does not exist, so nothing legitimate is hidden. Like the DNS drop it has no counter.
Alternatives rejected: Dropping them in the adapter (it is resolver behaviour, not a harness property); recording them as capability evidence (they carry no information about what the agent did).

### N-20: A connection to port 53 is capability evidence, not a dropped event
Status: Accepted, implemented (`emit` in `pkg/probe/net/observer.go`, `models.NetDNS` unclaimable). Decides O-15, removed from open.md on 2026-10-11. Supersedes N-13.
Date: 2026-10-11 (security review).
Context: N0 dropped every connection to port 53 on the reasoning that DNS lookups are the resolver's and no trajectory records them. The filter is on the port, not on the protocol: a TCP connection to port 53 anywhere is a channel for data, and it left no trace in the capture and no counter.
Decision: A connection to port 53 is emitted as `net_dns` with the `ip:port` target, ground truth only like `net_bind`: in the capture and the report's capability list, never aligned and never a finding, since an honest run makes one per lookup. The count is in `Coverage.DNS`. Port 0, the resolver's address selection, is still not emitted but is counted (`Coverage.AddressProbes`).
Consequences: Data moved over port 53 is visible to a reader of the report and in the forensic view of the command that did it. It is not a finding, because the probe cannot tell a lookup from an exfiltration, and the resolver's own connections are many. The claimable set loses `net_dns`, which no adapter ever produced.
Alternatives rejected: Distinguishing UDP from TCP (the connect tracepoint does not see the socket type; a socket hook is more code for a weak signal, since UDP carries data too); treating port 53 as a finding (every honest run resolves names).

### N-21: Connections still open at the end of the capture are emitted then
Status: Accepted, implemented (`flushOpenConnections` in `pkg/probe/net/observer.go`).
Date: 2026-10-11 (security review, local only).
Context: A connection whose ClientHello carried no name was emitted only on its `close()`, with the address as target. One held open until the process exited, or past the end of the capture, was never emitted and nothing counted it: an agent that connected by address, sent, and never closed left no trace.
Decision: When both record feeders have closed, the correlator emits every connection still open, in connect order, each stamped with its connect time, and counts them in `Coverage.OpenAtStop`.
Consequences: Every connection the probe saw reaches the capture. The stamp is the connect time, so the event sorts where the connection began; a connection with a name was already emitted at its hello and is not emitted twice.
Alternatives rejected: Emitting every connection at connect time (a connection with a name would then be emitted by address first and by name later, two events for one connection, and the baseline names addresses that change).
Note 2026-10-11: "every connection the probe saw" excludes one whose descriptor was closed without `close()` (by `dup2`, `close_range` or an exec under `O_CLOEXEC`) and on which the same process then connected again: the new connect replaces the entry before it is emitted, and nothing counts it ([../architecture/13_probe_net.md](../architecture/13_probe_net.md), Known limits).

### N-22: A connection that sent nothing is capability evidence, not a connection
Status: Accepted, implemented (`connection.wrote`, `emit` in `pkg/probe/net/observer.go`, `models.NetDial`).
Date: 2026-10-11 (security review; the IP literals in baseline rules).
Context: Every baseline held `net_connect` rules naming addresses, `160.79.104.10:443` and an IPv6 twin: the losing halves of the harness's dual-stack connects, which close with no ClientHello and so were emitted by address at their close. The addresses change with DNS, so the rules were tied to the day of the capture, and a rule for an address explained any later connection to it that sent data without a name.
Decision: A connection that closes, or is flushed at the end, with no name and no byte ever written on it is `net_dial`, ground truth only like `net_bind`: in the capture and the capability list, never aligned, never a rule. A connection that wrote and had no name stays `net_connect` by address, which a claim or a rule must explain.
Consequences: Baselines no longer name addresses for the harness's losing connects, so they do not rot with DNS, and a data-carrying connection by address is no longer explained by one. A dial carries at most the fact that it happened, a covert channel of one bit per connect, which the report shows. The `wrote` flag comes from the first write the kernel saw on the descriptor, whatever it carried.
Alternatives rejected: Templating addresses in rules (a wildcard explains whatever an attacker makes it match, V-19); resolving addresses back to names (DNS is not observed, O-20).
Note 2026-10-11: the writes the kernel sees are `write`, `sendto` and `sendmsg` by the process that made the connect. A connection without a name whose data went through `writev`, `sendfile`, `splice`, `sendmmsg` or io_uring, or was written by a child that inherited the descriptor, is a `net_dial`, and so is not a finding, even at level 0 ([../architecture/13_probe_net.md](../architecture/13_probe_net.md), Known limits; O-18).

### N-23: The send side of a connection is completed in the probe, and `net_dial` stays capability evidence
Status: Accepted, implemented (`trace_writev`, `trace_pwritev2`, `trace_sendmmsg`, `trace_sendfile`, `trace_splice`, `capture_hello_iov`, `mark_sent` in `pkg/probe/net/net.bpf.c`, `netSend` in `pkg/probe/net/observer.go`, keyed by socket per N-24; `TestObserver_SendsWithoutWriteAreConnections`, `TestObserver_HelloAcrossIovecsYieldsSNI`, `TestObserver_ForkedChildWriteMarksConnection`, `TestObserver_SCMRightsReceiverWriteMarksConnection`, `TestHandleNetRecord_RecordsFromAnotherProcessFollowTheSocket`). Ratified by the user on 2026-10-11 (was O-27 in open.md).
Date: 2026-10-11.
Context: N-22 makes a connection with no observed send `net_dial`, capability evidence that is never a finding. The probe sees a send only through `write`, `sendto` or `sendmsg` by the process that made the connect. Data sent through `writev`, `sendfile`, `splice`, `sendmmsg` or io_uring, or written by a child after `fork` (a shell that connects through `/dev/tcp` and pipes a file through a forked `cat`), leaves the connection a `net_dial`, so an unclaimed connection that carried data can pass unreported.
Decision: Keep N-22. Close the gap in the probe: observe the missing send paths and follow the socket across `fork` and descriptor passing, so that any connection that carried data is a `net_connect`.
Consequences: Baselines keep no address rules (N-22). Until the probe work lands, the gap is a known limit of the net lane, shared in part with io_uring (O-18).
Alternatives rejected: Reporting a dial only in a command's subtree, and reverting dials to `net_connect` by address: both bring address rules back into baselines for the cases they cover.
Note 2026-10-11 (docs review): scope of this entry. Sends through `writev`, `sendmmsg`, `sendfile` and `splice`, a multi-iovec `sendmsg`, and a connection written by another process that holds the descriptor (a child after `fork`, or a process that received it over `SCM_RIGHTS`) are in scope. Sends through io_uring are covered by O-18 (moving the hooks to the socket layer), which would also close this entry's gaps.

### N-24: A connection is identified by its socket and ends at its last descriptor
Status: Accepted, implemented (`fd_socket`, `file_last_ref`, `release_fd`, `trace_dup2`, `trace_dup3` in `pkg/probe/net/net.bpf.c`; `handleNetRecord` in `pkg/probe/net/observer.go`; `TestObserver_ConnectionClosedByDup2IsEmitted` and the N-23 tests).
Date: 2026-10-12.
Context: N-23 requires a send by any process holding a connection to mark it. The probe keyed a connection by the tgid and descriptor of the connect, which a child after `fork`, a receiver of `SCM_RIGHTS` and a duplicate descriptor do not share, and it ended the connection at the connecting process's `close()` of that descriptor, which can come before another holder sends (a sender commonly closes its copy right after passing it). A syscall tracepoint sees only the descriptor number. The socket-layer hooks of O-18 would receive the socket directly, but O-18 is undecided.
Decision: Every hook that names a descriptor of a connection resolves it with CO-RE reads through the calling task's fd table (`task->files->fdt->fd[fd]`) to the file, checks that its inode is a socket, and keys the connection by the socket inode number (`f_inode->i_ino`). Records carry the number in the header field `sock`, and userspace keys its connections by it. A connection ends when a tracked process drops a descriptor that holds the last reference to the socket's file, through `close`, `dup2` or `dup3`; the count is read from `f_ref` (kernel 6.13 and later) or `f_count`, chosen by a CO-RE field-existence check. The event's PID stays the process that connected.
Consequences: A send from any tracked holder marks the connection, in whatever order the holders close. A duplicate in the same process (bash moves its `/dev/tcp` descriptor with `fcntl(F_DUPFD)` before it closes it) no longer ends the connection early, and a `dup2` over a connected descriptor ends that connection at the `dup2` instead of at a later connect on the same number (N-21's note of 2026-10-11 described the earlier keying). A connection whose last reference goes without a hooked call (process exit, `close_range`, an exec under `O_CLOEXEC`, a holder outside the tracked tree) ends at the end of the capture with its connect time (N-21), where a close by the connecting process used to end it. A syscall running in another thread on the same socket holds a reference, so a close during it is not the last. Each send of a tracked process now costs a few kernel reads. `Coverage.Replaced` counts only a socket connected again.
Alternatives rejected: Keying by the `struct sock` address (the slab hands it to the next socket, so an entry left by a socket released without a hooked call would match an unrelated socket; the inode number is not reused that way); following descriptors in the (tgid, fd) map across `fork`, `dup` and `SCM_RIGHTS` (the receiver gets a number the sender never sees, and every dup path would need a hook); socket-layer hooks (O-18, undecided).

### N-25: io_uring socket operations by tracked processes are counted as event loss
Status: Accepted, implemented (`trace_iouring_submit`, `trace_iouring_setup` and the `iouring_*_count` maps in `pkg/probe/net/net.bpf.c`; `ProbeCoverage.IOURingNetOps`; `verification.Assess`; `TestObserver_IOURingSocketOpsAreCounted`, `TestObserver_IOURingFileOpsAreNotNetwork`).
Date: 2026-10-13.
Context: Every net hook is a `sys_enter_*` tracepoint, and an operation submitted through io_uring passes none of them, so a runtime that sends through io_uring yields no connection or a `net_dial` and a run can read FAITHFUL on a network omission. O-18 (socket-layer hooks) would see such operations but is undecided and costly. The cheap alternative, counting every `io_uring_setup` as loss, would make every run that starts Node.js INCONCLUSIVE. Measured on 2026-10-13, kernel 6.17, unprivileged (**Verified**): `strace -f -e trace=io_uring_setup,io_uring_enter,io_uring_register` shows no io_uring call from the Claude Code 2.1.296 process (Bun) in `claude --version`, `--help`, `auth status` (which connects over TCP), `doctor` and `mcp list`, and the binary has no io_uring symbol or string and imports `epoll_ctl` and `epoll_wait`. The io_uring calls in those runs came from Node.js children (`npm`, `npx` MCP servers). Node.js 20.19.4 with libuv 1.50.0 sets up two rings per process and, logged per submission by an `LD_PRELOAD` shim on libuv's `syscall` and `mmap64`, submits only `IORING_OP_EPOLL_CTL`, for a `fetch` over HTTPS with file copies, a raw `net.connect`, `npm config get prefix`, and a file read with `UV_USE_IO_URING=1`. Python 3.13 (`urllib` fetch, `shutil.copy`), curl 8.14, git 2.51 (`ls-remote` over HTTPS) and `cp` make no io_uring call.
Decision: Option 1 of O-18: detect and degrade. A program on the `io_uring:io_uring_submit_req` tracepoint counts, for tracked processes, every submitted operation (diagnostic) and every network operation in `iouring_net_count`, reported as `ProbeCoverage.IOURingNetOps`, which `Assess` treats as event loss, so the run is INCONCLUSIVE with a reason naming io_uring. A network operation is one whose opcode works only on sockets (`SENDMSG`, `RECVMSG`, `ACCEPT`, `CONNECT`, `SEND`, `RECV`, `SHUTDOWN`, `SOCKET`, `SEND_ZC`, `SENDMSG_ZC`, `BIND`, `LISTEN`, `RECV_ZC`), or a data operation (`READ`, `WRITE`, their vectored and fixed-buffer forms, `READ_MULTISHOT`, `SPLICE`, `TEE`) whose descriptor is a socket by the same fd-table lookup as N-24, or is a registered file or cannot be read, which the probe cannot tell from a socket. `EPOLL_CTL`, `POLL_ADD`, file operations and the rest are not. A `sys_enter_io_uring_setup` program counts the rings tracked processes set up (diagnostic). On a kernel without `io_uring_submit_req` but with the syscall, the observer adds every ring to `IOURingNetOps`, so the minimum kernel stays unchanged and such a kernel degrades every io_uring user. The operations themselves are still not recorded; O-18 stays open.
Consequences: A run in which a tracked process moves network data through io_uring can no longer be FAITHFUL. Runs of the measured runtimes are unaffected: Node.js's `EPOLL_CTL` submissions do not count. A file-only program that reads or writes registered files through io_uring is INCONCLUSIVE, the price of not resolving the ring's file table. The count says the net lane was blind for part of the run, not how many actions it missed. A capture written before this counter existed carries no `io_uring_net_ops` and reads as zero.
Alternatives rejected: Counting `io_uring_setup` alone (every Node.js child would make a run INCONCLUSIVE); counting every submitted operation (the same, through `EPOLL_CTL`); recording the operations as events (that is O-18's socket-layer rewrite, not a counter); resolving registered files through the ring's file table (kernel-version-specific layout for a case no measured runtime uses).
