# Architecture notes

Implementation detail that the README leaves out. The verification model itself is specified in the design documents kept with the project's local planning notes; this file records what is built and the constraints a user or contributor will run into.

## Components

`watch` builds the requested probes, launches the agent, and records its pid as the root of the process tree. It writes a ground truth file holding the events, a coverage record, and the root pid. `verify` reads that file and a trajectory and runs `pkg/verification`. `simagent` is a stand-in agent that performs real file, process and network actions and emits a matching trajectory.

## Probes

- **Filesystem** (`pkg/probe/fs`): `fanotify` events, each carrying the causing pid. Content hashes are taken at open and at close. A close is held briefly until it is known not to be superseded by another write, so its hash is of the final content.
- **Process** (`pkg/probe/proc`): eBPF tracepoints on `execve`, process exit and `task_newtask`. It emits exec and exit records with the command line as the kernel resolved it, and a fork record for every non-thread child of a tracked process so that a process that never execs still appears in the tree. Threads are excluded.
- **Network** (`pkg/probe/net`): eBPF tracepoints on connect, bind and listen, for TCP and Unix sockets. With a `libssl` path, an `SSL_write` uprobe captures request plaintext, which is parsed as HTTP/1.x to give a canonical target and a request body hash. The tracked set is inherited across fork, so a command's children are seen.

Each probe reports loss counters (kernel ring buffer drops, state map exhaustion, tracked-set overflow, channel drops, fanotify queue overflow). The verifier treats any non-zero counter as incomplete ground truth.

## Verification

1. `BuildForest` builds the process tree from fork records, falling back to exec records for older ground truth.
2. `Partition` attributes each event by pid and ancestry. The aligned sequence is the agent's own events plus each level-1 command's first exec and its exit. Everything else under a command is content of that command.
3. `Align` aligns claims against the aligned sequence one lane at a time (file, process, network), because the probes use different clocks and cross-lane order is not reliable. Pairing is by position, then content is compared, so a substituted target is one finding rather than a fabrication plus an omission. Claims must therefore be in the order the probe reports events. For files that is create, open, modify, close.
4. `CheckCoverage` reports commands no claim explains, with a quiet-fork exception: a process that never execs and causes no event has nothing to explain.
5. `Verify` combines them. Findings are mismatches, fabrications, omissions, an action outside its claim's time interval, and unexplained subtrees. Time orders events and never pairs them.

A missing field in a claim is a finding only where the trajectory format can state that field and the probe captured it. `Options.Expresses` is where an adapter declares which fields it can state.

## Constraints on network content capture

These apply to any agent verified at content level.

- Capture parses `SSL_write` plaintext as HTTP/1.x. Over HTTP/2 the plaintext is framed differently, so no request is recovered and a claim for it is unwitnessed. `simagent` passes `--http1.1` to `curl` for this reason.
- A host with several addresses can make a client open parallel connections, and the ones that lose complete no handshake and carry no hostname. `simagent` pins `curl` to one resolved IPv4 address with `--resolve` to avoid unclaimed connections.
- A statically linked TLS stack (Go's `crypto/tls`, `rustls` in a static binary) has no `SSL_write` symbol to attach to. Those connections are still seen at the identity level (address and SNI).

## Regenerating eBPF bindings

`make generate` runs `go generate` for the proc and net probes. CI regenerates the bindings and fails if the committed files differ, so commit regenerated output with the source change.
