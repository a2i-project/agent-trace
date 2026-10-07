# Network probe

Checked against commit d0e2c73 on 2026-10-06.

## Objective

The network probe (`pkg/probe/net`) records which remote endpoints the agent's process tree contacted and, when content capture is enabled, which HTTP requests it sent over TLS. It has two layers. N0, identity, is `net.bpf.c`: syscall tracepoints that see connects, listeners and the first bytes of each connection, from which userspace extracts the TLS SNI hostname. N1, content, is `tls.bpf.c`: a uprobe on `SSL_write` that captures plaintext before encryption, located by `pkg/tlsoffset` and parsed by `pkg/tlsparse`. The common contract, clocks and coverage format are in [10_probes_common.md](10_probes_common.md). The reasons behind the design are in [../decisions/network.md](../decisions/network.md) (N-D1 to N-D5).

## Structure

| File | Contents |
|---|---|
| `net.bpf.c` | N0 programs: `trace_connect`, `trace_bind`, `trace_listen`, `trace_write`, `trace_sendto`, `trace_sendmsg`, `trace_close`, `handle_fork`, `handle_exit` |
| `tls.bpf.c` | N1 programs: `probe_ssl_write` (uprobe), `handle_fork`, `handle_exit` |
| `generate.go` | the two `bpf2go` directives (`bpf`, `tlsbpf`) |
| `observer.go` | `Config`, `Observer`, `New`, `prepareTLS`, `attachAndValidateTLS`, `Start`, `Stop`, `TrackPID`, `Coverage`, `CaptureCoverage`, `correlate`, `handleNetRecord`, `emit`, `emitListener`, `unixTarget` |
| `correlator.go` | `Coverage` struct, `handleSSLFrame`, `emitNetRequest`, `newestHostForTGID` |
| `pkg/tlsoffset` | `ScanELF` (find `SSL_write` candidates), `Cache` (validated offsets by ELF build ID) |
| `pkg/tlsparse` | `ParseClientHello` (SNI and ALPN), `Stream`, `ParseHTTP1` |
| `pkg/models/nettarget.go`, `bindexposure.go` | `CanonicalNetTarget`; `UnixTargetPrefix`, `UnboundListenTarget`, `ClassifyBindTarget` |

Kernel maps in `net.bpf.c`: `tracked_pids` (hash, 4096), `conns` (hash, 8192, keyed by tgid and fd), `binds` (hash, 4096), `net_events` (ring buffer, 256 KiB), `heap`, and the counters `drop_count`, `untracked_count`, `state_lost_count`. In `tls.bpf.c`: its own `tracked_pids` (hash, 4096), `ssl_events` (ring buffer, 1 MiB), `ssl_heap`, `faulted_reads`, `drop_count`, `untracked_count`.

Record types in `net.bpf.c`: `NET_CONNECT` 1, `NET_HELLO` 2, `NET_BIND` 3, `NET_CLOSE` 4, `NET_SOCK_BIND` 5, `NET_SOCK_LISTEN` 6, `NET_UNIX_CONNECT` 7. `NET_BIND` is never emitted and the observer ignores it; the header's `seq` field is always 0. Both are left over from the abandoned write-bracket join (N-D1).

`Config` fields: `TrackedPID`, `EventBufSize`, `ExePath` (enables N1), `CachePath` (default `$TMPDIR/agent-trace-tlsoffset-cache.json`), `ValidationTimeout` (default 5 s), and the test-only overrides `TrackedPIDsMax` and `ConnsMax`.

## Technologies

Syscall tracepoints and one uprobe through cilium/ebpf, two ring buffers, ELF parsing with `debug/elf`, x86_64 instruction pattern matching for the offset scan. See [10_probes_common.md](10_probes_common.md) for code generation and the constant-size rule.

## Workflow

### Scoping

Every program in both objects starts with `is_tracked(tgid)`. There is no host-wide mode: an observer with no tracked pid sees nothing. `TrackPID` writes the pid into the net map and, when N1 is loaded, into the TLS map. Each object then follows children through its own `handle_fork` (with the `CLONE_THREAD` guard) and removes exiting thread group leaders in `handle_exit`.

### N0: identity

1. `trace_connect` reads the address family with a 2-byte read. For `AF_UNIX` it reads `sun_path` (a pathname with `bpf_probe_read_user_str`, an abstract name with a fixed 108-byte read trimmed by `addrlen`) and emits `NET_UNIX_CONNECT`. For `AF_INET` or `AF_INET6` it reads 16 or 28 bytes, stores family, address, port and time in `conns`, and emits `NET_CONNECT`. Other families are ignored.
2. `trace_bind` records the address in `binds` and emits `NET_SOCK_BIND`; `AF_UNIX` binds carry the path in the payload. `trace_listen` looks the fd up in `binds` and emits `NET_SOCK_LISTEN` with that address, or with family 0 when the socket was never bound through `bind()`.
3. `trace_write`, `trace_sendto` and `trace_sendmsg` (first iovec only) call `capture_hello`. On the first write to a fd that has a `conns` entry, it copies up to 1024 bytes (`HELLO_CAP_LEN`), emits `NET_HELLO` and marks the entry captured. If the user read faults, the record is dropped and the entry stays uncaptured, so a later write gets another attempt.
4. `trace_close` deletes the fd from `binds`, emits `NET_CLOSE` for a fd in `conns`, and deletes the `conns` entry.

Userspace (`correlate`, a single goroutine fed by `netFeed` and `sslFeed`) keeps a `connection` per (tgid, fd):

- `NET_CONNECT` opens the entry and counts `Connections`.
- `NET_HELLO` runs `tlsparse.ParseClientHello`. With an SNI name it stores host and ALPN, counts `WithHostname` (and `ContentUnsupported` when ALPN offers `h2`), and emits `net_connect` with the hostname as `Target`, stamped at the hello.
- `NET_CLOSE` emits `net_connect` for a connection that has not been emitted yet, with `ip:port` as `Target`, stamped at the close.
- `emit` skips any connection to port 53 (DNS) or port 0 (the resolver's source-address selection, N-19) and marks it emitted, without counting it.
- `NET_SOCK_BIND` and `NET_SOCK_LISTEN` become `net_bind` and `net_listen` with target `host:port` (IPv6 in brackets), `unix:<path>`, `unix:@<abstract>` or `unbound`. `NET_UNIX_CONNECT` becomes `net_unix_connect`. These three types are ground truth only; `models.ClassifyBindTarget` grades a listener as loopback, wildcard, interface, local socket or unknown.

Every N0 event carries `PID` (the tgid). None carries `PPID`.

### N1: content

1. `prepareTLS` (in `New`, when `ExePath` is set) calls `tlsoffset.ScanELF`. It returns the `SSL_write` symbol if present; otherwise it finds the `ssl_lib.cc` string, scans `.text` for RIP-relative `lea` and absolute-immediate references to it, walks back to each referencing function's start (`endbr64` after padding, or the byte after `int3` padding), and ranks functions by reference count. A cached offset for the ELF build ID is tried first. It then loads `tls.bpf.c`, opens the executable and the `ssl_events` reader, and attaches the TLS fork and exit tracepoints.
2. `Start` runs `correlate` and then `attachAndValidateTLS`, which blocks. For each candidate it attaches `probe_ssl_write` at that file offset and waits up to `ValidationTimeout` for one frame from a tracked process. The candidate is accepted only if the frame matches `^[A-Z]{2,10} \S+ HTTP/1\.[01]\r\n` (runtime validation is authoritative, N-D4). The accepted offset is stored in the cache, and the validating frame is replayed into the correlator so a single write is not lost. If no candidate validates, N1 is disabled, `TLSAttachError` explains whether frames arrived at all, and the probe continues identity-only.
3. `probe_ssl_write` reads `buf` and `num` from the second and third arguments, copies up to 16 KiB (`SSL_CAP_LEN`) and emits an `ssl_frame` with tgid, tid and time. A faulting read increments `faulted_reads` and emits nothing (N-D5).
4. `handleSSLFrame` appends each frame to a `tlsparse.Stream` per (tgid, tid) and calls `ParseHTTP1` until it needs more bytes. A malformed request discards that thread's buffer and counts `FramesUnattributed`.
5. `emitNetRequest` takes the host from the `Host` header, or from the newest SNI hostname of the same tgid when the header is absent, and counts `FramesUnattributed` when neither exists. It emits `net_request` with `Target` = `models.CanonicalNetTarget(method, host, port, path, query)` (form `METHOD https://host[:port]path[?query]`, host lowercased, port omitted when 443) and `RequestHash` = SHA-256 of the body when there is one. The plaintext is not kept (N-D3).

`Coverage` (in `correlator.go`) holds the diagnostic counts `Connections`, `WithHostname`, `WithContent`, `FramesUnattributed`, `ContentUnsupported`, plus the kernel counters. `cmd/watch` prints them; only the kernel counters reach `ProbeCoverage`.

## Guarantees and loss accounting

The hostname comes from the ClientHello the client sent, so it needs no plaintext and no cooperation from the agent, and it works for any TLS client. Request content is hashed, never stored.

| Counter | Incremented when | Coverage field | `Assess` |
|---|---|---|---|
| net and TLS `drop_count` | a ring buffer output fails | `RingbufDrops` (summed) | event loss |
| net and TLS `untracked_count` | a child cannot enter a `tracked_pids` map | `UntrackedChildren` (summed) | event loss |
| net `state_lost_count` | a `conns` update fails, so the connection gets no hello and no close and is never emitted | `StateMapFull` | event loss |
| `Dropped` (userspace) | the events channel is full | `ChannelDrops` | event loss |
| `faulted_reads` | an `SSL_write` buffer read faults | `FaultedReads` | note |
| N1 state | `ExePath` empty, attach failed, or active | `Content` | `attach_failed` is a note |

## Known limits

- All N0 hooks are `sys_enter_*` tracepoints, so socket operations submitted through io_uring are invisible.
- `writev` is not hooked and `sendmsg` inspects only its first iovec, so a ClientHello sent that way can be missed.
- The hello capture is 1024 bytes; an SNI extension beyond that is lost and the connection is reported by address.
- A faulted hello read is dropped without a counter.
- Connections to port 53 and port 0 are discarded without a counter, so DNS traffic and address-selection probes are not recorded.
- UDP is not tracked: `sendto` with an address on an unconnected socket creates no connection, so QUIC and HTTP/3 are invisible.
- No byte counts or response data are recorded.
- Encrypted Client Hello would hide the SNI name.
- `connect` is recorded at syscall entry, so a failed connect still appears as a connection.
- A connection without SNI is emitted only on `close()`; one still open when capture stops, or closed implicitly at process exit, is never emitted and nothing counts it.
- `conns` entries for fds closed implicitly at process exit are never deleted in the kernel.
- `net_connect` is stamped at the hello or the close, not at the connect.
- Only `SSL_write` entry is hooked: there is no `SSL_read`, so responses (including server-side tool results) are not seen.
- `SSL_write` capture is capped at 16 KiB per call.
- Content is parsed as HTTP/1.1 only; an h2 connection is counted in `ContentUnsupported` and its frames end in `FramesUnattributed` or stay buffered, producing no `net_request`.
- Offset validation needs an HTTP/1.x request from a tracked process within the timeout, so an h2-only client cannot enable N1.
- Attribution of a request to a host relies on the `Host` header and per-thread reassembly, with no join from `SSL*` to the socket.
- The per-thread reassembly buffer has no size bound.
- `trace_sendmsg` assumes the x86_64 user layout of `msghdr` and `iovec`, and `probe_ssl_write` the x86_64 calling convention.
- AF_UNIX pathnames are reported as given, not resolved against the caller's working directory.
- No `PPID` is recorded, so network events rely on proc fork and exec records for placement in the tree.
