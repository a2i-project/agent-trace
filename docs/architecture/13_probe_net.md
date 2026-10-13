# Network probe

Checked against commit 2c648e7 on 2026-10-13.

## Objective

The network probe (`pkg/probe/net`) records which remote endpoints the agent's process tree contacted and, when content capture is enabled, which HTTP requests it sent over TLS. It has two layers. N0, identity, is `net.bpf.c`: syscall tracepoints that see connects, listeners, every send and the first bytes of each connection, from which userspace extracts the TLS SNI hostname. N1, content, is `tls.bpf.c`: a uprobe on `SSL_write` that captures plaintext before encryption, located by `pkg/tlsoffset` and parsed by `pkg/tlsparse`. The common contract, clocks and coverage format are in [10_probes_common.md](10_probes_common.md). The reasons behind the design are in [../decisions/network.md](../decisions/network.md) (N-D1 to N-D5, N-6 to N-25).

## Structure

| File | Contents |
|---|---|
| `net.bpf.c` | N0 programs: `trace_connect`, `trace_bind`, `trace_listen`, `trace_write`, `trace_sendto`, `trace_sendmsg`, `trace_sendmmsg`, `trace_writev`, `trace_pwritev2`, `trace_sendfile`, `trace_splice`, `trace_close`, `trace_dup2`, `trace_dup3`, `trace_iouring_submit`, `trace_iouring_setup`, `handle_fork`, `handle_exit`; helpers `fd_socket`, `file_last_ref`, `capture_hello`, `capture_hello_iov`, `mark_sent`, `release_fd`, `iouring_socket_only_op`, `iouring_data_op`, `iouring_target_may_be_socket` |
| `tls.bpf.c` | N1 programs: `probe_ssl_write` (uprobe), `handle_fork`, `handle_exit` |
| `generate.go` | the two `bpf2go` directives (`bpf`, `tlsbpf`) |
| `observer.go` | `Config`, `Observer`, `netTracepoints`, `iouringTracepoints`, `New`, `prepareTLS`, `attachAndValidateTLS`, `Start`, `Stop`, `TrackPID`, `Coverage`, `CaptureCoverage`, `correlate`, `flushOpenConnections`, `handleNetRecord`, `emit`, `emitListener`, `emitGroundTruthOnly`, `unixTarget` |
| `correlator.go` | `Coverage` struct, `handleSSLFrame`, `emitNetRequest`, `newestHostForTGID` |
| `pkg/tlsoffset` | `ScanELF` (find `SSL_write` candidates), `Cache` (validated offsets by ELF build ID) |
| `pkg/tlsparse` | `ParseClientHello` (SNI and ALPN), `Stream`, `ParseHTTP1` |
| `pkg/models/nettarget.go`, `bindexposure.go` | `CanonicalNetTarget`; `UnixTargetPrefix`, `UnboundListenTarget`, `ClassifyBindTarget` |

Kernel maps in `net.bpf.c`: `tracked_pids` (hash, 4096), `conns` (hash, 8192, keyed by socket inode number, N-24), `binds` (hash, 4096), `net_events` (ring buffer, 256 KiB), `heap`, and the counters `drop_count`, `untracked_count`, `state_lost_count`, `iouring_net_count`, `iouring_ops_count`, `iouring_setup_count`. In `tls.bpf.c`: its own `tracked_pids` (hash, 4096), `ssl_events` (ring buffer, 1 MiB), `ssl_heap`, `faulted_reads`, `drop_count`, `untracked_count`.

Record types in `net.bpf.c`: `NET_CONNECT` 1, `NET_HELLO` 2, `NET_BIND` 3, `NET_CLOSE` 4, `NET_SOCK_BIND` 5, `NET_SOCK_LISTEN` 6, `NET_UNIX_CONNECT` 7, `NET_SEND` 8. `NET_BIND` is never emitted and the observer ignores it, a leftover of the abandoned write-bracket join (N-D1). The header's `sock` field carries the socket inode number on `NET_CONNECT`, `NET_HELLO`, `NET_SEND` and `NET_CLOSE` and is 0 on the others; its `tgid` and `fd` are the caller's, which on a send or close need not be the process that connected.

`Config` fields: `TrackedPID`, `EventBufSize`, `ExePath` (enables N1), `CachePath` (default `$TMPDIR/agent-trace-tlsoffset-cache.json`), `ValidationTimeout` (default 5 s), and the test-only overrides `TrackedPIDsMax` and `ConnsMax`.

## Technologies

Syscall tracepoints, the `io_uring:io_uring_submit_req` tracepoint, and one uprobe through cilium/ebpf, two ring buffers, ELF parsing with `debug/elf`, x86_64 instruction pattern matching for the offset scan. See [10_probes_common.md](10_probes_common.md) for code generation and the constant-size rule.

## Workflow

### Scoping

Every program in both objects starts with `is_tracked(tgid)`. There is no host-wide mode: an observer with no tracked pid sees nothing. `TrackPID` writes the pid into the net map and, when N1 is loaded, into the TLS map. Each object then follows children through its own `handle_fork` (with the `CLONE_THREAD` guard) and removes exiting thread group leaders in `handle_exit`.

### N0: identity

1. `fd_socket` turns a descriptor into a socket (N-24): it reads `task->files->fdt`, checks the fd against `max_fds`, reads `fd[fd]`, and returns the file and `f_inode->i_ino` when `i_mode` says socket. All reads are CO-RE `bpf_probe_read_kernel`, which kernel 5.5 already provides for the `bpf_probe_read_user` calls; no newer kernel is required. Every connect, send and close hook below uses it, so a connection is found from any tracked process that holds it: a child after `fork`, a receiver of `SCM_RIGHTS`, or a duplicate descriptor.
2. `trace_connect` reads the address family with a 2-byte read. For `AF_UNIX` it reads `sun_path` (a pathname with `bpf_probe_read_user_str`, an abstract name with a fixed 108-byte read trimmed by `addrlen`) and emits `NET_UNIX_CONNECT`. For `AF_INET` or `AF_INET6` it reads 16 or 28 bytes and resolves the descriptor; a descriptor that is not a socket (the connect fails) is skipped, and a failed kernel read is counted in `state_lost_count`. It stores family, address, port, the connecting tgid and time in `conns` under the socket inode number and emits `NET_CONNECT`. Other families are ignored.
3. `trace_bind` records the address in `binds` and emits `NET_SOCK_BIND`; `AF_UNIX` binds carry the path in the payload. `trace_listen` looks the fd up in `binds` and emits `NET_SOCK_LISTEN` with that address, or with family 0 when the socket was never bound through `bind()`.
4. The send hooks (N-23) look the socket up in `conns`. `trace_write` and `trace_sendto` call `capture_hello` with their buffer. `trace_writev`, `trace_pwritev2` (offset -1 only; any other offset fails on a socket), `trace_sendmsg` and `trace_sendmmsg` (its first message) call `capture_hello_iov`, which concatenates up to eight iovecs (`HELLO_MAX_IOV`, an unrolled loop) to at most 1024 bytes. The first send with readable bytes on a connection emits `NET_HELLO` with up to 1024 bytes (`HELLO_CAP_LEN`) and marks the entry captured. `trace_sendfile` (`sendfile64`) and `trace_splice` (its `fd_out`) read no bytes and call `mark_sent`, which emits a header-only `NET_SEND` once per connection. A hello read that faults, or an iovec copy that yields no bytes, also emits `NET_SEND`, and the entry stays uncaptured so a later send gets another attempt. A zero-length send is ignored.
5. `trace_close`, and `trace_dup2` and `trace_dup3` for a `newfd` they replace (when `oldfd` is open and differs), call `release_fd`. It deletes the fd from `binds`. For a socket in `conns` it emits `NET_CLOSE` and deletes the entry only when the descriptor holds the last reference to the socket's file (`file_last_ref`: `f_ref` from kernel 6.13, `f_count` before, chosen by `bpf_core_field_exists`). While another descriptor still holds the socket, the entry stays, so a later send by that holder still marks it.

6. `trace_iouring_submit`, on `io_uring_submit_req`, runs once per operation a tracked process submits through io_uring, in the submitting task or the ring's SQPOLL thread (same thread group), before the operation runs (N-25). It counts every operation in `iouring_ops_count`, and a network operation in `iouring_net_count`: an opcode that works only on sockets (`SENDMSG`, `RECVMSG`, `ACCEPT`, `CONNECT`, `SEND`, `RECV`, `SHUTDOWN`, `SOCKET`, `SEND_ZC`, `SENDMSG_ZC`, `BIND`, `LISTEN`, `RECV_ZC`), or a data opcode (`READV`, `WRITEV`, `READ_FIXED`, `WRITE_FIXED`, `READ`, `WRITE`, `SPLICE`, `TEE`, `READ_MULTISHOT`, `READV_FIXED`, `WRITEV_FIXED`) whose target may be a socket. `iouring_target_may_be_socket` reads the low byte of `req->flags` and `req->cqe.fd` (CO-RE, each guarded by `bpf_core_field_exists`): a registered file (`IOSQE_FIXED_FILE`), a missing field or a failed read counts, a negative fd does not, and otherwise `fd_socket` decides. The tracepoint context is a handwritten struct (opcode at offset 32), so a kernel without the event has nothing to relocate. `trace_iouring_setup`, on `sys_enter_io_uring_setup`, counts the rings tracked processes set up. Nothing is emitted: the operations are not recorded (O-18). `New` attaches both through `iouringTracepoints` and skips one whose tracepoint does not exist; when `io_uring_submit_req` is missing and the setup tracepoint is present, `Coverage` adds every ring to `IOURingNetOps`.

Userspace (`correlate`, a single goroutine fed by `netFeed` and `sslFeed`) keeps a `connection` per socket inode number (the header's `sock`), holding the tgid that connected. Every event of a connection carries that tgid as `PID`, whichever process sent or closed (`TestHandleNetRecord_RecordsFromAnotherProcessFollowTheSocket`).

- `NET_CONNECT` opens the entry and counts `Connections`. An entry already open for the same socket and not yet emitted belongs to a socket connected again (a datagram socket pointed at a new peer); it is emitted first, stamped with its connect time and by the same rules as at a close, and counted in `Coverage.Replaced` (`TestHandleNetRecord_ReplacedConnectionIsEmitted`).
- `NET_SEND` marks the entry as written (`wrote`).
- `NET_HELLO` marks the entry as written and runs `tlsparse.ParseClientHello`. With an SNI name it stores host and ALPN, counts `WithHostname` (and `ContentUnsupported` when ALPN offers `h2`), and emits `net_connect` with the hostname as `Target`, stamped at the hello.
- `NET_CLOSE` (the last tracked descriptor closed, or replaced by `dup2` or `dup3`: `TestObserver_ConnectionClosedByDup2IsEmitted`) emits a connection that has not been emitted yet, stamped at the close: `net_connect` with `ip:port` as `Target` if a `NET_HELLO` was received for it, or a `NET_SEND`, or `net_dial` with the same target, ground truth only, if neither was (the losing half of a dual-stack connect, a probe; N-22). A send through any hooked path by any tracked holder counts (N-23: `TestObserver_SendsWithoutWriteAreConnections`, `TestObserver_HelloAcrossIovecsYieldsSNI`, `TestObserver_ForkedChildWriteMarksConnection`, `TestObserver_SCMRightsReceiverWriteMarksConnection`). `Coverage.Dials` counts the latter.
- When both feeders have closed, `flushOpenConnections` emits every connection still open, in connect order and stamped with its connect time, and counts them in `Coverage.OpenAtStop` (N-21).
- `emit` turns a connection to port 53 into `net_dns` with the `ip:port` target, ground truth only like a listener (N-20), and counts it in `Coverage.DNS`; a connection to port 0 (the resolver's source-address selection, N-19) is counted in `Coverage.AddressProbes` and not emitted. Both are marked emitted so their close does not retry.
- `NET_SOCK_BIND` and `NET_SOCK_LISTEN` become `net_bind` and `net_listen` with target `host:port` (IPv6 in brackets), `unix:<path>`, `unix:@<abstract>` or `unbound`. `NET_UNIX_CONNECT` becomes `net_unix_connect`. These types, with `net_dns` and `net_dial`, are ground truth only; `models.ClassifyBindTarget` grades a listener as loopback, wildcard, interface, local socket or unknown.

Every N0 event carries `PID` (the tgid; for a connection, the tgid that connected). None carries `PPID`.

### N1: content

1. `prepareTLS` (in `New`, when `ExePath` is set) calls `tlsoffset.ScanELF`. It returns the `SSL_write` symbol if present; otherwise it finds the `ssl_lib.cc` string, scans `.text` for RIP-relative `lea` and absolute-immediate references to it, walks back to each referencing function's start (`endbr64` after padding, or the byte after `int3` padding), and ranks functions by reference count. A cached offset for the ELF build ID is tried first. It then loads `tls.bpf.c`, opens the executable and the `ssl_events` reader, and attaches the TLS fork and exit tracepoints.
2. `Start` runs `correlate` and then `attachAndValidateTLS`, which blocks. For each candidate it attaches `probe_ssl_write` at that file offset and waits up to `ValidationTimeout` for one frame from a tracked process. The candidate is accepted only if the frame matches `^[A-Z]{2,10} \S+ HTTP/1\.[01]\r\n` (runtime validation is authoritative, N-D4). The accepted offset is stored in the cache, and the validating frame is replayed into the correlator so a single write is not lost. If no candidate validates, N1 is disabled, `TLSAttachError` explains whether frames arrived at all, and the probe continues identity-only.
3. `probe_ssl_write` reads `buf` and `num` from the second and third arguments, copies up to 16 KiB (`SSL_CAP_LEN`) and emits an `ssl_frame` with tgid, tid and time. A faulting read increments `faulted_reads` and emits nothing (N-D5).
4. `handleSSLFrame` appends each frame to a `tlsparse.Stream` per (tgid, tid) and calls `ParseHTTP1` until it needs more bytes. A malformed request discards that thread's buffer and counts `FramesUnattributed`.
5. `emitNetRequest` takes the host from the `Host` header, or from the newest SNI hostname of the same tgid when the header is absent, and counts `FramesUnattributed` when neither exists. It emits `net_request` with `Target` = `models.CanonicalNetTarget(method, host, port, path, query)` (form `METHOD https://host[:port]path[?query]`, host lowercased, port omitted when 443) and `RequestHash` = SHA-256 of the body when there is one. The plaintext is not kept (N-D3).

`Coverage` (in `correlator.go`) holds the diagnostic counts `Connections`, `DNS`, `AddressProbes`, `OpenAtStop`, `Replaced`, `Dials`, `WithHostname`, `WithContent`, `FramesUnattributed`, `ContentUnsupported`, `IOURingOps`, `IOURingRings`, plus the kernel loss counters. `cmd/watch` prints the first ten; only the loss counters reach `ProbeCoverage`.

## Guarantees and loss accounting

The hostname comes from the ClientHello the client sent, so it needs no plaintext and no cooperation from the agent, and it works for any TLS client. Request content is hashed, never stored.

| Counter | Incremented when | Coverage field |
|---|---|---|
| net and TLS `drop_count` | a ring buffer output fails | `RingbufDrops` (summed) |
| net and TLS `untracked_count` | a child cannot enter a `tracked_pids` map | `UntrackedChildren` (summed) |
| net `state_lost_count` | a `conns` update fails, or a connect's descriptor cannot be resolved to its socket, so the connection gets no hello and no close and is never emitted | `StateMapFull` |
| net `iouring_net_count` | a tracked process submits an io_uring network operation, or a data operation on a registered file or an unreadable target (N-25); every ring set up, on a kernel without `io_uring_submit_req` | `IOURingNetOps` |
| `Dropped` (userspace) | the events channel is full | `ChannelDrops` |
| `faulted_reads` | an `SSL_write` buffer read faults | `FaultedReads` |
| N1 state | `ExePath` empty, attach failed, or active | `Content` |

Which of these fields `Assess` reads as event loss and which as a content gap is in [10_probes_common.md](10_probes_common.md#probecoverage).

## Known limits

- All N0 hooks are `sys_enter_*` tracepoints, so socket operations submitted through io_uring or Linux AIO (`io_submit`) are not recorded. A connection without a name whose data went only that way is emitted as `net_dial`: capability evidence, never aligned and never a finding (N-22, O-18). io_uring network operations by tracked processes are counted in `IOURingNetOps`, which makes the run INCONCLUSIVE (N-25); Linux AIO is not counted.
- `IOURingNetOps` also counts a read or write of a registered (fixed) file through io_uring, since the probe does not resolve the ring's file table, so a file-only program that uses registered files makes the run INCONCLUSIVE. A `SPLICE` or `TEE` is classified by its output descriptor only. `IORING_OP_URING_CMD` (socket options among other commands) is not counted.
- On a kernel without the `io_uring_submit_req` tracepoint, every io_uring ring a tracked process sets up counts in `IOURingNetOps`, whatever it was used for.
- A capture written before `IOURingNetOps` existed has no `io_uring_net_ops` field, which reads as zero.
- Only tracked processes are hooked. A connection whose descriptor leaves the tracked tree (passed over `SCM_RIGHTS` to an outside process) and is written only there is a `net_dial`.
- The send hooks fire at syscall entry, so a send that then fails still marks the connection as written.
- `sendfile` and `splice` mark a connection written without reading its bytes, so a ClientHello sent that way yields no name and the connection is reported by address.
- The hello is read from at most eight iovecs (`writev`, `pwritev2`, `sendmsg`, and the first message of `sendmmsg`). When the copied iovecs are all empty, the connection is marked written with no hello, and a later send gets a capture attempt.
- The hello capture is 1024 bytes; an SNI extension beyond that is lost and the connection is reported by address.
- A faulted hello read emits `NET_SEND`, so the connection counts as written, but the fault itself has no counter.
- A connection to port 53 is capability evidence, never a finding: an agent can move data over it and the report shows it, but no trajectory can claim it. Address-selection probes to port 0 are counted and not recorded.
- UDP is not tracked: `sendto` with an address on an unconnected socket creates no connection, so QUIC and HTTP/3 are invisible.
- No byte counts or response data are recorded.
- Encrypted Client Hello would hide the SNI name.
- `connect` is recorded at syscall entry, so a failed connect still appears as a connection.
- A connection without SNI is emitted when its last tracked descriptor closes (`close`, `dup2`, `dup3`), or at the end of the capture otherwise, then with its connect time; `Coverage.OpenAtStop` counts every connection emitted at the end, whatever type it became. The end of the capture is where a connection lands when its last reference goes without a hooked call: process exit, `close_range`, an exec under `O_CLOEXEC`, a holder outside the tracked tree, or a message carrying the descriptor that is never received. It is late but not lost (N-21, N-24).
- The last-reference test reads the file's reference count, which a syscall running at that moment in another thread on the same socket also holds. A close during such a call is not seen as the last, and the connection is emitted at the end of the capture.
- `conns` entries for sockets released without a hooked call are never deleted in the kernel and occupy a slot until the probe stops.
- `net_connect` is stamped at the hello or the close, not at the connect, except for a connection emitted at the end of the capture or when a new connect replaced it, which carries its connect time.
- Only `SSL_write` entry is hooked: there is no `SSL_read`, so responses (including server-side tool results) are not seen.
- `SSL_write` capture is capped at 16 KiB per call.
- Content is parsed as HTTP/1.1 only; an h2 connection is counted in `ContentUnsupported` and its frames end in `FramesUnattributed` or stay buffered, producing no `net_request`.
- Offset validation needs an HTTP/1.x request from a tracked process within the timeout, so an h2-only client cannot enable N1.
- Attribution of a request to a host relies on the `Host` header and per-thread reassembly, with no join from `SSL*` to the socket.
- The per-thread reassembly buffer has no size bound.
- `trace_sendmsg`, `trace_sendmmsg`, `trace_writev` and `trace_pwritev2` assume the x86_64 user layout of `msghdr`, `mmsghdr` and `iovec`, the hooks use the x86_64 tracepoint argument layout (`sys_enter_dup2` exists only there and on a few other architectures), and `probe_ssl_write` assumes the x86_64 calling convention.
- AF_UNIX pathnames are reported as given, not resolved against the caller's working directory.
- No `PPID` is recorded, so network events rely on proc fork and exec records for placement in the tree.
