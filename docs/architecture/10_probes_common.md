# Probes: common contract

Checked against commit c612b89 on 2026-10-08, with the changes in the commit that introduced P-17.

## Objective

agent-trace records what an agent did with three independent host probes: process (`pkg/probe/proc`, see [11_probe_proc.md](11_probe_proc.md)), filesystem (`pkg/probe/fs`, see [12_probe_fs.md](12_probe_fs.md)) and network (`pkg/probe/net`, see [13_probe_net.md](13_probe_net.md)). This page covers what the three share: the Go contract a probe implements, how `cmd/watch` drives them, the event and coverage records they produce, the clocks they stamp events with, the on-disk ground truth file, and the build rules for the eBPF programs. The verifier that consumes the file is described in [20_verifier.md](20_verifier.md).

## Structure

| File | Role |
|---|---|
| `pkg/probe/probe.go` | `probe.Observer` and `probe.CoverageReporter` interfaces |
| `cmd/watch/main.go` | `probeBuilders` registry, `runWatch`, `buildCoverage`; writes `ground_truth.json` |
| `pkg/models/action.go` | `ActionType` values, `IsClaimable`, `IsStructural` |
| `pkg/models/models.go` | `GroundTruthEvent`, `GroundTruth`, `ParseGroundTruth` |
| `pkg/models/coverage.go` | `ProbeCoverage`, `Coverage`, `GroundTruthFile`, `FSScope`, `ParseGroundTruthFile`, `CoverageSchema` |
| `pkg/verification/completeness.go` | `Assess`: turns coverage counters into Reasons (event loss) and Notes (content gaps) |

### The probe contract

`probe.Observer` has three methods. `Start()` begins emitting events in the background, `Stop() error` releases the probe's resources and closes the channel, and `Events() <-chan models.GroundTruthEvent` returns that channel. `probe.CoverageReporter` adds `CaptureCoverage() models.ProbeCoverage`, valid after `Stop` returns. It is a separate interface so `Observer` stays minimal, but `cmd/watch` refuses to run any probe that does not implement it: a probe that cannot report loss would otherwise be written into the coverage record as clean.

All three observers satisfy both interfaces. `proc.Observer` adds `SetRootPID`, and `net.Observer` adds `TrackPID`, `Coverage` and `TLSAttachError`; `cmd/watch` reaches these through type assertions.

### Per-object tracked set

The proc eBPF object (`proc.bpf.c`), the net object (`net.bpf.c`) and the TLS object (`tls.bpf.c`) each declare their own `tracked_pids` hash map. None is pinned or shared. Each object follows descendants itself: its `task_newtask` program (`handle_fork`) inserts the child's pid when the parent's tgid is in its map, and skips the event when `clone_flags` has `CLONE_THREAD`, since a thread shares an already tracked tgid. Each object's `sched_process_exit` program removes a tgid when the thread group leader exits (proc does this only for a process that has an `execs` entry, see [11_probe_proc.md](11_probe_proc.md)). The fs probe has no tracked set; it reports every event on the marked filesystems with the causing PID and leaves attribution to the verifier's forest. `cmd/watch` applies the scope rule afterwards (`scopeFSEvents`, P-17).

Each eBPF object also keeps its loss counters in one-slot `BPF_MAP_TYPE_PERCPU_ARRAY` maps: `drop_count` (ring buffer output failed), `untracked_count` (`tracked_pids` update failed) and, in proc and net, `state_lost_count` (a per-process or per-connection state map update failed). `tls.bpf.c` adds `faulted_reads`. Userspace sums the per-CPU slots (`sumPerCPU`) and snapshots them in `Stop()` before it closes the maps.

## Technologies

The eBPF probes use `github.com/cilium/ebpf` for loading, tracepoint and uprobe links and ring buffer readers. Each program is CO-RE C compiled against a committed `vmlinux.h`. `bpf2go` generates the Go bindings (`bpf_bpfel.go`, `bpf_bpfeb.go`, `tlsbpf_*.go`) and the matching `.o` objects, and both are committed, because the CI test job has no clang. The `//go:generate` lines sit in `pkg/probe/proc/observer.go` and `pkg/probe/net/generate.go`; after editing a `.bpf.c` file, run `go generate ./pkg/probe/proc/...` or `go generate ./pkg/probe/net/...` and commit the regenerated `.go` and `.o` files. The `-I/usr/include/x86_64-linux-gnu` flag ties generation to an x86_64 host, and `tls.bpf.c` is also built with `-D__TARGET_ARCH_x86`.

The CI job `bpf-freshness` in `.github/workflows/test.yml` regenerates `pkg/probe/proc` only and fails when a regenerated file other than a `.o` differs from the committed one. The net and TLS bindings have no such check.

The BPF verifier sets one invariant every program follows: a helper's size argument is a compile-time constant or is clamped against one immediately before the call. `net.bpf.c trace_connect` reads the address family with `sizeof(__u16)` and then the whole sockaddr with a per-family constant (16 or 28 bytes) rather than with `addrlen`, because stricter kernels reject a dynamic size even after masking. `proc.bpf.c handle_execve` masks the argv write offset with `MAX_ARGS_BYTES - 1` and pads the scratch buffer to twice that size, and `tls.bpf.c probe_ssl_write` clamps its length to `SSL_CAP_LEN`. A new program must keep to this, or it fails to load on some kernels.

The fs probe uses fanotify through `golang.org/x/sys/unix`; it has no eBPF component.

## Workflow

### How cmd/watch builds and starts probes

1. `runWatch` requires `--workspace` and root, and rejects `--root-pid` together with a trailing `-- <command>`.
2. It sets `AncestryPending` when an agent command or `--root-pid` is given, so the proc probe starts with an empty tracked set (`DeferRootPID`) instead of host-wide mode.
3. For each name in `--probes` (default `fs,proc`), it calls the builder in `probeBuilders`. Adding a probe means adding one entry there. Any probe that is not a `probe.CoverageReporter` aborts the run.
4. proc and net are held back. Every other probe (today only fs) gets a collector goroutine and is started at once.
5. In exec-wrap mode watch sleeps 200 ms, starts the agent with `exec.Command`, records its pid as `groundRoot`, calls `proc.Observer.SetRootPID(pid)`, starts proc, then calls `net.Observer.TrackPID(pid)` and runs `net.Observer.Start` in a goroutine (it blocks during TLS offset validation). After the agent exits (or on SIGINT/SIGTERM, which kills it) watch sleeps 300 ms so trailing events drain.
6. With `--root-pid N`, `groundRoot` is N and the same calls are made for N; watch records until a signal. With neither, `groundRoot` stays 0, proc runs host-wide (optionally narrowed by `--proc-filter`) and net is started with no tracked pid.
7. `stopEverything` stops the other probes, then net, then proc, and waits for the collectors.
8. `buildCoverage` asks every started probe for `CaptureCoverage()` and writes `ProbeCoverage{Ran: false}` for every known probe that was not selected.
9. watch prints the loss counters, runs `verification.Assess` and logs a warning with the Reasons when the capture is incomplete.
10. File events caused by `watch`'s own pid are dropped before anything else and never printed: the startup walk, the hash reads, and the writes of its own log, which on a marked filesystem would otherwise produce the event being printed, without end. The agent's stdout and stderr pass through `watch` on a pipe, so what the agent prints is not a file write by the agent. With an fs probe and a root pid, `scopeFSEvents` then keeps a file event when the agent's tree caused it (by the forest built from the fork records), wherever the path is, or when the path is under the workspace, whoever caused it; every other file event is counted and dropped. Non-file events are untouched. The rule runs here, after the capture, because the probe reads an event some time after the access, when a short-lived child has often already exited; the fork records have no such race.
11. Events are sorted by timestamp and written with `json.MarshalIndent` as a `models.GroundTruthFile`, with `fs_scope` saying which filesystems were marked and which rule was applied.

### Clocks

proc and net stamp records in the kernel with `bpf_ktime_get_ns()`, which counts from boot on `CLOCK_MONOTONIC`. Each observer computes `bootOffsetNs` once in `New` (`computeBootOffsetNs`: one `CLOCK_MONOTONIC` read followed by one wall-clock read) and converts every record with `time.Unix(0, ts_ns + bootOffsetNs)`. The offset is fixed for the probe's life, so NTP adjustments made during a run are not reflected. The fs probe stamps an event with `time.Now()` when userspace reads the batch from the fanotify fd, plus one nanosecond per record of the batch, so its timestamps carry read latency and order the records as the kernel delivered them, and a `FileClose` keeps the stamp of its record even though it is emitted after the settle window (P-18).

The two time sources differ in origin and latency, so the order of a file event against a process or network event is not reliable. The verifier therefore aligns each lane (fs, proc, net) separately (`pkg/verification.LaneOf`, `Align`) and uses timestamps only to choose between incarnations of a reused pid (`Forest.Resolve`), never to pair events.

### GroundTruthEvent

| Field | JSON | Set by |
|---|---|---|
| `Timestamp` | `timestamp` | all probes, see Clocks |
| `ActionType` | `action_type` | all probes |
| `Target` | `target` | all probes: command line, path, hostname, canonical URL, address or `unix:` name |
| `InputHash` | `input_hash` | fs, on `file_open` |
| `OutputHash` | `output_hash` | fs, on `file_close` when the settled hash is trusted |
| `ExitCode` | `exit_code` | proc, on `process_exit` when `exit_group` was seen |
| `PID` | `pid` | all probes; 0 means not recorded |
| `PPID` | `ppid` | proc only, on fork, exec and exit records |
| `IsTopLevel` | `is_top_level` | legacy: proc on exec and exit, net on `net_connect` and `net_request` (always true); fs leaves it nil |
| `PathIsAmbiguous` | `path_is_ambiguous` | fs, when only the parent directory resolved |
| `TargetTruncated` | `target_truncated` | proc, when the command line or the program path did not fit the record (P-19) |
| `RequestHash` | `request_hash` | net, on `net_request` with a body |

`process_fork`, `net_bind`, `net_listen` and `net_unix_connect` are ground truth only: `ActionType.IsClaimable` rejects them in a trajectory. `process_fork` is also structural (`IsStructural`): the verifier uses it to build the tree and neither aligns nor counts it. No probe emits `file_read`, `net_dns` or `git_commit`.

### ProbeCoverage

| Field | JSON | Producers | Meaning | `Assess` |
|---|---|---|---|---|
| `Ran` | `ran` | all | probe was started | a probe with `Ran=false` is skipped |
| `RingbufDrops` | `ringbuf_drops` | proc, net (net and TLS rings summed) | kernel ring buffer full, record discarded | Reason (event loss) |
| `UntrackedChildren` | `untracked_children` | proc, net (net and TLS maps summed) | `tracked_pids` full; a lower bound, one increment can be a whole subtree | Reason |
| `StateMapFull` | `state_map_full` | proc (`execs`), net (`conns`) | per-process or per-connection state map full | Reason |
| `ChannelDrops` | `channel_drops` | proc, net | Go events channel full; fs never drops (it blocks) | Reason |
| `QueueOverflow` | `queue_overflow` | fs | fanotify `FAN_Q_OVERFLOW` seen | Reason |
| `FaultedReads` | `faulted_reads` | net (TLS) | `SSL_write` plaintext read faulted | Note (content gap) |
| `Content` | `content` | net | `active`, `identity_only` or `attach_failed` | `attach_failed` is a Note |

Any Reason makes `Assess` return `Complete=false`, and the verifier then reports INCONCLUSIVE instead of FAITHFUL. Notes limit what content checks can say but do not make the event set incomplete. A nil coverage record (legacy file) is itself a Reason.

### ground_truth.json

```json
{
  "events": [ { "timestamp": "...", "action_type": "process_exec", "target": "/usr/bin/git status", "pid": 4242, "ppid": 4200, "is_top_level": true } ],
  "coverage": {
    "schema": 1,
    "probes": {
      "fs":   { "ran": true, "ringbuf_drops": 0, "untracked_children": 0, "state_map_full": 0, "channel_drops": 0 },
      "proc": { "ran": true, "ringbuf_drops": 0, "untracked_children": 0, "state_map_full": 0, "channel_drops": 0 },
      "net":  { "ran": false, "ringbuf_drops": 0, "untracked_children": 0, "state_map_full": 0, "channel_drops": 0 }
    }
  },
  "root_pid": 4200,
  "workspace": "/work/project",
  "fs_scope": { "rule": "tree-or-workspace", "mounts": ["/", "/tmp"], "unmarked": {"/run/user/1000/doc": "fanotify_mark on /run/user/1000/doc: invalid argument"}, "dropped_outside": 12 }
}
```

`models.ParseGroundTruthFile` accepts this object or the legacy form, a bare JSON array of events, which yields a nil coverage and a zero `root_pid`. It rejects a coverage `schema` other than `models.CoverageSchema` (1). `ParseGroundTruth` accepts only the bare array, so a caller that ignores coverage fails on the object form instead of silently dropping it. A zero `root_pid` means no tree can be built and the verifier cannot attribute events. `workspace` is the absolute directory the capture watched, written by `watch`; a baseline uses it to name that directory with a placeholder. `fs_scope` (`models.FSScope`) says which file events the capture can contain: the marked filesystems by mount point, those that could not be marked, the rule (`tree-or-workspace`, or `unfiltered` when there was no root pid), how many events the rule dropped, and `unresolved`, a count by action type of the file events whose path the probe could not resolve at all (a delete inside a tree being removed, whose parent was gone by the time it was read); those are not in `events`, since an event with no target cannot be aligned or attributed. A file without it predates the record and holds only paths under `workspace`, from any process. `watch` sorts events by timestamp with a stable sort, because events read in one batch share a timestamp and the verifier aligns by position.

## Guarantees and loss accounting

Every kernel-side failure that loses an event is counted where it happens, and `Assess` turns any non-zero loss counter into INCONCLUSIVE. Counters are read live while a probe runs and from a snapshot that `Stop` stores before closing the maps; the snapshot value is stored before an atomic "final" flag is raised, so a reader never sees a closed map.

### Adding a loss counter

1. In the `.bpf.c` file, declare a one-slot `BPF_MAP_TYPE_PERCPU_ARRAY` of `__u64` and increment it with `__sync_fetch_and_add` at the point where the helper call (`bpf_ringbuf_output`, `bpf_map_update_elem`, `bpf_probe_read_user`) returns non-zero.
2. Run `go generate` for the package and commit the regenerated `.go` and `.o` files.
3. In the observer, read it with `sumPerCPU` while running, and in `Stop`, after the readers have finished and before `objs.Close()`, store the final value and then raise the final flag.
4. Map it in `CaptureCoverage` to an existing `ProbeCoverage` field when the meaning is the same; otherwise add a field to `models.ProbeCoverage`.
5. Decide in `verification.Assess` whether it is event loss (append to `Reasons`) or a content gap (append to `Notes`). A new field that `Assess` does not read is ignored by the verdict.
6. Add it to the loss line `cmd/watch` prints.
7. Add a test that forces the counter non-zero through a test-only `Config` capacity override (the pattern of `RingbufBytes`, `TrackedPIDsMax`, `ExecsMax`, `ConnsMax`), a test that it stays zero when the map fits, and a case in `completeness_test.go`. Capacity overrides have no command-line flag.

## Known limits

- Each eBPF object tracks descendants independently, so the proc and net tracked sets can diverge when one map fills and the other does not.
- `cmd/watch` adds the root pid after `cmd.Start` returns, so a process the agent forks before `SetRootPID` or `TrackPID` runs is untracked and nothing counts it.
- In host-wide mode (no agent command and no `--root-pid`) the net probe tracks no pid, records nothing, and still reports `Ran=true` with no loss.
- The boot offset is computed once per probe, so wall-clock steps during a run shift kernel timestamps relative to fs timestamps.
- `IsTopLevel` is a legacy field still written by proc and net.
- CI checks the freshness of the proc bindings only; the net and TLS bindings can go stale without a failing job.
- Code generation assumes an x86_64 host.
