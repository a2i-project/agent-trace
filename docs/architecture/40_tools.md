# Command-line tools

Checked against commit d0e2c73 on 2026-10-06.

## Objective

Four commands turn the probes, adapters and verifier into a workflow: `watch` records ground truth while an agent runs, `baseline` measures a harness's own activity from control runs, `verify` compares a trajectory with a capture and prints a verdict, and `simagent` is a simulated agent that exercises the whole chain in tests. The probes are described in [10_probes_common.md](10_probes_common.md), the verifier in [20_verifier.md](20_verifier.md) and the adapters in [30_agent_adapters.md](30_agent_adapters.md).

## Structure

| Command | Source | Main function | Tests |
|---|---|---|---|
| `watch` | `cmd/watch/main.go` | `runWatch(watchOptions)`, `buildCoverage`, `probeBuilders` | `cmd/watch/main_test.go` |
| `verify` | `cmd/verify/main.go` | `run(args, out, errOut) int`, `chooseAdapter`, `report` | `cmd/verify/main_test.go` |
| `baseline` | `cmd/baseline/main.go` | `run(args, out, errOut) int` | `cmd/baseline/main_test.go` |
| `simagent` | `cmd/simagent/main.go` | `main` | driven by `tests/e2e` |

### watch

Launches or attaches to an agent, runs the selected probes, prints each event as it arrives, and writes the capture when recording ends.

| Flag | Default | Meaning |
|---|---|---|
| `--workspace PATH` | (required) | Directory the fs probe watches |
| `--probes LIST` | `fs,proc` | Comma-separated probes from `fs`, `proc`, `net` |
| `--proc-filter PREFIX` | empty | Only report processes whose command line has this prefix; replaced by ancestry scoping when a command or `--root-pid` is given |
| `--out PATH` | `ground_truth.json` | Output file |
| `--buf N` | 4096 | Per-probe event channel size |
| `--root-pid N` | 0 | Attach the ancestry root to a running process instead of launching one; needs the proc probe; exclusive with `-- <command>` |
| `--net-exe-path PATH` | empty | TLS library (for example `libssl.so.3`) for the `SSL_write` uprobe; empty means identity only |
| `--net-cache-path PATH` | `$TMPDIR/agent-trace-tlsoffset-cache.json` | Cache of computed TLS offsets |

Modes: with a trailing `-- <command> [args]`, `watch` starts the command, makes its pid the proc probe's ancestry root and the net probe's tracked pid, waits for it to exit (Ctrl+C kills it), waits 300 ms for trailing events and writes the file. With `--root-pid N` it attaches to that process and records until Ctrl+C; anything the process did before is invisible to the proc probe. With neither it records host-wide until Ctrl+C and writes `root_pid` as zero, which the verifier treats as INCONCLUSIVE.

`watch` requires root (fanotify and eBPF) and refuses a probe that does not implement `probe.CoverageReporter`. The output file is a `models.GroundTruthFile`: `events` sorted by timestamp, `coverage` with an entry for every known probe (`ran: false` for one not selected), and `root_pid`. On exit it prints each probe's loss counters and logs a warning when `verification.Assess` judges the capture incomplete.

| Exit code | When |
|---|---|
| 0 | Capture written |
| 1 | Any error (`log.Fatal`): missing workspace, not root, unknown probe, probe start failure, write failure. Also when the launched agent exits with an error, after the file has been written. |
| 2 | Flag parse error (Go `flag` default) |

### verify

Reads a trajectory through an adapter and a capture, runs `verification.Verify`, and prints the report.

| Flag | Default | Meaning |
|---|---|---|
| `--trajectory PATH` | (required) | The agent's own session file, or normalized trajectory JSON |
| `--ground-truth PATH` | (required) | Capture written by `watch` (object form, or a legacy bare array) |
| `--agent NAME` | detect | `claude-code`, `gemini` or `generic` |
| `--baseline PATH` | none | Baseline written by `baseline` |
| `--interval-slack D` | `500ms` | Widen each claim interval on both sides, because the probes and the agent do not share a clock |
| `--ignore-exits` | false | Do not align process exits even if the adapter's format records them |

Adapter choice: `--agent` selects by name (an unknown name is an error). Without it, `agent.Detect` runs; no match falls back to `generic`, and several matches are an error asking for `--agent`. A baseline whose `agent` differs from the chosen adapter's name is refused. Without a baseline, a non-generic adapter's report gains a degradation saying the harness's own activity will read as unexplained. `--ignore-exits` can only add to the adapter's choice: an adapter with `ExitsClaimed: false` always ignores exits.

The report, on standard output, contains in order: the inputs (entry count, adapter, event count, root pid, baseline rules and runs); the adapter `Report` (tool calls and claims, tools that produced no claim, unknown tools as a warning, parse errors, limitations); the alignment counts (Corroborated, Mismatched, Unwitnessed, Unrecorded, Outside interval, and an ambiguity note); the coverage counts (unexplained subtrees, events explained by a claimed command, by the baseline, quiet forks, outside events, unplaced events) and the capability count; the detail lists; the completeness judgement with notes; and the `VERDICT` line with the reasons when INCONCLUSIVE or advisory.

| Exit code | When |
|---|---|
| 0 | FAITHFUL |
| 1 | NOT FAITHFUL (advisory findings included) |
| 2 | INCONCLUSIVE |
| 3 | Usage or I/O error: missing flag, unknown agent, ambiguous detection, unreadable or invalid trajectory, ground truth or baseline, baseline for another agent. `-h` also exits 3. |

Exit 3 is separate from 1 so that a failure to verify can never be read as NOT FAITHFUL.

### baseline

Builds a harness baseline from control runs with `agent.Capture` and writes it with `agent.SaveBaseline`.

```
baseline --agent NAME --agent-version V [--out FILE] CONTROL_RUN.json...
```

| Flag | Default | Meaning |
|---|---|---|
| `--agent NAME` | (required) | Adapter that normalizes the runs |
| `--agent-version V` | (required) | Version of the agent that was run; a baseline holds for one version |
| `--out PATH` | `baseline.json` | Output file |
| `--min-agreement F` | `1` | Fraction of control runs that must perform an action for it to become a rule. Lower it for activity the harness does only sometimes, at the cost of a wider baseline (I-24). |

Each positional argument is a capture from `watch`. A run with no coverage record, with any loss counter set, or with no root pid is refused. On success it prints how many rules every run produced and how many unstable actions were left out, and warns when given a single run that one run cannot separate stable from incidental activity.

The baseline file is JSON: `schema` (1), `agent`, `agent_version`, `captured`, `runs`, `min_agreement`, `rules` and `unstable`, each rule an `action_type` and `target`. A target names the watched directory as `{workspace}`.

| Exit code | When |
|---|---|
| 0 | Baseline written |
| 3 | Usage error (missing flag or no runs, unknown agent, `-h`), unreadable or invalid capture, refused control run, write failure |

### simagent

A simulated agent that performs a fixed script of actions in a workspace and writes the trajectory it claims, in the normalized JSON form the generic adapter reads. It does not need root; `watch` does.

| Flag | Default | Meaning |
|---|---|---|
| `--workspace PATH` | (required) | Directory to act in |
| `--trajectory-out PATH` | (required) | Where to write the trajectory |
| `--file-only` | false | Skip the `wc` step, for runs with no proc probe |
| `--shell-cmd SCRIPT` | empty | Run `/bin/sh -c SCRIPT` (`{ws}` expands to the workspace) and claim only the shell's exec (with an interval) and exit, not what the script spawns |
| `--fetch-url URL` | empty | Make an HTTPS request and claim it |
| `--fetch-via-curl` | false | Make the request with a `curl` child (HTTP/1.1, pinned to one IPv4 address) and claim the curl exec and exit instead of the connection |
| `--fetch-method M`, `--fetch-body B` | `GET`, empty | Request method and body |
| `--emit-net-request` | false | Also claim a `net_request` with the body hash; refused with `--fetch-via-curl` |
| `--drop-entry N` | -1 | Remove claim N before writing |
| `--attack MODE` | empty | Tamper with the trajectory, below |

The fixed script, in claim order: write `file1.txt` (claimed in kernel order as `file_write` create, `file_open`, `file_write`, `file_close` with the content hash), rename it to `file2.txt` (`file_rename`), run `<abs path of wc> -l file2.txt` (`process_exec`, `process_exit` with its code) unless `--file-only`, the optional shell command, delete `file2.txt` (`file_delete`), then the optional fetch. Without `--fetch-via-curl` the request is made in-process over a single pinned IPv4 connection and claimed as `net_connect` to the host.

| `--attack` | Tampering | Expected finding |
|---|---|---|
| `omission` | Drop the first claim (only when `--drop-entry` is not set) | Unrecorded |
| `fabrication` | Append `process_exec /usr/bin/curl https://example.com` | Unwitnessed |
| `substitution-exit` | Add 1 to the first claimed exit code | Mismatched (`exit_code`) |
| `substitution-hash` | Replace the first `file_close` output hash with zeros | Mismatched (`output_hash`) |
| `substitution-cmd` | Append ` --fake-flag` to the first `process_exec` | Mismatched (`target`) |
| `net-omission` | Drop every `net_connect` claim | Unrecorded |
| `net-fabrication` | Append `net_connect ghost.example.invalid` | Unwitnessed |

An unrecognised `--attack` value is ignored. Exit codes: 0 on success, 1 on any failure (`log.Fatal`).

## Technologies

Go with the standard `flag` package. `watch` needs root for fanotify and the eBPF programs and links the probe packages; `verify` and `baseline` are unprivileged and read files only. `make build` builds all four binaries into the repository root.

## Workflow

### Record and verify the simulated agent

```sh
make build
mkdir -p /tmp/agent-trace-demo
sudo ./watch --workspace /tmp/agent-trace-demo --out ground_truth.json -- \
	./simagent --workspace /tmp/agent-trace-demo --trajectory-out trajectory.json
./verify --trajectory trajectory.json --ground-truth ground_truth.json
```

`verify` finds no adapter for the JSON trajectory and uses `generic`. Adding `--drop-entry 0` or an `--attack` mode to `simagent` turns the verdict into NOT FAITHFUL with the finding in the table above. Adding `--probes fs,proc,net --net-exe-path <libssl>` to `watch` and `--fetch-url ... --fetch-via-curl` to `simagent` exercises network content capture.

### Build a baseline for a real agent

1. Run the agent several times under `watch` on a task that claims nothing, with the same probes as the real run: `sudo ./watch --probes fs,proc,net --workspace "$PWD" --out runN.json -- <agent command>`.
2. Check each run reports no loss; `baseline` refuses one that does.
3. `./baseline --agent claude-code --agent-version <version> --out baseline.json run1.json run2.json run3.json`.
4. Read the `unstable` list: those actions will still read as unexplained if they appear in a real run.

### Verify a real agent session

```sh
sudo ./watch --probes fs,proc,net --workspace "$PWD" --out ground_truth.json -- claude -p "your task"
./verify --agent claude-code --trajectory <session>.jsonl \
         --ground-truth ground_truth.json --baseline baseline.json
```

Read the adapter section of the report before the verdict: unknown tools, parse errors and limitations bound what the verdict can mean. The exit code (0, 1, 2, 3) is the machine-readable result.

### Tests

`go test ./...` runs the unit tests; probe and end-to-end tests skip without root. `sudo go test -v ./...` runs everything. The end-to-end tests in `tests/e2e` build `simagent` themselves, run it under the probes with the flags each scenario needs, and assert the verdict.

## Guarantees and loss accounting

- `watch` writes a coverage entry for every known probe, so an unselected probe reads as not run, never as clean, and refuses to run a probe that cannot report its loss.
- `watch` writes the capture even when the agent fails, so a failing agent can still be verified.
- `verify` keeps verdicts (0 to 2) and errors (3) apart, and never guesses between two adapters.
- `baseline` refuses control runs that lost events or carry no coverage record, so a baseline cannot be short because of loss.

## Known limits

- `watch` exits 1 both for its own errors and for an agent that exited with an error, so its exit code does not separate the two.
- `watch` without a command or `--root-pid` records with `root_pid` zero, which `verify` can only report as INCONCLUSIVE.
- `watch --root-pid` misses whatever the process did before attaching.
- `verify` does not compare the baseline's `agent_version` with the agent that produced the session.
- `simagent` ignores an unknown `--attack` value instead of rejecting it.
- `simagent` covers one fixed script; it is not a substitute for a real agent session, and no real agent has been verified end to end yet.
