# Agent-Trace: Trajectory Faithfulness Verifier

[![Tests](https://github.com/a2i-project/agent-trace/actions/workflows/test.yml/badge.svg)](https://github.com/a2i-project/agent-trace/actions/workflows/test.yml)

AI agents report what they did in a trajectory log. If the agent is compromised, hallucinating or hiding something, that log cannot be trusted by itself.

**Agent-Trace** checks a trajectory against what the host actually observed. Probes in the kernel record file, process and network activity independently of the agent, and a verifier compares that record with the agent's claims.

## How verification works

1. **Observe.** `watch` runs the agent and records a **ground truth**: every file, process and network event, each stamped with the process that caused it, plus a record of anything the probes may have lost.
2. **Build the process tree.** Events are attributed by process ancestry, never by timestamp. What the agent does itself is level 0. Each command it starts is the root of a subtree, and everything that command's descendants do belongs to that command.
3. **Run two checks.**
   - *Alignment:* the agent's claims are aligned, in order, against the top-level actions the agent itself took (its own events plus each command it started). A fabricated claim, an unreported action, and a claim whose target or content differs from what happened are reported separately.
   - *Coverage:* every observed event must be explained by a claim, by a claimed command's subtree, or by the harness baseline. A command nothing claims is reported with everything beneath it.
4. **Conclude.**

| Outcome | Exit code | Meaning |
|---|---|---|
| FAITHFUL | 0 | Both checks passed and the capture lost nothing. |
| NOT FAITHFUL | 1 | A discrepancy was found. Marked advisory if the capture also lost events. |
| INCONCLUSIVE | 2 | No discrepancy found, but FAITHFUL cannot be asserted: events were lost, the capture has no coverage record or root pid, or an event could not be attributed. |
| (error) | 3 | `verify` could not run: bad arguments, an unreadable file or a baseline for another agent. |

The agent claims commands, not what they do. A listener a command opens, or a connection it makes, is counted as capability evidence and shown in the report, but it is not a claim to corroborate.

## What it does not prove

A faithful verdict says that the agent's top-level claims are true and that nothing observable happened outside them. It does not say that what a claimed command did was benign. An agent that writes `helper.sh` and runs it produces a fully faithful trajectory whatever the script does. The report makes that visible (the command's subtree and capability evidence are listed), but judging it is out of scope. The probes and the host kernel are the trust boundary: an attacker with root on the host can defeat them.

## Status

| Component | State |
|---|---|
| Filesystem probe (`fanotify`): opens, writes, closes, renames, deletes, with SHA-256 of contents | done |
| Process probe (eBPF): exec, exit code, fork edges, parent pid | done |
| Network probe (eBPF): connections with TLS SNI, request body hash via an `SSL_write` uprobe, listeners and Unix sockets | done |
| Verification: process tree, alignment, coverage, baseline hook, outcome rules | done |
| Agent adapters: Claude Code (JSONL, subagents, command-wrapper recovery) and Gemini (SQLite and protobuf, fails loudly when a field moves) | implemented, not yet checked against a real capture |
| Harness baseline from control runs (`baseline`) | implemented, no baseline captured yet |
| Attack generator suite | planned |

The verifier is tested against a simulated agent (`cmd/simagent`) only. The adapters read real session formats and are tested on fixtures and for robustness against real transcripts, but no real agent has been captured and verified end to end, so what a real session's file tools do at the kernel level is still a hypothesis in the adapters. Nothing here is evaluated on real agents yet.

## Requirements

- Go 1.26 or later
- Linux with eBPF support
- Root, to run the probes and their tests (they use `fanotify` and load eBPF programs)
- `clang` and kernel headers, only to regenerate the eBPF bindings
- A dynamically linked `libssl` (the one `curl` uses), only for network content capture

## Build and test

```sh
make build            # watch, verify, simagent in the repo root
make generate         # regenerate eBPF bindings after editing a .bpf.c file
go test ./...
```

Without root, the probe and end-to-end tests skip rather than fail, so an unprivileged run is not a full signal. For the full suite:

```sh
sudo go test -v ./...
```

## Quickstart

`watch` launches the agent, records its process tree, and writes `ground_truth.json` when the agent exits. `simagent` is a simulated agent that writes, renames and deletes a file and runs `wc`.

```sh
mkdir -p /tmp/agent-trace-demo
sudo ./watch --workspace /tmp/agent-trace-demo --out ground_truth.json -- \
	./simagent --workspace /tmp/agent-trace-demo --trajectory-out trajectory.json

./verify --trajectory trajectory.json --ground-truth ground_truth.json
```

This prints FAITHFUL. To see a discrepancy, rerun with `--drop-entry 0` on `simagent` (it omits one claim) and verify again: the unreported action appears under *Unrecorded* and the verdict is NOT FAITHFUL.

To record an agent `watch` cannot launch (a container entrypoint, say), start it yourself and pass `--root-pid N` in place of `-- <command>`. Anything that process did before `watch` attached is invisible to the process probe.

`verify` options: `--interval-slack` (default 500ms) widens each claim's time interval for a trajectory clock that differs from the kernel's, and `--ignore-exits` skips process exits for a format that cannot state them.

### Verifying a real agent

For a real agent, `verify` reads the agent's own session file through an adapter. It detects the adapter from the file, or you choose one with `--agent claude-code` or `--agent gemini`:

```sh
sudo ./watch --probes fs,proc,net --workspace "$PWD" --out ground_truth.json -- claude -p "your task"
./verify --agent claude-code --trajectory ~/.claude/projects/<project>/<session>.jsonl \
         --ground-truth ground_truth.json --baseline baseline.json
```

The report lists what the adapter could not turn into a claim (tools that produced no entry, tools it has no mapping for, records it could not parse) and each limitation of the format, so a verdict is never read as stronger than the evidence.

A harness does things on its own that no trajectory records, such as keeping a connection to its model API open. Those events would read as unreported actions, so they are measured rather than guessed. Give the agent a task that claims nothing, record it with `watch`, and build a baseline from several such runs:

```sh
./baseline --agent claude-code --agent-version 2.1.286 --out baseline.json run1.json run2.json run3.json
```

Only what every control run did becomes a rule, rules match an action type and target exactly, and a baseline holds for one agent version. Pass it to `verify` with `--baseline`. Without one, the harness's own activity is reported as unexplained.

### Network example

Add the network probe and point it at the `libssl` your agent's HTTP client uses, so request bodies can be hashed:

```sh
LIBSSL=$(ldd "$(which curl)" | awk '/libssl\.so/ {print $3}')

sudo ./watch --probes fs,proc,net --net-exe-path "$LIBSSL" \
	--workspace /tmp/agent-trace-demo --out ground_truth.json -- \
	./simagent --workspace /tmp/agent-trace-demo --trajectory-out trajectory.json \
		--fetch-url https://example.com/api --fetch-method POST --fetch-body content-body \
		--fetch-via-curl

./verify --trajectory trajectory.json --ground-truth ground_truth.json
```

Here `simagent` claims the `curl` command and nothing curl does, so the connection and the request show up under coverage as events explained by that command. Without `--fetch-via-curl`, `simagent` makes the request itself and claims the connection. Adding `--attack net-fabrication` or `--attack net-omission` to that form claims a connection that never happened or drops a real one, and the verdict becomes NOT FAITHFUL.

## Repository layout

```
cmd/watch         Records ground truth: runs the probes, launches the agent, writes the file
cmd/verify        Compares a trajectory and a ground truth file and prints the verdict
cmd/baseline      Builds a harness baseline from control runs
cmd/simagent      Simulated agent, for exercising the probes end to end
pkg/models        Trajectory, ground truth and coverage types
pkg/probe         Observer interface; fs, proc and net implement it
pkg/verification  Process tree, alignment, coverage and the verdict
pkg/agent         Adapter interface, registry, baseline; claudecode and gemini adapters
pkg/matching      Target comparison between a claim and an observed event
pkg/content       SHA-256 content digests
pkg/tlsparse      TLS ClientHello and HTTP/1.1 request parsing
pkg/tlsoffset     Locates SSL_write in a libssl binary for the uprobe
tests/e2e         End-to-end scenarios: simagent, probes and verifier together
```

Design and implementation notes are in [`docs/architecture.md`](docs/architecture.md). Related work and the measurement method are in [`docs/related_work/`](docs/related_work/00_intro_and_contents.md) and [`docs/methodology/`](docs/methodology/being_data_driven.md).
