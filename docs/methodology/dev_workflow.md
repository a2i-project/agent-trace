# Development Workflow

How changes to agent-trace are made, tested and documented. `AGENTS.md` at the
repository root holds the short rules every agent session must follow; this
page gives the detail. How to decide things by measurement is in
[`being_data_driven.md`](being_data_driven.md).

## Unit of work

One item per commit: a probe change, a verifier stage, an adapter, a document.
Tests grow with the implementation in the same commit. A change that spans
`pkg/models`, a probe and the verifier is still one item if it delivers one
capability, and its commit message says which part does what.

## Tests

| Kind | Where | Needs root | Runs |
|---|---|---|---|
| Unit tests, table-driven | next to the code (`*_test.go`) | no | locally and in CI |
| Probe tests (eBPF load, fanotify) | `pkg/probe/...` | yes, skip without it | CI; locally only when a human runs `sudo` |
| End-to-end scenarios | `tests/e2e`, `cmd/watch` | yes, skip without it | same |

An unprivileged `go test ./...` passing is not a full signal, because the
privileged tests skip. CI runs the whole suite with `sudo go test -v ./...`
(`.github/workflows/test.yml`), so a green CI run covers the eBPF and end-to-end
tests.

**Never run `sudo` from an unattended agent session.** It blocks on a password
prompt or breaks the environment. An agent runs `go vet ./...` and the
unprivileged tests locally, then either pushes and watches CI, or asks the
human to run the privileged tests in their own terminal and paste the output.

Every capability gets at least one end-to-end test that drives `simagent` with
a fully scripted action sequence, so a probe is validated where the answer is
known before it is trusted on a real agent.

## eBPF programs

* The BPF verifier rejects a runtime-computed size argument to
  `bpf_probe_read_user`. Use compile-time constants and trim afterwards.
* After editing any `.bpf.c` file, regenerate the bindings with
  `make generate` (`go generate ./pkg/probe/...`, which runs `bpf2go`) and
  commit the regenerated `.o` and `_bpfel.go`/`_bpfeb.go` files with the
  source change.
* A new kernel-side loss counter is snapshotted in the observer's `Stop()`
  before the maps close, and is surfaced through the coverage record. The rule
  is in [`../architecture/10_probes_common.md`](../architecture/10_probes_common.md).

## CI

Two workflows run on every push to `main`: `test.yml` (all tests under sudo,
plus a check that the committed proc bindings match a fresh `go generate`) and
`lint-and-security.yml`. After a push, watch the run
(`gh run watch <run-id> --exit-status`) and give every failure a verdict before
moving on: a transient flake (rerun once, and record it in the session state if
it passes), a real regression (fix it), or an environment difference on the
runner (add a diagnostic step, do not raise a timeout to hide it).

Design timing-sensitive tests for the shared CI runner, not for a fast
development box. Prefer synchronizing on an explicit signal over a fixed sleep.

## Commits

Each harness has a wrapper file at the repository root (`CLAUDE.md`,
`CODEX.md`, `GEMINI.md`) with its commit template. All templates share the
shape `[<harness>] <type>: <short description>`, a list of details, and the
trailers `Co-Authored-By`, `Harness` and `Model`, with the model matching the
session. Never force-push. Never commit secrets or build output other than the
generated eBPF bindings.

## Documentation

The documentation layout and its rules are in [`../README.md`](../README.md).
In short:

* A change to behaviour updates the matching page in `docs/architecture/` in the
  same commit, including its "Checked against commit" line.
* A design choice with alternatives gets an entry in `docs/decisions/`. A
  changed decision is marked superseded and a new entry is added. Entries are
  never rewritten into a different decision.
* An open question goes to `docs/decisions/open.md`. Open work goes to the local
  `docs/todo/` folder. When an item is done its content moves into the
  architecture page and the todo item is deleted.
* Evidence carries one of three labels: **Verified** (measured here, with the
  command), **Reported** (from vendor documentation or source), **Unverified**
  (a hypothesis).
* No number measured on a private transcript corpus appears in a tracked file.

## Session state

`STATE.md` at the repository root is a local, untracked session log for
agents that switch context often. It holds the current focus, the last results
and the next steps, and points into `docs/todo/` for the work list. It does not
hold design: design belongs in `docs/architecture/` and `docs/decisions/`.
