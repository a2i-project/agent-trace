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

Three workflows run on every push to `main`: `test.yml` (all tests under sudo,
after building the rustls test client in `pkg/probe/net/testdata/rustls-client` with `cargo build --release --locked`, its crates downloaded at the build and pinned by its `Cargo.lock`, and passing it to the tests as `AGENT_TRACE_RUSTLS_CLIENT` (N-39);
plus a check that the committed `.go` bindings of the proc and net probes match a fresh `make generate`; the `.o` files are not compared, since their bytes depend on the clang version),
`lint-and-security.yml`, and `docs.yml` (the documentation checks, see Documentation below). After a push, watch the run
(`gh run watch <run-id> --exit-status`) and give every failure a verdict before
moving on: a transient flake (rerun once, and if it then passes record it as a
todo item naming the test), a real regression (fix it), or an environment difference on the
runner (add a diagnostic step, do not raise a timeout to hide it).

Design timing-sensitive tests for the shared CI runner, not for a fast
development box. Prefer synchronizing on an explicit signal over a fixed sleep.

## Commits

Each harness has a wrapper file at the repository root (`CLAUDE.md`,
`CODEX.md`, `GEMINI.md`) with its commit template. All templates share the
shape `[<tag>] <type>: <short description>` (the tag names the harness:
`claude`, `codex`, `agy`), a list of details, and the trailers `Docs`
(always), `Implements` and `Closes-Todo` (when they apply), `Co-Authored-By`,
`Harness` and `Model`, with the model matching the session. Never force-push. Never commit secrets or build output other than the
generated eBPF bindings.

## Documentation

The documentation describes the code as it is, in every commit. A commit that
leaves a published page, a decision or a todo item out of step with the code
is incomplete, in the same way as a commit that breaks a test. The layout is
in [`../README.md`](../README.md).

### The contract, per commit

1. **Behaviour changes update the component's page.** A change to what a
   component does, its flags, outputs, counters or limits updates its page in
   `docs/architecture/` in the same commit (the map from code paths to pages is
   `PAGE_OF` in `scripts/check-docs.py`; the agent version configuration,
   `config/` and `pkg/config/`, maps to the adapters' page, and the overhead
   benchmark `scripts/bench-overhead.sh`, the comparison tooling
   `scripts/compare/`, the capture script `scripts/capture-agent.sh` with its
   wrapper `scripts/capture-claude-code.sh` and the profile reader
   `scripts/agent-profile.py`, the campaign runner `scripts/capture-campaign.sh` with
   its helpers `scripts/measure-watch.py` and `scripts/annotate-run.sh`, and
   the capture seeds `scripts/seed/` to the tools page). Remove a known limit the commit
   fixes; add one it introduces. Set the page's `Checked against commit` line
   to the commit's parent.
2. **Design changes are decisions.** A new design choice gets an entry in
   `docs/decisions/`. A change to an existing decision supersedes or amends it
   explicitly (`Superseded by X`, or a dated `Amended <date> (commit <sha>):`
   note); an entry is never rewritten into a different decision.
3. **Implementing a decision updates its status.** When a commit builds an
   entry marked "not yet implemented", it changes that Status in the same
   commit and names it in an `Implements:` trailer.
4. **Closing an open question moves it.** When a question in
   `docs/decisions/open.md` is decided, the decision goes to its area file, the
   entry is deleted from `open.md`, and its ID is added to the `Closed:` line at
   the top of `open.md`.
5. **Doing a todo item deletes it.** An item taken from `docs/todo/` (local
   only) is deleted when the work is done, after any open remainder has been
   moved into a surviving item. The commit names it in a `Closes-Todo:`
   trailer.
6. **New findings are recorded where they belong.** A gap found while working
   becomes a known limit (a fact about built code), a todo item (work), or an
   `open.md` entry (a question that needs a decision). Nothing is left only in
   a commit message, a session log or a conversation.
7. **Every commit says what it did to the docs.** The message carries a
   `Docs:` trailer: `Docs: updated`, or `Docs: none (<why no documented
   behaviour changed>)`, for example a refactor or a test-only change.

"The commit's parent" in rule 1 means: the page describes the parent's code
plus the change made in the same commit, and its `Checked against commit` line
names the parent, the newest commit that existed when the page was checked.

### Before starting an item

Re-read the item and the pages it touches against the code at `HEAD`. If it is
already done, its premise changed, or the page is wrong, fix the docs first
(its own commit) and only then start the work.

### Enforcement

`scripts/check-docs.py` checks the mechanical part of the contract:

| Check | Where it runs |
|---|---|
| Published docs (`README.md`, `AGENTS.md`, the harness wrappers, `docs/README.md`, `docs/architecture/`, `docs/decisions/`, `docs/methodology/`, `docs/related_work/`): no em or en dashes; relative links resolve and none points into a local-only folder; every decision ID cited exists or is listed on the `Closed:` line of `open.md`; no local todo ID (unless the line says "local only") and no reference to the retired plan folder, also in tracked code; every architecture page has its `Checked against commit` line naming a real commit, and every page but `00_overview.md` has its six sections in order; every decision has `Status` and `Date`, and a `Superseded by` target exists; nothing decided is left in `open.md`; "not yet implemented" on an architecture page or the README names a decision whose Status still says so | `lint`: CI (`.github/workflows/docs.yml`) and the `pre-push` hook |
| Every commit in the pushed range: a valid `Docs:` trailer; `Docs: updated` changes a published doc and the page of every component whose non-test code it changed (`PAGE_OF`); an architecture page it edits (except `00_overview.md`) names a commit whose code for that component, tests and fixtures excluded, equals the commit's parent; `Implements:` names an entry no longer marked "not yet implemented"; run locally, `Closes-Todo:` names no item still in `docs/todo/` | `commits BASE HEAD`: CI and the `pre-push` hook |
| One message, before it is recorded: the `Docs:` trailer against the staged files, `Implements:`, and `Closes-Todo:` against the local `docs/todo/` | `commit-msg` hook |

Exempt: merge commits, commits whose subject starts with `Revert "`, and commits by bots (Dependabot). A message-only `git commit --amend` is checked for its trailer only.

Install the hooks once per clone: `git config core.hooksPath scripts/hooks`.
When a check fails on pushed or shared commits, do not rewrite history: add a
commit that repairs the docs and carries `Docs-Fixes: <sha of the failing
commit>`, which clears that commit's errors in the same range. A push to
`main` is checked over the pushed commits only, so the repair also passes on
its own. What the script cannot judge (whether a page is true) stays the
author's job: the trailer is a statement that it was checked.

### Conventions

* Evidence carries one of three labels: **Verified** (measured here, with the
  command), **Reported** (from vendor documentation or source), **Unverified**
  (a hypothesis).
* No number measured on a private transcript corpus appears in a tracked file.
* A published page never depends on a local one for a fact a reader needs; a
  mention of a local file carries "(local only)".

## Session state

`STATE.md` at the repository root is a local, untracked session log. A
session reads it first when it exists and updates it before it ends, so the
next session, often in another harness, starts from it. It holds the current
focus, what is pushed and what is not, and the next steps as pointers to todo
IDs (`docs/todo/`, local only); about 60 lines. It holds no design and no
finished narrative: design belongs in `docs/architecture/` and
`docs/decisions/`, history in the commits.
