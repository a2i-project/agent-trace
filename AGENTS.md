# Agent-Trace Repository Guide

## Privileged commands: never run sudo headlessly

**NEVER attempt to run `sudo` in a background task or unattended terminal.** Sudo requires an interactive password and any attempt to do so will block, fail, or break the environment.

**Instead**: when a privileged test or command is needed (e.g., `sudo go test -v ./...` for eBPF/fanotify tests), either push and let CI run it (CI runs the whole suite with sudo), or **STOP** and ask the user to run it in their own terminal and paste back the output.

This applies to ALL privileged operations: `sudo go test`, `sudo go run`, any BPF/fanotify program requiring root, etc.

If your harness opened `CLAUDE.md`, `GEMINI.md`, or `CODEX.md` first, read this file next. This is the shared source of truth for all agents in this repo.

This repository contains the Agent Trajectory Faithfulness Verifier, written in Go. Its goal is to provide execution assurance for AI agent trajectories by comparing self-reported actions against ground-truth system probes.

## Documentation contract (every commit)

The docs must describe the code as it is after every single commit. A commit that leaves them stale is incomplete, like a commit that breaks a test. Full rules: `docs/methodology/dev_workflow.md`, Documentation. In short:

1. **Before starting an item**, re-check it and the pages it touches against the code at `HEAD`. If it is already done or its premise changed, fix the docs first.
2. **A behaviour change** updates its component's page in `docs/architecture/` in the same commit (known limits included) and sets the page's `Checked against commit` line to the commit's parent.
3. **A design change** adds or supersedes an entry in `docs/decisions/`; never rewrite a decision in place. Building an entry marked "not yet implemented" updates its Status and adds an `Implements: <ID>` trailer.
4. **A decided open question** moves out of `docs/decisions/open.md` into its area file, and its ID joins the `Closed:` line.
5. **A todo item you finish** is deleted from `docs/todo/` (local only), with any open remainder moved to a surviving item, and named in a `Closes-Todo: <ID>` trailer.
6. **Anything you discover** (a bug, a gap, a question) is written down where it belongs: a known limit, a todo item, or an `open.md` entry. Never only in a commit message, `STATE.md` or the conversation.
7. **Every commit message** carries `Docs: updated` or `Docs: none (<why no documented behaviour changed>)`.

`scripts/check-docs.py` enforces the mechanical part in CI (`.github/workflows/docs.yml`) and in local git hooks. Install the hooks once per clone: `git config core.hooksPath scripts/hooks`. Run `python3 scripts/check-docs.py lint` before ending a session.

## Agent Entry Points

- `CLAUDE.md`: Claude-specific wrapper and commit metadata.
- `GEMINI.md`: Gemini-specific wrapper and commit metadata.
- `CODEX.md`: Codex-specific wrapper and commit metadata.

## Codebase Gotchas & Architecture Rules

- No Large Autonomous Implementation: Implementations are done as focused, reviewable units. Tests grow incrementally alongside the implementation.
- eBPF probes: the process and network probes use `cilium/ebpf` with CO-RE and `bpf2go`; the filesystem probe uses fanotify.
- Testing philosophy: every capability MUST have at least one end-to-end test that demonstrates its requirements. We strongly prefer table-driven `go test` for unit testing.
- Module Boundaries: Keep models (`TrajectoryEntry`, `GroundTruthEvent`, `ActionType`) strictly in `pkg/models`. Do not intermingle matching/verification logic into the data models.

## Documentation Index (Progressive Disclosure)

Do not assume all context is listed here. `docs/README.md` explains the layout. Load what the task needs:

- `docs/architecture/00_overview.md`: objective, threat model, properties, end-to-end workflow. Read first.
- `docs/architecture/1x_*.md`: the probes (common contract and loss accounting, proc, fs, net). Read before touching `pkg/probe`.
- `docs/architecture/20_verifier.md`: process forest, alignment, coverage, verdict. Read before touching `pkg/verification` or `pkg/matching`.
- `docs/architecture/30_agent_adapters.md`, `40_tools.md` and `50_attack_generators.md`: adapters, baseline, command-line tools, attack generators.
- `docs/decisions/*.md`: why each design choice was made, with stable IDs (`D`, `E-`, `I-`, `N-`, `O-`, `P-`, `V`). `docs/decisions/open.md` lists undecided questions. Do not silently resolve an open decision in code; record it.
- `docs/methodology/dev_workflow.md`: tests, privileged runs, eBPF bindings, CI, commits, documentation rules.
- `docs/methodology/being_data_driven.md`: measurement discipline for experiments.
- `docs/related_work/`: survey of other systems and threat models (`01_threat_models.md` defines TM-A to TM-D).
- Local only, gitignored, may be absent: `docs/todo/` (open work), `docs/eval/` (experiment plans), `docs/research/` (evidence), `docs/archive/` (superseded plans). Never treat `docs/archive/` as current.

## Session state (`STATE.md`)

The user often switches agents and harnesses, so do not rely on conversation history. `STATE.md` at the repository root (local, untracked) is the hand-over between sessions:

1. **Read it first** when it exists.
2. **Update it before ending your turn**: current goal, what is pushed and what is only local, next steps as todo IDs. Keep it to about 60 lines, with no design content and no finished narrative.

Design belongs in `docs/architecture/` and `docs/decisions/`, open work in `docs/todo/`, history in the commits. If something is not in one of these, the next agent will not know it.

## Agentic CI & TDD

Shift Left via Agent Self-Correction: Before you attempt to commit any code or state that you have finished your turn, you MUST run `go vet ./...` and `go test ./...` locally (or `golangci-lint run` if available). The privileged tests skip without root, so they run in CI or in the user's terminal, never headlessly (see the top of this file). Act as your own IDE. Never commit broken code or ignore unhandled errors. If a test or linter fails, fix it immediately.

## Measurement Discipline

This project's central claim is a verdict (FAITHFUL, NOT FAITHFUL or INCONCLUSIVE, built from Corroborated, Mismatched, Unwitnessed and Unrecorded positions and the coverage check). Every such verdict is a measurement, and this is a research prototype for a paper, so the measurement has to survive scrutiny, not just pass locally. Full rationale and worked examples: `docs/methodology/being_data_driven.md`. Read it before designing a new experiment, probe, or E2E tier. In this repo, in practice:

- **Name the premise before building on it.** Before trusting a new probe or matcher on real trajectories, state the assumption you're least sure of (e.g. "curl opens exactly one connection per fetch", which is false: Happy-Eyeballs opens one per address, see `tests/e2e/tier5_test.go`) and check it cheaply first.
- **Pre-register GO/STOP thresholds in the test/tool, before running it**, not after seeing the result. A verdict decided after the fact is a negotiation, not a measurement.
- **No verdict without a control.** A corroboration-rate change is only meaningful relative to the same rate measured on an unmodified baseline in the same run/environment. If there's no control, the tool should print UNJUDGED, not a verdict.
- **Validate new instrumentation against a known answer first.** A new probe's first real test should be against `simagent` with a fully scripted, known action sequence, before it's trusted on an unscripted trajectory.
- **Distinguish "not measured" from "measured zero."** Use an explicit `ok bool` or `*T`, never a bare zero default. This is why a nil claim field is a finding only where the format can express it and the probe captured it (`Options.Expresses` in `pkg/verification`).
- **Report `considered` / `evaluated` / `succeeded` together**, and count what couldn't be evaluated (skipped tiers, attach failures) instead of dropping it.
- **A proxy passing (e.g. 100% on the current E2E suite) is not the same as coverage of the threat model.** Check coverage against `docs/related_work/01_threat_models.md` periodically, not just test pass/fail.
- **Log abandoned approaches and corrected numbers** in the changelog section of `docs/methodology/being_data_driven.md` when they're relevant to a paper claim, so they aren't silently lost or re-attempted.

## CI Discipline

Tests run twice: once on your dev box, once on GitHub Actions' shared `ubuntu-latest` runners in `.github/workflows/test.yml`. `sudo go test -v ./...` passing locally is necessary, not sufficient: the runner is slower, shared, and sometimes cold-starting, and eBPF attach/ring-buffer timing can differ from a local box in ways that don't show up until CI.

- **Design timing-sensitive tests for CI, not your dev box.** Fixed `time.Sleep` windows around probe attach, process forking, or ring-buffer draining (e.g. `cmd/watch/main_test.go`) must budget for a contended GitHub-hosted runner, not local timing. Prefer synchronizing on an explicit signal over a bare sleep; when a sleep is unavoidable, size it generously and say in a comment that CI sets the bound, not the dev box.
- **A pass on this box is a hypothesis, not a result.** After any commit that touches probes, timing, or CI-relevant code, push and watch the actual CI run before treating the change as done.
- **Watch CI after every push, without being asked.** Immediately after pushing to `main` or opening a PR, run `gh run list --limit 1` (or `gh run watch <run-id> --exit-status`) and report pass/fail back in the same turn, so failures get fixed while context is still loaded instead of discovered later.
- **A CI failure needs a verdict before moving on**: transient flake (rerun once with `gh run rerun <run-id> --failed`; if it then passes, record it as a todo item with the test name) vs. real regression (fix it) vs. environment-specific gap (kernel/BTF difference on the runner: add a debug step to the workflow, don't guess with a timeout bump).
