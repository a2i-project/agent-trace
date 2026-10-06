# Agent-Trace Repository Guide

## ⚠️ Privileged Commands: NEVER run sudo headlessly

**NEVER attempt to run `sudo` in a background task or unattended terminal.** Sudo requires an interactive password and any attempt to do so will block, fail, or break the environment.

**Instead**: when a privileged test or command is needed (e.g., `sudo go test -v ./...` for eBPF/fanotify tests), either push and let CI run it (CI runs the whole suite with sudo), or **STOP** and ask the user to run it in their own terminal and paste back the output.

This applies to ALL privileged operations: `sudo go test`, `sudo go run`, any BPF/fanotify program requiring root, etc.

If your harness opened `CLAUDE.md`, `GEMINI.md`, or `CODEX.md` first, read this file next. This is the shared source of truth for all agents in this repo.

This repository contains the Agent Trajectory Faithfulness Verifier, written in Go. Its goal is to provide execution assurance for AI agent trajectories by comparing self-reported actions against ground-truth system probes.

## Agent Entry Points

- `CLAUDE.md`: Claude-specific wrapper and commit metadata.
- `GEMINI.md`: Gemini-specific wrapper and commit metadata.
- `CODEX.md`: Codex-specific wrapper and commit metadata.

## Codebase Gotchas & Architecture Rules

- No Large Autonomous Implementation: Implementations are done as focused, reviewable units. Tests grow incrementally alongside the implementation.
- eBPF Probes: For Tier 2+, we use `cilium/ebpf` for process probes.
- Testing Philosophy: Every tier MUST have at least one E2E semantic test that demonstrates the requirements. We strongly prefer table-driven `go test` for unit testing.
- Module Boundaries: Keep models (`TrajectoryEntry`, `GroundTruthEvent`, `ActionType`) strictly in `pkg/models`. Do not intermingle matching/verification logic into the data models.

## Documentation Index (Progressive Disclosure)

Do not assume all context is listed here. `docs/README.md` explains the layout. Load what the task needs:

- `docs/architecture/00_overview.md`: objective, threat model, properties, end-to-end workflow. Read first.
- `docs/architecture/1x_*.md`: the probes (common contract and loss accounting, proc, fs, net). Read before touching `pkg/probe`.
- `docs/architecture/20_verifier.md`: process forest, alignment, coverage, verdict. Read before touching `pkg/verification` or `pkg/matching`.
- `docs/architecture/30_agent_adapters.md` and `40_tools.md`: adapters, baseline, command-line tools.
- `docs/decisions/*.md`: why each design choice was made, with stable IDs (`P-`, `N-`, `V`, `D`/`I-`). `docs/decisions/open.md` lists undecided questions. Do not silently resolve an open decision in code; record it.
- `docs/methodology/dev_workflow.md`: tests, privileged runs, eBPF bindings, CI, commits, documentation rules.
- `docs/methodology/being_data_driven.md`: measurement discipline for experiments.
- `docs/related_work/`: survey of other systems and threat models (`01_threat_models.md` defines TM-A to TM-D).
- Local only, gitignored, may be absent: `docs/todo/` (open work), `docs/eval/` (experiment plans), `docs/research/` (evidence), `docs/archive/` (superseded plans). Never treat `docs/archive/` as current.

## SKILL.state Agent Protocol

You are operating under a state-centric execution protocol. Because the user frequently switches agents to manage context limits, you must not rely on conversational history. Instead, you must rely entirely on the explicit structured state persisted in `STATE.md`.

### Execution Loop

For every turn/request you receive, you MUST follow this loop:

1. Read State: Your first action should always be to read `STATE.md` to understand the current world state, past progress, and overarching goals.
2. Execute: Perform the requested actions or continue the work based on the "Next Steps" outlined in the state.
3. Update State: Before ending your turn, you MUST update `STATE.md` (overwriting it or modifying it) to reflect the new state.

### State Format

The `STATE.md` file should be kept concise and structured. It should ideally contain:

- Current Goal: The overarching objective.
- Completed Steps: What has been accomplished so far (briefly).
- Active Context: Current hypotheses, bugs found, critical files modified, or specific test results.
- Next Steps: The immediate next actions the agent should take on the next turn.

### Golden Rule

If it's not in `STATE.md`, the next agent won't know about it. Project all transient reasoning and discoveries into the structured state before you finish.

## Agentic CI & TDD

Shift Left via Agent Self-Correction: Before you attempt to commit any code or state that you have finished your turn, you MUST run `go vet ./...` and `go test ./...` locally (or `golangci-lint run` if available). The privileged tests skip without root, so they run in CI or in the user's terminal, never headlessly (see the top of this file). Act as your own IDE. Never commit broken code or ignore unhandled errors. If a test or linter fails, fix it immediately.

## Measurement Discipline

This project's central claim is a verdict (FAITHFUL, NOT FAITHFUL or INCONCLUSIVE, built from Corroborated, Mismatched, Unwitnessed and Unrecorded positions and the coverage check). Every such verdict is a measurement, and this is a research prototype for a paper, so the measurement has to survive scrutiny, not just pass locally. Full rationale and worked examples: `docs/methodology/being_data_driven.md`. Read it before designing a new experiment, probe, or E2E tier. In this repo, in practice:

- **Name the premise before building on it.** Before trusting a new probe or matcher on real trajectories, state the assumption you're least sure of (e.g. "curl opens exactly one connection per fetch", which is false, see Tier 5 Happy-Eyeballs) and check it cheaply first.
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
- **A CI failure needs a verdict before moving on**: transient flake (rerun once with `gh run rerun <run-id> --failed`; if it then passes, record it under STATE.md's "Known Flaky Tests") vs. real regression (fix it) vs. environment-specific gap (kernel/BTF difference on the runner: add a debug step to the workflow, don't guess with a timeout bump).
