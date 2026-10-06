# Documentation

Start with [`architecture/00_overview.md`](architecture/00_overview.md).

## Layout

Each folder holds one kind of content with its own lifecycle.

| Folder | Holds | Changes when | Published |
|---|---|---|---|
| [`architecture/`](architecture/) | what the code does now, one page per component: objective, structure, technologies, workflow, guarantees, known limits | the code changes; each page names the commit it was checked against | yes |
| [`decisions/`](decisions/) | why the design is what it is, one file per area, with stable IDs; [`decisions/open.md`](decisions/open.md) lists the questions not yet decided | a decision is made or superseded; entries are never rewritten into a different decision | yes |
| [`methodology/`](methodology/) | how the project works: [development workflow](methodology/dev_workflow.md) and [measurement discipline](methodology/being_data_driven.md) | rarely | yes |
| [`related_work/`](related_work/00_intro_and_contents.md) | survey of other systems and threat models | new work appears | yes |
| `todo/` | open work, each item with why, acceptance and trigger | an item is added, or done and deleted | no, local only |
| `eval/` | evaluation and experiment plans, then results | an experiment is planned or run | no, local only |
| `research/` | measurements and evidence, including data from local transcript corpora | new evidence | no, local only |
| `archive/` | superseded planning documents, kept read-only | never | no, local only |

The local-only folders are gitignored. A published page never depends on
them for a fact a reader needs.

## Architecture pages

| Page | Component |
|---|---|
| [00_overview.md](architecture/00_overview.md) | objective, threat model, properties, end-to-end workflow |
| [10_probes_common.md](architecture/10_probes_common.md) | probe contract, coverage and loss accounting, ground truth file |
| [11_probe_proc.md](architecture/11_probe_proc.md) | process probe (eBPF) |
| [12_probe_fs.md](architecture/12_probe_fs.md) | filesystem probe (fanotify) |
| [13_probe_net.md](architecture/13_probe_net.md) | network probe (eBPF tracepoints, `SSL_write` uprobe) |
| [20_verifier.md](architecture/20_verifier.md) | process forest, alignment, coverage, verdict |
| [30_agent_adapters.md](architecture/30_agent_adapters.md) | adapters for Claude Code and Gemini, harness baseline |
| [40_tools.md](architecture/40_tools.md) | `watch`, `verify`, `baseline`, `simagent` |

## Decision files

| File | Area | ID prefix |
|---|---|---|
| [probes.md](decisions/probes.md) | observation technique for files, processes, sockets; loss accounting | P- |
| [network.md](decisions/network.md) | capture layers, TLS content, threat-model scope for the network | N- |
| [verification.md](decisions/verification.md) | verification model | V |
| [integration.md](decisions/integration.md) | agent adapters and trajectory formats | D, I- |
| [open.md](decisions/open.md) | undecided questions | O- |

## Conventions

* Evidence labels: **Verified** (measured here, with the command to repeat
  it), **Reported** (from vendor documentation or source code), **Unverified**
  (a hypothesis, not to be built on before it is tested).
* Code is referenced by package and symbol, not by line number.
* No numbers measured on a private transcript corpus appear in a published
  page.
* Writing: active voice, no em-dashes, no filler.
