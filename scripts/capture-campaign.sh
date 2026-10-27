#!/usr/bin/env bash
# Capture campaign: many paired captures (scripts/capture-claude-code.sh) in
# one sitting, under one sudo, each task run with its own fresh control runs, in
# a recorded random order, with a manifest of every run and resumption after an
# interruption.
#
# It runs the real agents, so it uses the accounts' model quota and needs root
# for the probes: run it yourself. Run it with --dry-run first, which checks
# everything and prints the schedule and its cost without sudo or any model
# call.
#
#   scripts/capture-campaign.sh [--dry-run] [--controls N] [--seed N]
#                               [--validate] [--validate-e2e]
#                               [--heldout-dir DIR] [--agy-model ID]
#                               [--allow-unconfigured-version] [--new-version-stratum]
#                               [--stop-after-failures N] PLAN OUTPUT_DIR
#   scripts/capture-campaign.sh --validate-only [--validate-e2e] [--dry-run] OUTPUT_DIR
#
# PLAN is a text file with one entry per line, # starting a comment:
#
#   AGENT TASK REPETITIONS [content] [split] [model=ID]
#
#   claude-code long 3 content
#   claude-code project 3
#   gemini long 2
#   gemini heldout:subagent 15 split model=gemini-3.8-flash-medium
#
# AGENT is claude-code or gemini, TASK one of the capture script's tasks for
# that agent or heldout:NAME, REPETITIONS how many task runs to record, and
#   content   turns on the net probe's content capture for that entry's runs and
#             controls (capture-claude-code.sh --content; Claude Code only);
#   split     takes the controls 2 before and 3 after the task run instead of
#             after it (D11), as the task `long` always does;
#   model=ID  the model of the entry's runs (D7). Claude Code defaults to
#             claude-sonnet-5-5 and agy to gemini-3.8-flash-high (the id the
#             existing captures recorded); --agy-model ID changes agy's default
#             for the plan, and model=ID one entry's. After every run the
#             model the transcript or conversation records must equal the
#             pinned one, so an id the agent does not run under stops the
#             campaign at the first run (MODEL MISMATCH).
# heldout:NAME is a held-out task (D8): its prompt.txt, tools.txt and optional
# seed/ come from --heldout-dir DIR/NAME, a directory outside the repository,
# which the script refuses inside it and never copies; the manifest holds only
# the SHA-256 of the prompt and the seed.
#
# Every task run is one call of capture-claude-code.sh into its own directory,
#   OUTPUT_DIR/<agent>-<version>/<task>[-content]/run-NN
# and records CONTROLS control runs (--controls, default 5) of its own, fresh
# for every task run (D10): none is reused. A short task is recorded first and
# its controls after it; a split task (`long`, or an entry marked split) takes
# 2 control runs before the task and the other 3 after (D11; for another
# --controls N, N*2/5 before). The order is in the manifest.
#
# Before anything else, the script runs capture-claude-code.sh --check for
# every entry (the agent is installed, its version is listed in
# config/agents.json unless --allow-unconfigured-version, Claude Code's
# ~/.claude/settings.json sets env.DISABLE_UPDATES to "1" (D6), the model is
# named, the task and its seed exist, the locked-directory test of shapes
# passes), and refuses a malformed plan, an OUTPUT_DIR or --heldout-dir inside
# the repository, an OUTPUT_DIR that already holds runs of another version of an
# agent (protocol 6.1: that is a new stratum, onboarded first; pass
# --new-version-stratum to start it) and a missing setpriv, sudo or make.
# --dry-run stops there and prints the schedule: the runs already complete, the
# task and control sessions still to record, the seed and the order of the
# slots, and an estimate of the model turns.
#
# Otherwise it builds the binaries once, asks for sudo once and keeps the
# credential fresh while it runs. With --validate it then validates the
# instrument (protocol 9.4, I-67), in seconds: under watch (fs,proc, the agent
# run as the user) it runs simagent --null three times as control runs,
# simagent's script once, and the script with --drop-entry 0 once, in the order
# null, honest, null, dropped, null, every run writing its trajectory to the
# same path, which is moved aside after the run. It builds a baseline
# (cmd/baseline --agent generic) from the null runs at an agreement of one run
# in three, so an event of simagent's own start-up and exit that only some
# runs show is still explained. It fails closed when a watch exits non-zero, a
# null run claims anything, the baseline names the workspace, holds a command,
# or explains any action the honest run claims (the dropped entry would then
# be hidden), when the honest run does not verify FAITHFUL against it, or when
# the dropped run does not verify NOT FAITHFUL with exactly one finding, an
# Unrecorded one that is the dropped entry. A failure stops the invocation
# before any run (protocol 10.2); the result is written to
# OUTPUT_DIR/validation/, the runs beside it. --validate-e2e also runs `sudo go
# test ./tests/e2e` there, which is slow, so it is opt-in. --validate-only takes
# no PLAN: it builds, asks for sudo, validates and exits (0 when the validation
# passed, 1 otherwise), recording no agent session and writing no manifest.
# Then it records the plan's slots in a
# permutation fixed by --seed (protocol 6.6): the slots are ordered by the
# SHA-256 of seed and slot, so a resumed invocation with the same seed keeps
# the order of the slots that remain. Without --seed the seed of the output
# directory's last invocation is reused, and a new directory gets a random one;
# it is printed and recorded in the manifest and in each run.json.
#
# Version lock (D6, protocol 6.1). Every Claude Code run gets DISABLE_UPDATES=1
# in its environment, and agy runs get AGY_CLI_DISABLE_AUTO_UPDATE=true. The
# agent's version is read before and after every run; a change, or a check that
# now refuses, stops that agent's campaign (the other agent's slots go on), and
# a run whose version changed is excluded as X3.
#
# Every run is checked after it: a transcript that records another model than
# the pinned one fails the run (MODEL MISMATCH) and stops the campaign, since a
# changed model is a variable nobody registered.
#
# Exclusions (protocol 10.1). A run that fails is classified and the reason is
# written to its run.json and the manifest; nothing is deleted. X4, a harness
# error (the agent or watch failed, no transcript, an API or login error):
# the run is moved aside to run-NN.failed-<time>-aK and recorded again in the
# same slot, at most twice; a slot that fails three times is reported failed
# and not replaced, and on a rerun it is skipped. X6, an interruption (Ctrl+C):
# the run is excluded and recorded again on the rerun. X3, a version change.
# X1, loss, is decided later by the analysis from the counters in the manifest.
# A login or quota error, or a model mismatch, ends the campaign at once, since
# the next run would fail the same way. After --stop-after-failures
# consecutive failed runs (default 4) the campaign stops.
#
# Rerunning the same command resumes: complete and failed-out slots are
# skipped, and the directory of an interrupted or failed run is moved aside
# before the slot is recorded again.
#
# manifest.json holds the runs (in place), the attempts moved aside, the slots
# with their final state, every exclusion with its rule and reason, the
# invocations (seed, commit, flags) and the instrument validations. Per run:
# agent, version before and after, model pinned and recorded (task and
# controls), task, run index, recording mode, directory, the paths of its
# files, start and end, exit status, the slot's seed and position, the attempt
# number, the control order (with each run's subagents and their tool calls,
# I-71), the SHA-256 of the task's prompt and seed, the verdict with and without the baseline (outcome, findings, tool calls, claims,
# the alignment counts, completeness), and the scale record of the task run and
# of each control run:
#   probes        each probe's coverage record from the ground truth (ring
#                 buffer drops, untracked children, state map full, channel
#                 drops, content and response state)
#   net           the net probe's coverage counters (connections, with
#                 hostname, with content, h2 offered, dials, ...) and
#                 content_fraction, with_content over connections less
#                 content_unsupported (null when that is zero), read from the
#                 ground truth's net_content (coverage schema 2); only a
#                 schema 1 capture falls back to watch's log, and net.source
#                 says which
#   diagnostics   from the ground truth (schema 2): per probe, each ring
#                 buffer's size, peak occupancy, records and drops, and each
#                 tracked_pids map's capacity, peak and entries at stop, with
#                 the peak as a fraction of the size; a schema 1 capture has
#                 none (not measured)
#   events        the ground truth's events by type, and requests and
#                 connections by target
#   processes     the peak number of processes of the agent's tree alive at
#                 once, counted from the fork and exit events
# Per run, besides the scale record:
#   cost          (control_cost for each control run) what scripts/measure-watch.py
#                 measured around each watch: start-up, drain, watch's own CPU
#                 and peak RSS (cmd/analyze H4b reads startup_s, drain_s,
#                 watch_cpu_s and watch_maxrss_kb); a field it could not
#                 measure is null
#   watch_exit    watch's exit status of the task run and of each control run
# summary.txt is a table of the same, one line per run.
#
# annotations.json (in OUTPUT_DIR, the file cmd/analyze reads for what the
# manifest cannot show): for a task run that completed but whose watch exited
# non-zero, the runner writes agent_exit_status (a note the analysis ignores)
# when watch's log says the agent exited with an error, since such a run counts
# (I-66), and x4 when watch itself failed. Entries it wrote are listed under "auto" and rewritten when the slot is
# recorded again. scripts/annotate-run.sh records what only the operator knows
# (task completion for X5, a user intervention for X6, other X4 causes) and
# takes those fields over from the runner.
set -euo pipefail

die() { echo "capture-campaign: $*" >&2; exit 1; }

dry_run=
allow_unconfigured=
controls=${CONTROLS:-5}
stop_after=4
seed=
validate=
validate_e2e=
validate_only=
heldout_dir=
agy_model=
new_stratum=
while [ $# -gt 0 ]; do
  case $1 in
    --dry-run) dry_run=1; shift ;;
    --controls) controls=${2:?--controls needs a number}; shift 2 ;;
    --seed) seed=${2:?--seed needs a number}; shift 2 ;;
    --validate) validate=1; shift ;;
    --validate-e2e) validate=1; validate_e2e=1; shift ;;
    --validate-only) validate=1; validate_only=1; shift ;;
    --heldout-dir) heldout_dir=${2:?--heldout-dir needs a directory}; shift 2 ;;
    --agy-model) agy_model=${2:?--agy-model needs a model id}; shift 2 ;;
    --allow-unconfigured-version) allow_unconfigured=1; shift ;;
    --new-version-stratum) new_stratum=1; shift ;;
    --stop-after-failures) stop_after=${2:?--stop-after-failures needs a number}; shift 2 ;;
    -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "unknown option $1" >&2; exit 2 ;;
    *) break ;;
  esac
done
usage() {
  echo "usage: $0 [--dry-run] [--controls N] [--seed N] [--validate] [--validate-e2e] [--heldout-dir DIR] [--agy-model ID] [--allow-unconfigured-version] [--new-version-stratum] [--stop-after-failures N] PLAN OUTPUT_DIR" >&2
  echo "       $0 --validate-only [--validate-e2e] [--dry-run] OUTPUT_DIR" >&2
  exit 2
}
if [ -n "$validate_only" ]; then
  [ $# -eq 1 ] || usage
  plan=
  out=$1
else
  [ $# -eq 2 ] || usage
  plan=$1
  out=$2
fi
case $controls in ''|*[!0-9]*|0) die "--controls must be a positive number" ;; esac
case $stop_after in ''|*[!0-9]*|0) die "--stop-after-failures must be a positive number" ;; esac
case $seed in *[!0-9]*) die "--seed must be a number" ;; esac
[ -n "$validate_only" ] || [ -f "$plan" ] || die "no plan file $plan"

root=$(cd "$(dirname "$0")/.." && pwd)
capture=$root/scripts/capture-claude-code.sh
[ -x "$capture" ] || die "missing $capture"
for tool in python3 setpriv sudo make sha256sum realpath; do
  command -v "$tool" >/dev/null || die "$tool is not on PATH"
done
[ -z "$validate_e2e" ] || command -v go >/dev/null || die "--validate-e2e needs go on PATH"
out=$(realpath -m "$out")
case $out/ in "$root"/*) die "OUTPUT_DIR $out is inside the repository; captures are private and never written there" ;; esac
if [ -n "$heldout_dir" ]; then
  heldout_dir=$(realpath -m "$heldout_dir")
  case $heldout_dir/ in "$root"/*) die "--heldout-dir $heldout_dir is inside the repository; held-out tasks are never copied into it" ;; esac
  [ -d "$heldout_dir" ] || die "no held-out directory $heldout_dir"
fi

# The helper below does the parsing, the bookkeeping and the summaries.
helper=$(mktemp "${TMPDIR:-/tmp}/capture-campaign.XXXXXX.py")
keepalive=
cleanup() {
  rm -f "$helper"
  [ -z "$keepalive" ] || kill "$keepalive" 2>/dev/null || true
}
trap cleanup EXIT
cat >"$helper" <<'PY'
import collections, datetime, glob, hashlib, json, os, re, sys

TASKS = {
    "claude-code": {"basic", "parallel", "project", "edits", "tools", "shapes", "long"},
    "gemini": {"basic", "search", "long"},
}
HELDOUT = re.compile(r"heldout:[A-Za-z0-9][A-Za-z0-9._-]*")
MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]*")
# Model turns a session costs, roughly its tool calls plus the final reply:
# from the prompts' step counts and the fixtures (project made 11 tool calls,
# tools 14). long is the prompt's count of about 120 calls plus fixes; its
# real count is in the manifest after the first run. A held-out task is not
# known to the script: HELDOUT_TURNS is a guess. A control makes one call, the
# tools controls three and a subagent's, and the controls of the other tasks
# with the subagent tool (parallel, long) one and a subagent's (I-71); a
# held-out task's controls are counted as one call.
TURNS = {"basic": 6, "parallel": 9, "project": 20, "edits": 8, "tools": 16,
         "shapes": 8, "search": 7, "long": 150}
HELDOUT_TURNS = 100
CONTROL_TURNS = {"tools": 5, "parallel": 4, "long": 4}
# Protocol 10.1, X4: a slot is attempted once and retried twice.
MAX_X4 = 3
AUTH = re.compile(r"not logged in|please run /login|/login|authentication_error|invalid api key|oauth token has expired|invalid bearer|401 unauthorized|login expired|not authenticated", re.I)
QUOTA = re.compile(r"rate.?limit|usage limit|quota|resource.?exhausted|\b429\b|credit balance|overloaded", re.I)
# The probes' event lines in a watch log: a time, two spaces, an action.
EVENT_LINE = re.compile(r"^\d\d:\d\d:\d\d\.\d{3}  \S")
# An account error in a session that still left a transcript. Stricter than
# QUOTA, since a completed run's output is the agent's own text and may name a
# rate limit in passing.
ACCOUNT_AUTH = re.compile(r"not logged in|not logged into|please run /login|oauth token has expired|invalid api key|authentication_error|401 unauthorized", re.I)
ACCOUNT_QUOTA = re.compile(r"RESOURCE_EXHAUSTED|quota (?:reached|exceeded)|usage limit (?:reached|exceeded)|you(?:'ve| have) (?:hit|reached) your (?:usage )?limit|credit balance is too low|rate limit exceeded", re.I)


def label(task):
    return task.replace(":", "-")


def plan(path):
    """Print the plan's entries as tab-separated agent, task, reps, mode, split, model."""
    bad = []
    seen = set()
    for n, line in enumerate(open(path, encoding="utf-8"), 1):
        words = line.split("#", 1)[0].split()
        if not words:
            continue
        if len(words) < 3:
            bad.append(f"{path}:{n}: want AGENT TASK REPETITIONS [content] [split] [model=ID], got {line.strip()!r}")
            continue
        agent, task, reps = words[:3]
        if task.startswith("task="):
            task = task[len("task="):]
        mode, split, model, err = "identity", False, "", None
        for w in words[3:]:
            if w == "content":
                mode = "content"
            elif w == "split":
                split = True
            elif w.startswith("model="):
                model = w[len("model="):]
                if not MODEL.fullmatch(model):
                    err = f"bad model id {model!r}"
            else:
                err = f"unknown option {w!r} (content, split or model=ID)"
        if err:
            bad.append(f"{path}:{n}: {err}")
            continue
        if agent not in TASKS:
            bad.append(f"{path}:{n}: unknown agent {agent!r} (claude-code or gemini)")
            continue
        if task not in TASKS[agent] and not HELDOUT.fullmatch(task):
            bad.append(f"{path}:{n}: unknown task {task!r} for {agent} ({', '.join(sorted(TASKS[agent]))} or heldout:NAME)")
            continue
        if not reps.isdigit() or int(reps) < 1:
            bad.append(f"{path}:{n}: repetitions must be a positive number, got {reps!r}")
            continue
        if mode == "content" and agent == "gemini":
            bad.append(f"{path}:{n}: content capture is for claude-code only (agy has no TLS library to hook)")
            continue
        if (agent, task, mode) in seen:
            bad.append(f"{path}:{n}: {agent} {task} {mode} appears twice; give it one line")
            continue
        seen.add((agent, task, mode))
        split = split or task == "long"
        print(f"{agent}\t{task}\t{int(reps)}\t{mode}\t{'split' if split else '-'}\t{model or '-'}")
    if bad:
        print("\n".join(bad), file=sys.stderr)
        sys.exit(1)
    if not seen:
        print(f"{path}: no entries", file=sys.stderr)
        sys.exit(1)


def load(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def slot_base(out, agent, version, task, mode, idx):
    d = os.path.join(out, f"{agent}-{version}", label(task) + ("-content" if mode == "content" else ""))
    return os.path.join(d, "run-%02d" % int(idx))


def attempts_of(base):
    """The attempts at one slot: those moved aside, then the one in place."""
    recs = []
    for d in sorted(glob.glob(base + ".failed-*")):
        recs.append((d, load(os.path.join(d, "run.json"))))
    if os.path.isdir(base):
        recs.append((base, load(os.path.join(base, "run.json"))))
    return recs


def rule_of(rec):
    if rec is None:
        return "unclassified"
    return (rec.get("exclusion") or {}).get("rule", "unclassified" if rec.get("status") != "ok" else None)


def slot_state(out, agent, version, task, mode, idx):
    """Print ok, exhausted (X4 budget spent), or pending with the attempts made and the X4 ones."""
    recs = attempts_of(slot_base(out, agent, version, task, mode, idx))
    if recs and recs[-1][1] and recs[-1][1].get("status") == "ok":
        print("ok 0 0")
        return
    x4 = sum(1 for _, r in recs if rule_of(r) == "X4")
    print(("exhausted" if x4 >= MAX_X4 else "pending"), len(recs), x4)


def permute(seed):
    """Reorder the slots on stdin (agent, task, mode, run first) by the SHA-256 of seed and slot."""
    rows = [l.rstrip("\n") for l in sys.stdin if l.strip()]
    def key(l):
        f = l.split("\t")
        return hashlib.sha256(f"{seed}|{f[0]}|{f[1]}|{f[2]}|{f[3]}".encode()).hexdigest()
    rows.sort(key=key)
    for n, l in enumerate(rows, 1):
        print(f"{n}\t{len(rows)}\t{l}")


def seed_of(out):
    """Print the seed of the output directory's last invocation."""
    last = ""
    try:
        for line in open(os.path.join(out, "invocations.jsonl"), encoding="utf-8"):
            last = str(json.loads(line).get("seed", last))
    except (OSError, ValueError):
        pass
    print(last)


def versions_in(out, agent, version):
    """Print the directories of out that hold runs of the agent at another version."""
    for d in sorted(glob.glob(os.path.join(out, agent + "-*"))):
        if os.path.isdir(d) and os.path.basename(d) != f"{agent}-{version}":
            print(os.path.basename(d))


# The net probe's log line names its counters in camelCase; the ground truth's
# net_content (coverage schema 2) names them as the record does. The fallback
# maps the logged ones onto those names.
LOG_NET = {"connections": "connections", "withHostname": "with_hostname", "withContent": "with_content",
           "unattributed": "frames_unattributed", "unsupported": "content_unsupported", "dns": "dns",
           "addressProbes": "address_probes", "openAtStop": "open_at_stop", "replaced": "replaced",
           "dials": "dials"}


def content_fraction(c):
    denom = c.get("connections", 0) - c.get("content_unsupported", 0)
    return round(c.get("with_content", 0) / denom, 4) if denom > 0 else None


def net_from_log(log):
    """The counters of watch's `net probe coverage:` line, for a capture whose
    ground truth has no diagnostics (coverage schema 1)."""
    try:
        text = open(log, encoding="utf-8", errors="replace").read()
    except OSError:
        return None
    m = re.search(r"^net probe coverage: (.*)$", text, re.M)
    if not m:
        return None
    c = {LOG_NET[k]: int(v) for k, v in re.findall(r"(\w+)=(\d+)", m.group(1)) if k in LOG_NET}
    c["source"] = "watch log (coverage schema 1 fallback)"
    c["content_fraction"] = content_fraction(c)
    return c


def frac(num, den):
    return round(num / den, 4) if den else None


def diagnostics_of(cov):
    """Per probe, the rings and tracked sets the ground truth's diagnostics hold,
    each with its peak as a fraction of its size. Schema 1 and a probe that
    keeps none (fs) have nothing: not measured."""
    schema = cov.get("schema")
    out = {"source": "ground_truth" if isinstance(schema, int) and schema >= 2 else None,
           "coverage_schema": schema, "probes": {}}
    for name, p in sorted((cov.get("probes") or {}).items()):
        d = (p or {}).get("diagnostics")
        if not d:
            continue
        rings = {}
        for k, r in sorted((d.get("rings") or {}).items()):
            rings[k] = dict(r, peak_fraction=frac(r.get("peak_bytes", 0), r.get("size_bytes", 0)))
        sets = {}
        for k, t in sorted((d.get("tracked_sets") or {}).items()):
            sets[k] = dict(t, peak_fraction=frac(t.get("peak", 0), t.get("capacity", 0)))
        out["probes"][name] = {"rings": rings, "tracked_sets": sets}
    return out


def peak_processes(events, root):
    """The most processes of the tree alive at once, from fork and exit events."""
    live = {root} if root else set()
    peak = len(live)
    for e in sorted(events, key=lambda e: e.get("timestamp", "")):
        t, pid = e.get("action_type"), e.get("pid")
        if t == "process_fork":
            live.add(pid)
        elif t == "process_exit":
            live.discard(pid)
        peak = max(peak, len(live))
    return peak


def scale(gt_path, log_path):
    g = load(gt_path)
    if g is None:
        return None
    events = g.get("events") or []
    by_type = collections.Counter(e.get("action_type") for e in events)
    def targets(kind):
        return dict(collections.Counter(e.get("target", "") for e in events if e.get("action_type") == kind).most_common())
    cov = g.get("coverage") or {}
    probes = {n: {k: v for k, v in (p or {}).items() if k != "diagnostics"} for n, p in (cov.get("probes") or {}).items()} or None
    diag = diagnostics_of(cov)
    nc = (((cov.get("probes") or {}).get("net") or {}).get("diagnostics") or {}).get("net_content")
    if nc:
        net = dict(nc, source="ground truth net_content (coverage schema %s)" % cov.get("schema"))
        net["content_fraction"] = content_fraction(net)
    elif diag["source"] is None:
        net = net_from_log(log_path)
    else:
        net = None  # schema 2 and the net probe kept no counters: it did not run
    return {
        "ground_truth": gt_path,
        "probes": probes,
        "diagnostics": diag,
        "net": net,
        "events": {"total": len(events), "by_type": dict(sorted(by_type.items())),
                   "net_connect_by_target": targets("net_connect"),
                   "net_request_by_target": targets("net_request")},
        "processes": {"peak_alive": peak_processes(events, g.get("root_pid")),
                      "forks": by_type.get("process_fork", 0)},
    }


def verdict(path):
    v = load(path)
    if v is None:
        return None
    a = v.get("alignment") or {}
    p = v.get("parse") or {}
    return {
        "outcome": v.get("outcome"), "exit_code": v.get("exit_code"), "findings": v.get("findings"),
        "tool_calls": p.get("ToolCalls"), "claims": p.get("Entries"), "agent_version": p.get("AgentVersion"),
        "alignment": {k: len(x or []) for k, x in sorted(a.items())},
        "complete": (v.get("completeness") or {}).get("Complete"),
        "reasons": v.get("reasons") or [],
    }


CHECKS = {"0": "ok", "1": "mismatch", "2": "unrecorded", "-": "not-run"}


def count_of(v):
    """A count from order.tsv, or None where it was not counted (-) or absent."""
    return int(v) if v and v.isdigit() else None


def read_order(run_dir):
    """The runs of one capture in the order they were recorded, with their model checks."""
    rows = []
    try:
        lines = open(os.path.join(run_dir, "order.tsv"), encoding="utf-8").read().splitlines()
    except OSError:
        return rows
    for line in lines:
        f = line.split("\t")
        if len(f) < 6:
            continue
        m = re.fullmatch(r"model_check=([^;]*);(?:observed=([^;]*);subagents=(.*))?", f[5])
        wx = re.fullmatch(r"watch_exit=(\d+)", f[6]) if len(f) > 6 else None
        # The subagents the run started and their tool calls (I-71); absent
        # in a capture made before the field, and - where not counted.
        sa = re.fullmatch(r"subagents=(\d+|-)(?:;subagent_tool_calls=(\d+|-))?", f[7]) if len(f) > 7 else None
        rows.append({"seq": int(f[0]), "label": f[1], "role": f[2], "start": f[3], "end": f[4],
                     "watch_exit": int(wx.group(1)) if wx else None,
                     "subagents": count_of(sa.group(1)) if sa else None,
                     "subagent_tool_calls": count_of(sa.group(2)) if sa else None,
                     "model_check": CHECKS.get(m.group(1), m.group(1)) if m else "unknown",
                     "model_observed": [x for x in (m.group(2) or "").split(",") if x] if m else [],
                     "subagent_models": [x for x in (m.group(3) or "").split(",") if x] if m else []})
    return rows


def read_kv(path):
    d = {}
    try:
        for line in open(path, encoding="utf-8"):
            if "=" in line:
                k, v = line.rstrip("\n").split("=", 1)
                d[k] = v
    except OSError:
        pass
    return d


def classify(exit_status, log, version, version_after):
    """The exclusion rule and reason of a run that did not complete (protocol 10.1)."""
    if exit_status == 130:
        return {"rule": "X6", "reason": "interrupted"}
    if version_after and version_after != version:
        return {"rule": "X3", "reason": f"version changed during the run: {version} to {version_after}"}
    if "MODEL MISMATCH" in log:
        return {"rule": "X4", "reason": "model-mismatch"}
    if AUTH.search(log):
        return {"rule": "X4", "reason": "auth"}
    if QUOTA.search(log):
        return {"rule": "X4", "reason": "quota"}
    if "no transcript found" in log or "no conversation database found" in log:
        return {"rule": "X4", "reason": "no-transcript"}
    if "watch exited non-zero" in log:
        return {"rule": "X4", "reason": "watch-failed"}
    return {"rule": "X4", "reason": "harness-error"}


COST_FIELDS = ("startup_s", "drain_s", "watch_cpu_s", "watch_maxrss_kb")


def read_cost(path):
    """The measurements scripts/measure-watch.py wrote for one watch. The four
    fields cmd/analyze reads come first; a field that was not measured is null.
    None when there is no file (the measurement did not run)."""
    c = load(path)
    if not isinstance(c, dict):
        return None
    out = {k: c.get(k) for k in COST_FIELDS}
    for k in ("agent_s", "wall_s", "tree_cpu_s", "tree_maxrss_kb", "watch_maxrss_is_lower_bound", "interval_ms",
              "samples", "method", "notes"):
        if k in c:
            out[k] = c[k]
    return out


def update_annotations(out, rid, auto):
    """Rewrite the runner's own fields of annotations.json for one run. The
    entry lists them under "auto"; fields the operator set (annotate-run.sh
    removes a field from "auto") are never touched."""
    path = os.path.join(out, "annotations.json")
    doc = load(path) if os.path.exists(path) else {}
    if not isinstance(doc, dict):
        # The run is recorded; a damaged operator file is reported, never overwritten.
        print("capture-campaign: %s is not a JSON object; not updated, fix or remove it" % path, file=sys.stderr)
        return
    runs = doc.setdefault("runs", {})
    entry = runs.get(rid) or {}
    for k in entry.get("auto", []):
        entry.pop(k, None)
    entry.pop("auto", None)
    entry.update(auto)
    if auto:
        entry["auto"] = sorted(auto)
    if entry:
        runs[rid] = entry
    else:
        runs.pop(rid, None)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, path)


def watch_nonzero(run_dir, lab, code):
    """Classify a task run's non-zero watch exit from watch's log: ("agent", N)
    when the agent it ran exited with an error (N is the agent's status, else
    watch's own), which does not make the run a failure (I-66), and ("watch",
    reason) when watch itself failed, a harness error (X4)."""
    try:
        text = open(os.path.join(run_dir, f"{lab}.watch.log"), encoding="utf-8", errors="replace").read()
    except OSError:
        text = ""
    m = re.search(r"agent exited with error: exit status (\d+)", text)
    if m:
        return "agent", int(m.group(1))
    if "agent exited with error" in text:
        return "agent", code
    return "watch", f"watch failed with exit status {code} for the task run; the capture and the transcript exist"


def summarize(run_dir, agent, version, task, idx, mode, start, end, exit_status, seed, position, total,
              attempt, model, version_after):
    """Write run.json for one run and print its status, rule and reason."""
    lab = label(task)
    def f(name):
        p = os.path.join(run_dir, name)
        return p if os.path.exists(p) else None
    traj = f(f"{lab}.session.jsonl") or f(f"{lab}.conversation.db")
    control_scale = []
    for gt in sorted(glob.glob(os.path.join(run_dir, "control-*.ground_truth.json")),
                     key=lambda p: int(re.search(r"control-(\d+)", p).group(1))):
        name = os.path.basename(gt)[:-len(".ground_truth.json")]
        s = scale(gt, os.path.join(run_dir, f"{name}.watch.log"))
        if s:
            s["label"] = name
            control_scale.append(s)
    exit_status = int(exit_status)
    try:
        log = open(os.path.join(run_dir, "campaign.log"), encoding="utf-8", errors="replace").read()
    except OSError:
        log = ""
    # The agent's own error text is in the watch logs (stderr goes there),
    # between the probes' event lines, which name files and hosts that can
    # contain any word (an npm package called rate-limit): only the other
    # lines are read.
    for wl in sorted(glob.glob(os.path.join(run_dir, "*.watch.log"))):
        try:
            text = open(wl, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        log += "\n" + "\n".join(l for l in text.splitlines() if not EVENT_LINE.match(l))
    order = read_order(run_dir)
    meta = read_kv(os.path.join(run_dir, "task-meta.txt"))
    co = read_kv_pairs(os.path.join(run_dir, "control-order.txt"))
    task_row = next((r for r in order if r["role"] == "task"), None)
    changed = bool(version_after) and version_after != version
    # A session can end with a transcript although the account stopped it: a
    # quota or login error in the task's or any control's output means the
    # task did not run to its end or a control recorded nothing, so the run
    # fails and the campaign stops (the agy pilot of 2026-10-27 hit its quota
    # mid-task and in three controls and was read as complete).
    account = "auth" if ACCOUNT_AUTH.search(log) else ("quota" if ACCOUNT_QUOTA.search(log) else None)
    ok = exit_status == 0 and not changed and account is None
    r = {
        "agent": agent, "version": version, "version_after": version_after, "task": task, "run": int(idx),
        "mode": mode, "dir": run_dir,
        "status": "ok" if ok else ("interrupted" if exit_status == 130 else "failed"),
        "exit_status": exit_status, "start": start, "end": end,
        "duration_s": round((datetime.datetime.fromisoformat(end) - datetime.datetime.fromisoformat(start)).total_seconds()),
        "slot": {"seed": int(seed), "position": int(position), "of": int(total), "attempt": int(attempt)},
        "model": model,
        "model_check": task_row["model_check"] if task_row else "not-run",
        "model_observed": task_row["model_observed"] if task_row else [],
        "task_prompt_sha256": meta.get("task_prompt_sha256"), "seed_sha256": meta.get("seed_sha256"),
        "controls": {"count": len(control_scale), "before": co.get("before"), "after": co.get("after"),
                     "order": order, "fresh": True},
        "paths": {"trajectory": traj, "ground_truth": f(f"{lab}.ground_truth.json"),
                  "watch_log": f(f"{lab}.watch.log"), "report": f("report.txt"),
                  "verify_json": f("verify.json"), "verify_baseline_json": f("verify-baseline.json"),
                  "baseline": f("baseline.json"), "campaign_log": f("campaign.log")},
        "verdict": {"without_baseline": verdict(os.path.join(run_dir, "verify.json")),
                    "with_baseline": verdict(os.path.join(run_dir, "verify-baseline.json"))},
        "scale": scale(os.path.join(run_dir, f"{lab}.ground_truth.json"), os.path.join(run_dir, f"{lab}.watch.log")),
        "control_scale": control_scale,
    }
    cost = read_cost(os.path.join(run_dir, f"{lab}.cost.json"))
    if cost is not None:
        r["cost"] = cost
    control_cost = []
    for cs in control_scale:
        c = read_cost(os.path.join(run_dir, cs["label"] + ".cost.json"))
        if c is not None:
            control_cost.append(dict(c, label=cs["label"]))
    if control_cost:
        r["control_cost"] = control_cost
    r["watch_exit"] = {"task": task_row["watch_exit"] if task_row else None,
                       "controls": {o["label"]: o["watch_exit"] for o in order if o["role"] == "control"}}
    if ok:
        exclusion = None
    elif exit_status == 0 and not changed and account:
        exclusion = {"rule": "X4", "reason": account}
    else:
        exclusion = classify(exit_status, log, version, version_after)
    if exclusion:
        r["exclusion"] = exclusion
    with open(os.path.join(run_dir, "run.json"), "w", encoding="utf-8") as fh:
        json.dump(r, fh, indent=2)
        fh.write("\n")
    out_root = os.path.dirname(os.path.dirname(os.path.dirname(run_dir.rstrip("/"))))
    wx = r["watch_exit"]["task"]
    auto = {}
    if ok and wx:
        kind, what = watch_nonzero(run_dir, lab, wx)
        # An agent that exited non-zero after a complete session counts (I-66):
        # its status is a note the analysis does not read. Only watch's own
        # failure is a harness error.
        auto["agent_exit_status" if kind == "agent" else "x4"] = what
    update_annotations(out_root, os.path.relpath(run_dir, out_root), auto)
    print("\t".join([r["status"], exclusion["rule"] if exclusion else "-", exclusion["reason"] if exclusion else "-"]))


def read_kv_pairs(path):
    """before=2 after=3 on one line."""
    try:
        return dict(re.findall(r"(\w+)=(\d+)", open(path, encoding="utf-8").read()))
    except OSError:
        return {}


def manifest(out, plan_path, commit, dirty, seed):
    runs, attempts = [], []
    for path in sorted(glob.glob(os.path.join(out, "*", "*", "run-*", "run.json"))):
        d = os.path.dirname(path)
        r = load(path)
        if not r:
            continue
        if re.fullmatch(r"run-\d+", os.path.basename(d)):
            runs.append(r)
        else:
            attempts.append(r)
    # An attempt moved aside without a record (the campaign was killed) is listed too.
    for d in sorted(glob.glob(os.path.join(out, "*", "*", "run-*.failed-*"))):
        if os.path.isdir(d) and not os.path.exists(os.path.join(d, "run.json")):
            attempts.append({"dir": d, "status": "incomplete", "exclusion": {"rule": "unclassified", "reason": "no run.json: the campaign ended inside this run"}})
    excluded = [{"dir": r.get("dir"), "agent": r.get("agent"), "task": r.get("task"), "run": r.get("run"),
                 "attempt": (r.get("slot") or {}).get("attempt"), **(r.get("exclusion") or {})}
                for r in runs + attempts if r.get("status") != "ok"]
    by_rule = collections.Counter(e.get("rule") for e in excluded)
    slots = {}
    for r in runs + attempts:
        if "run" not in r:
            continue
        k = (r["agent"], r["version"], r["task"], r["mode"], r["run"])
        s = slots.setdefault(k, {"agent": r["agent"], "version": r["version"], "task": r["task"], "mode": r["mode"],
                                 "run": r["run"], "attempts": 0, "x4": 0, "state": "pending"})
        s["attempts"] += 1
        s["x4"] += (r.get("exclusion") or {}).get("rule") == "X4"
    for r in runs:
        k = (r["agent"], r["version"], r["task"], r["mode"], r["run"])
        slots[k]["state"] = "ok" if r["status"] == "ok" else slots[k]["state"]
    for s in slots.values():
        if s["state"] != "ok" and s["x4"] >= MAX_X4:
            s["state"] = "failed"
    invocations = []
    try:
        invocations = [json.loads(l) for l in open(os.path.join(out, "invocations.jsonl"), encoding="utf-8") if l.strip()]
    except (OSError, ValueError):
        pass
    validations = [v for v in (load(p) for p in sorted(glob.glob(os.path.join(out, "validation", "*.json")))) if v]
    m = {"schema": 2, "generated": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
         "plan": open(plan_path, encoding="utf-8").read(), "commit": commit, "dirty": dirty == "true",
         "seed": int(seed) if seed else None, "invocations": invocations, "validations": validations,
         "runs": runs, "attempts": attempts,
         "slots": sorted(slots.values(), key=lambda s: (s["agent"], s["task"], s["mode"], s["run"])),
         "exclusions": {"by_rule": dict(by_rule), "list": excluded}}
    with open(os.path.join(out, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(m, fh, indent=2)
        fh.write("\n")
    def g(d, *ks):
        for k in ks:
            if not isinstance(d, dict):
                return None
            d = d.get(k)
        return d
    def peak(s, probe, kind):
        """The highest peak fraction among a probe's rings or tracked sets, as a percentage."""
        d = g(s, "diagnostics", "probes", probe, kind)
        v = [x.get("peak_fraction") for x in (d or {}).values() if x.get("peak_fraction") is not None]
        return "-" if not v else "%.1f" % (100 * max(v))
    rows = [("run", "status", "verdict", "with baseline", "calls", "claims", "drops f/p/n",
             "untracked p/n", "ring peak% p/n", "tracked peak% p/n", "peak procs", "content", "model", "seconds")]
    for r in runs:
        s = r.get("scale") or {}
        probes = s.get("probes") or {}
        drops = "/".join(str(g(probes, p, "ringbuf_drops")) for p in ("fs", "proc", "net"))
        untracked = "/".join(str(g(probes, p, "untracked_children")) for p in ("proc", "net"))
        net = s.get("net") or {}
        content = "-" if not net else f"{net.get('with_content')}/{net.get('connections')}-{net.get('content_unsupported')}"
        rings = "/".join(peak(s, p, "rings") for p in ("proc", "net"))
        tracked = "/".join(peak(s, p, "tracked_sets") for p in ("proc", "net"))
        st = r["status"] + ("" if r["status"] == "ok" else f" {g(r, 'exclusion', 'rule')} {g(r, 'exclusion', 'reason')}")
        rows.append((os.path.relpath(r["dir"], out), st,
                     str(g(r, "verdict", "without_baseline", "outcome")),
                     str(g(r, "verdict", "with_baseline", "outcome")),
                     str(g(r, "verdict", "without_baseline", "tool_calls")),
                     str(g(r, "verdict", "without_baseline", "claims")),
                     drops, untracked, rings, tracked, str(g(s, "processes", "peak_alive")), content,
                     f"{r.get('model')} {r.get('model_check')}", str(r.get("duration_s"))))
    widths = [max(len(row[i]) for row in rows) for i in range(len(rows[0]))]
    with open(os.path.join(out, "summary.txt"), "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write("  ".join(c.ljust(w) for c, w in zip(row, widths)).rstrip() + "\n")
        failed = [s for s in m["slots"] if s["state"] == "failed"]
        fh.write(f"\nattempts excluded: {dict(by_rule) or 'none'}; slots failed three times: {len(failed)}\n")
        for s in failed:
            fh.write(f"  failed slot: {s['agent']} {s['version']} {s['task']} {s['mode']} run {s['run']}\n")


def estimate(task, pending, controls_per_run):
    """Print the model turns for the pending task sessions and their controls."""
    per = TURNS.get(task, HELDOUT_TURNS)
    ctl = CONTROL_TURNS.get(task, 2)
    print(per * int(pending) + ctl * int(pending) * int(controls_per_run))


def invocation(out, seed, commit, dirty, plan_path, controls, validate, e2e, stop_after):
    rec = {"start": datetime.datetime.now().astimezone().isoformat(timespec="seconds"), "seed": int(seed),
           "commit": commit, "dirty": dirty == "true",
           "plan_sha256": hashlib.sha256(open(plan_path, "rb").read()).hexdigest(),
           "controls": int(controls), "validate": bool(validate), "validate_e2e": bool(e2e),
           "stop_after_failures": int(stop_after)}
    with open(os.path.join(out, "invocations.jsonl"), "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")


def templated(target, ws):
    """target with the workspace as cmd/baseline writes it in a rule (I-24, I-29,
    I-70): every UTF-16 unit but an ASCII letter or digit a dash, and no
    mangled form over 200 units, which the harness hashes."""
    if len(ws) < 2:
        return target
    target = target.replace(ws, "{workspace}")
    mangled = "".join(c if c.isascii() and c.isalnum() else "-" * (2 if ord(c) > 0xFFFF else 1) for c in ws)
    if len(mangled) > 200:
        return target
    return target.replace(mangled, "{workspace-}")


def events_text(events, limit=5):
    shown = ", ".join(f"{e.get('action_type')} {e.get('target')}" for e in events[:limit])
    return shown + (f" and {len(events) - limit} more" if len(events) > limit else "")


def null_check(*paths):
    """Each null control must have written a trajectory of no claims (I-67)."""
    bad = []
    for p in paths:
        t = load(p)
        if t != []:
            bad.append(f"{os.path.basename(p)}: " + ("missing or unreadable" if t is None else f"{len(t) if isinstance(t, list) else 'not a list of'} claim(s)"))
    print("ok" if not bad else "a null control did not write an empty trajectory: " + "; ".join(bad))


def power(baseline, honest_traj, honest_ws):
    """The baseline built from the null controls must explain none of the known
    answer's actions, or the dropped entry would be hidden (I-67). A rule that
    names the workspace, a command rule or a subtree record means a null control
    did something simagent --null never does: the check fails closed."""
    b = load(baseline)
    if b is None:
        print(f"no baseline at {baseline}")
        return
    rules = b.get("rules") or []
    problems = []
    ws_rules = [r for r in rules if "{workspace" in r.get("target", "")]
    if ws_rules:
        problems.append(f"{len(ws_rules)} rule(s) name the workspace ({events_text(ws_rules, 3)})")
    cmd_rules = [r for r in rules if r.get("action_type", "").startswith("process_")]
    if cmd_rules or b.get("subtrees"):
        problems.append(f"{len(cmd_rules)} command rule(s) and {len(b.get('subtrees') or [])} subtree record(s), though a null control runs no command ({events_text(cmd_rules, 3)})")
    t = load(honest_traj)
    if not isinstance(t, list) or not t:
        problems.append(f"no honest trajectory at {honest_traj} to check the rules against")
    else:
        have = {(r.get("action_type"), r.get("target")) for r in rules}
        hidden = [e for e in t if (e.get("action_type"), templated(e.get("target", ""), honest_ws)) in have]
        if hidden:
            problems.append(f"the baseline explains {len(hidden)} of the known answer's {len(t)} action(s) ({events_text(hidden, 3)})")
    if problems:
        print("the baseline from the null controls would hide what the known answer must show: " + "; ".join(problems))
    else:
        print("ok")


def judge(kind, path, rc, honest_traj="", honest_ws="", dropped_ws=""):
    """Judge one known-answer verify run against the null baseline (protocol 9.4,
    I-67); print ok or the reason."""
    v = load(path)
    if v is None:
        print(f"{kind}: no verify JSON at {path}")
        return
    want = {"honest": ("FAITHFUL", 0), "dropped": ("NOT FAITHFUL", 1)}[kind]
    got = (v.get("outcome"), int(rc))
    al = v.get("alignment") or {}
    unrecorded = al.get("unrecorded") or []
    if got != want:
        why = f"{kind}: verify said {got[0]} (exit {got[1]}), wanted {want[0]} (exit {want[1]})"
        if kind == "honest" and unrecorded:
            why += f"; {len(unrecorded)} Unrecorded event(s) no null control explains: {events_text(unrecorded)}"
        print(why)
        return
    if kind == "dropped":
        if v.get("findings") != 1 or len(unrecorded) != 1:
            print(f"dropped: wanted exactly one finding, an Unrecorded one; got {v.get('findings')} finding(s), {len(unrecorded)} Unrecorded" + (f": {events_text(unrecorded)}" if unrecorded else ""))
            return
        t = load(honest_traj)
        if not isinstance(t, list) or not t:
            print(f"dropped: no honest trajectory at {honest_traj} to name the dropped entry")
            return
        e0 = t[0]
        expect = (e0.get("action_type"), templated(e0.get("target", ""), honest_ws))
        seen = (unrecorded[0].get("action_type"), templated(unrecorded[0].get("target", ""), dropped_ws))
        if seen != expect:
            print(f"dropped: the Unrecorded event is {seen[0]} {seen[1]}, not the dropped entry {expect[0]} {expect[1]}")
            return
    print("ok")


def validation_write(path, commit, honest, dropped, e2e, controls="not-run", baseline="not-run", power_="not-run", nulls="0", rules=""):
    checks = [honest, dropped, controls, baseline, power_]
    rec = {"time": datetime.datetime.now().astimezone().isoformat(timespec="seconds"), "commit": commit,
           "method": "verify against a baseline of simagent --null control runs (I-67)",
           "null_controls": int(nulls), "null_controls_check": controls, "baseline": baseline,
           "baseline_rules": int(rules) if rules.isdigit() else None, "baseline_hides_nothing": power_,
           "known_answer_honest": honest, "known_answer_dropped": dropped, "e2e": e2e,
           "passed": all(c == "ok" for c in checks) and e2e in ("ok", "not-run")}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(rec, fh, indent=2)
        fh.write("\n")


def baseline_rules(path):
    b = load(path)
    print(len(b.get("rules") or []) if isinstance(b, dict) else "")


cmd = sys.argv[1]
args = sys.argv[2:]
{"plan": plan, "slot-state": slot_state, "permute": permute, "seed": seed_of, "versions": versions_in,
 "summarize": summarize, "manifest": manifest, "estimate": estimate, "invocation": invocation,
 "judge": judge, "validation-write": validation_write, "null-check": null_check, "power": power,
 "baseline-rules": baseline_rules}[cmd](*args)
PY
helper() { python3 "$helper" "$@"; }

# start_privileged: build once, ask for sudo once and keep the credential
# fresh for the hours a long campaign takes. sudo -n never prompts; if the
# credential lapses anyway, the next capture asks again. The refresher ends
# with the campaign, and holds none of its output open.
start_privileged() {
  mkdir -p "$out"
  (cd "$root" && make build >/dev/null)
  sudo -v
  local campaign=$$
  ( while sleep 60 && kill -0 "$campaign" 2>/dev/null; do sudo -n -v || exit 0; done ) >/dev/null 2>&1 </dev/null &
  keepalive=$!
}

# Instrument validation (protocol 9.4, I-67), before the first run of the
# invocation. watch marks every filesystem (P-17), so the capture of a known
# answer also holds simagent's own start-up and exit: the hold script, setpriv,
# the loader, simagent's binary, the zone file and the write of the trajectory.
# Null control runs measure that activity, a baseline subtracts it, and the
# power check makes sure the baseline explains none of the known answer.
null_runs=3
validate_instrument() {
  local ts vdir traj n rc i e2e=not-run
  local honest="not run" dropped="not run" nullchk="not run" base="not run" pow="not run" rules=
  local null_trajs=() null_gts=() watch_failed=()
  ts=$(date +%Y%m%d-%H%M%S)
  vdir=$out/validation/$ts
  # One trajectory path for every run, so the rules for its write hold in each
  # (I-41); each run's file is moved aside after it, outside watch.
  traj=$vdir/trajectory.json
  mkdir -p "$vdir"
  echo "validating the instrument (protocol 9.4), $vdir"
  # run_known NAME [SIMAGENT FLAGS]: one run of simagent under watch.
  run_known() {
    local n=$1 ws=$vdir/ws-$1
    shift
    mkdir -p "$ws"
    rm -f "$traj"
    sudo "$root/watch" --probes fs,proc --workspace "$ws" --out "$vdir/$n.ground_truth.json" -- \
      setpriv --reuid "$(id -u)" --regid "$(id -g)" --init-groups --reset-env \
      "$root/simagent" --workspace "$ws" --trajectory-out "$traj" "$@" \
      >"$vdir/$n.watch.log" 2>&1 || watch_failed+=("$n")
    sudo chown -R "$(id -u):$(id -g)" "$vdir" 2>/dev/null || true
    [ ! -e "$traj" ] || mv "$traj" "$vdir/$n.trajectory.json"
  }
  run_known null-1 --null
  run_known honest
  run_known null-2 --null
  run_known dropped --drop-entry 0
  for i in $(seq 3 "$null_runs"); do run_known "null-$i" --null; done
  for i in $(seq 1 "$null_runs"); do
    null_trajs+=("$vdir/null-$i.trajectory.json")
    null_gts+=("$vdir/null-$i.ground_truth.json")
  done

  if [ "${#watch_failed[@]}" -gt 0 ]; then
    nullchk="watch exited non-zero for ${watch_failed[*]}, see their .watch.log"
  else
    nullchk=$(helper null-check "${null_trajs[@]}")
  fi
  if [ "$nullchk" = ok ]; then
    rc=0
    "$root/baseline" --agent generic --agent-version simagent --min-agreement "$(awk -v n="$null_runs" 'BEGIN { printf "%.4f", 1 / n }')" \
      --out "$vdir/baseline.json" "${null_gts[@]}" >"$vdir/baseline.log" 2>&1 || rc=$?
    if [ "$rc" -eq 0 ]; then
      base=ok
      rules=$(helper baseline-rules "$vdir/baseline.json")
      pow=$(helper power "$vdir/baseline.json" "$vdir/honest.trajectory.json" "$vdir/ws-honest")
    else
      base="cmd/baseline refused the null controls (exit $rc): $(tail -1 "$vdir/baseline.log")"
    fi
  fi
  if [ "$pow" = ok ]; then
    for n in honest dropped; do
      rc=0
      "$root/verify" --agent generic --trajectory "$vdir/$n.trajectory.json" --ground-truth "$vdir/$n.ground_truth.json" \
        --baseline "$vdir/baseline.json" --json "$vdir/$n.verify.json" >"$vdir/$n.verify.txt" 2>&1 || rc=$?
      if [ "$n" = honest ]; then
        honest=$(helper judge honest "$vdir/$n.verify.json" "$rc")
      else
        dropped=$(helper judge dropped "$vdir/$n.verify.json" "$rc" "$vdir/honest.trajectory.json" "$vdir/ws-honest" "$vdir/ws-dropped")
      fi
    done
  fi
  if [ -n "$validate_e2e" ]; then
    echo "running sudo go test ./tests/e2e (slow), log $vdir/e2e.log"
    if (cd "$root" && sudo env PATH="$PATH" go test -count=1 ./tests/e2e) >"$vdir/e2e.log" 2>&1; then e2e=ok; else e2e="failed, see $vdir/e2e.log"; fi
  fi
  helper validation-write "$out/validation/$ts.json" "$commit" "$honest" "$dropped" "$e2e" "$nullchk" "$base" "$pow" "$null_runs" "$rules"
  [ -n "$validate_only" ] || helper manifest "$out" "$plan" "$commit" "$dirty" "$seed"
  echo "   null controls: $nullchk; baseline: $base${rules:+ ($rules rules)}; baseline hides nothing: $pow"
  echo "   FAITHFUL known answer: $honest; dropped-entry known answer: $dropped; e2e: $e2e"
  [ "$nullchk" = ok ] && [ "$base" = ok ] && [ "$pow" = ok ] && [ "$honest" = ok ] && [ "$dropped" = ok ] &&
    { [ "$e2e" = ok ] || [ "$e2e" = not-run ]; } ||
    die "the instrument validation failed: the block is halted (protocol 10.2); read $vdir"
  echo "   the instrument validation passed"
}

if [ -n "$validate_only" ]; then
  echo "output: $out"
  echo "validation only: simagent known answers against a baseline of $null_runs null runs${validate_e2e:+ and sudo go test ./tests/e2e}; no agent session"
  if [ -n "$dry_run" ]; then
    echo "dry run: everything checked; nothing was built, no sudo was asked for, nothing was run"
    exit 0
  fi
  commit=$(git -C "$root" rev-parse --short HEAD 2>/dev/null || echo unknown)
  start_privileged
  validate_instrument
  exit 0
fi

entries=$(helper plan "$plan") || die "the plan is not valid"
if grep -q $'\theldout:' <<<"$entries" && [ -z "$heldout_dir" ]; then
  die "the plan has held-out tasks: give --heldout-dir DIR, which holds NAME/prompt.txt and NAME/tools.txt for each"
fi

# check AGENT TASK MODE MODEL BEFORE: capture-claude-code.sh --check, which
# prints key=value lines; the caller reads them with field.
check() {
  local args=(--agent "$1" --task "$2" --check --model "$4" --controls-before "$5")
  [ "$3" != content ] || args+=(--content)
  [ -z "$allow_unconfigured" ] || args+=(--allow-unconfigured-version)
  case $2 in heldout:*) args+=(--heldout-dir "$heldout_dir") ;; esac
  CONTROLS=$controls "$capture" "${args[@]}" "$out/.check"
}
field() { sed -n "s/^$1=//p" <<<"$2"; }
# agent_version AGENT: the version the installed agent states now, read the way
# the capture script reads it.
agent_version() {
  if [ "$1" = gemini ]; then agy --version 2>/dev/null | awk '{print $NF}'
  else claude --version 2>/dev/null | awk '{print $1}'; fi
}
run_dir() { # agent version task mode index
  local d="$out/$1-$2/${3//:/-}"
  [ "$4" != content ] || d+=-content
  printf '%s/run-%02d' "$d" "$5"
}
before_of() { [ "$1" = split ] && echo $((controls * 2 / 5)) || echo 0; }

# Validate every entry and build the schedule.
declare -A agent_version_of
declare -A entry_model
slots=()
echo "plan: $plan"
echo "output: $out"
while IFS=$'\t' read -r agent task reps mode split model; do
  [ "$model" != - ] || model=
  if [ -z "$model" ]; then
    if [ "$agent" = gemini ]; then model=${agy_model:-gemini-3.8-flash-high}; else model=claude-sonnet-5-5; fi
  fi
  before=$(before_of "$split")
  if ! info=$(check "$agent" "$task" "$mode" "$model" "$before"); then
    die "$agent $task ($mode): capture-claude-code.sh --check refused, see above"
  fi
  version=$(field version "$info")
  if [ -n "${agent_version_of[$agent]:-}" ] && [ "${agent_version_of[$agent]}" != "$version" ]; then
    die "$agent reports version $version for $task and ${agent_version_of[$agent]} for an earlier entry: the agent is changing under the campaign"
  fi
  agent_version_of[$agent]=$version
  entry_model["$agent|$task|$mode"]=$model
  for i in $(seq 1 "$reps"); do
    slots+=("$agent"$'\t'"$task"$'\t'"$mode"$'\t'"$i"$'\t'"$split"$'\t'"$model")
  done
done <<<"$entries"
# Each entry's check above showed the unconfigured-version warning once; the
# capture script stays quiet about it for the runs (it still refuses without
# --allow-unconfigured-version).
export AGENT_TRACE_VERSION_WARNED=1
for agent in "${!agent_version_of[@]}"; do
  other=$(helper versions "$out" "$agent" "${agent_version_of[$agent]}")
  if [ -n "$other" ] && [ -z "$new_stratum" ]; then
    die "$out already holds runs of $agent at another version ($(tr '\n' ' ' <<<"$other")), the installed one is ${agent_version_of[$agent]}: a new version is a new stratum (protocol 6.1), onboarded first; pass --new-version-stratum to start it here"
  fi
done

# The order of the slots: a permutation fixed by the seed.
seed_generated=
if [ -z "$seed" ]; then
  seed=$(helper seed "$out")
  if [ -z "$seed" ]; then seed=$(python3 -c 'import secrets; print(secrets.randbelow(2**31))'); seed_generated=1; fi
fi
mapfile -t order < <(printf '%s\n' "${slots[@]}" | helper permute "$seed")

# What is left to do: a slot is done when its run is complete, and finished when
# it has used its three attempts.
pending_order=()
declare -A pend_task
total_task=0 total_control=0 total_turns=0 done_runs=0 failed_slots=0
for line in "${order[@]}"; do
  IFS=$'\t' read -r pos total agent task mode i split model <<<"$line"
  version=${agent_version_of[$agent]}
  read -r st attempts x4 <<<"$(helper slot-state "$out" "$agent" "$version" "$task" "$mode" "$i")"
  case $st in
    ok) done_runs=$((done_runs + 1)) ;;
    exhausted) failed_slots=$((failed_slots + 1)) ;;
    *)
      pending_order+=("$line")
      k="$agent|$task|$mode"
      pend_task[$k]=$(( ${pend_task[$k]:-0} + 1 ))
      ;;
  esac
done
while IFS=$'\t' read -r agent task reps mode split model; do
  k="$agent|$task|$mode"
  pending=${pend_task[$k]:-0}
  version=${agent_version_of[$agent]}
  before=$(before_of "$split")
  turns=$(helper estimate "${task}" "$pending" "$controls")
  if [ "$split" = split ]; then ord="$before controls before, $((controls - before)) after"; else ord="controls after"; fi
  printf '  %-12s %-14s %-8s %s run(s), %s pending, %s control session(s) each (%s), %s %s model %s, about %s model turns\n' \
    "$agent" "$task" "$mode" "$reps" "$pending" "$controls" "$ord" "$agent" "$version" "${entry_model[$k]}" "$turns"
  total_task=$((total_task + pending))
  total_control=$((total_control + pending * controls))
  total_turns=$((total_turns + turns))
done <<<"$entries"
echo "complete already: $done_runs run(s); failed slots (three X4 attempts): $failed_slots"
echo "to record: $total_task task session(s) and $total_control control session(s), about $total_turns model turns"
if [ -n "$seed_generated" ]; then
  echo "seed: $seed (generated; pass --seed $seed to fix it)"
else
  echo "seed: $seed"
fi
if [ "${#pending_order[@]}" -gt 0 ]; then
  echo "order of the pending slots:"
  for line in "${pending_order[@]}"; do
    IFS=$'\t' read -r pos total agent task mode i split model <<<"$line"
    printf '  %3s/%s  %s %s %s run %s\n' "$pos" "$total" "$agent" "$task" "$mode" "$i"
  done
fi
[ -z "$validate" ] || echo "validation: simagent known answers against a baseline of $null_runs null runs${validate_e2e:+ and sudo go test ./tests/e2e} before the first run"
if [ -n "$dry_run" ]; then
  echo "dry run: everything checked; nothing was built, no sudo was asked for, no agent was run"
  exit 0
fi
commit=$(git -C "$root" rev-parse --short HEAD 2>/dev/null || echo unknown)
dirty=false
[ -z "$(git -C "$root" status --porcelain --untracked-files=no 2>/dev/null)" ] || dirty=true
[ "$total_task" -gt 0 ] || {
  echo "nothing to record"
  mkdir -p "$out"
  helper manifest "$out" "$plan" "$commit" "$dirty" "$seed"
  exit 0
}

start_privileged

[ -z "$validate" ] || validate_instrument

helper invocation "$out" "$seed" "$commit" "$dirty" "$plan" "$controls" "$validate" "$validate_e2e" "$stop_after"
interrupted=
trap 'interrupted=1' INT
failures=0
declare -A stopped=()
abandoned=()
for line in "${pending_order[@]}"; do
  IFS=$'\t' read -r pos total agent task mode i split model <<<"$line"
  if [ -n "${stopped[$agent]:-}" ]; then
    echo "skipped: $agent $task $mode run $i ($agent's campaign is stopped: ${stopped[$agent]})"
    continue
  fi
  version=${agent_version_of[$agent]}
  before=$(before_of "$split")
  read -r st attempts x4 <<<"$(helper slot-state "$out" "$agent" "$version" "$task" "$mode" "$i")"
  while :; do
    attempts=$((attempts + 1))
    # Repeat the check: the version may have changed since the campaign began.
    if ! info=$(check "$agent" "$task" "$mode" "$model" "$before"); then
      echo "$agent $task ($mode): the check now refuses, see above" >&2
      stopped[$agent]="the check refused before run $i"
      break
    fi
    if [ "$(field version "$info")" != "$version" ]; then
      echo "$agent changed during the campaign (now $(field version "$info"), was $version): its campaign stops (protocol 6.1); onboard the new version, then rerun" >&2
      stopped[$agent]="version changed to $(field version "$info")"
      break
    fi
    d=$(run_dir "$agent" "$version" "$task" "$mode" "$i")
    if [ -e "$d" ]; then
      moved="$d.failed-$(date +%Y%m%d-%H%M%S)-a$((attempts - 1))"
      mv "$d" "$moved"
      echo "moved the earlier attempt aside to $moved"
    fi
    args=(--agent "$agent" --task "$task" --no-build --model "$model" --controls-before "$before")
    [ "$mode" != content ] || args+=(--content)
    [ -z "$allow_unconfigured" ] || args+=(--allow-unconfigured-version)
    case $task in heldout:*) args+=(--heldout-dir "$heldout_dir") ;; esac
    mkdir -p "$d"
    echo
    echo "=== $agent $version $task ($mode) run $i, slot $pos/$total, attempt $attempts -> $d"
    start=$(date --iso-8601=seconds)
    set +e
    # tee -i: Ctrl+C must not end the pipe the capture still writes to.
    CONTROLS=$controls "$capture" "${args[@]}" "$d" 2>&1 | tee -i "$d/campaign.log"
    status=${PIPESTATUS[0]}
    set -e
    end=$(date --iso-8601=seconds)
    [ -z "$interrupted" ] || [ "$status" -ne 0 ] || status=130
    after=$(agent_version "$agent")
    IFS=$'\t' read -r result rule reason <<<"$(helper summarize "$d" "$agent" "$version" "$task" "$i" "$mode" "$start" "$end" "$status" "$seed" "$pos" "$total" "$attempts" "$model" "$after")"
    helper manifest "$out" "$plan" "$commit" "$dirty" "$seed"
    if [ "$result" = ok ]; then echo "=== ok (exit $status)"; else echo "=== $result $rule $reason (exit $status)"; fi
    if [ "$result" = ok ]; then
      failures=0
      break
    fi
    failures=$((failures + 1))
    if [ -n "$interrupted" ]; then
      echo "interrupted: rerun the same command to resume"
      exit 130
    fi
    case $rule in
      X3) stopped[$agent]="the version changed during a run"; break ;;
    esac
    case $reason in
      model-mismatch) die "a run recorded another model than the pinned $model: the campaign stops; read $d/campaign.log" ;;
      auth) die "$agent is not logged in or its login failed: log in, then rerun the same command to resume" ;;
      quota) die "the quota or a rate limit stopped $agent: pause (protocol 10.2), then rerun the same command to resume" ;;
    esac
    x4=$((x4 + 1))
    if [ "$x4" -ge 3 ]; then
      echo "slot failed: $agent $task $mode run $i failed 3 times (X4); it is reported failed and not replaced"
      abandoned+=("$agent $task $mode run $i")
      break
    fi
    if [ "$failures" -ge "$stop_after" ]; then
      die "$failures run(s) failed in a row; read their campaign.log, then rerun the same command to resume"
    fi
    echo "retrying in the same slot (X4, attempt $((attempts + 1)) of 3)"
  done
done
echo
cat "$out/summary.txt"
echo "done. Manifest: $out/manifest.json"
if [ "${#stopped[@]}" -gt 0 ]; then
  for agent in "${!stopped[@]}"; do echo "stopped: $agent: ${stopped[$agent]}"; done
  exit 1
fi
if [ "${#abandoned[@]}" -gt 0 ]; then
  printf 'failed slot: %s\n' "${abandoned[@]}"
fi
