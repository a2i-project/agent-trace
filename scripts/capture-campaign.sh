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
#
# PLAN is a text file with one entry per line, # starting a comment:
#
#   AGENT TASK REPETITIONS [content] [split] [model=ID]
#
#   claude-code long 3 content
#   claude-code project 3
#   gemini long 2 model=gemini-3.8-flash-high
#   gemini heldout:subagent 15 split
#
# AGENT is claude-code or gemini, TASK one of the capture script's tasks for
# that agent or heldout:NAME, REPETITIONS how many task runs to record, and
#   content   turns on the net probe's content capture for that entry's runs and
#             controls (capture-claude-code.sh --content; Claude Code only);
#   split     takes the controls 2 before and 3 after the task run instead of
#             after it (D11), as the task `long` always does;
#   model=ID  the model of the entry's runs (D7). Claude Code defaults to
#             claude-sonnet-5-5. agy has no default: give model=ID or --agy-model
#             ID, the id `agy models` lists (gemini-3.8-flash-high is the one the
#             existing captures recorded), or the script refuses.
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
# instrument (protocol 9.4): simagent under watch must verify FAITHFUL, and
# with --drop-entry 0 NOT FAITHFUL with the one Unrecorded finding; a failure
# stops the invocation before any run (protocol 10.2), the result is written to
# OUTPUT_DIR/validation/. --validate-e2e also runs `sudo go test ./tests/e2e`
# there, which is slow, so it is opt-in. Then it records the plan's slots in a
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
# number, the control order, the SHA-256 of the task's prompt and seed, the
# verdict with and without the baseline (outcome, findings, tool calls, claims,
# the alignment counts, completeness), and the scale record of the task run and
# of each control run:
#   probes        each probe's coverage record from the ground truth (ring
#                 buffer drops, untracked children, state map full, channel
#                 drops, content and response state)
#   net           the net probe's coverage counters from watch's log
#                 (connections, with hostname, with content, unsupported,
#                 dials, ...) and content_fraction, with_content over
#                 connections less unsupported (null when that is zero)
#   events        the ground truth's events by type, and requests and
#                 connections by target
#   processes     the peak number of processes of the agent's tree alive at
#                 once, counted from the fork and exit events
# summary.txt is a table of the same, one line per run.
set -euo pipefail

die() { echo "capture-campaign: $*" >&2; exit 1; }

dry_run=
allow_unconfigured=
controls=${CONTROLS:-5}
stop_after=4
seed=
validate=
validate_e2e=
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
[ $# -eq 2 ] || { echo "usage: $0 [--dry-run] [--controls N] [--seed N] [--validate] [--validate-e2e] [--heldout-dir DIR] [--agy-model ID] [--allow-unconfigured-version] [--new-version-stratum] [--stop-after-failures N] PLAN OUTPUT_DIR" >&2; exit 2; }
plan=$1
out=$2
case $controls in ''|*[!0-9]*|0) die "--controls must be a positive number" ;; esac
case $stop_after in ''|*[!0-9]*|0) die "--stop-after-failures must be a positive number" ;; esac
case $seed in *[!0-9]*) die "--seed must be a number" ;; esac
[ -f "$plan" ] || die "no plan file $plan"

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
# tools controls three and a subagent's.
TURNS = {"basic": 6, "parallel": 9, "project": 20, "edits": 8, "tools": 16,
         "shapes": 8, "search": 7, "long": 150}
HELDOUT_TURNS = 100
CONTROL_TURNS = {"tools": 5}
# Protocol 10.1, X4: a slot is attempted once and retried twice.
MAX_X4 = 3
AUTH = re.compile(r"not logged in|please run /login|/login|authentication_error|invalid api key|oauth token has expired|invalid bearer|401 unauthorized|login expired|not authenticated", re.I)
QUOTA = re.compile(r"rate.?limit|usage limit|quota|resource.?exhausted|\b429\b|credit balance|overloaded", re.I)


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


def net_counters(log):
    try:
        text = open(log, encoding="utf-8", errors="replace").read()
    except OSError:
        return None
    m = re.search(r"^net probe coverage: (.*)$", text, re.M)
    if not m:
        return None
    c = {k: int(v) for k, v in re.findall(r"(\w+)=(\d+)", m.group(1))}
    denom = c.get("connections", 0) - c.get("unsupported", 0)
    c["content_fraction"] = round(c.get("withContent", 0) / denom, 4) if denom > 0 else None
    return c


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
    return {
        "ground_truth": gt_path,
        "probes": (g.get("coverage") or {}).get("probes"),
        "net": net_counters(log_path),
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
        rows.append({"seq": int(f[0]), "label": f[1], "role": f[2], "start": f[3], "end": f[4],
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
    # The agent's own error text is in the watch logs (stderr goes there).
    for wl in sorted(glob.glob(os.path.join(run_dir, "*.watch.log"))):
        try:
            log += "\n" + open(wl, encoding="utf-8", errors="replace").read(200000)
        except OSError:
            pass
    order = read_order(run_dir)
    meta = read_kv(os.path.join(run_dir, "task-meta.txt"))
    co = read_kv_pairs(os.path.join(run_dir, "control-order.txt"))
    task_row = next((r for r in order if r["role"] == "task"), None)
    changed = bool(version_after) and version_after != version
    ok = exit_status == 0 and not changed
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
    exclusion = None if ok else classify(exit_status, log, version, version_after)
    if exclusion:
        r["exclusion"] = exclusion
    with open(os.path.join(run_dir, "run.json"), "w", encoding="utf-8") as fh:
        json.dump(r, fh, indent=2)
        fh.write("\n")
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
    rows = [("run", "status", "verdict", "with baseline", "calls", "claims", "drops f/p/n",
             "untracked p/n", "peak procs", "content", "model", "seconds")]
    for r in runs:
        s = r.get("scale") or {}
        probes = s.get("probes") or {}
        drops = "/".join(str(g(probes, p, "ringbuf_drops")) for p in ("fs", "proc", "net"))
        untracked = "/".join(str(g(probes, p, "untracked_children")) for p in ("proc", "net"))
        net = s.get("net") or {}
        content = "-" if not net else f"{net.get('withContent')}/{net.get('connections')}-{net.get('unsupported')}"
        st = r["status"] + ("" if r["status"] == "ok" else f" {g(r, 'exclusion', 'rule')} {g(r, 'exclusion', 'reason')}")
        rows.append((os.path.relpath(r["dir"], out), st,
                     str(g(r, "verdict", "without_baseline", "outcome")),
                     str(g(r, "verdict", "with_baseline", "outcome")),
                     str(g(r, "verdict", "without_baseline", "tool_calls")),
                     str(g(r, "verdict", "without_baseline", "claims")),
                     drops, untracked, str(g(s, "processes", "peak_alive")), content,
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


def judge(kind, path, rc):
    """Judge one known-answer verify run (protocol 9.4); print ok or the reason."""
    v = load(path)
    if v is None:
        print(f"no verify JSON at {path}")
        return
    want = {"honest": ("FAITHFUL", 0), "dropped": ("NOT FAITHFUL", 1)}[kind]
    got = (v.get("outcome"), int(rc))
    if got != want:
        print(f"{kind}: verify said {got[0]} (exit {got[1]}), wanted {want[0]} (exit {want[1]})")
        return
    if kind == "dropped":
        unrecorded = len((v.get("alignment") or {}).get("unrecorded") or [])
        if v.get("findings") != 1 or unrecorded != 1:
            print(f"dropped: wanted exactly one finding, an Unrecorded one; got {v.get('findings')} finding(s), {unrecorded} Unrecorded")
            return
    print("ok")


def validation_write(path, commit, honest, dropped, e2e):
    rec = {"time": datetime.datetime.now().astimezone().isoformat(timespec="seconds"), "commit": commit,
           "known_answer_honest": honest, "known_answer_dropped": dropped, "e2e": e2e,
           "passed": honest == "ok" and dropped == "ok" and e2e in ("ok", "not-run")}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(rec, fh, indent=2)
        fh.write("\n")


cmd = sys.argv[1]
args = sys.argv[2:]
{"plan": plan, "slot-state": slot_state, "permute": permute, "seed": seed_of, "versions": versions_in,
 "summarize": summarize, "manifest": manifest, "estimate": estimate, "invocation": invocation,
 "judge": judge, "validation-write": validation_write}[cmd](*args)
PY
helper() { python3 "$helper" "$@"; }

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
    if [ "$agent" = gemini ]; then model=$agy_model; else model=claude-sonnet-5-5; fi
  fi
  [ "$agent" != gemini ] || [ -n "$model" ] ||
    die "gemini $task: agy has no default model here; give model=ID in the plan or --agy-model ID (an id \`agy models\` lists, e.g. gemini-3.8-flash-high)"
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
[ -z "$validate" ] || echo "validation: simagent known answers${validate_e2e:+ and sudo go test ./tests/e2e} before the first run"
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

mkdir -p "$out"
(cd "$root" && make build >/dev/null)
sudo -v
# Keep the credential fresh for the hours a long campaign takes. sudo -n never
# prompts; if the credential lapses anyway, the next capture asks again.
# It ends with the campaign, and holds none of its output open.
campaign=$$
( while sleep 60 && kill -0 "$campaign" 2>/dev/null; do sudo -n -v || exit 0; done ) >/dev/null 2>&1 </dev/null &
keepalive=$!

# Instrument validation (protocol 9.4), before the first run of the invocation.
validate_instrument() {
  local ts vdir n ws drop honest dropped e2e=not-run rc
  ts=$(date +%Y%m%d-%H%M%S)
  vdir=$out/validation/$ts
  mkdir -p "$vdir"
  echo "validating the instrument (protocol 9.4), $vdir"
  for n in honest dropped; do
    ws=$vdir/ws-$n
    mkdir -p "$ws"
    drop=()
    [ "$n" != dropped ] || drop=(--drop-entry 0)
    sudo "$root/watch" --probes fs,proc --workspace "$ws" --out "$vdir/$n.ground_truth.json" -- \
      setpriv --reuid "$(id -u)" --regid "$(id -g)" --init-groups --reset-env \
      "$root/simagent" --workspace "$ws" --trajectory-out "$vdir/$n.trajectory.json" "${drop[@]}" \
      >"$vdir/$n.watch.log" 2>&1 || echo "   watch exited non-zero, see $vdir/$n.watch.log"
    sudo chown -R "$(id -u):$(id -g)" "$vdir" 2>/dev/null || true
    rc=0
    "$root/verify" --trajectory "$vdir/$n.trajectory.json" --ground-truth "$vdir/$n.ground_truth.json" \
      --json "$vdir/$n.verify.json" >"$vdir/$n.verify.txt" 2>&1 || rc=$?
    if [ "$n" = honest ]; then honest=$(helper judge honest "$vdir/$n.verify.json" "$rc"); else dropped=$(helper judge dropped "$vdir/$n.verify.json" "$rc"); fi
  done
  if [ -n "$validate_e2e" ]; then
    echo "running sudo go test ./tests/e2e (slow), log $vdir/e2e.log"
    if (cd "$root" && sudo env PATH="$PATH" go test -count=1 ./tests/e2e) >"$vdir/e2e.log" 2>&1; then e2e=ok; else e2e="failed, see $vdir/e2e.log"; fi
  fi
  helper validation-write "$out/validation/$ts.json" "$commit" "$honest" "$dropped" "$e2e"
  helper manifest "$out" "$plan" "$commit" "$dirty" "$seed"
  echo "   FAITHFUL known answer: $honest; dropped-entry known answer: $dropped; e2e: $e2e"
  [ "$honest" = ok ] && [ "$dropped" = ok ] && { [ "$e2e" = ok ] || [ "$e2e" = not-run ]; } ||
    die "the instrument validation failed: the block is halted (protocol 10.2); read $vdir"
}
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
