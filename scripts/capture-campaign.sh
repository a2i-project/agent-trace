#!/usr/bin/env bash
# Capture campaign: many paired captures (scripts/capture-claude-code.sh) in
# one sitting, under one sudo, with each set of control runs taken once and
# reused, a manifest of every run, and resumption after an interruption.
#
# It runs the real agents, so it uses the accounts' model quota and needs root
# for the probes: run it yourself. Run it with --dry-run first, which checks
# everything and prints the schedule and its cost without sudo or any model
# call.
#
#   scripts/capture-campaign.sh [--dry-run] [--controls N]
#                               [--allow-unconfigured-version]
#                               [--stop-after-failures N] PLAN OUTPUT_DIR
#
# PLAN is a text file with one entry per line, # starting a comment:
#
#   AGENT TASK REPETITIONS [content]
#
#   claude-code long 3 content
#   claude-code project 3
#   gemini long 2
#
# AGENT is claude-code or gemini, TASK one of the capture script's tasks for
# that agent, REPETITIONS how many task runs to record, and `content` turns on
# the net probe's content capture for that entry's runs and controls
# (capture-claude-code.sh --content; Claude Code only).
#
# Every task run is one call of capture-claude-code.sh into its own directory,
#   OUTPUT_DIR/<agent>-<version>/<task>[-content]/run-NN
# Control runs are taken once per control set, the values --baseline-from
# compares: agent, version, tool set, control prompt and recording mode. The
# first run of a set records CONTROLS control runs (--controls, default 5)
# beside its task run; every later run of the set reuses them with
# --baseline-from, which applies its own refusals as well. So two tasks with
# the same tool set and the same control prompt (basic, edits and shapes for
# Claude Code) share one set of controls.
#
# Before anything else, the script runs capture-claude-code.sh --check for
# every entry (the agent is installed, its version is listed in
# config/agents.json unless --allow-unconfigured-version, the seed exists, the
# locked-directory test of shapes passes, a reused control set is accepted),
# and refuses a malformed plan, an OUTPUT_DIR inside the repository and a
# missing setpriv, sudo or make. --dry-run stops there and prints the schedule:
# the runs already complete, the task and control sessions still to record,
# and an estimate of the model turns they cost.
#
# Otherwise it builds the binaries once, asks for sudo once and keeps the
# credential fresh while it runs, and records the runs in plan order. Before
# each run it repeats the check, so an agent that updated itself stops the
# campaign instead of mixing versions in one control set. After each run it
# writes run.json in the run's directory and rewrites OUTPUT_DIR/manifest.json
# and OUTPUT_DIR/summary.txt. A run is complete when capture-claude-code.sh
# exited 0; anything else is recorded as failed. After --stop-after-failures
# consecutive failed runs (default 2) the campaign stops, since a lapsed login
# fails every run that follows. Ctrl+C stops the agent's current run (watch
# writes what it recorded) and then the campaign.
#
# Rerunning the same command resumes: complete runs are skipped, and the
# directory of a failed or interrupted run is moved aside to
# run-NN.failed-<time> (never deleted) before the run is recorded again. A
# changed version starts new directories, since runs of two versions do not
# share controls.
#
# manifest.json holds, per run: agent, version, task, run index, recording
# mode, control set, directory, the paths of its files, start and end, exit
# status, whether it took its control runs or reused whose, the verdict with
# and without the baseline (outcome, findings, tool calls, claims, the
# alignment counts, completeness), and the scale record of the task run and of
# each control run it took:
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
stop_after=2
while [ $# -gt 0 ]; do
  case $1 in
    --dry-run) dry_run=1; shift ;;
    --controls) controls=${2:?--controls needs a number}; shift 2 ;;
    --allow-unconfigured-version) allow_unconfigured=1; shift ;;
    --stop-after-failures) stop_after=${2:?--stop-after-failures needs a number}; shift 2 ;;
    -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "unknown option $1" >&2; exit 2 ;;
    *) break ;;
  esac
done
[ $# -eq 2 ] || { echo "usage: $0 [--dry-run] [--controls N] [--allow-unconfigured-version] [--stop-after-failures N] PLAN OUTPUT_DIR" >&2; exit 2; }
plan=$1
out=$2
case $controls in ''|*[!0-9]*|0) die "--controls must be a positive number" ;; esac
case $stop_after in ''|*[!0-9]*|0) die "--stop-after-failures must be a positive number" ;; esac
[ -f "$plan" ] || die "no plan file $plan"

root=$(cd "$(dirname "$0")/.." && pwd)
capture=$root/scripts/capture-claude-code.sh
[ -x "$capture" ] || die "missing $capture"
for tool in python3 setpriv sudo make sha256sum realpath; do
  command -v "$tool" >/dev/null || die "$tool is not on PATH"
done
out=$(realpath -m "$out")
case $out/ in "$root"/*) die "OUTPUT_DIR $out is inside the repository; captures are private and never written there" ;; esac

# The helper below does the parsing, the bookkeeping and the summaries.
helper=$(mktemp "${TMPDIR:-/tmp}/capture-campaign.XXXXXX.py")
keepalive=
cleanup() {
  rm -f "$helper"
  [ -z "$keepalive" ] || kill "$keepalive" 2>/dev/null || true
}
trap cleanup EXIT
cat >"$helper" <<'PY'
import collections, datetime, glob, json, os, re, sys

TASKS = {
    "claude-code": {"basic", "parallel", "project", "edits", "tools", "shapes", "long"},
    "gemini": {"basic", "search", "long"},
}
# Model turns a session costs, roughly its tool calls plus the final reply:
# from the prompts' step counts and the fixtures (project made 11 tool calls,
# tools 14). long is the prompt's count of about 120 calls plus fixes; its
# real count is in the manifest after the first run. A control makes one call,
# the tools controls three and a subagent's.
TURNS = {"basic": 6, "parallel": 9, "project": 20, "edits": 8, "tools": 16,
         "shapes": 8, "search": 7, "long": 150}
CONTROL_TURNS = {"tools": 5}


def plan(path):
    """Print the plan's entries as tab-separated agent, task, reps, mode."""
    bad = []
    seen = set()
    for n, line in enumerate(open(path, encoding="utf-8"), 1):
        words = line.split("#", 1)[0].split()
        if not words:
            continue
        if len(words) not in (3, 4):
            bad.append(f"{path}:{n}: want AGENT TASK REPETITIONS [content], got {line.strip()!r}")
            continue
        agent, task, reps = words[:3]
        mode = "identity"
        if len(words) == 4:
            if words[3] != "content":
                bad.append(f"{path}:{n}: unknown option {words[3]!r} (only content)")
                continue
            mode = "content"
        if agent not in TASKS:
            bad.append(f"{path}:{n}: unknown agent {agent!r} (claude-code or gemini)")
            continue
        if task not in TASKS[agent]:
            bad.append(f"{path}:{n}: unknown task {task!r} for {agent} ({', '.join(sorted(TASKS[agent]))})")
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
        print(f"{agent}\t{task}\t{int(reps)}\t{mode}")
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


def run_records(out):
    """The run.json files of the campaign's runs, not of attempts moved aside."""
    return [p for p in sorted(glob.glob(os.path.join(out, "*", "*", "run-*", "run.json")))
            if re.fullmatch(r"run-\d+", os.path.basename(os.path.dirname(p)))]


def controls_source(out, key):
    """Print the directory of a complete run that took the control set key."""
    for path in run_records(out):
        r = load(path)
        if r and r.get("status") == "ok" and r.get("controls", {}).get("taken") and r.get("control_set") == key:
            print(os.path.dirname(path))
            return


def status(run_dir):
    r = load(os.path.join(run_dir, "run.json"))
    print(r.get("status", "unknown") if r else ("absent" if not os.path.exists(run_dir) else "incomplete"))


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


def summarize(run_dir, agent, version, task, idx, mode, key, controls_from, start, end, exit_status):
    """Write run.json for one run and print its status."""
    def f(name):
        p = os.path.join(run_dir, name)
        return p if os.path.exists(p) else None
    traj = f(f"{task}.session.jsonl") or f(f"{task}.conversation.db")
    took = not controls_from
    control_scale = []
    if took:
        for gt in sorted(glob.glob(os.path.join(run_dir, "control-*.ground_truth.json")),
                         key=lambda p: int(re.search(r"control-(\d+)", p).group(1))):
            label = os.path.basename(gt)[:-len(".ground_truth.json")]
            s = scale(gt, os.path.join(run_dir, f"{label}.watch.log"))
            if s:
                s["label"] = label
                control_scale.append(s)
    exit_status = int(exit_status)
    r = {
        "agent": agent, "version": version, "task": task, "run": int(idx), "mode": mode,
        "control_set": key, "dir": run_dir,
        "status": "ok" if exit_status == 0 else ("interrupted" if exit_status == 130 else "failed"),
        "exit_status": exit_status, "start": start, "end": end,
        "duration_s": round((datetime.datetime.fromisoformat(end) - datetime.datetime.fromisoformat(start)).total_seconds()),
        "controls": {"taken": took, "from": run_dir if took else controls_from,
                     "count": len(control_scale) if took else None},
        "paths": {"trajectory": traj, "ground_truth": f(f"{task}.ground_truth.json"),
                  "watch_log": f(f"{task}.watch.log"), "report": f("report.txt"),
                  "verify_json": f("verify.json"), "verify_baseline_json": f("verify-baseline.json"),
                  "baseline": f("baseline.json"), "campaign_log": f("campaign.log")},
        "verdict": {"without_baseline": verdict(os.path.join(run_dir, "verify.json")),
                    "with_baseline": verdict(os.path.join(run_dir, "verify-baseline.json"))},
        "scale": scale(os.path.join(run_dir, f"{task}.ground_truth.json"), os.path.join(run_dir, f"{task}.watch.log")),
        "control_scale": control_scale,
    }
    with open(os.path.join(run_dir, "run.json"), "w", encoding="utf-8") as fh:
        json.dump(r, fh, indent=2)
        fh.write("\n")
    print(r["status"])


def manifest(out, plan_path, commit):
    runs = []
    for path in run_records(out):
        r = load(path)
        if r:
            runs.append(r)
    m = {"schema": 1, "generated": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
         "plan": open(plan_path, encoding="utf-8").read(), "commit": commit, "runs": runs}
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
             "untracked p/n", "peak procs", "content", "seconds")]
    for r in runs:
        s = r.get("scale") or {}
        probes = s.get("probes") or {}
        drops = "/".join(str(g(probes, p, "ringbuf_drops")) for p in ("fs", "proc", "net"))
        untracked = "/".join(str(g(probes, p, "untracked_children")) for p in ("proc", "net"))
        net = s.get("net") or {}
        content = "-" if not net else f"{net.get('withContent')}/{net.get('connections')}-{net.get('unsupported')}"
        rows.append((os.path.relpath(r["dir"], out), r["status"],
                     str(g(r, "verdict", "without_baseline", "outcome")),
                     str(g(r, "verdict", "with_baseline", "outcome")),
                     str(g(r, "verdict", "without_baseline", "tool_calls")),
                     str(g(r, "verdict", "without_baseline", "claims")),
                     drops, untracked, str(g(s, "processes", "peak_alive")), content,
                     str(r.get("duration_s"))))
    widths = [max(len(row[i]) for row in rows) for i in range(len(rows[0]))]
    with open(os.path.join(out, "summary.txt"), "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write("  ".join(c.ljust(w) for c, w in zip(row, widths)).rstrip() + "\n")


def estimate(task, sessions, control_sessions):
    """Print the model turns for task sessions and control sessions."""
    t = TURNS[task] * int(sessions) + CONTROL_TURNS.get(task, 2) * int(control_sessions)
    print(t)


cmd = sys.argv[1]
args = sys.argv[2:]
{"plan": plan, "controls-source": controls_source, "status": status, "summarize": summarize,
 "manifest": manifest, "estimate": estimate}[cmd](*args)
PY
helper() { python3 "$helper" "$@"; }

entries=$(helper plan "$plan") || die "the plan is not valid"

# check AGENT TASK MODE [BASELINE_FROM]: capture-claude-code.sh --check, which
# prints key=value lines; the caller reads them with field.
check() {
  local args=(--agent "$1" --task "$2" --check)
  [ "$3" != content ] || args+=(--content)
  [ -z "$allow_unconfigured" ] || args+=(--allow-unconfigured-version)
  [ -z "${4:-}" ] || args+=(--baseline-from "$4")
  "$capture" "${args[@]}" "$out/.check"
}
field() { sed -n "s/^$1=//p" <<<"$2"; }
control_set() { # check output -> the values --baseline-from compares, as one string
  printf '%s|%s|%s|%s|%s' "$(field agent "$1")" "$(field version "$1")" "$(field control_tools "$1")" \
    "$(field control_prompt_sha256 "$1")" "$(field watch_mode "$1")"
}
run_dir() { # agent version task mode index
  local d="$out/$1-$2/$3"
  [ "$4" != content ] || d+=-content
  printf '%s/run-%02d' "$d" "$5"
}

# Validate every entry and build the schedule. A control set is satisfied by a
# complete run that took it; otherwise its first pending run takes it.
declare -A set_source set_planned
schedule=()
total_task=0 total_control=0 total_turns=0 done_runs=0
echo "plan: $plan"
echo "output: $out"
while IFS=$'\t' read -r agent task reps mode; do
  if ! info=$(check "$agent" "$task" "$mode"); then
    die "$agent $task ($mode): capture-claude-code.sh --check refused, see above"
  fi
  version=$(field version "$info")
  key=$(control_set "$info")
  if [ -z "${set_source[$key]+x}" ]; then
    set_source[$key]=$(helper controls-source "$out" "$key")
    if [ -n "${set_source[$key]}" ]; then
      check "$agent" "$task" "$mode" "${set_source[$key]}" >/dev/null ||
        die "$agent $task ($mode): the control runs in ${set_source[$key]} are refused, see above"
    fi
  fi
  pending=0 controls_here=0
  for i in $(seq 1 "$reps"); do
    d=$(run_dir "$agent" "$version" "$task" "$mode" "$i")
    st=$(helper status "$d")
    if [ "$st" = ok ]; then
      done_runs=$((done_runs + 1))
      continue
    fi
    pending=$((pending + 1))
    if [ -z "${set_source[$key]}" ] && [ -z "${set_planned[$key]+x}" ]; then
      set_planned[$key]=$d
      controls_here=$controls
    fi
    schedule+=("$agent"$'\t'"$task"$'\t'"$mode"$'\t'"$i"$'\t'"$key")
  done
  turns=$(helper estimate "$task" "$pending" "$controls_here")
  printf '  %-12s %-9s %-8s %s run(s), %s pending, %s control session(s), %s %s, about %s model turns\n' \
    "$agent" "$task" "$mode" "$reps" "$pending" "$controls_here" "$agent" "$version" "$turns"
  total_task=$((total_task + pending))
  total_control=$((total_control + controls_here))
  total_turns=$((total_turns + turns))
done <<<"$entries"
echo "complete already: $done_runs run(s)"
echo "to record: $total_task task session(s) and $total_control control session(s), about $total_turns model turns"
for key in "${!set_source[@]}"; do
  if [ -n "${set_source[$key]}" ]; then
    echo "control set ${key%%|*} ($(cut -d'|' -f2 <<<"$key"), $(cut -d'|' -f5 <<<"$key")) reuses ${set_source[$key]}"
  fi
done
if [ -n "$dry_run" ]; then
  echo "dry run: everything checked; nothing was built, no sudo was asked for, no agent was run"
  exit 0
fi
[ "$total_task" -gt 0 ] || { echo "nothing to record"; helper manifest "$out" "$plan" "$(git -C "$root" rev-parse --short HEAD 2>/dev/null || echo unknown)"; exit 0; }

mkdir -p "$out"
(cd "$root" && make build >/dev/null)
sudo -v
# Keep the credential fresh for the hours a long campaign takes. sudo -n never
# prompts; if the credential lapses anyway, the next capture asks again.
# It ends with the campaign, and holds none of its output open.
campaign=$$
( while sleep 60 && kill -0 "$campaign" 2>/dev/null; do sudo -n -v || exit 0; done ) >/dev/null 2>&1 </dev/null &
keepalive=$!

interrupted=
trap 'interrupted=1' INT
commit=$(git -C "$root" rev-parse --short HEAD 2>/dev/null || echo unknown)
failures=0
for entry in "${schedule[@]}"; do
  IFS=$'\t' read -r agent task mode i key <<<"$entry"
  # Repeat the check: the version may have changed since the campaign began.
  info=$(check "$agent" "$task" "$mode") || die "$agent $task ($mode): the check now refuses, see above"
  if [ "$(control_set "$info")" != "$key" ]; then
    die "$agent $task ($mode): the agent changed during the campaign (now $(field version "$info")); rerun the command to resume with the new version"
  fi
  version=$(field version "$info")
  d=$(run_dir "$agent" "$version" "$task" "$mode" "$i")
  if [ -e "$d" ]; then
    moved="$d.failed-$(date +%Y%m%d-%H%M%S)"
    mv "$d" "$moved"
    echo "moved the earlier attempt aside to $moved"
  fi
  src=${set_source[$key]:-}
  args=(--agent "$agent" --task "$task" --no-build)
  [ "$mode" != content ] || args+=(--content)
  [ -z "$allow_unconfigured" ] || args+=(--allow-unconfigured-version)
  [ -z "$src" ] || args+=(--baseline-from "$src")
  mkdir -p "$d"
  echo
  echo "=== $agent $version $task ($mode) run $i -> $d${src:+ (controls from $src)}"
  start=$(date --iso-8601=seconds)
  set +e
  # tee -i: Ctrl+C must not end the pipe the capture still writes to.
  CONTROLS=$controls "$capture" "${args[@]}" "$d" 2>&1 | tee -i "$d/campaign.log"
  status=${PIPESTATUS[0]}
  set -e
  end=$(date --iso-8601=seconds)
  [ -z "$interrupted" ] || [ "$status" -ne 0 ] || status=130
  result=$(helper summarize "$d" "$agent" "$version" "$task" "$i" "$mode" "$key" "$src" "$start" "$end" "$status")
  helper manifest "$out" "$plan" "$commit"
  echo "=== $result (exit $status)"
  if [ "$result" = ok ]; then
    failures=0
    [ -n "$src" ] || set_source[$key]=$d
  else
    failures=$((failures + 1))
  fi
  if [ -n "$interrupted" ]; then
    echo "interrupted: rerun the same command to resume"
    exit 130
  fi
  if [ "$failures" -ge "$stop_after" ]; then
    die "$failures run(s) failed in a row; read their campaign.log, then rerun the same command to resume"
  fi
done
echo
cat "$out/summary.txt"
echo "done. Manifest: $out/manifest.json"
