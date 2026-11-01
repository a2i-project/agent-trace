#!/usr/bin/env bash
# Overhead benchmark: the time and storage the instrumentation (watch) and the
# verification (verify, baseline) cost, on deterministic workloads that make no
# model call, so it uses no quota. Run it yourself as an ordinary user: it asks
# for sudo once, for watch.
#
#   scripts/bench-overhead.sh [--reps N] [--sizes LIST] [--workloads LIST]
#                             [--conditions LIST] [--net-exe-path LIB]
#                             [--unprivileged-only] [--no-fixtures]
#                             [--keep-captures] [--dry-run] [OUTPUT_DIR]
#
# Workloads (each run in a fresh workspace):
#   shell     a scripted bash loop of SIZE iterations; each writes a file with
#             a builtin, writes one with head, renames it with mv, reads both
#             with cat, opens a TCP connection to a listener on 127.0.0.1 and
#             deletes both with rm. One workload per size in --sizes.
#   simagent  cmd/simagent's fixed script (file write, rename, wc, delete).
#   project   replay-like: the command pattern of the capture script's project
#             task without the model, in a copy of scripts/seed/project (run
#             the tests twice, grep, edit the README with sed, run the CLI,
#             write a file, list the tree).
#
# Conditions: alone (the workload as you, no watch), all (watch with
# fs,proc,net), and fs, proc, net (watch with that probe alone). Under watch
# the workload runs as you through setpriv, as in the capture script, and
# watch's output goes to a log file. Every repetition runs every workload under
# every condition, in an order rotated per repetition; repetition 0 is a
# warm-up and is left out of the statistics.
#
# Per run it records: the workload's own wall time and CPU (from inside the
# workload: bash's EPOCHREALTIME and times), the run's wall time from launch to
# exit, start-up (launch to the workload's first instruction) and stop/drain
# (the workload's last instruction to watch's exit), the CPU of watch's tree
# minus the workload's, the peak RSS of the measured process tree from GNU
# time, which must be at /usr/bin/time (for watch:
# the largest of watch and its descendants, so watch's own peak when it exceeds
# the workload's peak measured alone), the capture's size, event count and
# bytes per event, whether verify judges it complete, and the descendant
# events it retains as the capability record (the events beneath the commands
# in verify's JSON report) with their size.
#
# The fixture part (unprivileged; skipped with --no-fixtures) times baseline
# on each paired fixture the agent profiles list (config/agents.json, each
# version's fixtures) and verify on its session, with and without that
# baseline, and records the same storage figures. The profile names the
# session file (its trace) and whether verify needs --agent-version (a trace
# that does not state the version); the script names no agent. Fixtures are
# reduced by scripts/make-capture-fixture.py, so their sizes are not those of
# a raw capture.
#
# --unprivileged-only runs the fixture part and the alone condition only, with
# no sudo. --keep-captures keeps every run's directory (capture, log,
# workspace); by default each is removed once measured. --net-exe-path is passed
# to watch for the net probe's TLS uprobe; without it the net probe records
# identity only. --dry-run validates the arguments and prints the fixtures
# with their commands, the fixtures left out and why, and the workloads and
# conditions; it builds nothing, writes nothing to OUTPUT_DIR, asks for no
# sudo and may run as root.
#
# Output, in OUTPUT_DIR (default /tmp/agent-trace-overhead-<time>), which must
# be outside the repository and empty or absent:
#   results.json   machine, kernel, CPU governor, load average, commit,
#                  parameters, every sample, summary
#   results.csv    one row per (scope, name, condition, metric): n, median,
#                  q1, q3, min, max
#   summary.txt    a short text summary, also printed
#   samples.jsonl  one line per measured run
set -euo pipefail

reps=10
sizes=10,100,1000
workloads=shell,simagent,project
conditions=alone,all,fs,proc,net
net_exe=
unpriv=
fixtures=1
keep=
dry=
while [ $# -gt 0 ]; do
  case $1 in
    --reps) reps=${2:?--reps needs a number}; shift 2 ;;
    --sizes) sizes=${2:?--sizes needs a list}; shift 2 ;;
    --workloads) workloads=${2:?--workloads needs a list}; shift 2 ;;
    --conditions) conditions=${2:?--conditions needs a list}; shift 2 ;;
    --net-exe-path) net_exe=${2:?--net-exe-path needs a file}; shift 2 ;;
    --unprivileged-only) unpriv=1; shift ;;
    --no-fixtures) fixtures=; shift ;;
    --keep-captures) keep=1; shift ;;
    --dry-run) dry=1; shift ;;
    -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "unknown option $1" >&2; exit 2 ;;
    *) break ;;
  esac
done
[ $# -le 1 ] || { echo "at most one OUTPUT_DIR" >&2; exit 2; }

# Everything is validated here, before any build or sudo.
die() { echo "$*" >&2; exit 2; }
[[ $reps =~ ^[1-9][0-9]{0,2}$ ]] || die "--reps must be an integer from 1 to 999"
[[ $sizes =~ ^[1-9][0-9]{0,5}(,[1-9][0-9]{0,5})*$ ]] || die "--sizes must be a comma-separated list of positive integers"
IFS=, read -r -a size_list <<<"$sizes"
IFS=, read -r -a wl_list <<<"$workloads"
IFS=, read -r -a cond_list <<<"$conditions"
for w in "${wl_list[@]}"; do
  case $w in shell|simagent|project) ;; *) die "unknown workload '$w' (shell, simagent, project)" ;; esac
done
has_alone=
watch_conds=()
for c in "${cond_list[@]}"; do
  case $c in
    alone) has_alone=1 ;;
    all|fs|proc|net) watch_conds+=("$c") ;;
    *) die "unknown condition '$c' (alone, all, fs, proc, net)" ;;
  esac
done
# Every overhead is relative to the same workload alone in the same run.
[ -n "$has_alone" ] || { echo "note: adding the alone condition, which every overhead is relative to" >&2; }
if [ -n "$unpriv" ]; then
  watch_conds=()
  [ -z "$net_exe" ] || die "--net-exe-path needs watch, which --unprivileged-only does not run"
fi
run_conds=(alone "${watch_conds[@]}")
if [ -n "$net_exe" ]; then
  [ -f "$net_exe" ] || die "--net-exe-path $net_exe is not a file"
  net_exe=$(realpath "$net_exe")
fi
[ -n "$dry" ] || [ "$(id -u)" -ne 0 ] || die "run as an ordinary user: the workloads run as you, and the script asks for sudo itself"
((BASH_VERSINFO[0] >= 5)) || die "bash 5 or later is needed (EPOCHREALTIME)"
needed=(go python3 git realpath)
[ ${#watch_conds[@]} -eq 0 ] || needed+=(sudo setpriv)
for t in "${needed[@]}"; do
  command -v "$t" >/dev/null || die "$t is not on PATH"
done
python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))' || die "python 3.9 or later is needed"
/usr/bin/time --version 2>&1 | grep -q 'GNU' || die "GNU time is needed at /usr/bin/time (the peak RSS)"

root=$(cd "$(dirname "$0")/.." && pwd -P)
out=${1:-/tmp/agent-trace-overhead-$(date +%Y%m%d-%H%M%S)}
out=$(realpath -m "$out")
case $out/ in "$root"/*) die "OUTPUT_DIR $out is inside the repository; results are never written there" ;; esac
[ ! -e "$out" ] || [ -z "$(ls -A "$out")" ] || die "OUTPUT_DIR $out is not empty"
seed=$root/scripts/seed/project
bash_bin=$(command -v bash)
uid=$(id -u)
gid=$(id -g)

echo "output: $out"
if [ -n "$dry" ]; then
  # The helpers go to a scratch directory; OUTPUT_DIR stays untouched.
  tools=$(mktemp -d)
  trap 'rm -rf "$tools"' EXIT
else
  tools=$out/tools
  mkdir -p "$out/bin" "$tools" "$out/runs"
  for c in watch verify baseline simagent; do
    (cd "$root" && go build -o "$out/bin/$c" "./cmd/$c")
  done
fi

# The workload, run as bash wl.sh MARK KIND SIZE WS PORT SIMAGENT TRAJ. It
# writes its start and end times, exit status and CPU (times) to MARK.
cat >"$tools/wl.sh" <<'WL'
mark=$1 kind=$2 size=$3 ws=$4 port=$5 simagent=$6 traj=$7
start=$EPOCHREALTIME
rc=0
cd "$ws" || exit 97
case $kind in
  shell)
    for ((i = 0; i < size; i++)); do
      printf 'line %d\n' "$i" >"f$i.txt" || rc=1
      head -c 4096 /dev/zero >"d$i.bin" || rc=1
      mv "f$i.txt" "g$i.txt" || rc=1
      cat "g$i.txt" "d$i.bin" >/dev/null || rc=1
      # true is a regular builtin: the redirection connects and closes
      # without a fork, and a failure does not end the shell.
      true 3<>"/dev/tcp/127.0.0.1/$port" || rc=1
      rm -f "g$i.txt" "d$i.bin" || rc=1
    done
    ;;
  simagent)
    "$simagent" --workspace "$ws" --trajectory-out "$traj" >/dev/null || rc=1
    ;;
  project)
    # The tests fail by design (the seeded bug), so their status is ignored.
    python3 -m unittest discover -q >/dev/null 2>&1
    grep -rn "def " wordstats >/dev/null || rc=1
    sed -i 's/^# wordstats$/# wordstats (bench)/' README.md || rc=1
    python3 -m wordstats.cli README.md >/dev/null || rc=1
    printf 'notes\n' >notes.txt || rc=1
    python3 -m unittest discover -q >/dev/null 2>&1
    ls -R >/dev/null || rc=1
    ;;
esac
end=$EPOCHREALTIME
printf '%s %s %s\n' "$start" "$end" "$rc" >"$mark"
times >>"$mark"
exit "$rc"
WL

cat >"$tools/bench.py" <<'PY'
"""Helpers of scripts/bench-overhead.sh: measure, collect, fixtures, listen,
machine, report. Not meant to be run by hand."""
import glob, json, os, platform, re, shlex, socket, statistics, subprocess, sys, time


def measure(cmd, log):
    """Run cmd and return its wall time, the CPU of its waited tree and the
    peak RSS of the largest process in it.

    A process's peak RSS starts at that of the process it was forked from, so
    the peak comes from GNU time, whose own is small, and not from the rusage
    this process gets, which would never read below Python's own. The CPU does
    come from that rusage, at microsecond resolution; it includes GNU time's."""
    rss = log + ".rss"
    with open(log, "ab") as lf:
        t0 = time.time_ns()
        p = subprocess.Popen(["/usr/bin/time", "-f", "%M", "-o", rss, "--"] + cmd,
                             stdin=subprocess.DEVNULL, stdout=lf, stderr=lf)
        _, status, ru = os.wait4(p.pid, 0)
        t1 = time.time_ns()
    try:
        with open(rss) as f:
            maxrss = int(f.read().split()[-1])
        os.remove(rss)
    except (OSError, ValueError, IndexError):
        maxrss = None
    return {"start_ns": t0, "end_ns": t1, "wall_s": (t1 - t0) / 1e9,
            "cpu_s": ru.ru_utime + ru.ru_stime, "maxrss_kb": maxrss,
            "exit": os.waitstatus_to_exitcode(status)}


def ns(text):
    sec, _, frac = text.replace(",", ".").partition(".")
    return int(sec) * 10**9 + int((frac + "000000000")[:9])


def times_cpu(lines):
    total = 0.0
    for m in re.finditer(r"(\d+)m([\d.,]+)s", "\n".join(lines)):
        total += int(m.group(1)) * 60 + float(m.group(2).replace(",", "."))
    return total


def storage(gt_path, report_path):
    """Size of a capture and of the capability record verify's report holds."""
    s = {"gt_bytes": os.path.getsize(gt_path)}
    with open(gt_path) as f:
        g = json.load(f)
    events = g["events"] if isinstance(g, dict) else g
    s["gt_events"] = len(events or [])
    s["bytes_per_event"] = s["gt_bytes"] / s["gt_events"] if s["gt_events"] else None
    if report_path and os.path.exists(report_path):
        with open(report_path) as f:
            r = json.load(f)
        retained = [e for c in (r.get("commands") or []) for e in (c.get("events") or [])]
        s["capability_events"] = len(retained)
        s["capability_bytes"] = len(json.dumps(retained, separators=(",", ":")).encode())
        s["report_bytes"] = os.path.getsize(report_path)
        s["complete"] = bool((r.get("completeness") or {}).get("Complete"))
    return s


def cmd_measure(args):
    out, log, cmd = args[0], args[1], args[3:]
    assert args[2] == "--"
    with open(out, "w") as f:
        json.dump(measure(cmd, log), f)


def cmd_collect(args):
    samples, d, workload, size, cond, rep, verify = args
    rec = {"scope": "workload", "workload": workload, "size": int(size) or None,
           "condition": cond, "rep": int(rep)}
    with open(os.path.join(d, "measure.json")) as f:
        m = json.load(f)
    rec.update(run_wall_s=m["wall_s"], tree_cpu_s=m["cpu_s"], tree_maxrss_kb=m["maxrss_kb"],
               exit=m["exit"])
    mark = os.path.join(d, "mark")
    ok = m["exit"] == 0 and os.path.exists(mark)
    if os.path.exists(mark):
        with open(mark) as f:
            lines = f.read().splitlines()
        start, end, rc = lines[0].split()
        s, e = ns(start), ns(end)
        cpu = times_cpu(lines[1:])
        rec.update(workload_rc=int(rc), workload_wall_s=(e - s) / 1e9, workload_cpu_s=cpu,
                   startup_s=(s - m["start_ns"]) / 1e9, drain_s=(m["end_ns"] - e) / 1e9)
        if cond != "alone":
            rec["watch_cpu_s"] = m["cpu_s"] - cpu
        ok = ok and int(rc) == 0
    gt = os.path.join(d, "gt.json")
    if cond != "alone":
        if os.path.exists(gt):
            traj = os.path.join(d, "traj.json")
            if not os.path.exists(traj):
                traj = os.path.join(d, "empty.json")
                with open(traj, "w") as f:
                    f.write("[]\n")
            report = os.path.join(d, "verify.json")
            v = measure([verify, "--agent", "generic", "--trajectory", traj, "--ground-truth", gt,
                         "--json", report], os.path.join(d, "verify.log"))
            rec.update(verify_wall_s=v["wall_s"], verify_cpu_s=v["cpu_s"],
                       verify_maxrss_kb=v["maxrss_kb"], verify_exit=v["exit"])
            rec.update(storage(gt, report if v["exit"] in (0, 1, 2) else None))
        else:
            ok = False
    rec["ok"] = ok
    with open(samples, "a") as f:
        f.write(json.dumps(rec) + "\n")
    print("   %-8s %-7s %-6s rep %-3s %s" % (workload, size if int(size) else "", cond, rep,
          "ok" if ok else "FAILED (see %s)" % d))


def fixtures_of(root, skipped=None):
    """The paired fixtures the profiles list (config/agents.json, each
    version's fixtures), per agent in file order and by directory name within
    it: control captures, exactly one other ground truth, and the transcript
    the profile's trace names for its label. A listed fixture of another shape
    is left out, with the reason appended to skipped."""
    path = os.path.join(root, "config", "agents.json")
    with open(path) as f:
        cfg = json.load(f)
    if cfg.get("schema") != 2:
        sys.exit("%s: schema %s, the benchmark reads 2" % (path, cfg.get("schema")))
    found = []
    for agent, prof in (cfg.get("adapters") or {}).items():
        trace = prof.get("trace") or {}
        listed = [(v["version"], d) for v in prof.get("versions") or [] for d in v.get("fixtures") or []]
        for version, rel in sorted(listed, key=lambda x: os.path.basename(x[1])):
            d = os.path.join(root, rel)
            controls = sorted(glob.glob(os.path.join(d, "control-*.ground_truth.json")))
            gts = [g for g in glob.glob(os.path.join(d, "*.ground_truth.json")) if g not in controls]
            why = None
            if not trace.get("file"):
                why = "the profile names no trace file"
            elif not controls or len(gts) != 1:
                why = "not paired (%d control capture(s), %d other ground truth(s))" % (len(controls), len(gts))
            else:
                label = os.path.basename(gts[0])[: -len(".ground_truth.json")]
                session = os.path.join(d, trace["file"].replace("{label}", label))
                if not os.path.exists(session):
                    why = "no %s" % os.path.basename(session)
            if why:
                if skipped is not None:
                    skipped.append((os.path.basename(d), agent, why))
                continue
            # A transcript that states its version needs no --agent-version.
            found.append({"name": os.path.basename(d), "agent": agent, "version": version,
                          "controls": controls, "gt": gts[0], "session": session,
                          "pass_version": not trace.get("states_version")})
    return found


def fixture_runs(f, bindir, work):
    """The baseline and verify commands of one fixture, by step."""
    base = os.path.join(work, f["name"] + ".baseline.json")
    agree = "%.6f" % (1 / len(f["controls"]))
    runs = {
        "baseline": [os.path.join(bindir, "baseline"), "--agent", f["agent"], "--agent-version",
                     f["version"], "--exclude", ": agent-trace-control-marker", "--min-agreement",
                     agree, "--out", base] + f["controls"],
    }
    vcmd = [os.path.join(bindir, "verify"), "--agent", f["agent"], "--trajectory", f["session"],
            "--ground-truth", f["gt"]]
    if f["pass_version"]:
        vcmd += ["--agent-version", f["version"]]
    runs["verify"] = vcmd + ["--json", os.path.join(work, f["name"] + ".verify.json")]
    runs["verify+baseline"] = vcmd + ["--baseline", base, "--json",
                                      os.path.join(work, f["name"] + ".verify-baseline.json")]
    return runs


def cmd_plan(args):
    """The fixture part of a dry run: every fixture's commands, run by none."""
    root, bindir, work, reps = args[0], args[1], args[2], int(args[3])
    skipped = []
    fx = fixtures_of(root, skipped)
    print("fixtures: %d paired fixture(s), %d repetition(s) plus a warm-up" % (len(fx), reps))
    for f in fx:
        print("  %s (%s %s, %d control(s))" % (f["name"], f["agent"], f["version"], len(f["controls"])))
        for step, cmd in fixture_runs(f, bindir, work).items():
            print("    %-16s %s" % (step, " ".join(shlex.quote(os.path.relpath(c, root) if c.startswith(root + os.sep) else c)
                                               for c in cmd)))
    for name, agent, why in skipped:
        print("  left out: %s (%s): %s" % (name, agent, why))


def cmd_fixtures(args):
    samples, root, bindir, work, reps = args[0], args[1], args[2], args[3], int(args[4])
    fx = fixtures_of(root)
    print("fixtures: %d paired fixture(s), %d repetition(s) plus a warm-up" % (len(fx), reps))
    os.makedirs(work, exist_ok=True)
    stored = {}
    for rep in range(reps + 1):
        for f in fx:
            runs = fixture_runs(f, bindir, work)
            for step in ("baseline", "verify", "verify+baseline"):
                m = measure(runs[step], os.path.join(work, f["name"] + ".log"))
                ok = m["exit"] == 0 if step == "baseline" else m["exit"] in (0, 1, 2)
                rec = {"scope": "fixture", "workload": f["name"], "size": None, "condition": step,
                       "rep": rep, "ok": ok, "exit": m["exit"], "run_wall_s": m["wall_s"],
                       "tree_cpu_s": m["cpu_s"], "tree_maxrss_kb": m["maxrss_kb"]}
                with open(samples, "a") as out:
                    out.write(json.dumps(rec) + "\n")
                if not ok:
                    print("   %s %s rep %d FAILED (exit %d, see %s.log)" % (f["name"], step, rep, m["exit"],
                                                                         os.path.join(work, f["name"])))
        print("   repetition %d done" % rep)
    for f in fx:
        s = storage(f["gt"], os.path.join(work, f["name"] + ".verify-baseline.json"))
        s["controls"] = len(f["controls"])
        s["control_gt_bytes"] = sum(os.path.getsize(c) for c in f["controls"])
        base = os.path.join(work, f["name"] + ".baseline.json")
        s["baseline_bytes"] = os.path.getsize(base) if os.path.exists(base) else None
        s.update(agent=f["agent"], version=f["version"])
        stored[f["name"]] = s
    with open(os.path.join(work, "storage.json"), "w") as out:
        json.dump(stored, out, indent=1)


def cmd_listen(args):
    """Accept and close TCP connections on 127.0.0.1 until killed."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(512)
    with open(args[0], "w") as f:
        f.write("%d\n" % s.getsockname()[1])
    while True:
        c, _ = s.accept()
        c.close()


def read(path, default=None):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return default


def cmd_machine(args):
    out, root, outdir = args
    cpu = None
    for line in (read("/proc/cpuinfo", "") or "").splitlines():
        if line.startswith("model name"):
            cpu = line.split(":", 1)[1].strip()
            break
    mem = None
    for line in (read("/proc/meminfo", "") or "").splitlines():
        if line.startswith("MemTotal:"):
            mem = int(line.split()[1])
    osrel = None
    for line in (read("/etc/os-release", "") or "").splitlines():
        if line.startswith("PRETTY_NAME="):
            osrel = line.split("=", 1)[1].strip('"')

    def run(*cmd):
        try:
            return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.strip()
        except (OSError, subprocess.CalledProcessError):
            return None

    m = {"kernel": platform.release(), "kernel_version": platform.version(), "arch": platform.machine(),
         "os": osrel, "cpu_model": cpu, "cpus": os.cpu_count(), "mem_total_kb": mem,
         "cpu_governor": read("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"),
         "output_fs": run("stat", "-f", "-c", "%T", outdir),
         "go": run("go", "version"), "python": platform.python_version(),
         "bash": run("bash", "-c", "echo $BASH_VERSION"),
         "commit": run("git", "-C", root, "rev-parse", "HEAD"),
         "dirty": bool(run("git", "-C", root, "status", "--porcelain")),
         "loadavg_start": read("/proc/loadavg"), "date": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    with open(out, "w") as f:
        json.dump(m, f, indent=1)


METRICS = ["workload_wall_s", "workload_cpu_s", "run_wall_s", "startup_s", "drain_s", "watch_cpu_s",
           "tree_cpu_s", "tree_maxrss_kb", "gt_bytes", "gt_events", "bytes_per_event",
           "capability_events", "capability_bytes", "verify_wall_s", "verify_maxrss_kb",
           "wall_ratio", "cpu_ratio"]


def stats(values):
    v = sorted(values)
    if not v:
        return None
    if len(v) >= 2:
        q1, _, q3 = statistics.quantiles(v, n=4, method="inclusive")
    else:
        q1 = q3 = None
    return {"n": len(v), "median": statistics.median(v), "q1": q1, "q3": q3, "min": v[0], "max": v[-1]}


def fmt(s, scale=1.0, unit=""):
    if not s:
        return "-"
    if s["q1"] is None:
        return "%.3g%s" % (s["median"] * scale, unit)
    return "%.3g%s [%.3g, %.3g]" % (s["median"] * scale, unit, s["q1"] * scale, s["q3"] * scale)


def cmd_report(args):
    outdir, params_json = args
    params = json.loads(params_json)
    samples = []
    if os.path.exists(os.path.join(outdir, "samples.jsonl")):
        with open(os.path.join(outdir, "samples.jsonl")) as f:
            samples = [json.loads(l) for l in f if l.strip()]
    with open(os.path.join(outdir, "machine.json")) as f:
        machine = json.load(f)
    machine["loadavg_end"] = read("/proc/loadavg")
    storage_fx = {}
    if os.path.exists(os.path.join(outdir, "fixtures", "storage.json")):
        with open(os.path.join(outdir, "fixtures", "storage.json")) as f:
            storage_fx = json.load(f)
    measured = [s for s in samples if s["rep"] > 0]
    # The ratio of a run under watch to the same workload alone in the same
    # repetition: the repetitions interleave the conditions, so they pair.
    alone = {(s["workload"], s["size"], s["rep"]): s for s in measured
             if s["scope"] == "workload" and s["condition"] == "alone" and s["ok"]}
    for s in measured:
        a = alone.get((s["workload"], s["size"], s["rep"]))
        if s["scope"] == "workload" and s["condition"] != "alone" and s["ok"] and a:
            if a.get("workload_wall_s"):
                s["wall_ratio"] = s["workload_wall_s"] / a["workload_wall_s"]
            if a.get("workload_cpu_s"):
                s["cpu_ratio"] = s["workload_cpu_s"] / a["workload_cpu_s"]
    groups = {}
    for s in measured:
        groups.setdefault((s["scope"], s["workload"], s["size"], s["condition"]), []).append(s)
    summary = []
    order = ["alone", "all", "fs", "proc", "net", "baseline", "verify", "verify+baseline"]
    for (scope, name, size, cond), runs in sorted(groups.items(), key=lambda kv: (
            kv[0][0] != "workload", kv[0][1], kv[0][2] or 0, order.index(kv[0][3]))):
        ok = [r for r in runs if r["ok"]]
        row = {"scope": scope, "name": name if size is None else "%s-%d" % (name, size), "condition": cond,
               "runs": len(runs), "ok": len(ok), "with_loss": sum(1 for r in ok if r.get("complete") is False),
               "metrics": {}}
        for m in METRICS:
            st = stats([r[m] for r in ok if r.get(m) is not None])
            if st:
                row["metrics"][m] = st
        summary.append(row)
    with open(os.path.join(outdir, "results.json"), "w") as f:
        json.dump({"schema": 1, "machine": machine, "params": params, "summary": summary,
                   "fixture_storage": storage_fx, "samples": samples}, f, indent=1)
    with open(os.path.join(outdir, "results.csv"), "w") as f:
        f.write("scope,name,condition,metric,n,median,q1,q3,min,max\n")
        for row in summary:
            for m, st in row["metrics"].items():
                f.write("%s,%s,%s,%s,%d,%r,%s,%s,%r,%r\n" % (
                    row["scope"], row["name"], row["condition"], m, st["n"], st["median"],
                    "" if st["q1"] is None else repr(st["q1"]), "" if st["q3"] is None else repr(st["q3"]),
                    st["min"], st["max"]))
    lines = ["agent-trace overhead benchmark (median [q1, q3] over the measured repetitions)",
             "commit %s%s, kernel %s, %s, %s CPUs, governor %s" % (
                 (machine.get("commit") or "?")[:12], " (dirty)" if machine.get("dirty") else "",
                 machine.get("kernel"), machine.get("cpu_model"), machine.get("cpus"), machine.get("cpu_governor")),
             "repetitions %d (plus one warm-up), output filesystem %s" % (params["reps"], machine.get("output_fs")),
             "load average at start %s, at end %s" % (machine.get("loadavg_start"), machine.get("loadavg_end")),
             ""]
    wl = [r for r in summary if r["scope"] == "workload"]
    if wl:
        lines.append("Workloads: workload wall s, wall ratio to alone, start-up s, drain s, watch CPU s, "
                     "peak RSS MiB, capture KiB, bytes/event, capability events")
        for r in wl:
            m = r["metrics"]
            lines.append("  %-16s %-6s ok %d/%d%s" % (r["name"], r["condition"], r["ok"], r["runs"],
                                                     ", %d with loss" % r["with_loss"] if r["with_loss"] else ""))
            lines.append("      wall %s  ratio %s  start %s  drain %s  watchcpu %s  rss %s" % (
                fmt(m.get("workload_wall_s")), fmt(m.get("wall_ratio")), fmt(m.get("startup_s")),
                fmt(m.get("drain_s")), fmt(m.get("watch_cpu_s")), fmt(m.get("tree_maxrss_kb"), 1 / 1024)))
            if r["condition"] != "alone":
                lines.append("      capture %s  bytes/event %s  capability events %s" % (
                    fmt(m.get("gt_bytes"), 1 / 1024), fmt(m.get("bytes_per_event")), fmt(m.get("capability_events"))))
        lines.append("")
    fx = [r for r in summary if r["scope"] == "fixture"]
    if fx:
        lines.append("Fixtures: wall s, CPU s, peak RSS MiB")
        for r in fx:
            m = r["metrics"]
            lines.append("  %-30s %-16s ok %d/%d  wall %s  cpu %s  rss %s" % (
                r["name"], r["condition"], r["ok"], r["runs"], fmt(m.get("run_wall_s")),
                fmt(m.get("tree_cpu_s")), fmt(m.get("tree_maxrss_kb"), 1 / 1024)))
        lines.append("Fixture storage (reduced fixtures): capture KiB, events, capability events")
        for name, s in sorted(storage_fx.items()):
            lines.append("  %-30s %.1f KiB  %d events  %s capability events" % (
                name, s["gt_bytes"] / 1024, s["gt_events"], s.get("capability_events", "-")))
    text = "\n".join(lines) + "\n"
    with open(os.path.join(outdir, "summary.txt"), "w") as f:
        f.write(text)
    sys.stdout.write(text)


if __name__ == "__main__":
    {"measure": cmd_measure, "collect": cmd_collect, "fixtures": cmd_fixtures, "plan": cmd_plan,
     "listen": cmd_listen, "machine": cmd_machine, "report": cmd_report}[sys.argv[1]](sys.argv[2:])
PY
bench=(python3 "$tools/bench.py")

jobs=()
for w in "${wl_list[@]}"; do
  if [ "$w" = shell ]; then
    for s in "${size_list[@]}"; do jobs+=("shell $s"); done
  else
    jobs+=("$w 0")
  fi
done

if [ -n "$dry" ]; then
  [ -z "$fixtures" ] || "${bench[@]}" plan "$root" "$out/bin" "$out/fixtures" "$reps"
  echo "workloads: ${#jobs[@]}, conditions: ${run_conds[*]}, repetitions: $reps plus a warm-up"
  for job in "${jobs[@]}"; do
    read -r w s <<<"$job"
    if [ "$s" = 0 ]; then echo "  $w"; else echo "  $w-$s"; fi
  done
  [ ${#watch_conds[@]} -eq 0 ] || echo "sudo: asked once, for watch (${watch_conds[*]})"
  echo "dry run: nothing built, measured or written"
  exit 0
fi

"${bench[@]}" machine "$out/machine.json" "$root" "$out"

if [ -n "$fixtures" ]; then
  "${bench[@]}" fixtures "$out/samples.jsonl" "$root" "$out/bin" "$out/fixtures" "$reps"
fi

listener=
cleanup() { [ -z "$listener" ] || kill "$listener" 2>/dev/null || true; }
trap cleanup EXIT
"${bench[@]}" listen "$tools/port" &
listener=$!
for _ in $(seq 50); do [ -s "$tools/port" ] && break; sleep 0.1; done
port=$(cat "$tools/port")

# One run of a workload under a condition. The workload runs with the
# environment setpriv --reset-env gives it under watch, alone too.
run_one() { # rep workload size condition
  local rep=$1 w=$2 size=$3 cond=$4
  local d=$out/runs/$w-$size-$cond-r$rep
  mkdir -p "$d/ws"
  [ "$w" != project ] || cp -r "$seed/." "$d/ws/"
  local wl=("$bash_bin" "$tools/wl.sh" "$d/mark" "$w" "$size" "$d/ws" "$port" "$out/bin/simagent" "$d/traj.json")
  if [ "$cond" = alone ]; then
    "${bench[@]}" measure "$d/measure.json" "$d/log" -- \
      env -i PATH=/usr/local/bin:/bin:/usr/bin HOME="$HOME" SHELL="$bash_bin" USER="$(id -un)" LOGNAME="$(id -un)" "${wl[@]}"
  else
    local probes=$cond
    [ "$cond" != all ] || probes=fs,proc,net
    local watch=("$out/bin/watch" --probes "$probes" --workspace "$d/ws" --out "$d/gt.json")
    [ -z "$net_exe" ] || watch+=(--net-exe-path "$net_exe")
    sudo python3 "$tools/bench.py" measure "$d/measure.json" "$d/log" -- \
      "${watch[@]}" -- setpriv --reuid "$uid" --regid "$gid" --init-groups --reset-env "${wl[@]}"
    sudo chown -R "$uid:$gid" "$d"
  fi
  "${bench[@]}" collect "$out/samples.jsonl" "$d" "$w" "$size" "$cond" "$rep" "$out/bin/verify"
  [ -n "$keep" ] || rm -rf "$d"
}

echo "workloads: ${#jobs[@]}, conditions: ${run_conds[*]}, repetitions: $reps plus a warm-up"
[ ${#watch_conds[@]} -eq 0 ] || sudo -v
for ((rep = 0; rep <= reps; rep++)); do
  [ ${#watch_conds[@]} -eq 0 ] || sudo -v
  n=${#run_conds[@]}
  for job in "${jobs[@]}"; do
    read -r w s <<<"$job"
    for ((k = 0; k < n; k++)); do
      run_one "$rep" "$w" "$s" "${run_conds[$(((k + rep) % n))]}"
    done
  done
done

params=$(printf '{"reps": %d, "sizes": "%s", "workloads": "%s", "conditions": "%s", "net_exe_path": %s, "fixtures": %s}' \
  "$reps" "$sizes" "$workloads" "${run_conds[*]}" "$([ -n "$net_exe" ] && echo true || echo false)" "$([ -n "$fixtures" ] && echo true || echo false)")
"${bench[@]}" report "$out" "$params"
echo "results: $out/results.json, $out/results.csv, $out/summary.txt"
