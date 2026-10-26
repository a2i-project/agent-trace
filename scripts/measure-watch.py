#!/usr/bin/env python3
"""Run a command that starts `watch` (sudo watch ... -- AGENT) and measure the
cost of the recording around one real session, for H4b (cmd/analyze reads
`cost` in run.json): start-up, drain, watch's CPU and its peak resident set.

    measure-watch.py --gt GROUND_TRUTH.json --out COST.json [--interval-ms 5] -- COMMAND...

COMMAND is the whole recorded command, with `--out GROUND_TRUTH.json` among
the arguments of watch. The script finds the watch process by that argument,
and samples it every INTERVAL milliseconds from /proc while COMMAND runs.
It changes nothing about COMMAND: same arguments, same standard streams,
same exit status. It never reads the agent's data, and no Go code changes.

What it writes (COST.json), in the units cmd/analyze reads:

  startup_s        COMMAND started to the held agent process leaving
                   watch's hold script (the agent's first instruction);
                   includes sudo, the probes' start and watch's 200 ms wait
  drain_s          the agent process ended to COMMAND ended: watch's trailing
                   300 ms, the probes' stop and the write of the capture
  agent_s          release to the end of the agent process (not in the
                   manifest's cost object)
  watch_cpu_s      watch's own user plus system CPU, from /proc/PID/stat
                   (utime and stime, in clock ticks, so 10 ms steps): the
                   agent's CPU is in cutime and cstime and is not counted
  watch_maxrss_kb  watch's own peak resident set (VmHWM of /proc/PID/status),
                   the largest value seen: a lower bound, short by what grew
                   after the last sample
  tree_cpu_s, tree_maxrss_kb
                   rusage of COMMAND's waited tree (sudo, watch and the agent
                   with its descendants): the CPU is exact but includes the
                   agent; the peak is the largest process of the tree, an
                   upper bound of watch's own

A field that could not be measured is null (the process was never found, no
held agent was seen, /proc was unreadable): not measured, never zero. The
CPU the kernel spends in the probes' BPF programs runs in the context of the
traced tasks, so it is charged to the agent's tree, not to watch, and is not
separated here. Times have the sampling interval's resolution.
"""
import signal

# Ctrl+C reaches the whole foreground group, watch included; watch stops the
# agent and writes the capture, and this process must outlive it. A handler
# (not SIG_IGN) is reset by exec, so the command still sees SIGINT. Installed
# before anything else loads, to leave the shortest window.
signal.signal(signal.SIGINT, lambda *_: None)

import argparse  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import resource  # noqa: E402
import subprocess  # noqa: E402
import sys  # noqa: E402
import time  # noqa: E402

HOLD = b"agent-trace-hold"  # argv[3] of the hold script cmd/watch starts (startHeld)
CLK = os.sysconf("SC_CLK_TCK")


def read(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError:
        return None


def argv_of(pid):
    b = read("/proc/%d/cmdline" % pid)
    if not b:
        return None
    return b.rstrip(b"\0").split(b"\0")


def stat_of(pid):
    """(state, ppid, cpu ticks of the process itself) or None."""
    b = read("/proc/%d/stat" % pid)
    if not b:
        return None
    try:
        f = b.rsplit(b")", 1)[1].split()
        return f[0].decode(), int(f[1]), int(f[11]) + int(f[12])
    except (IndexError, ValueError):
        return None


def hwm_kb(pid):
    b = read("/proc/%d/status" % pid)
    if not b:
        return None
    for line in b.splitlines():
        if line.startswith(b"VmHWM:"):
            try:
                return int(line.split()[1])
            except (IndexError, ValueError):
                return None
    return None


def pids():
    try:
        return [int(n) for n in os.listdir("/proc") if n.isdigit()]
    except OSError:
        return []


def find_watch(gt, skip):
    """The process whose arguments carry --out GT and that is not sudo or us."""
    want = gt.encode()
    for pid in pids():
        if pid in skip:
            continue
        a = argv_of(pid)
        if not a or os.path.basename(a[0]) == b"sudo":
            continue
        for i in range(len(a) - 1):
            if a[i] == b"--out" and a[i + 1] == want:
                return pid
    return None


def children(pid):
    """Direct children of pid, from /proc/PID/task/*/children, else a scan."""
    out, seen_file = [], False
    try:
        tasks = os.listdir("/proc/%d/task" % pid)
    except OSError:
        return []
    for t in tasks:
        b = read("/proc/%d/task/%s/children" % (pid, t))
        if b is not None:
            seen_file = True
            out += [int(x) for x in b.split()]
    if seen_file:
        return out
    return [c for c in pids() if (stat_of(c) or (None, None))[1] == pid]


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--gt", required=True, help="the ground truth path given to watch --out")
    ap.add_argument("--out", required=True, help="where to write the measurements (JSON)")
    ap.add_argument("--interval-ms", type=float, default=5.0)
    ap.add_argument("cmd", nargs=argparse.REMAINDER)
    a = ap.parse_args(argv)
    cmd = a.cmd[1:] if a.cmd[:1] == ["--"] else a.cmd
    if not cmd:
        ap.error("no command after --")
    interval = max(a.interval_ms, 1.0) / 1000.0

    t0 = time.monotonic()
    try:
        proc = subprocess.Popen(cmd)
    except OSError as e:
        print("measure-watch: %s: %s" % (cmd[0], e), file=sys.stderr)
        return 127
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, lambda s, _f: proc.send_signal(s))

    me = {os.getpid()}  # sudo, when it is not replaced by watch, is skipped by name
    watch = hold = None
    t_hold = t_release = t_gone = None
    ticks = hwm = None
    last_scan = 0.0
    samples = 0
    rc = None
    try:
        while True:
            rc = proc.poll()
            now = time.monotonic()
            if rc is not None:
                t_end = now
                break
            if watch is None:
                if now - last_scan >= 0.02:
                    last_scan = now
                    watch = find_watch(a.gt, me)
            else:
                st = stat_of(watch)
                if st is not None:
                    ticks = st[2]
                    h = hwm_kb(watch)
                    if h is not None:
                        hwm = max(hwm or 0, h)
                    samples += 1
                if hold is None:
                    for c in children(watch):
                        av = argv_of(c)
                        if av and HOLD in av:
                            hold, t_hold = c, now
                            break
                elif t_gone is None:
                    av = argv_of(hold)
                    if t_release is None and av and HOLD not in av:
                        t_release = now
                    hs = stat_of(hold)
                    if hs is None or hs[0] == "Z":
                        t_gone = now
            time.sleep(interval)
    except Exception as e:  # measurement must never end the recording
        print("measure-watch: sampling stopped: %r" % e, file=sys.stderr)
        rc = proc.wait()
        t_end = time.monotonic()

    ru = resource.getrusage(resource.RUSAGE_CHILDREN)
    notes = []
    if watch is None:
        notes.append("the watch process was not found by its --out argument")
    elif hold is None:
        notes.append("no held agent process was seen under watch: start-up and drain not measured")
    elif t_release is None:
        notes.append("the held agent process was seen but never left the hold script")
    elif t_gone is None:
        notes.append("the agent process end was not seen: drain not measured")

    def span(x, y):
        return round(y - x, 3) if x is not None and y is not None and y >= x else None

    res = {
        "method": "measure-watch/1",
        "interval_ms": round(interval * 1000, 3),
        "exit": rc,
        "wall_s": round(t_end - t0, 3),
        "startup_s": span(t0, t_release),
        "agent_s": span(t_release, t_gone),
        "drain_s": span(t_gone, t_end) if t_release is not None else None,
        "watch_cpu_s": round(ticks / CLK, 3) if ticks is not None else None,
        "watch_maxrss_kb": hwm,
        "watch_maxrss_is_lower_bound": True,
        "tree_cpu_s": round(ru.ru_utime + ru.ru_stime, 3),
        "tree_maxrss_kb": ru.ru_maxrss,
        "samples": samples,
        "notes": notes,
    }
    try:
        tmp = a.out + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(res, f, indent=2)
            f.write("\n")
        os.replace(tmp, a.out)
    except OSError as e:
        print("measure-watch: cannot write %s: %s" % (a.out, e), file=sys.stderr)
    return rc if rc >= 0 else 128 - rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
