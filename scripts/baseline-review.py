#!/usr/bin/env python3
"""Print a baseline's rules grouped for a person to review (I-164).

    baseline-review.py BASELINE [--against OTHER_BASELINE]

The rules are grouped as commands run (process_exec), hosts and requests
(the net_ action types), files outside the workspace by directory, files in
the workspace ({workspace}/...), and anything else; then what each
baselined command did beneath it (the baseline's subtrees, V-38), and the
sensitive-file changes it explains (V-40). A file's action types are
listed together on its line. With --against, only what OTHER lacks is
printed: a rule whose action type and target OTHER has no rule for, an
event beneath a command that OTHER's record of the same command lacks, a
sensitive change OTHER does not list. A multi-line command is shown by its
first line and its line count, a line over 200 characters by its start and
its length.

The review is report only: it decides nothing and exits 0 whatever it
prints; 1 for a baseline it cannot read, 2 for a usage error.
"""
import argparse
import json
import os
import sys

WORKSPACE = "{workspace}"
# The longest command line shown whole.
WIDTH = 200
SHORT = {"file_open": "open", "file_read": "read", "file_write": "write", "file_close": "close",
         "file_rename": "rename", "file_delete": "delete"}


def load(path):
    try:
        with open(path, encoding="utf-8") as f:
            b = json.load(f)
    except (OSError, ValueError) as e:
        print("baseline-review: cannot read %s: %s" % (path, e), file=sys.stderr)
        sys.exit(1)
    if not isinstance(b, dict) or not isinstance(b.get("rules"), list):
        print("baseline-review: %s is not a baseline (no rules)" % path, file=sys.stderr)
        sys.exit(1)
    return b


def pairs(rules):
    return [(r.get("action_type", ""), r.get("target", "")) for r in rules or [] if isinstance(r, dict)]


def command(target):
    lines = target.split("\n")
    first = lines[0] if len(lines[0]) <= WIDTH else lines[0][:WIDTH] + " ... (%d characters)" % len(lines[0])
    return first if len(lines) == 1 else "%s  (+%d more lines)" % (first, len(lines) - 1)


def describe(b, path):
    return "%s (%s %s, mode %s, %d rule(s) from %d control run(s))" % (
        path, b.get("agent", "?"), b.get("agent_version", "?"), b.get("mode") or "print", len(b.get("rules") or []), b.get("runs", 0))


def group(rules):
    """The rules by section: commands, network, files outside the
    workspace by directory, files in the workspace, other."""
    execs = {t for a, t in rules if a == "process_exec"}
    out = {"commands": [], "network": [], "outside": {}, "inside": {}, "other": []}
    for a, t in sorted(set(rules)):
        if a == "process_exec":
            out["commands"].append(t)
        elif a == "process_exit" and t in execs:
            continue  # the exit of a command listed above
        elif a.startswith("net_"):
            out["network"].append((a, t))
        elif a in SHORT:
            inside = t == WORKSPACE or t.startswith(WORKSPACE + "/")
            out["inside" if inside else "outside"].setdefault(t, []).append(SHORT[a])
        else:
            out["other"].append((a, t))
    return out


def print_rules(rules, w):
    g = group(rules)
    w("commands run (%d):" % len(g["commands"]))
    for t in g["commands"]:
        w("  " + command(t))
    w("hosts and requests (%d):" % len(g["network"]))
    for a, t in g["network"]:
        w("  %-16s %s" % (a, t))
    w("files outside the workspace (%d), by directory:" % len(g["outside"]))
    dirs = {}
    for t, acts in g["outside"].items():
        dirs.setdefault(os.path.dirname(t) or "/", []).append((os.path.basename(t), acts))
    for d in sorted(dirs):
        w("  %s/" % d.rstrip("/"))
        for name, acts in sorted(dirs[d]):
            w("    %s  %s" % (name, ", ".join(acts)))
    w("files in the workspace (%d):" % len(g["inside"]))
    for t, acts in sorted(g["inside"].items()):
        w("  %s  %s" % (t, ", ".join(acts)))
    if g["other"]:
        w("other (%d):" % len(g["other"]))
        for a, t in g["other"]:
            w("  %-16s %s" % (a, command(t)))


def main(argv):
    ap = argparse.ArgumentParser(prog="baseline-review.py", description=__doc__.split("\n\n")[0])
    ap.add_argument("baseline")
    ap.add_argument("--against", help="print only what this baseline lacks")
    a = ap.parse_args(argv)
    b = load(a.baseline)
    other = load(a.against) if a.against else None
    lines = []
    w = lines.append
    w("baseline review: " + describe(b, a.baseline))
    rules = pairs(b.get("rules"))
    subtrees = [s for s in b.get("subtrees") or [] if isinstance(s, dict)]
    sensitive = [(c.get("file", ""), tuple(c.get("key") or []), c.get("kind", "")) for c in ((b.get("sensitive") or {}).get("changes") or [])]
    if other is not None:
        w("against:         " + describe(other, a.against) + ": only what it lacks")
        have = set(pairs(other.get("rules")))
        rules = [r for r in rules if r not in have]
        theirs = {s.get("command"): set(pairs(s.get("events"))) for s in other.get("subtrees") or [] if isinstance(s, dict)}
        subtrees = [dict(s, events=[{"action_type": x, "target": y} for x, y in pairs(s.get("events")) if (x, y) not in theirs.get(s.get("command"), set())])
                    for s in subtrees]
        known = {(c.get("file", ""), tuple(c.get("key") or []), c.get("kind", "")) for c in ((other.get("sensitive") or {}).get("changes") or [])}
        sensitive = [c for c in sensitive if c not in known]
    w("")
    print_rules(rules, w)
    subtrees = [s for s in subtrees if s.get("events")]
    w("beneath baselined commands (%d command(s)):" % len(subtrees))
    for s in sorted(subtrees, key=lambda s: s.get("command", "")):
        w("  %s%s:" % (command(s.get("command", "")), " (declared harness command)" if s.get("declared") else ""))
        for x, y in sorted(set(pairs(s.get("events")))):
            w("    %-16s %s" % (x, command(y)))
    w("sensitive-file changes (%d):" % len(sensitive))
    for f, key, kind in sorted(sensitive):
        w("  %s  %s  %s" % (f, ".".join(key) or "(whole file)", kind))
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
