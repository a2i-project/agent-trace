#!/usr/bin/env python3
"""Run halo-record, Signet and reproducible-trajectories over cmd/attack's
four attacks on the gated captures, and write machine-readable results.

    scripts/compare/sweep.py --tools TOOLS_DIR --out OUT_DIR
        [--seeds 0-99] [--n 1] [--fixtures basic,parallel,project,edits]
        [--kinds omission,...] [--only halo-record,signet,reproducible-trajectories]
        [--jobs N] [--honest-repeats 3] [--keep]

TOOLS_DIR is what setup.sh built. OUT_DIR must lie outside the repository
and be new or empty; every tool runs with HOME=OUT_DIR/home. Writes:

  results.jsonl  one row per tool, condition, attacker mode (rt only),
                 attack kind, fixture, seed and n, with the outcome
                 (accepted, detected, not_representable, attack_refused,
                 inapplicable, error) and the tool's own output; the
                 controls have kind honest or control-*.
  summary.json   counts per tool, condition, attacker, kind and fixture,
                 with the distinct mutations among the runs, and whether
                 that tool's controls on the fixture held.
  summary.txt    the same as tables.
  run.json       parameters, the agent-trace commit, the tools' manifest.

A cell is judged only when its controls held: the honest trajectory
accepted (every repeat, for reproducible-trajectories), a record dropped
without re-sealing detected (halo-record, Signet), and a halo checkpoint
taken after the attack accepting it. Otherwise summary.txt prints UNJUDGED.
No number here is a verdict on agent-trace.
"""
import argparse
import collections
import concurrent.futures
import datetime
import json
import os
import sys
import threading

sys.dont_write_bytecode = True  # no __pycache__ in the repository
import chains  # noqa: E402
import common  # noqa: E402
import rt  # noqa: E402

TOOLS = ["halo-record", "signet", "reproducible-trajectories"]


def seeds(spec):
    out = []
    for part in spec.split(","):
        a, _, b = part.partition("-")
        out.extend(range(int(a), int(b or a) + 1))
    return out


def git_state():
    head = common.run(["git", "rev-parse", "HEAD"], cwd=common.REPO).stdout.strip()
    dirty = bool(common.run(["git", "status", "--porcelain"], cwd=common.REPO).stdout.strip())
    return {"commit": head, "dirty": dirty}


class Sweep:
    def __init__(self, args):
        self.a = args
        self.out = args.out
        self.home = os.path.join(self.out, "home")
        os.makedirs(self.home, exist_ok=True)
        self.tools = common.Tools(args.tools)
        self.attack = common.build_attack(self.out)
        self.netns = rt.netns_available()
        self.ch = chains.Chains(self.tools, self.home)
        self.lock = threading.Lock()
        self.results = open(os.path.join(self.out, "results.jsonl"), "w")

    def emit(self, rows, **fields):
        with self.lock:
            for r in rows:
                r = dict(fields, **r)
                self.results.write(json.dumps(r, sort_keys=True) + "\n")
            self.results.flush()

    def want(self, tool):
        return tool in self.a.only

    def fixture(self, name, pool):
        d = os.path.join(self.out, "work", name)
        os.makedirs(d, exist_ok=True)
        honest = common.honest_claims(self.attack, name, os.path.join(d, "honest"))
        state, harness = None, None
        if self.want("halo-record") or self.want("signet"):
            state, rows = chains.prepare_fixture(self.ch, honest, os.path.join(d, "chains"))
            self.emit([r for r in rows if self.want(r["tool"])], fixture=name, seed=None, n=None)
        if self.want("reproducible-trajectories"):
            harness = rt.Harness(self.tools, self.home, name, honest, self.netns)
            unmapped = [i for i, t in enumerate(harness.mapping) if t is None]
            for k in range(self.a.honest_repeats):
                rows = harness.variant(os.path.join(d, "rt", "honest.%d" % k), keep=self.a.keep)
                self.emit(rows, fixture=name, kind="honest", seed=None, n=None, repeat=k,
                          unmapped_claims=unmapped)
        jobs = []
        for kind in self.a.kinds:
            for n in self.a.n:
                for seed in self.a.seeds:
                    jobs.append(pool.submit(self.variant, name, d, state, harness, kind, n, seed))
        return jobs

    def variant(self, name, d, state, harness, kind, n, seed):
        tag = "%s.n%d.s%d" % (kind, n, seed)
        os.makedirs(os.path.join(d, "attacks"), exist_ok=True)
        claims, rec = common.attack(self.attack, name, kind, seed, n, os.path.join(d, "attacks", tag))
        fields = {"fixture": name, "kind": kind, "seed": seed, "n": n}
        if claims is None:
            self.emit([{"tool": t, "condition": "all", "outcome": "attack_refused", "detail": rec}
                       for t in self.a.only], **fields)
            return
        fields["mutation"] = common.mutation_key(rec)
        try:
            if state is not None:
                rows, halo = chains.run_variant(self.ch, state, claims, os.path.join(d, "chains"), tag)
                self.emit([r for r in rows if self.want(r["tool"])], **fields)
                if kind == "omission" and n == self.a.n[0] and seed == self.a.seeds[0] and self.want("halo-record"):
                    self.emit([chains.late_witness_control(self.ch, halo, os.path.join(d, "chains"))],
                              fixture=name, seed=None, n=None)
            if harness is not None:
                try:
                    rows = harness.variant(os.path.join(d, "rt", tag), rec, keep=self.a.keep)
                except rt.NotRepresentable as e:
                    rows = rt.not_representable_rows(str(e))
                self.emit(rows, **fields)
        except Exception as e:  # recorded, never dropped
            self.emit([{"tool": "harness", "condition": "all", "outcome": "error", "detail": repr(e)}], **fields)


def summarize(path):
    rows = [json.loads(l) for l in open(path)]
    cells = collections.OrderedDict()
    controls = collections.defaultdict(list)
    for r in rows:
        if r["tool"] == "harness":
            continue
        key = (r["tool"], r["condition"], r.get("attacker", ""), r["fixture"])
        if r["kind"] == "honest" or r["kind"].startswith("control-"):
            want = "detected" if r["kind"] == "control-drop-not-resealed" else "accepted"
            ok = r["outcome"] == want
            if r["tool"] == "reproducible-trajectories":
                for c in ("edit-criterion", "command-criterion", "overall"):
                    if r["condition"] == c:
                        controls[(r["tool"], c, r["fixture"])].append(ok)
            elif r["tool"] == "signet":
                for c in ("operator-key", "other-key"):
                    controls[(r["tool"], c, r["fixture"])].append(ok)
            else:
                controls[(r["tool"], r["condition"], r["fixture"])].append(ok)
            continue
        c = cells.setdefault((r["tool"], r["condition"], r.get("attacker", ""), r["kind"], r["fixture"]),
                             {"runs": 0, "outcomes": collections.Counter(), "statuses": collections.Counter(),
                              "mutations": set()})
        c["runs"] += 1
        c["outcomes"][r["outcome"]] += 1
        if "status" in r:
            c["statuses"][str(r["status"])] += 1
        if r.get("mutation"):
            c["mutations"].add(r["mutation"])
    out = []
    for (tool, cond, att, kind, fx), c in cells.items():
        ctl = controls.get((tool, cond, fx), [])
        out.append({"tool": tool, "condition": cond, "attacker": att or None, "kind": kind, "fixture": fx,
                    "runs": c["runs"], "distinct_mutations": len(c["mutations"]),
                    "outcomes": dict(c["outcomes"]), "statuses": dict(c["statuses"]),
                    "controls_held": bool(ctl) and all(ctl), "controls": len(ctl)})
    harness_errors = sum(1 for r in rows if r["tool"] == "harness")
    return out, harness_errors


def tables(summary, fixtures, kinds):
    lines = []
    groups = collections.OrderedDict()
    for s in summary:
        groups.setdefault((s["tool"], s["condition"], s["attacker"]), {})[(s["kind"], s["fixture"])] = s
    for (tool, cond, att), cells in groups.items():
        lines.append("%s, %s%s" % (tool, cond, ", attacker " + att if att else ""))
        lines.append("  cell: accepted/evaluated (distinct mutations); +k not representable or refused")
        lines.append("  %-18s" % "kind" + "".join("%-24s" % f for f in fixtures))
        for kind in kinds:
            row = "  %-18s" % kind
            for fx in fixtures:
                s = cells.get((kind, fx))
                if s is None:
                    row += "%-24s" % "-"
                    continue
                o = s["outcomes"]
                ev = o.get("accepted", 0) + o.get("detected", 0)
                cell = "%d/%d (%d)" % (o.get("accepted", 0), ev, s["distinct_mutations"])
                other = s["runs"] - ev
                if other:
                    cell += " +%d" % other
                if not s["controls_held"]:
                    cell = "UNJUDGED " + cell
                row += "%-24s" % cell
            lines.append(row)
        lines.append("")
    return "\n".join(lines)


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tools", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--seeds", default="0-99", type=seeds)
    ap.add_argument("--n", default="1", type=seeds)
    ap.add_argument("--fixtures", default=",".join(common.FIXTURES))
    ap.add_argument("--kinds", default=",".join(common.KINDS))
    ap.add_argument("--only", default=",".join(TOOLS))
    ap.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    ap.add_argument("--honest-repeats", type=int, default=3)
    ap.add_argument("--keep", action="store_true", help="keep every reproducible-trajectories repository")
    a = ap.parse_args(argv)
    a.fixtures = a.fixtures.split(",")
    a.kinds = a.kinds.split(",")
    a.only = a.only.split(",")
    for f in a.fixtures:
        if f not in common.FIXTURES:
            ap.error("unknown fixture " + f)
    for k in a.kinds:
        if k not in common.KINDS:
            ap.error("unknown kind " + k)
    for t in a.only:
        if t not in TOOLS:
            ap.error("unknown tool " + t)
    a.out = os.path.abspath(a.out)
    repo = os.path.realpath(common.REPO) + os.sep
    if (os.path.realpath(a.out) + os.sep).startswith(repo):
        ap.error("--out must lie outside the repository")
    if os.path.exists(a.out) and os.listdir(a.out):
        ap.error("--out must be new or empty")
    os.makedirs(a.out, exist_ok=True)

    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    sw = Sweep(a)
    if not sw.netns and "reproducible-trajectories" in a.only:
        print("warning: no unprivileged network namespace; the command criterion runs commands "
              "with the network reachable", file=sys.stderr)
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.jobs) as pool:
        jobs = []
        for f in a.fixtures:
            jobs.extend(sw.fixture(f, pool))
        for j in jobs:
            j.result()
    sw.results.close()
    summary, harness_errors = summarize(os.path.join(a.out, "results.jsonl"))
    json.dump({"cells": summary, "harness_errors": harness_errors},
              open(os.path.join(a.out, "summary.json"), "w"), indent=1)
    text = tables(summary, a.fixtures, a.kinds)
    if harness_errors:
        text += "\nharness errors: %d (see results.jsonl, tool \"harness\")\n" % harness_errors
    open(os.path.join(a.out, "summary.txt"), "w").write(text)
    json.dump({"started": started, "finished": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "agent_trace": git_state(), "tools": sw.tools.manifest, "network_namespace": sw.netns,
               "params": {"seeds": [a.seeds[0], a.seeds[-1], len(a.seeds)], "n": a.n, "fixtures": a.fixtures,
                          "kinds": a.kinds, "only": a.only, "honest_repeats": a.honest_repeats}},
              open(os.path.join(a.out, "run.json"), "w"), indent=1)
    print(text)
    return 1 if harness_errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
