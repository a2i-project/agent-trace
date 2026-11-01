#!/usr/bin/env python3
"""Run halo-record, Signet and reproducible-trajectories over cmd/attack's
attacks and write machine-readable results, in the layout cmd/analyze reads
for H1 (--comparison).

Fixture mode (the default): the four attacks on the gated captures.

    scripts/compare/sweep.py --tools TOOLS_DIR --out OUT_DIR
        [--seeds 0-99] [--n 1] [--fixtures basic,parallel,project,edits]
        [--kinds omission,...] [--only halo-record,signet,reproducible-trajectories]
        [--jobs N] [--honest-repeats 3] [--keep]

Campaign mode (--campaign): the kept runs of a campaign directory, with the
attacked trajectories of the H2 sweep (protocol 5.3 and 8.2, decision D13).

    scripts/compare/sweep.py --tools TOOLS_DIR --out OUT_DIR --campaign DIR
        [--kept-from results.json] [--heldout-dir DIR] [--seeds 1-100]
        [--rt-seeds 1-10] [--variants primary|all] [--agents LIST]
        [--only ...] [--jobs N] [--honest-repeats 3] [--resume] [--plan-only]

  Subjects are the runs cmd/analyze keeps for H2: --kept-from takes the
  results.json of an analysis run (`analyze --campaign DIR --no-sweep`
  suffices; a run is kept when scope.Kept holds), which is the registered
  list. Without it the manifest's own reading is used (status ok, version
  unchanged, no exclusion, no loss counter, no X4 or X6 annotation), an
  approximation that run.json records.
  Variants are the H2 generators' primary rows: omission (n=1 at every
  position, built here as pkg/attack.Omit with an index writes it; n=2 and 3
  by seed), fabrication and substitution (n=1 to 3 by seed), substitution of
  each field (n=1 by seed), and interval widening (n=1 by seed: H2 runs it
  at every position). Seeds are --seeds (default 1-100) through cmd/attack
  with the same flags as the H2 generators. --variants all adds the secondary
  rows (omission and substitution selecting sensitive claims, retimed
  omission). halo-record and Signet run on every attacked trajectory of every
  agent in --agents (default every agent with a profile). reproducible-
  trajectories reads Claude Code transcripts, so it runs on the runs whose
  profile's trace method is jsonl-session, with Write or Edit claims only, on --rt-seeds of each variant (and not on the exhaustive
  omissions); a held-out task needs --heldout-dir for its seed. The rows name
  a run by its directory under the campaign, which is how cmd/analyze names
  it, so the bootstrap clusters by session.
  --resume continues an interrupted output directory: subjects with a done
  marker are kept, the rows of the others are dropped and redone.
  --plan-only prints the subjects and the number of attacked trajectories and
  tool invocations, and runs no tool.
  The inputs are cmd/attack's, not analyze's in-process generators; the two
  are the same code, and differ only where cmd/attack's avoided targets do
  (see docs/architecture/40_tools.md, comparison tools).

TOOLS_DIR is what setup.sh built. OUT_DIR must lie outside the repository
and be new or empty (campaign mode with --resume: it may hold an earlier
run); every tool runs with HOME=OUT_DIR/home. The rows hold the claims'
targets (paths, commands, hosts), so OUT_DIR is as private as the captures.
Writes:

  results.jsonl  one row per tool, condition, attacker mode (rt only),
                 attack kind, fixture (a run, in campaign mode), seed and n,
                 with the outcome (accepted, detected, not_representable,
                 attack_refused, inapplicable, error) and the tool's own
                 output; the controls have kind honest or control-*.
  summary.json   counts per tool, condition, attacker, kind and fixture,
                 with the distinct mutations among the runs, and whether
                 that tool's controls on the fixture held.
  summary.txt    the same as tables (campaign mode: per agent and task).
  run.json       parameters, the agent-trace commit, the tools' manifest,
                 and in campaign mode the subjects and those left out.

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
import shutil
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


# The H2 sweep's primary generators (cmd/analyze protocol.go GenSpecs: uniform
# selection, not retimed), as cmd/attack flags. n is the mutation count; "pos"
# marks the exhaustive n=1 omission, which cmd/attack cannot select by position.
SUBSTITUTE_FIELDS = ["target", "output_hash", "exit_code", "request_hash"]


def variant_table(which, ns):
    """(variant, kind, n, extra flags, exhaustive) for the campaign sweep."""
    out = []
    def add(name, kind, nn, exhaustive=False, **extra):
        out.append((name, kind, nn, extra, exhaustive))
    for n in ns:
        add("omit", "omission", n, exhaustive=n == 1)
    for n in ns:
        add("fabricate", "fabrication", n)
    for n in ns:
        add("substitute", "substitution", n)
    for f in SUBSTITUTE_FIELDS:
        add("substitute-field-" + f, "substitution", 1, field=f)
    add("widen", "interval-widening", 1)
    if which == "all":
        for n in ns:
            add("omit-sensitive", "omission", n, select="sensitive")
        for n in ns:
            add("omit-retime", "omission", n, retime=True)
        for n in ns:
            add("substitute-sensitive", "substitution", n, select="sensitive")
    return out


EDIT_TOOLS = ("Write", "Edit")
# The trace method of the transcripts reproducible-trajectories reads.
RT_TRACE = "jsonl-session"


def safe(name):
    return name.replace("/", "__").replace(":", "_")


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
        self.results = open(os.path.join(self.out, "results.jsonl"), "a" if args.resume else "w")
        self.notes = {}  # per subject: what was left out, for run.json

    def emit(self, rows, **fields):
        with self.lock:
            for r in rows:
                r = dict(fields, **r)
                self.results.write(json.dumps(r, sort_keys=True) + "\n")
            self.results.flush()

    def want(self, tool):
        return tool in self.a.only

    def subject_task(self, subject, pool):
        """Campaign mode: prepare a subject, then mark it done when its last
        variant job has finished without an exception (--resume reads the marks)."""
        futures = self.fixture(subject, pool)
        remaining, failed = [len(futures)], []
        if not futures:
            self.mark_done(subject)
            return []

        def finished(f):
            with self.lock:
                remaining[0] -= 1
                if f.exception() is not None:
                    failed.append(1)
                last = remaining[0] == 0
            if last and not failed:
                self.mark_done(subject)
        for f in futures:
            f.add_done_callback(finished)
        return futures

    def mark_done(self, subject):
        marks = os.path.join(self.out, "done")
        os.makedirs(marks, exist_ok=True)
        with open(os.path.join(marks, safe(subject.name)), "w") as fh:
            fh.write(subject.name + "\n")
        print("done: %s" % subject.name, flush=True)

    def note(self, subject, key, value):
        with self.lock:
            self.notes.setdefault(subject.name, {})[key] = value

    # ---- one subject ------------------------------------------------------
    def fixture(self, subject, pool):
        """Prepare a subject (fixture or campaign run) and return the futures
        of its attacked variants, or a list of futures that submit more."""
        subject = common.as_subject(subject)
        name = subject.name
        campaign = bool(self.a.campaign)
        d = os.path.join(self.out, "work", safe(name))
        os.makedirs(d, exist_ok=True)
        try:
            honest = common.honest_claims(self.attack, subject, os.path.join(d, "honest"))
        except SystemExit as e:
            if not campaign:
                raise
            self.note(subject, "skipped", str(e))
            return []
        if campaign and len(honest) < 2:
            self.note(subject, "skipped", "%d claim(s) of the agent's own: the generators need 2 (X5)" % len(honest))
            return []
        cut = common.cut_claimed(subject, honest)
        if cut:
            self.note(subject, "skipped", "%d claimed request(s) recorded cut, which confirm no claim (N-45)" % len(cut))
            return []
        state, harness = None, None
        if self.want("halo-record") or self.want("signet"):
            state, rows = chains.prepare_fixture(self.ch, honest, os.path.join(d, "chains"))
            state["late_witness"] = threading.Lock()
            state["late_done"] = False
            self.emit([r for r in rows if self.want(r["tool"])], fixture=name, seed=None, n=None)
        if self.want("reproducible-trajectories"):
            harness = self.rt_harness(subject, honest, d, name, campaign)
        if campaign:
            return self.campaign_jobs(subject, d, honest, state, harness, pool)
        jobs = []
        for kind in self.a.kinds:
            for n in self.a.n:
                for seed in self.a.seeds:
                    jobs.append(pool.submit(self.variant, subject, d, state, harness, kind, kind, n, seed))
        return jobs

    def rt_harness(self, subject, honest, d, name, campaign):
        """The reproducible-trajectories harness of a subject, with its honest
        repeats emitted; None when the tool does not apply to it (campaign
        mode: Claude Code runs with Write or Edit claims only, D13)."""
        if campaign:
            if common.trace_method(subject.agent) != RT_TRACE:
                self.note(subject, "rt", "not run: the tool reads Claude Code transcripts only")
                return None
            if not any(c.get("tool") in EDIT_TOOLS for c in honest):
                self.note(subject, "rt", "not run: no Write or Edit claim")
                return None
        try:
            harness = rt.Harness(self.tools, self.home, subject, honest, self.netns)
            unmapped = [i for i, t in enumerate(harness.mapping) if t is None]
            for k in range(self.a.honest_repeats):
                rows = harness.variant(os.path.join(d, "rt", "honest.%d" % k), keep=self.a.keep)
                self.emit(rows, fixture=name, kind="honest", seed=None, n=None, repeat=k,
                          unmapped_claims=unmapped)
        except (RuntimeError, OSError, ValueError, KeyError, StopIteration) as e:
            if not campaign:
                raise
            # The repository of this run cannot be rebuilt from its capture (a write
            # outside the workspace, a seed that is not at hand): reported, not tuned.
            why = str(e)
            if subject.task.startswith("heldout:") and not subject.heldout_seed:
                why += " (a held-out task's seed needs --heldout-dir)"
            self.note(subject, "rt", "not run: %s" % why)
            self.emit([{"tool": "reproducible-trajectories", "condition": c, "attacker": "adaptive",
                        "outcome": "inapplicable", "detail": why}
                       for c in ("edit-criterion", "command-criterion", "overall")],
                      fixture=name, kind="honest", seed=None, n=None, repeat=0)
            return None
        self.note(subject, "rt", "run on seeds %s" % self.a.rt_seeds_text)
        return harness

    def campaign_jobs(self, subject, d, honest, state, harness, pool):
        jobs = []
        ns = self.a.n
        for name, kind, n, extra, exhaustive in variant_table(self.a.variants, ns):
            if kind not in self.a.kinds:
                continue
            if exhaustive:
                jobs.append(pool.submit(self.exhaustive_omissions, subject, d, honest, state, name))
            jobs.append(pool.submit(self.seeded_group, subject, d, state, harness, name, kind, n, extra,
                                    exhaustive))
        return jobs

    def exhaustive_omissions(self, subject, d, honest, state, name):
        """Attack A1 n=1 at every position (the H2 sweep's exhaustive row)."""
        for i in range(len(honest)):
            claims, rec = common.omission_at(honest, i)
            tag = "%s.n1.p%d" % (name, i)
            fields = {"fixture": subject.name, "kind": "omission", "seed": None, "n": 1, "variant": name,
                      "position": i, "mutation": common.mutation_key(rec)}
            self.run_chains(subject, d, state, claims, tag, fields, "omission", first=(i == 0))

    def seeded_group(self, subject, d, state, harness, name, kind, n, extra, exhaustive):
        """One variant and mutation count over the seeds, stopping at the first
        seed the trajectory cannot admit, as the H2 sweep does (every seed fails
        the same way)."""
        for seed in self.a.seeds:
            # halo-record and Signet run on every seed, except for the n=1
            # omission, which they have exhaustively; rt runs on its seeds.
            chains_too = state is not None and not exhaustive
            rt_too = harness is not None and seed in self.a.rt_seed_set
            if not chains_too and not rt_too:
                continue
            if self.variant(subject, d, state, harness, name, kind, n, seed, extra, chains_too=chains_too):
                break

    def run_chains(self, subject, d, state, claims, tag, fields, kind, first=False):
        if state is None:
            return
        try:
            rows, halo = chains.run_variant(self.ch, state, claims, os.path.join(d, "chains"), tag)
            self.emit([r for r in rows if self.want(r["tool"])], **fields)
            if kind == "omission" and self.want("halo-record") and self.take_late_witness(state):
                self.emit([chains.late_witness_control(self.ch, halo, os.path.join(d, "chains"))],
                          fixture=subject.name, seed=None, n=None)
        except Exception as e:  # recorded, never dropped
            self.emit([{"tool": "harness", "condition": "all", "outcome": "error", "detail": repr(e)}], **fields)
        finally:
            if not self.a.keep:
                self.clean(os.path.join(d, "chains"), tag)

    @staticmethod
    def take_late_witness(state):
        """The halo control that a checkpoint taken after the attack accepts it
        runs once per subject, on the first omission that gets here."""
        with state["late_witness"]:
            if state["late_done"]:
                return False
            state["late_done"] = True
            return True

    @staticmethod
    def clean(directory, tag):
        """Remove a variant's files; thousands of them would fill the disk."""
        try:
            for f in os.listdir(directory):
                if f == tag or f.startswith(tag + "."):
                    path = os.path.join(directory, f)
                    shutil.rmtree(path) if os.path.isdir(path) else os.remove(path)
        except OSError:
            pass

    def variant(self, subject, d, state, harness, name, kind, n, seed, extra=None, chains_too=True):
        """One attacked trajectory through every tool. Returns True when the
        trajectory does not admit the mutation (attack_refused)."""
        extra = extra or {}
        tag = "%s.n%d.s%d" % (name, n, seed)
        os.makedirs(os.path.join(d, "attacks"), exist_ok=True)
        claims, rec = common.attack(self.attack, subject, kind, seed, n, os.path.join(d, "attacks", tag), **extra)
        fields = {"fixture": subject.name, "kind": kind, "seed": seed, "n": n}
        if self.a.campaign:
            fields["variant"] = name
        try:
            if claims is None:
                tools = self.a.only
                if self.a.campaign:  # only the tools that were to judge this subject
                    tools = [t for t in self.a.only
                             if (harness is not None if t == "reproducible-trajectories" else state is not None)]
                self.emit([{"tool": t, "condition": "all", "outcome": "attack_refused", "detail": rec}
                           for t in tools], **fields)
                return True
            fields["mutation"] = common.mutation_key(rec)
            if chains_too:
                self.run_chains(subject, d, state, claims, tag, fields, kind)
            if harness is not None and (not self.a.campaign or seed in self.a.rt_seed_set):
                try:
                    rows = harness.variant(os.path.join(d, "rt", tag), rec, keep=self.a.keep)
                except rt.NotRepresentable as e:
                    rows = rt.not_representable_rows(str(e))
                self.emit(rows, **fields)
        except Exception as e:  # recorded, never dropped
            self.emit([{"tool": "harness", "condition": "all", "outcome": "error", "detail": repr(e)}], **fields)
        finally:
            if not self.a.keep:
                self.clean(os.path.join(d, "attacks"), tag)
        return False


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


def tables(summary, fixtures, kinds, group=None):
    """Per tool row and attack kind, one column per fixture; with `group`, one
    column per group of fixtures (campaign mode: agent-version/task), summed
    over its runs, UNJUDGED unless every run's controls held."""
    lines = []
    groups = collections.OrderedDict()
    for s in summary:
        col = group(s["fixture"]) if group else s["fixture"]
        cell = groups.setdefault((s["tool"], s["condition"], s["attacker"]), {}).setdefault((s["kind"], col), {
            "runs": 0, "outcomes": collections.Counter(), "distinct_mutations": 0, "controls_held": True})
        cell["runs"] += s["runs"]
        cell["outcomes"].update(s["outcomes"])
        cell["distinct_mutations"] += s["distinct_mutations"]
        cell["controls_held"] = cell["controls_held"] and s["controls_held"]
    width = max([24] + [len(f) + 2 for f in fixtures]) if group else 24
    for (tool, cond, att), cells in groups.items():
        lines.append("%s, %s%s" % (tool, cond, ", attacker " + att if att else ""))
        lines.append("  cell: accepted/evaluated (distinct mutations); +k not representable or refused")
        lines.append("  %-18s" % "kind" + "".join(("%-" + str(width) + "s") % f for f in fixtures))
        for kind in kinds:
            row = "  %-18s" % kind
            for fx in fixtures:
                s = cells.get((kind, fx))
                if s is None:
                    row += ("%-" + str(width) + "s") % "-"
                    continue
                o = s["outcomes"]
                ev = o.get("accepted", 0) + o.get("detected", 0)
                cell = "%d/%d (%d)" % (o.get("accepted", 0), ev, s["distinct_mutations"])
                other = s["runs"] - ev
                if other:
                    cell += " +%d" % other
                if not s["controls_held"]:
                    cell = "UNJUDGED " + cell
                row += ("%-" + str(width) + "s") % cell
            lines.append(row)
        lines.append("")
    return "\n".join(lines)


def group_of(fixture):
    """The column of a campaign run in the text tables: agent-version/task."""
    return "/".join(fixture.split("/")[:2])


def kept_from(path):
    """The runs cmd/analyze attacks for H2, from its results.json. When the
    analysis ran the sweep, a run it swept carries an `attack` record: that is
    the exact set. Otherwise (--no-sweep) the set is the one the sweep would
    take: kept (scope.Kept) with a baseline built (a primary verdict without
    an error). X5 (fewer than two claims) is not known then, and is applied
    here when the honest trajectory is read."""
    doc = json.load(open(path))
    runs = doc.get("runs")
    if runs is None:
        raise SystemExit("%s has no runs: it is not an analyze results.json" % path)
    if any(r.get("attack") for r in runs):
        return {r["id"] for r in runs if r.get("attack")}
    return {r["id"] for r in runs
            if (r.get("scope") or {}).get("Kept") and r.get("primary") and not r["primary"].get("error")}


def plan(subjects, a):
    """The number of attacked trajectories and tool invocations, without running a tool."""
    attack = common.build_attack(a.out)
    rows = []
    totals = collections.Counter()
    for sub in subjects:
        d = os.path.join(a.out, "work", safe(sub.name))
        os.makedirs(d, exist_ok=True)
        try:
            honest = common.honest_claims(attack, sub, os.path.join(d, "honest"))
        except SystemExit as e:
            rows.append((sub.name, "skipped: %s" % e))
            continue
        if len(honest) < 2:
            rows.append((sub.name, "skipped: %d claim(s), the generators need 2" % len(honest)))
            continue
        cut = common.cut_claimed(sub, honest)
        if cut:
            rows.append((sub.name, "skipped: %d claimed request(s) recorded cut (N-45)" % len(cut)))
            continue
        rt_ok = common.trace_method(sub.agent) == RT_TRACE and any(c.get("tool") in EDIT_TOOLS for c in honest) \
            and "reproducible-trajectories" in a.only
        halo = 0
        rtn = 0
        for name, kind, n, extra, exhaustive in variant_table(a.variants, a.n):
            if kind not in a.kinds:
                continue
            seeds = len(a.seeds)
            if exhaustive:
                halo += len(honest)
                rtn += len([x for x in a.seeds if x in a.rt_seed_set]) if rt_ok else 0
            else:
                halo += seeds
                rtn += len([x for x in a.seeds if x in a.rt_seed_set]) if rt_ok else 0
        if not ({"halo-record", "signet"} & set(a.only)):
            halo = 0
        rows.append((sub.name, "%d claims, %d trajectories for halo-record and Signet, %d for reproducible-trajectories%s"
                     % (len(honest), halo, rtn, "" if rt_ok else " (not applicable)")))
        totals["subjects"] += 1
        totals["chains"] += halo
        totals["rt"] += rtn
        totals["rt_subjects"] += 1 if rt_ok else 0
    return rows, totals


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tools", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--seeds", default=None, type=seeds, help="default 0-99, or 1-100 with --campaign")
    ap.add_argument("--n", default=None, type=seeds, help="default 1, or 1-3 with --campaign")
    ap.add_argument("--fixtures", default=",".join(common.FIXTURES))
    ap.add_argument("--kinds", default=",".join(common.KINDS))
    ap.add_argument("--only", default=",".join(TOOLS))
    ap.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    ap.add_argument("--honest-repeats", type=int, default=3)
    ap.add_argument("--keep", action="store_true", help="keep every variant's files and every reproducible-trajectories repository")
    ap.add_argument("--campaign", help="attack the kept runs of this campaign directory instead of the fixtures")
    ap.add_argument("--kept-from", help="results.json of an analyze run: its kept runs are the subjects")
    ap.add_argument("--heldout-dir", help="the held-out tasks' directory (NAME/seed), for reproducible-trajectories")
    ap.add_argument("--rt-seeds", default="1-10", type=seeds, help="seeds reproducible-trajectories runs (D13)")
    ap.add_argument("--variants", choices=("primary", "all"), default="primary")
    ap.add_argument("--agents", default=",".join(common.profiles()),
                    help="default every agent with a profile in config/agents.json")
    ap.add_argument("--resume", action="store_true")
    ap.add_argument("--plan-only", action="store_true")
    a = ap.parse_args(argv)
    campaign = bool(a.campaign)
    if a.seeds is None:
        a.seeds = seeds("1-100" if campaign else "0-99")
    if a.n is None:
        a.n = seeds("1-3" if campaign else "1")
    a.fixtures = a.fixtures.split(",")
    a.kinds = a.kinds.split(",")
    a.only = a.only.split(",")
    a.agents = a.agents.split(",")
    for f in a.fixtures:
        if f not in common.FIXTURES:
            ap.error("unknown fixture " + f)
    for k in a.kinds:
        if k not in common.KINDS:
            ap.error("unknown kind " + k)
    for t in a.only:
        if t not in TOOLS:
            ap.error("unknown tool " + t)
    if a.resume and not campaign:
        ap.error("--resume is for --campaign")
    if (a.kept_from or a.heldout_dir or a.plan_only) and not campaign:
        ap.error("--kept-from, --heldout-dir and --plan-only are for --campaign")
    a.rt_seed_set = set(a.rt_seeds)
    a.rt_seeds_text = "%d-%d" % (a.rt_seeds[0], a.rt_seeds[-1])
    a.out = os.path.abspath(a.out)
    repo = os.path.realpath(common.REPO) + os.sep
    if (os.path.realpath(a.out) + os.sep).startswith(repo):
        ap.error("--out must lie outside the repository")
    if a.campaign:
        a.campaign = os.path.abspath(a.campaign)
        if (os.path.realpath(a.campaign) + os.sep).startswith(repo):
            ap.error("--campaign must lie outside the repository")
        if not os.path.exists(os.path.join(a.campaign, "manifest.json")):
            ap.error("%s has no manifest.json" % a.campaign)
    if a.heldout_dir:
        a.heldout_dir = os.path.abspath(a.heldout_dir)
        if (os.path.realpath(a.heldout_dir) + os.sep).startswith(repo):
            ap.error("--heldout-dir must lie outside the repository")
    if os.path.exists(a.out) and os.listdir(a.out) and not a.resume:
        ap.error("--out must be new or empty")
    os.makedirs(a.out, exist_ok=True)

    subjects, left_out = [], []
    kept_rule = None
    if campaign:
        kept = kept_from(a.kept_from) if a.kept_from else None
        kept_rule = "cmd/analyze results.json (scope.Kept)" if kept is not None else \
            "the manifest's own reading (an approximation of X1, X3, X4 and X6)"
        if kept is None:
            print("warning: no --kept-from: the subjects are chosen by the manifest's own reading, "
                  "an approximation of the analysis's exclusion rules", file=sys.stderr)
        subjects, left_out = common.campaign_subjects(a.campaign, kept, a.heldout_dir)
        subjects = [x for x in subjects if x.agent in a.agents]
        if not subjects:
            ap.error("no run of %s is kept" % a.campaign)
    if a.plan_only:
        rows, totals = plan(subjects, a)
        for name, text in rows:
            print("%-60s %s" % (name, text))
        print("\n%d subject(s), %d run(s) left out (not kept); %d reproducible-trajectories subject(s)"
              % (totals["subjects"], len(left_out), totals["rt_subjects"]))
        print("attacked trajectories: %d for halo-record and Signet (9 tool invocations each), "
              "%d for reproducible-trajectories (a repository built per trajectory)" % (totals["chains"], totals["rt"]))
        return 0

    done = set()
    if a.resume:
        done = resume_state(a.out)
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    sw = Sweep(a)
    if not sw.netns and "reproducible-trajectories" in a.only:
        print("warning: no unprivileged network namespace; the command criterion runs commands "
              "with the network reachable", file=sys.stderr)
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.jobs) as pool:
        if campaign:
            pending = [pool.submit(sw.subject_task, x, pool) for x in subjects if x.name not in done]
            finish_campaign(pending)
        else:
            jobs = []
            for f in a.fixtures:
                jobs.extend(sw.fixture(f, pool))
            for j in jobs:
                j.result()
    sw.results.close()
    summary, harness_errors = summarize(os.path.join(a.out, "results.jsonl"))
    json.dump({"cells": summary, "harness_errors": harness_errors},
              open(os.path.join(a.out, "summary.json"), "w"), indent=1)
    cols = a.fixtures
    group = None
    if campaign:
        group = group_of
        cols = sorted({group_of(c["fixture"]) for c in summary})
    text = tables(summary, cols, a.kinds, group)
    if harness_errors:
        text += "\nharness errors: %d (see results.jsonl, tool \"harness\")\n" % harness_errors
    open(os.path.join(a.out, "summary.txt"), "w").write(text)
    params = {"seeds": [a.seeds[0], a.seeds[-1], len(a.seeds)], "n": a.n, "fixtures": a.fixtures,
              "kinds": a.kinds, "only": a.only, "honest_repeats": a.honest_repeats}
    if campaign:
        params = dict(params, mode="campaign", campaign=os.path.basename(a.campaign), variants=a.variants,
                      rt_seeds=[a.rt_seeds[0], a.rt_seeds[-1], len(a.rt_seeds)], kept_rule=kept_rule,
                      agents=a.agents, subjects=sorted(x.name for x in subjects),
                      subject_notes=sw.notes, not_kept=sorted(dict(left_out)))
    json.dump({"started": started, "finished": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "agent_trace": git_state(), "tools": sw.tools.manifest, "network_namespace": sw.netns,
               "params": params},
              open(os.path.join(a.out, "run.json"), "w"), indent=1)
    print(text)
    return 1 if harness_errors else 0


def resume_state(out):
    """The subjects with a done marker; the rows of the others are dropped, since
    their subject runs again from the start."""
    done = set()
    marks = os.path.join(out, "done")
    if os.path.isdir(marks):
        for f in os.listdir(marks):
            done.add(open(os.path.join(marks, f)).read().strip())
    path = os.path.join(out, "results.jsonl")
    if os.path.exists(path):
        keep = [l for l in open(path) if l.strip() and json.loads(l).get("fixture") in done]
        open(path, "w").writelines(keep)
    return done


def finish_campaign(pending):
    """Wait for every subject: its preparation returns the variant jobs. A job
    that raised stops the sweep here, with the subject not marked done."""
    queue = list(pending)
    while queue:
        more = queue.pop().result()
        if isinstance(more, list):
            queue.extend(more)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
