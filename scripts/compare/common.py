"""Shared pieces of the comparison harnesses: pins, fixtures, the scratch
environment every tool runs in, and the attacks from cmd/attack.

Standard library only; runs under the system python3.
"""
import json
import os
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
CONFIG = os.path.join(REPO, "config", "agents.json")

# The gated captures of the attack evaluation (pkg/attack/eval_test.go, E-5):
# name -> (fixture directory, run label). The profile that lists the directory
# among its versions' fixtures gives its path, its agent and its session file.
FIXTURES = {
    "basic": ("paired-2.1.286", "task"),
    "parallel": ("paired-2.1.286-parallel", "parallel"),
    "project": ("paired-2.1.286-project", "project"),
    "edits": ("paired-2.1.296-edits", "edits"),
}
KINDS = ["omission", "fabrication", "substitution", "interval-widening"]


def load_pins():
    pins = {}
    with open(os.path.join(HERE, "pins.env")) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                k, v = line.split("=", 1)
                pins[k] = v
    return pins


def profiles():
    """The agent profiles of config/agents.json (I-77), by agent."""
    with open(CONFIG) as f:
        c = json.load(f)
    if c.get("schema") != 2:
        raise SystemExit("%s: schema %s, the comparison reads 2" % (CONFIG, c.get("schema")))
    return c.get("adapters") or {}


def trace_method(agent):
    """The method of the agent's trace in its profile, or None."""
    return ((profiles().get(agent) or {}).get("trace") or {}).get("method")


def fixture_paths(name):
    d, label = FIXTURES[name]
    for agent, prof in profiles().items():
        for v in prof.get("versions") or []:
            for rel in v.get("fixtures") or []:
                if os.path.basename(rel) != d:
                    continue
                base = os.path.join(REPO, rel)
                session = (prof.get("trace") or {}).get("file", "").replace("{label}", label)
                return {"dir": base, "label": label, "agent": agent,
                        "session": os.path.join(base, session),
                        "ground_truth": os.path.join(base, label + ".ground_truth.json")}
    raise SystemExit("fixture %s is listed by no profile in %s" % (d, CONFIG))


class Subject:
    """One capture the sweep attacks: a checked-in fixture or a campaign run.

    name          the identifier written to the rows' `fixture` field: the
                  fixture's name, or a campaign run's directory relative to
                  the campaign (the identifier cmd/analyze gives the run)
    agent         the adapter that reads the session (a profile's name)
    session       the transcript or conversation database
    ground_truth  the capture's ground truth
    label         the run's label (the task's), used in scratch paths
    task          the task, which names the seed of its workspace
    ws            the workspace path as the transcript and the capture name it
    heldout_seed  the seed directory of a held-out task (outside the repo)
    """

    def __init__(self, name, agent, session, ground_truth, label, task, ws, heldout_seed=None):
        self.name, self.agent, self.session, self.ground_truth = name, agent, session, ground_truth
        self.label, self.task, self.ws, self.heldout_seed = label, task, ws, heldout_seed


def fixture_subject(name):
    fx = fixture_paths(name)
    return Subject(name, fx["agent"], fx["session"], fx["ground_truth"], fx["label"], name,
                   "/ws/" + fx["label"])


def as_subject(x):
    return x if isinstance(x, Subject) else fixture_subject(x)


def run_id(campaign, rec):
    """A run's identifier, as cmd/analyze names it: its directory under the
    campaign. The manifest records the path of the machine that wrote it, so
    the last three components, <agent>-<version>/<task>/run-NN, are what count."""
    return "/".join(rec["dir"].rstrip("/").split("/")[-3:])


def campaign_subjects(campaign, kept=None, heldout_dir=None):
    """The runs of a campaign directory that the sweep attacks.

    kept: a set of run identifiers (from cmd/analyze's results.json), or None
    for the manifest's own reading of a kept run: status ok, no version change,
    no recorded exclusion, no loss counter on the task run, no annotation of
    X4 or X6. Returns (subjects, skipped), skipped as (identifier, reason)."""
    manifest = json.load(open(os.path.join(campaign, "manifest.json")))
    ann = {}
    p = os.path.join(campaign, "annotations.json")
    if os.path.exists(p):
        ann = json.load(open(p)).get("runs", {})
    subjects, skipped = [], []
    for rec in manifest.get("runs", []):
        rid = run_id(campaign, rec)
        why = None
        if kept is not None:
            if rid not in kept:
                why = "not a kept run in the analysis"
        else:
            why = unkept_reason(rec, ann.get(rid, {}))
        if why:
            skipped.append((rid, why))
            continue
        d = os.path.join(campaign, *rid.split("/"))
        paths = rec.get("paths") or {}
        traj = os.path.basename(paths.get("trajectory") or "")
        gt = os.path.basename(paths.get("ground_truth") or "")
        if not traj or not gt:
            skipped.append((rid, "the manifest names no trajectory or ground truth"))
            continue
        g = json.load(open(os.path.join(d, gt)))
        label = rec["task"].replace(":", "-")
        seed = None
        if rec["task"].startswith("heldout:") and heldout_dir:
            c = os.path.join(heldout_dir, rec["task"][len("heldout:"):], "seed")
            seed = c if os.path.isdir(c) else None
        subjects.append(Subject(rid, rec["agent"], os.path.join(d, traj), os.path.join(d, gt), label,
                                rec["task"], g.get("workspace") or "", seed))
    return subjects, skipped


LOSS_COUNTERS = ("ringbuf_drops", "untracked_children", "state_map_full", "channel_drops", "queue_overflow",
                 "undrained_records", "unresolved_in_tree", "response_gaps")


def unkept_reason(rec, ann):
    """Why the manifest alone says a run is not kept, or None. An approximation
    of cmd/analyze's exclusion rules (X1, X3, X4, X6): the analysis's own list
    (--kept-from) is the registered one."""
    if rec.get("status") != "ok":
        return "status %s" % rec.get("status")
    if rec.get("version_after") and rec["version_after"] != rec.get("version"):
        return "X3: the version changed"
    if rec.get("exclusion"):
        return "excluded by the runner: %s" % (rec["exclusion"].get("rule"),)
    if ann.get("x4") or ann.get("x6"):
        return "annotated X4 or X6"
    probes = ((rec.get("scale") or {}).get("probes")) or {}
    for name, p in probes.items():
        if not p.get("ran", True):
            continue
        for k in LOSS_COUNTERS:
            if p.get(k):
                return "X1: %s %s=%s" % (name, k, p[k])
    if not probes:
        return "X1: no coverage record"
    return None


def cut_claimed(subject, honest):
    """The targets of the requests the subject's capture recorded cut (N-44)
    that a claim of its honest trajectory names, sorted. A cut request confirms
    no claim, so a run with one reads INCONCLUSIVE when honest and is left out
    (N-45); a cut request no claim names, the harness's own housekeeping, does
    not leave a run out. A claim is matched by its target, as the verifier
    keeps a request for a claim of its target (V-54)."""
    g = json.load(open(as_subject(subject).ground_truth))
    cut = {e.get("target") for e in g.get("events") or []
           if e.get("action_type") == "net_request" and e.get("request_cut")}
    claimed = {c.get("target") for c in honest if c.get("action_type") == "net_request"}
    return sorted(cut & claimed)


class Tools:
    """The layout setup.sh writes into TOOLS_DIR."""

    def __init__(self, root):
        self.root = os.path.abspath(root)
        b = os.path.join(self.root, "bin")
        self.halo = os.path.join(b, "halo")
        self.halo_python = os.path.join(self.root, "venv-halo", "bin", "python")
        self.halo_src = os.path.join(self.root, "src", "halo-record", "src")
        self.signet = os.path.join(b, "signet")
        self.sign_cjs = os.path.join(self.root, "src", "signet", "plugins", "claude-code", "bin", "sign.cjs")
        self.rt = os.path.join(b, "reproducible-trajectories")
        manifest = os.path.join(self.root, "manifest.json")
        if not os.path.exists(manifest):
            raise SystemExit("%s has no manifest.json: run scripts/compare/setup.sh first" % self.root)
        self.manifest = json.load(open(manifest))
        pins = load_pins()
        for name, key in (("halo-record", "HALO_COMMIT"), ("reproducible-trajectories", "RT_COMMIT"),
                          ("signet", "SIGNET_COMMIT")):
            head = subprocess.run(["git", "-C", os.path.join(self.root, "src", name), "rev-parse", "HEAD"],
                                  capture_output=True, text=True).stdout.strip()
            if head != pins[key]:
                raise SystemExit("%s is at %s, pins.env says %s: rerun setup.sh" % (name, head, pins[key]))


def scratch_env(home, **extra):
    """A minimal environment: the scratch HOME, no global git configuration,
    and nothing inherited that a tool reads (HALO_*, SIGNET_*, ...)."""
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": home,
        "LANG": "C.UTF-8",
        "TZ": "UTC",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }
    env.update(extra)
    return env


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def build_attack(out_dir):
    path = os.path.join(out_dir, "attack")
    p = run(["go", "build", "-o", path, "./cmd/attack"], cwd=REPO)
    if p.returncode != 0:
        raise SystemExit("go build ./cmd/attack failed:\n" + p.stderr)
    return path


def attack(binary, subject, kind, seed, n, out_prefix, select=None, field=None, retime=False):
    """Run cmd/attack on a subject's session. Fabrication and substitution get
    the capture's ground truth to avoid, as in the evaluation; the other two
    generators ignore it, so it is not parsed for them. Returns (claims, record)
    or (None, error)."""
    subject = as_subject(subject)
    out, rec = out_prefix + ".json", out_prefix + ".rec.json"
    cmd = [binary, "--kind", kind, "--seed", str(seed), "--n", str(n),
           "--trajectory", subject.session, "--agent", subject.agent, "--out", out, "--record", rec]
    if kind in ("fabrication", "substitution"):
        cmd += ["--avoid-ground-truth", subject.ground_truth]
    if select:
        cmd += ["--select", select]
    if field:
        cmd += ["--field", field]
    if retime:
        cmd += ["--retime"]
    p = run(cmd)
    if p.returncode != 0:
        return None, p.stderr.strip()
    return json.load(open(out)), json.load(open(rec))


def honest_claims(binary, subject, out_prefix):
    """The honest normalized trajectory as cmd/attack sees it: an omission with
    its dropped entry put back. Two seeds must give the same list."""
    subject = as_subject(subject)
    lists = []
    for seed in (0, 1):
        claims, rec = attack(binary, subject, "omission", seed, 1, "%s.s%d" % (out_prefix, seed))
        if claims is None:
            raise SystemExit("attack on %s: %s" % (subject.name, rec))
        m = rec["mutations"][0]
        claims.insert(m["original_index"], m["before"])
        lists.append(claims)
    if lists[0] != lists[1]:
        raise SystemExit("%s: the honest trajectory differs between seeds" % subject.name)
    return lists[0]


def omission_at(honest, i):
    """Attack A1 at position i, as pkg/attack.Omit with Indices: [i] writes it
    (seed 0, nothing retimed), for the exhaustive n=1 omissions of the H2 sweep,
    which cmd/attack has no flag for. Returns (claims, record)."""
    claims = honest[:i] + honest[i + 1:]
    rec = {"kind": "omission", "seed": 0,
           "mutations": [{"kind": "omission", "original_index": i, "index": -1, "before": honest[i]}]}
    return claims, rec


def mutation_key(record):
    """What makes two mutations the same, for counting distinct cases."""
    return json.dumps(record.get("mutations"), sort_keys=True)
