"""Shared pieces of the comparison harnesses: pins, fixtures, the scratch
environment every tool runs in, and the attacks from cmd/attack.

Standard library only; runs under the system python3.
"""
import json
import os
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
TESTDATA = os.path.join(REPO, "pkg", "agent", "claudecode", "testdata")

# The gated captures of the attack evaluation (pkg/attack/eval_test.go, E-5):
# name -> (fixture directory, run label).
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


def fixture_paths(name):
    d, label = FIXTURES[name]
    base = os.path.join(TESTDATA, d)
    return {"dir": base, "label": label,
            "session": os.path.join(base, label + ".session.jsonl"),
            "ground_truth": os.path.join(base, label + ".ground_truth.json")}


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


def attack(binary, fixture, kind, seed, n, out_prefix):
    """Run cmd/attack on a fixture's session, with the capture's ground truth
    avoided as in the evaluation. Returns (claims, record) or (None, error)."""
    fx = fixture_paths(fixture)
    out, rec = out_prefix + ".json", out_prefix + ".rec.json"
    p = run([binary, "--kind", kind, "--seed", str(seed), "--n", str(n),
             "--trajectory", fx["session"], "--agent", "claude-code",
             "--avoid-ground-truth", fx["ground_truth"], "--out", out, "--record", rec])
    if p.returncode != 0:
        return None, p.stderr.strip()
    return json.load(open(out)), json.load(open(rec))


def honest_claims(binary, fixture, out_prefix):
    """The honest normalized trajectory as cmd/attack sees it: an omission with
    its dropped entry put back. Two seeds must give the same list."""
    lists = []
    for seed in (0, 1):
        claims, rec = attack(binary, fixture, "omission", seed, 1, "%s.s%d" % (out_prefix, seed))
        if claims is None:
            raise SystemExit("attack on %s: %s" % (fixture, rec))
        m = rec["mutations"][0]
        claims.insert(m["original_index"], m["before"])
        lists.append(claims)
    if lists[0] != lists[1]:
        raise SystemExit("%s: the honest trajectory differs between seeds" % fixture)
    return lists[0]


def mutation_key(record):
    """What makes two mutations the same, for counting distinct cases."""
    return json.dumps(record.get("mutations"), sort_keys=True)
