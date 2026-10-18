"""halo-record and Signet over cmd/attack's trajectories: build a fresh chain
for each trajectory from its PostToolUse events (posttooluse.py) and ask
each tool's own verifier about it.

halo-record, two rows:
  no-checkpoint       the attacker re-seals the chain from the attacked
                      claims; `halo verify` exit 0 is accepted, 1 detected.
  witness-checkpoint  the honest chain was anchored to a local witness log
                      before the attack; `halo anchor --check
                      --expect-subject` on the re-sealed chain: exit 0
                      (COMPLETE) is accepted, 1 (INCOMPLETE) detected.
                      Every chain carries the same HALO_SUBJECT, since a
                      checkpoint is otherwise keyed by the chain's root,
                      which a re-seal changes (UNWITNESSED, exit 3).
Signet, two rows, both checked with the honest key pinned
(`signet verify --chain` and `signet audit --verify --trusted-agent-key`):
  operator-key        the attacker holds the signing key (no server
                      co-signing); accepted when the chain is intact and
                      every signature valid.
  other-key           a forger without the operator's key re-signs with a
                      fresh key; the same check.
`signet audit --verify` without a pinned key checks each receipt against the
key embedded in it and accepts the other-key chain, so it is not used.
"""
import json
import os
import shutil

import common
import posttooluse

HERE = os.path.dirname(os.path.abspath(__file__))
SUBJECT = "agent-trace-compare"


def _last_line(p):
    """The verdict line: halo prints COMPLETE, INCOMPLETE or UNWITNESSED
    before its notes; otherwise the last line."""
    lines = (p.stdout + p.stderr).strip().splitlines()
    for l in lines:
        if any(w in l for w in ("COMPLETE", "UNWITNESSED", "FAIL", "Invalid", "untrusted")):
            return l[:300]
    return lines[-1][:300] if lines else ""


class Chains:
    def __init__(self, tools, home):
        self.t = tools
        self.home = home

    def env(self, **kw):
        return common.scratch_env(self.home, **kw)

    # ---- halo-record --------------------------------------------------
    def halo_build(self, evs, path):
        for f in (path, path + ".lock"):
            if os.path.exists(f):
                os.remove(f)
        ev_path = path + ".events.jsonl"
        posttooluse.write_jsonl(evs, ev_path)
        p = common.run([self.t.halo_python, "-s", os.path.join(HERE, "halo_drive.py"), ev_path],
                       env=self.env(HALO_LOG=path, HALO_SUBJECT=SUBJECT, PYTHONPATH=self.t.halo_src))
        if p.returncode != 0:
            raise RuntimeError("halo hook: " + p.stderr.strip())
        return path

    def halo_verify(self, path):
        p = common.run([self.t.halo, "verify", path], env=self.env())
        return {"exit": p.returncode, "line": _last_line(p)}

    def halo_anchor(self, path, witness, check):
        cmd = [self.t.halo, "anchor", path, witness]
        if check:
            cmd += ["--check", "--expect-subject", SUBJECT]
        p = common.run(cmd, env=self.env())
        return {"exit": p.returncode, "line": _last_line(p)}

    # ---- Signet -------------------------------------------------------
    def signet_build(self, evs, signet_home, key_from=None):
        if os.path.exists(signet_home):
            shutil.rmtree(signet_home)
        os.makedirs(signet_home)
        if key_from:
            shutil.copytree(os.path.join(key_from, "keys"), os.path.join(signet_home, "keys"))
        ev_path = signet_home + ".events.jsonl"
        posttooluse.write_jsonl(evs, ev_path)
        p = common.run(["node", os.path.join(HERE, "signet_drive.cjs"), self.t.sign_cjs, ev_path],
                       env=self.env(SIGNET_HOME=signet_home))
        if p.returncode != 0:
            raise RuntimeError("signet sign: " + p.stderr.strip())
        return signet_home

    def signet_verify(self, signet_home, pubkey_file):
        chain = common.run([self.t.signet, "verify", "--chain"], env=self.env(SIGNET_HOME=signet_home))
        sigs = common.run([self.t.signet, "audit", "--verify", "--trusted-agent-key", pubkey_file],
                          env=self.env(SIGNET_HOME=signet_home))
        return {"chain_exit": chain.returncode, "chain": _last_line(chain),
                "signatures_exit": sigs.returncode, "signatures": _last_line(sigs)}


def halo_outcome(r):
    return {0: "accepted", 1: "detected"}.get(r["exit"], "error")


def signet_outcome(r):
    if r["chain_exit"] == 0 and r["signatures_exit"] == 0:
        return "accepted"
    if r["chain_exit"] in (0, 1) and r["signatures_exit"] in (0, 1):
        return "detected"
    return "error"


def prepare_fixture(ch, honest, d):
    """The honest chains, the witness of the honest halo chain, and the
    controls showing each verifier detects an edit that is not re-sealed.
    Returns (state for attacked variants, control rows)."""
    os.makedirs(d, exist_ok=True)
    evs = posttooluse.events(honest)
    halo = ch.halo_build(evs, os.path.join(d, "honest.halo.jsonl"))
    witness = os.path.join(d, "witness.jsonl")
    if os.path.exists(witness):
        os.remove(witness)
    anchored = ch.halo_anchor(halo, witness, check=False)
    if anchored["exit"] != 0:
        raise RuntimeError("halo anchor: " + anchored["line"])
    shome = ch.signet_build(evs, os.path.join(d, "honest.signet"))
    pub = os.path.join(shome, "keys", "claude-agent.pub")
    rows = []

    def row(tool, condition, kind, outcome, detail):
        rows.append({"tool": tool, "condition": condition, "kind": kind, "outcome": outcome, "detail": detail})

    v = ch.halo_verify(halo)
    row("halo-record", "no-checkpoint", "honest", halo_outcome(v), v)
    v = ch.halo_anchor(halo, witness, check=True)
    row("halo-record", "witness-checkpoint", "honest", halo_outcome(v), v)
    v = ch.signet_verify(shome, pub)
    row("signet", "operator-key", "honest", signet_outcome(v), v)

    # A record dropped from the middle without re-sealing.
    lines = open(halo).read().splitlines(True)
    naive = os.path.join(d, "naive-drop.halo.jsonl")
    open(naive, "w").writelines(lines[:len(lines) // 2] + lines[len(lines) // 2 + 1:])
    v = ch.halo_verify(naive)
    row("halo-record", "no-checkpoint", "control-drop-not-resealed", halo_outcome(v), v)
    nhome = os.path.join(d, "naive-drop.signet")
    if os.path.exists(nhome):
        shutil.rmtree(nhome)
    shutil.copytree(shome, nhome)
    audit = os.path.join(nhome, "audit")
    log = os.path.join(audit, sorted(f for f in os.listdir(audit) if f.endswith(".jsonl"))[0])
    sl = open(log).read().splitlines(True)
    open(log, "w").writelines(sl[:len(sl) // 2] + sl[len(sl) // 2 + 1:])
    v = ch.signet_verify(nhome, pub)
    row("signet", "operator-key", "control-drop-not-resealed", signet_outcome(v), v)
    return {"witness": witness, "signet_home": shome, "pub": pub}, rows


def run_variant(ch, state, claims, d, tag):
    """Re-sealed chains of one attacked trajectory; returns result rows
    without the fixture, kind and seed fields."""
    evs = posttooluse.events(claims)
    halo = ch.halo_build(evs, os.path.join(d, tag + ".halo.jsonl"))
    rows = []
    v = ch.halo_verify(halo)
    rows.append({"tool": "halo-record", "condition": "no-checkpoint", "outcome": halo_outcome(v), "detail": v})
    v = ch.halo_anchor(halo, state["witness"], check=True)
    rows.append({"tool": "halo-record", "condition": "witness-checkpoint", "outcome": halo_outcome(v), "detail": v})
    same = ch.signet_build(evs, os.path.join(d, tag + ".signet"), key_from=state["signet_home"])
    v = ch.signet_verify(same, state["pub"])
    rows.append({"tool": "signet", "condition": "operator-key", "outcome": signet_outcome(v), "detail": v})
    other = ch.signet_build(evs, os.path.join(d, tag + ".other-key.signet"))
    v = ch.signet_verify(other, state["pub"])
    rows.append({"tool": "signet", "condition": "other-key", "outcome": signet_outcome(v), "detail": v})
    return rows, halo


def late_witness_control(ch, attacked_halo, d):
    """A checkpoint taken only after the attack: the witness holds the
    re-sealed chain, and the check accepts it."""
    w = os.path.join(d, "late-witness.jsonl")
    if os.path.exists(w):
        os.remove(w)
    a = ch.halo_anchor(attacked_halo, w, check=False)
    if a["exit"] != 0:
        raise RuntimeError("halo anchor: " + a["line"])
    v = ch.halo_anchor(attacked_halo, w, check=True)
    return {"tool": "halo-record", "condition": "witness-checkpoint", "kind": "control-witness-after-attack",
            "outcome": halo_outcome(v), "detail": v}


def dump(rows):
    return "\n".join(json.dumps(r) for r in rows)
