"""reproducible-trajectories over cmd/attack's mutations, applied to the
Claude Code transcript, with a git repository rebuilt per fixture.

The tool reads a session transcript, not normalized claims, and takes a git
commit as its ground truth: its edit criterion replays the transcript's
Write and Edit calls from the parent commit and compares the result with the
commit whose message names the transcript; its command criterion re-runs
every Bash command of the transcript and compares stdout plus stderr byte for
byte with the recorded result.

Repository. The checked-in fixtures carry no repository, no cwd and elided
tool results. For each variant this module builds a scratch repository whose
parent commit holds the workspace before the session (scripts/seed/<task>
for a seeded task, otherwise the capture script's b.txt, c.txt and d.txt
containing "seed"), each file checked against the hash the capture observed
when the agent first opened it, and whose second commit holds the state the
honest Write and Edit calls produce, each file checked against the hashes
the capture observed for that path. A mismatch stops the fixture. The
transcript's /ws/<label> paths are rewritten into the repository and every
record gets its cwd.

Attacks. cmd/attack mutates normalized claims; each mutation is mapped back
to the transcript call its claim came from (same tool, the call's record
timestamp, a consistent target) and applied there:
  omission           the call and its result are removed (an Edit's
                     file_open and file_write claims are one call: omitting
                     either removes the call);
  fabrication        a call of the claim's tool with the claim's target is
                     inserted after the result of the preceding claim's
                     call; a Write gets the content "fabricated\\n", an Edit
                     replaces "fabricated" with "fabricated edit";
  substitution       target: the call's file_path, command or URL changes;
                     output_hash: a Write's content or an Edit's new_string
                     gets a suffix; exit_code: the result's is_error flips;
  interval widening  the call's and its result's record timestamps take the
                     claim's new start and end.
A mutation whose claim has no call in the main transcript (a subagent's
claim, which the tool does not read), or whose field has no transcript
equivalent (a request hash, a target of Grep or Glob), is recorded as
not_representable.

Bash results. The elided results are filled by running the transcript's
Bash commands, in order, in the variant's repository at the final commit,
which is then reset and cleaned. Attacker modes: "adaptive" re-records every
Bash result after the mutation the same way (the re-sealing attacker of the
other tools); "naive" keeps the honest results, so a substituted command
keeps the old output and a fabricated one gets an empty result. The naive
mode is run only when the mutation touches a Bash call.

Safety. The command criterion and the result filling execute the
transcript's commands. They run only inside the variant's scratch
repository, with the scratch HOME and, when unprivileged user namespaces
are available, in a new network namespace (`unshare -rn`), so a command
reaches no network. That is not a sandbox: use a container or VM to run the
command criterion on a transcript you do not control.
"""
import copy
import hashlib
import json
import os
import shutil
import subprocess

import common

TARGET_FIELD = {"Read": "file_path", "Write": "file_path", "Edit": "file_path",
                "NotebookEdit": "notebook_path", "Bash": "command", "WebFetch": "url"}


class NotRepresentable(Exception):
    pass


def netns_available():
    try:
        return subprocess.run(["unshare", "-rn", "true"], capture_output=True).returncode == 0
    except FileNotFoundError:
        return False


def sha(text):
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


def load_records(path):
    return [json.loads(l) for l in open(path) if l.strip()]


def items(rec):
    c = (rec.get("message") or {}).get("content")
    return c if isinstance(c, list) else []


def tool_uses(records):
    """[(record index, tool_use item)] in transcript order."""
    return [(i, it) for i, r in enumerate(records) for it in items(r)
            if isinstance(it, dict) and it.get("type") == "tool_use"]


def result_of(records, tid):
    for i, r in enumerate(records):
        for it in items(r):
            if isinstance(it, dict) and it.get("type") == "tool_result" and it.get("tool_use_id") == tid:
                return i, it
    return None, None


def same_instant(a, b):
    """Two RFC 3339 timestamps name the same millisecond ("46.04Z" and "46.040Z")."""
    def norm(s):
        s = s.rstrip("Z")
        head, _, frac = s.partition(".")
        return head + "." + (frac + "000")[:3]
    return norm(a) == norm(b)


def consistent(claim, item):
    field = TARGET_FIELD.get(item["name"])
    if field is None:
        return True
    value = item["input"].get(field, "")
    if item["name"] == "WebFetch":
        return claim["target"] in value
    return value == claim["target"]


def map_claims(records, claims):
    """For each claim, the id of the transcript call it came from, or None."""
    uses = tool_uses(records)
    out = []
    for c in claims:
        cands = [it for i, it in uses
                 if it["name"] == c.get("tool") and same_instant(records[i]["timestamp"], c["timestamp"])
                 and consistent(c, it)]
        out.append(cands[0]["id"] if len(cands) == 1 else None)
    return out


# ---- repository reconstruction -------------------------------------------

def parent_state(fixture):
    seed = os.path.join(common.REPO, "scripts", "seed", fixture)
    state = {}
    if os.path.isdir(seed):
        for root, _, files in os.walk(seed):
            for f in files:
                p = os.path.join(root, f)
                state[os.path.relpath(p, seed)] = open(p).read()
    else:
        # scripts/capture-claude-code.sh seeds every task without a seed
        # directory with these three files.
        for f in ("b.txt", "c.txt", "d.txt"):
            state[f] = "seed\n"
    return state


def replay(state, records, ws):
    """Apply the transcript's Write and Edit calls, as Claude Code does."""
    state = dict(state)
    for _, it in tool_uses(records):
        if it["name"] not in ("Write", "Edit"):
            continue
        inp = it["input"]
        rel = os.path.relpath(inp["file_path"], ws)
        if rel.startswith(".."):
            raise RuntimeError("a write outside the workspace: " + inp["file_path"])
        if it["name"] == "Write":
            state[rel] = inp["content"]
        elif rel in state:
            n = -1 if inp.get("replace_all") else 1
            state[rel] = state[rel].replace(inp["old_string"], inp["new_string"], n)
    return state


def check_against_capture(fixture, parent, final, label):
    """Every parent file the agent opened must hash as first observed, and
    every file the agent wrote must hash to a content the capture observed
    for that path or one of its temporary siblings."""
    g = json.load(open(common.fixture_paths(fixture)["ground_truth"]))
    first_open, seen = {}, {}
    prefix = "/ws/%s/" % label
    for e in g["events"]:
        t = e.get("target", "")
        if not t.startswith(prefix):
            continue
        rel = t[len(prefix):]
        base = rel.split(".tmp.")[0]
        for k in ("input_hash", "output_hash"):
            if e.get(k):
                seen.setdefault(base, set()).add(e[k])
        if e.get("action_type") == "file_open" and e.get("input_hash") and rel not in first_open:
            first_open[rel] = e["input_hash"]
    for rel, content in parent.items():
        if rel in first_open and sha(content) != first_open[rel]:
            raise RuntimeError("%s: parent %s does not hash as the capture observed" % (fixture, rel))
    for rel, content in final.items():
        if parent.get(rel) == content:
            continue
        if sha(content) not in seen.get(rel, ()):
            raise RuntimeError("%s: replayed %s matches no content the capture observed" % (fixture, rel))


class Harness:
    def __init__(self, tools, home, fixture, honest, netns):
        self.t = tools
        self.home = home
        self.fixture = fixture
        self.fx = common.fixture_paths(fixture)
        self.label = self.fx["label"]
        self.netns = netns
        self.raw = load_records(self.fx["session"])
        self.mapping = map_claims(self.raw, honest)
        self.honest = honest
        self.parent = parent_state(fixture)

    def env(self):
        return common.scratch_env(self.home)

    def sandboxed(self, cmd):
        return (["unshare", "-rn"] if self.netns else []) + cmd

    def git(self, ws, *args):
        p = common.run(["git", "-c", "user.name=compare", "-c", "user.email=compare@example.invalid"] + list(args),
                       cwd=ws, env=self.env())
        if p.returncode != 0:
            raise RuntimeError("git %s: %s" % (" ".join(args), p.stderr.strip()))
        return p.stdout

    def transcript(self, ws):
        s = json.dumps(self.raw).replace('"/ws/%s/' % self.label, '"%s/' % ws).replace("/ws/%s" % self.label, ws)
        recs = json.loads(s)
        for r in recs:
            r["cwd"] = ws
        return recs

    def build_repo(self, vdir):
        """The repository and the honest transcript of one variant."""
        if os.path.exists(vdir):
            shutil.rmtree(vdir)
        ws = os.path.join(vdir, "ws")
        os.makedirs(ws)
        # Created now, so the variant directory's listing (`ls -la` in the
        # workspace shows it as ..) does not change between the result
        # filling and the tool's re-run.
        traj = os.path.join(vdir, "trajectory.jsonl")
        open(traj, "w").close()
        recs = self.transcript(ws)
        final = replay(self.parent, recs, ws)
        check_against_capture(self.fixture, self.parent, final, self.label)
        self.git(ws, "init", "-q", "-b", "main")
        for rel, content in self.parent.items():
            os.makedirs(os.path.dirname(os.path.join(ws, rel)), exist_ok=True)
            open(os.path.join(ws, rel), "w").write(content)
        self.git(ws, "add", "-A")
        self.git(ws, "commit", "-q", "--allow-empty", "-m", "parent")
        for rel, content in final.items():
            os.makedirs(os.path.dirname(os.path.join(ws, rel)), exist_ok=True)
            open(os.path.join(ws, rel), "w").write(content)
        self.git(ws, "add", "-A")
        self.git(ws, "commit", "-q", "--allow-empty", "-m", "agent session\n\ntrajectory: " + traj)
        return ws, traj, recs

    def fill(self, recs, ws, only=None):
        """Record each Bash call's output, run in order in the repository at
        the final commit; then restore the repository. `only` limits which
        calls get the new output (all of them are run)."""
        for _, it in tool_uses(recs):
            if it["name"] != "Bash":
                continue
            p = subprocess.run(self.sandboxed(["/bin/sh", "-c", it["input"]["command"]]),
                               cwd=ws, env=self.env(), capture_output=True, text=True)
            if only is None or it["id"] in only:
                _, res = result_of(recs, it["id"])
                if res is not None:
                    res["content"] = p.stdout + p.stderr
        self.restore(ws)
        return recs

    def restore(self, ws):
        """Back to the final commit without writing to .git (a reset would
        add ORIG_HEAD, which a `find .` in a transcript then lists)."""
        self.git(ws, "clean", "-q", "-fdx")
        if common.run(["git", "diff", "--quiet"], cwd=ws, env=self.env()).returncode != 0:
            self.git(ws, "checkout", "-q", "--", ".")

    # ---- transcript-level attacks ------------------------------------
    def apply(self, recs, record, ws):
        """Apply a cmd/attack record to a filled honest transcript. Returns
        (records, ids of Bash calls the mutation touched)."""
        recs = copy.deepcopy(recs)
        by_id = {it["id"]: (i, it) for i, it in tool_uses(recs)}
        drop, bash = set(), set()
        inserts = []

        def call_of(m, idx):
            tid = self.mapping[idx]
            if tid is None:
                c = self.honest[idx]
                raise NotRepresentable("claim %d (%s %s %s) has no call in the main transcript"
                                       % (idx, c.get("tool"), c["action_type"], c["target"]))
            return tid

        def rewrite(target):
            return target.replace("/ws/%s" % self.label, ws)

        fabricated = sorted(m["index"] for m in record["mutations"] if m["kind"] == "fabrication")
        for k, m in enumerate(record["mutations"]):
            kind = m["kind"]
            if kind == "omission":
                drop.add(call_of(m, m["original_index"]))
            elif kind == "interval_widening":
                tid = call_of(m, m["original_index"])
                ri, _ = by_id[tid]
                recs[ri]["timestamp"] = m["after"]["timestamp"]
                if m["after"].get("end"):
                    si, _ = result_of(recs, tid)
                    if si is not None:
                        recs[si]["timestamp"] = m["after"]["end"]
            elif kind == "substitution":
                tid = call_of(m, m["original_index"])
                _, it = by_id[tid]
                tool, field = it["name"], m["field"]
                if field == "target":
                    key = TARGET_FIELD.get(tool)
                    if key is None:
                        raise NotRepresentable("the target of a %s call is not an input field" % tool)
                    it["input"][key] = "https://%s/" % m["new"] if tool == "WebFetch" else rewrite(m["new"])
                elif field == "output_hash" and tool == "Write":
                    it["input"]["content"] += "substituted\n"
                elif field == "output_hash" and tool == "Edit":
                    it["input"]["new_string"] += " substituted"
                elif field == "exit_code":
                    _, res = result_of(recs, tid)
                    res["is_error"] = not res.get("is_error", False)
                else:
                    raise NotRepresentable("a %s of a %s call has no transcript equivalent" % (field, tool))
                if tool == "Bash":
                    bash.add(tid)
            elif kind == "fabrication":
                a = m["after"]
                tool = a.get("tool")
                inp = fabricated_input(tool, a, rewrite)
                fid = "toolu_compare_fabricated_%d" % k
                if tool == "Bash":
                    bash.add(fid)
                # The preceding claim of the mutated trajectory that is honest.
                pos, prev = m["index"] - 1, None
                while pos >= 0:
                    if pos in fabricated:
                        pos -= 1
                        continue
                    hidx = pos - sum(1 for f in fabricated if f < pos)
                    if self.mapping[hidx] is not None:
                        prev = self.mapping[hidx]
                        break
                    pos -= 1
                inserts.append((prev, fabricated_records(recs, fid, tool, inp, a)))
            else:
                raise RuntimeError("unknown mutation kind " + kind)

        for prev, (use, res) in inserts:
            if prev is None:
                at = tool_uses(recs)[0][0]
            else:
                ri, _ = result_of(recs, prev)
                at = (ri if ri is not None else
                      next(i for i, it in tool_uses(recs) if it["id"] == prev)) + 1
            recs[at:at] = [use, res]
        if drop:
            keep = []
            for r in recs:
                ids = {it.get("id") for it in items(r) if isinstance(it, dict) and it.get("type") == "tool_use"}
                ids |= {it.get("tool_use_id") for it in items(r) if isinstance(it, dict) and it.get("type") == "tool_result"}
                if not ids & drop:
                    keep.append(r)
            recs = keep
        return recs, bash

    def check(self, traj, ws):
        p = common.run(self.sandboxed([self.t.rt, "check-execution-reproducible", traj,
                                       "--repo", ws, "--cwd", ws, "--json"]), cwd=ws, env=self.env())
        try:
            r = json.loads(p.stdout)
        except ValueError:
            return {"error": (p.stdout + p.stderr)[-500:]}
        return {"edit": r["edit_criterion"]["status"],
                "edit_files": [[f["file"], f["status"]] for f in r["edit_criterion"].get("files", [])],
                "command": r["command_criterion"]["status"],
                "commands": [[c["command"][:120], c["match"]] + ([] if c["match"] else [first_difference(c)])
                             for c in r["command_criterion"]["commands"]],
                "execution_reproducible": r["execution_reproducible"]}

    def variant(self, vdir, record=None, keep=False):
        """Rows for one variant (record None: the honest transcript)."""
        ws, traj, recs = self.build_repo(vdir)
        honest = self.fill(recs, ws)
        modes = []
        if record is None:
            modes.append(("adaptive", honest))
        else:
            mutated, bash = self.apply(honest, record, ws)
            modes.append(("adaptive", self.fill(copy.deepcopy(mutated), ws)))
            if bash:
                stale = copy.deepcopy(mutated)
                for _, it in tool_uses(stale):
                    if it["id"].startswith("toolu_compare_fabricated_"):
                        _, res = result_of(stale, it["id"])
                        res["content"] = ""
                modes.append(("naive", stale))
        rows = []
        for mode, rs in modes:
            with open(traj, "w") as f:
                for r in rs:
                    f.write(json.dumps(r) + "\n")
            r = self.check(traj, ws)
            self.restore(ws)
            rows.extend(rt_rows(r, mode))
        if not keep:
            shutil.rmtree(vdir)
        return rows


def fabricated_input(tool, claim, rewrite):
    t = claim["target"]
    if tool == "Write":
        return {"file_path": rewrite(t), "content": "fabricated\n"}
    if tool == "Edit":
        return {"replace_all": False, "file_path": rewrite(t), "old_string": "fabricated", "new_string": "fabricated edit"}
    if tool == "Read":
        return {"file_path": rewrite(t)}
    if tool == "NotebookEdit":
        return {"notebook_path": rewrite(t), "new_source": "fabricated", "edit_mode": "replace"}
    if tool == "Bash":
        return {"command": t, "description": "fabricated"}
    if tool == "WebFetch":
        return {"url": "https://%s/" % t, "prompt": "fabricated"}
    raise NotRepresentable("no transcript call for a fabricated %s claim" % tool)


def fabricated_records(recs, fid, tool, inp, claim):
    use_t = next(r for r in recs if any(isinstance(it, dict) and it.get("type") == "tool_use" for it in items(r)))
    res_t = next(r for r in recs if any(isinstance(it, dict) and it.get("type") == "tool_result" for it in items(r)))
    use, res = copy.deepcopy(use_t), copy.deepcopy(res_t)
    use["timestamp"] = claim["timestamp"]
    use["message"]["id"] = "msg_compare_" + fid
    use["message"]["content"] = [{"type": "tool_use", "id": fid, "name": tool, "input": inp}]
    res["timestamp"] = claim.get("end") or claim["timestamp"]
    res["message"]["content"] = [{"type": "tool_result", "tool_use_id": fid, "content": "(fabricated)"}]
    res.pop("toolUseResult", None)
    return use, res


def first_difference(c):
    """The first line where a re-run's output differs from the recorded one."""
    exp, act = c["expected"].splitlines(), c["actual"].splitlines()
    for k in range(max(len(exp), len(act))):
        e = exp[k] if k < len(exp) else None
        a = act[k] if k < len(act) else None
        if e != a:
            return {"line": k + 1, "recorded": e and e[:160], "rerun": a and a[:160]}
    return {"line": None, "recorded": repr(c["expected"][-80:]), "rerun": repr(c["actual"][-80:])}


def rt_rows(r, mode):
    base = {"tool": "reproducible-trajectories", "attacker": mode}
    if "error" in r:
        return [dict(base, condition=c, outcome="error", detail=r)
                for c in ("edit-criterion", "command-criterion", "overall")]
    edit = {"not_reproducible": "detected", "reproducible": "accepted", "no_operations": "accepted"}.get(r["edit"], "error")
    cmd = {"not_reproducible": "detected", "reproducible": "accepted", "no_commands": "accepted"}.get(r["command"], "error")
    overall = {False: "detected", True: "accepted", None: "inapplicable"}[r["execution_reproducible"]]
    return [dict(base, condition="edit-criterion", outcome=edit, status=r["edit"], detail=r["edit_files"]),
            dict(base, condition="command-criterion", outcome=cmd, status=r["command"], detail=r["commands"]),
            dict(base, condition="overall", outcome=overall, status=r["execution_reproducible"])]


def not_representable_rows(reason):
    return [{"tool": "reproducible-trajectories", "attacker": "adaptive", "condition": c,
             "outcome": "not_representable", "detail": reason}
            for c in ("edit-criterion", "command-criterion", "overall")]
