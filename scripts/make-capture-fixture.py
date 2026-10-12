#!/usr/bin/env python3
"""Reduce a capture made by capture-claude-code.sh to a checked-in fixture.

A raw capture holds the account's email and organisation id, system prompts, the
user's home directory and a multi-kilobyte shell snapshot script in every run.
The fixture keeps what the adapter and verifier read and rewrites the rest:

  * the task transcript is cut to the records that carry tool calls and results,
    and each is cut to the fields the adapter reads;
  * the home directory becomes /home/user and each run's workspace becomes
    /ws/<label>, so the baseline's workspace placeholder is exercised;
  * the snapshot-creation command keeps its first line, with its per-run id
    intact, and loses the script body. The body differs with the enabled tool
    set, so a reduced fixture cannot show that a baseline is tied to one;
  * the account's organisation id, which the harness uses in cache paths such as
    ~/.claude/cache/model-catalog/<id>-0, becomes the zero UUID wherever it
    appears. The ids are read from the capture's own transcripts;
  * the 64-digit hex in a session key file's name,
    ~/.claude/sessions/<pid>.<hex>.key, becomes zeros. The key itself is the
    file's content, which no capture holds, but the name is per session.

Before it finishes, the script checks every file it wrote for the home
directory, the user name, the organisation ids, every e-mail address found in
the raw transcripts and any session key name left unrewritten, and deletes its
output and fails if one is left.

Ground truth events, pids, timestamps and coverage are kept as captured.

    scripts/make-capture-fixture.py CAPTURE_DIR OUTPUT_DIR [TASK_LABEL]

TASK_LABEL is the task run's label (basic captures use `task`, which is the
default; the parallel task uses `parallel`). Subagent transcripts, when the
capture has them, are reduced the same way.
"""
import json
import os
import re
import sys

capture, out = sys.argv[1], sys.argv[2]
task = sys.argv[3] if len(sys.argv) > 3 else "task"
os.makedirs(out, exist_ok=True)
home = os.path.expanduser("~")
# Every control run the capture holds (the capture script takes five by default).
labels = [task] + sorted(
    os.path.basename(f)[: -len(".ground_truth.json")]
    for f in os.listdir(capture)
    if f.startswith("control-") and f.endswith(".ground_truth.json")
)

# The account's organisation ids and e-mail addresses, as the raw transcripts
# state them. They are private and must not reach a checked-in file.
org_ids, emails = set(), set()
for name in os.listdir(capture):
    if name.endswith(".jsonl"):
        with open(os.path.join(capture, name), errors="replace") as f:
            text = f.read()
        org_ids.update(re.findall(r'"organizationUuid":\s*"([0-9a-fA-F-]{36})"', text))
        emails.update(re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text))
# Addresses that are part of the harness's own text, not the account.
emails = {e for e in emails if not e.endswith("@anthropic.com") and not e.endswith("@example.com")}
ZERO_UUID = "00000000-0000-0000-0000-000000000000"
SESSION_KEY = re.compile(r"(/\.claude/sessions/\d+\.)[0-9a-f]{64}")
ZERO_KEY = "0" * 64


def rewrite(s, label):
    ws = os.path.join(capture, "ws-" + label)
    s = s.replace(ws, "/ws/" + label)
    s = s.replace(capture, "/capture")
    s = s.replace(home, "/home/user")
    for org in org_ids:
        s = s.replace(org, ZERO_UUID)
    s = SESSION_KEY.sub(lambda m: m.group(1) + ZERO_KEY, s)
    return s.replace(os.environ.get("USER", "\0"), "user")


def elide_snapshot(target):
    if target.startswith("/bin/bash -c -l SNAPSHOT_FILE="):
        return target.split("\n", 1)[0] + "\n      <snapshot script elided>"
    return target


for label in labels:
    with open(os.path.join(capture, label + ".ground_truth.json")) as f:
        g = json.load(f)
    g["workspace"] = "/ws/" + label
    for e in g["events"]:
        e["target"] = elide_snapshot(e["target"])
    # Rewrite the whole file, so paths outside the events (the scope record's
    # mounts) are covered too.
    text = rewrite(json.dumps(g, indent=1), label)
    with open(os.path.join(out, label + ".ground_truth.json"), "w") as f:
        f.write(text + "\n")

def reduce_transcript(src, dst):
    kept = []
    with open(src) as f:
        for line in f:
            o = json.loads(line)
            m = o.get("message")
            if not isinstance(m, dict) or not isinstance(m.get("content"), list):
                continue
            blocks = [b for b in m["content"] if b.get("type") in ("tool_use", "tool_result")]
            if not blocks:
                continue
            slim = []
            for b in blocks:
                if b["type"] == "tool_use":
                    slim.append({"type": "tool_use", "id": b["id"], "name": b["name"], "input": b["input"]})
                else:
                    slim.append({"type": "tool_result", "tool_use_id": b["tool_use_id"], "content": "(elided)"})
            rec = {"type": o["type"], "timestamp": o["timestamp"], "sessionId": "00000000-0000-0000-0000-000000000000",
                   "version": o.get("version", ""), "message": {"id": m.get("id", ""), "role": m.get("role", ""), "content": slim}}
            if o.get("isSidechain"):
                rec["isSidechain"] = True
            tr = o.get("toolUseResult")
            if isinstance(tr, dict) and "type" in tr:
                rec["toolUseResult"] = {"type": tr["type"]}
            elif isinstance(tr, dict) and "originalFile" in tr:
                # An Edit's result: the adapter computes the final content from
                # these (I-31). The seeded project's files are not private.
                rec["toolUseResult"] = {k: tr[k] for k in ("originalFile", "oldString", "newString", "replaceAll") if k in tr}
            elif tr is not None:
                rec["toolUseResult"] = {}
            kept.append(json.loads(rewrite(json.dumps(rec), task)))
    os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)
    with open(dst, "w") as f:
        for r in kept:
            f.write(json.dumps(r) + "\n")
    return len(kept)


n = reduce_transcript(os.path.join(capture, task + ".session.jsonl"), os.path.join(out, task + ".session.jsonl"))
sub = os.path.join(capture, task + ".session", "subagents")
if os.path.isdir(sub):
    for name in sorted(os.listdir(sub)):
        if name.endswith(".jsonl"):
            n += reduce_transcript(os.path.join(sub, name), os.path.join(out, task + ".session", "subagents", name))
# Nothing private may be left in what was written.
user = os.environ.get("USER", "")
forbidden = {home} | org_ids | emails | ({user} if len(user) > 2 else set())
leaks = []
for root, _, files in os.walk(out):
    for name in files:
        path = os.path.join(root, name)
        with open(path, errors="replace") as f:
            text = f.read()
        for word in forbidden:
            if word and word in text:
                leaks.append((path, word))
        if any(m.group(0)[-64:] != ZERO_KEY for m in SESSION_KEY.finditer(text)):
            leaks.append((path, "session key name"))
if leaks:
    for path, word in leaks:
        print("private string left in", path, file=sys.stderr)
    import shutil
    shutil.rmtree(out)
    sys.exit("refusing to keep the fixture: remove the leaks above and run again")
print("wrote", out, "with", n, "transcript records; no private string found")
