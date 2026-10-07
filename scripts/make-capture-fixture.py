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
    set, so a reduced fixture cannot show that a baseline is tied to one.

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
labels = [task, "control-1", "control-2", "control-3"]


def rewrite(s, label):
    ws = os.path.join(capture, "ws-" + label)
    s = s.replace(ws, "/ws/" + label)
    s = s.replace(capture, "/capture")
    s = s.replace(home, "/home/user")
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
        e["target"] = elide_snapshot(rewrite(e["target"], label))
    with open(os.path.join(out, label + ".ground_truth.json"), "w") as f:
        json.dump(g, f, indent=1)
        f.write("\n")

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
print("wrote", out, "with", n, "transcript records")
