#!/usr/bin/env python3
"""Convert a normalized trajectory (cmd/attack's output) into Claude Code
PostToolUse hook events, one per claim, for halo-record's `halo hook` and
Signet's Claude Code signer.

    posttooluse.py CLAIMS.json [EVENTS.jsonl]

The whole claim, timestamps included, goes into `tool_input`, so the chain
seals every field an attack can change (interval widening included). The
claim's tool is the event's `tool_name`; its output hash and exit code, when
present, form `tool_response`. The ids are derived from the claim, so the
same claims give the same events.
"""
import hashlib
import json
import sys

SESSION = "00000000-0000-0000-0000-000000000000"


def events(claims, session_id=SESSION):
    out, seen = [], {}
    for c in claims:
        digest = hashlib.sha256(json.dumps(c, sort_keys=True).encode()).hexdigest()
        # Two identical claims still get distinct ids.
        seen[digest] = seen.get(digest, 0) + 1
        cid = hashlib.sha256(("%s/%d" % (digest, seen[digest])).encode()).hexdigest()[:24]
        ev = {
            "hook_event_name": "PostToolUse",
            "session_id": session_id,
            "tool_name": c.get("tool") or c["action_type"],
            "tool_input": c,
            "tool_use_id": "toolu_" + cid,
        }
        resp = {k: c[k] for k in ("output_hash", "exit_code") if k in c}
        if resp:
            ev["tool_response"] = resp
        out.append(ev)
    return out


def write_jsonl(evs, path):
    with open(path, "w") as f:
        for ev in evs:
            f.write(json.dumps(ev) + "\n")


def main(argv):
    if len(argv) not in (2, 3):
        sys.stderr.write(__doc__)
        return 2
    evs = events(json.load(open(argv[1])))
    if len(argv) == 3:
        write_jsonl(evs, argv[2])
    else:
        for ev in evs:
            print(json.dumps(ev))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
