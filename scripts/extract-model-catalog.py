#!/usr/bin/env python3
"""Extract one model's entry from an agent's model cache into a catalog file.

  extract-model-catalog.py CACHE MODEL OUT

CACHE is the agent's cache of the server's per-model settings (Codex:
~/.codex/models_cache.json, a JSON object whose "models" list holds one
object per model, each with a "slug"). OUT receives {"models": [entry]} for
the entry whose slug is MODEL, which is the catalog format Codex reads with
-c model_catalog_json=PATH (I-80). The output is deterministic: the entry's
keys in the cache's order, two-space indentation, ASCII escapes and a final
newline, so the same cache entry always gives the same bytes and the
SHA-256 the profile pins (model.catalog.sha256) tells whether the server's
settings are still the ones the captures were pinned to.

The catalog holds the server's instructions for the model, so it is kept
outside the repository (by default under ~/.config/agent-trace/); this
script prints its SHA-256 and writes nothing else. Exit status 1 when the
cache cannot be read or has no such model, 2 on a usage error.
"""
import hashlib
import json
import os
import sys


def main(argv):
    if len(argv) != 3:
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 2
    cache, model, out = (os.path.expanduser(a) for a in argv)
    try:
        with open(cache, encoding="utf-8") as f:
            c = json.load(f)
    except (OSError, ValueError) as e:
        print(f"could not read {cache}: {e}", file=sys.stderr)
        return 1
    models = c.get("models") if isinstance(c, dict) else None
    entries = [m for m in models or [] if isinstance(m, dict) and m.get("slug") == model]
    if len(entries) != 1:
        print(f"{cache} holds {len(entries)} entries for model {model}, not one", file=sys.stderr)
        return 1
    data = (json.dumps({"models": entries}, indent=2) + "\n").encode("ascii")
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    tmp = out + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, out)
    print(f"{hashlib.sha256(data).hexdigest()}  {out}")
    if isinstance(c, dict) and c.get("client_version"):
        print(f"from the cache of client {c['client_version']}, fetched {c.get('fetched_at', 'at an unknown time')}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
