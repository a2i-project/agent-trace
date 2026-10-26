#!/usr/bin/env bash
# Record what only the operator knows about campaign runs, in the campaign's
# annotations.json, the file cmd/analyze reads (protocol 10.1):
#
#   scripts/annotate-run.sh [--campaign DIR] [--completed yes|no] [--note TEXT]
#                           [--intervened] [--x4 TEXT] RUN_DIR...
#   scripts/annotate-run.sh [--campaign DIR] --list
#
#   --completed yes|no  the agent did (or did not) complete the task: X5, reported
#                       per task and never an exclusion from H3
#   --intervened        you intervened in the run (typed to the agent, answered a
#                       prompt, suspended the machine): X6, which takes the run
#                       out of every analysis; --note gives the reason
#   --x4 TEXT           a harness error the manifest cannot show (a crash, a
#                       quota error, a suspend): X4, which takes the run out of
#                       every analysis
#   --note TEXT         a free note, kept in the run's entry (the analysis does
#                       not read it); with --intervened it is also the X6 reason
#   --list              print every run of the manifest with its recorded
#                       completion, and mark those with none
#
# RUN_DIR is a run directory of the campaign (OUTPUT_DIR/<agent>-<version>/
# <task>/run-NN), absolute or relative; several may be given and each gets the
# same fields. The campaign directory is three levels above it unless
# --campaign names it. A field the runner wrote itself (listed under "auto":
# currently x4 for a run whose watch exited non-zero) becomes yours as soon as
# you set it, and the runner no longer rewrites it. The file is replaced
# atomically; a call with no field option changes nothing.
set -euo pipefail

campaign=
completed=
note=
intervened=
x4=
list=
dirs=()
while [ $# -gt 0 ]; do
  case $1 in
    --campaign) campaign=${2:?--campaign needs a directory}; shift 2 ;;
    --completed) completed=${2:?--completed needs yes or no}; shift 2 ;;
    --note) note=${2:?--note needs text}; shift 2 ;;
    --intervened) intervened=1; shift ;;
    --x4) x4=${2:?--x4 needs text}; shift 2 ;;
    --list) list=1; shift ;;
    -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "unknown option $1" >&2; exit 2 ;;
    *) dirs+=("$1"); shift ;;
  esac
done
case $completed in ''|yes|no) ;; *) echo "--completed must be yes or no" >&2; exit 2 ;; esac
if [ -z "$list" ] && [ -z "$completed$note$intervened$x4" ]; then
  echo "nothing to record: give --completed, --intervened, --x4 or --note" >&2
  exit 2
fi
if [ -z "$list" ] && [ "${#dirs[@]}" -eq 0 ]; then
  echo "usage: $0 [--campaign DIR] [--completed yes|no] [--note TEXT] [--intervened] [--x4 TEXT] RUN_DIR... | --list" >&2
  exit 2
fi
if [ -n "$list" ] && [ -z "$campaign" ] && [ "${#dirs[@]}" -gt 0 ]; then
  campaign=$(realpath -m "${dirs[0]}/../../..")
fi
[ -z "$list" ] || [ -n "$campaign" ] || { echo "--list needs --campaign DIR or a RUN_DIR" >&2; exit 2; }

python3 - "$campaign" "$completed" "$note" "$intervened" "$x4" "$list" "${dirs[@]}" <<'PY'
import json, os, sys

campaign, completed, note, intervened, x4, listing = sys.argv[1:7]
dirs = sys.argv[7:]


def die(msg):
    print("annotate-run: " + msg, file=sys.stderr)
    sys.exit(1)


def load(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return default
    except ValueError as e:
        die("%s does not parse (%s); fix or remove it" % (path, e))


def write(path, doc):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(tmp, path)


def ident(c, d):
    rel = os.path.relpath(os.path.realpath(d), os.path.realpath(c))
    if rel.startswith("..") or rel.count(os.sep) != 2:
        die("%s is not a run directory of %s (want <agent>-<version>/<task>/run-NN under it)" % (d, c))
    return rel.replace(os.sep, "/")


if listing:
    manifest = load(os.path.join(campaign, "manifest.json"), None)
    if manifest is None:
        die("no manifest.json in " + campaign)
    ann = (load(os.path.join(campaign, "annotations.json"), {}) or {}).get("runs", {})
    missing = 0
    for r in sorted(manifest.get("runs", []), key=lambda r: r.get("dir", "")):
        rid = "/".join(r["dir"].rstrip("/").split("/")[-3:])  # as cmd/analyze names a run
        e = ann.get(rid, {})
        c = e.get("completed")
        flags = ",".join(k for k in ("x4", "x6") if e.get(k))
        if c is None:
            missing += 1
        print("%-3s %-60s %s%s" % ({True: "yes", False: "no", None: "?"}[c], rid, r.get("status"), "  [" + flags + "]" if flags else ""))
    print("%d run(s) without a completion statement" % missing)
    sys.exit(0)

c = campaign
if not c:
    c = os.path.realpath(os.path.join(dirs[0], "..", "..", ".."))
if not os.path.exists(os.path.join(c, "manifest.json")):
    die("no manifest.json in %s: is that the campaign directory? (--campaign DIR)" % c)
path = os.path.join(c, "annotations.json")
doc = load(path, {})
if not isinstance(doc, dict):
    die(path + " is not a JSON object")
runs = doc.setdefault("runs", {})
for d in dirs:
    if not os.path.isdir(d):
        die("no run directory " + d)
    rid = ident(c, d)
    e = runs.get(rid) or {}
    taken = set()
    if completed:
        e["completed"] = completed == "yes"
        taken.add("completed")
    if x4:
        e["x4"] = x4
        taken.add("x4")
    if intervened:
        e["x6"] = note or "the operator intervened"
        taken.add("x6")
    if note:
        notes = e.setdefault("notes", [])
        if note not in notes:
            notes.append(note)
    auto = [k for k in e.get("auto", []) if k not in taken]
    if auto:
        e["auto"] = auto
    else:
        e.pop("auto", None)
    runs[rid] = e
    print("%s: %s" % (rid, json.dumps({k: v for k, v in e.items() if k != "auto"}, sort_keys=True)))
write(path, doc)
PY
