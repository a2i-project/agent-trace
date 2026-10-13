#!/usr/bin/env python3
"""Reduce a capture made by capture-claude-code.sh to a checked-in fixture.

A capture of Gemini (--agent gemini) is recognised by its
<TASK_LABEL>.conversation.db and reduced as described at the end.

A raw capture holds the account's email and organisation id, system prompts, the
user's home directory and a multi-kilobyte shell snapshot script in every run.
The fixture keeps what the adapter and verifier read and rewrites the rest:

  * the task transcript is cut to the records that carry tool calls and results,
    and each is cut to the fields the adapter reads: a result's text only for
    a Write whose text starts with the create or update sentence (I-35),
    is_error when set, an Edit's and a NotebookEdit's structured result (I-31,
    I-37), a Read's structured result (I-40, below), and any other structured
    result's type. A call's input is kept whole, so a Read's offset and limit
    stay;
  * a Read's structured result keeps type, file.filePath, file.startLine,
    file.numLines, file.totalLines and file.truncatedByTokenCap, so the
    adapter decides as on the raw capture whether the Read was of the whole
    file (I-40). file.content, whose sha256 the adapter claims as the open's
    input hash, is kept only when the file read lies in the run's workspace or
    in the harness's per-session task directory of that workspace
    (/tmp/claude-<uid>/<mangled workspace>/<session>/tasks/, where a background
    command's output goes), and only when it holds nothing the rewriting below
    would change and no e-mail address. Any other content is dropped, so the
    adapter claims no hash for that Read. Kept content is never rewritten: the
    probe's measured hash is of the bytes as read, and a rewritten text would
    no longer match it. A private string inside content therefore drops the
    content rather than rewriting it;
  * each run's workspace becomes /ws/<label> and the capture directory
    /capture, both as paths and in the form Claude Code names its per-project
    directories with (every character but a letter or digit a dash), so the
    baseline's workspace placeholders are exercised; the home directory
    becomes /home/user;
  * a capture may have been moved after it was recorded. The directory it was
    recorded in is read from each run's ground truth (its workspace is
    <recorded directory>/ws-<label>), must be the same for every run, and is
    rewritten together with the directory the capture is in now;
  * the snapshot-creation command keeps its first line, with its per-run id
    intact, and loses the script body. The body differs with the enabled tool
    set, so a reduced fixture cannot show that a baseline is tied to one;
  * the account's organisation id, which the harness uses in cache paths such as
    ~/.claude/cache/model-catalog/<id>-0, becomes the zero UUID wherever it
    appears. The ids are read from the capture's own transcripts;
  * the 64-digit hex in a session key file's name,
    ~/.claude/sessions/<pid>.<hex>.key, becomes zeros. The key itself is the
    file's content, which no capture holds, but the name is per session.

Before it finishes, the script checks every file it wrote, kept Read content
included, for the home directory, the user name, the organisation ids, every
e-mail address found in the raw transcripts, the recorded and the current
capture directory in either form, and any session key name left unrewritten,
and deletes its output and fails if one is left.

Ground truth events, pids, timestamps and coverage are kept as captured.

    scripts/make-capture-fixture.py CAPTURE_DIR OUTPUT_DIR [TASK_LABEL]

TASK_LABEL is the task run's label (basic captures use `task`, which is the
default; the parallel task uses `parallel`). Subagent transcripts, when the
capture has them, are reduced the same way.

A Gemini capture's ground truth is rewritten as above. Its conversation
database holds the system prompt, the model's thinking, every tool result and
opaque signatures; it is read from a copy of the database and of its
write-ahead log, when there is one, so that nothing is written beside the
capture and steps only the log holds are kept (I-51). The fixture is a new SQLite database with only the steps
table's columns the adapter reads (idx, step_type, status, has_subtrajectory,
step_payload), and each payload cut to the fields the adapter reads: the step
type (1), field 4, and of field 5 the created (5.1), started (5.6) and
completed (5.8) timestamps and the tool calls (5.4), each cut to its id (1),
name (2) and JSON arguments (3), rewritten like every other path. A call
whose CodeContent the rewriting would change is refused rather than altered,
since the adapter claims the hash of that content. The private-string check
reads the written database's bytes.
"""
import json
import os
import re
import shutil
import sqlite3
import sys
import tempfile

capture, out = os.path.abspath(sys.argv[1]).rstrip("/"), sys.argv[2]
task = sys.argv[3] if len(sys.argv) > 3 else "task"
home = os.path.expanduser("~")
# Every control run the capture holds (the capture script takes five by default).
labels = [task] + sorted(
    os.path.basename(f)[: -len(".ground_truth.json")]
    for f in os.listdir(capture)
    if f.startswith("control-") and f.endswith(".ground_truth.json")
)

# The account's organisation ids and e-mail addresses, as the raw transcripts
# state them. They are private and must not reach a checked-in file.
# Subagent transcripts included: their result texts are kept too.
org_ids, emails = set(), set()
for root, _, files in os.walk(capture):
    for name in (n for n in files if n.endswith(".jsonl")):
        with open(os.path.join(root, name), errors="replace") as f:
            text = f.read()
        org_ids.update(re.findall(r'"organizationUuid":\s*"([0-9a-fA-F-]{36})"', text))
        emails.update(re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text))
# A Gemini conversation database states the account nowhere the adapter
# reads, but its bytes are checked for addresses all the same.
gemini_db = os.path.join(capture, task + ".conversation.db")
for root, _, files in os.walk(capture):
    for name in (n for n in files if n.endswith((".conversation.db", ".conversation.db-wal"))):
        with open(os.path.join(root, name), "rb") as f:
            emails.update(m.decode() for m in re.findall(rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", f.read()))
# Addresses that are part of the harness's own text, not the account.
emails = {e for e in emails if not e.endswith("@anthropic.com") and not e.endswith("@example.com")}
ZERO_UUID = "00000000-0000-0000-0000-000000000000"


def mangle(path):
    """A path as Claude Code spells it in a directory name, such as
    ~/.claude/projects/<mangled workspace>."""
    return re.sub(r"[^A-Za-z0-9]", "-", path)


# The directory the capture was recorded in. watch writes each run's workspace,
# <recorded directory>/ws-<label>, into its ground truth; every run must agree,
# or the paths inside cannot be rewritten reliably.
recorded = set()
for label in labels:
    with open(os.path.join(capture, label + ".ground_truth.json")) as f:
        ws = json.load(f).get("workspace") or ""
    suffix = "/ws-" + label
    if not ws.startswith("/") or not ws.endswith(suffix) or len(ws) <= len(suffix) + 1:
        sys.exit("%s.ground_truth.json: workspace %r is not <directory>/ws-%s" % (label, ws, label))
    recorded.add(ws[: -len(suffix)])
if len(recorded) != 1:
    sys.exit("the runs were recorded in different directories: " + ", ".join(sorted(recorded)))
recorded = recorded.pop()
# Longest first, so a directory inside another is rewritten before it.
roots = sorted({recorded, capture}, key=len, reverse=True)
if recorded != capture:
    print("capture recorded in", recorded, "and now in", capture)
os.makedirs(out, exist_ok=True)
SESSION_KEY = re.compile(r"(/\.claude/sessions/\d+\.)[0-9a-f]{64}")
ZERO_KEY = "0" * 64


def rewrite(s, label):
    for root in roots:
        ws = root + "/ws-" + label
        s = s.replace(ws, "/ws/" + label).replace(mangle(ws), mangle("/ws/" + label))
    for root in roots:
        s = s.replace(root, "/capture").replace(mangle(root), mangle("/capture"))
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

# What a Write's result says, as the adapter reads it (I-35).
WRITE_TEXTS = ("File created successfully at: ", "The file ")
# A NotebookEdit's structured result, as the adapter reads it (I-37), with the
# call's own fields beside it. The seeded notebook is not private.
NOTEBOOK_FIELDS = ("notebook_path", "original_file", "updated_file", "error", "edit_mode", "cell_id", "new_source", "old_source")
# A Read's structured result, as the adapter reads it (I-40). content is
# handled apart, by read_content.
READ_FILE_FIELDS = ("filePath", "startLine", "numLines", "totalLines", "truncatedByTokenCap")
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def readable(path):
    """Whether a Read of path may keep its content: a file in the task run's
    workspace, or in the harness's per-session task directory of that
    workspace, both as recorded."""
    if not isinstance(path, str) or not path.startswith("/") or os.path.normpath(path) != path:
        return False
    for root in roots:
        ws = root + "/ws-" + task
        if path.startswith(ws + "/"):
            return True
        if re.fullmatch(r"/tmp/claude-\d+/" + re.escape(mangle(ws)) + r"/[0-9a-f-]+/tasks/[^/]+", path):
            return True
    return False


def read_content(file, call_input):
    """The content of a Read's result to keep, or None to drop it."""
    content = file.get("content")
    if not isinstance(content, str) or not readable(file.get("filePath")):
        return None
    if isinstance(call_input, dict) and call_input.get("file_path") != file.get("filePath"):
        return None
    if rewrite(content, task) != content or EMAIL.search(content):
        return None
    return content


def result_text(content):
    """A tool_result's text: the string, or its text blocks joined."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text")
    return ""


BASH_FIELDS = ("interrupted", "isImage", "backgroundTaskId", "returnCodeInterpretation")


def reduce_transcript(src, dst):
    kept = []
    names = {}  # tool_use id -> tool name, from the calls read so far
    inputs = {}  # tool_use id -> the call's input
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
                    names[b["id"]] = b["name"]
                    inputs[b["id"]] = b["input"]
                    slim.append({"type": "tool_use", "id": b["id"], "name": b["name"], "input": b["input"]})
                else:
                    text = result_text(b.get("content"))
                    if names.get(b["tool_use_id"]) != "Write" or not text.startswith(WRITE_TEXTS):
                        text = "(elided)"
                    r = {"type": "tool_result", "tool_use_id": b["tool_use_id"], "content": text}
                    if b.get("is_error") is True:
                        r["is_error"] = True
                    slim.append(r)
            rec = {"type": o["type"], "timestamp": o["timestamp"], "sessionId": "00000000-0000-0000-0000-000000000000",
                   "version": o.get("version", ""), "message": {"id": m.get("id", ""), "role": m.get("role", ""), "content": slim}}
            if o.get("isSidechain"):
                rec["isSidechain"] = True
            # The session's working directory, against which the adapter
            # resolves the file a Bash read command names (I-46); rewritten
            # like every other path below.
            if isinstance(o.get("cwd"), str):
                rec["cwd"] = o["cwd"]
            tr = o.get("toolUseResult")
            results = [b for b in blocks if b["type"] == "tool_result"]
            read_id = results[0]["tool_use_id"] if len(results) == 1 and names.get(results[0]["tool_use_id"]) == "Read" else None
            content = None
            if isinstance(tr, dict) and "notebook_path" in tr:
                rec["toolUseResult"] = {k: tr[k] for k in NOTEBOOK_FIELDS if k in tr}
            elif isinstance(tr, dict) and "type" in tr:
                rec["toolUseResult"] = {"type": tr["type"]}
                if read_id and isinstance(tr.get("file"), dict):
                    rec["toolUseResult"]["file"] = {k: tr["file"][k] for k in READ_FILE_FIELDS if k in tr["file"]}
                    content = read_content(tr["file"], inputs.get(read_id))
            elif isinstance(tr, dict) and "originalFile" in tr:
                # An Edit's result: the adapter computes the final content from
                # these (I-31). The seeded project's files are not private.
                rec["toolUseResult"] = {k: tr[k] for k in ("originalFile", "oldString", "newString", "replaceAll") if k in tr}
            elif isinstance(tr, dict) and len(results) == 1 and names.get(results[0]["tool_use_id"]) == "Bash":
                # The states in which the harness does not read the file a Bash
                # read command names (I-46); the output itself stays out.
                rec["toolUseResult"] = {k: tr[k] for k in BASH_FIELDS if k in tr}
            elif tr is not None:
                rec["toolUseResult"] = {}
            rec = json.loads(rewrite(json.dumps(rec), task))
            # Kept content goes in after the rewriting, which must not touch it.
            if content is not None:
                rec["toolUseResult"]["file"]["content"] = content
            kept.append(rec)
    os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)
    with open(dst, "w") as f:
        for r in kept:
            f.write(json.dumps(r) + "\n")
    return len(kept)


# --- Gemini: the conversation database (see the docstring) ---


def pb_varint(b, i):
    v, shift = 0, 0
    while True:
        if i >= len(b) or shift > 63:
            raise ValueError("truncated varint")
        c = b[i]
        i += 1
        v |= (c & 0x7F) << shift
        shift += 7
        if c < 0x80:
            return v, i


def pb_fields(b):
    """Every top-level field of a protobuf message as (number, wire type, value)."""
    out, i = [], 0
    while i < len(b):
        key, i = pb_varint(b, i)
        num, wt = key >> 3, key & 7
        if num == 0:
            raise ValueError("field number 0")
        if wt == 0:
            v, i = pb_varint(b, i)
        elif wt == 1:
            v, i = b[i:i + 8], i + 8
        elif wt == 5:
            v, i = b[i:i + 4], i + 4
        elif wt == 2:
            n, i = pb_varint(b, i)
            v, i = b[i:i + n], i + n
            if i > len(b):
                raise ValueError("length past the end")
        else:
            raise ValueError("unsupported wire type %d" % wt)
        out.append((num, wt, v))
    return out


def pb_enc_varint(v):
    b = bytearray()
    while v >= 0x80:
        b.append((v & 0x7F) | 0x80)
        v >>= 7
    b.append(v)
    return bytes(b)


def pb_field(num, wt, v):
    if wt == 0:
        return pb_enc_varint(num << 3) + pb_enc_varint(v)
    if wt == 2:
        return pb_enc_varint(num << 3 | 2) + pb_enc_varint(len(v)) + v
    return pb_enc_varint(num << 3 | wt) + v


def reduce_call(call):
    kept = b""
    for num, wt, v in pb_fields(call):
        if num == 3 and wt == 2:
            args = json.loads(v)
            code = args.get("CodeContent")
            if isinstance(code, str) and rewrite(code, task) != code:
                sys.exit("a write_to_file's CodeContent holds a private path; refusing to alter the content its hash is claimed from")
            v = rewrite(json.dumps(args), task).encode()
        if num in (1, 2, 3):
            kept += pb_field(num, wt, v)
    return kept


def reduce_payload(payload):
    kept = b""
    for num, wt, v in pb_fields(payload):
        if num in (1, 4) and wt == 0:
            kept += pb_field(num, wt, v)
        elif num == 5 and wt == 2:
            inner = b""
            for n5, w5, v5 in pb_fields(v):
                if n5 in (1, 6, 8) and w5 == 2:
                    inner += pb_field(n5, w5, v5)
                elif n5 == 4 and w5 == 2:
                    inner += pb_field(4, 2, reduce_call(v5))
            kept += pb_field(5, 2, inner)
    return kept


def reduce_conversation(src, dst):
    # Read a copy of the database and its write-ahead log, as the adapter does
    # (I-51): SQLite would otherwise create <db>-shm beside the capture.
    with tempfile.TemporaryDirectory() as tmp:
        snap = os.path.join(tmp, "conversation.db")
        shutil.copyfile(src, snap)
        if os.path.exists(src + "-wal"):
            shutil.copyfile(src + "-wal", snap + "-wal")
        con = sqlite3.connect("file:%s?mode=ro" % snap, uri=True)
        rows = con.execute("select idx, step_type, status, has_subtrajectory, step_payload from steps order by idx").fetchall()
        con.close()
    if os.path.exists(dst):
        os.remove(dst)
    new = sqlite3.connect(dst)
    new.execute("create table steps (idx integer, step_type integer not null default 0, status integer not null default 0, "
                "has_subtrajectory numeric not null default false, step_payload blob, primary key (idx))")
    for idx, typ, status, sub, payload in rows:
        new.execute("insert into steps values (?,?,?,?,?)", (idx, typ, status, sub, reduce_payload(payload or b"")))
    new.commit()
    new.execute("vacuum")
    new.close()
    return len(rows)


if os.path.exists(gemini_db):
    n = reduce_conversation(gemini_db, os.path.join(out, task + ".conversation.db"))
    record_kind = "conversation steps"
else:
    n = reduce_transcript(os.path.join(capture, task + ".session.jsonl"), os.path.join(out, task + ".session.jsonl"))
    record_kind = "transcript records"
sub = os.path.join(capture, task + ".session", "subagents")
if os.path.isdir(sub):
    for name in sorted(os.listdir(sub)):
        if name.endswith(".jsonl"):
            n += reduce_transcript(os.path.join(sub, name), os.path.join(out, task + ".session", "subagents", name))
# Nothing private may be left in what was written.
user = os.environ.get("USER", "")
forbidden = {home} | org_ids | emails | ({user} if len(user) > 2 else set())
# Every form of the recorded and the current capture directory must be gone.
forbidden |= set(roots) | {mangle(r) for r in roots}
leaks = []
for root, _, files in os.walk(out):
    for name in files:
        path = os.path.join(root, name)
        with open(path, "rb") as f:
            text = f.read().decode("utf-8", errors="replace")
        for word in forbidden:
            if word and word in text:
                leaks.append((path, word))
        if any(m.group(0)[-64:] != ZERO_KEY for m in SESSION_KEY.finditer(text)):
            leaks.append((path, "session key name"))
if leaks:
    for path, word in leaks:
        print("private string left in", path, file=sys.stderr)
    shutil.rmtree(out)
    sys.exit("refusing to keep the fixture: remove the leaks above and run again")
print("wrote", out, "with", n, record_kind + "; no private string found")
