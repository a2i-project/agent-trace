#!/usr/bin/env python3
"""Read an agent's profile from config/agents.json for the capture scripts.

The profile (schema 2) says how an agent is found, version-checked, locked,
pinned, isolated, invoked and recorded; scripts/capture-agent.sh and
scripts/capture-campaign.sh read it here and never name an agent. A method
name (tool set, session, trace, content) maps to code in those scripts that
does not know which agent uses it; this helper refuses a name the scripts do
not implement.

  agent-profile.py shell CONFIG AGENT TASK   shell assignments (p_*), for eval;
                                             AGENT '' is the default_agent
  agent-profile.py agents CONFIG             the agents, one per line
  agent-profile.py campaign-tasks CONFIG     AGENT<TAB>TASK... per agent
  agent-profile.py get CONFIG AGENT KEY...   one value (a list joined by spaces)
  agent-profile.py setting FILE KEY VALUE    exit 0 when FILE, JSON, holds
                                             KEY (dotted) as VALUE, else 1

Exit status 2 is a usage error (an unknown agent or task), 1 a profile the
scripts cannot use.
"""
import fnmatch
import json
import re
import shlex
import sys

SCHEMA = 2
# The methods the capture scripts implement.
TOOL_SETS = {"list", "agent-md", "none"}
SESSIONS = {"assigned", "stdout-json"}
TRACES = {"jsonl-session", "sqlite-conversation", "jsonl-rollout", "sqlite-sessions"}
# A declared trace is checked after the run (missing, empty, damaged or
# read); only these trace methods have that check.
STATE_CHECKED = {"jsonl-session", "jsonl-rollout", "sqlite-conversation", "sqlite-sessions"}
# Placeholders of an invocation besides the profile's params: each stands for
# a whole word.
PLACEHOLDERS = {"{isolation}", "{model}", "{tool_set}", "{session}", "{prompt}"}
# Placeholders filled inside a word, from the profile's model record.
INLINE = {"{effort}": "effort", "{catalog}": "catalog"}
STDIN = {"inherit", "null"}
# The key names scripts/pty-drive.py maps to the bytes a terminal sends
# (its KEYS; a test keeps the two equal).
DRIVER_KEYS = {"enter", "tab", "space", "escape", "backspace", "up", "down", "right", "left", "ctrl-c", "ctrl-d"}
# The trace methods whose transcript scripts/pty-drive.py counts turns in.
DRIVER_TRACES = {"jsonl-session"}
ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def fail(msg, code=1):
    print(msg, file=sys.stderr)
    sys.exit(code)


def load(path):
    try:
        with open(path, encoding="utf-8") as f:
            c = json.load(f)
    except (OSError, ValueError) as e:
        fail(f"could not read {path}: {e}")
    if c.get("schema") != SCHEMA:
        fail(f"{path}: schema {c.get('schema')}, the capture scripts read {SCHEMA}")
    return c


def either(names):
    names = list(names)
    return names[0] if len(names) == 1 else ", ".join(names[:-1]) + " or " + names[-1]


def profile(c, path, agent):
    adapters = c.get("adapters") or {}
    if agent not in adapters:
        fail(f"unknown agent {agent} ({either(sorted(adapters))})", 2)
    return adapters[agent]


def param(values, task):
    """A per-task parameter: the task's own key, else a matching pattern, else '*'."""
    if not isinstance(values, dict):
        return str(values)
    if task in values:
        return values[task]
    for k, v in values.items():
        if k not in ("*", "note") and fnmatch.fnmatchcase(task, k):
            return v
    return values.get("*", "")


def sh(name, value):
    if isinstance(value, list):
        return f"{name}=(" + " ".join(shlex.quote(str(v)) for v in value) + ")"
    if isinstance(value, bool):
        value = "1" if value else ""
    return f"{name}={shlex.quote('' if value is None else str(value))}"


def shell(path, agent, task):
    c = load(path)
    agent = agent or c.get("default_agent") or fail(f"{path}: no --agent given and no default_agent", 2)
    p = profile(c, path, agent)
    where = f"{path}: profile of {agent}"
    tasks = p.get("tasks") or {}
    builtin = task in tasks
    if not builtin and not task.startswith("heldout:"):
        fail(f"unknown task {task} for {agent} ({either(list(tasks) + ['heldout:NAME'])})", 2)
    out = []
    put = lambda k, v: out.append(sh(k, v))

    put("p_agent", agent)
    put("p_binary", p.get("binary") or fail(f"{where}: no binary"))
    vc = p.get("version_command") or {}
    put("p_version_args", vc.get("args") or ["--version"])
    field = vc.get("field", "first")
    if field not in ("first", "last"):
        fail(f"{where}: version_command.field {field!r} (first or last)")
    put("p_version_field", field)

    lock = p.get("version_lock") or {}
    env = lock.get("env") or {}
    put("p_lock_env", [f"{k}={v}" for k, v in env.items()])
    req = lock.get("require_setting")
    put("p_require", bool(req))
    req = req or {}
    for k in ("dir_env", "dir", "file", "key", "value", "why"):
        put("p_require_" + k, req.get(k, ""))
    pe = p.get("pass_env") or {}
    put("p_pass_env", pe.get("names") or [])
    put("p_pass_env_why", pe.get("why", ""))
    # The names that apply only when the agent runs as the operator (I-150):
    # a run as another user gets none of them, and is not refused for them.
    oo = pe.get("operator_only") or []
    if not isinstance(oo, list) or any(n not in (pe.get("names") or []) for n in oo):
        fail(f"{where}: pass_env.operator_only must list names of pass_env.names")
    put("p_pass_env_operator_only", oo)
    put("p_pass_env_operator_only_why", pe.get("operator_only_why", ""))
    # Secret environment (a model provider's key): the names only; the
    # values reach the agent through its stdin, never a command line, so
    # the agent's stdin must otherwise be /dev/null.
    se = p.get("secret_env") or {}
    names = se.get("names") or []
    for n in names:
        if not isinstance(n, str) or not ENV_NAME.match(n):
            fail(f"{where}: secret_env name {n!r} is not an environment variable name")
    if names and p.get("stdin", "inherit") != "null":
        fail(f"{where}: secret_env passes its values on the agent's stdin, so the profile's stdin must be null")
    put("p_secret_env", names)
    names_secret = list(names)
    put("p_secret_env_why", se.get("why", ""))

    model = p.get("model") or {}
    put("p_model_default", model.get("default") or fail(f"{where}: no model.default"))
    put("p_model_effort", model.get("effort", ""))
    cat = model.get("catalog") or {}
    if cat and not (isinstance(cat, dict) and cat.get("path") and cat.get("sha256")):
        fail(f"{where}: model.catalog needs a path and a sha256")
    for k in ("path", "sha256", "override_env", "cache"):
        put("p_model_catalog_" + k, cat.get(k, ""))
    iso = p.get("isolation") or {}
    put("p_isolation", iso.get("flags") or [])
    put("p_isolation_env", iso.get("override_env", ""))
    put("p_isolation_setenv", [f"{k}={v}" for k, v in (iso.get("env") or {}).items()])
    # The agent's own configuration file, agent-trace's and outside the
    # repository: its content is the profile's, its path is passed in an
    # environment variable.
    cf = p.get("config_file") or {}
    if cf and not (cf.get("path") and cf.get("env") and isinstance(cf.get("content"), dict)):
        fail(f"{where}: config_file needs a path, an env and a content object")
    if cf and not ENV_NAME.match(cf["env"]):
        fail(f"{where}: config_file.env {cf['env']!r} is not an environment variable name")
    put("p_config_file_path", cf.get("path", ""))
    put("p_config_file_env", cf.get("env", ""))
    put("p_config_file_content", json.dumps(cf["content"], indent=2) + "\n" if cf else "")
    put("p_instruction_files", (p.get("instruction_files") or {}).get("paths") or [])

    ts = p.get("tool_set") or {}
    if ts.get("method") not in TOOL_SETS:
        fail(f"{where}: tool_set method {ts.get('method')!r} is not implemented ({either(sorted(TOOL_SETS))})")
    put("p_tool_set_method", ts["method"])
    put("p_tool_set_name", ts.get("name", ""))
    put("p_tool_set_dir", ts.get("dir", ""))
    if ts["method"] == "none" and "{tool_set}" in (p.get("invocation") or []):
        fail(f"{where}: tool_set method none passes no tool set, so the invocation cannot name {{tool_set}}")
    ses = p.get("session") or {}
    if ses.get("method") not in SESSIONS:
        fail(f"{where}: session method {ses.get('method')!r} is not implemented ({either(sorted(SESSIONS))})")
    put("p_session_method", ses["method"])
    put("p_session_key", ses.get("key", ""))

    params = p.get("params") or {}
    inv = p.get("invocation") or fail(f"{where}: no invocation")
    names = []
    for w in inv:
        if w.startswith("{") and w.endswith("}") and w not in PLACEHOLDERS:
            if w[1:-1] not in params:
                fail(f"{where}: invocation placeholder {w} is neither one of {', '.join(sorted(PLACEHOLDERS))} nor a param")
            names.append(w[1:-1])
    for w in inv:
        for ph in re.findall(r"\{[A-Za-z0-9_-]+\}", w):
            if w == ph:
                continue
            if ph not in INLINE:
                fail(f"{where}: invocation word {w!r} holds {ph}; inside a word only {', '.join(sorted(INLINE))} are filled")
            if not model.get(INLINE[ph]):
                fail(f"{where}: invocation word {w!r} holds {ph}, and the profile has no model.{INLINE[ph]}")
    stdin = p.get("stdin", "inherit")
    if stdin not in STDIN:
        fail(f"{where}: stdin {stdin!r} ({either(sorted(STDIN))})")
    put("p_stdin", stdin)
    put("p_invocation", inv)
    # The interactive invocation (I-159): the agent started for an operator
    # who types into it on the terminal, for --interactive's task run. The
    # operator gives the prompts, so it names no {prompt}; the capture gives
    # the session its id, since what the agent prints reaches the terminal
    # and not the script; and the terminal is the agent's stdin, which a
    # secret cannot then travel on.
    ia = p.get("interactive") or {}
    iinv = ia.get("invocation") or []
    if ia and not iinv:
        fail(f"{where}: interactive needs an invocation")
    for w in iinv:
        if w == "{prompt}":
            fail(f"{where}: interactive.invocation names {{prompt}}; the operator types the prompts")
        if w.startswith("{") and w.endswith("}") and w not in PLACEHOLDERS and w not in inv:
            fail(f"{where}: interactive.invocation placeholder {w} is neither one of {', '.join(sorted(PLACEHOLDERS))} nor a param the invocation names")
        for ph in re.findall(r"\{[A-Za-z0-9_-]+\}", w):
            if w != ph and (ph not in INLINE or not model.get(INLINE[ph])):
                fail(f"{where}: interactive.invocation word {w!r} holds {ph}, which is not filled inside a word for this profile")
    if iinv and ses.get("method") != "assigned":
        fail(f"{where}: interactive needs the session method assigned; the agent's output goes to the terminal, where the capture cannot read an id")
    if iinv and names_secret:
        fail(f"{where}: interactive cannot pass secret_env, whose values travel on the agent's stdin, the operator's terminal in an interactive run")
    put("p_interactive_invocation", iinv)
    put("p_interactive_note", ia.get("note", ""))
    # The driver of the interactive controls (I-162): the dialogs to answer
    # (a screen marker and key names), the ready screen's markers, the exit
    # command and the controls' prompts, the first of which is the capture's
    # control prompt, {control_prompt}, so that its command stays excluded
    # from the baseline. scripts/pty-drive.py counts the turns in the
    # transcript, which only a jsonl-session trace gives it.
    drv = ia.get("driver") or {}
    if drv:
        if not isinstance(drv, dict):
            fail(f"{where}: interactive.driver must be an object")
        if (p.get("trace") or {}).get("method") not in DRIVER_TRACES:
            fail(f"{where}: interactive.driver needs a trace method whose turns the driver counts ({either(sorted(DRIVER_TRACES))})")
        dialogs = drv.get("dialogs") or []
        if not isinstance(dialogs, list):
            fail(f"{where}: interactive.driver.dialogs must be a list")
        for d in dialogs:
            keys = d.get("keys") if isinstance(d, dict) else None
            if not (isinstance(d, dict) and isinstance(d.get("marker"), str) and d["marker"].strip() and isinstance(keys, list) and keys):
                fail(f"{where}: an interactive.driver dialog needs a marker and a list of keys")
            bad = [k for k in keys if k not in DRIVER_KEYS]
            if bad:
                fail(f"{where}: interactive.driver dialog {d['marker']!r} names unknown key(s) {', '.join(map(str, bad))} ({either(sorted(DRIVER_KEYS))})")
        ready = drv.get("ready")
        if not (isinstance(ready, list) and ready and all(isinstance(m, str) and m.strip() for m in ready)):
            fail(f"{where}: interactive.driver.ready must list the ready screen's markers")
        # The exit: key names sent one by one (exit_keys), or a typed
        # command (exit), exactly one of them.
        ex, exk = drv.get("exit"), drv.get("exit_keys")
        if (ex is None) == (exk is None):
            fail(f"{where}: interactive.driver needs exactly one of exit (a typed command) and exit_keys (key names)")
        if ex is not None and not (isinstance(ex, str) and ex.strip()):
            fail(f"{where}: interactive.driver.exit must be a command")
        if exk is not None:
            if not (isinstance(exk, list) and exk):
                fail(f"{where}: interactive.driver.exit_keys must list key names")
            bad = [k for k in exk if k not in DRIVER_KEYS]
            if bad:
                fail(f"{where}: interactive.driver.exit_keys names unknown key(s) {', '.join(map(str, bad))} ({either(sorted(DRIVER_KEYS))})")
        prompts = drv.get("prompts")
        if not (isinstance(prompts, list) and prompts and all(isinstance(x, str) and x.strip() for x in prompts)):
            fail(f"{where}: interactive.driver.prompts must list the controls' prompts")
        if prompts[0] != "{control_prompt}" or "{control_prompt}" in prompts[1:]:
            fail(f"{where}: interactive.driver.prompts must start with {{control_prompt}}, the capture's control prompt, and name it once")
        put("p_driver", True)
        put("p_driver_dialog_markers", [d["marker"] for d in dialogs])
        put("p_driver_dialog_keys", [" ".join(d["keys"]) for d in dialogs])
        put("p_driver_ready", ready)
        put("p_driver_exit", ex or "")
        put("p_driver_exit_keys", " ".join(exk or []))
        put("p_driver_prompts", prompts)
    else:
        put("p_driver", False)
        for k in ("dialog_markers", "dialog_keys", "ready", "prompts"):
            put("p_driver_" + k, [])
        put("p_driver_exit", "")
        put("p_driver_exit_keys", "")
    put("p_params", names)
    for n in names:
        put("p_param_" + n.replace("-", "_"), param(params[n], task))

    tr = p.get("trace") or {}
    if tr.get("method") not in TRACES:
        fail(f"{where}: trace method {tr.get('method')!r} is not implemented ({either(sorted(TRACES))})")
    if tr.get("declared") and tr["method"] not in STATE_CHECKED:
        fail(f"{where}: a declared trace needs a trace method with a state check ({either(sorted(STATE_CHECKED))})")
    if tr.get("method") == "sqlite-sessions" and not tr.get("database"):
        fail(f"{where}: trace method sqlite-sessions needs trace.database, the database file in trace.dir")
    for k in ("method", "dir", "file", "subagents", "snapshots", "database"):
        put("p_trace_" + k, tr.get(k, ""))
    if tr.get("databases") and "{label}" not in tr.get("snapshots", ""):
        fail(f"{where}: trace.databases needs trace.snapshots, the directory of their copies with {{label}}")
    put("p_trace_databases", tr.get("databases") or [])
    put("p_trace_declared", bool(tr.get("declared")))
    put("p_trace_states_version", bool(tr.get("states_version")))

    content = p.get("content") or [{"method": "none", "reason": "its profile names no content method"}]
    methods = [m.get("method", "") for m in content]
    put("p_content_method", "+".join(methods))
    first = content[0]
    put("p_content_library", first.get("library", ""))
    put("p_content_parser", first.get("parser", ""))
    put("p_content_reason", first.get("reason", ""))
    # Every method, for a profile that names several (N-39), in order.
    put("p_content_methods", methods)
    put("p_content_libraries", [m.get("library", "") for m in content])
    put("p_content_parsers", [m.get("parser", "") for m in content])

    ctl = p.get("controls") or {}
    for k in ("command_tool", "subagent_tool", "prompt"):
        if not ctl.get(k):
            fail(f"{where}: no controls.{k}")
    put("p_command_tool", ctl["command_tool"])
    put("p_subagent_tool", ctl["subagent_tool"])
    put("p_control_prompt", ctl["prompt"])
    put("p_control_prompt_subagent", ctl.get("prompt_subagent") or ctl["prompt"])
    # The control edit (I-88): a profile whose harness reacts to an edit
    # names the edit tool, and every control prompt of the profile names
    # the file, {file}, the controls create with it; no other profile's
    # prompt may name it.
    edit_tool = ctl.get("edit_tool", "")
    put("p_edit_tool", edit_tool)
    prompts = [("controls.prompt", ctl["prompt"]), ("controls.prompt_subagent", ctl.get("prompt_subagent"))]
    prompts += [(f"tasks.{n}.control_prompt", d.get("control_prompt")) for n, d in sorted(tasks.items())]
    for name, text in prompts:
        if not text:
            continue
        if edit_tool and "{file}" not in text:
            fail(f"{where}: controls.edit_tool is {edit_tool}, and {name} does not name the file the controls edit ({{file}})")
        if not edit_tool and "{file}" in text:
            fail(f"{where}: {name} names {{file}}, and the profile has no controls.edit_tool")

    # The warm-up (I-151): one run of the profile's invocation with this
    # prompt, outside watch, before a capture's first recorded run; its
    # tools, for a tool set method that passes some, else the task's.
    wu = p.get("warm_up") or {}
    if wu and not (isinstance(wu.get("prompt"), str) and wu["prompt"].strip()):
        fail(f"{where}: warm_up needs a prompt")
    if wu.get("tools") is not None and not isinstance(wu["tools"], str):
        fail(f"{where}: warm_up.tools is the tools separated by spaces, as a task's")
    put("p_warm_up_prompt", wu.get("prompt", ""))
    put("p_warm_up_tools", wu.get("tools", ""))

    t = tasks.get(task) or {}
    put("p_task_builtin", builtin)
    put("p_task_prompt", t.get("prompt", ""))
    put("p_task_tools", t.get("tools", ""))
    put("p_task_control_prompt", t.get("control_prompt", ""))

    u = c.get("unrecorded") or {}
    put("p_unrecorded_agent", u.get("agent", ""))
    put("p_unrecorded_control_tools", u.get("control_tools", ""))
    put("p_unrecorded_control_prompt", u.get("control_prompt", ""))
    print("\n".join(out))


def get(path, agent, keys):
    v = profile(load(path), path, agent)
    for k in keys:
        if isinstance(v, list):
            v = v[int(k)] if k.lstrip("-").isdigit() and -len(v) <= int(k) < len(v) else None
        elif isinstance(v, dict):
            v = v.get(k)
        else:
            v = None
        if v is None:
            print("")
            return
    if isinstance(v, list):
        v = " ".join(str(x) for x in v)
    elif isinstance(v, bool):
        v = "1" if v else ""
    print(v)


def setting(path, key, want):
    try:
        with open(path, encoding="utf-8") as f:
            v = json.load(f)
        parts = key.split(".")
        for k in parts[:-1]:
            v = v.get(k, {})
        v = v.get(parts[-1])
    except (OSError, ValueError, AttributeError):
        sys.exit(1)
    sys.exit(0 if str(v) == want else 1)


def main(argv):
    if len(argv) >= 4 and argv[0] == "shell":
        shell(argv[1], argv[2], argv[3])
    elif len(argv) == 2 and argv[0] == "agents":
        print("\n".join(sorted((load(argv[1]).get("adapters") or {}))))
    elif len(argv) == 2 and argv[0] == "campaign-tasks":
        for name, p in sorted((load(argv[1]).get("adapters") or {}).items()):
            tasks = [t for t, d in (p.get("tasks") or {}).items() if d.get("campaign", True)]
            print(name + "\t" + " ".join(tasks))
    elif len(argv) >= 4 and argv[0] == "get":
        get(argv[1], argv[2], argv[3:])
    elif len(argv) == 4 and argv[0] == "setting":
        setting(argv[1], argv[2], argv[3])
    else:
        fail(__doc__.split("\n\n")[2], 2)


if __name__ == "__main__":
    main(sys.argv[1:])
