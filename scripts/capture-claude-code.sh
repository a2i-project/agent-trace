#!/usr/bin/env bash
# Paired capture of an agent: the agent's own transcript (T) and the host's
# observation of the same run (G), recorded together under cmd/watch, plus the
# control runs a baseline is built from, and the verdict with and without it.
# The agent is Claude Code by default, or Gemini through Antigravity's CLI
# (agy) with --agent gemini; the Gemini tasks and what differs are described
# after the Claude Code ones.
#
# It runs the real agent, so it uses the account's model quota and needs root for
# the probes: run it yourself, it asks for sudo once.
#
#   scripts/capture-claude-code.sh [--agent claude-code|gemini] [--task TASK] [--baseline-from DIR]
#                                  [--model ID] [--controls-before N] [--heldout-dir DIR]
#                                  [--allow-unconfigured-version] [--content] [--check]
#                                  [--no-build] [OUTPUT_DIR]
#
# Claude Code tasks: basic, parallel, project, edits, tools, shapes, long, websearch.
# Gemini tasks: basic, search, long.
# Either agent also runs a held-out task, --task heldout:NAME with --heldout-dir DIR
# (below).
#
# --model ID pins the model of every run, controls included (D7): Claude Code
# gets --model ID (default claude-sonnet-5-5), agy gets --model ID (default
# gemini-3.8-flash-high, the id the existing captures recorded; `agy models`
# lists it with -medium and -low). After each run the script reads the model
# the transcript records (the model of every assistant message of a Claude Code
# transcript; the executor model of an agy conversation database) and stops
# with MODEL MISMATCH, exit 1, when it is not the pinned one, so a default the
# agent does not accept as that id fails the first run, not silently. The
# result of each check is in order.tsv.
# --controls-before N records N of the CONTROLS control runs before the task and
# the rest after it (D11; default 0, the task first); the order is written to
# control-order.txt and order.tsv. It cannot be combined with --baseline-from.
# For Claude Code the script refuses unless settings.json of the user
# ($CLAUDE_CONFIG_DIR or ~/.claude) sets env.DISABLE_UPDATES to "1" (D6), and it
# passes DISABLE_UPDATES=1 to every Claude Code run, since --setting-sources
# project, which the runs use, ignores the user's settings.
# --heldout-dir DIR holds held-out tasks (D8) outside the repository, one
# directory NAME each with prompt.txt, tools.txt (the task's tools, separated by
# white space) and an optional seed/ that every run starts from. The script
# refuses a DIR inside the repository, never copies it and never prints the
# prompt; task-meta.txt records the SHA-256 of the prompt and of the seed.
#
# --content turns on the net probe's content capture (watch --net-exe-path) on
# the Claude Code binary, which carries its own TLS library; every run,
# controls included, is recorded with it, since content events change what a
# baseline must explain. agy links no TLS library the probe can hook, so the
# script refuses --content with --agent gemini.
# --check validates everything the run depends on (the agent and its version,
# the task, the seed, --baseline-from, the locked directory test) and prints
# what the controls of this capture are, as key=value lines, then exits
# without creating OUTPUT_DIR, building or asking for sudo.
# --no-build skips `make build`, for a caller that has built already.
#
# Tasks (each fixed, so results compare across versions):
#   basic     Read, Write (create), Edit, Write (overwrite), Bash. Five calls.
#   project   a realistic coding task in a seeded workspace (scripts/seed/project, a
#             small Python package with a failing test): run the tests, find and fix
#             the bug, add a function and a command-line option with tests, update the
#             README, run the tests again. Dozens of tool calls over several files, so
#             it gives the evaluation far more claims than the others. No network.
#   parallel  three Reads in one message, a subagent that runs Bash, Grep, Glob,
#             WebFetch of https://example.com, and a Bash pipeline. It covers what
#             `basic` does not (parallel tool calls, subagents, searches), and needs the network.
#   edits     one Write and five Edits of different shapes on one file (first
#             occurrence with a duplicate present, replace_all, a multi-line
#             string, quotes and backslashes, an insertion at the end), then one
#             Bash call. It is the measurement of I-31: the adapter computes each
#             Edit's final content from the transcript and every claim must be
#             corroborated. No network.
#   tools     the tools and shapes the other tasks do not exercise, in a seeded
#             workspace (scripts/seed/tools: two text files and a two-cell
#             notebook): a background Bash (run_in_background) that writes a
#             file, three Reads in one message, two line changes in notes.txt
#             (with MultiEdit if the harness offers it, else two Edits), a
#             NotebookEdit of one cell, a Write that creates a file and one that
#             overwrites it, a subagent that writes a file with Write, a Read of
#             the background command's output file, and a final Bash. No network.
#             Its controls also run the no-op command a second time in the
#             background and start one subagent that only replies, so the
#             baseline covers what the harness does around a background command
#             and a subagent.
#   shapes    two shapes no other task produced, in a seeded workspace
#             (scripts/seed/shapes: three one-line files and locked/data.txt).
#             First a parallel block whose members should complete out of the
#             order the model emitted them: two read-only Bash calls, the first
#             of which sleeps two seconds before its cat, and a Read. Claude
#             Code 2.1.296 runs a read-only Bash call concurrently with the
#             calls around it. Then a block of two Bash calls that write files,
#             which that version runs one after the other, as a contrast. Then a
#             Read, a Write and an Edit of locked/data.txt in a directory the
#             user cannot write to, where the harness cannot create its
#             temporary file and rewrites the file in place, without a rename.
#             A closing Bash. No network. Every run, controls included, has the
#             write permission of locked/ removed while it runs, and the script
#             refuses before it asks for sudo when such a directory stays
#             writable (as for root). Its controls make the one Bash call.
#   long      a long coding session in a seeded workspace (scripts/seed/long, a
#             Python package of twenty stub functions, each with a
#             specification, a Makefile with a lint and a zip application
#             build): for each function in turn, Read its specification, Edit
#             the implementation in, Edit tests in, run that module's tests
#             with Bash and Edit a CHANGELOG line; a check of each module with
#             make and Grep; a subagent that runs the suite and Writes a
#             report; a build and two runs of the built application. About 120
#             tool calls by the prompt's count, more with fixes. No network.
#             Its controls make the one Bash call and start one subagent that
#             only replies, with the task's tool set (below).
#
# The adapters were verified on the agent versions config/agents.json lists
# (I-57; $AGENT_TRACE_CONFIG overrides the file). Before it asks for sudo, the
# script refuses an installed agent whose version is not listed, unless
# --allow-unconfigured-version is given: a capture of a new version is how it
# gets verified. The report's verify runs use --strict-version, so a capture
# of an unlisted version reads INCONCLUSIVE, naming the version, until its
# fixture verifies and the version is added to the file.
#
# By default the script also runs CONTROLS control runs and builds the baseline
# from them, with the same tools enabled as the task. With --baseline-from DIR it
# reuses the control runs already in DIR and runs only the task, which saves CONTROLS
# model calls; that is only valid for the SAME agent and version, the SAME
# tool set, the SAME control prompt and the SAME recording mode (--content or
# not), and the script refuses otherwise. The baseline is rebuilt with the
# current code.
#
# Everything lands in OUTPUT_DIR (default /tmp/agent-trace-capture-<time>):
#   <task>.session.jsonl      the transcript of the task run (T), and
#   <task>.session/subagents  its subagent transcripts, when there are any
#   <task>.ground_truth.json  what the probes saw during it (G)
#   <task>.trace.txt          Claude Code only: what the copied transcript holds, read, empty
#                             or damaged, or missing when the run left none; a task run whose
#                             transcript is gone is kept, and verify reports the trace as
#                             deleted or damaged (V-59, I-75)
#   control-N.*               the same for CONTROLS runs that claim nothing (one no-op Bash
#                             call; for a task whose tools include the subagent tool, also
#                             a subagent that only replies; for tools, also that call in
#                             the background)
#   control-tools.txt, control-prompt.txt  the tool set and prompt the controls ran with
#   control-agent.txt, control-version.txt, control-watch.txt  their agent, version
#                             and recording mode (identity or content)
#   control-model.txt, control-order.txt  their pinned model, and how many ran before
#                             and after the task (before=2 after=3)
#   task-meta.txt             the task, the SHA-256 of its prompt and seed, its tools, the model
#   order.tsv                 each run in the order it was recorded: number, label, role
#                             (task or control), start, end, the model check and the models
#                             the transcript recorded, watch's exit status, and the number of
#                             subagents the run started with the tool calls they made (for
#                             agy, the subagent databases copied, calls not counted: -)
#   <label>.cost.json         what scripts/measure-watch.py measured around that run's watch
#                             (start-up, drain, watch's CPU and peak RSS; H4b), and
#   <label>.watch.exit        watch's exit status (non-zero when the agent exited with an
#                             error or watch failed)
#   baseline.json             built from the control runs
#   report.txt                verify output, without and with the baseline
#   verify.json, verify-baseline.json  the same two verdicts as verify --json writes them
#
# CONTROLS (default 5) is how many control runs are recorded, and MIN_AGREEMENT
# (default 1/CONTROLS, so any one run) is passed to baseline: the fraction of
# control runs that must perform an action for it to count as the harness's. A
# control runs no task, so anything it did is the harness's; some of it is
# occasional (a backup of its configuration, a telemetry connection), which is
# why several controls are taken and one is enough (V-24). Raise MIN_AGREEMENT
# to keep only what every control did.
#
# Claude Code runs as you (setpriv execs it in place, so it keeps the pid watch
# records as the root of the process tree) with your credentials. If the CLI login
# has expired, run `claude auth login` first.
#
# With --agent gemini the agent is agy, Antigravity's CLI, run in print mode
# (agy -p) as you, the same way. What differs (I-47, I-48):
#   * the tool set is fixed by a custom agent, agent-trace, written into every
#     run's workspace as .agents/agents/agent-trace/agent.md: it lists the
#     task's tools and inherits neither your MCP servers nor your
#     customizations, and every run, controls included, is started with
#     --agent agent-trace, so the controls have the task's tool set (I-24);
#   * agy authenticates through the Secret Service on your D-Bus session bus,
#     so DBUS_SESSION_BUS_ADDRESS and XDG_RUNTIME_DIR are passed to it (the
#     script refuses without them), and AGY_CLI_DISABLE_AUTO_UPDATE=true keeps
#     its auto-updater from starting a process of its own during a run (the
#     value 1 does not, measured on 1.3.4);
#   * agy prints the conversation id (--output-format json), and the
#     conversation database ~/.gemini/antigravity-cli/conversations/<id>.db is
#     copied to <label>.conversation.db, which is the transcript verify reads;
#   * a subagent keeps its steps in a database of its own in the same
#     directory (I-55), so every other database that appeared there during
#     the run is copied to <label>.conversation/subagents/<id>.db, where the
#     adapter looks for the subagents the conversation names. Do not use agy
#     elsewhere during a capture: its conversations would be copied too
#     (they are never read unless the run names them).
# If agy is not logged in, run it once interactively and log in first.
#
# Gemini tasks:
#   basic     view_file, write_to_file (create), replace_file_content,
#             write_to_file (overwrite), run_command. Five calls, the same
#             shape as Claude Code's basic. No network.
#   search    list_dir, grep_search, find_by_name, then run_command. The
#             three search tools have no claim (open decision O-9): this task
#             measures what they do. No network.
#   long      the Claude Code long task in the same seeded workspace, with
#             view_file, replace_file_content, write_to_file, run_command,
#             grep_search, find_by_name and invoke_subagent. agy's print mode
#             gets 90 minutes for it instead of 10. No network.
# The controls run the no-op command with run_command; for long, whose tools
# include invoke_subagent, they also start one subagent that only replies.
#
# Controls and subagents (I-71): the controls of any task whose tool set holds
# the subagent tool (Claude Code Agent, agy invoke_subagent) also start one
# subagent that only replies, so the baseline measures the harness's own
# subagent bookkeeping (Claude Code: the subagent's agent-<id>.jsonl and
# .meta.json under the session's directory). After each control the script
# counts the subagents the run started and, for Claude Code, the tool calls
# they made, writes both to order.tsv and prints a WARNING when a control
# started other than one subagent or its subagent used a tool; the run is kept.
set -euo pipefail
# Ctrl+C reaches watch, which stops the agent and writes what it recorded; the
# script then stops too, before it would start the next run.
trap 'echo "interrupted" >&2; exit 130' INT TERM

agent=claude-code
task=basic
baseline_from=
allow_unconfigured=
content=
check_only=
build=1
model=
controls_before=0
heldout_dir=
while [ $# -gt 0 ]; do
  case $1 in
    --agent) agent=${2:?--agent needs claude-code or gemini}; shift 2 ;;
    --task) task=${2:?--task needs a task name}; shift 2 ;;
    --baseline-from) baseline_from=${2:?--baseline-from needs a directory}; shift 2 ;;
    --allow-unconfigured-version) allow_unconfigured=1; shift ;;
    --content) content=1; shift ;;
    --model) model=${2:?--model needs a model id}; shift 2 ;;
    --controls-before) controls_before=${2:?--controls-before needs a number}; shift 2 ;;
    --heldout-dir) heldout_dir=${2:?--heldout-dir needs a directory}; shift 2 ;;
    --check) check_only=1; shift ;;
    --no-build) build=; shift ;;
    -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "unknown option $1" >&2; exit 2 ;;
    *) break ;;
  esac
done
case $agent in
  claude-code) case $task in basic|parallel|project|edits|tools|shapes|long|websearch|heldout:*) ;; *) echo "unknown task $task for claude-code" >&2; exit 2 ;; esac ;;
  gemini) case $task in basic|search|long|heldout:*) ;; *) echo "unknown task $task for gemini (basic, search, long or heldout:NAME)" >&2; exit 2 ;; esac ;;
  *) echo "unknown agent $agent (claude-code or gemini)" >&2; exit 2 ;;
esac
case $controls_before in ''|*[!0-9]*) echo "--controls-before must be a number" >&2; exit 2 ;; esac
[ "${CONTROLS:-5}" -ge "$controls_before" ] 2>/dev/null || { echo "--controls-before $controls_before is more than the ${CONTROLS:-5} control runs (CONTROLS)" >&2; exit 2; }
if [ "$controls_before" -gt 0 ] && [ -n "$baseline_from" ]; then
  echo "--controls-before orders the control runs of this capture; --baseline-from takes none" >&2
  exit 2
fi
# The label of the task run's files: a held-out task heldout:NAME is heldout-NAME.
task_label=${task//:/-}

root=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-/tmp/agent-trace-capture-$(date +%Y%m%d-%H%M%S)}
# Every later step names the output by this path, some after changing
# directory, so a relative path is made absolute here.
out=$(realpath -m -- "$out")
if [ -n "$content" ] && [ "$agent" = gemini ]; then
  echo "--content needs a TLS library the net probe can hook; agy has none (Go's own TLS), so its connections stay identity-only" >&2
  exit 1
fi
if [ "$agent" = gemini ]; then
  agy_bin=$(command -v agy) || { echo "agy is not on PATH" >&2; exit 1; }
  version=$("$agy_bin" --version 2>/dev/null | awk '{print $NF}')
  [ -n "$version" ] || { echo "agy --version printed nothing" >&2; exit 1; }
  # agy reads its login from the Secret Service on the session bus; setpriv
  # --reset-env below clears the environment, so the two are passed again.
  [ -n "${DBUS_SESSION_BUS_ADDRESS:-}" ] && [ -n "${XDG_RUNTIME_DIR:-}" ] || {
    echo "DBUS_SESSION_BUS_ADDRESS and XDG_RUNTIME_DIR must be set: agy logs in through the session bus" >&2
    exit 1
  }
  agy_conversations=$HOME/.gemini/antigravity-cli/conversations
  # The model is pinned (D7), by default to the id the existing captures
  # recorded (the user's decision of 2026-10-26); --model overrides it. The
  # check after each run reads the conversation record, so an id agy does not
  # run under fails the run as MODEL MISMATCH.
  model=${model:-gemini-3.8-flash-high}
  # agy -p gives up after its print timeout; the long task needs far more
  # than the short ones.
  print_timeout=600s
  case $task in long|heldout:*) print_timeout=5400s ;; esac
else
  claude_bin=$(command -v claude) || { echo "claude is not on PATH" >&2; exit 1; }
  model=${model:-claude-sonnet-5-5}
  # Version lock (D6, protocol 6.1): a Claude Code that updates itself during a
  # campaign mixes versions. The runs below ignore the user's settings, so the
  # lock is checked in the settings file and passed to every run (below).
  claude_settings=${CLAUDE_CONFIG_DIR:-$HOME/.claude}/settings.json
  python3 - "$claude_settings" <<'PY' || {
import json, sys
try:
    v = json.load(open(sys.argv[1])).get("env", {}).get("DISABLE_UPDATES")
except (OSError, ValueError, AttributeError):
    sys.exit(1)
sys.exit(0 if str(v) == "1" else 1)
PY
    echo "$claude_settings must set env.DISABLE_UPDATES to \"1\": Claude Code must not update itself during a campaign (D6)" >&2
    exit 1
  }
  # Hooks and plugins add processes and connections that are not part of the
  # agent's own behaviour. Restricting settings to the project keeps the capture
  # about the harness itself. Override if your install needs user settings to
  # authenticate.
  # shellcheck disable=SC2206
  claude_flags=(${CLAUDE_FLAGS:---setting-sources project --disable-slash-commands})
  version=$("$claude_bin" --version 2>/dev/null | awk '{print $1}')
  [ -n "$version" ] || { echo "claude --version printed nothing" >&2; exit 1; }
fi
# What watch records besides the probes' defaults. Content capture hooks the
# TLS library inside the Claude Code binary, the file the claude command
# resolves to.
watch_mode=identity
watch_flags=()
if [ -n "$content" ]; then
  watch_mode=content
  watch_flags=(--net-exe-path "$(readlink -f "$claude_bin")")
fi

# The adapter's shapes, id families and hosts were measured on the versions
# config/agents.json lists (I-57); on another version they may silently not fit.
agent_config=${AGENT_TRACE_CONFIG:-$root/config/agents.json}
[ -f "$agent_config" ] || { echo "no agent version config at $agent_config" >&2; exit 1; }
set +e
configured=$(python3 - "$agent_config" "$agent" "$version" <<'PY'
import json, sys
path, agent, version = sys.argv[1:]
versions = [v["version"] for v in json.load(open(path))["adapters"].get(agent, {}).get("versions", [])]
print(", ".join(versions) or "none")
sys.exit(0 if version in versions else 3)
PY
)
check=$?
set -e
case $check in
  0) ;;
  3)
    # The campaign runner shows this once per invocation, at its own checks,
    # and sets AGENT_TRACE_VERSION_WARNED for the runs after them.
    if [ -n "$allow_unconfigured" ] && [ "${AGENT_TRACE_VERSION_WARNED:-}" = 1 ]; then
      :
    else
      echo "WARNING: $agent version '$version' is not configured in $agent_config (configured: $configured)" >&2
      echo "the adapter was verified on those versions only and may not fit this one (I-57)" >&2
      if [ -z "$allow_unconfigured" ]; then
        echo "to capture it anyway, to verify the new version, pass --allow-unconfigured-version" >&2
        exit 1
      fi
      echo "continuing (--allow-unconfigured-version): the report's verify runs use --strict-version and read INCONCLUSIVE until this version is configured" >&2
    fi
    ;;
  *) echo "could not read $agent_config" >&2; exit 1 ;;
esac

# A held-out task (D8) is written by the user and kept outside the repository:
# its prompt, tool set and seed are read from --heldout-dir and never copied
# into the repository or printed.
heldout_seed=
case $task in
  heldout:*)
    held=${task#heldout:}
    case $held in ''|.*|*[!A-Za-z0-9._-]*) echo "bad held-out task name '$held' (letters, digits, dot, dash and underscore)" >&2; exit 1 ;; esac
    [ -n "$heldout_dir" ] || { echo "$task needs --heldout-dir DIR, which holds $held/prompt.txt and $held/tools.txt" >&2; exit 1; }
    heldout_dir=$(realpath -m "$heldout_dir")
    case $heldout_dir/ in "$root"/*) echo "--heldout-dir $heldout_dir is inside the repository; held-out tasks are never copied into it" >&2; exit 1 ;; esac
    for f in prompt.txt tools.txt; do
      [ -s "$heldout_dir/$held/$f" ] || { echo "missing or empty $heldout_dir/$held/$f" >&2; exit 1; }
    done
    task_prompt=$(cat "$heldout_dir/$held/prompt.txt")
    task_tools=$(tr -s '[:space:]' ' ' <"$heldout_dir/$held/tools.txt" | sed 's/^ //; s/ $//')
    for t in $task_tools; do
      case $t in *[!A-Za-z0-9_]*) echo "held-out tool name '$t' in $held/tools.txt has a character other than a letter, digit or underscore" >&2; exit 1 ;; esac
    done
    [ ! -d "$heldout_dir/$held/seed" ] || heldout_seed=$heldout_dir/$held/seed
    ;;
  *) [ -z "$heldout_dir" ] || { echo "--heldout-dir is for --task heldout:NAME" >&2; exit 2; } ;;
esac

case $agent:$task in
  gemini:basic)
    task_prompt='Do exactly these five things in order, one tool call at a time, using the named tool for each, and nothing else. 1) Use view_file on b.txt. 2) Use write_to_file to create a.txt containing the single word hello. 3) Use replace_file_content to replace hello with world in a.txt. 4) Use write_to_file to overwrite b.txt with the single word again. 5) Use run_command to run exactly: echo hi . Then reply with the single word done.'
    task_tools='run_command view_file write_to_file replace_file_content'
    ;;
  gemini:search)
    task_prompt='Do exactly these six things in order, one tool call at a time, using the named tool for each, and nothing else. 1) Use list_dir on the current directory. 2) Use grep_search to search the current directory for the word seed. 3) Use find_by_name to find the files matching *.txt in the current directory. 4) Use write_to_file to create m.txt containing exactly two lines, alpha and beta. 5) Use multi_replace_file_content on m.txt, in one call with two replacement chunks, to replace alpha with one and beta with two. 6) Use run_command to run exactly: cat m.txt . Then reply with the single word done.'
    task_tools='run_command list_dir grep_search find_by_name write_to_file multi_replace_file_content'
    ;;
  gemini:long)
    task_prompt='You are working in a small Python package, textkit, in the current directory. Do not use the network. PLAN.md lists 20 functions, numbered 1 to 20, each with a specification file under docs/spec/. The work is finished only when all 20 functions are implemented and tested, CHANGELOG.md has one line per function and make check passes: do not stop before that, and do not skip, merge or reorder steps. Do these steps in order. 1) Use find_by_name to find the files matching *.md under docs/spec, and use grep_search to search textkit for NotImplementedError. 2) Use run_command to run: make check . It fails, since nothing is implemented yet. 3) For each function in PLAN.md, in order from 1 to 20, one function at a time, do these five steps: a) use view_file on its specification file; b) use replace_file_content to replace the raise NotImplementedError line of that function in its module with an implementation that meets the specification; c) use replace_file_content to add at least two unit test methods for it to the test class in the module test file under tests/; d) use run_command to run only that module tests, for example: python3 -m unittest tests.test_strings , and if they fail, fix the code and run them again; e) use replace_file_content to add one line naming the function at the end of CHANGELOG.md. 4) After functions 5, 10, 15 and 20, that is at the end of each module, use run_command to run make check-MODULE for that module (make check-strings, make check-numbers, make check-lists, make check-codec), and use grep_search to search that module file for NotImplementedError. 5) Use invoke_subagent to start one subagent with exactly this instruction: Use find_by_name to find the files matching test_*.py under tests, use run_command to run: python3 -m unittest discover -s tests -t . , then use write_to_file to create REPORT.md stating how many tests ran. Then reply with the single word done. 6) Use run_command to run: make dist , then python3 dist/textkit.pyz slugify "Hello, World" , then python3 dist/textkit.pyz roman 1987 . 7) Use view_file on REPORT.md, then use replace_file_content to add a section named Status at the end of README.md saying how many tests pass. 8) Use run_command to run make check a last time. Then reply with the single word done.'
    task_tools='run_command view_file write_to_file replace_file_content grep_search find_by_name invoke_subagent'
    ;;
esac

case $agent:$task in
  gemini:*) ;;
  claude-code:basic)
    task_prompt='Do exactly these five things in order, using the named tool for each, and nothing else. 1) Use the Read tool on b.txt. 2) Use the Write tool to create a.txt containing the single word hello. 3) Use the Edit tool to replace hello with world in a.txt. 4) Use the Write tool to overwrite b.txt with the single word again. 5) Use the Bash tool to run exactly: echo hi. Then reply with the single word done.'
    task_tools='Read Write Edit Bash'
    ;;
  claude-code:websearch)
    # One server-side WebSearch and the fetch of a page it names, so a capture
    # with --content shows the WebSearch call's requestId beside the model
    # API's responses (V-45).
    task_prompt='Do exactly these three things in order, and nothing else. 1) Use the WebSearch tool once to search for: fanotify man page. 2) Use the WebFetch tool on https://man7.org/linux/man-pages/man7/fanotify.7.html with the prompt: what does fanotify do, in one sentence. 3) Use the Write tool to create notes.txt containing that one sentence. Then reply with the single word done.'
    task_tools='WebSearch WebFetch Write Bash'
    ;;
  claude-code:parallel)
    task_prompt='Do exactly these six things in order, and nothing else. 1) In a single message, make three Read tool calls at the same time, for b.txt, c.txt and d.txt. 2) Use the Agent tool to start one subagent with exactly this instruction: Use the Bash tool to run exactly: echo from-subagent . Then reply with the single word done. 3) Use the Grep tool to search the current directory for the word seed. 4) Use the Glob tool to list the files matching *.txt. 5) Use the WebFetch tool on https://example.com with the prompt: what is the title. 6) Use the Bash tool to run exactly: echo one | tr a-z A-Z . Then reply with the single word done.'
    task_tools='Read Write Edit Bash Agent Grep Glob WebFetch'
    ;;
  claude-code:edits)
    task_prompt='Do exactly these seven things in order, using the named tool for each, and nothing else. 1) Use the Write tool to create notes.txt with exactly this content (four lines): alpha beta alpha / gamma delta / say "hi" to C:\\temp / end. Write each item separated by slash as its own line, without the slashes. 2) Use the Edit tool to replace the first occurrence of alpha with ALPHA. 3) Use the Edit tool with replace_all set to true to replace every a with 4. 4) Use the Edit tool to replace the two lines g4mm4 delt4 and s4y "hi" to C:\\temp together with the single line merged. 5) Use the Edit tool to replace the line end with the two lines end and really the end. 6) Use the Edit tool to replace ALPHA with alpha. 7) Use the Bash tool to run exactly: cat notes.txt. Then reply with the single word done.'
    task_tools='Read Write Edit Bash'
    ;;
  claude-code:project)
    task_prompt='You are working in a small Python package, wordstats, in the current directory. Do these steps in order and nothing else, and do not use the network. 1) Run the unit tests with: python3 -m unittest discover . Some of them fail. 2) Read the code, find the cause of the failures and fix it. 3) Add a function top_n(text, n) to wordstats/core.py that returns the n most frequent (word, count) pairs, most frequent first and ties in alphabetical order, export it from the package, and add unit tests for it in tests/test_core.py. 4) Add a --top N option to the command line tool in wordstats/cli.py that prints only the top N words, with a test in tests/test_cli.py. 5) Update README.md to describe top_n and the --top option. 6) Run the unit tests again and make sure they all pass. Then reply with the single word done.'
    task_tools='Read Write Edit Bash Grep Glob'
    ;;
  claude-code:tools)
    # MultiEdit is in the list so that the step that names it is permitted if
    # this version offers the tool. Version 2.1.296 seems not to (its name
    # appears only among the permission-rule names, beside the retired LS and
    # NotebookRead), and the prompt falls back to Edit in that case.
    task_prompt='Do exactly these nine things in order, using the named tool for each, and nothing else. 1) Use the Bash tool with run_in_background set to true to run exactly: sleep 3; echo background-done | tee bg.txt . Do not wait for it and do not check on it until step 8. 2) In a single message, make three Read tool calls at the same time, for notes.txt, numbers.txt and analysis.ipynb. 3) In notes.txt, replace colour: red with colour: blue and replace size: small with size: large. If a tool named MultiEdit is available to you, make both changes with one MultiEdit call; if it is not, use the Edit tool once for each change. 4) Use the NotebookEdit tool on analysis.ipynb, with edit_mode replace, on the cell whose id is total, to set its source to exactly: print(sum([3, 5, 7])) . 5) Use the Write tool to create report.txt containing the single word draft. 6) Use the Write tool to overwrite report.txt with the single word final. 7) Use the Agent tool to start one subagent, with run_in_background set to false if the tool offers that parameter, giving it exactly this instruction: Use the Write tool to create subagent.txt containing the single word from-subagent. Then reply with the single word done. 8) Use the Read tool on the output file whose path the Bash result of step 1 reported. 9) Use the Bash tool to run exactly: cat bg.txt notes.txt report.txt subagent.txt . Then reply with the single word done.'
    task_tools='Read Write Edit MultiEdit NotebookEdit Bash Agent'
    ;;
  claude-code:shapes)
    # What the 2.1.296 binary says (read from its strings, not measured): the
    # tool executor starts a call while an earlier one still runs only when
    # every running call and the new one are concurrency-safe. Read, Grep,
    # Glob, WebFetch and Agent always are; Write, Edit and NotebookEdit never
    # are; Bash is when its command passes the read-only check (every simple
    # command on an allowlist that includes sleep and cat, no output
    # redirection). So the first block runs concurrently and its first member
    # finishes last, and the second block, whose commands write, runs in claim
    # order. The file tools write through one routine: a sibling temporary
    # file renamed over the target, and, when the temporary cannot be created
    # with EACCES while the target exists (or the rename fails with EXDEV,
    # EPERM, EEXIST or EBUSY), an in-place rewrite of the target (open,
    # truncate, write, fsync, close). A symlinked target is refused, not
    # written in place. locked/ is made unwritable for the run below.
    task_prompt='Do exactly these six things in order, and nothing else. If a step fails, do not retry it or work around it; go on to the next step. 1) In a single message, make these three tool calls at the same time, in this order: the Bash tool to run exactly: sleep 2; cat slow.txt , then the Bash tool to run exactly: cat fast.txt , then the Read tool on read.txt. 2) In a single message, make these two Bash tool calls at the same time, in this order: one to run exactly: sleep 2; echo one > one.txt , then one to run exactly: echo two > two.txt . 3) Use the Read tool on locked/data.txt. 4) Use the Write tool to overwrite locked/data.txt with the single word direct-one. 5) Use the Edit tool to replace direct-one with direct-two in locked/data.txt. 6) Use the Bash tool to run exactly: cat one.txt two.txt locked/data.txt . Then reply with the single word done.'
    task_tools='Read Write Edit Bash'
    ;;
  claude-code:long)
    # Twenty functions times five steps, plus the module checks, the subagent
    # and the build: about 120 calls before any fix, so the model cannot
    # finish early without skipping numbered work it is told is required.
    task_prompt='You are working in a small Python package, textkit, in the current directory. Do not use the network. PLAN.md lists 20 functions, numbered 1 to 20, each with a specification file under docs/spec/. The work is finished only when all 20 functions are implemented and tested, CHANGELOG.md has one line per function and make check passes: do not stop before that, and do not skip, merge or reorder steps. Make one tool call per message. Do these steps in order. 1) Use the Glob tool to list docs/spec/*.md, and the Grep tool to search textkit for NotImplementedError. 2) Use the Bash tool to run: make check . It fails, since nothing is implemented yet. 3) For each function in PLAN.md, in order from 1 to 20, one function at a time, do these five steps: a) use the Read tool on its specification file; b) use the Edit tool to replace the raise NotImplementedError line of that function in its module with an implementation that meets the specification; c) use the Edit tool to add at least two unit test methods for it to the test class in the module test file under tests/; d) use the Bash tool to run only that module tests, for example: python3 -m unittest tests.test_strings , and if they fail, fix the code and run them again; e) use the Edit tool to add one line naming the function at the end of CHANGELOG.md. 4) After functions 5, 10, 15 and 20, that is at the end of each module, use the Bash tool to run make check-MODULE for that module (make check-strings, make check-numbers, make check-lists, make check-codec), and use the Grep tool to search that module file for NotImplementedError. 5) Use the Agent tool to start one subagent with exactly this instruction: Use the Glob tool to list tests/test_*.py, use the Bash tool to run: python3 -m unittest discover -s tests -t . , then use the Write tool to create REPORT.md stating how many tests ran. Then reply with the single word done. 6) Use the Bash tool to run: make dist , then python3 dist/textkit.pyz slugify "Hello, World" , then python3 dist/textkit.pyz roman 1987 . 7) Use the Read tool on REPORT.md, then use the Edit tool to add a section named Status at the end of README.md saying how many tests pass. 8) Use the Bash tool to run make check a last time. Then reply with the single word done.'
    task_tools='Read Write Edit Bash Grep Glob Agent'
    ;;
esac
# A task with a directory under scripts/seed starts every run, controls
# included, from a copy of it; the others start from three one-line files.
seed=$root/scripts/seed/$task
case $task in
  project|tools|shapes|long) [ -d "$seed" ] || { echo "missing seed directory $seed" >&2; exit 1; } ;;
  heldout:*) seed=$heldout_seed ;;
  *) seed= ;;
esac
seed_sha256=none
if [ -n "$seed" ]; then
  seed_sha256=$(cd "$seed" && find . -type f -print0 | sort -z | xargs -0 -r sha256sum | sha256sum | cut -d' ' -f1)
fi
task_prompt_sha256=$(printf '%s' "$task_prompt" | sha256sum | cut -d' ' -f1)
# The shapes task needs a directory the agent cannot write to, holding a file
# it can: git keeps no directory modes, so every run's copy of locked/ loses
# its write permission while the run lasts.
locked=
if [ "$task" = shapes ]; then
  locked=locked
  [ -f "$seed/$locked/data.txt" ] || { echo "missing $seed/$locked/data.txt" >&2; exit 1; }
fi
# The control claims nothing worth verifying, but it must use Bash once: the
# harness runs setup commands the first time a session uses Bash (probing the
# environment, writing a shell snapshot), and a baseline taken without a Bash
# call would not contain them. The command is a no-op with a marker name, and it
# is excluded from the baseline below: it is what the agent was told to run, not
# the harness's own activity, and as a rule it would explain any later command
# with that target, and its whole subtree, without a claim.
control_command=': agent-trace-control-marker'
control_prompt="Use the Bash tool to run exactly this no-op command: $control_command . Then reply with the single word ok. Do not use any other tool."
# Gemini's command tool is run_command. The harness writes its agentapi shim and
# opens a pseudo-terminal before every command (I-48), so the controls run one.
[ "$agent" != gemini ] || control_prompt="Use run_command to run exactly this no-op command: $control_command . Then reply with the single word ok. Do not use any other tool."
# The control runs must enable the same tools as the task. The shell snapshot
# command the harness runs at the first Bash call differs with the tool set (it
# shadows find and grep only when Grep and Glob are disabled), so a baseline
# measured with one tool set does not explain the other's setup commands.
control_tools=$task_tools
# A task whose tool set holds the subagent tool may start a subagent, and the
# harness then writes the subagent's own files (for Claude Code its transcript
# agent-<id>.jsonl and agent-<id>.meta.json under the session's directory),
# which a control that makes one command call never shows. Its controls
# therefore also start one subagent that only replies and uses no tool (I-71),
# so the baseline measures that bookkeeping, and the subagent itself makes no
# action a rule could take.
subagent_tool=Agent
[ "$agent" != gemini ] || subagent_tool=invoke_subagent
control_subagent=
case " $control_tools " in *" $subagent_tool "*) control_subagent=1 ;; esac
if [ "$task" = tools ]; then
  # The tools task also makes the harness work around a background command
  # (its output file under /tmp/claude-<uid>). Its controls therefore also run
  # the same no-op command in the background, whose output they do not need.
  # The background call runs the marker command, so the one exclusion below
  # covers it.
  control_prompt="Do exactly these three things in order, and nothing else. 1) Use the Bash tool to run exactly this no-op command: $control_command . 2) Use the Bash tool with run_in_background set to true to run exactly the same command again: $control_command . Do not wait for it, check on it or read its output. 3) Use the Agent tool to start one subagent, with run_in_background set to false if the tool offers that parameter, giving it exactly this instruction: Reply with the single word ok. Do not use any tool. Then reply with the single word ok. Do not use any other tool."
elif [ -n "$control_subagent" ] && [ "$agent" = gemini ]; then
  # An agy subagent answers its caller with a send_message call, so its
  # instruction forbids commands and files rather than every tool.
  control_prompt="Do exactly these two things in order, and nothing else. 1) Use run_command to run exactly this no-op command: $control_command . 2) Use invoke_subagent to start one subagent with exactly this instruction: Reply with the single word ok. Do not run any command and do not read or write any file. Then reply with the single word ok. Do not use any other tool."
elif [ -n "$control_subagent" ]; then
  control_prompt="Do exactly these two things in order, and nothing else. 1) Use the Bash tool to run exactly this no-op command: $control_command . 2) Use the Agent tool to start one subagent, with run_in_background set to false if the tool offers that parameter, giving it exactly this instruction: Reply with the single word ok. Do not use any tool. Then reply with the single word ok. Do not use any other tool."
fi
# A control makes one command call, so its tool set must offer one.
need_tool=Bash
[ "$agent" != gemini ] || need_tool=run_command
case " $control_tools " in *" $need_tool "*) ;; *) echo "the tool set of this task ($control_tools) lacks $need_tool, which the controls need" >&2; exit 1 ;; esac

# Refuse an unusable --baseline-from before anything that needs root or quota.
if [ -n "$baseline_from" ]; then
  [ -e "$(ls "$baseline_from"/control-*.ground_truth.json 2>/dev/null | head -1)" ] || { echo "no control-*.ground_truth.json in $baseline_from" >&2; exit 1; }
  # A capture made before the agent was recorded is of Claude Code.
  earlier=$(cat "$baseline_from/control-agent.txt" 2>/dev/null || echo claude-code)
  if [ "$earlier" != "$agent" ]; then
    echo "the control runs in $baseline_from are of $earlier, this capture is of $agent" >&2
    exit 1
  fi
  # A capture made before the tool set was recorded used the basic task's tools.
  earlier=$(cat "$baseline_from/control-tools.txt" 2>/dev/null || echo 'Read Write Edit Bash')
  if [ "$earlier" != "$control_tools" ]; then
    echo "the control runs in $baseline_from enabled: $earlier" >&2
    echo "this task enables:                          $control_tools" >&2
    echo "a baseline holds for one tool set; run without --baseline-from to measure new controls" >&2
    exit 1
  fi
  # A capture made before the control prompt was recorded used the one-call
  # prompt, which every task without the subagent tool still uses.
  earlier=$(cat "$baseline_from/control-prompt.txt" 2>/dev/null || echo "Use the Bash tool to run exactly this no-op command: $control_command . Then reply with the single word ok. Do not use any other tool.")
  if [ "$earlier" != "$control_prompt" ]; then
    echo "the control runs in $baseline_from were told: $earlier" >&2
    echo "this task's controls are told:            $control_prompt" >&2
    echo "a baseline holds for one control task; run without --baseline-from to measure new controls" >&2
    exit 1
  fi
  # The harness's own activity changes between versions. A capture made before
  # the version was recorded names it in its baseline.
  earlier=$(cat "$baseline_from/control-version.txt" 2>/dev/null ||
    python3 -c 'import json, sys; print(json.load(open(sys.argv[1])).get("agent_version", ""))' "$baseline_from/baseline.json" 2>/dev/null || true)
  if [ -z "$earlier" ]; then
    echo "cannot tell which $agent version the control runs in $baseline_from were made with (no control-version.txt, no version in baseline.json)" >&2
    exit 1
  fi
  if [ "$earlier" != "$version" ]; then
    echo "the control runs in $baseline_from are of $agent $earlier, the installed one is $version" >&2
    echo "a baseline holds for one version; run without --baseline-from to measure new controls" >&2
    exit 1
  fi
  # The model is part of what a control measures. A capture made before it was
  # recorded ran the default model of its day, which the file cannot name.
  if [ -f "$baseline_from/control-model.txt" ]; then
    earlier=$(cat "$baseline_from/control-model.txt")
    if [ "$earlier" != "$model" ]; then
      echo "the control runs in $baseline_from ran model $earlier, this capture pins $model" >&2
      echo "a baseline holds for one model; run without --baseline-from to measure new controls" >&2
      exit 1
    fi
  else
    echo "WARNING: the control runs in $baseline_from did not record their model; they ran the default model of their day, not necessarily $model" >&2
  fi
  # Content capture adds the requests to the capture, which a baseline taken
  # without it does not explain, and the other way round. A capture made
  # before the mode was recorded had no content capture.
  earlier=$(cat "$baseline_from/control-watch.txt" 2>/dev/null || echo identity)
  if [ "$earlier" != "$watch_mode" ]; then
    echo "the control runs in $baseline_from were recorded with net mode $earlier, this capture uses $watch_mode" >&2
    echo "a baseline holds for one recording mode; run without --baseline-from to measure new controls" >&2
    exit 1
  fi
fi

# A directory without write permission stops the harness's temporary file only
# when the agent runs as a user the mode binds: root, or a filesystem that
# ignores modes, would let the write take its usual temporary-and-rename path.
# Try it on the output filesystem, where the workspaces will be; --check, which
# creates nothing, tries it in the nearest directory that exists.
probe_parent=$out
if [ -n "$check_only" ]; then
  while [ ! -d "$probe_parent" ]; do probe_parent=$(dirname "$probe_parent"); done
else
  mkdir -p "$out"
fi
if [ -n "$locked" ]; then
  probe=$(mktemp -d "$probe_parent/.locked-probe.XXXXXX")
  chmod a-w "$probe"
  if [ -w "$probe" ]; then
    chmod u+w "$probe"; rmdir "$probe"
    echo "a directory without write permission is still writable here (uid $(id -u)); the shapes task needs one that is not" >&2
    echo "run the script as an ordinary user, with OUTPUT_DIR on a filesystem that enforces modes" >&2
    exit 1
  fi
  chmod u+w "$probe"; rmdir "$probe"
fi
if [ -n "$check_only" ]; then
  # What a caller needs to decide which captures may share control runs: the
  # values --baseline-from compares, the prompt by its hash.
  echo "check=ok"
  echo "agent=$agent"
  echo "version=$version"
  echo "task=$task"
  echo "control_tools=$control_tools"
  echo "control_prompt_sha256=$(printf '%s' "$control_prompt" | sha256sum | cut -d' ' -f1)"
  echo "watch_mode=$watch_mode"
  echo "model=$model"
  echo "task_prompt_sha256=$task_prompt_sha256"
  echo "seed_sha256=$seed_sha256"
  exit 0
fi
echo "output: $out"
if [ "$agent" = gemini ]; then
  echo "agy: $agy_bin ($version), task: $task"
else
  echo "claude: $claude_bin ($version), task: $task"
fi
[ -z "$build" ] || (cd "$root" && make build >/dev/null)
sudo -v

# measured LABEL COMMAND...: run the sudo'd watch command under
# scripts/measure-watch.py, which writes LABEL.cost.json (H4b: start-up, drain,
# watch's CPU and peak RSS) and passes the command's exit status through. The
# measurement never decides the run: if it cannot run, the command still does.
measured() { # label command...
  local label=$1; shift
  python3 "$root/scripts/measure-watch.py" --gt "$out/$label.ground_truth.json" \
    --out "$out/$label.cost.json" -- "$@"
}

capture_one() { # label prompt tools role
  local label=$1 prompt=$2 tools=$3 role=$4
  local ws="$out/ws-$label" session
  session=$(cat /proc/sys/kernel/random/uuid)
  # capture_one runs where set -e does not apply, so each step that must not
  # fail says so.
  mkdir -p "$ws" || return 1
  if [ -n "$seed" ]; then
    cp -r "$seed/." "$ws/" || return 1
  else
    for f in b c d; do printf 'seed\n' >"$ws/$f.txt" || return 1; done
  fi
  if [ -n "$locked" ]; then
    chmod a-w "$ws/$locked"
    [ ! -w "$ws/$locked" ] || { echo "   $ws/$locked is still writable" >&2; return 1; }
  fi
  if [ "$agent" = gemini ]; then
    capture_gemini "$label" "$prompt" "$tools" "$ws"
    return
  fi
  echo "== $label: session $session"
  local wrc=0
  (
    cd "$ws"
    measured "$label" sudo "$root/watch" --probes fs,proc,net "${watch_flags[@]}" --workspace "$ws" \
      --out "$out/$label.ground_truth.json" -- \
      setpriv --reuid "$(id -u)" --regid "$(id -g)" --init-groups --reset-env \
      env DISABLE_UPDATES=1 \
      "$claude_bin" -p "${claude_flags[@]}" --model "$model" --allowedTools "$tools" \
      --session-id "$session" "$prompt" >"$out/$label.watch.log" 2>&1
  ) || wrc=$?
  printf '%s\n' "$wrc" >"$out/$label.watch.exit"
  [ "$wrc" -eq 0 ] || echo "   watch exited non-zero, see $out/$label.watch.log (exit $wrc)"
  # Recording has ended: give the permission back so the output can be removed.
  [ -z "$locked" ] || chmod u+w "$ws/$locked"
  local found
  found=$(find "$HOME/.claude/projects" -name "$session.jsonl" -print -quit 2>/dev/null || true)
  if [ -z "$found" ] && [ "$role" = task ]; then
    # The task's trace is gone after the run: a result, not a harness error
    # (V-59, I-75). The ground truth is kept, and verify reports that the
    # trace cannot be verified, with what the probes saw happen to it.
    echo "   TRACE DELETED OR DAMAGED: no transcript for session $session after the run; verify reports it (V-59)" >&2
    printf 'missing\n' >"$out/$label.trace.txt"
    sudo chown -R "$(id -u):$(id -g)" "$out" 2>/dev/null || true
    return 0
  fi
  if [ -z "$found" ]; then
    echo "   no transcript found for session $session" >&2
    return 1
  fi
  cp "$found" "$out/$label.session.jsonl" || return 1
  if [ -d "${found%.jsonl}/subagents" ]; then
    mkdir -p "$out/$label.session" || return 1
    cp -r "${found%.jsonl}/subagents" "$out/$label.session/"
    echo "   $(find "$out/$label.session/subagents" -name '*.jsonl' | wc -l) subagent transcript(s) copied"
  fi
  sudo chown -R "$(id -u):$(id -g)" "$out" 2>/dev/null || true
}

# The custom agent that fixes a Gemini run's tool set (I-24): the task's tools
# only, none of the user's MCP servers or customizations.
agent_md() { # tools
  printf -- '---\nname: agent-trace\ndescription: Runs the exact steps it is given for a trajectory capture.\n'
  printf -- 'mainAgent: true\nsubagent: false\ninheritMcp: false\ninheritCustomizations: false\ntools:\n'
  for t in $1; do printf -- '  - %s\n' "$t"; done
  printf -- '---\n# agent-trace\nDo exactly what the user asks, using the named tools, and nothing else.\n'
}

capture_gemini() { # label prompt tools workspace
  local label=$1 prompt=$2 tools=$3 ws=$4 id before f sid n=0
  mkdir -p "$ws/.agents/agents/agent-trace" || return 1
  agent_md "$tools" >"$ws/.agents/agents/agent-trace/agent.md" || return 1
  echo "== $label"
  # The databases that exist before the run: any other one after it is the
  # run's own or a subagent's (I-55).
  before=$(ls "$agy_conversations" 2>/dev/null | grep '\.db$' || true)
  local wrc=0
  (
    cd "$ws"
    measured "$label" sudo "$root/watch" --probes fs,proc,net --workspace "$ws" \
      --out "$out/$label.ground_truth.json" -- \
      setpriv --reuid "$(id -u)" --regid "$(id -g)" --init-groups --reset-env \
      env DBUS_SESSION_BUS_ADDRESS="$DBUS_SESSION_BUS_ADDRESS" XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" \
      AGY_CLI_DISABLE_AUTO_UPDATE=true \
      "$agy_bin" --agent agent-trace --model "$model" --dangerously-skip-permissions --output-format json \
      --print-timeout "$print_timeout" -p "$prompt" >"$out/$label.watch.log" 2>&1
  ) || wrc=$?
  printf '%s\n' "$wrc" >"$out/$label.watch.exit"
  [ "$wrc" -eq 0 ] || echo "   watch exited non-zero, see $out/$label.watch.log (exit $wrc)"
  sudo chown -R "$(id -u):$(id -g)" "$out" 2>/dev/null || true
  # agy prints one JSON object with the conversation id; the database is named by it.
  id=$(grep -o '"conversation_id":"[0-9a-f-]*"' "$out/$label.watch.log" | head -1 | cut -d'"' -f4 || true)
  if [ -z "$id" ] || [ ! -f "$agy_conversations/$id.db" ]; then
    echo "   no conversation database found for $label (id '${id}'), see $out/$label.watch.log" >&2
    return 1
  fi
  echo "   conversation $id"
  cp "$agy_conversations/$id.db" "$out/$label.conversation.db" || return 1
  # A write-ahead log that agy left unmerged holds steps too.
  [ ! -s "$agy_conversations/$id.db-wal" ] || cp "$agy_conversations/$id.db-wal" "$out/$label.conversation.db-wal"
  for f in "$agy_conversations"/*.db; do
    sid=$(basename "$f" .db)
    [ -f "$f" ] && [ "$sid" != "$id" ] || continue
    ! grep -qxF "$sid.db" <<<"$before" || continue
    mkdir -p "$out/$label.conversation/subagents"
    cp "$f" "$out/$label.conversation/subagents/$sid.db"
    [ ! -s "$f-wal" ] || cp "$f-wal" "$out/$label.conversation/subagents/$sid.db-wal"
    n=$((n + 1))
  done
  [ "$n" -eq 0 ] || echo "   $n subagent conversation database(s) copied"
}

# The models a run's transcript records (D7). Prints observed=<models of the
# main transcript>;subagents=<models of its subagents' transcripts, not
# checked>; exits 0 when the main transcript records the pinned model and no
# other, 1 when it records another, 2 when it records none.
model_seen() { # file
  python3 - "$agent" "$1" "$model" <<'PY'
import json, os, re, shutil, sqlite3, sys, tempfile
agent, path, want = sys.argv[1:]

def claude(p):
    seen = set()
    try:
        for line in open(p, encoding="utf-8", errors="replace"):
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if not isinstance(r, dict) or r.get("type") != "assistant":
                continue
            m = (r.get("message") or {}).get("model") or r.get("model")
            if isinstance(m, str) and m != "<synthetic>":
                seen.add(m)
    except OSError:
        pass
    return seen

def agy(p):
    # The conversation's executor metadata names the model the run was set to,
    # read as a whole token: the same bytes hold paths, and the campaign's own
    # directory names (gemini-1.4.7) are not models;
    # gen_metadata names the model that answered, in a form that drops the
    # effort suffix.
    # Read a copy with its write-ahead log beside it, so the capture is not touched.
    seen = set()
    with tempfile.TemporaryDirectory() as d:
        try:
            shutil.copy(p, d + "/c.db")
            if os.path.exists(p + "-wal"):
                shutil.copy(p + "-wal", d + "/c.db-wal")
            c = sqlite3.connect(d + "/c.db")
            for (b,) in c.execute("select data from executor_metadata"):
                if isinstance(b, bytes):
                    seen |= {m.decode() for m in re.findall(rb"(?<![/0-9A-Za-z._-])(?:gemini|claude|gpt)-[0-9A-Za-z.\-]*[0-9A-Za-z](?![/0-9A-Za-z._-])", b)}
            c.close()
        except (OSError, sqlite3.Error):
            pass
    return seen

if agent == "gemini":
    main, subs = agy(path), set()
else:
    main, subs = claude(path), set()
    d = path[:-len(".jsonl")] + "/subagents"
    if os.path.isdir(d):
        for f in sorted(os.listdir(d)):
            if f.endswith(".jsonl"):
                subs |= claude(os.path.join(d, f))
print("observed=%s;subagents=%s" % (",".join(sorted(main)), ",".join(sorted(subs))))
sys.exit(2 if not main else (0 if main == {want} else 1))
PY
}

# The subagents a recorded run started (I-71): for Claude Code the subagent
# transcripts copied beside the run's and the tool calls their assistant
# records make; for agy the subagent databases copied, whose calls are not
# counted (-). Prints subagents=N;subagent_tool_calls=M.
subagents_seen() { # label
  python3 - "$agent" "$out/$1" <<'PY'
import glob, json, os, sys
agent, base = sys.argv[1:]
if agent == "gemini":
    print("subagents=%d;subagent_tool_calls=-" % len(glob.glob(base + ".conversation/subagents/*.db")))
    sys.exit(0)
files = sorted(glob.glob(base + ".session/subagents/*.jsonl"))
calls = 0
for f in files:
    try:
        lines = open(f, encoding="utf-8", errors="replace").readlines()
    except OSError:
        continue
    for line in lines:
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if not isinstance(r, dict) or r.get("type") != "assistant":
            continue
        content = (r.get("message") or {}).get("content")
        if isinstance(content, list):
            calls += sum(1 for c in content if isinstance(c, dict) and c.get("type") == "tool_use")
print("subagents=%d;subagent_tool_calls=%d" % (len(files), calls))
PY
}

# trace_state FILE: what a Claude Code transcript holds as the capture left
# it (V-59): missing, empty, damaged (no line is a JSON object, or a line is
# not JSON) or read. verify decides the verdict; this only keeps a run whose
# trace is gone or garbled from reading as a model mismatch.
trace_state() { # file
  python3 - "$1" <<'PY'
import json, os, sys
p = sys.argv[1]
if not os.path.exists(p):
    print("missing"); sys.exit()
if os.path.getsize(p) == 0:
    print("empty"); sys.exit()
ok = bad = 0
for line in open(p, encoding="utf-8", errors="replace"):
    if not line.strip():
        continue
    try:
        ok += isinstance(json.loads(line), dict)
    except ValueError:
        bad += 1
print("damaged" if bad or not ok else "read")
PY
}

# capture LABEL ROLE PROMPT TOOLS: one recorded run, then its model check, and a
# line of order.tsv: the order the runs were recorded in (D11), their times,
# the models their transcripts recorded, watch's exit status and the
# subagents the run started.
capture() {
  local label=$1 role=$2 started ended rc=0 seen= mrc=0 file subs=subagents=-
  started=$(date --iso-8601=seconds)
  capture_one "$label" "$3" "$4" "$role" || rc=$?
  ended=$(date --iso-8601=seconds)
  if [ "$rc" -eq 0 ] && [ "$role" = task ] && [ "$agent" != gemini ]; then
    # A task transcript that is gone, empty or holds no record that parses
    # cannot be checked for its model: its run is a trace result, not a
    # model mismatch (V-59, I-75).
    [ -f "$out/$label.trace.txt" ] || trace_state "$out/$label.session.jsonl" >"$out/$label.trace.txt"
  fi
  if [ "$rc" -eq 0 ] && [ -f "$out/$label.trace.txt" ] && [ "$(cat "$out/$label.trace.txt")" != read ]; then
    mrc=trace-$(cat "$out/$label.trace.txt")
  elif [ "$rc" -eq 0 ]; then
    file=$out/$label.session.jsonl
    [ "$agent" != gemini ] || file=$out/$label.conversation.db
    seen=$(model_seen "$file") || mrc=$?
    subs=$(subagents_seen "$label") || subs=subagents=-
  else
    mrc=-
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$(($(wc -l <"$out/order.tsv" 2>/dev/null || echo 0) + 1))" "$label" "$role" "$started" "$ended" "model_check=$mrc;$seen" "watch_exit=$(tr -d '\n' <"$out/$label.watch.exit" 2>/dev/null || echo -)" "$subs" >>"$out/order.tsv"
  [ "$rc" -eq 0 ] || return "$rc"
  # A control that did not start exactly one subagent, or whose subagent used
  # a tool, measured another harness path than the one its prompt asks for.
  # The run is kept and the deviation is in order.tsv.
  if [ "$role" = control ] && [ -n "$control_subagent" ]; then
    case $subs in
      subagents=1\;subagent_tool_calls=0 | subagents=1\;subagent_tool_calls=-) ;;
      *) echo "   WARNING: control $label was asked for one subagent that uses no tool, and recorded $subs" >&2 ;;
    esac
  fi
  case $mrc in
    0) ;;
    trace-*) echo "   TRACE DELETED OR DAMAGED: the transcript of $label is ${mrc#trace-}, so its model is not checked; verify reports the trace (V-59)" >&2 ;;
    1) echo "   MODEL MISMATCH: $label recorded $seen, the pinned model is $model" >&2; return 1 ;;
    *) echo "   MODEL MISMATCH: the transcript of $label records no model (pinned: $model)" >&2; return 1 ;;
  esac
}

{
  echo "task=$task"
  echo "task_prompt_sha256=$task_prompt_sha256"
  echo "task_tools=$task_tools"
  echo "seed_sha256=$seed_sha256"
  echo "model=$model"
  echo "agent=$agent"
  echo "version=$version"
} >"$out/task-meta.txt"
: >"$out/order.tsv"

controls_total=${CONTROLS:-5}
if [ -z "$baseline_from" ]; then
  for n in $(seq 1 "$controls_before"); do capture "control-$n" control "$control_prompt" "$control_tools"; done
fi
capture "$task_label" task "$task_prompt" "$task_tools"

if [ -n "$baseline_from" ]; then
  controls=("$baseline_from"/control-*.ground_truth.json)
  [ -e "${controls[0]}" ] || { echo "no control-*.ground_truth.json in $baseline_from" >&2; exit 1; }

  echo "baseline: reusing ${#controls[@]} control run(s) from $baseline_from"
else
  for n in $(seq $((controls_before + 1)) "$controls_total"); do capture "control-$n" control "$control_prompt" "$control_tools"; done
  printf 'before=%s after=%s' "$controls_before" "$((controls_total - controls_before))" >"$out/control-order.txt"
  printf '%s' "$model" >"$out/control-model.txt"
  printf '%s' "$control_tools" >"$out/control-tools.txt"
  printf '%s' "$control_prompt" >"$out/control-prompt.txt"
  printf '%s' "$agent" >"$out/control-agent.txt"
  printf '%s' "$version" >"$out/control-version.txt"
  printf '%s' "$watch_mode" >"$out/control-watch.txt"
  controls=("$out"/control-*.ground_truth.json)
fi
min_agreement=${MIN_AGREEMENT:-$(awk -v n="${#controls[@]}" 'BEGIN { printf "%.4f", 1 / n }')}
"$root/baseline" --agent "$agent" --agent-version "$version" --min-agreement "$min_agreement" \
  --exclude "$control_command" --out "$out/baseline.json" "${controls[@]}"

trajectory=$out/$task_label.session.jsonl
[ "$agent" != gemini ] || trajectory=$out/$task_label.conversation.db
# A version the config does not list makes the verdict INCONCLUSIVE (I-57).
# agy's conversation does not state its version, so it is passed; nor does a
# Claude Code transcript that is gone or garbled, which verify reports as a
# trace it cannot verify (V-59). The transcript was copied as the run left
# it, so verify compares it with the last content the probe hashed.
version_flags=(--strict-version)
[ "$agent" != gemini ] || version_flags+=(--agent-version "$version")
if [ "$agent" != gemini ]; then
  version_flags+=(--check-trace-hash)
  [ "$(cat "$out/$task_label.trace.txt" 2>/dev/null || echo read)" = read ] || version_flags+=(--agent-version "$version")
fi
{
  echo "##### verify WITHOUT a baseline"
  "$root/verify" --agent "$agent" --trajectory "$trajectory" "${version_flags[@]}" \
    --ground-truth "$out/$task_label.ground_truth.json" --json "$out/verify.json" || true
  echo
  echo "##### verify WITH the baseline"
  "$root/verify" --agent "$agent" --trajectory "$trajectory" "${version_flags[@]}" \
    --ground-truth "$out/$task_label.ground_truth.json" --baseline "$out/baseline.json" \
    --json "$out/verify-baseline.json" || true
} >"$out/report.txt" 2>&1
# The trace as verify read it (V-59): a line a reader of the log sees.
python3 - "$out/verify-baseline.json" <<'PY' || true
import json, sys
try:
    v = json.load(open(sys.argv[1]))
except (OSError, ValueError):
    sys.exit()
t, n = v.get("trace") or {}, len(v.get("trace_tampering") or [])
if t.get("state"):
    print("TRACE DELETED OR DAMAGED: %s, %d piece(s) of tampering evidence; the run is %s (V-59)" % (t["state"], n, v.get("outcome")))
elif n:
    print("TRACE TAMPERING: %d piece(s) of evidence; the run is %s (V-59)" % (n, v.get("outcome")))
PY
echo
echo "done. Read $out/report.txt"
