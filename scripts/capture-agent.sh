#!/usr/bin/env bash
# Paired capture of an agent: the agent's own transcript (T) and the host's
# observation of the same run (G), recorded together under cmd/watch, plus the
# control runs a baseline is built from, and the verdict with and without it.
# The agent is any adapter config/agents.json profiles (schema 2), the
# profile's default_agent unless --agent names another; today claude-code
# (Claude Code) and gemini (Gemini through Antigravity's CLI, agy). The
# profile says how the agent is found, version-checked, locked, pinned,
# isolated, invoked and recorded, and which tasks it has; this script never
# names an agent. scripts/capture-claude-code.sh is kept as a wrapper that
# runs this script, so earlier commands still work.
#
# It runs the real agent, so it uses the account's model quota and needs root for
# the probes: run it yourself, it asks for sudo once.
#
#   scripts/capture-agent.sh [--agent AGENT] [--task TASK] [--baseline-from DIR]
#                            [--model ID] [--controls-before N] [--heldout-dir DIR]
#                            [--allow-unconfigured-version] [--content] [--check]
#                            [--no-build] [OUTPUT_DIR]
#
# The tasks are the profile's: Claude Code has basic, parallel, project,
# edits, tools, shapes, long and websearch; Gemini has basic, search and long.
# Either agent also runs a held-out task, --task heldout:NAME with
# --heldout-dir DIR (below).
#
# --model ID pins the model of every run, controls included (D7), passed where
# the profile's invocation says ({model}); without it the profile's
# model.default is pinned (claude-sonnet-5-5 for Claude Code,
# gemini-3.8-flash-high for agy, the id the existing captures recorded). After
# each run the script reads the model the transcript records, by the
# profile's trace method (jsonl-session: the model of every assistant record;
# sqlite-conversation: the executor model of the conversation database), and stops
# with MODEL MISMATCH, exit 1, when it is not the pinned one, so a default the
# agent does not accept as that id fails the first run, not silently. The
# result of each check is in order.tsv.
# --controls-before N records N of the CONTROLS control runs before the task and
# the rest after it (D11; default 0, the task first); the order is written to
# control-order.txt and order.tsv. It cannot be combined with --baseline-from.
# Version lock (D6): every run gets the profile's version_lock.env in its
# environment (Claude Code DISABLE_UPDATES=1, agy AGY_CLI_DISABLE_AUTO_UPDATE=true),
# and the script refuses when the profile's version_lock.require_setting does
# not hold (Claude Code: settings.json of the user, $CLAUDE_CONFIG_DIR or
# ~/.claude, sets env.DISABLE_UPDATES to "1", since --setting-sources project,
# the profile's isolation, ignores the user's settings). The environment the
# profile's pass_env names must be set; it is passed to the run.
# --heldout-dir DIR holds held-out tasks (D8) outside the repository, one
# directory NAME each with prompt.txt, tools.txt (the task's tools, separated by
# white space) and an optional seed/ that every run starts from. The script
# refuses a DIR inside the repository, never copies it and never prints the
# prompt; task-meta.txt records the SHA-256 of the prompt and of the seed.
#
# --content turns on the net probe's content capture by the profile's content
# method; every run, controls included, is recorded with it, since content
# events change what a baseline must explain. The method tls-symbols hooks the
# TLS library its library parameter names (watch --net-exe-path; Claude Code:
# {binary}, the file the claude command resolves to, which carries its own TLS
# library). The method none refuses --content with the profile's reason (agy
# links no TLS library the probe can hook), and so does a method this script
# does not implement.
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
#   <task>.session.jsonl      the transcript of the task run (T), named by the profile's
#                             trace.file (agy: <task>.conversation.db), and
#   <task>.session/subagents  its subagent transcripts, when there are any (trace.subagents)
#   <task>.ground_truth.json  what the probes saw during it (G)
#   <task>.trace.txt          for a declared trace (trace.declared, I-74; Claude Code):
#                             what the copied transcript holds, read, empty
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
#                             sqlite-conversation, the subagent databases copied, calls not
#                             counted: -)
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
# The agent runs as you (setpriv execs it in place, so it keeps the pid watch
# records as the root of the process tree) with your credentials, in print
# mode, with the argument list of the profile's invocation. If its login has
# expired, log in first (Claude Code: `claude auth login`; agy: run it once
# interactively). The profile's methods (I-47, I-48 for agy):
#   * tool_set: list passes the task's tools as one argument ({tool_set};
#     Claude Code --allowedTools); agent-md writes a custom agent NAME into
#     every run's workspace as DIR/NAME/agent.md, which lists the task's tools
#     and inherits neither your MCP servers nor your customizations, and
#     passes NAME ({tool_set}; agy --agent agent-trace), so the controls have
#     the task's tool set (I-24);
#   * session: assigned gives every run a fresh id ({session}; Claude Code
#     --session-id); stdout-json reads the id the agent prints as the
#     profile's key (agy --output-format json, conversation_id);
#   * trace: jsonl-session finds <session>.jsonl under the profile's dir
#     (~/.claude/projects) and copies it, with its subagents/ directory;
#     sqlite-conversation copies <session>.db from the profile's dir
#     (~/.gemini/antigravity-cli/conversations) with its write-ahead log, and,
#     since a subagent keeps its steps in a database of its own in the same
#     directory (I-55), every other database that appeared there during the
#     run, as the subagent databases where the adapter looks for the
#     subagents the conversation names. Do not use agy elsewhere during a
#     capture: its conversations would be copied too (they are never read
#     unless the run names them);
#   * params: per-task values an invocation names ({print_timeout}: agy -p
#     gives up after it, 600s, and 5400s for long and held-out tasks).
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
#             grep_search, find_by_name and invoke_subagent. No network.
# The controls run the no-op command with the profile's controls.command_tool
# (Bash, run_command) and the profile's control prompt; for a task whose tools
# include the subagent tool, the prompt_subagent one, and a task's own
# control_prompt (Claude Code tools) wins over both.
#
# Controls and subagents (I-71): the controls of any task whose tool set holds
# the profile's subagent tool (Claude Code Agent, agy invoke_subagent) also start one
# subagent that only replies, so the baseline measures the harness's own
# subagent bookkeeping (Claude Code: the subagent's agent-<id>.jsonl and
# .meta.json under the session's directory). After each control the script
# counts the subagents the run started and, for the jsonl-session trace, the
# tool calls they made, writes both to order.tsv and prints a WARNING when a control
# started other than one subagent or its subagent used a tool; the run is kept.
set -euo pipefail
# Ctrl+C reaches watch, which stops the agent and writes what it recorded; the
# script then stops too, before it would start the next run.
trap 'echo "interrupted" >&2; exit 130' INT TERM

agent=
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
    --agent) agent=${2:?--agent needs an agent name}; shift 2 ;;
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
root=$(cd "$(dirname "$0")/.." && pwd)
# The agent's profile (config/agents.json, schema 2; $AGENT_TRACE_CONFIG
# overrides the file): every p_* variable below comes from it. An unknown
# agent or task is refused here.
agent_config=${AGENT_TRACE_CONFIG:-$root/config/agents.json}
[ -f "$agent_config" ] || { echo "no agent version config at $agent_config" >&2; exit 1; }
profile=$(python3 "$root/scripts/agent-profile.py" shell "$agent_config" "$agent" "$task") || exit $?
eval "$profile"
agent=$p_agent
case $controls_before in ''|*[!0-9]*) echo "--controls-before must be a number" >&2; exit 2 ;; esac
[ "${CONTROLS:-5}" -ge "$controls_before" ] 2>/dev/null || { echo "--controls-before $controls_before is more than the ${CONTROLS:-5} control runs (CONTROLS)" >&2; exit 2; }
if [ "$controls_before" -gt 0 ] && [ -n "$baseline_from" ]; then
  echo "--controls-before orders the control runs of this capture; --baseline-from takes none" >&2
  exit 2
fi
# The label of the task run's files: a held-out task heldout:NAME is heldout-NAME.
task_label=${task//:/-}

out=${1:-/tmp/agent-trace-capture-$(date +%Y%m%d-%H%M%S)}
# Every later step names the output by this path, some after changing
# directory, so a relative path is made absolute here.
out=$(realpath -m -- "$out")
# A content method this script does not implement refuses, as none does.
if [ -n "$content" ]; then
  case $p_content_method:$p_content_parser in
    tls-symbols:http1 | tls-symbols:) ;;
    none:*) echo "--content needs a TLS library the net probe can hook; $p_content_reason" >&2; exit 1 ;;
    *) echo "--content: the content method $p_content_method (parser '${p_content_parser}') of $agent's profile is not implemented in this build" >&2; exit 1 ;;
  esac
fi
agent_bin=$(command -v "$p_binary") || { echo "$p_binary is not on PATH" >&2; exit 1; }
# The model is pinned (D7), by default to the profile's; --model overrides it.
# The check after each run reads the transcript, so an id the agent does not
# run under fails the run as MODEL MISMATCH.
model=${model:-$p_model_default}
# Version lock (D6, protocol 6.1): an agent that updates itself during a
# campaign mixes versions. A setting the lock needs that the runs' isolation
# ignores is checked in the settings file; version_lock.env is passed to
# every run (below).
if [ -n "$p_require" ]; then
  settings_dir=
  [ -z "$p_require_dir_env" ] || settings_dir=${!p_require_dir_env:-}
  [ -n "$settings_dir" ] || settings_dir=${p_require_dir/#\~/$HOME}
  agent_settings=$settings_dir/$p_require_file
  python3 "$root/scripts/agent-profile.py" setting "$agent_settings" "$p_require_key" "$p_require_value" || {
    echo "$agent_settings must set $p_require_key to \"$p_require_value\": $p_require_why" >&2
    exit 1
  }
fi
# The settings isolation (the profile's isolation.flags, {isolation} in its
# invocation): hooks and plugins add processes and connections that are not
# part of the agent's own behaviour. isolation.override_env, when set and not
# empty, replaces the flags, for an install that needs user settings to
# authenticate.
agent_flags=("${p_isolation[@]}")
if [ -n "$p_isolation_env" ] && [ -n "${!p_isolation_env:-}" ]; then
  # shellcheck disable=SC2206
  agent_flags=(${!p_isolation_env})
fi
version=$("$agent_bin" "${p_version_args[@]}" 2>/dev/null | awk -v last="$([ "$p_version_field" = last ] && echo 1)" '{print (last ? $NF : $1)}')
[ -n "$version" ] || { echo "$p_binary ${p_version_args[*]} printed nothing" >&2; exit 1; }
# The environment the agent needs from the session (agy logs in through the
# Secret Service on the session bus); setpriv --reset-env below clears the
# environment, so it is passed again.
run_env=()
missing_env=()
for v in "${p_pass_env[@]}"; do
  if [ -n "${!v:-}" ]; then run_env+=("$v=${!v}"); else missing_env+=("$v"); fi
done
if [ "${#missing_env[@]}" -gt 0 ]; then
  n=${#p_pass_env[@]}
  names=${p_pass_env[*]:0:n-1}
  names=${names// /, }
  [ "$n" -eq 1 ] && names=${p_pass_env[0]} || names="$names and ${p_pass_env[n-1]}"
  echo "$names must be set: $p_pass_env_why" >&2
  exit 1
fi
run_env+=("${p_lock_env[@]}")
trace_dir=${p_trace_dir/#\~/$HOME}
# What watch records besides the probes' defaults. Content capture by
# tls-symbols hooks the TLS library its library parameter names ({binary}
# is the file the agent's command resolves to).
watch_mode=identity
watch_flags=()
if [ -n "$content" ]; then
  watch_mode=content
  watch_flags=(--net-exe-path "$(readlink -f "${p_content_library//\{binary\}/"$agent_bin"}")")
fi

# The adapter's shapes, id families and hosts were measured on the versions
# config/agents.json lists (I-57); on another version they may silently not fit.
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

# A built-in task's prompt and tool set are the profile's (tasks.TASK).
if [ -n "$p_task_builtin" ]; then
  task_prompt=$p_task_prompt
  task_tools=$p_task_tools
fi
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
# The profile's control prompts name the command as {command}. agy's
# harness writes its agentapi shim and opens a pseudo-terminal before every
# command (I-48), so its controls run one too.
fill() { printf '%s' "${1//\{command\}/"$control_command"}"; }
control_prompt=$(fill "$p_control_prompt")
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
# action a rule could take (an agy subagent answers its caller with a
# send_message call, so its profile's instruction forbids commands and files
# rather than every tool).
subagent_tool=$p_subagent_tool
control_subagent=
case " $control_tools " in *" $subagent_tool "*) control_subagent=1 ;; esac
if [ -n "$p_task_control_prompt" ]; then
  # A task's own control prompt: the tools task also makes the harness work
  # around a background command (its output file under the harness's
  # temporary directory), so its controls also run the same no-op command in
  # the background, whose output they do not need. The background call runs
  # the marker command, so the one exclusion below covers it.
  control_prompt=$(fill "$p_task_control_prompt")
elif [ -n "$control_subagent" ]; then
  control_prompt=$(fill "$p_control_prompt_subagent")
fi
# A control makes one command call, so its tool set must offer one.
need_tool=$p_command_tool
case " $control_tools " in *" $need_tool "*) ;; *) echo "the tool set of this task ($control_tools) lacks $need_tool, which the controls need" >&2; exit 1 ;; esac

# Refuse an unusable --baseline-from before anything that needs root or quota.
if [ -n "$baseline_from" ]; then
  [ -e "$(ls "$baseline_from"/control-*.ground_truth.json 2>/dev/null | head -1)" ] || { echo "no control-*.ground_truth.json in $baseline_from" >&2; exit 1; }
  # A capture made before the agent was recorded is of the agent the config's
  # unrecorded record names (Claude Code).
  earlier=$(cat "$baseline_from/control-agent.txt" 2>/dev/null || echo "$p_unrecorded_agent")
  if [ "$earlier" != "$agent" ]; then
    echo "the control runs in $baseline_from are of $earlier, this capture is of $agent" >&2
    exit 1
  fi
  # A capture made before the tool set was recorded used the basic task's tools.
  earlier=$(cat "$baseline_from/control-tools.txt" 2>/dev/null || echo "$p_unrecorded_control_tools")
  if [ "$earlier" != "$control_tools" ]; then
    echo "the control runs in $baseline_from enabled: $earlier" >&2
    echo "this task enables:                          $control_tools" >&2
    echo "a baseline holds for one tool set; run without --baseline-from to measure new controls" >&2
    exit 1
  fi
  # A capture made before the control prompt was recorded used the one-call
  # prompt, which every task without the subagent tool still uses.
  earlier=$(cat "$baseline_from/control-prompt.txt" 2>/dev/null || fill "$p_unrecorded_control_prompt")
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
echo "$p_binary: $agent_bin ($version), task: $task"
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

# trace_path LABEL: the copied transcript of a run, as the profile's
# trace.file names it.
trace_path() { printf '%s/%s' "$out" "${p_trace_file//\{label\}/"$1"}"; }
subagents_path() { printf '%s/%s' "$out" "${p_trace_subagents//\{label\}/"$1"}"; }

# agent_md TOOLS: the custom agent of the agent-md tool set method (I-24):
# the task's tools only, none of the user's MCP servers or customizations.
agent_md() { # tools
  printf -- '---\nname: %s\ndescription: Runs the exact steps it is given for a trajectory capture.\n' "$p_tool_set_name"
  printf -- 'mainAgent: true\nsubagent: false\ninheritMcp: false\ninheritCustomizations: false\ntools:\n'
  for t in $1; do printf -- '  - %s\n' "$t"; done
  printf -- '---\n# %s\nDo exactly what the user asks, using the named tools, and nothing else.\n' "$p_tool_set_name"
}

# invocation PROMPT TOOL_SET: the profile's invocation with its placeholders
# filled, into the array argv.
invocation() { # prompt tool_set
  local w p
  argv=()
  for w in "${p_invocation[@]}"; do
    case $w in
      '{isolation}') argv+=("${agent_flags[@]}") ;;
      '{model}') argv+=("$model") ;;
      '{tool_set}') argv+=("$2") ;;
      '{session}') argv+=("$session") ;;
      '{prompt}') argv+=("$1") ;;
      '{'*'}') p=p_param_${w:1:${#w}-2}; p=${p//-/_}; argv+=("${!p}") ;;
      *) argv+=("$w") ;;
    esac
  done
}

capture_one() { # label prompt tools role
  local label=$1 prompt=$2 tools=$3 role=$4
  local ws="$out/ws-$label" tool_set rc=0
  session=
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
  case $p_tool_set_method in
    list) tool_set=$tools ;;
    agent-md)
      mkdir -p "$ws/$p_tool_set_dir/$p_tool_set_name" || return 1
      agent_md "$tools" >"$ws/$p_tool_set_dir/$p_tool_set_name/agent.md" || return 1
      tool_set=$p_tool_set_name
      ;;
  esac
  case $p_session_method in
    assigned) session=$(cat /proc/sys/kernel/random/uuid); echo "== $label: session $session" ;;
    stdout-json) echo "== $label" ;;
  esac
  # The databases that exist before the run: any other one after it is the
  # run's own or a subagent's (I-55).
  [ "$p_trace_method" != sqlite-conversation ] || before=$(ls "$trace_dir" 2>/dev/null | grep '\.db$' || true)
  invocation "$prompt" "$tool_set"
  local wrc=0
  (
    cd "$ws"
    measured "$label" sudo "$root/watch" --probes fs,proc,net "${watch_flags[@]}" --workspace "$ws" \
      --out "$out/$label.ground_truth.json" -- \
      setpriv --reuid "$(id -u)" --regid "$(id -g)" --init-groups --reset-env \
      env "${run_env[@]}" \
      "$agent_bin" "${argv[@]}" >"$out/$label.watch.log" 2>&1
  ) || wrc=$?
  printf '%s\n' "$wrc" >"$out/$label.watch.exit"
  [ "$wrc" -eq 0 ] || echo "   watch exited non-zero, see $out/$label.watch.log (exit $wrc)"
  # Recording has ended: give the permission back so the output can be removed.
  [ -z "$locked" ] || chmod u+w "$ws/$locked"
  # stdout-json: the agent prints one JSON object with the session id.
  [ "$p_session_method" != stdout-json ] ||
    session=$(grep -o "\"$p_session_key\":\"[0-9a-f-]*\"" "$out/$label.watch.log" | head -1 | cut -d'"' -f4 || true)
  case $p_trace_method in
    jsonl-session) collect_jsonl_session "$label" || rc=$? ;;
    sqlite-conversation) collect_sqlite_conversation "$label" || rc=$? ;;
  esac
  [ "$rc" -eq 3 ] || return "$rc"
  if [ -n "$p_trace_declared" ] && [ "$role" = task ]; then
    # The task's declared trace is gone after the run: a result, not a
    # harness error (V-59, I-75). The ground truth is kept, and verify reports
    # that the trace cannot be verified, with what the probes saw happen to it.
    echo "   TRACE DELETED OR DAMAGED: $trace_gone; verify reports it (V-59)" >&2
    printf 'missing\n' >"$out/$label.trace.txt"
    sudo chown -R "$(id -u):$(id -g)" "$out" 2>/dev/null || true
    return 0
  fi
  echo "   $trace_missing" >&2
  return 1
}

# The trace methods. Each copies the run's transcript to trace_path and its
# subagents' to subagents_path, or sets trace_gone and trace_missing (what is
# said for a declared task trace that is gone, and for any other) and
# returns 3.

# jsonl-session: <session>.jsonl under the profile's dir, with the subagent
# transcripts in the <session>/subagents directory beside it.
collect_jsonl_session() { # label
  local label=$1 found subs
  found=$(find "$trace_dir" -name "$session.jsonl" -print -quit 2>/dev/null || true)
  if [ -z "$found" ]; then
    trace_gone="no transcript for session $session after the run"
    trace_missing="no transcript found for session $session"
    return 3
  fi
  cp "$found" "$(trace_path "$label")" || return 1
  if [ -d "${found%.jsonl}/subagents" ]; then
    subs=$(subagents_path "$label")
    mkdir -p "$(dirname "$subs")" || return 1
    cp -r "${found%.jsonl}/subagents" "$subs"
    echo "   $(find "$subs" -name '*.jsonl' | wc -l) subagent transcript(s) copied"
  fi
  sudo chown -R "$(id -u):$(id -g)" "$out" 2>/dev/null || true
}

# sqlite-conversation: <session>.db in the profile's dir with its write-ahead
# log, and every other database that appeared there during the run as a
# subagent's (I-55).
collect_sqlite_conversation() { # label
  local label=$1 f sid n=0 file subs
  sudo chown -R "$(id -u):$(id -g)" "$out" 2>/dev/null || true
  if [ -z "$session" ] || [ ! -f "$trace_dir/$session.db" ]; then
    trace_missing="no conversation database found for $label (id '${session}'), see $out/$label.watch.log"
    trace_gone=$trace_missing
    return 3
  fi
  echo "   conversation $session"
  file=$(trace_path "$label")
  subs=$(subagents_path "$label")
  cp "$trace_dir/$session.db" "$file" || return 1
  # A write-ahead log that the agent left unmerged holds steps too.
  [ ! -s "$trace_dir/$session.db-wal" ] || cp "$trace_dir/$session.db-wal" "$file-wal"
  for f in "$trace_dir"/*.db; do
    sid=$(basename "$f" .db)
    [ -f "$f" ] && [ "$sid" != "$session" ] || continue
    ! grep -qxF "$sid.db" <<<"$before" || continue
    mkdir -p "$subs"
    cp "$f" "$subs/$sid.db"
    [ ! -s "$f-wal" ] || cp "$f-wal" "$subs/$sid.db-wal"
    n=$((n + 1))
  done
  [ "$n" -eq 0 ] || echo "   $n subagent conversation database(s) copied"
}

# The models a run's transcript records (D7), read by the profile's trace
# method. Prints observed=<models of the main transcript>;subagents=<models of
# its subagents' transcripts, not checked>; exits 0 when the main transcript
# records the pinned model and no other, 1 when it records another, 2 when it
# records none.
model_seen() { # label
  python3 - "$p_trace_method" "$(trace_path "$1")" "$(subagents_path "$1")" "$model" <<'PY'
import json, os, re, shutil, sqlite3, sys, tempfile
method, path, subdir, want = sys.argv[1:]

def jsonl(p):
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

def sqlite(p):
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

if method == "sqlite-conversation":
    main, subs = sqlite(path), set()
else:
    main, subs = jsonl(path), set()
    if os.path.isdir(subdir):
        for f in sorted(os.listdir(subdir)):
            if f.endswith(".jsonl"):
                subs |= jsonl(os.path.join(subdir, f))
print("observed=%s;subagents=%s" % (",".join(sorted(main)), ",".join(sorted(subs))))
sys.exit(2 if not main else (0 if main == {want} else 1))
PY
}

# The subagents a recorded run started (I-71), by the profile's trace method:
# for jsonl-session the subagent transcripts copied beside the run's and the
# tool calls their assistant records make; for sqlite-conversation the
# subagent databases copied, whose calls are not counted (-). Prints
# subagents=N;subagent_tool_calls=M.
subagents_seen() { # label
  python3 - "$p_trace_method" "$(subagents_path "$1")" <<'PY'
import glob, json, os, sys
method, subdir = sys.argv[1:]
if method == "sqlite-conversation":
    print("subagents=%d;subagent_tool_calls=-" % len(glob.glob(subdir + "/*.db")))
    sys.exit(0)
files = sorted(glob.glob(subdir + "/*.jsonl"))
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

# trace_state FILE: what a declared jsonl-session transcript holds as the
# capture left it (V-59): missing, empty, damaged (no line is a JSON object, or a line is
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
  if [ "$rc" -eq 0 ] && [ "$role" = task ] && [ -n "$p_trace_declared" ]; then
    # A task transcript that is gone, empty or holds no record that parses
    # cannot be checked for its model: its run is a trace result, not a
    # model mismatch (V-59, I-75).
    [ -f "$out/$label.trace.txt" ] || trace_state "$(trace_path "$label")" >"$out/$label.trace.txt"
  fi
  if [ "$rc" -eq 0 ] && [ -f "$out/$label.trace.txt" ] && [ "$(cat "$out/$label.trace.txt")" != read ]; then
    mrc=trace-$(cat "$out/$label.trace.txt")
  elif [ "$rc" -eq 0 ]; then
    seen=$(model_seen "$label") || mrc=$?
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

trajectory=$(trace_path "$task_label")
# A version the config does not list makes the verdict INCONCLUSIVE (I-57).
# A transcript whose format does not state its version (trace.states_version
# false; agy's conversation) gets it passed; so does a declared one that is
# gone or garbled, which verify reports as a trace it cannot verify (V-59). A
# declared transcript was copied as the run left it, so verify compares it
# with the last content the probe hashed.
version_flags=(--strict-version)
[ -n "$p_trace_states_version" ] || version_flags+=(--agent-version "$version")
if [ -n "$p_trace_declared" ]; then
  version_flags+=(--check-trace-hash)
  [ -z "$p_trace_states_version" ] || [ "$(cat "$out/$task_label.trace.txt" 2>/dev/null || echo read)" = read ] || version_flags+=(--agent-version "$version")
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
