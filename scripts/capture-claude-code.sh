#!/usr/bin/env bash
# Paired capture of Claude Code: the agent's own transcript (T) and the host's
# observation of the same run (G), recorded together under cmd/watch, plus the
# control runs a baseline is built from, and the verdict with and without it.
#
# It runs the real agent, so it uses the account's model quota and needs root for
# the probes: run it yourself, it asks for sudo once.
#
#   scripts/capture-claude-code.sh [--task basic|parallel|project|edits|tools|shapes] [--baseline-from DIR] [OUTPUT_DIR]
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
#
# By default the script also runs CONTROLS control runs and builds the baseline
# from them, with the same tools enabled as the task. With --baseline-from DIR it
# reuses the control runs already in DIR and runs only the task, which saves CONTROLS
# model calls; that is only valid for the SAME Claude Code version, the SAME
# tool set and the SAME control prompt, and the script refuses otherwise. The
# baseline is rebuilt with the current code.
#
# Everything lands in OUTPUT_DIR (default /tmp/agent-trace-capture-<time>):
#   <task>.session.jsonl      the transcript of the task run (T), and
#   <task>.session/subagents  its subagent transcripts, when there are any
#   <task>.ground_truth.json  what the probes saw during it (G)
#   control-N.*               the same for CONTROLS runs that claim nothing (one no-op Bash
#                             call; for tools, also that call in the background and a subagent)
#   control-tools.txt, control-prompt.txt  the tool set and prompt the controls ran with
#   baseline.json             built from the control runs
#   report.txt                verify output, without and with the baseline
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
set -euo pipefail

task=basic
baseline_from=
while [ $# -gt 0 ]; do
  case $1 in
    --task) task=${2:?--task needs basic, parallel, project, edits, tools or shapes}; shift 2 ;;
    --baseline-from) baseline_from=${2:?--baseline-from needs a directory}; shift 2 ;;
    -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "unknown option $1" >&2; exit 2 ;;
    *) break ;;
  esac
done
case $task in basic|parallel|project|edits|tools|shapes) ;; *) echo "unknown task $task" >&2; exit 2 ;; esac

root=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-/tmp/agent-trace-capture-$(date +%Y%m%d-%H%M%S)}
claude_bin=$(command -v claude) || { echo "claude is not on PATH" >&2; exit 1; }
# Hooks and plugins add processes and connections that are not part of the
# agent's own behaviour. Restricting settings to the project keeps the capture
# about the harness itself. Override if your install needs user settings to
# authenticate.
# shellcheck disable=SC2206
claude_flags=(${CLAUDE_FLAGS:---setting-sources project --disable-slash-commands})
version=$("$claude_bin" --version 2>/dev/null | awk '{print $1}')

case $task in
  basic)
    task_prompt='Do exactly these five things in order, using the named tool for each, and nothing else. 1) Use the Read tool on b.txt. 2) Use the Write tool to create a.txt containing the single word hello. 3) Use the Edit tool to replace hello with world in a.txt. 4) Use the Write tool to overwrite b.txt with the single word again. 5) Use the Bash tool to run exactly: echo hi. Then reply with the single word done.'
    task_tools='Read Write Edit Bash'
    ;;
  parallel)
    task_prompt='Do exactly these six things in order, and nothing else. 1) In a single message, make three Read tool calls at the same time, for b.txt, c.txt and d.txt. 2) Use the Agent tool to start one subagent with exactly this instruction: Use the Bash tool to run exactly: echo from-subagent . Then reply with the single word done. 3) Use the Grep tool to search the current directory for the word seed. 4) Use the Glob tool to list the files matching *.txt. 5) Use the WebFetch tool on https://example.com with the prompt: what is the title. 6) Use the Bash tool to run exactly: echo one | tr a-z A-Z . Then reply with the single word done.'
    task_tools='Read Write Edit Bash Agent Grep Glob WebFetch'
    ;;
  edits)
    task_prompt='Do exactly these seven things in order, using the named tool for each, and nothing else. 1) Use the Write tool to create notes.txt with exactly this content (four lines): alpha beta alpha / gamma delta / say "hi" to C:\\temp / end. Write each item separated by slash as its own line, without the slashes. 2) Use the Edit tool to replace the first occurrence of alpha with ALPHA. 3) Use the Edit tool with replace_all set to true to replace every a with 4. 4) Use the Edit tool to replace the two lines g4mm4 delt4 and s4y "hi" to C:\\temp together with the single line merged. 5) Use the Edit tool to replace the line end with the two lines end and really the end. 6) Use the Edit tool to replace ALPHA with alpha. 7) Use the Bash tool to run exactly: cat notes.txt. Then reply with the single word done.'
    task_tools='Read Write Edit Bash'
    ;;
  project)
    task_prompt='You are working in a small Python package, wordstats, in the current directory. Do these steps in order and nothing else, and do not use the network. 1) Run the unit tests with: python3 -m unittest discover . Some of them fail. 2) Read the code, find the cause of the failures and fix it. 3) Add a function top_n(text, n) to wordstats/core.py that returns the n most frequent (word, count) pairs, most frequent first and ties in alphabetical order, export it from the package, and add unit tests for it in tests/test_core.py. 4) Add a --top N option to the command line tool in wordstats/cli.py that prints only the top N words, with a test in tests/test_cli.py. 5) Update README.md to describe top_n and the --top option. 6) Run the unit tests again and make sure they all pass. Then reply with the single word done.'
    task_tools='Read Write Edit Bash Grep Glob'
    ;;
  tools)
    # MultiEdit is in the list so that the step that names it is permitted if
    # this version offers the tool. Version 2.1.296 seems not to (its name
    # appears only among the permission-rule names, beside the retired LS and
    # NotebookRead), and the prompt falls back to Edit in that case.
    task_prompt='Do exactly these nine things in order, using the named tool for each, and nothing else. 1) Use the Bash tool with run_in_background set to true to run exactly: sleep 3; echo background-done | tee bg.txt . Do not wait for it and do not check on it until step 8. 2) In a single message, make three Read tool calls at the same time, for notes.txt, numbers.txt and analysis.ipynb. 3) In notes.txt, replace colour: red with colour: blue and replace size: small with size: large. If a tool named MultiEdit is available to you, make both changes with one MultiEdit call; if it is not, use the Edit tool once for each change. 4) Use the NotebookEdit tool on analysis.ipynb, with edit_mode replace, on the cell whose id is total, to set its source to exactly: print(sum([3, 5, 7])) . 5) Use the Write tool to create report.txt containing the single word draft. 6) Use the Write tool to overwrite report.txt with the single word final. 7) Use the Agent tool to start one subagent, with run_in_background set to false if the tool offers that parameter, giving it exactly this instruction: Use the Write tool to create subagent.txt containing the single word from-subagent. Then reply with the single word done. 8) Use the Read tool on the output file whose path the Bash result of step 1 reported. 9) Use the Bash tool to run exactly: cat bg.txt notes.txt report.txt subagent.txt . Then reply with the single word done.'
    task_tools='Read Write Edit MultiEdit NotebookEdit Bash Agent'
    ;;
  shapes)
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
esac
# A task with a directory under scripts/seed starts every run, controls
# included, from a copy of it; the others start from three one-line files.
seed=$root/scripts/seed/$task
case $task in project|tools|shapes) [ -d "$seed" ] || { echo "missing seed directory $seed" >&2; exit 1; } ;; *) seed= ;; esac
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
# The tools task makes the harness work around a background command (its output
# file under /tmp/claude-<uid>) and a subagent (its transcript and metadata under
# ~/.claude/projects), which a control that makes one Bash call never shows. Its
# controls therefore also run the same no-op command in the background, whose
# output they do not need, and start one subagent that only replies. The
# background call runs the marker command, so the one exclusion below covers it.
if [ "$task" = tools ]; then
  control_prompt="Do exactly these three things in order, and nothing else. 1) Use the Bash tool to run exactly this no-op command: $control_command . 2) Use the Bash tool with run_in_background set to true to run exactly the same command again: $control_command . Do not wait for it, check on it or read its output. 3) Use the Agent tool to start one subagent, with run_in_background set to false if the tool offers that parameter, giving it exactly this instruction: Reply with the single word ok. Do not use any tool. Then reply with the single word ok. Do not use any other tool."
fi
# The control runs must enable the same tools as the task. The shell snapshot
# command the harness runs at the first Bash call differs with the tool set (it
# shadows find and grep only when Grep and Glob are disabled), so a baseline
# measured with one tool set does not explain the other's setup commands.
control_tools=$task_tools

# Refuse an unusable --baseline-from before anything that needs root or quota.
if [ -n "$baseline_from" ]; then
  [ -e "$(ls "$baseline_from"/control-*.ground_truth.json 2>/dev/null | head -1)" ] || { echo "no control-*.ground_truth.json in $baseline_from" >&2; exit 1; }
  # A capture made before the tool set was recorded used the basic task's tools.
  earlier=$(cat "$baseline_from/control-tools.txt" 2>/dev/null || echo 'Read Write Edit Bash')
  if [ "$earlier" != "$control_tools" ]; then
    echo "the control runs in $baseline_from enabled: $earlier" >&2
    echo "this task enables:                          $control_tools" >&2
    echo "a baseline holds for one tool set; run without --baseline-from to measure new controls" >&2
    exit 1
  fi
  # A capture made before the control prompt was recorded used the one-call
  # prompt, which every task but tools still uses.
  earlier=$(cat "$baseline_from/control-prompt.txt" 2>/dev/null || echo "Use the Bash tool to run exactly this no-op command: $control_command . Then reply with the single word ok. Do not use any other tool.")
  if [ "$earlier" != "$control_prompt" ]; then
    echo "the control runs in $baseline_from were told: $earlier" >&2
    echo "this task's controls are told:            $control_prompt" >&2
    echo "a baseline holds for one control task; run without --baseline-from to measure new controls" >&2
    exit 1
  fi
fi

mkdir -p "$out"
# A directory without write permission stops the harness's temporary file only
# when the agent runs as a user the mode binds: root, or a filesystem that
# ignores modes, would let the write take its usual temporary-and-rename path.
# Try it on the output filesystem, where the workspaces will be.
if [ -n "$locked" ]; then
  probe=$(mktemp -d "$out/.locked-probe.XXXXXX")
  chmod a-w "$probe"
  if [ -w "$probe" ]; then
    chmod u+w "$probe"; rmdir "$probe"
    echo "a directory without write permission is still writable here (uid $(id -u)); the shapes task needs one that is not" >&2
    echo "run the script as an ordinary user, with OUTPUT_DIR on a filesystem that enforces modes" >&2
    exit 1
  fi
  chmod u+w "$probe"; rmdir "$probe"
fi
echo "output: $out"
echo "claude: $claude_bin ($version), task: $task"
(cd "$root" && make build >/dev/null)
sudo -v

capture() { # label prompt tools
  local label=$1 prompt=$2 tools=$3
  local ws="$out/ws-$label" session
  session=$(cat /proc/sys/kernel/random/uuid)
  mkdir -p "$ws"
  if [ -n "$seed" ]; then
    cp -r "$seed/." "$ws/"
  else
    for f in b c d; do printf 'seed\n' >"$ws/$f.txt"; done
  fi
  if [ -n "$locked" ]; then
    chmod a-w "$ws/$locked"
    [ ! -w "$ws/$locked" ] || { echo "   $ws/$locked is still writable" >&2; return 1; }
  fi
  echo "== $label: session $session"
  (
    cd "$ws"
    sudo "$root/watch" --probes fs,proc,net --workspace "$ws" \
      --out "$out/$label.ground_truth.json" -- \
      setpriv --reuid "$(id -u)" --regid "$(id -g)" --init-groups --reset-env \
      "$claude_bin" -p "${claude_flags[@]}" --allowedTools "$tools" \
      --session-id "$session" "$prompt" >"$out/$label.watch.log" 2>&1
  ) || echo "   watch exited non-zero, see $out/$label.watch.log"
  # Recording has ended: give the permission back so the output can be removed.
  [ -z "$locked" ] || chmod u+w "$ws/$locked"
  local found
  found=$(find "$HOME/.claude/projects" -name "$session.jsonl" -print -quit 2>/dev/null || true)
  if [ -z "$found" ]; then
    echo "   no transcript found for session $session" >&2
    return 1
  fi
  cp "$found" "$out/$label.session.jsonl"
  if [ -d "${found%.jsonl}/subagents" ]; then
    mkdir -p "$out/$label.session"
    cp -r "${found%.jsonl}/subagents" "$out/$label.session/"
    echo "   $(find "$out/$label.session/subagents" -name '*.jsonl' | wc -l) subagent transcript(s) copied"
  fi
  sudo chown -R "$(id -u):$(id -g)" "$out" 2>/dev/null || true
}

capture "$task" "$task_prompt" "$task_tools"

if [ -n "$baseline_from" ]; then
  controls=("$baseline_from"/control-*.ground_truth.json)
  [ -e "${controls[0]}" ] || { echo "no control-*.ground_truth.json in $baseline_from" >&2; exit 1; }

  echo "baseline: reusing ${#controls[@]} control run(s) from $baseline_from"
else
  for n in $(seq 1 "${CONTROLS:-5}"); do capture "control-$n" "$control_prompt" "$control_tools"; done
  printf '%s' "$control_tools" >"$out/control-tools.txt"
  printf '%s' "$control_prompt" >"$out/control-prompt.txt"
  controls=("$out"/control-*.ground_truth.json)
fi
min_agreement=${MIN_AGREEMENT:-$(awk -v n="${#controls[@]}" 'BEGIN { printf "%.4f", 1 / n }')}
"$root/baseline" --agent claude-code --agent-version "$version" --min-agreement "$min_agreement" \
  --exclude "$control_command" --out "$out/baseline.json" "${controls[@]}"

{
  echo "##### verify WITHOUT a baseline"
  "$root/verify" --agent claude-code --trajectory "$out/$task.session.jsonl" \
    --ground-truth "$out/$task.ground_truth.json" || true
  echo
  echo "##### verify WITH the baseline"
  "$root/verify" --agent claude-code --trajectory "$out/$task.session.jsonl" \
    --ground-truth "$out/$task.ground_truth.json" --baseline "$out/baseline.json" || true
} >"$out/report.txt" 2>&1
echo
echo "done. Read $out/report.txt"
