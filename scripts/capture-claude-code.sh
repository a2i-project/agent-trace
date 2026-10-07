#!/usr/bin/env bash
# Paired capture of Claude Code: the agent's own transcript (T) and the host's
# observation of the same run (G), recorded together under cmd/watch, plus the
# control runs a baseline is built from, and the verdict with and without it.
#
# It runs the real agent, so it uses the account's model quota and needs root for
# the probes: run it yourself, it asks for sudo once.
#
#   scripts/capture-claude-code.sh [--task basic|parallel] [--baseline-from DIR] [OUTPUT_DIR]
#
# Tasks (both small and fixed, so results compare across versions):
#   basic     Read, Write (create), Edit, Write (overwrite), Bash. Five calls.
#   parallel  three Reads in one message, a subagent that runs Bash, Grep, Glob,
#             WebFetch of https://example.com, and a Bash pipeline. It covers what
#             `basic` does not (docs/todo/adapters.md ADP-1), and needs the network.
#
# By default the script also runs three control runs and builds the baseline from
# them, with the same tools enabled as the task. With --baseline-from DIR it
# reuses the control runs already in DIR and runs only the task, which saves three
# model calls; that is only valid for the SAME Claude Code version and the SAME
# tool set, and the script refuses otherwise. The baseline is rebuilt with the
# current code.
#
# Everything lands in OUTPUT_DIR (default /tmp/agent-trace-capture-<time>):
#   <task>.session.jsonl      the transcript of the task run (T), and
#   <task>.session/subagents  its subagent transcripts, when there are any
#   <task>.ground_truth.json  what the probes saw during it (G)
#   control-N.*               the same for three runs that claim nothing (one no-op Bash call)
#   baseline.json             built from the control runs
#   report.txt                verify output, without and with the baseline
#
# MIN_AGREEMENT (default 1) is passed to baseline: the fraction of control runs
# that must perform an action for it to count as the harness's. Some activity is
# occasional, so lower it if the task run shows unexplained harness commands.
#
# Claude Code runs as you (setpriv execs it in place, so it keeps the pid watch
# records as the root of the process tree) with your credentials. If the CLI login
# has expired, run `claude auth login` first.
set -euo pipefail

task=basic
baseline_from=
while [ $# -gt 0 ]; do
  case $1 in
    --task) task=${2:?--task needs basic or parallel}; shift 2 ;;
    --baseline-from) baseline_from=${2:?--baseline-from needs a directory}; shift 2 ;;
    -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "unknown option $1" >&2; exit 2 ;;
    *) break ;;
  esac
done
case $task in basic|parallel) ;; *) echo "unknown task $task" >&2; exit 2 ;; esac

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
esac
# The control claims nothing worth verifying, but it must use Bash once: the
# harness runs setup commands the first time a session uses Bash (probing the
# environment, writing a shell snapshot), and a baseline taken without a Bash
# call would not contain them. The command is a no-op with a marker name, so the
# rule the baseline records for it hides nothing.
control_prompt='Use the Bash tool to run exactly this no-op command: : agent-trace-control-marker . Then reply with the single word ok. Do not use any other tool.'
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
fi

mkdir -p "$out"
echo "output: $out"
echo "claude: $claude_bin ($version), task: $task"
(cd "$root" && make build >/dev/null)
sudo -v

capture() { # label prompt tools
  local label=$1 prompt=$2 tools=$3
  local ws="$out/ws-$label" session
  session=$(cat /proc/sys/kernel/random/uuid)
  mkdir -p "$ws"
  for f in b c d; do printf 'seed\n' >"$ws/$f.txt"; done
  echo "== $label: session $session"
  (
    cd "$ws"
    sudo "$root/watch" --probes fs,proc,net --workspace "$ws" \
      --out "$out/$label.ground_truth.json" -- \
      setpriv --reuid "$(id -u)" --regid "$(id -g)" --init-groups --reset-env \
      "$claude_bin" -p "${claude_flags[@]}" --allowedTools "$tools" \
      --session-id "$session" "$prompt" >"$out/$label.watch.log" 2>&1
  ) || echo "   watch exited non-zero, see $out/$label.watch.log"
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
  for n in 1 2 3; do capture "control-$n" "$control_prompt" "$control_tools"; done
  printf '%s' "$control_tools" >"$out/control-tools.txt"
  controls=("$out"/control-*.ground_truth.json)
fi
"$root/baseline" --agent claude-code --agent-version "$version" --min-agreement "${MIN_AGREEMENT:-1}" \
  --out "$out/baseline.json" "${controls[@]}"

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
