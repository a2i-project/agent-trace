#!/usr/bin/env bash
# Paired capture of Claude Code: the agent's own transcript (T) and the host's
# observation of the same run (G), recorded together under cmd/watch, plus the
# control runs a baseline is built from, and the verdict with and without it.
#
# It runs the real agent, so it uses the account's model quota (five short
# calls) and needs root for the probes: run it yourself, it asks for sudo once.
#
#   scripts/capture-claude-code.sh [OUTPUT_DIR]
#
# Everything lands in OUTPUT_DIR (default /tmp/agent-trace-capture-<time>):
#   task.session.jsonl     the transcript of the task run (T)
#   task.ground_truth.json what the probes saw during it (G)
#   control-N.*            the same for three runs that claim nothing
#   baseline.json          built from the control runs
#   report.txt             verify output, without and with the baseline
#
# The task is small and fixed so the result can be compared across versions.
# Claude Code runs as you (setpriv execs it in place, so it keeps the pid watch
# records as the root of the process tree) with your credentials.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-/tmp/agent-trace-capture-$(date +%Y%m%d-%H%M%S)}
claude_bin=$(command -v claude) || { echo "claude is not on PATH" >&2; exit 1; }
# Hooks and plugins add processes and connections that are not part of the
# agent's own behaviour. Restricting settings to the project keeps the capture
# about the harness itself. Override if your install needs user settings to
# authenticate.
claude_flags=(${CLAUDE_FLAGS:---setting-sources project --disable-slash-commands})
version=$("$claude_bin" --version 2>/dev/null | awk '{print $1}')

task_prompt='Do exactly these five things in order, using the named tool for each, and nothing else. 1) Use the Read tool on b.txt. 2) Use the Write tool to create a.txt containing the single word hello. 3) Use the Edit tool to replace hello with world in a.txt. 4) Use the Write tool to overwrite b.txt with the single word again. 5) Use the Bash tool to run exactly: echo hi. Then reply with the single word done.'
control_prompt='Reply with the single word ok. Do not use any tools.'

mkdir -p "$out"
echo "output: $out"
echo "claude: $claude_bin ($version)"
(cd "$root" && make build >/dev/null)
sudo -v

capture() { # label prompt
  local label=$1 prompt=$2
  local ws="$out/ws-$label" session
  session=$(cat /proc/sys/kernel/random/uuid)
  mkdir -p "$ws"
  printf 'seed\n' >"$ws/b.txt"
  echo "== $label: session $session"
  (
    cd "$ws"
    sudo "$root/watch" --probes fs,proc,net --workspace "$ws" \
      --out "$out/$label.ground_truth.json" -- \
      setpriv --reuid "$(id -u)" --regid "$(id -g)" --init-groups --reset-env \
      "$claude_bin" -p "${claude_flags[@]}" --allowedTools "Read Write Edit Bash" \
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
  fi
  sudo chown -R "$(id -u):$(id -g)" "$out" 2>/dev/null || true
}

capture task "$task_prompt"
for n in 1 2 3; do capture "control-$n" "$control_prompt"; done

"$root/baseline" --agent claude-code --agent-version "$version" --out "$out/baseline.json" \
  "$out"/control-*.ground_truth.json

{
  echo "##### verify WITHOUT a baseline"
  "$root/verify" --agent claude-code --trajectory "$out/task.session.jsonl" \
    --ground-truth "$out/task.ground_truth.json" || true
  echo
  echo "##### verify WITH the baseline"
  "$root/verify" --agent claude-code --trajectory "$out/task.session.jsonl" \
    --ground-truth "$out/task.ground_truth.json" --baseline "$out/baseline.json" || true
} >"$out/report.txt" 2>&1
echo
echo "done. Read $out/report.txt"
