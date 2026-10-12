#!/bin/bash
# Read the JSON payload from the agent via stdin
INPUT=$(cat)

# Extract tool name and parameters
TOOL_NAME=$(echo "$INPUT" | jq -r '.toolCall.name // ""')
# The repository root: this script lives in .agents/scripts.
WORKSPACE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# 1. Prevent writing to files outside the workspace
if [ "$TOOL_NAME" = "write_to_file" ] || [ "$TOOL_NAME" = "replace_file_content" ]; then
  TARGET_FILE=$(echo "$INPUT" | jq -r '.toolCall.args.TargetFile // ""')
  if [[ "$TARGET_FILE" != "$WORKSPACE"* ]]; then
    echo '{"decision": "force_ask", "reason": "YOLO paused: Attempting to modify a file outside the workspace."}'
    exit 0
  fi
fi

if [ "$TOOL_NAME" = "run_command" ]; then
  CMD=$(echo "$INPUT" | jq -r '.toolCall.args.CommandLine // ""')
  
  # 2. Block git add, git commit, and git push
  if echo "$CMD" | grep -iqE "git\s+(add|commit|push)"; then
    echo '{"decision": "force_ask", "reason": "YOLO paused: git add, commit, or push requires confirmation."}'
    exit 0
  fi
  
  # 3. Block remote script execution (e.g., curl ... | bash)
  if echo "$CMD" | grep -iqE "(curl|wget)[^|]*\|\s*(bash|sh|zsh)"; then
    echo '{"decision": "force_ask", "reason": "YOLO paused: Executing remote downloaded scripts is not allowed."}'
    exit 0
  fi
  
  # 4. Block potentially dangerous 'rm' outside the workspace
  # Flags 'rm' if it uses an absolute path (/) that isn't inside our workspace, or if it navigates up (../)
  if echo "$CMD" | grep -iqE "rm\s+"; then
    if echo "$CMD" | grep -qE "rm\s+.*(/[^ ]+)" && ! echo "$CMD" | grep -q "$WORKSPACE"; then
      echo '{"decision": "force_ask", "reason": "YOLO paused: Dangerous rm with absolute path outside workspace."}'
      exit 0
    fi
    if echo "$CMD" | grep -qE "rm\s+.*\.\./"; then
      echo '{"decision": "force_ask", "reason": "YOLO paused: Dangerous rm using relative paths (../)."}'
      exit 0
    fi
  fi
fi

# Auto-allow everything else (YOLO)
echo '{"decision": "allow"}'
