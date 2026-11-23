#!/usr/bin/env bash
# Runs as agenttrace in the guest (vm/login.sh): the sign-ins of
# integration-tools' agenttrace-install.sh, each asked for first, with the
# agents' version locks set. OpenCode needs none: its key reaches each run
# from the operator's environment (secret_env).
set -u
cd "$HOME" || exit 1
export PATH="$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin"
nobus() { env -u DBUS_SESSION_BUS_ADDRESS -u XDG_RUNTIME_DIR "$@"; }
ask() { printf '\n%s [y/N] ' "$1"; read -r a; [ "$a" = y ] || [ "$a" = Y ]; }
echo "Each sign-in prints a link or a code: open it in your browser and sign in with the account the captures use."
if ask "Sign in to Claude Code now?"; then DISABLE_UPDATES=1 claude auth login; fi
DISABLE_UPDATES=1 claude auth status 2>&1 | head -3
if ask "Sign in to Codex now (device code)?"; then codex login --device-auth; fi
codex login status 2>&1 | head -2
if ask "Sign in to agy now? It opens agy: sign in, then type /quit."; then nobus AGY_CLI_DISABLE_AUTO_UPDATE=true agy; fi
echo
echo "Done with the sign-ins."
