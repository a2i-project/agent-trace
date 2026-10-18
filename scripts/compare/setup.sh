#!/usr/bin/env bash
# Fetch and build the comparison tools at their pinned commits, without root,
# into TOOLS_DIR (outside this repository). See docs/architecture/40_tools.md,
# "Comparison tools".
#
#   scripts/compare/setup.sh [--mirror DIR] TOOLS_DIR
#
# --mirror DIR clones from DIR/halo-record, DIR/reproducible-trajectories and
# DIR/signet (existing clones that contain the pinned commits) instead of
# GitHub. Either way the checked-out commit is compared with pins.env.
#
# What it fetches: the three repositories, the trajectoriz wheel from PyPI
# (pinned by hash) and the crates in Signet's Cargo.lock (cargo --locked).
# Nothing else: the Python tools run from source (no build backend is
# installed), and Signet's Claude Code signer runs under the system node with
# the WASM module checked into the repository at the pinned commit.
#
# Everything runs with HOME=TOOLS_DIR/home, CARGO_HOME=TOOLS_DIR/cargo-home and
# no global git configuration, so nothing is written to the user's home.
#
# Licences (the tools are fetched, not redistributed): halo-record Apache-2.0;
# reproducible-trajectories MIT as declared in its pyproject.toml (no LICENSE
# file at the pinned commit); trajectoriz MIT; Signet Apache-2.0 OR MIT.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
mirror=
usage() { echo "usage: $0 [--mirror DIR] TOOLS_DIR" >&2; exit 2; }
while [ $# -gt 0 ]; do
  case $1 in
    --mirror) [ $# -ge 2 ] || usage; mirror=$(cd "$2" && pwd); shift 2 ;;
    -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
    -*) usage ;;
    *) break ;;
  esac
done
[ $# -eq 1 ] || usage
tools=$(realpath -m "$1")
case "$tools/" in
  "$(cd "$repo" && pwd -P)/"*) echo "TOOLS_DIR must lie outside the repository" >&2; exit 2 ;;
esac
mkdir -p "$tools"

# shellcheck source=pins.env
. "$here/pins.env"

for cmd in git node cargo; do
  command -v "$cmd" >/dev/null || { echo "$cmd is not on PATH" >&2; exit 1; }
done
python=${PYTHON:-$(command -v python3)}
[ -x "$python" ] || { echo "no python3 (set PYTHON)" >&2; exit 1; }

export HOME="$tools/home" CARGO_HOME="$tools/cargo-home" CARGO_TARGET_DIR="$tools/signet-target"
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0
export UV_CACHE_DIR="$tools/uv-cache" UV_PYTHON_DOWNLOADS=never PIP_CACHE_DIR="$tools/pip-cache"
# Signet's rust-toolchain.toml names a nightly; under rustup that would
# install it. Build with the installed stable toolchain instead.
if command -v rustup >/dev/null; then export RUSTUP_TOOLCHAIN=${RUSTUP_TOOLCHAIN:-stable}; fi
mkdir -p "$HOME" "$tools/src" "$tools/bin"

fetch() { # name url commit
  local name=$1 url=$2 commit=$3 dir="$tools/src/$1"
  [ -z "$mirror" ] || url="$mirror/$name"
  if [ ! -d "$dir/.git" ]; then
    echo "== fetching $name at $commit"
    git clone -q --no-checkout "$url" "$dir"
  fi
  git -C "$dir" checkout -q --detach "$commit" 2>/dev/null || {
    git -C "$dir" fetch -q origin "$commit" && git -C "$dir" checkout -q --detach "$commit"
  }
  local head
  head=$(git -C "$dir" rev-parse HEAD)
  [ "$head" = "$commit" ] || { echo "$name: HEAD is $head, pinned $commit" >&2; exit 1; }
  [ -z "$(git -C "$dir" status --porcelain --untracked-files=no)" ] || {
    echo "$name: the checkout at $dir has local changes" >&2; exit 1; }
}
fetch halo-record "$HALO_URL" "$HALO_COMMIT"
fetch reproducible-trajectories "$RT_URL" "$RT_COMMIT"
fetch signet "$SIGNET_URL" "$SIGNET_COMMIT"

version_of() { # pyproject.toml or Cargo.toml: the first version = "..." line
  sed -n 's/^version *= *"\(.*\)"/\1/p' "$1" | head -1
}
check_version() { # name file pinned
  local v
  v=$(version_of "$2")
  [ "$v" = "$3" ] || { echo "$1: version $v at the pinned commit, expected $3" >&2; exit 1; }
}
check_version halo-record "$tools/src/halo-record/pyproject.toml" "$HALO_VERSION"
check_version reproducible-trajectories "$tools/src/reproducible-trajectories/pyproject.toml" "$RT_VERSION"
check_version signet-cli "$tools/src/signet/signet-cli/Cargo.toml" "$SIGNET_VERSION"

venv() { # dir
  [ -x "$1/bin/python" ] && return
  if command -v uv >/dev/null; then uv venv -q --python "$python" "$1"; else "$python" -m venv "$1"; fi
}
echo "== python environments ($("$python" --version))"
venv "$tools/venv-halo"
venv "$tools/venv-rt"
req="$tools/trajectoriz.requirements.txt"
echo "trajectoriz==$TRAJECTORIZ_VERSION --hash=sha256:$TRAJECTORIZ_SHA256" >"$req"
if command -v uv >/dev/null; then
  uv pip install -q --python "$tools/venv-rt/bin/python" --require-hashes --no-deps -r "$req"
else
  "$tools/venv-rt/bin/python" -m pip install -q --require-hashes --no-deps -r "$req"
fi

echo "== building signet-cli (cargo $(cargo --version | cut -d' ' -f2), CARGO_HOME=$CARGO_HOME)"
(cd "$tools/src/signet" && cargo build -q --release --locked -p signet-cli)

# Wrappers: the Python tools run from their checkouts, the user site ignored.
cat >"$tools/bin/halo" <<EOF
#!/bin/sh
PYTHONPATH="$tools/src/halo-record/src" exec "$tools/venv-halo/bin/python" -s -m halo_record.cli "\$@"
EOF
# Only the subcommand the comparison uses: the tool's upload and share
# commands reach the network and must never run here.
cat >"$tools/bin/reproducible-trajectories" <<EOF
#!/bin/sh
case "\$1" in
  check-execution-reproducible|--help|-h) ;;
  *) echo "this wrapper runs check-execution-reproducible only" >&2; exit 2 ;;
esac
PYTHONPATH="$tools/src/reproducible-trajectories" exec "$tools/venv-rt/bin/python" -s -m reproducible_trajectories "\$@"
EOF
cat >"$tools/bin/signet-sign" <<EOF
#!/bin/sh
exec node "$tools/src/signet/plugins/claude-code/bin/sign.cjs" "\$@"
EOF
ln -sf "$tools/signet-target/release/signet" "$tools/bin/signet"
chmod +x "$tools/bin/halo" "$tools/bin/reproducible-trajectories" "$tools/bin/signet-sign"

echo "== smoke test"
smoke=$(mktemp -d "$tools/smoke.XXXXXX")
ev='{"hook_event_name":"PostToolUse","session_id":"s","tool_name":"Bash","tool_input":{"command":"true"},"tool_use_id":"t"}'
echo "$ev" | HALO_LOG="$smoke/halo.jsonl" "$tools/bin/halo" hook
"$tools/bin/halo" verify "$smoke/halo.jsonl" >/dev/null
echo "$ev" | SIGNET_HOME="$smoke/signet" "$tools/bin/signet-sign"
SIGNET_HOME="$smoke/signet" "$tools/bin/signet" verify --chain >/dev/null 2>&1
"$tools/bin/reproducible-trajectories" --help >/dev/null
signet_v=$("$tools/bin/signet" --version | awk '{print $2}')
[ "$signet_v" = "$SIGNET_VERSION" ] || { echo "signet --version says $signet_v" >&2; exit 1; }
rm -rf "$smoke"

"$python" - "$tools" "$here/pins.env" <<'EOF'
import json, subprocess, sys
tools, pins = sys.argv[1], sys.argv[2]
p = dict(l.split("=", 1) for l in open(pins).read().splitlines() if l and not l.startswith("#"))
def out(*cmd):
    return subprocess.run(cmd, capture_output=True, text=True).stdout.strip()
m = {
    "pins": p,
    "heads": {n: out("git", "-C", "%s/src/%s" % (tools, n), "rev-parse", "HEAD")
              for n in ("halo-record", "reproducible-trajectories", "signet")},
    "python": out("%s/venv-halo/bin/python" % tools, "--version"),
    "node": out("node", "--version"),
    "cargo": out("cargo", "--version"),
    "signet": out("%s/bin/signet" % tools, "--version"),
}
json.dump(m, open("%s/manifest.json" % tools, "w"), indent=1)
EOF
echo "tools ready in $tools (manifest.json)"
