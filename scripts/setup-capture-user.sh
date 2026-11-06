#!/usr/bin/env bash
# One-time setup of the dedicated user experiment captures run the agent as
# (I-140): run it yourself, once, with sudo.
#
#   sudo scripts/setup-capture-user.sh [--user NAME] [--workspace-root DIR]
#   scripts/setup-capture-user.sh --steps-only [--user NAME]
#
# It creates the user NAME (default agenttrace) with its own group, a home
# of its own (/home/NAME, mode 700), no login password and no sudo, in no
# group of yours, and the workspace root DIR (default
# /var/lib/agent-trace/ws, root's, mode 711) under which
# scripts/capture-agent.sh --run-as NAME puts each run's workspace (I-138).
# It marks the user it creates in the account's comment field and refuses
# to touch an existing user without that mark, so it never changes an
# account it did not create; run again, it changes nothing that is already
# as it should be. It checks that your home is closed to the new user
# (mode 750 or stricter, I-137) and says how to close it, without changing
# it.
#
# It runs no agent and installs none. It prints, for every agent
# config/agents.json profiles, the steps to install the version the profile
# lists last as NAME, with the profile's version lock, and to log in, which
# you then follow yourself: as NAME, except a copy of an agent that is one
# executable (agy), which you make from yours. A profile's pass_env names
# that apply only to a run as you (agy's session bus, I-150) are left out of
# its login, so it signs in as the capture runs it. --steps-only prints only
# those steps, without root, and changes nothing.
set -euo pipefail

user=agenttrace
ws_root=/var/lib/agent-trace/ws
steps_only=
while [ $# -gt 0 ]; do
  case $1 in
    --user) user=${2:?--user needs a name}; shift 2 ;;
    --workspace-root) ws_root=${2:?--workspace-root needs a directory}; shift 2 ;;
    --steps-only) steps_only=1; shift ;;
    -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done
case $user in [a-z_]*) ;; *) echo "--user: '$user' is not a user name" >&2; exit 2 ;; esac
case $user in *[!a-z0-9_-]*) echo "--user: '$user' is not a user name" >&2; exit 2 ;; esac
case $ws_root in /?*) ;; *) echo "--workspace-root must be absolute" >&2; exit 2 ;; esac
root=$(cd "$(dirname "$0")/.." && pwd)
config=${AGENT_TRACE_CONFIG:-$root/config/agents.json}
home=/home/$user
# The mark this script leaves in the account's comment field.
mark="agent-trace capture user (scripts/setup-capture-user.sh)"

# steps: the per-agent install and login steps, from the profiles.
steps() {
  local h
  h=$(getent passwd "$user" 2>/dev/null | cut -d: -f6) || true
  python3 - "$config" "$user" "${h:-$home}" <<'PY'
import json, shlex, sys
config, user, home = sys.argv[1:]
adapters = json.load(open(config, encoding="utf-8"))["adapters"]
# How each agent's pinned version is installed into the user's ~/.local,
# keyed by the profile's binary; Reported from the vendors' instructions,
# not run by this script. A binary missing here is installed by hand. An
# entry marked "you" is run by you, not as the user: agy is one
# executable, a copy of yours, which the user cannot read in your home.
INSTALL = {
    "claude": [("user", "curl -fsSL https://claude.ai/install.sh | bash -s {version}")],
    "codex": [("user", "npm install -g --prefix ~/.local @openai/codex@{version}")],
    "opencode": [("user", "npm install -g --prefix ~/.local opencode-ai@{version}")],
    "agy": [("you", "{binary} --version   # yours must print {version}; then copy it into %s's ~/.local/bin:" % user),
            ("you", "cat \"$(readlink -f \"$(command -v {binary})\")\" | sudo -u %s sh -c 'mkdir -p %s/.local/bin && cat >%s/.local/bin/{binary} && chmod 755 %s/.local/bin/{binary}'"
             % (user, shlex.quote(home), shlex.quote(home), shlex.quote(home)))],
}
# How each logs in, run once by hand as the user.
LOGIN = {"claude": "claude auth login", "codex": "codex login",
         "agy": "agy   # sign in once interactively, then /quit"}
print("For each agent the experiments use: the lines marked 'as you' in your own shell, the others as %s" % user)
print("(sudo -iu %s). The capture runs the agent with PATH=~/.local/bin:/usr/local/bin:/usr/bin:/bin, so what" % user)
print("an agent needs besides itself (node and npm for the npm packages) must be installed system-wide, not in your home.")
for name, p in sorted(adapters.items()):
    binary = p.get("binary")
    versions = [v["version"] for v in p.get("versions", [])]
    if not binary or not versions:
        continue
    version = versions[-1]
    lock = p.get("version_lock") or {}
    env = " ".join("%s=%s" % kv for kv in sorted((lock.get("env") or {}).items()))
    print("\n  %s: %s %s (the version config/agents.json lists last)" % (name, binary, version))
    for who, c in INSTALL.get(binary, [("user", "install %s %s into ~/.local/bin by hand" % (binary, version))]):
        print("    %s%s" % ("as you: " if who == "you" else "", c.format(version=version, binary=binary)))
    req = lock.get("require_setting")
    if req:
        key, value = req["key"], req["value"]
        print("    # the version lock the capture checks (%s): %s/%s sets %s to \"%s\"" % (req.get("why", ""), req["dir"], req["file"], key, value))
        obj = value
        for part in reversed(key.split(".")):
            obj = {part: obj}
        print("    mkdir -p %s && printf '%%s\\n' '%s' > %s/%s" % (req["dir"], json.dumps(obj), req["dir"], req["file"]))
    pe = p.get("pass_env") or {}
    unset = ""
    if pe:
        only = [n for n in pe.get("names", []) if n in (pe.get("operator_only") or [])]
        rest = [n for n in pe.get("names", []) if n not in only]
        if only:
            # Signed in as the capture runs it: without the operator-only
            # environment (I-150).
            unset = "env " + " ".join("-u " + n for n in only) + " "
            print("    # sign in without %s, as capture-agent.sh --run-as runs it (%s);" % (" ".join(only), pe.get("operator_only_why", "")))
            print("    # a sudo -iu shell has none; a lingering user session would give it one at /run/user/UID/bus:")
            print("    test -e /run/user/$(id -u)/bus && echo 'a session bus exists: sign in where there is none' || echo 'no session bus'")
        if rest:
            print("    # the profile passes %s from your session (%s): capture-agent.sh --run-as refuses it (I-137)" % (" ".join(rest), pe.get("why", "")))
    if p.get("secret_env"):
        names = " ".join(p["secret_env"].get("names", []))
        print("    # no login: %s reaches each run on its stdin from your session (I-113), as without --run-as" % names)
    if p.get("warm_up"):
        print("    # no warm-up by hand: every capture first makes the profile's warm-up run as %s, outside watch (I-151)" % user)
    if binary in LOGIN:
        print("    %s%s%s" % (unset, env + " " if env else "", LOGIN[binary]))
    print("    %s%s%s --version   # must print %s" % (unset, env + " " if env else "", binary, version))
print("\nThen, as you: scripts/capture-agent.sh --check --run-as %s --agent AGENT --task basic (after sudo -v)" % user)
PY
}

if [ -n "$steps_only" ]; then
  steps
  exit 0
fi
[ "$(id -u)" = 0 ] || { echo "run it with sudo: sudo $0 $*" >&2; exit 1; }
operator=${SUDO_USER:-}
[ -n "$operator" ] && [ "$operator" != root ] || { echo "run it with sudo from your own account, so it knows whose home to check" >&2; exit 1; }
for tool in getent useradd usermod id stat install; do
  command -v "$tool" >/dev/null || { echo "$tool is not on PATH" >&2; exit 1; }
done

# The user: created with the mark, or found with it.
if ent=$(getent passwd "$user"); then
  IFS=: read -r _ _ uid _ gecos home _ <<<"$ent"
  if [ "$gecos" != "$mark" ]; then
    echo "a user $user exists that this script did not create (its comment is '$gecos'); it is left alone: choose another --user" >&2
    exit 1
  fi
  echo "user $user exists (uid $uid), created by this script"
else
  getent group "$user" >/dev/null && { echo "a group $user exists without the user; it is left alone: choose another --user" >&2; exit 1; }
  useradd --create-home --home-dir "$home" --user-group --shell /bin/bash --comment "$mark" "$user"
  echo "created user $user (uid $(id -u "$user")), home $home"
fi
# No password to log in with: the account is reached with sudo -iu only.
usermod --lock "$user" >/dev/null
chmod 700 "$home"
# No sudo and none of your groups, and you in none of its.
groups=" $(id -nG "$user") "
for g in sudo admin wheel "$(id -gn "$operator")"; do
  case $groups in *" $g "*) echo "$user is in the group $g: remove it (gpasswd -d $user $g), then run again" >&2; exit 1 ;; esac
done
case " $(id -nG "$operator") " in *" $(id -gn "$user") "*) echo "$operator is in $user's group: remove it, then run again" >&2; exit 1 ;; esac

# The workspace root, root's, which the agent's user can pass through only.
install -d -o root -g root -m 755 "$(dirname "$ws_root")"
install -d -o root -g root -m 711 "$ws_root"
echo "workspace root $ws_root (root, 711)"

# Your home must be closed to the new user (I-137); it is not changed here.
op_home=$(getent passwd "$operator" | cut -d: -f6)
mode=$(stat -c %a "$op_home")
if [ $((8#$mode & 8#007)) -ne 0 ]; then
  echo "WARNING: your home $op_home has mode $mode, which lets $user in; close it with: chmod 750 $op_home" >&2
else
  echo "your home $op_home has mode $mode: closed to $user"
fi
echo
steps
