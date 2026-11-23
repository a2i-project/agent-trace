#!/usr/bin/env bash
# Runs as root in the guest. The sign-ins of agenttrace, kept on the logins
# disk (mounted at /var/lib/agent-trace/logins), never in the image.
#   logins.sh snapshot   record the hash of every file in agenttrace's home
#   logins.sh save       copy every file the sign-ins created or changed since
#                        the snapshot to the disk's home/, list them in
#                        files.list and print the list; the profiles' trace
#                        directories and the caches are left out
#   logins.sh restore    copy the listed files into agenttrace's home, with
#                        their modes, owned by agenttrace
set -euo pipefail
user=agenttrace
home=$(getent passwd "$user" | cut -d: -f6)
disk=/var/lib/agent-trace/logins
snap=/run/agent-trace/logins.snapshot
config=/home/trace/agent-trace/config/agents.json
hashes() { (cd "$home" && find . -type f -print0 | sort -z | xargs -0 -r sha256sum); }
case ${1:-} in
  snapshot)
    install -d -m 700 /run/agent-trace
    hashes >"$snap"
    ;;
  save)
    [ -f "$snap" ] || { echo "logins: no snapshot" >&2; exit 1; }
    mountpoint -q "$disk" || { echo "logins: $disk is not mounted" >&2; exit 1; }
    # Left out: the trace directories the profiles name (sessions, not
    # sign-ins), caches and package stores.
    excl=$(python3 - "$config" <<'PY'
import json, sys
a = json.load(open(sys.argv[1]))["adapters"]
dirs = {"~/.cache", "~/.npm", "~/.local/bin", "~/.local/lib", "~/.local/share/claude", "~/.local/state"}
for p in a.values():
    d = (p.get("trace") or {}).get("dir")
    if d:
        dirs.add(d)
print("\n".join(sorted(x[2:] for x in dirs if x.startswith("~/"))))
PY
)
    changed=$(hashes | grep -vxF -f "$snap" | sed 's/^[0-9a-f]*  \.\///' || true)
    files=()
    while IFS= read -r f; do
      [ -n "$f" ] || continue
      skip=
      while IFS= read -r e; do case $f in "$e"/*|"$e") skip=1 ;; esac; done <<<"$excl"
      [ -n "$skip" ] || files+=("$f")
    done <<<"$changed"
    rm -rf "$disk/home"
    install -d -m 700 "$disk/home"
    : >"$disk/files.list.new"
    for f in "${files[@]}"; do
      (cd "$home" && cp -a --parents "./$f" "$disk/home/")
      printf '%s\n' "$f" >>"$disk/files.list.new"
    done
    mv "$disk/files.list.new" "$disk/files.list"
    date --iso-8601=seconds >"$disk/saved"
    sync
    echo "logins: saved ${#files[@]} file(s) to the logins disk:"
    sed 's/^/  ~\//' "$disk/files.list"
    ;;
  restore)
    [ -f "$disk/files.list" ] || { echo "logins: the logins disk holds no sign-ins yet (vm/login.sh)" >&2; exit 0; }
    while IFS= read -r f; do
      [ -n "$f" ] || continue
      install -d -o "$user" -g "$user" -m 700 "$home/$(dirname "$f")"
      cp -a "$disk/home/$f" "$home/$f"
      chown "$user:$user" "$home/$f"
    done <"$disk/files.list"
    echo "logins: restored $(grep -c . "$disk/files.list") file(s) saved $(cat "$disk/saved" 2>/dev/null)"
    ;;
  *) echo "usage: logins.sh snapshot|save|restore" >&2; exit 2 ;;
esac
