#!/usr/bin/env bash
# Runs as root in a run's guest (vm/run.sh, vm/login.sh): mounts the disks
# the runner attached, found by their serial numbers.
#   attach.sh [--logins] [--logins-rw] [--results]
# --logins mounts the logins disk (an overlay of the user's disk) and copies
# the saved sign-ins into agenttrace's home (logins.sh restore);
# --logins-rw (vm/login.sh) mounts the disk itself, formatting it when it has
# no file system yet; --results mounts the results disk, formatting it on
# first use, owned by the operator.
set -euo pipefail
dev() { readlink -f "/dev/disk/by-id/virtio-$1"; }
fs_on() { # serial label mountpoint owner
  local d
  d=$(dev "$1")
  [ -b "$d" ] || { echo "attach: no disk with serial $1" >&2; exit 1; }
  blkid "$d" >/dev/null 2>&1 || mkfs.ext4 -q -L "$2" "$d"
  mount "$d" "$3"
  chown "$4" "$3"
}
while [ $# -gt 0 ]; do
  case $1 in
    --logins) fs_on agent-trace-logins agent-trace-logins /var/lib/agent-trace/logins root:root
              /usr/local/lib/agent-trace-vm/logins.sh restore ;;
    --logins-rw) fs_on agent-trace-logins agent-trace-logins /var/lib/agent-trace/logins root:root ;;
    --results) fs_on agent-trace-results agent-trace-results /var/lib/agent-trace/results trace:trace ;;
    *) echo "attach: unknown $1" >&2; exit 2 ;;
  esac
  shift
done
