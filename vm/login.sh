#!/usr/bin/env bash
# Creates or updates the logins disk: a VM from the golden image with the
# disk attached, a console in it as agenttrace for the agents' sign-ins, and
# the sign-ins saved to the disk.
#
#   vm/login.sh [--image IMG] [--logins DISK]
#
# DISK (default $AGENT_TRACE_VM_HOME/logins.qcow2, outside the repository) is
# created when absent: a 2 GiB qcow2 that the guest formats. It is attached
# read-write to this VM only (a lock keeps a second one off it); every run of
# vm/run.sh attaches it through an overlay, so no run changes it. The guest
# records the hash of every file in agenttrace's home, opens a console as
# agenttrace running vm/guest/signin.sh (the sign-ins of
# agenttrace-install.sh: Claude Code, Codex, agy; each asked for first), then
# copies every file the sign-ins created or changed, except the profiles'
# trace directories and caches, to the disk and prints their list. The VM
# and its overlay are then thrown away. Run it again to sign in again: the
# disk's earlier contents are replaced.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

image=$VM_HOME/images/current.qcow2
logins=$VM_HOME/logins.qcow2
while [ $# -gt 0 ]; do
  case $1 in
    --image) image=${2:?}; shift 2 ;;
    --logins) logins=${2:?}; shift 2 ;;
    -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) vm_die "unknown argument $1" ;;
  esac
done
vm_need qemu-system-x86_64 qemu-img ssh flock
image=$(readlink -f "$image")
[ -f "$image" ] || vm_die "no image $image: build it with vm/build.sh"
logins=$(realpath -m "$logins")
case $logins/ in "$VM_REPO"/*) vm_die "the logins disk must be outside the repository" ;; esac
[ -t 0 ] && [ -t 1 ] || vm_die "the sign-ins need your terminal"
mkdir -p "$(dirname "$logins")"
[ -f "$logins" ] || { qemu-img create -q -f qcow2 "$logins" 2G; chmod 600 "$logins"; vm_log "created $logins"; }
exec {lockfd}>"$logins.lock"
flock -n "$lockfd" || vm_die "$logins is in use by another VM"

dir=$(mktemp -d "$VM_HOME/runs/login.XXXXXX" 2>/dev/null || { mkdir -p "$VM_HOME/runs"; mktemp -d "$VM_HOME/runs/login.XXXXXX"; })
port=$(vm_free_port)
trap 'vm_stop "$dir" "$port"; rm -rf "$dir"' EXIT
qemu-img create -q -f qcow2 -b "$image" -F qcow2 "$dir/root.qcow2"
vm_boot "$dir" agent-trace-login 2 4G "$port" \
  -drive "file=$logins,if=none,id=logins,format=qcow2,cache=writethrough" -device virtio-blk-pci,drive=logins,serial=agent-trace-logins
vm_wait_ssh "$port" "$dir" 300
vm_ssh "$port" 'sudo /usr/local/lib/agent-trace-vm/attach.sh --logins-rw && sudo /usr/local/lib/agent-trace-vm/logins.sh restore && sudo /usr/local/lib/agent-trace-vm/logins.sh snapshot'
ssh -t "${VM_SSH_OPTS[@]}" -p "$port" "$VM_OPERATOR@127.0.0.1" 'cd / && sudo -u agenttrace -H /usr/local/lib/agent-trace-vm/signin.sh'
vm_ssh "$port" 'sudo /usr/local/lib/agent-trace-vm/logins.sh save && sudo umount /var/lib/agent-trace/logins'
vm_log "the sign-ins are on $logins; vm/run.sh attaches it to every run"
