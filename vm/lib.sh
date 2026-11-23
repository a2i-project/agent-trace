# Host-side helpers of the VM recipe, sourced by vm/build.sh, vm/run.sh and
# vm/login.sh. Nothing here needs root: QEMU runs as you with KVM, the
# network is QEMU's user-mode network, and the guest is reached by SSH on a
# port forwarded from 127.0.0.1.

vm_die() { echo "vm: $*" >&2; exit 1; }
vm_log() { echo "vm: $*" >&2; }

VM_REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# Where images, overlays, caches and keys live: outside the repository,
# never committed.
VM_HOME=${AGENT_TRACE_VM_HOME:-${XDG_CACHE_HOME:-$HOME/.cache}/agent-trace-vm}
case $VM_HOME/ in "$VM_REPO"/*) vm_die "AGENT_TRACE_VM_HOME $VM_HOME is inside the repository" ;; esac
VM_KEY=$VM_HOME/keys/id_ed25519
# The operator account inside the image (uid 1000): it builds agent-trace and
# runs the captures with sudo; agenttrace (uid 1001) runs the agents.
VM_OPERATOR=trace
VM_SSH_OPTS=(-i "$VM_KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
  -o LogLevel=ERROR -o ConnectTimeout=5 -o ServerAliveInterval=15 -o ServerAliveCountMax=8)

# shellcheck disable=SC1091
. "$VM_REPO/vm/inputs.env"

vm_need() {
  local t
  for t in "$@"; do command -v "$t" >/dev/null || vm_die "$t is not on PATH"; done
  [ -r /dev/kvm ] && [ -w /dev/kvm ] || vm_die "/dev/kvm is not usable by you (are you in the kvm group?)"
}

vm_key() {
  [ -f "$VM_KEY" ] && return
  mkdir -p "$(dirname "$VM_KEY")"
  chmod 700 "$(dirname "$VM_KEY")"
  ssh-keygen -q -t ed25519 -N '' -C agent-trace-vm -f "$VM_KEY"
}

# vm_fetch URL SHA256 DEST: download into the cache unless a file with that
# hash is already there.
vm_fetch() {
  local url=$1 sum=$2 dest=$3
  if [ -f "$dest" ] && [ "$(sha256sum "$dest" | cut -d' ' -f1)" = "$sum" ]; then return; fi
  mkdir -p "$(dirname "$dest")"
  vm_log "downloading $url"
  curl -fsSL --retry 3 -o "$dest.part" "$url" || vm_die "download failed: $url"
  [ "$(sha256sum "$dest.part" | cut -d' ' -f1)" = "$sum" ] || { rm -f "$dest.part"; vm_die "SHA-256 mismatch for $url (want $sum)"; }
  mv "$dest.part" "$dest"
}

vm_free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
}

# vm_boot DIR NAME CPUS MEM SSH_PORT [extra qemu args...]: start QEMU in the
# background on the disk DIR/root.qcow2, the boot disk whatever else is
# attached (the firmware would try a blank data disk first); the serial console goes to
# DIR/console.log and the pid to DIR/qemu.pid. The network is user-mode, with
# 127.0.0.1:SSH_PORT forwarded to the guest's port 22 and nothing else open.
vm_boot() {
  local dir=$1 name=$2 cpus=$3 mem=$4 port=$5
  shift 5
  qemu-system-x86_64 -name "$name" -machine q35,accel=kvm -cpu host -smp "$cpus" -m "$mem" \
    -drive "file=$dir/root.qcow2,if=none,id=root,format=qcow2,discard=unmap" -device virtio-blk-pci,drive=root,bootindex=0 \
    -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:$port-:22" -device virtio-net-pci,netdev=n0 \
    -device virtio-rng-pci -display none -serial "file:$dir/console.log" -monitor none \
    -pidfile "$dir/qemu.pid" -daemonize "$@" || vm_die "QEMU did not start (see $dir/console.log)"
}

# vm_ssh PORT ARGS...: ssh to the operator account.
vm_ssh() {
  local port=$1
  shift
  ssh "${VM_SSH_OPTS[@]}" -p "$port" "$VM_OPERATOR@127.0.0.1" "$@"
}

# vm_wait_ssh PORT DIR SECONDS: wait until the guest answers on SSH and has
# finished booting.
vm_wait_ssh() {
  local port=$1 dir=$2 limit=$3 t=0
  while ! vm_ssh "$port" true 2>/dev/null; do
    sleep 2
    t=$((t + 2))
    [ -f "$dir/qemu.pid" ] && kill -0 "$(cat "$dir/qemu.pid")" 2>/dev/null || vm_die "QEMU exited during boot (see $dir/console.log)"
    [ "$t" -lt "$limit" ] || vm_die "no SSH after ${limit}s (see $dir/console.log)"
  done
  vm_ssh "$port" 'systemctl is-system-running --wait >/dev/null 2>&1 || true'
}

# vm_stop DIR PORT: power the guest off, then make sure QEMU is gone.
vm_stop() {
  local dir=$1 port=$2 pid t=0
  [ -f "$dir/qemu.pid" ] || return 0
  pid=$(cat "$dir/qemu.pid")
  vm_ssh "$port" 'sudo systemctl poweroff' >/dev/null 2>&1 || true
  while kill -0 "$pid" 2>/dev/null && [ "$t" -lt 60 ]; do sleep 1; t=$((t + 1)); done
  kill "$pid" 2>/dev/null || true
  rm -f "$dir/qemu.pid"
}
