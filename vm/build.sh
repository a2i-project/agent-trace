#!/usr/bin/env bash
# Builds the golden VM image, with one command, from the pinned inputs of
# vm/inputs.env and agent-trace at a given commit.
#
#   vm/build.sh [--commit REV] [--allow-dirty]
#
# It needs no root: QEMU runs as you with KVM (/dev/kvm), with QEMU's
# user-mode network. The steps:
#   1. download the inputs into the cache ($AGENT_TRACE_VM_HOME, default
#      ~/.cache/agent-trace-vm; outside the repository, never committed), each
#      checked against its SHA-256: the Ubuntu 26.04 cloud image, Go, the
#      Claude Code binary; agy, which no vendor URL serves by version, is
#      copied from your install ($AGY_SOURCE, default the agy on PATH) and
#      checked against its pinned hash;
#   2. take agent-trace at REV (default HEAD) as a shallow git clone, so the
#      image holds a repository whose HEAD is that commit;
#   3. boot a copy of the cloud image once, with a cloud-init seed served by a
#      local HTTP server on 127.0.0.1 and named by SMBIOS (ds=nocloud), which
#      creates the operator account (trace, uid 1000) with the cache's SSH key
#      and nothing else;
#   4. copy the inputs in over SSH and run vm/guest/provision.sh as root in the
#      guest: it checks the kernel, installs the pinned packages from the
#      Ubuntu snapshot archive, Go, builds agent-trace, creates agenttrace
#      with scripts/setup-capture-user.sh, installs the four agents as
#      agenttrace, checks every kernel feature the tool needs and writes the
#      manifest /etc/agent-trace/image.json;
#   5. power the guest off and write the image, with its SHA-256 and the
#      manifest beside it, to $AGENT_TRACE_VM_HOME/images/, and point
#      images/current.qcow2 at it.
# The recipe commit (this checkout's HEAD) is recorded; a recipe with
# uncommitted changes under vm/ is refused unless --allow-dirty, and then
# recorded as dirty.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

rev=HEAD
allow_dirty=
while [ $# -gt 0 ]; do
  case $1 in
    --commit) rev=${2:?--commit needs a revision}; shift 2 ;;
    --allow-dirty) allow_dirty=1; shift ;;
    -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) vm_die "unknown argument $1" ;;
  esac
done
vm_need qemu-system-x86_64 qemu-img ssh scp ssh-keygen curl python3 git sha256sum
t0=$(date +%s)

recipe_commit=$(git -C "$VM_REPO" rev-parse HEAD)
recipe_dirty=false
if [ -n "$(git -C "$VM_REPO" status --porcelain -- vm)" ]; then
  [ -n "$allow_dirty" ] || vm_die "vm/ has uncommitted changes: commit them, or pass --allow-dirty (recorded)"
  recipe_dirty=true
fi
src_commit=$(git -C "$VM_REPO" rev-parse --verify "$rev^{commit}") || vm_die "no commit $rev"

cache=$VM_HOME/cache
vm_key
vm_fetch "$UBUNTU_IMAGE_URL" "$UBUNTU_IMAGE_SHA256" "$cache/${UBUNTU_IMAGE_URL##*/}"
vm_fetch "$GO_URL" "$GO_SHA256" "$cache/${GO_URL##*/}"
vm_fetch "$CLAUDE_URL" "$CLAUDE_SHA256" "$cache/claude-$CLAUDE_VERSION"
agy=$cache/agy-$AGY_VERSION
if ! { [ -f "$agy" ] && [ "$(sha256sum "$agy" | cut -d' ' -f1)" = "$AGY_SHA256" ]; }; then
  src=${AGY_SOURCE:-$(command -v agy || true)}
  [ -n "$src" ] || vm_die "agy $AGY_VERSION is not in the cache and no agy is on PATH: set AGY_SOURCE"
  src=$(readlink -f "$src")
  [ "$(sha256sum "$src" | cut -d' ' -f1)" = "$AGY_SHA256" ] || vm_die "$src is not agy $AGY_VERSION (SHA-256 differs from vm/inputs.env)"
  mkdir -p "$cache"
  cp "$src" "$agy.part" && mv "$agy.part" "$agy"
  vm_log "agy $AGY_VERSION copied from $src into the cache"
fi

work=$(mktemp -d "$VM_HOME/build.XXXXXX")
http_pid=
port=
cleanup() {
  [ -z "$http_pid" ] || kill "$http_pid" 2>/dev/null || true
  [ -z "$port" ] || vm_stop "$work" "$port"
  rm -rf "$work"
}
trap cleanup EXIT

# agent-trace at the commit, as a shallow clone whose HEAD is the commit.
git init -q "$work/src/agent-trace"
git -C "$work/src/agent-trace" fetch -q --depth 1 "file://$VM_REPO" "$src_commit"
git -C "$work/src/agent-trace" -c advice.detachedHead=false checkout -q FETCH_HEAD
tar -C "$work/src" -czf "$work/agent-trace.tar.gz" agent-trace

# The cloud-init seed: the operator account and its key, nothing else.
mkdir -p "$work/seed"
printf 'instance-id: agent-trace-build-%s\nlocal-hostname: agent-trace\n' "$(date +%s)" >"$work/seed/meta-data"
cat >"$work/seed/user-data" <<EOF
#cloud-config
users:
  - name: $VM_OPERATOR
    shell: /bin/bash
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    lock_passwd: true
    ssh_authorized_keys:
      - $(cat "$VM_KEY.pub")
ssh_pwauth: false
package_update: false
package_upgrade: false
EOF
: >"$work/seed/vendor-data"
port_http=$(vm_free_port)
python3 -m http.server --bind 127.0.0.1 --directory "$work/seed" "$port_http" >"$work/http.log" 2>&1 &
http_pid=$!

qemu-img convert -O qcow2 "$cache/${UBUNTU_IMAGE_URL##*/}" "$work/root.qcow2"
qemu-img resize -q "$work/root.qcow2" "$IMAGE_DISK_SIZE"
port=$(vm_free_port)
vm_log "booting the build VM (SSH on 127.0.0.1:$port, console $work/console.log)"
vm_boot "$work" agent-trace-build "$BUILD_CPUS" "$BUILD_MEM" "$port" \
  -smbios "type=1,serial=ds=nocloud;s=http://10.0.2.2:$port_http/"
vm_wait_ssh "$port" "$work" 600
kill "$http_pid" 2>/dev/null || true
http_pid=

vm_log "copying the inputs in"
vm_ssh "$port" 'mkdir -p /tmp/build'
scp -q "${VM_SSH_OPTS[@]}" -P "$port" -r "$VM_REPO/vm/guest" "$VM_REPO/vm/inputs.env" "$work/agent-trace.tar.gz" \
  "$cache/${GO_URL##*/}" "$cache/claude-$CLAUDE_VERSION" "$agy" "$VM_OPERATOR@127.0.0.1:/tmp/build/"
vm_log "provisioning (log: $work/provision.log, copied to the image's directory)"
set +e
vm_ssh "$port" "sudo env RECIPE_COMMIT=$recipe_commit RECIPE_DIRTY=$recipe_dirty SRC_COMMIT=$src_commit \
  bash /tmp/build/guest/provision.sh /tmp/build" 2>&1 | tee "$work/provision.log"
rc=${PIPESTATUS[0]}
set -e
mkdir -p "$VM_HOME/images"
cp "$work/provision.log" "$VM_HOME/images/last-provision.log"
[ "$rc" -eq 0 ] || vm_die "provisioning failed (exit $rc); log: $VM_HOME/images/last-provision.log"
vm_ssh "$port" 'sudo cat /etc/agent-trace/image.json' >"$work/image.json"
vm_stop "$work" "$port"
port=

name=agent-trace-${src_commit:0:12}-$(date +%Y%m%d-%H%M%S)
img=$VM_HOME/images/$name.qcow2
vm_log "writing $img"
qemu-img convert -O qcow2 "$work/root.qcow2" "$img.part"
mv "$img.part" "$img"
chmod 444 "$img"
sum=$(sha256sum "$img" | cut -d' ' -f1)
echo "$sum  $name.qcow2" >"$VM_HOME/images/$name.sha256"
python3 - "$work/image.json" "$VM_HOME/images/$name.json" "$sum" "$name.qcow2" "$(($(date +%s) - t0))" <<'PY'
import json, os, sys
src, dst, sha, name, secs = sys.argv[1:]
m = json.load(open(src))
m["image"] = {"file": name, "sha256": sha, "bytes": os.path.getsize(os.path.join(os.path.dirname(dst), name)),
              "build_seconds": int(secs)}
json.dump(m, open(dst, "w"), indent=2)
open(dst, "a").write("\n")
PY
cp "$VM_HOME/images/last-provision.log" "$VM_HOME/images/$name.provision.log"
ln -sfn "$name.qcow2" "$VM_HOME/images/current.qcow2"
vm_log "image $img"
vm_log "sha256 $sum, $(du -h --apparent-size "$img" | cut -f1) apparent, $(du -h "$img" | cut -f1) on disk, built in $(($(date +%s) - t0))s"
vm_log "manifest $VM_HOME/images/$name.json"
