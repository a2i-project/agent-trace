#!/usr/bin/env bash
# Starts a throwaway VM from the golden image and runs one thing in it.
#
#   vm/run.sh [options] shell
#   vm/run.sh [options] exec 'COMMAND'
#   vm/run.sh [options] campaign [CAMPAIGN FLAGS] PLAN OUTPUT_DIR
#
# Options:
#   --image IMG    the image (default $AGENT_TRACE_VM_HOME/images/current.qcow2)
#   --cpus N       vCPUs (default 4)
#   --mem SIZE     memory (default 8G)
#   --logins DISK  the logins disk vm/login.sh made (default
#                  $AGENT_TRACE_VM_HOME/logins.qcow2 when it exists; --no-logins
#                  attaches none)
#   --keep         keep the overlay after the run (for debugging)
#   --wait         wait for a free VM slot instead of refusing
#
# Every run boots a fresh copy-on-write overlay of the image (the image is
# never written) and deletes it at the end, so no state carries over from one
# run to the next. The network is QEMU's user-mode network; the only port
# open is SSH, forwarded from 127.0.0.1. At most three VMs run at once (a
# slot lock each, $AGENT_TRACE_VM_HOME/slots/).
#
# The logins disk is attached through an overlay of its own, so a run reads
# the sign-ins but never changes the disk; the guest copies its credential
# files into agenttrace's home (vm/guest/logins.sh restore). At boot the
# runner writes /run/agent-trace/vm.json in the guest: the image file, its
# SHA-256 and the recipe commit from the image's manifest, the run's name,
# vCPUs and memory; scripts/capture-agent.sh records it in task-meta.txt.
#
# campaign runs scripts/capture-campaign.sh --run-as agenttrace in the guest,
# as the operator account, with PLAN and the campaign's output on a results
# disk, OUTPUT_DIR/vm-results.qcow2, created on first use and kept: a VM or
# host that goes down loses nothing the campaign wrote, and the same command
# boots a fresh VM on the same disk and resumes. The campaign runs detached
# in the guest; the runner follows its log, and when it ends copies the
# output to OUTPUT_DIR/campaign/ and its log to OUTPUT_DIR/campaign.log over
# SSH. The values of the variables the
# profiles name as secret_env (OpenCode's provider key) reach the guest on
# SSH's stdin when they are set here, never on a command line.
set -euo pipefail
. "$(dirname "$0")/lib.sh"

image=$VM_HOME/images/current.qcow2
cpus=4
mem=8G
logins=
no_logins=
keep=
wait_slot=
while [ $# -gt 0 ]; do
  case $1 in
    --image) image=${2:?}; shift 2 ;;
    --cpus) cpus=${2:?}; shift 2 ;;
    --mem) mem=${2:?}; shift 2 ;;
    --logins) logins=${2:?}; shift 2 ;;
    --no-logins) no_logins=1; shift ;;
    --keep) keep=1; shift ;;
    --wait) wait_slot=1; shift ;;
    -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) vm_die "unknown option $1" ;;
    *) break ;;
  esac
done
mode=${1:-}
[ -n "$mode" ] || vm_die "usage: vm/run.sh [options] shell | exec 'COMMAND' | campaign [FLAGS] PLAN OUTPUT_DIR"
shift
vm_need qemu-system-x86_64 qemu-img ssh flock python3
[ -f "$VM_KEY" ] || vm_die "no key $VM_KEY: build the image first (vm/build.sh)"
image=$(readlink -f "$image")
[ -f "$image" ] || vm_die "no image $image: build it with vm/build.sh"
img_json=${image%.qcow2}.json
img_sum=${image%.qcow2}.sha256
[ -f "$img_json" ] && [ -f "$img_sum" ] || vm_die "no manifest or checksum beside $image"
if [ -z "$logins" ] && [ -z "$no_logins" ] && [ -f "$VM_HOME/logins.qcow2" ]; then logins=$VM_HOME/logins.qcow2; fi
[ -z "$logins" ] || [ -f "$logins" ] || vm_die "no logins disk $logins (make one with vm/login.sh)"

campaign_args=()
results=
if [ "$mode" = campaign ]; then
  [ $# -ge 2 ] || vm_die "campaign needs PLAN OUTPUT_DIR"
  out=$(realpath -m "${*: -1}")
  plan=$(realpath "${*: -2:1}")
  campaign_args=("${@:1:$#-2}")
  case $out/ in "$VM_REPO"/*) vm_die "OUTPUT_DIR $out is inside the repository" ;; esac
  [ -f "$plan" ] || vm_die "no plan $plan"
  mkdir -p "$out"
  results=$out/vm-results.qcow2
  [ -f "$results" ] || qemu-img create -q -f qcow2 "$results" 64G
fi

# A slot: one of three, held for the VM's life.
mkdir -p "$VM_HOME/slots" "$VM_HOME/runs"
slot=
while :; do
  for n in 1 2 3; do
    exec {lockfd}>"$VM_HOME/slots/$n.lock"
    if flock -n "$lockfd"; then slot=$n; break 2; fi
    exec {lockfd}>&-
  done
  [ -n "$wait_slot" ] || vm_die "three VMs are running already (pass --wait to wait for a slot)"
  sleep 10
done
# The results disk is one VM's at a time.
if [ -n "$results" ]; then
  exec {resfd}>"$results.lock"
  flock -n "$resfd" || vm_die "another VM is using $results"
fi

name=run-$(date +%Y%m%d-%H%M%S)-s$slot
dir=$VM_HOME/runs/$name
mkdir -p "$dir"
port=$(vm_free_port)
cleanup() {
  vm_stop "$dir" "$port"
  if [ -n "$keep" ]; then vm_log "kept $dir"; else rm -rf "$dir"; fi
}
trap cleanup EXIT
qemu-img create -q -f qcow2 -b "$image" -F qcow2 "$dir/root.qcow2"
extra=()
if [ -n "$logins" ]; then
  qemu-img create -q -f qcow2 -b "$(readlink -f "$logins")" -F qcow2 "$dir/logins.qcow2"
  extra+=(-drive "file=$dir/logins.qcow2,if=none,id=logins,format=qcow2" -device virtio-blk-pci,drive=logins,serial=agent-trace-logins)
fi
[ -z "$results" ] || extra+=(-drive "file=$results,if=none,id=results,format=qcow2,cache=writethrough" -device virtio-blk-pci,drive=results,serial=agent-trace-results)
vm_log "$name: slot $slot, $cpus vCPU, $mem, SSH 127.0.0.1:$port, image $(basename "$image")"
vm_boot "$dir" "agent-trace-$name" "$cpus" "$mem" "$port" "${extra[@]}"
vm_wait_ssh "$port" "$dir" 300

# The run's record in the guest, which every capture copies into task-meta.txt.
python3 - "$img_json" "$img_sum" "$image" "$name" "$cpus" "$mem" "${logins:+yes}" <<'PY' | vm_ssh "$port" 'sudo install -d -m 755 /run/agent-trace && sudo tee /run/agent-trace/vm.json >/dev/null'
import datetime, json, os, sys
mj, ms, image, name, cpus, mem, logins = sys.argv[1:]
m = json.load(open(mj))
print(json.dumps({"image": os.path.basename(image), "image_sha256": open(ms).read().split()[0],
                  "recipe_commit": m["recipe"]["commit"], "recipe_dirty": m["recipe"]["dirty"],
                  "agent_trace_commit": m["agent_trace"]["commit"], "run": name, "vcpus": int(cpus), "memory": mem,
                  "logins_disk": bool(logins),
                  "started": datetime.datetime.now().astimezone().isoformat(timespec="seconds")}, indent=2))
PY
vm_ssh "$port" "sudo /usr/local/lib/agent-trace-vm/attach.sh ${logins:+--logins} ${results:+--results}"

case $mode in
  shell)
    ssh -t "${VM_SSH_OPTS[@]}" -p "$port" "$VM_OPERATOR@127.0.0.1" 'cd ~/agent-trace && exec bash -l'
    ;;
  exec)
    [ $# -ge 1 ] || vm_die "exec needs a command"
    rc=0
    vm_ssh "$port" "cd ~/agent-trace && $*" || rc=$?
    exit "$rc"
    ;;
  campaign)
    vm_ssh "$port" 'cat > /var/lib/agent-trace/results/plan.txt' <"$plan"
    # Secret values, by name, on stdin only.
    names=$(python3 -c 'import json,sys
a=json.load(open(sys.argv[1]))["adapters"]
print(" ".join(sorted({n for p in a.values() for n in (p.get("secret_env") or {}).get("names", [])})))' "$VM_REPO/config/agents.json")
    {
      for n in $names; do
        [ -z "${!n:-}" ] || printf '%s=%s\n' "$n" "${!n}"
      done
    } | vm_ssh "$port" "/usr/local/lib/agent-trace-vm/campaign.sh start $(printf '%q ' "${campaign_args[@]}")"
    # Follow the log until the campaign ends; a dropped SSH connection is
    # reconnected, the campaign goes on in the guest.
    while :; do
      vm_ssh "$port" '/usr/local/lib/agent-trace-vm/campaign.sh follow' && break
      kill -0 "$(cat "$dir/qemu.pid")" 2>/dev/null || vm_die "the VM went down; rerun the same command to resume on $results"
      sleep 5
    done
    rc=$(vm_ssh "$port" 'cat /var/lib/agent-trace/results/campaign.exit')
    mkdir -p "$out/campaign"
    # The campaign's output, when it wrote any (a dry run writes none).
    vm_ssh "$port" 'if [ -d /var/lib/agent-trace/results/out ]; then tar -C /var/lib/agent-trace/results/out -cf - .; fi' | tar -C "$out/campaign" -xf - 2>/dev/null || true
    vm_ssh "$port" 'cat /var/lib/agent-trace/results/campaign.log' >"$out/campaign.log"
    vm_log "campaign exit $rc; output copied to $out/campaign (the results disk stays at $results)"
    exit "$rc"
    ;;
  *) vm_die "unknown mode $mode" ;;
esac
