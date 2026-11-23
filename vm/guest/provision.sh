#!/usr/bin/env bash
# Runs as root inside the build VM (vm/build.sh copies it in with the inputs
# into DIR). Every check that fails stops the build: an image that lacks a
# setting the tool needs is never written.
#
#   RECIPE_COMMIT=... RECIPE_DIRTY=... SRC_COMMIT=... provision.sh DIR
set -euo pipefail
dir=${1:?usage: provision.sh DIR}
. "$dir/inputs.env"
op=trace
agent=agenttrace
die() { echo "provision: $*" >&2; exit 1; }
step() { echo; echo "== $*"; }
[ "$(id -u)" = 0 ] || die "run as root"
export DEBIAN_FRONTEND=noninteractive

step "kernel"
[ "$(uname -r)" = "$KERNEL_RELEASE" ] || die "running kernel $(uname -r), pinned $KERNEL_RELEASE"
v=$(dpkg-query -W -f '${Version}' "linux-image-$KERNEL_RELEASE")
[ "$v" = "$KERNEL_PACKAGE_VERSION" ] || die "linux-image-$KERNEL_RELEASE is $v, pinned $KERNEL_PACKAGE_VERSION"
# Hold every installed kernel package, so nothing replaces the kernel.
dpkg-query -W -f '${db:Status-Abbrev} ${Package}\n' 'linux-*' | awk '$1 == "ii" {print $2}' |
  grep -E '^linux-(image|modules|headers|generic|virtual|kvm)' | xargs -r apt-mark hold >/dev/null
# No background upgrade, ever.
systemctl disable --now apt-daily.timer apt-daily-upgrade.timer unattended-upgrades.service 2>/dev/null || true
printf 'APT::Periodic::Update-Package-Lists "0";\nAPT::Periodic::Unattended-Upgrade "0";\n' >/etc/apt/apt.conf.d/99agent-trace-no-periodic

step "packages from the snapshot archive $APT_SNAPSHOT"
# shellcheck disable=SC2086
apt-get -q --snapshot "$APT_SNAPSHOT" update
# shellcheck disable=SC2086
apt-get -q -y --snapshot "$APT_SNAPSHOT" install --no-install-recommends $APT_PACKAGES

step "Go $GO_VERSION"
rm -rf /usr/local/go
tar -C /usr/local -xzf "$dir/${GO_URL##*/}"
ln -sf /usr/local/go/bin/go /usr/local/bin/go
ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
[ "$(go version | awk '{print $3}')" = "go$GO_VERSION" ] || die "go version: $(go version)"

step "agent-trace at $SRC_COMMIT, built as $op"
id "$op" >/dev/null || die "no operator account $op"
[ "$(id -u "$op")" = 1000 ] || die "$op is uid $(id -u "$op"), want 1000"
oh=$(getent passwd "$op" | cut -d: -f6)
chmod 750 "$oh"
tar -C "$oh" -xzf "$dir/agent-trace.tar.gz"
chown -R "$op:$op" "$oh/agent-trace"
as_op() { sudo -u "$op" -H env -C "$oh/agent-trace" PATH=/usr/local/bin:/usr/bin:/bin "$@"; }
[ "$(as_op git rev-parse HEAD)" = "$SRC_COMMIT" ] || die "the source is not at $SRC_COMMIT"
as_op git config --global --add safe.directory "$oh/agent-trace"
as_op git config core.hooksPath scripts/hooks
as_op make build
as_op go build ./...
# Warm the module and build caches of the privileged test binaries.
as_op go test -count=1 -run '^$' ./pkg/probe/fs ./cmd/watch >/dev/null

step "the capture user $agent (scripts/setup-capture-user.sh)"
SUDO_USER=$op bash "$oh/agent-trace/scripts/setup-capture-user.sh" --user "$agent" >/tmp/setup-capture-user.log
head -5 /tmp/setup-capture-user.log
[ "$(id -u "$agent")" = 1001 ] || die "$agent is uid $(id -u "$agent"), want 1001"
ah=$(getent passwd "$agent" | cut -d: -f6)

step "the agents, installed as $agent"
as_agent() { sudo -u "$agent" -H env -C "$ah" PATH="$ah/.local/bin:/usr/local/bin:/usr/bin:/bin" "$@"; }
as_agent mkdir -p "$ah/.local/bin" "$ah/.local/share/claude/versions"
install -o "$agent" -g "$agent" -m 755 "$dir/claude-$CLAUDE_VERSION" "$ah/.local/share/claude/versions/$CLAUDE_VERSION"
install -o "$agent" -g "$agent" -m 755 "$dir/agy-$AGY_VERSION" "$ah/.local/bin/agy"
as_agent ln -sfn "$ah/.local/share/claude/versions/$CLAUDE_VERSION" "$ah/.local/bin/claude"
# The version lock Claude Code's profile requires (agenttrace-install.sh).
as_agent mkdir -p "$ah/.claude"
as_agent sh -c 'printf "%s\n" "{\"env\": {\"DISABLE_UPDATES\": \"1\"}}" > "$HOME/.claude/settings.json"'
as_agent npm install -g --no-fund --no-audit --prefix "$ah/.local" "@openai/codex@$CODEX_VERSION" "opencode-ai@$OPENCODE_VERSION"

got_claude=$(as_agent env DISABLE_UPDATES=1 claude --version 2>/dev/null | awk '{print $1}')
got_codex=$(as_agent codex --version 2>/dev/null | awk '{print $NF}')
got_opencode=$(as_agent env OPENCODE_DISABLE_AUTOUPDATE=1 OPENCODE_DISABLE_MODELS_FETCH=1 opencode --version 2>/dev/null)
got_agy=$(as_agent env -u DBUS_SESSION_BUS_ADDRESS -u XDG_RUNTIME_DIR AGY_CLI_DISABLE_AUTO_UPDATE=true agy --version 2>/dev/null)
for pair in "claude:$CLAUDE_VERSION:$got_claude" "codex:$CODEX_VERSION:$got_codex" "opencode:$OPENCODE_VERSION:$got_opencode" "agy:$AGY_VERSION:$got_agy"; do
  IFS=: read -r n want got <<<"$pair"
  [ "$want" = "$got" ] || die "$n: wanted $want, got '$got'"
  echo "  OK $n $got"
done
# Whatever the version queries left in the home is not part of the image.
rm -rf "$ah/.cache" "$ah/.npm" "$ah/.claude.json" "$ah/.claude/statsig" "$ah/.codex" "$ah/.gemini" "$ah/.local/share/opencode" "$ah/.local/state" 2>/dev/null || true

step "the guest tools"
install -d /usr/local/lib/agent-trace-vm
install -m 755 "$dir"/guest/*.sh /usr/local/lib/agent-trace-vm/
rm -f /usr/local/lib/agent-trace-vm/provision.sh

step "kernel features the tool needs"
cfg=/boot/config-$(uname -r)
lsm=$(cat /sys/kernel/security/lsm)
case ",$lsm," in *,bpf,*) ;; *) die "bpf is not among the active LSMs ($lsm)" ;; esac
[ -r /sys/kernel/btf/vmlinux ] || die "no BTF (/sys/kernel/btf/vmlinux)"
for k in CONFIG_BPF_LSM CONFIG_DEBUG_INFO_BTF CONFIG_FANOTIFY CONFIG_UPROBES CONFIG_UPROBE_EVENTS CONFIG_BPF_SYSCALL CONFIG_BPF_JIT; do
  grep -q "^$k=y" "$cfg" || die "$k is not y in $cfg"
done
for f in bpf_dynptr_from_file bpf_dynptr_file_discard bpf_dynptr_copy; do
  grep -aq "$f" /sys/kernel/btf/vmlinux || die "the kernel's BTF has no kfunc $f (kernel hashing)"
done
echo "  OK lsm=$lsm, BTF, fanotify, uprobes, file dynptr kfuncs"

step "the boot of a run: no cloud-init, a network on any virtio NIC"
touch /etc/cloud/cloud-init.disabled
rm -f /etc/netplan/50-cloud-init.yaml
cat >/etc/netplan/90-agent-trace.yaml <<'EOF'
network:
  version: 2
  ethernets:
    nic:
      match: {name: "en*"}
      dhcp4: true
EOF
chmod 600 /etc/netplan/90-agent-trace.yaml
# A run mounts the logins disk and the results disk here.
install -d -m 755 /var/lib/agent-trace/logins /var/lib/agent-trace/results

step "the manifest"
mkdir -p /etc/agent-trace
python3 - "$ah" <<PY
import hashlib, json, os, subprocess, sys
ah = sys.argv[1]
def sh(*a):
    return subprocess.run(a, capture_output=True, text=True).stdout.strip()
def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()
# The npm packages as installed: every package's version, and the hash of
# every file over 1 MiB (the native binaries the agents run).
nm = os.path.join(ah, ".local/lib/node_modules")
npm = {"packages": {}, "binaries": {}}
for d, _, fs in os.walk(nm):
    for f in fs:
        p = os.path.join(d, f)
        if f == "package.json" and os.path.basename(os.path.dirname(d)) in ("node_modules", "@openai"):
            try:
                j = json.load(open(p))
                npm["packages"][os.path.relpath(d, nm)] = j.get("version")
            except (OSError, ValueError):
                pass
        elif os.path.isfile(p) and not os.path.islink(p) and os.path.getsize(p) > (1 << 20):
            npm["binaries"][os.path.relpath(p, nm)] = sha(p)
pkgs = {}
for p in "$APT_PACKAGES".split():
    n = p.split("=")[0]
    pkgs[n] = sh("dpkg-query", "-W", "-f", "\${Version}", n)
m = {
    "schema": 1,
    "recipe": {"commit": "$RECIPE_COMMIT", "dirty": "$RECIPE_DIRTY" == "true"},
    "agent_trace": {"commit": "$SRC_COMMIT", "path": "/home/trace/agent-trace"},
    "base_image": {"url": "$UBUNTU_IMAGE_URL", "sha256": "$UBUNTU_IMAGE_SHA256"},
    "os": sh("sh", "-c", ". /etc/os-release; echo \$PRETTY_NAME"),
    "kernel": {"release": sh("uname", "-r"), "package": "linux-image-$KERNEL_RELEASE",
               "package_version": sh("dpkg-query", "-W", "-f", "\${Version}", "linux-image-$KERNEL_RELEASE"),
               "lsm": open("/sys/kernel/security/lsm").read().strip(), "btf": os.path.exists("/sys/kernel/btf/vmlinux")},
    "apt": {"snapshot": "$APT_SNAPSHOT", "packages": pkgs},
    "go": sh("go", "version"),
    "users": {"operator": {"name": "trace", "uid": 1000}, "agents": {"name": "agenttrace", "uid": 1001}},
    "agents": {
        "claude-code": {"version": "$got_claude", "binary": "~/.local/share/claude/versions/$CLAUDE_VERSION",
                        "sha256": sha(os.path.join(ah, ".local/share/claude/versions/$CLAUDE_VERSION")), "source": "$CLAUDE_URL",
                        "lock": "~/.claude/settings.json env.DISABLE_UPDATES=1"},
        "codex": {"version": "$got_codex", "source": "npm @openai/codex@$CODEX_VERSION"},
        "opencode": {"version": "$got_opencode", "source": "npm opencode-ai@$OPENCODE_VERSION"},
        "gemini": {"version": "$got_agy", "binary": "~/.local/bin/agy", "sha256": sha(os.path.join(ah, ".local/bin/agy")),
                   "source": "the operator's install, checked against its pinned hash"},
    },
    "npm": npm,
    "built": sh("date", "--iso-8601=seconds"),
}
json.dump(m, open("/etc/agent-trace/image.json", "w"), indent=2)
open("/etc/agent-trace/image.json", "a").write("\n")
PY
cat /etc/agent-trace/image.json

step "clean up"
apt-get clean
rm -rf /tmp/build /tmp/setup-capture-user.log
cloud-init clean --logs >/dev/null 2>&1 || true
fstrim -av >/dev/null 2>&1 || true
echo "provision: done"
