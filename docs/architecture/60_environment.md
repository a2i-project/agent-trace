# Capture environment

Checked against commit 67a0cec on 2026-11-23.

## Objective

Every capture of an experiment runs in the same machine: a KVM virtual
machine built from pinned inputs by one command, booted fresh for every run,
with every kernel setting the probes need, the agents at their frozen
versions, run as the dedicated unprivileged user, and agent-trace built at a
recorded commit (I-166). The image and the recipe that built it are named in
every capture, so a result can be traced to the machine that produced it and
the machine rebuilt.

## Structure

`vm/` holds the recipe; nothing it produces is in the repository. Images,
overlays, the download cache, the SSH key and the logins disk live in
`$AGENT_TRACE_VM_HOME` (default `~/.cache/agent-trace-vm`), which the scripts
refuse inside the repository.

| File | Runs on | Does |
|---|---|---|
| `vm/inputs.env` | | the pinned inputs: the Ubuntu 26.04 cloud image (dated release URL and SHA-256), the kernel release and package version, the Ubuntu snapshot archive date and the packages with their versions, Go (URL and SHA-256), Claude Code (URL and SHA-256), Codex and OpenCode (npm versions), agy (version and SHA-256), the disk size and the build machine's size |
| `vm/lib.sh` | host | helpers: the cache, the SSH key, QEMU start and stop, SSH |
| `vm/build.sh` | host | builds the golden image with one command |
| `vm/run.sh` | host | boots a throwaway VM from the image and runs a shell, a command or a campaign in it |
| `vm/login.sh` | host | creates or updates the logins disk |
| `vm/guest/provision.sh` | guest, root, at build | installs and checks everything, writes the image manifest |
| `vm/guest/attach.sh` | guest, root | mounts the logins and results disks, found by their serial numbers |
| `vm/guest/logins.sh` | guest, root | records, saves and restores the sign-ins |
| `vm/guest/signin.sh` | guest, agenttrace | the agents' sign-ins |
| `vm/guest/campaign.sh` | guest, operator | starts a campaign detached and follows its log |

The image has two accounts besides root: the operator `trace` (uid 1000,
passwordless sudo, home mode 750), which owns `~/agent-trace` (a shallow
clone whose `HEAD` is the built commit, with the binaries `make build`
writes) and runs the captures, and `agenttrace` (uid 1001), which
`scripts/setup-capture-user.sh` creates and which runs the agents. The
manifest `/etc/agent-trace/image.json` records the recipe commit (and whether
`vm/` had uncommitted changes), the agent-trace commit, the base image URL
and SHA-256, the kernel release, package version and active LSMs, the
snapshot date and each package's installed version, the Go version, each
agent's version, Claude Code's and agy's binary SHA-256, the npm packages'
versions and the SHA-256 of every file over 1 MiB under them (the native
binaries), and the build time. `vm/build.sh` copies it beside the image
(`<image>.json`) and adds the image's file name, SHA-256, size and build time.

## Technologies

QEMU 10.2 with KVM as the user (no libvirt, no root on the host), qcow2
images and copy-on-write overlays, QEMU's user-mode network with one
forwarded port, cloud-init's NoCloud data source (`ds=nocloud` in the SMBIOS
serial, the seed served by Python's `http.server` on 127.0.0.1), SSH with a
key generated into the cache, the Ubuntu snapshot archive
(`apt --snapshot`), ext4 data disks.

## Workflow

**Build.** `vm/build.sh [--commit REV] [--allow-dirty]` downloads each input
into the cache and checks its SHA-256; agy, which no vendor URL serves by
version, is copied from the operator's install (`$AGY_SOURCE`, default the
`agy` on `PATH`) and checked against its pinned hash. It takes agent-trace at
`REV` (default `HEAD`) as a shallow clone, converts the cloud image into a
new disk of 40 GiB, boots it once with a seed that creates the operator with
the cache's key, copies the inputs in over SSH and runs
`vm/guest/provision.sh` as root. Provisioning refuses any kernel other than
the pinned `7.0.0-43-generic` (package `7.0.0-43.43`, the release the image
ships), holds every installed kernel package and disables the periodic apt
jobs; installs the pinned packages from the snapshot archive of
`APT_SNAPSHOT`; unpacks Go 1.26.0 (CI's version, from `go.mod`); builds
agent-trace as the operator (`make build`, `go build ./...`, and the fs
probe's and `cmd/watch`'s test binaries to fill the caches); creates
`agenttrace` with `scripts/setup-capture-user.sh`; installs the agents as
`agenttrace` as `agenttrace-install.sh` does (local only, the user's script)
on the host: Claude Code's binary at `~/.local/share/claude/versions/2.1.306`
with `~/.local/bin/claude` pointing at it and `~/.claude/settings.json`
setting `env.DISABLE_UPDATES` to `1`, Codex and OpenCode with
`npm install -g --prefix ~/.local`, agy copied to `~/.local/bin`; checks each
agent's version with its version lock in the environment, and removes what
the version queries left in the home. It then checks the kernel: `bpf` among
the active LSMs, `/sys/kernel/btf/vmlinux`, `CONFIG_BPF_LSM`,
`CONFIG_DEBUG_INFO_BTF`, `CONFIG_FANOTIFY`, `CONFIG_UPROBES`,
`CONFIG_UPROBE_EVENTS`, `CONFIG_BPF_SYSCALL` and `CONFIG_BPF_JIT`, and the
file dynptr kfuncs of kernel hashing (`bpf_dynptr_from_file`,
`bpf_dynptr_file_discard`, `bpf_dynptr_copy`) in the kernel's BTF; any
failure stops the build. Finally it disables cloud-init, so a run boots
without a seed, with a network on any virtio NIC; writes the manifest; and
cleans the package cache. The host powers the guest off, writes the disk as
`images/agent-trace-<commit>-<time>.qcow2` (read-only) with its SHA-256 and
manifest, and points `images/current.qcow2` at it. A recipe with uncommitted
changes under `vm/` is refused unless `--allow-dirty`, which the manifest
records.

**Run.** `vm/run.sh [--image IMG] [--cpus N] [--mem SIZE] [--logins DISK |
--no-logins] [--keep] [--wait] shell | exec 'COMMAND' | campaign [FLAGS] PLAN
OUTPUT_DIR` takes one of three slot locks (at most three VMs at once; `--wait`
waits for one), creates an overlay of the image (the image is never written),
boots it with 4 vCPUs and 8 GiB by default and a forwarded SSH port on
127.0.0.1, writes `/run/agent-trace/vm.json` in the guest (the image file, its
SHA-256 and the recipe commit from its manifest, the agent-trace commit, the
run's name, vCPUs and memory, whether a logins disk is attached), mounts the
disks, runs the mode, then powers the guest off and deletes the overlay
(`--keep` keeps it). `scripts/capture-agent.sh` copies `vm.json` into every
capture's `task-meta.txt` as a `vm=` line (I-166).

**Campaign.** `vm/run.sh campaign [FLAGS] PLAN OUTPUT_DIR` attaches a results
disk, `OUTPUT_DIR/vm-results.qcow2`, created on first use and kept, which one
VM at a time may use (a lock), writes `PLAN` onto it and starts
`scripts/capture-campaign.sh --run-as agenttrace FLAGS` in the guest as the
operator, detached from the SSH session, with the output on the results disk.
The values of the profiles' `secret_env` variables set on the host reach the
guest on SSH's stdin, are exported to the campaign and written nowhere. The
runner follows the campaign's log, reconnecting when SSH drops, and when it
ends copies the output to `OUTPUT_DIR/campaign/`. A VM or host that goes down
loses nothing the campaign wrote: the same command boots a fresh VM on the
same results disk and the campaign resumes (I-167).

**Logins.** `vm/login.sh [--logins DISK]` creates the logins disk (default
`$AGENT_TRACE_VM_HOME/logins.qcow2`, 2 GiB, mode 600) when absent, boots a
VM with it attached read-write, restores what it already holds, records the
hash of every file in `agenttrace`'s home, opens a console as `agenttrace`
that runs the sign-ins (Claude Code `claude auth login`, Codex
`codex login --device-auth`, agy interactively without a session bus; each
asked for first), then copies every file the sign-ins created or changed to
the disk, except the profiles' trace directories, caches and the agents'
installs, and prints the list. Every run attaches the disk through an overlay
of its own and copies the listed files into `agenttrace`'s home before
anything runs (I-168).

**Reproduce.**

1. Build the image: `vm/build.sh` (with a clean `vm/`).
2. Create the logins disk: `vm/login.sh`, then sign in to each agent in the
   console it opens.
3. Run a plan: `vm/run.sh campaign --seed N PLAN OUTPUT_DIR`, with
   `SCILIFELAB_API_KEY` set when the plan has OpenCode entries; run the same
   command again to resume.

The privileged tests that need the BPF LSM run in the same image:
`vm/run.sh exec scripts/test-privileged-local.sh` prints the
`Privileged-Tested-Locally:` line for the built commit.

## Guarantees and loss accounting

* Every download is checked against its pinned SHA-256 before use; a
  mismatch stops the build.
* An image is written only when every kernel check and every agent version
  check passed; its manifest states what it holds.
* A run never writes the image or the logins disk: both are behind an
  overlay that is deleted when the run ends.
* A capture made in a VM names the image's SHA-256 and the recipe commit in
  its `task-meta.txt`; a capture made elsewhere says `vm=none`.

## Known limits

* agy comes from the operator's install, not from a vendor URL: a machine
  without agy 1.4.7 (by hash) cannot build the image.
* Codex's and OpenCode's npm packages are pinned by version, not by hash; the
  manifest records what was installed, but a build does not refuse a registry
  that serves different bytes under the same version. The packages the
  snapshot archive does not hold (none today) would come from the live archive.
* Go modules come from the Go module proxy at build time, checked by
  `go.sum`.
* A sign-in whose agent rotates its refresh token at each refresh leaves the
  logins disk's copy stale once a run refreshes it, since a run never writes
  the disk back. Three VMs signed in to one account refresh independently.
* A sign-in that completes through a callback on the guest's `localhost`
  cannot be reached from the host's browser (only SSH is forwarded).
* The image's host key is the same in every VM; SSH runs without host key
  checking, on 127.0.0.1 only.
