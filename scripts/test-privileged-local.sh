#!/usr/bin/env bash
# Run, as root on this machine, the privileged tests that GitHub's runners
# cannot run, and print the trailer line that records the run (I-129).
#
# The kernel content copy of the fs probe needs kernel 7.0 with the
# BPF LSM active, which the runners lack, so its tests skip in CI. This script
# builds each package's test binary as the invoking user (root never writes
# to the Go build cache), runs it under sudo, fails when a test that needs
# the BPF LSM skipped, and on success prints:
#
#   Privileged-Tested-Locally: <kernel> <commit> <date>
#
# Add that line as a trailer to a commit in the same push (for example an
# empty commit made after the last rebase); scripts/check-docs.py commits
# requires it for a range that changes pkg/probe/fs.
#
# Usage: scripts/test-privileged-local.sh [extra go test flags, e.g. -test.run X]
set -uo pipefail

# Packages whose privileged tests need a kernel the runners lack.
PACKAGES=(./pkg/probe/fs)
# Tests that must not skip: they are the ones the runners cannot run.
MUST_RUN='^TestKernelHash_'

root=$(git rev-parse --show-toplevel) || exit 2
cd "$root" || exit 2
commit=$(git rev-parse --short=12 HEAD)
kernel=$(uname -r)
date=$(date +%F)
clean=yes
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
  clean=no
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
status=pass
for pkg in "${PACKAGES[@]}"; do
  bin="$work/$(basename "$pkg").test"
  if ! go test -c -o "$bin" "$pkg"; then
    echo "build failed: $pkg" >&2
    status=fail
    continue
  fi
  log="$work/$(basename "$pkg").log"
  # The test binary runs in the package directory, as go test runs it.
  if ! (cd "$pkg" && sudo "$bin" -test.v -test.count=1 "$@") 2>&1 | tee "$log"; then
    status=fail
  fi
  if grep -q -- "^--- FAIL" "$log" || ! grep -q "^PASS$\|^ok" "$log"; then
    status=fail
  fi
  if grep -E -- "--- SKIP: ${MUST_RUN#^}" "$log" >/dev/null; then
    echo "a test that needs kernel 7.0 with the BPF LSM skipped on $kernel:" >&2
    grep -E -A1 -- "--- SKIP: ${MUST_RUN#^}" "$log" | head -4 >&2
    status=fail
  fi
done

echo
if [ "$status" != pass ]; then
  echo "privileged tests FAILED on kernel $kernel at $commit; no trailer line"
  exit 1
fi
if [ "$clean" != yes ]; then
  echo "privileged tests passed on kernel $kernel, but the tree has uncommitted changes, so no commit was tested; commit and rerun"
  exit 1
fi
echo "privileged tests passed on kernel $kernel at $commit. Trailer line to paste:"
echo
echo "Privileged-Tested-Locally: $kernel $commit $date"
