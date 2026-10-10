#!/usr/bin/env bash
# Local test harness (DEV ONLY — the audit runs inside the VM).
#
# The challenge binaries are 32-bit ELF built against glibc 2.19 from the VM.
# This host is x86-64 WSL, so we run them with the *VM's own* loader + libc
# (extracted from the VM disk image) to reproduce the VM environment faithfully.
#
# Usage:
#   scripts/runlocal.sh challenges/ex00/bin            # run interactively
#   <payload-producer> | scripts/runlocal.sh <bin>     # pipe a payload in
#
# Override the lib dir with VMLIB=/path if you relocate the extracted libs.
set -euo pipefail
VMLIB="${VMLIB:-/tmp/claude-1000/-home-skopetos-cyber-hole-in-bin/17825846-b056-4f9b-bc60-07ca128a0f99/scratchpad/lib32}"
LD="$VMLIB/ld-linux.so.2"
if [[ ! -x "$LD" ]]; then
  echo "ERROR: VM loader not found at $LD" >&2
  echo "Re-extract libc-2.19.so/ld-2.19.so from the VM image, or set VMLIB." >&2
  exit 1
fi
exec "$LD" --library-path "$VMLIB" "$@"
