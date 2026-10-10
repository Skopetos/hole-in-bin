#!/usr/bin/env bash
# Local test harness (DEV ONLY — the audit runs inside the VM).
#
# The challenge binaries are 32-bit ELF built against glibc 2.19 from the VM.
# This host is x86-64 WSL, so to run them faithfully we patch a *copy* of the
# binary to use the VM's own loader (ld-2.19.so) + libc (libc-2.19.so),
# extracted from the VM disk image, and run that copy directly as `./bin`.
#
# Patching the interpreter (instead of invoking `ld-linux.so.2 ./bin`) keeps
# argv == [bin] and normal lazy PLT binding, so the stack layout / alignment
# matches a native run — important for return-address and stack-address offsets.
#
# Usage:
#   scripts/runlocal.sh challenges/ex00/bin [args...]      # run (stdin inherited)
#   <payload> | scripts/runlocal.sh challenges/ex00/bin    # pipe a payload in
#
# Env: VMLIB=/path to override the extracted-lib dir.
set -euo pipefail
VMLIB="${VMLIB:-/tmp/claude-1000/-home-skopetos-cyber-hole-in-bin/17825846-b056-4f9b-bc60-07ca128a0f99/scratchpad/lib32}"
LD="$VMLIB/ld-linux.so.2"
PATCHELF="${PATCHELF:-/tmp/claude-1000/-home-skopetos-cyber-hole-in-bin/17825846-b056-4f9b-bc60-07ca128a0f99/scratchpad/debs/root/usr/bin/patchelf}"
CACHE="${CACHE:-/tmp/claude-1000/-home-skopetos-cyber-hole-in-bin/17825846-b056-4f9b-bc60-07ca128a0f99/scratchpad/patched}"

[[ -x "$LD" ]]       || { echo "ERROR: VM loader not found at $LD" >&2; exit 1; }
[[ -x "$PATCHELF" ]] || { echo "ERROR: patchelf not found at $PATCHELF" >&2; exit 1; }

bin="$1"; shift
[[ -f "$bin" ]] || { echo "ERROR: binary not found: $bin" >&2; exit 1; }

mkdir -p "$CACHE"
# cache key from the full path so ex00/bin and ex01/bin don't collide
key=$(echo "$bin" | tr '/' '_')
copy="$CACHE/$key"
if [[ ! -f "$copy" || "$bin" -nt "$copy" ]]; then
  cp "$bin" "$copy"
  "$PATCHELF" --set-interpreter "$LD" --set-rpath "$VMLIB" "$copy"
fi
exec "$copy" "$@"
