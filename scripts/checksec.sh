#!/usr/bin/env bash
# Minimal checksec using only readelf (no external checksec/pwntools needed).
# Reports: arch, NX, PIE, Stack Canary, RELRO  for each binary passed as arg.
set -u
printf "%-24s %-8s %-5s %-5s %-7s %-10s\n" "BINARY" "ARCH" "NX" "PIE" "CANARY" "RELRO"
for b in "$@"; do
  [[ -f "$b" ]] || continue
  hdr=$(readelf -h "$b" 2>/dev/null)
  arch=$(echo "$hdr" | awk -F: '/Machine/{gsub(/^ +/,"",$2);print $2}' | sed 's/Intel 80386/i386/;s/Advanced Micro Devices X86-64/x86-64/')
  etype=$(echo "$hdr" | awk -F: '/Type/{gsub(/^ +/,"",$2);print $2}')
  # PIE: ET-DYN with a PT_INTERP/DYN flag => PIE; EXEC => No PIE
  if echo "$etype" | grep -q "DYN"; then pie="Yes"; else pie="No"; fi
  # NX: GNU_STACK segment flags - 'RWE' means executable stack (NX off)
  if readelf -l "$b" 2>/dev/null | grep -A1 GNU_STACK | grep -q "RWE"; then nx="No"; else nx="Yes"; fi
  # Canary: presence of __stack_chk_fail symbol
  if readelf -s "$b" 2>/dev/null | grep -q "__stack_chk_fail"; then can="Yes"; else can="No"; fi
  # RELRO: GNU_RELRO present? + BIND_NOW => Full, GNU_RELRO only => Partial, none => No
  if readelf -l "$b" 2>/dev/null | grep -q GNU_RELRO; then
    if readelf -d "$b" 2>/dev/null | grep -q "BIND_NOW"; then relro="Full"; else relro="Partial"; fi
  else relro="No"; fi
  printf "%-24s %-8s %-5s %-5s %-7s %-10s\n" "$b" "$arch" "$nx" "$pie" "$can" "$relro"
done
