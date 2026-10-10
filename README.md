# Hole-In-Bin — Reverse Engineering & Binary Exploitation

> Educational project. All analysis and exploitation was performed **only** inside the
> provided, isolated VM (`hole-in-bin`), against the binaries shipped in `/opt/hole-in-bin`.
> Nothing here targets any live or third-party system.

## Table of Contents
- [Environment & Tooling](#environment--tooling)
- [Methodology](#methodology)
- [Challenge Walkthroughs](#challenge-walkthroughs)
- [Remediation Suggestions](#remediation-suggestions)
- [Ethical Hacking Report](#ethical-hacking-report)
- [Bonus](#bonus)

---

## Environment & Tooling

- **VM:** `hole-in-bin` (provided OVA/UTM image), user `user` / `user`.
- **Target binaries:** `/opt/hole-in-bin/<challenge>/` — each folder has a binary + `README.txt`.
- **Allowed tools:** Ghidra (Listing/Assembly view **only** — Decompiler forbidden), GDB, PEDA, radare2, Python, Bash.
- **Prohibited:** decompilers / decompiler views, automated external exploitation tools.

Baseline recon for each binary (protections, symbols, strings):

```bash
file ./<binary>
checksec --file=./<binary>      # or: readelf -a / rabin2 -I
objdump -d -M intel ./<binary>  # disassembly (allowed)
strings -a ./<binary>
```

---

## Methodology

For every challenge the same disciplined loop was applied:

1. **Recon** — `file`, `checksec`, `strings`, identify architecture & protections (NX, PIE, canary, RELRO, ASLR).
2. **Static analysis** — disassemble (`objdump -M intel`, radare2 `pdf`, or Ghidra Listing view) to map functions, find the vulnerable input path.
3. **Dynamic analysis** — GDB: find the offset to control flow, inspect the stack/registers, locate useful gadgets or target addresses.
4. **Exploit development** — craft the payload (overflow offset + target address / shellcode), scripted in Python/Bash.
5. **Verification** — run the exploit in the VM, confirm the win condition (shell, flag, or privileged function).
6. **Remediation** — note how the bug would be fixed in source and at build time.

---

## Challenge Walkthroughs

<!-- One section per challenge, filled in once each binary is analyzed in the VM. -->

### Challenge: _<name>_  (TODO)

- **Binary:** `/opt/hole-in-bin/<name>/<bin>`
- **Protections (checksec):** _TODO_
- **Vulnerability class:** _TODO (e.g. stack buffer overflow, format string, ret2win, ret2libc, ...)_
- **Goal / win condition:** _TODO_

**Analysis**

_Step-by-step: key functions, the vulnerable call, the assembly instructions that matter._

**Exploitation**

_Offset discovery, payload layout, commands/script used (see `scripts/`)._

**Key takeaways**

_What this challenge teaches._

---

## Remediation Suggestions

_General + per-vulnerability fixes (safe functions, bounds checks, compiler hardening flags such as
`-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, `-pie -fPIE`, full RELRO, enabling ASLR/NX, etc.).
Filled in per challenge._

---

## Ethical Hacking Report

### Importance of proper authorization
_TODO_

### Legal and ethical boundaries
_TODO_

### Responsible disclosure practices
_TODO_

---

## Bonus
_Alternative exploitation paths, custom shellcode, ROP, etc. (optional)._
