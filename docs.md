# Hole-In-Bin — What To Do (step-by-step guide)

This is your practical checklist. `README.md` is the full write-up you submit and defend;
**this file is just "how to actually run and present it."**

---

## 0. What this project is (10-second version)

12 tiny 32-bit Linux programs (`ex00`…`ex11`) in the VM at `/opt/hole-in-bin`. Each has a bug.
You feed each one a crafted input so it prints a "win" message. The exploits are already written
in `scripts/exNN.py`. During the audit you run them **in the VM** and explain the assembly.

---

## 1. One-time setup in the VM

1. Import `hole-in-bin.ova` into VirtualBox (File → Import Appliance) and start it.
2. Log in: user **`user`**, password **`user`**.
3. Open a terminal and turn **ASLR off** (needed by ex06, ex09, ex11, and makes the rest stable):
   ```bash
   cat /proc/sys/kernel/randomize_va_space        # want 0
   # if it's not 0:
   echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
   ```
4. Get the `scripts/` folder into the VM (shared folder, or just copy/paste each small `.py`).
   You only need the `scripts/` directory — the binaries are already in `/opt/hole-in-bin`.

> You do **not** need the `vm/`, `challenges/`, or the extraction steps on audit day. Those were
> only used to build the project on the host. The audit uses the real binaries in the VM.

---

## 2. Run the exploits (in the VM)

Each script's top comment shows the exact command. Summary:

```bash
# stdin-based (pipe the payload in)
python3 ex00.py | /opt/hole-in-bin/ex00/bin
python3 ex03.py | /opt/hole-in-bin/ex03/bin
python3 ex04.py | /opt/hole-in-bin/ex04/bin
python3 ex07.py | /opt/hole-in-bin/ex07/bin
python3 ex08.py | /opt/hole-in-bin/ex08/bin
python3 ex09.py | /opt/hole-in-bin/ex09/bin

# argv-based (payload is a command-line argument)
/opt/hole-in-bin/ex01/bin "$(python3 ex01.py)"
/opt/hole-in-bin/ex05/bin "$(python3 ex05.py)"
/opt/hole-in-bin/ex10/bin "$(python3 ex10.py)"

# these set up the environment / multiple args themselves, so give them the target path
python3 ex02.py /opt/hole-in-bin/ex02/bin     # sets the GREENIE env var
python3 ex06.py /opt/hole-in-bin/ex06/bin     # heap unlink, 3 args
python3 ex11.py /opt/hole-in-bin/ex11/bin     # heap write-what-where, 2 args
```

**What success looks like (the win message per challenge):**

| run | expect to see |
|-----|---------------|
| ex00 | `you have changed the 'modified' variable` |
| ex01 | `you have correctly got the variable to the right value` |
| ex02 | `you have correctly modified the variable` |
| ex03 | `code flow successfully changed` |
| ex04 | `code flow successfully changed` |
| ex05 | `you have hit the target correctly :)` |
| ex06 | `that wasn't too bad now, was it? @ <number>` |
| ex07 | `you have modified the target :)` |
| ex08 | `you have modified the target :)` |
| ex09 | `code execution redirected! you win` |
| ex10 | `level passed` |
| ex11 | `and we have a winner @ <number>` |

> ex07/ex08/ex09 print a lot of padding first — scroll up, the win line is at the end.
> Run in a **real terminal** (not piped to a file); ex04 and ex09 rely on terminal buffering to
> show their line.

---

## 3. If something doesn't fire (troubleshooting)

Only one challenge is environment-sensitive: **ex04** (the exact offset to the return address can
shift with stack alignment). If `ex04` doesn't win, find the real offset in the VM:

```bash
gdb /opt/hole-in-bin/ex04/bin
(gdb) run                       # type a long line like AAAA...; it will crash
(gdb) info registers eip        # see which bytes landed in EIP
# or use a cyclic pattern; then edit OFFSET at the top of scripts/ex04.py
```

For ex06/ex09/ex11, if they fail, it's almost always ASLR — re-check step 1.3
(`randomize_va_space` must be `0`).

---

## 4. Disassemble the way the audit requires (assembly only!)

**Decompilers are forbidden.** Use these to read the binaries:

```bash
objdump -d -M intel /opt/hole-in-bin/ex00/bin        # full disassembly, Intel syntax
gdb /opt/hole-in-bin/ex00/bin
  (gdb) disassemble main        # read a function
  (gdb) break *0x080484xx       # set a breakpoint
  (gdb) run
  (gdb) x/16wx $esp             # inspect memory/stack
  (gdb) info registers
```

If you use **Ghidra**, stay in the **Listing (assembly) view** and **close the Decompiler window** —
show the examiner you're working from assembly.

---

## 5. Prepare for the role-play (this is graded)

For **each** challenge, be ready to say, in plain words:

1. **The bug** — which function is unsafe and why (`gets`/`strcpy` have no size limit;
   `printf(user)` lets the user control the format; a heap buffer sits next to a pointer).
2. **The fix** — e.g. `fgets`/`snprintf`, `printf("%s", user)`, bound the copy.
3. **How you exploited it** — the offset and what you overwrote (a variable / a function pointer /
   the return address / a GOT entry).
4. **Point at the assembly** — e.g. for ex04, show `sub esp,0x50`, `call gets`, `leave`, `ret`, and
   explain that `ret` pops the saved address you overwrote.

Each README section already contains exactly this (disassembly + explanation). Practice ex06 (heap
`unlink`) and the format-string ones (ex07–ex09) most — that's where they'll dig.

**Likely questions (from `audit.md`) and where the answer lives:**
- "How did you analyze/exploit?" → the per-challenge sections.
- "What vulnerabilities and impact?" → the "Vulnerability class" + "Key takeaway" lines.
- "How would you mitigate?" → README → *Remediation Suggestions*.
- "How did you stay ethical?" → README → *Ethical Hacking Report*.

---

## 6. Key terms to know cold

- **Buffer overflow** — writing past the end of a buffer into adjacent memory.
- **Saved return address** — where `ret` jumps back to; overwrite it = control EIP (ex04).
- **Function pointer** — a variable holding a code address that gets `call`ed (ex03, ex10).
- **Format string bug** — `printf(user)`; `%n` *writes* the number of chars printed to an address
  you supply (ex07–ex09).
- **GOT (Global Offset Table)** — where the addresses of libc functions are stored; writable here
  (no RELRO), so overwriting `puts`/`exit`'s entry redirects that call (ex09, ex11).
- **`unlink`** — old dlmalloc code run during `free()`; a corrupted chunk turns it into an
  arbitrary memory write (ex06).
- **Protections (all OFF here):** NX (no-exec memory), PIE (randomized code), stack canary,
  RELRO (read-only GOT), ASLR. Their absence is *why* these exploits are easy — see
  `scripts/checksec.sh`.

---

## 7. Submit

Commit everything (already done, one commit per challenge — run `git log --oneline` to show the
incremental work) and hand over the repo: `README.md` + `scripts/` are the core deliverable.
