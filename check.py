#!/usr/bin/env python3
"""Referee for the Sudoku shellcode puzzle (see README.md).

usage: check.py N answer.bin
Exit status 0 iff the answer passes both the Sudoku check and the execution check.
"""
import sys

from unicorn import (UC_ARCH_X86, UC_HOOK_INSN, UC_HOOK_INTR, UC_MODE_64,
                     UC_PROT_ALL, UC_PROT_READ, UC_PROT_WRITE, Uc, UcError)
from unicorn.x86_const import *

SIZE = 128
PAGE = 0x1000
CODE_BASE = 0x10000
STACK_BASE = 0x100000
STACK_HALF = 0x8000  # writable stack above and below the entry rsp
STACK_SIZE = 2 * STACK_HALF + PAGE
ENTRY_RSP = STACK_BASE + STACK_HALF + 8  # rsp = 8 mod 16, as after `call` from an aligned frame
RET_ADDR = 0x200000
MAX_INSNS = 100_000
GPRS = [UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
        UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_R8,
        UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11, UC_X86_REG_R12,
        UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15]


def sudoku_errors(b: bytes) -> list[str]:
    grid = [[b[8 * r + c // 2] >> 4 if c % 2 == 0 else b[8 * r + c // 2] & 0xF
             for c in range(16)] for r in range(16)]
    groups = {}
    for r in range(16):
        groups[f"row {r}"] = grid[r]
    for c in range(16):
        groups[f"col {c}"] = [grid[r][c] for r in range(16)]
    for br in range(4):
        for bc in range(4):
            groups[f"box ({br},{bc})"] = [grid[4 * br + i][4 * bc + j]
                                          for i in range(4) for j in range(4)]
    return [f"{name}: {' '.join(f'{v:X}' for v in vals)}"
            for name, vals in groups.items() if sorted(vals) != list(range(16))]


def run(code: bytes, want: bytes) -> str | None:
    """Execute from the initial state described in README.md. Returns an error or None."""
    uc = Uc(UC_ARCH_X86, UC_MODE_64)  # mapped memory starts zeroed
    uc.mem_map(CODE_BASE, PAGE, UC_PROT_ALL)
    uc.mem_write(CODE_BASE, code)
    uc.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)
    uc.mem_write(ENTRY_RSP, RET_ADDR.to_bytes(8, "little"))
    uc.mem_map(RET_ADDR, PAGE, UC_PROT_ALL)
    uc.mem_write(RET_ADDR, b"\xf4" * PAGE)  # hlt; emulation stops before executing it
    for reg in GPRS:
        uc.reg_write(reg, 0)
    uc.reg_write(UC_X86_REG_RSP, ENTRY_RSP)
    uc.reg_write(UC_X86_REG_RFLAGS, 0x202)

    traps = []
    def on_trap(uc, *args):
        traps.append(f"interrupt/syscall at rip={uc.reg_read(UC_X86_REG_RIP):#x}")
        uc.emu_stop()
    uc.hook_add(UC_HOOK_INTR, on_trap)
    uc.hook_add(UC_HOOK_INSN, on_trap, None, 1, 0, UC_X86_INS_SYSCALL)
    uc.hook_add(UC_HOOK_INSN, on_trap, None, 1, 0, UC_X86_INS_SYSENTER)

    try:
        uc.emu_start(CODE_BASE, RET_ADDR, count=MAX_INSNS)
    except UcError as e:
        return f"{e} at rip={uc.reg_read(UC_X86_REG_RIP):#x}"
    if traps:
        return traps[0]
    rip, rsp, rax = (uc.reg_read(r) for r in (UC_X86_REG_RIP, UC_X86_REG_RSP, UC_X86_REG_RAX))
    if rip != RET_ADDR:
        return f"did not return within {MAX_INSNS} instructions (rip={rip:#x})"
    if rsp != ENTRY_RSP + 8:
        return f"returned with rsp off by {rsp - (ENTRY_RSP + 8):+#x}"
    try:
        got = bytes(uc.mem_read(rax, len(want)))
    except UcError:
        return f"rax={rax:#x} points to unmapped memory"
    if got != want:
        return f"[rax] = {got!r}, want {want!r}"
    return None


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    n, path = sys.argv[1], sys.argv[2]
    if not (len(n) == 6 and n.isascii() and n.isdigit()):
        print(f"N must be six ASCII digits, got {n!r}", file=sys.stderr)
        return 2
    code = open(path, "rb").read()
    if len(code) != SIZE:
        print(f"FAIL: answer is {len(code)} bytes, want {SIZE}")
        return 1

    errors = sudoku_errors(code)
    print("sudoku: ok" if not errors else f"sudoku: FAIL ({len(errors)} bad groups)")
    for e in errors[:8]:
        print(f"  {e}")

    err = run(code, n.encode() + b"\0")
    print("exec: ok" if not err else f"exec: FAIL\n  {err}")

    return 0 if not errors and not err else 1


if __name__ == "__main__":
    sys.exit(main())
