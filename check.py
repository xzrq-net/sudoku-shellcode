#!/usr/bin/env python3
"""Referee for the Sudoku shellcode puzzle (see README.md).

usage: check.py N answer.bin [SEED]
Exit status 0 iff the answer passes both the Sudoku check and the execution check.
The code runs from several random initial states; SEED reruns one of them.
"""
import random
import sys

from unicorn import (UC_ARCH_X86, UC_HOOK_INSN, UC_HOOK_INTR, UC_MODE_64,
                     UC_PROT_ALL, UC_PROT_EXEC, UC_PROT_READ, UC_PROT_WRITE, Uc,
                     UcError)
from unicorn.x86_const import *

SIZE = 128
PAGE = 0x1000
STACK_HALF = 0x8000  # mapped stack above and below the entry rsp
STACK_SIZE = 2 * STACK_HALF + PAGE
MAX_INSNS = 100_000
TRIALS = 5
GPRS = [UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
        UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_R8,
        UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11, UC_X86_REG_R12,
        UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15]
STATUS_FLAGS = [0, 2, 4, 6, 7, 11]  # CF PF AF ZF SF OF; DF stays clear per the ABI


def random_page(rng: random.Random, lo: int, hi: int) -> int:
    return rng.randrange(lo // PAGE, hi // PAGE) * PAGE


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


def run(code: bytes, want: bytes, seed: int) -> str | None:
    """Execute from a random initial state (see README.md). Returns an error or None."""
    rng = random.Random(seed)
    code_base = random_page(rng, 0x5500_0000_0000, 0x5600_0000_0000)
    ret_addr = random_page(rng, 0x5600_0000_0000, 0x5700_0000_0000)
    stack_base = random_page(rng, 0x7f00_0000_0000, 0x7ff0_0000_0000)
    entry_rsp = stack_base + STACK_HALF + 8  # rsp = 8 mod 16, as after `call` from an aligned frame

    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(code_base, PAGE, UC_PROT_ALL)  # rest of the page is zero
    uc.mem_write(code_base, code)
    uc.mem_map(ret_addr, PAGE, UC_PROT_READ | UC_PROT_EXEC)
    uc.mem_write(ret_addr, b"\xf4" * PAGE)  # hlt; emulation stops before executing it
    uc.mem_map(stack_base, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)
    uc.mem_write(stack_base, rng.randbytes(STACK_SIZE))  # stale garbage
    uc.mem_write(entry_rsp, ret_addr.to_bytes(8, "little"))
    caller_frames = bytes(uc.mem_read(entry_rsp + 8, stack_base + STACK_SIZE - entry_rsp - 8))
    for reg in GPRS:
        uc.reg_write(reg, rng.getrandbits(64))
    uc.reg_write(UC_X86_REG_RSP, entry_rsp)
    uc.reg_write(UC_X86_REG_RFLAGS, 0x202 | sum(rng.getrandbits(1) << b for b in STATUS_FLAGS))

    traps = []
    def on_trap(uc, *args):
        traps.append(f"interrupt/syscall at rip={uc.reg_read(UC_X86_REG_RIP):#x}")
        uc.emu_stop()
    uc.hook_add(UC_HOOK_INTR, on_trap)
    uc.hook_add(UC_HOOK_INSN, on_trap, None, 1, 0, UC_X86_INS_SYSCALL)
    uc.hook_add(UC_HOOK_INSN, on_trap, None, 1, 0, UC_X86_INS_SYSENTER)

    try:
        uc.emu_start(code_base, ret_addr, count=MAX_INSNS)
    except UcError as e:
        return f"{e} at rip={uc.reg_read(UC_X86_REG_RIP):#x}"
    if traps:
        return traps[0]
    rip, rsp, rax = (uc.reg_read(r) for r in (UC_X86_REG_RIP, UC_X86_REG_RSP, UC_X86_REG_RAX))
    if rip != ret_addr:
        return f"did not return within {MAX_INSNS} instructions (rip={rip:#x})"
    if rsp != entry_rsp + 8:
        return f"returned with rsp off by {rsp - (entry_rsp + 8):+#x}"
    if bytes(uc.mem_read(entry_rsp + 8, len(caller_frames))) != caller_frames:
        return "modified the caller's stack frames above the return address"

    # The caller goes on to make more calls, reusing the stack below its rsp.
    uc.mem_write(stack_base, rng.randbytes(rsp - stack_base))
    try:
        got = bytes(uc.mem_read(rax, len(want)))
    except UcError:
        return f"rax={rax:#x} points to unmapped memory"
    if got != want:
        return f"[rax] = {got!r} after the caller reused its stack, want {want!r}"
    return None


def main() -> int:
    if len(sys.argv) not in (3, 4):
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

    seeds = [int(sys.argv[3])] if len(sys.argv) > 3 else [random.getrandbits(32) for _ in range(TRIALS)]
    err = None
    for seed in seeds:
        if err := run(code, n.encode() + b"\0", seed):
            break
    print(f"exec: ok ({len(seeds)} runs)" if not err else f"exec: FAIL (seed {seed})\n  {err}")

    return 0 if not errors and not err else 1


if __name__ == "__main__":
    sys.exit(main())
