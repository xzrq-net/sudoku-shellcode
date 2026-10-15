# Sudoku shellcode

You will be given a six-digit number (`000000` to `999999`). Your answer must be
128 bytes that are, at the same time:

1. **A valid 16×16 Sudoku.** Each byte fills two cells, high nibble first, row
   by row, so each row of the grid is 8 consecutive bytes. Every row, column
   and 4×4 box must contain each hex digit 0–F exactly once.
2. **An x86-64 function**, invoked with `call`, that returns a pointer to the
   six digits (leading zeros included) as a NUL-terminated string.

Once you are given the number, you have 60 seconds to answer. What you are
building is a generator that works for any number:

    ./gen 482913 > answer.bin

Also explain how it works in `WRITEUP.md`.

## Checking

    python check.py 482913 answer.bin

This checks both properties. It runs the code in an emulator from a fixed
initial state; for any detail not covered here, the checker is the referee.

## Environment

`nix develop` (or direnv) enters a dev shell. On first entry it creates a
Python venv in `.venv`; add packages with `uv add`. This is NixOS, so script
shebangs need `/usr/bin/env`.

## Ground rules

- Please don't look up existing solutions to this puzzle. Solve it yourself.
- Stick to common, well-known libraries and tools.
- Don't change check.py.
