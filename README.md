# rop4

rop4 is a Go port of [rop3](https://github.com/reverseame/rop3), a multi-architecture
ROP/JOP/RETF gadget finder. It searches ELF, PE and Mach-O binaries (x86, x86-64,
AArch64 and RISC-V, including compressed RISC-V) for gadgets, matches them against a
high-level operation language (ROPLang), and assembles ROP chains with a backtracking
search.

It is a faithful port: for the same input and options, rop4's gadgets, operation
matches and ROP chains are identical to rop3's. Disassembly uses the official
[Capstone](https://www.capstone-engine.org/) v5 C library through a small in-tree CGo
wrapper (there is no official Go binding for Capstone, and rop4 deliberately depends on
no third-party one). Binary parsing uses the Go standard library (`debug/elf`,
`debug/pe`, `debug/macho`).

## Differences from rop3

- **No Triton / symbolic validation.** rop3's optional `--symbolic` concolic pass (a
  Triton dependency) is not ported; Triton has no Go binding. All other functionality
  is present.
- **No Keystone.** rop3 uses Keystone as an optional fast path to locate `raw(...)`
  chain gadgets; rop4 always uses rop3's own Capstone disassembly fallback, so
  `raw(...)` steps work everywhere with no extra native dependency.

## Build

rop4 needs Go and libcapstone v5 and builds with CGo (`CGO_ENABLED=1`). On NixOS a
`shell.nix` is provided:

```sh
nix-shell ./shell.nix --run 'go build -o rop4 ./cmd/rop4'
```

On other systems, install libcapstone v5 (headers + shared library) and a Go
toolchain, then `CGO_ENABLED=1 go build ./cmd/rop4`.

## Usage

```sh
rop4 --binary /bin/ls                                  # dump gadgets
rop4 --binary /bin/ls --op mov --operands rdi rax      # search an operation
rop4 --binary libc.so.6 --ropchain chain.txt           # build a ROP chain
rop4 --binary /bin/ls --interactive                    # REPL, scans once
```

The flags mirror rop3: `--rop/--no-rop`, `--jop`, `--retf`, `--ret-imm`, `--frame/
--no-frame`, `--ropblock`, `--depth`, `--all`, `--badchar`, `--badchar-bytes`,
`--keep-canary-address`, `--base`, `--arch`, `--raw`, `--symbols`, `--reg-aliases`,
`--allow-undeterministic-gadgets`, `--allow-complex-memory-ops`,
`--allow-segment-override`, `--keep-contradictory`, `--op`/`--operands` (and the legacy
`--dst`/`--src`), `--ropchain`/`--exhaustive`/`--legacy-ropchain`, `--output
text|json|csv`, `--tuple`, `--interactive`, `--jobs`, `--cache`/`--cache-dir`,
`--verbose`. See rop3's README for the semantics of each; they are identical here.

## Tests

```sh
nix-shell ./shell.nix --run 'go test ./...'
```

`scripts/difftest.sh` runs rop4 and rop3 with the same arguments and diffs the output,
the harness used to validate parity during the port.

## License

GNU GPLv3 (same as rop3).
