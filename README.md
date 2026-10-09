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
rop4 --binary libc.so.6 --ropchain chain.txt           # build a ROP chain from a file
rop4 --binary libc.so.6 --ropchain mprotect            # build a bundled ROP chain
rop4 --binary /bin/ls --interactive                    # REPL, scans once
```

Arguments use the Go standard-library `flag` package. Boolean options default
sensibly and are turned off with the idiomatic `-flag=false` form (there are no
`--no-xxx` aliases). List options (`-binary`, `-base`, `-badchar`, `-badchar-bytes`,
`-operands`) are repeatable or comma-separated, e.g. `-operands rdi,rax`. Either one
or two leading dashes work (`-binary` or `--binary`).

Flags: `-rop` (default on), `-jop`, `-retf`, `-ret-imm`, `-frame` (default on),
`-ropblock`, `-depth`, `-all`, `-badchar`, `-badchar-bytes`, `-keep-canary-address`,
`-base`, `-arch`, `-raw`, `-symbols`, `-reg-aliases`, `-allow-undeterministic-gadgets`,
`-allow-complex-memory-ops`, `-allow-segment-override`, `-keep-contradictory`, `-op`,
`-operands`, `-ropchain`, `-exhaustive`, `-output text|json|csv`, `-tuple`,
`-interactive`, `-jobs` (defaults to the CPU count), `-cache`, `-cache-dir`, `-verbose`.

The rop3 backward-compatibility options are intentionally dropped for a cleaner,
faster tool: the legacy `--dst`/`--src` operand flags, and `--legacy-ropchain` with its
whole-chain "Tree" engine (rop4 keeps only the order-aware chain engine). Gadget,
operation and ROP-chain results are otherwise identical to rop3.

## Writing ROP chains

`--ropchain` takes a ROPLang chain. The value is either a path to a chain file or,
when no such file exists, the name of a chain bundled inside rop4 (see below). rop4
parses the chain into high-level operations, matches each against the gadgets found
in the target binary, and assembles a working chain with a backtracking search.

A chain file is plain text, one step per line. Blank lines are ignored and `;` starts
a comment to end of line. Each step is either an operation call or a `raw(...)` step:

```
; mprotect(addr, len, PROT_READ|PROT_WRITE|PROT_EXEC) on amd64
lc(rdi)          ; rdi <- addr    page-aligned base
lc(rsi)          ; rsi <- len     region length
lc(rdx)          ; rdx <- 7       PROT_READ|PROT_WRITE|PROT_EXEC
lc(rax)          ; rax <- 10      mprotect syscall number
raw([syscall], [], [], [rdi, rsi, rdx, rax])
```

**Operations** are written `op(operand, operand, ...)` with positional operands
drawn from the ROPLang catalog (`internal/roplang/roplang/*.yaml`). Common ones:

- `lc(reg)` — load a constant into `reg` (a stack pop the caller fills in);
- `mov(dst, src)`, `add(dst, src)` — register-to-register data and arithmetic;
- `ld(dst, src)` — load from memory at `src` into `dst`; `st(dst, src)` — store `src`
  to memory at `dst`;
- `jmp(reg)` — transfer control to the address in `reg`;
- `free(reg)` — release a generic register slot so the search may reuse it.

An operand is either a **concrete register** for the target architecture (`rdi`, `rax`
on amd64; `ebx` on x86; `x0` on AArch64; `a0` on RISC-V) or a **generic slot**
(`reg1`, `reg2`, ..., or `TMP_REG*`). A generic slot lets the search pick any suitable
register; `free(regN)` ends a slot's lifetime so it can be reused later in the chain.

**Raw steps** pin exact instructions when no operation expresses them, written
`raw([mnemonics], [immediates], [stack], [clobbered regs])`. The mnemonic list gives
the instructions to locate (e.g. `[syscall]`, `[mov, svc]`), and the last list names
the registers the step consumes. rop4 resolves each raw step by rescanning the target
binary for a matching gadget, so raw steps work with no external assembler.

### Bundled chains

rop4 ships a few example chains embedded in the binary. Pass a bare name and rop4
loads the variant for the target binary's detected architecture, so the same command
works across architectures:

```sh
rop4 --binary ./target --ropchain mprotect      # make a page RWX, then jump into it
rop4 --binary ./target --ropchain syscall_exec  # execve("/bin/sh", ...) via syscall
rop4 --binary ./target --ropchain turing         # a Turing machine in ROP (amd64)
```

| Name           | Architectures                 |
|----------------|-------------------------------|
| `mprotect`     | amd64, x86, aarch64, riscv    |
| `syscall_exec` | amd64, x86, aarch64, riscv    |
| `turing`       | amd64                         |

A name with no variant for the detected architecture (for example `turing` on a
non-amd64 binary) reports which architectures it does cover. A real file path always
takes precedence over a bundled name. The chain sources live in
`internal/ropchain/chains/` and are embedded with `//go:embed`; add a
`<name>_<arch>.txt` there to ship another one.

## Python API

rop4 can be driven from Python. Build it as a C shared library and use the thin
`python/rop4.py` wrapper, whose `Rop4` class mirrors rop3's `Rop3`:

```sh
nix-shell ./shell.nix --run 'go build -buildmode=c-shared -o python/librop4.so ./pybind'
```

```python
import sys; sys.path.insert(0, "python")
from rop4 import Rop4            # Rop3 is an alias

r = Rop4("libc.so.6", symbols=True)
for g in r.gadgets():            # list of dicts (same shape as --output json)
    print(g["vaddr"], g["gadget"])

r.find_op("mov", ["rdi", "rax"]) # gadget dicts, or (compound op) a list of chains
r.ropchain("chain.txt")          # list of chains, each a list of gadget dicts
r.describe()                     # per-binary metadata
```

The wrapper loads `python/librop4.so` (override with the `ROP4_LIB` environment
variable). The library links libcapstone; on NixOS its path is baked into the
shared object's RPATH, so it loads without a nix-shell.

## Tests

```sh
nix-shell ./shell.nix --run 'go test ./...'
```

`scripts/difftest.sh` runs rop4 and rop3 with the same arguments and diffs the output,
the harness used to validate parity during the port.

## License

GNU GPLv3 (same as rop3).
