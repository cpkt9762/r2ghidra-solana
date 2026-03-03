<img width="150" height="150" align="left" style="float: left; margin: 0 10px 0 0;" alt="r2ghidra logo" src="https://raw.githubusercontent.com/radareorg/r2ghidra/master/dist/images/logo.png">

# r2ghidra-solana

[![ci](https://github.com/cpkt9762/r2ghidra-solana/actions/workflows/ci.yml/badge.svg)](https://github.com/cpkt9762/r2ghidra-solana/actions/workflows/ci.yml)

Ghidra decompiler plugin for [radare2](https://github.com/radareorg/radare2) with **Solana sBPF** enhancements. Fork of [radareorg/r2ghidra](https://github.com/radareorg/r2ghidra) — adds 6 Solana-specific analyzers that transform raw hex offsets into meaningful account field names, resolve syscalls, and recover Anchor dispatch tables.

> **Requires**: [radare2-solana](https://github.com/cpkt9762/radare2-solana) (provides the sBPF disassembler architecture plugin)

<br clear="left"/>

## What's Different from Upstream r2ghidra?

| Feature | Upstream r2ghidra | r2ghidra-solana |
|---|---|---|
| sBPF input buffer offsets | Raw hex (`0x50`, `0x2870`) | Named symbols (`ACCOUNT_0_LAMPORTS`, `ACCOUNT_1_KEY`) |
| Solana syscall resolution | No | Yes — 42+ syscalls (`sol_invoke_signed_c`, `sol_log_`, etc.) |
| Anchor discriminator dispatch | No | Auto-detected, labeled |
| Global pointer strings | No | Resolved to string literals |
| Struct field hints | No | Type-aware field annotations |
| IDA signature factory | No | Generate `.sig` files from Solana program `.rlib` |

## Showcase

### Decompilation (`pdg`)

The decompiler automatically resolves Solana input buffer offsets into human-readable account field names:

```c
uint64_t entry0(uint8_t *input)
{
    // ...
    if (*input != 3) {
        return 1;
    }
    if ((*(input + ACCOUNT_1_HEADER) != 0xff) || (*(input + ACCOUNT_2_HEADER) != 0xff)) {
        return 2;
    }
    if (*(input + INSTRUCTION_DATA_LEN) != 8) {
        return 3;
    }
    uStack_11c = *(input + INSTRUCTION_DATA);
    if (uStack_11c <= *(input + ACCOUNT_0_LAMPORTS)) {
        puStack_e0 = input + ACCOUNT_0_KEY;
        puStack_d0 = input + ACCOUNT_1_KEY;
        puStack_110 = input + ACCOUNT_2_KEY;
        puStack_b0 = input + ACCOUNT_0_KEY;
        puStack_a8 = input + ACCOUNT_0_LAMPORTS;
        uStack_a0 = *(input + ACCOUNT_0_DATA_LEN);
        puStack_98 = input + ACCOUNT_0_DATA;
        puStack_90 = input + ACCOUNT_0_OWNER;
        uStack_88 = *(input + ACCOUNT_0_RENT_EPOCH);
        puStack_78 = input + ACCOUNT_1_KEY;
        puStack_70 = input + ACCOUNT_1_LAMPORTS;
        uStack_68 = *(input + ACCOUNT_1_DATA_LEN);
        puStack_60 = input + ACCOUNT_1_DATA;
        puStack_58 = input + ACCOUNT_1_OWNER;
        uStack_50 = *(input + ACCOUNT_1_RENT_EPOCH);
        entry0(&puStack_110, &puStack_b0, 2, 0, 0);
        return 0;
    }
    return 4;
}
```

### Disassembly (`pdf`)

```
            ;-- entrypoint:
┌ 992: entry0 ();
│           0x000000e8      ldxdw r2, [r1]
│       ┌─< 0x000000f0      jne r2, 0x3, 0x00000468
│       │   0x000000f8      ldxb r2, [r1+0x2868]
│      ┌──< 0x00000100      jne r2, 0xff, 0x00000480
│      ││   0x00000108      ldxb r2, [r1+0x50c8]
│     ┌───< 0x00000110      jne r2, 0xff, 0x00000480
│     │││   0x00000118      ldxdw r4, [r1+0x7938]
│    ┌────< 0x00000120      jne r4, 0x8, 0x00000498
│    ││││   0x00000128      ldxdw r4, [r1+0x7940]
│    ││││   0x00000130      ldxdw r2, [r1+0x50]
│   ┌─────< 0x00000138      jlt r2, r4, 0x000004b0
│   │││││   0x00000140      mov64 r9, r10
│   │││││   0x00000148      sub64 r9, 0x120
│   │││││   ...
```

## Solana Analyzers

| Analyzer | Description |
|---|---|
| `SolanaInputOffsetAnalyzer` | Maps input buffer byte offsets to account field names (`ACCOUNT_N_KEY`, `ACCOUNT_N_LAMPORTS`, etc.) |
| `SolanaCallResolver` | Resolves sBPF syscall hashes to named functions (`sol_invoke_signed_c`, `sol_log_64`, etc.) |
| `SolanaAnchorDispatcherAnalyzer` | Detects and labels Anchor 8-byte discriminator dispatch tables |
| `SolanaGlobalPtrStringAnalyzer` | Resolves global pointer loads to string literal annotations |
| `SolanaStringFromPtrLenAnalyzer` | Reconstructs string references from pointer+length pairs |
| `SolanaStructFieldHintAnalyzer` | Annotates struct field accesses with type information |

## Installation

### Prerequisites

Install [radare2-solana](https://github.com/cpkt9762/radare2-solana) first (provides the sBPF arch plugin):

```bash
git clone https://github.com/cpkt9762/radare2-solana.git
cd radare2-solana
sys/install.sh
```

### Build r2ghidra-solana

```bash
git clone https://github.com/cpkt9762/r2ghidra-solana.git
cd r2ghidra-solana
./preconfigure
./configure
make -j$(nproc)
make install  # or: make user-install
```

### One-liner Install (both repos)

```bash
curl -sSL https://raw.githubusercontent.com/cpkt9762/r2ghidra-solana/master/install.sh | bash
```

### Verify Installation

```bash
# Should show the r2ghidra plugin loaded
r2 -qc 'Lc' --

# Decompile a Solana program
r2 -a sbpf -qc 'aa; s entry0; pdg' your_program.so
```

## Quick Start

```bash
# Dump a Solana program from mainnet
solana program dump <PROGRAM_ID> program.so

# Open with radare2 (sBPF arch is auto-detected)
r2 program.so

# Inside r2:
[0x000000e8]> aa          # analyze all
[0x000000e8]> afl         # list functions
[0x000000e8]> s entry0    # seek to entrypoint
[0x000000e8]> pdg         # decompile with Ghidra + Solana enhancements
[0x000000e8]> pdf         # disassemble
[0x000000e8]> pdga        # side-by-side disasm + decompilation
```

## Usage

All standard r2ghidra commands work:

```
[0x000000e8]> pdg?
Usage: pdg  # Native Ghidra decompiler plugin
| pdg           # Decompile current function with the Ghidra decompiler
| pdg*          # Decompiled code is returned to r2 as comment
| pdga          # Side by side two column disasm and decompilation
| pdgd          # Dump the debug XML Dump
| pdgj          # Dump the current decompiled function as JSON
| pdgo          # Decompile current function side by side with offsets
| pdgs          # Display loaded Sleigh Languages
| pdgsd N       # Disassemble N instructions with Sleigh and print pcode
| pdgss         # Display automatically matched Sleigh Language ID
| pdgx          # Dump the XML of the current decompiled function
```

## IDA Signature Factory

The `sys/solana-ida-signatures-factory/` directory contains tooling to generate IDA-compatible `.sig` signature files from Solana program `.rlib` archives. This enables function identification in stripped binaries.

Pre-built `.rlib` archives for common Solana SDK crates are available at **[solana-sbpf-rlib](https://github.com/cpkt9762/solana-sbpf-rlib)**.

## Dependencies

* [radare2-solana](https://github.com/cpkt9762/radare2-solana) — sBPF architecture plugin (must be installed first)
* pkg-config
* C++ compiler (g++/clang++/msvc)
* acr/make or meson/ninja
* git/patch

## Portability

Tested on:

* macOS (arm64 / x86_64)
* GNU/Linux (x86_64)
* Windows (x64)

## Upstream

This is a fork of [radareorg/r2ghidra](https://github.com/radareorg/r2ghidra). Solana-specific changes are isolated in `src/Solana*.cpp/h` files and minimal patches to `core_ghidra.cpp`, `R2Architecture.h/cpp`, and `R2PrintC.cpp`.

## License

See `LICENSE.md` for details — **LGPLv3**.
