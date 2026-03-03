#!/usr/bin/env bash
#
# One-liner installer for radare2-solana + r2ghidra-solana
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/cpkt9762/r2ghidra-solana/master/install.sh | bash
#
# Or clone and run locally:
#   ./install.sh
#
set -e

RADARE2_REPO="https://github.com/cpkt9762/radare2-solana.git"
R2GHIDRA_REPO="https://github.com/cpkt9762/r2ghidra-solana.git"

NPROC=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

info()  { printf "\033[1;34m[*]\033[0m %s\n" "$1"; }
ok()    { printf "\033[1;32m[✓]\033[0m %s\n" "$1"; }
err()   { printf "\033[1;31m[✗]\033[0m %s\n" "$1" >&2; exit 1; }

# Check dependencies
for cmd in git make gcc g++ pkg-config; do
    command -v "$cmd" >/dev/null 2>&1 || err "Missing dependency: $cmd"
done

WORKDIR="${SOLANA_R2_BUILD_DIR:-$(mktemp -d)}"
info "Build directory: $WORKDIR"

# Step 1: Install radare2-solana
info "Installing radare2-solana (sBPF disassembler)..."
if [ -d "$WORKDIR/radare2-solana" ]; then
    info "radare2-solana already cloned, pulling latest..."
    git -C "$WORKDIR/radare2-solana" pull --ff-only
else
    git clone --depth=1 "$RADARE2_REPO" "$WORKDIR/radare2-solana"
fi

(cd "$WORKDIR/radare2-solana" && sys/install.sh)
ok "radare2-solana installed"

# Verify radare2 is available
command -v r2 >/dev/null 2>&1 || err "radare2 not found in PATH after installation"
info "radare2 version: $(r2 -v 2>/dev/null | head -1)"

# Step 2: Install r2ghidra-solana
info "Installing r2ghidra-solana (Ghidra decompiler + Solana analyzers)..."
if [ -d "$WORKDIR/r2ghidra-solana" ]; then
    info "r2ghidra-solana already cloned, pulling latest..."
    git -C "$WORKDIR/r2ghidra-solana" pull --ff-only
else
    git clone --depth=1 "$R2GHIDRA_REPO" "$WORKDIR/r2ghidra-solana"
fi

(
    cd "$WORKDIR/r2ghidra-solana"
    ./preconfigure
    ./configure
    make -j"$NPROC"
    make install || make user-install
)
ok "r2ghidra-solana installed"

# Step 3: Verify
info "Verifying installation..."
if r2 -a sbpf -qc 'e asm.arch' -- 2>/dev/null | grep -q sbpf; then
    ok "sBPF architecture plugin loaded"
else
    info "Warning: could not verify sBPF plugin (may still work)"
fi

echo ""
ok "Installation complete!"
echo ""
echo "  Usage:"
echo "    solana program dump <PROGRAM_ID> program.so"
echo "    r2 program.so"
echo "    [0x...]> aa"
echo "    [0x...]> pdg    # decompile with Solana enhancements"
echo "    [0x...]> pdf    # disassemble"
echo ""
