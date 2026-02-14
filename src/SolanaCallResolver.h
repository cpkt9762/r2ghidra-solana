/* r2ghidra - LGPL - Copyright 2026 - pancake */

#ifndef R2GHIDRA_SOLANA_CALL_RESOLVER_H
#define R2GHIDRA_SOLANA_CALL_RESOLVER_H

#include <string>
#include <cstdint>

namespace ghidra {
class PcodeOp;
}

class R2Architecture;

const char *get_sbpf_syscall_name(uint64_t addr);
bool resolve_sbpf_internal_call_target(
	R2Architecture *arch,
	const ghidra::PcodeOp *op,
	uint64_t *out_target);
std::string resolve_sbpf_call_name(R2Architecture *arch, const ghidra::PcodeOp *op);

#endif // R2GHIDRA_SOLANA_CALL_RESOLVER_H
