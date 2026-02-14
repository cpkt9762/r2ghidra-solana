/* r2ghidra - LGPL - Copyright 2026 - pancake */

#include "SolanaInputOffsetAnalyzer.h"

#include "R2Architecture.h"

#include <funcdata.hh>

#include <unordered_set>

using namespace ghidra;

namespace {

struct OffsetSymbol {
	uintb offset;
	const char *symbol;
};

const char *lookup_offset_symbol(uintb offset) {
	static const OffsetSymbol kOffsetSymbols[] = {
		{ 0x0000, "NUM_ACCOUNTS" },
		{ 0x0008, "OWNER_HEADER" },
		{ 0x0010, "OWNER_KEY" },
		{ 0x0030, "OWNER_OWNER" },
		{ 0x0050, "OWNER_LAMPORTS" },
		{ 0x0058, "OWNER_DATA_LEN" },
		{ 0x0060, "OWNER_DATA" },
		{ 0x2860, "OWNER_RENT_EPOCH" },
		{ 0x2868, "COUNTER_HEADER" },
		{ 0x2870, "COUNTER_KEY" },
		{ 0x2890, "COUNTER_OWNER" },
		{ 0x28b0, "COUNTER_LAMPORTS" },
		{ 0x28b8, "COUNTER_DATA_LEN" },
		{ 0x28c0, "COUNTER_DATA" },
		{ 0x50c0, "COUNTER_RENT_EPOCH" },
		{ 0x50c8, "SYSTEM_PROGRAM_HEADER" },
		{ 0x50d0, "SYSTEM_PROGRAM_KEY" },
		{ 0x50f0, "SYSTEM_PROGRAM_OWNER" },
		{ 0x5110, "SYSTEM_PROGRAM_LAMPORTS" },
		{ 0x5118, "SYSTEM_PROGRAM_DATA_LEN" },
		{ 0x5120, "SYSTEM_PROGRAM_DATA" },
		{ 0x7930, "SYSTEM_PROGRAM_RENT_EPOCH" },
		{ 0x7938, "INSTRUCTION_DATA_LEN" },
		{ 0x7940, "INSTRUCTION_DATA" },
		{ 0x7942, "PROGRAM_ID" },
	};
	for (const auto &entry : kOffsetSymbols) {
		if (entry.offset == offset) {
			return entry.symbol;
		}
	}
	return nullptr;
}

bool try_resolve_constant_varnode(const Varnode *vn, uintb &out, int depth = 8) {
	if (!vn || depth <= 0) {
		return false;
	}
	if (vn->isConstant()) {
		out = vn->getOffset();
		return true;
	}
	if (!vn->isWritten()) {
		return false;
	}
	const PcodeOp *def = vn->getDef();
	if (!def || def->numInput() < 1) {
		return false;
	}
	switch (def->code()) {
	case CPUI_COPY:
	case CPUI_CAST:
	case CPUI_INT_ZEXT:
	case CPUI_INT_SEXT:
		return try_resolve_constant_varnode(def->getIn(0), out, depth - 1);
	case CPUI_PTRSUB: {
		if (def->numInput() < 2) {
			return false;
		}
		uintb base = 0;
		uintb offset = 0;
		if (!try_resolve_constant_varnode(def->getIn(0), base, depth - 1)
				|| !try_resolve_constant_varnode(def->getIn(1), offset, depth - 1)) {
			return false;
		}
		out = base + offset;
		return true;
	}
	case CPUI_PTRADD: {
		if (def->numInput() < 3) {
			return false;
		}
		uintb base = 0;
		uintb idx = 0;
		uintb stride = 0;
		if (!try_resolve_constant_varnode(def->getIn(0), base, depth - 1)
				|| !try_resolve_constant_varnode(def->getIn(1), idx, depth - 1)
				|| !try_resolve_constant_varnode(def->getIn(2), stride, depth - 1)) {
			return false;
		}
		out = base + (idx * stride);
		return true;
	}
	case CPUI_INT_ADD: {
		if (def->numInput() < 2) {
			return false;
		}
		uintb lhs = 0;
		uintb rhs = 0;
		if (!try_resolve_constant_varnode(def->getIn(0), lhs, depth - 1)
				|| !try_resolve_constant_varnode(def->getIn(1), rhs, depth - 1)) {
			return false;
		}
		out = lhs + rhs;
		return true;
	}
	case CPUI_INT_SUB: {
		if (def->numInput() < 2) {
			return false;
		}
		uintb lhs = 0;
		uintb rhs = 0;
		if (!try_resolve_constant_varnode(def->getIn(0), lhs, depth - 1)
				|| !try_resolve_constant_varnode(def->getIn(1), rhs, depth - 1)) {
			return false;
		}
		out = lhs - rhs;
		return true;
	}
	default:
		break;
	}
	return false;
}

bool try_resolve_input_relative_offset_impl(
	const Varnode *vn,
	const Varnode *input_root,
	int64_t &out,
	std::unordered_set<uint4> &visited,
	int depth = 16)
{
	if (!vn || !input_root || depth <= 0) {
		return false;
	}
	if (vn == input_root) {
		out = 0;
		return true;
	}
	const uint4 idx = vn->getCreateIndex();
	if (visited.find(idx) != visited.end()) {
		return false;
	}
	visited.insert(idx);

	if (!vn->isWritten()) {
		return false;
	}
	const PcodeOp *def = vn->getDef();
	if (!def || def->numInput() < 1) {
		return false;
	}
	switch (def->code()) {
	case CPUI_COPY:
	case CPUI_CAST:
	case CPUI_INT_ZEXT:
	case CPUI_INT_SEXT:
		return try_resolve_input_relative_offset_impl(def->getIn(0), input_root, out, visited, depth - 1);
	case CPUI_INT_ADD: {
		int64_t base = 0;
		uintb cst = 0;
		if (try_resolve_input_relative_offset_impl(def->getIn(0), input_root, base, visited, depth - 1)
				&& try_resolve_constant_varnode(def->getIn(1), cst, depth - 1)) {
			out = base + static_cast<int64_t>(cst);
			return true;
		}
		if (try_resolve_input_relative_offset_impl(def->getIn(1), input_root, base, visited, depth - 1)
				&& try_resolve_constant_varnode(def->getIn(0), cst, depth - 1)) {
			out = base + static_cast<int64_t>(cst);
			return true;
		}
		break;
	}
	case CPUI_INT_SUB: {
		int64_t base = 0;
		uintb cst = 0;
		if (try_resolve_input_relative_offset_impl(def->getIn(0), input_root, base, visited, depth - 1)
				&& try_resolve_constant_varnode(def->getIn(1), cst, depth - 1)) {
			out = base - static_cast<int64_t>(cst);
			return true;
		}
		break;
	}
	case CPUI_PTRSUB: {
		int64_t base = 0;
		uintb cst = 0;
		if (def->numInput() < 2) {
			return false;
		}
		if (try_resolve_input_relative_offset_impl(def->getIn(0), input_root, base, visited, depth - 1)
				&& try_resolve_constant_varnode(def->getIn(1), cst, depth - 1)) {
			out = base + static_cast<int64_t>(cst);
			return true;
		}
		break;
	}
	case CPUI_PTRADD: {
		if (def->numInput() < 3) {
			return false;
		}
		int64_t base = 0;
		uintb idx_cst = 0;
		uintb stride_cst = 0;
		if (try_resolve_input_relative_offset_impl(def->getIn(0), input_root, base, visited, depth - 1)
				&& try_resolve_constant_varnode(def->getIn(1), idx_cst, depth - 1)
				&& try_resolve_constant_varnode(def->getIn(2), stride_cst, depth - 1)) {
			out = base + static_cast<int64_t>(idx_cst * stride_cst);
			return true;
		}
		break;
	}
	default:
		break;
	}
	return false;
}

bool try_resolve_input_relative_offset(
	const Varnode *vn,
	const Varnode *input_root,
	int64_t &out,
	int depth = 16)
{
	std::unordered_set<uint4> visited;
	return try_resolve_input_relative_offset_impl(vn, input_root, out, visited, depth);
}

void maybe_mark_input_offset_constant(const Varnode *vn, R2Architecture *arch) {
	if (!vn || !arch || !vn->isConstant()) {
		return;
	}
	const char *symbol = lookup_offset_symbol(vn->getOffset());
	if (!symbol) {
		return;
	}
	R2Architecture::SolanaInputOffsetHint hint;
	hint.symbol = symbol;
	hint.value = vn->getOffset();
	arch->setSolanaInputOffsetHint(vn->getCreateIndex(), hint);
}

const Varnode *find_input_root(Funcdata *func, R2Architecture *arch) {
	if (!func || !arch) {
		return nullptr;
	}
	const Address r1 = arch->registerAddressFromR2Reg("r1");
	if (r1.isInvalid()) {
		return nullptr;
	}
	for (auto iter = func->beginDef(); iter != func->endDef(); ++iter) {
		const Varnode *vn = *iter;
		if (!vn || !vn->isInput()) {
			continue;
		}
		if (vn->getAddr() == r1) {
			return vn;
		}
	}
	return nullptr;
}

} // namespace

void SolanaInputOffsetAnalyzer::run(Funcdata *func, R2Architecture *arch) {
	if (!func || !arch) {
		return;
	}
	arch->clearSolanaInputOffsetHints();
	const Varnode *input_root = find_input_root(func, arch);
	if (!input_root) {
		return;
	}

	for (auto iter = func->beginOpAll(); iter != func->endOpAll(); ++iter) {
		const PcodeOp *op = iter->second;
		if (!op) {
			continue;
		}
		switch (op->code()) {
		case CPUI_INT_ADD:
		case CPUI_INT_SUB:
		case CPUI_PTRSUB:
		case CPUI_PTRADD:
			break;
		default:
			continue;
		}
		if (op->numInput() < 2) {
			continue;
		}

		if (op->code() == CPUI_PTRADD && op->numInput() >= 3) {
			int64_t base_offset = 0;
			if (try_resolve_input_relative_offset(op->getIn(0), input_root, base_offset) && base_offset == 0) {
				uintb idx = 0;
				uintb stride = 0;
				if (try_resolve_constant_varnode(op->getIn(1), idx) && try_resolve_constant_varnode(op->getIn(2), stride)) {
					const uintb offset = idx * stride;
					if (lookup_offset_symbol(offset)) {
						maybe_mark_input_offset_constant(op->getIn(1), arch);
					}
				}
			}
			continue;
		}

		for (int4 i = 0; i < op->numInput(); ++i) {
			const Varnode *candidate = op->getIn(i);
			if (!candidate || !candidate->isConstant()) {
				continue;
			}
			const int4 other_i = (i == 0) ? 1 : 0;
			if (other_i >= op->numInput()) {
				continue;
			}
			int64_t base_offset = 0;
			if (!try_resolve_input_relative_offset(op->getIn(other_i), input_root, base_offset) || base_offset != 0) {
				continue;
			}
			maybe_mark_input_offset_constant(candidate, arch);
		}
	}
}
