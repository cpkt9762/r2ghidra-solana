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
		{ 0x0008, "ACCOUNT_0_HEADER" },
		{ 0x0010, "ACCOUNT_0_KEY" },
		{ 0x0030, "ACCOUNT_0_OWNER" },
		{ 0x0050, "ACCOUNT_0_LAMPORTS" },
		{ 0x0058, "ACCOUNT_0_DATA_LEN" },
		{ 0x0060, "ACCOUNT_0_DATA" },
		{ 0x2860, "ACCOUNT_0_RENT_EPOCH" },
		{ 0x2868, "ACCOUNT_1_HEADER" },
		{ 0x2870, "ACCOUNT_1_KEY" },
		{ 0x2890, "ACCOUNT_1_OWNER" },
		{ 0x28b0, "ACCOUNT_1_LAMPORTS" },
		{ 0x28b8, "ACCOUNT_1_DATA_LEN" },
		{ 0x28c0, "ACCOUNT_1_DATA" },
		{ 0x50c0, "ACCOUNT_1_RENT_EPOCH" },
		{ 0x50c8, "ACCOUNT_2_HEADER" },
		{ 0x50d0, "ACCOUNT_2_KEY" },
		{ 0x50f0, "ACCOUNT_2_OWNER" },
		{ 0x5110, "ACCOUNT_2_LAMPORTS" },
		{ 0x5118, "ACCOUNT_2_DATA_LEN" },
		{ 0x5120, "ACCOUNT_2_DATA" },
		{ 0x7930, "ACCOUNT_2_RENT_EPOCH" },
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

constexpr uintb kInputCompensation = 0x10;
constexpr const char *kInputCompensationSymbol = "ACCOUNT_1_DATA_COMPENSATION";

bool is_instruction_tail_offset(uintb offset) {
	switch (offset) {
	case 0x7938:
	case 0x7940:
	case 0x7942:
		return true;
	default:
		return false;
	}
}

const char *lookup_compensated_offset_symbol(uintb offset) {
	if (!is_instruction_tail_offset(offset)) {
		return nullptr;
	}
	return lookup_offset_symbol(offset);
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
	case CPUI_MULTIEQUAL: {
		bool seen = false;
		int64_t merged = 0;
		for (int4 i = 0; i < def->numInput(); ++i) {
			int64_t cur = 0;
			if (!try_resolve_input_relative_offset_impl(def->getIn(i), input_root, cur, visited, depth - 1)) {
				return false;
			}
			if (!seen) {
				merged = cur;
				seen = true;
				continue;
			}
			if (cur == merged) {
				continue;
			}
			const bool plain_and_comp =
				((merged == 0 && cur == static_cast<int64_t>(kInputCompensation))
				|| (merged == static_cast<int64_t>(kInputCompensation) && cur == 0));
			if (!plain_and_comp) {
				return false;
			}
			merged = 0;
		}
		if (seen) {
			out = merged;
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

void set_input_offset_hint(const Varnode *vn, const char *symbol, R2Architecture *arch) {
	if (!vn || !arch || !vn->isConstant() || !symbol || !*symbol) {
		return;
	}
	R2Architecture::SolanaInputOffsetHint hint;
	hint.symbol = symbol;
	hint.value = vn->getOffset();
	arch->setSolanaInputOffsetHint(vn->getCreateIndex(), hint);
}

bool varnode_uses_instruction_tail_offsets_impl(
	const Varnode *vn,
	std::unordered_set<uint4> &visited,
	int depth = 8)
{
	if (!vn || depth <= 0) {
		return false;
	}
	const uint4 idx = vn->getCreateIndex();
	if (visited.find(idx) != visited.end()) {
		return false;
	}
	visited.insert(idx);

	for (auto iter = vn->beginDescend(); iter != vn->endDescend(); ++iter) {
		const PcodeOp *use = *iter;
		if (!use) {
			continue;
		}
		for (int4 i = 0; i < use->numInput(); ++i) {
			uintb cst = 0;
			if (try_resolve_constant_varnode(use->getIn(i), cst, 6) && is_instruction_tail_offset(cst)) {
				return true;
			}
		}
		switch (use->code()) {
		case CPUI_COPY:
		case CPUI_CAST:
		case CPUI_INT_ZEXT:
		case CPUI_INT_SEXT:
		case CPUI_MULTIEQUAL:
			if (varnode_uses_instruction_tail_offsets_impl(use->getOut(), visited, depth - 1)) {
				return true;
			}
			break;
		default:
			break;
		}
	}
	return false;
}

bool varnode_uses_instruction_tail_offsets(const Varnode *vn) {
	std::unordered_set<uint4> visited;
	return varnode_uses_instruction_tail_offsets_impl(vn, visited);
}

bool looks_like_compensation_base(const Varnode *vn, const Varnode *input_root) {
	if (!vn || !input_root) {
		return false;
	}
	int64_t base_offset = 0;
	if (!try_resolve_input_relative_offset(vn, input_root, base_offset)
			|| base_offset != static_cast<int64_t>(kInputCompensation)) {
		return false;
	}
	return varnode_uses_instruction_tail_offsets(vn);
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
		const bool output_is_compensation_base = looks_like_compensation_base(op->getOut(), input_root);

		for (int4 i = 0; i < op->numInput(); ++i) {
			const Varnode *candidate = op->getIn(i);
			if (!candidate || !candidate->isConstant()) {
				continue;
			}
			const char *symbol = nullptr;
			for (int4 j = 0; j < op->numInput(); ++j) {
				if (j == i) {
					continue;
				}
				int64_t base_offset = 0;
				if (!try_resolve_input_relative_offset(op->getIn(j), input_root, base_offset)) {
					continue;
				}
				if (base_offset == 0) {
					if (candidate->getOffset() == kInputCompensation && output_is_compensation_base) {
						symbol = kInputCompensationSymbol;
					} else {
						symbol = lookup_offset_symbol(candidate->getOffset());
					}
				} else if (base_offset == static_cast<int64_t>(kInputCompensation)) {
					symbol = lookup_compensated_offset_symbol(candidate->getOffset());
				}
				if (symbol) {
					break;
				}
			}
			if (symbol) {
				set_input_offset_hint(candidate, symbol, arch);
			}
		}
	}
}
