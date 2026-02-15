/* r2ghidra - LGPL - Copyright 2026 - pancake */

#include "SolanaStructFieldHintAnalyzer.h"

#include "R2Architecture.h"

#include <funcdata.hh>

#include <cctype>
#include <string>
#include <unordered_map>

using namespace ghidra;

namespace {

enum class SolanaStructKind {
	Unknown = 0,
	AccountInfo,
	Instruction,
	Pubkey,
};

using KindMask = uint8_t;
constexpr KindMask kKindNone = 0;
constexpr KindMask kKindAccountInfo = 1u << 0;
constexpr KindMask kKindInstruction = 1u << 1;
constexpr KindMask kKindPubkey = 1u << 2;

struct FieldHintSpec {
	SolanaStructKind kind;
	uintb offset;
	const char *symbol;
};

struct SizeHintSpec {
	SolanaStructKind kind;
	uintb size;
	const char *symbol;
};

KindMask mask_from_kind(SolanaStructKind kind) {
	switch (kind) {
	case SolanaStructKind::AccountInfo:
		return kKindAccountInfo;
	case SolanaStructKind::Instruction:
		return kKindInstruction;
	case SolanaStructKind::Pubkey:
		return kKindPubkey;
	default:
		break;
	}
	return kKindNone;
}

SolanaStructKind single_kind_from_mask(KindMask mask) {
	if (!mask || (mask & (mask - 1))) {
		return SolanaStructKind::Unknown;
	}
	if (mask == kKindAccountInfo) {
		return SolanaStructKind::AccountInfo;
	}
	if (mask == kKindInstruction) {
		return SolanaStructKind::Instruction;
	}
	if (mask == kKindPubkey) {
		return SolanaStructKind::Pubkey;
	}
	return SolanaStructKind::Unknown;
}

std::string normalize_type_name(const std::string &name) {
	std::string out;
	out.reserve(name.size());
	for (unsigned char ch : name) {
		if (std::isalnum(ch)) {
			out.push_back(static_cast<char>(std::tolower(ch)));
		}
	}
	return out;
}

SolanaStructKind kind_from_name(const std::string &raw_name) {
	const std::string name = normalize_type_name(raw_name);
	if (name == "solaccountinfo" || name == "solaccountinfoc" || name == "accountinfo") {
		return SolanaStructKind::AccountInfo;
	}
	if (name == "solinstruction" || name == "instruction") {
		return SolanaStructKind::Instruction;
	}
	if (name == "solpubkey" || name == "pubkey") {
		return SolanaStructKind::Pubkey;
	}
	return SolanaStructKind::Unknown;
}

SolanaStructKind classify_struct_kind(Datatype *type, int depth = 8) {
	if (!type || depth <= 0) {
		return SolanaStructKind::Unknown;
	}
	if (Datatype *td = type->getTypedef()) {
		const SolanaStructKind td_kind = classify_struct_kind(td, depth - 1);
		if (td_kind != SolanaStructKind::Unknown) {
			return td_kind;
		}
	}
	if (auto ptr = dynamic_cast<TypePointer *>(type)) {
		return classify_struct_kind(ptr->getPtrTo(), depth - 1);
	}
	if (auto arr = dynamic_cast<TypeArray *>(type)) {
		return classify_struct_kind(arr->getBase(), depth - 1);
	}
	return kind_from_name(type->getName());
}

KindMask mask_from_varnode_type(const Varnode *vn) {
	if (!vn) {
		return kKindNone;
	}
	return mask_from_kind(classify_struct_kind(vn->getType()));
}

const char *lookup_field_symbol(SolanaStructKind kind, uintb offset) {
	static const FieldHintSpec kSpecs[] = {
		{ SolanaStructKind::AccountInfo, 0x00, "SOL_ACCOUNT_INFO_KEY_OFF" },
		{ SolanaStructKind::AccountInfo, 0x08, "SOL_ACCOUNT_INFO_LAMPORTS_OFF" },
		{ SolanaStructKind::AccountInfo, 0x10, "SOL_ACCOUNT_INFO_DATA_LEN_OFF" },
		{ SolanaStructKind::AccountInfo, 0x18, "SOL_ACCOUNT_INFO_DATA_OFF" },
		{ SolanaStructKind::AccountInfo, 0x20, "SOL_ACCOUNT_INFO_OWNER_OFF" },
		{ SolanaStructKind::AccountInfo, 0x28, "SOL_ACCOUNT_INFO_RENT_EPOCH_OFF" },
		{ SolanaStructKind::AccountInfo, 0x30, "SOL_ACCOUNT_INFO_IS_SIGNER_OFF" },
		{ SolanaStructKind::AccountInfo, 0x31, "SOL_ACCOUNT_INFO_IS_WRITABLE_OFF" },
		{ SolanaStructKind::AccountInfo, 0x32, "SOL_ACCOUNT_INFO_EXECUTABLE_OFF" },
		{ SolanaStructKind::Instruction, 0x00, "SOL_INSTRUCTION_PROGRAM_ID_OFF" },
		{ SolanaStructKind::Instruction, 0x08, "SOL_INSTRUCTION_ACCOUNTS_OFF" },
		{ SolanaStructKind::Instruction, 0x10, "SOL_INSTRUCTION_ACCOUNTS_LEN_OFF" },
		{ SolanaStructKind::Instruction, 0x18, "SOL_INSTRUCTION_DATA_OFF" },
		{ SolanaStructKind::Instruction, 0x20, "SOL_INSTRUCTION_DATA_LEN_OFF" },
		{ SolanaStructKind::Pubkey, 0x00, "SOL_PUBKEY_BYTES_OFF" },
	};
	for (const auto &spec : kSpecs) {
		if (spec.kind == kind && spec.offset == offset) {
			return spec.symbol;
		}
	}
	return nullptr;
}

KindMask lookup_field_kind_mask(uintb offset) {
	static const FieldHintSpec kSpecs[] = {
		{ SolanaStructKind::AccountInfo, 0x00, nullptr },
		{ SolanaStructKind::AccountInfo, 0x08, nullptr },
		{ SolanaStructKind::AccountInfo, 0x10, nullptr },
		{ SolanaStructKind::AccountInfo, 0x18, nullptr },
		{ SolanaStructKind::AccountInfo, 0x20, nullptr },
		{ SolanaStructKind::AccountInfo, 0x28, nullptr },
		{ SolanaStructKind::AccountInfo, 0x30, nullptr },
		{ SolanaStructKind::AccountInfo, 0x31, nullptr },
		{ SolanaStructKind::AccountInfo, 0x32, nullptr },
		{ SolanaStructKind::Instruction, 0x00, nullptr },
		{ SolanaStructKind::Instruction, 0x08, nullptr },
		{ SolanaStructKind::Instruction, 0x10, nullptr },
		{ SolanaStructKind::Instruction, 0x18, nullptr },
		{ SolanaStructKind::Instruction, 0x20, nullptr },
		{ SolanaStructKind::Pubkey, 0x00, nullptr },
	};
	KindMask mask = kKindNone;
	for (const auto &spec : kSpecs) {
		if (spec.offset == offset) {
			mask |= mask_from_kind(spec.kind);
		}
	}
	return mask;
}

const char *lookup_size_symbol(SolanaStructKind kind, uintb size) {
	static const SizeHintSpec kSpecs[] = {
		{ SolanaStructKind::AccountInfo, 56, "SOL_ACCOUNT_INFO_SIZE" },
		{ SolanaStructKind::Instruction, 40, "SOL_INSTRUCTION_SIZE" },
		{ SolanaStructKind::Pubkey, 32, "SOL_PUBKEY_SIZE" },
	};
	for (const auto &spec : kSpecs) {
		if (spec.kind == kind && spec.size == size) {
			return spec.symbol;
		}
	}
	return nullptr;
}

KindMask lookup_size_kind_mask(uintb size) {
	static const SizeHintSpec kSpecs[] = {
		{ SolanaStructKind::AccountInfo, 56, nullptr },
		{ SolanaStructKind::Instruction, 40, nullptr },
		{ SolanaStructKind::Pubkey, 32, nullptr },
	};
	KindMask mask = kKindNone;
	for (const auto &spec : kSpecs) {
		if (spec.size == size) {
			mask |= mask_from_kind(spec.kind);
		}
	}
	return mask;
}

KindMask intersect_or_self(KindMask base, KindMask refine) {
	if (!base) {
		return refine;
	}
	if (!refine) {
		return base;
	}
	const KindMask masked = static_cast<KindMask>(base & refine);
	return masked ? masked : base;
}

KindMask kind_mask_for_varnode(
	const Varnode *vn,
	const std::unordered_map<uint4, KindMask> &inferred)
{
	if (!vn) {
		return kKindNone;
	}
	KindMask mask = mask_from_varnode_type(vn);
	auto it = inferred.find(vn->getCreateIndex());
	if (it != inferred.end()) {
		mask = static_cast<KindMask>(mask | it->second);
	}
	return mask;
}

bool merge_kind_mask(
	const Varnode *vn,
	KindMask mask,
	std::unordered_map<uint4, KindMask> &inferred)
{
	if (!vn || !mask) {
		return false;
	}
	auto it = inferred.find(vn->getCreateIndex());
	if (it == inferred.end()) {
		inferred.emplace(vn->getCreateIndex(), mask);
		return true;
	}
	const KindMask merged = static_cast<KindMask>(it->second | mask);
	if (merged == it->second) {
		return false;
	}
	it->second = merged;
	return true;
}

void seed_kind_from_types(Funcdata *func, std::unordered_map<uint4, KindMask> &inferred) {
	if (!func) {
		return;
	}
	for (auto iter = func->beginOpAll(); iter != func->endOpAll(); ++iter) {
		const PcodeOp *op = iter->second;
		if (!op) {
			continue;
		}
		for (int4 i = 0; i < op->numInput(); ++i) {
			const Varnode *in = op->getIn(i);
			if (!in) {
				continue;
			}
			merge_kind_mask(in, mask_from_varnode_type(in), inferred);
		}
		const Varnode *out = op->getOut();
		if (out) {
			merge_kind_mask(out, mask_from_varnode_type(out), inferred);
		}
	}
}

void propagate_kind_masks(Funcdata *func, std::unordered_map<uint4, KindMask> &inferred) {
	if (!func) {
		return;
	}
	for (int pass = 0; pass < 8; ++pass) {
		bool changed = false;
		for (auto iter = func->beginOpAll(); iter != func->endOpAll(); ++iter) {
			const PcodeOp *op = iter->second;
			if (!op) {
				continue;
			}
			const Varnode *out = op->getOut();
			switch (op->code()) {
			case CPUI_COPY:
			case CPUI_CAST:
			case CPUI_INT_ZEXT:
			case CPUI_INT_SEXT:
				if (out && op->numInput() >= 1) {
					const KindMask in_mask = kind_mask_for_varnode(op->getIn(0), inferred);
					changed |= merge_kind_mask(out, in_mask, inferred);
				}
				break;
			case CPUI_MULTIEQUAL:
				if (out && op->numInput() >= 1) {
					KindMask merged = kKindNone;
					for (int4 i = 0; i < op->numInput(); ++i) {
						merged = static_cast<KindMask>(merged | kind_mask_for_varnode(op->getIn(i), inferred));
					}
					changed |= merge_kind_mask(out, merged, inferred);
				}
				break;
			case CPUI_PTRADD:
				if (op->numInput() >= 3) {
					const Varnode *base = op->getIn(0);
					KindMask base_mask = kind_mask_for_varnode(base, inferred);
					if (const Varnode *stride = op->getIn(2); stride && stride->isConstant()) {
						const KindMask size_mask = lookup_size_kind_mask(stride->getOffset());
						base_mask = intersect_or_self(base_mask, size_mask);
					}
					changed |= merge_kind_mask(base, base_mask, inferred);
					if (out) {
						changed |= merge_kind_mask(out, base_mask, inferred);
					}
				}
				break;
			case CPUI_PTRSUB:
			case CPUI_INT_ADD: {
				if (op->numInput() < 2) {
					break;
				}
				const Varnode *base = nullptr;
				for (int4 i = 0; i < op->numInput(); ++i) {
					const Varnode *in = op->getIn(i);
					if (in && !in->isConstant()) {
						base = in;
						break;
					}
				}
				KindMask base_mask = kind_mask_for_varnode(base, inferred);
				for (int4 i = 0; i < op->numInput(); ++i) {
					const Varnode *in = op->getIn(i);
					if (!in || !in->isConstant()) {
						continue;
					}
					const KindMask field_mask = lookup_field_kind_mask(in->getOffset());
					base_mask = intersect_or_self(base_mask, field_mask);
				}
				changed |= merge_kind_mask(base, base_mask, inferred);
				if (out) {
					changed |= merge_kind_mask(out, base_mask, inferred);
				}
				break;
			}
			default:
				break;
			}
		}
		if (!changed) {
			break;
		}
	}
}

void set_struct_field_hint(const Varnode *constant_vn, const char *symbol, R2Architecture *arch) {
	if (!constant_vn || !constant_vn->isConstant() || !symbol || !*symbol || !arch) {
		return;
	}
	if (arch->findSolanaInputOffsetHint(constant_vn->getCreateIndex())) {
		// Preserve more specific input-buffer symbols if they already exist.
		return;
	}
	R2Architecture::SolanaInputOffsetHint hint;
	hint.value = constant_vn->getOffset();
	hint.symbol = symbol;
	arch->setSolanaInputOffsetHint(constant_vn->getCreateIndex(), hint);
}

const char *try_resolve_symbol_for_constant(
	const PcodeOp *op,
	int4 constant_idx,
	const std::unordered_map<uint4, KindMask> &inferred)
{
	if (!op || constant_idx < 0 || constant_idx >= op->numInput()) {
		return nullptr;
	}
	const Varnode *constant_vn = op->getIn(constant_idx);
	if (!constant_vn || !constant_vn->isConstant()) {
		return nullptr;
	}

	const uintb constant = constant_vn->getOffset();
	if (op->code() == CPUI_PTRADD) {
		if (constant_idx != 2 || op->numInput() < 3) {
			return nullptr;
		}
		const Varnode *base = op->getIn(0);
		KindMask mask = kind_mask_for_varnode(base, inferred);
		mask = intersect_or_self(mask, lookup_size_kind_mask(constant));
		const SolanaStructKind kind = single_kind_from_mask(mask);
		if (kind == SolanaStructKind::Unknown) {
			return nullptr;
		}
		return lookup_size_symbol(kind, constant);
	}

	KindMask merged_mask = kKindNone;
	for (int4 i = 0; i < op->numInput(); ++i) {
		if (i == constant_idx) {
			continue;
		}
		const Varnode *candidate_base = op->getIn(i);
		if (!candidate_base || candidate_base->isConstant()) {
			continue;
		}
		const KindMask base_mask = kind_mask_for_varnode(candidate_base, inferred);
		if (base_mask) {
			merged_mask = static_cast<KindMask>(merged_mask | base_mask);
		}
	}
	merged_mask = intersect_or_self(merged_mask, lookup_field_kind_mask(constant));
	const SolanaStructKind kind = single_kind_from_mask(merged_mask);
	if (kind == SolanaStructKind::Unknown) {
		return nullptr;
	}
	return lookup_field_symbol(kind, constant);
}

} // namespace

void SolanaStructFieldHintAnalyzer::run(Funcdata *func, R2Architecture *arch) {
	if (!func || !arch) {
		return;
	}
	std::unordered_map<uint4, KindMask> inferred_kinds;
	seed_kind_from_types(func, inferred_kinds);
	propagate_kind_masks(func, inferred_kinds);

	for (auto iter = func->beginOpAll(); iter != func->endOpAll(); ++iter) {
		const PcodeOp *op = iter->second;
		if (!op) {
			continue;
		}
		switch (op->code()) {
		case CPUI_PTRSUB:
		case CPUI_INT_ADD:
		case CPUI_PTRADD:
			break;
		default:
			continue;
		}
		for (int4 i = 0; i < op->numInput(); ++i) {
			const Varnode *vn = op->getIn(i);
			if (!vn || !vn->isConstant()) {
				continue;
			}
			const char *symbol = try_resolve_symbol_for_constant(op, i, inferred_kinds);
			if (!symbol) {
				continue;
			}
			set_struct_field_hint(vn, symbol, arch);
		}
	}
}
