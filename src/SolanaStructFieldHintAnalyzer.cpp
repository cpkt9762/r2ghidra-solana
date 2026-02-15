/* r2ghidra - LGPL - Copyright 2026 - pancake */

#include "SolanaStructFieldHintAnalyzer.h"

#include "R2Architecture.h"

#include <funcdata.hh>

#include <cctype>
#include <string>

using namespace ghidra;

namespace {

enum class SolanaStructKind {
	Unknown = 0,
	AccountInfo,
	Instruction,
	Pubkey,
};

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

const char *try_resolve_symbol_for_constant(const PcodeOp *op, int4 constant_idx) {
	if (!op || constant_idx < 0 || constant_idx >= op->numInput()) {
		return nullptr;
	}
	const Varnode *constant_vn = op->getIn(constant_idx);
	if (!constant_vn || !constant_vn->isConstant()) {
		return nullptr;
	}
	for (int4 i = 0; i < op->numInput(); ++i) {
		if (i == constant_idx) {
			continue;
		}
		const Varnode *base = op->getIn(i);
		if (!base) {
			continue;
		}
		const SolanaStructKind kind = classify_struct_kind(base->getType());
		if (kind == SolanaStructKind::Unknown) {
			continue;
		}
		const uintb constant = constant_vn->getOffset();
		const char *symbol = nullptr;
		if (op->code() == CPUI_PTRADD && constant_idx == 2) {
			symbol = lookup_size_symbol(kind, constant);
		} else if (op->code() != CPUI_PTRADD) {
			symbol = lookup_field_symbol(kind, constant);
		}
		if (symbol) {
			return symbol;
		}
	}
	return nullptr;
}

} // namespace

void SolanaStructFieldHintAnalyzer::run(Funcdata *func, R2Architecture *arch) {
	if (!func || !arch) {
		return;
	}
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
			const char *symbol = try_resolve_symbol_for_constant(op, i);
			if (!symbol) {
				continue;
			}
			set_struct_field_hint(vn, symbol, arch);
		}
	}
}
