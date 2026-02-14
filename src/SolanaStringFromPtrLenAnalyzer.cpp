/* r2ghidra - LGPL - Copyright 2026 - pancake */

#include "SolanaStringFromPtrLenAnalyzer.h"

#include "R2Architecture.h"
#include "RCoreMutex.h"
#include "SolanaCallResolver.h"

#include <funcdata.hh>

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <limits.h>
#include <limits>
#include <sstream>
#include <vector>

using namespace ghidra;

namespace {

#if defined(MAXPATH)
constexpr uintb kMaxStringBytes = static_cast<uintb>(MAXPATH);
#elif defined(MAXPATHLEN)
constexpr uintb kMaxStringBytes = static_cast<uintb>(MAXPATHLEN);
#elif defined(PATH_MAX)
constexpr uintb kMaxStringBytes = static_cast<uintb>(PATH_MAX);
#else
constexpr uintb kMaxStringBytes = 1024;
#endif

struct StringFromPtrLenRule {
	const char *call_name;
	int4 ptr_slot;
	int4 len_slot;
	int4 replace_slot;
};

const StringFromPtrLenRule *lookup_rule(const std::string &call_name) {
	static const StringFromPtrLenRule kRules[] = {
		{ "sol_log_", 1, 2, 1 },
		{ "sol_panic_", 1, 2, 1 },
	};
	for (const auto &rule : kRules) {
		if (call_name == rule.call_name) {
			return &rule;
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

bool looks_like_text_buffer(const std::vector<uint1> &buf) {
	if (buf.empty()) {
		return false;
	}
	size_t printable = 0;
	size_t ascii_letters = 0;
	for (uint1 ch : buf) {
		if (ch == 0) {
			return false;
		}
		if (ch == '\n' || ch == '\r' || ch == '\t' || (ch >= 0x20 && ch <= 0x7e)) {
			printable++;
		}
		if (std::isalpha(static_cast<unsigned char>(ch))) {
			ascii_letters++;
		}
	}
	return printable * 100 >= buf.size() * 85 && ascii_letters > 0;
}

std::string quote_c_string(const std::vector<uint1> &buf) {
	std::ostringstream out;
	out << '"';
	for (uint1 c : buf) {
		switch (c) {
		case '\\':
			out << "\\\\";
			break;
		case '"':
			out << "\\\"";
			break;
		case '\n':
			out << "\\n";
			break;
		case '\r':
			out << "\\r";
			break;
		case '\t':
			out << "\\t";
			break;
		default:
			if (c >= 0x20 && c <= 0x7e) {
				out << static_cast<char>(c);
			} else {
				out << "\\x" << std::hex << std::setw(2) << std::setfill('0')
					<< static_cast<unsigned>(c) << std::dec;
			}
			break;
		}
	}
	out << '"';
	return out.str();
}

bool read_solana_string_literal(
	R2Architecture *arch,
	uintb ptr,
	uintb len,
	std::string &quoted)
{
	if (!arch) {
		return false;
	}
	if (len == 0 || len > kMaxStringBytes || len > static_cast<uintb>(std::numeric_limits<int>::max())) {
		return false;
	}
	std::vector<uint1> bytes(static_cast<size_t>(len));
	{
		RCoreLock core(arch->getCore());
		if (!core || !core->io) {
			return false;
		}
		bool ok = r_io_vread_at(core->io, static_cast<ut64>(ptr), bytes.data(), static_cast<int>(len));
		if (!ok) {
			int final_rd = r_io_read_at(core->io, static_cast<ut64>(ptr), bytes.data(), static_cast<int>(len));
			if (final_rd != static_cast<int>(len)) {
				const ut64 paddr = r_io_v2p(core->io, static_cast<ut64>(ptr));
				if (paddr != UT64_MAX) {
					final_rd = r_io_read_at(core->io, paddr, bytes.data(), static_cast<int>(len));
				}
			}
			ok = (final_rd == static_cast<int>(len));
		}
		if (!ok) {
			return false;
		}
	}
	if (!looks_like_text_buffer(bytes)) {
		return false;
	}
	quoted = quote_c_string(bytes);
	return true;
}

} // namespace

void SolanaStringFromPtrLenAnalyzer::run(Funcdata *func, R2Architecture *arch) {
	if (!func || !arch) {
		return;
	}
	arch->clearSolanaStringFromPtrLenHints();

	for (auto iter = func->beginOpAll(); iter != func->endOpAll(); ++iter) {
		PcodeOp *op = iter->second;
		if (!op || op->code() != CPUI_CALL || op->numInput() < 3) {
			continue;
		}
		const std::string call_name = resolve_sbpf_call_name(arch, op);
		const StringFromPtrLenRule *rule = lookup_rule(call_name);
		if (!rule) {
			continue;
		}
		if (rule->ptr_slot >= op->numInput() || rule->len_slot >= op->numInput()) {
			continue;
		}

		uintb ptr = 0;
		uintb len = 0;
		if (!try_resolve_constant_varnode(op->getIn(rule->ptr_slot), ptr)
				|| !try_resolve_constant_varnode(op->getIn(rule->len_slot), len)) {
			continue;
		}

		std::string quoted;
		if (!read_solana_string_literal(arch, ptr, len, quoted)) {
			continue;
		}

		R2Architecture::SolanaStringFromPtrLenHint hint;
		hint.replace_slot = rule->replace_slot;
		hint.ptr_value = ptr;
		hint.quoted = quoted;
		arch->setSolanaStringFromPtrLenHint(op->getAddr(), hint);
	}
}
