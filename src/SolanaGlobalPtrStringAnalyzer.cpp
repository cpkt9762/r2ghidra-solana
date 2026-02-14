/* r2ghidra - LGPL - Copyright 2026 - pancake */

#include "SolanaGlobalPtrStringAnalyzer.h"

#include "R2Architecture.h"
#include "RCoreMutex.h"

#include <funcdata.hh>

#include <r_core.h>
#include <r_bin.h>
#include <r_flag.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <limits.h>
#include <limits>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

using namespace ghidra;

namespace {

struct AddressRange {
	ut64 start = 0;
	ut64 size = 0;
	std::string name;
};

struct PtrLenKey {
	ut64 ptr = 0;
	ut64 len = 0;
	bool operator==(const PtrLenKey &other) const {
		return ptr == other.ptr && len == other.len;
	}
};

struct PtrLenKeyHash {
	size_t operator()(const PtrLenKey &k) const {
		return static_cast<size_t>(k.ptr ^ (k.len << 1));
	}
};

struct DiscoveredString {
	ut64 ptr = 0;
	ut64 len = 0;
	bool is_pubkey = false;
	std::string text;
	std::string string_flag_name;
};

#if defined(MAXPATH)
constexpr ut64 kMaxStringBytes = static_cast<ut64>(MAXPATH);
#elif defined(MAXPATHLEN)
constexpr ut64 kMaxStringBytes = static_cast<ut64>(MAXPATHLEN);
#elif defined(PATH_MAX)
constexpr ut64 kMaxStringBytes = static_cast<ut64>(PATH_MAX);
#else
constexpr ut64 kMaxStringBytes = 1024;
#endif

bool read_virtual(RCore *core, ut64 addr, uint1 *buf, size_t len) {
	if (!core || !core->io || !buf || len == 0 || len > static_cast<size_t>(std::numeric_limits<int>::max())) {
		return false;
	}
	const int ilen = static_cast<int>(len);
	bool ok = r_io_vread_at(core->io, addr, buf, ilen);
	if (ok) {
		return true;
	}
	int rd = r_io_read_at(core->io, addr, buf, ilen);
	if (rd == ilen) {
		return true;
	}
	const ut64 paddr = r_io_v2p(core->io, addr);
	if (paddr == UT64_MAX) {
		return false;
	}
	rd = r_io_read_at(core->io, paddr, buf, ilen);
	return rd == ilen;
}

ut64 read_u64_le(const uint1 *p) {
	return static_cast<ut64>(p[0])
		| (static_cast<ut64>(p[1]) << 8)
		| (static_cast<ut64>(p[2]) << 16)
		| (static_cast<ut64>(p[3]) << 24)
		| (static_cast<ut64>(p[4]) << 32)
		| (static_cast<ut64>(p[5]) << 40)
		| (static_cast<ut64>(p[6]) << 48)
		| (static_cast<ut64>(p[7]) << 56);
}

bool contains_text_section_name(const std::string &name, const char *needle) {
	return name.find(needle) != std::string::npos;
}

void collect_section_ranges(
	RCore *core,
	std::vector<AddressRange> &rodata_ranges,
	std::vector<AddressRange> &table_ranges)
{
	const RList *sections = r_bin_get_sections(core->bin);
	if (!sections) {
		return;
	}
	RListIter *iter;
	void *pos;
	r_list_foreach (sections, iter, pos) {
		auto *sec = reinterpret_cast<RBinSection *>(pos);
		if (!sec || !sec->name) {
			continue;
		}
		ut64 start = sec->vaddr ? sec->vaddr : sec->paddr;
		ut64 size = sec->vsize ? sec->vsize : sec->size;
		if (size < 8) {
			continue;
		}
		std::string name = sec->name;
		if (contains_text_section_name(name, "rodata")) {
			rodata_ranges.push_back({ start, size, name });
		}
		if (contains_text_section_name(name, ".data.rel.ro")
				|| name == ".data"
				|| contains_text_section_name(name, ".data.rel.ro.")
				|| contains_text_section_name(name, ".data.rel")) {
			table_ranges.push_back({ start, size, name });
		}
	}
}

bool range_contains(const AddressRange &range, ut64 addr, ut64 len) {
	if (len == 0) {
		return false;
	}
	if (addr < range.start) {
		return false;
	}
	const ut64 end = addr + len;
	if (end < addr) {
		return false;
	}
	return end <= range.start + range.size;
}

bool in_ranges(const std::vector<AddressRange> &ranges, ut64 addr, ut64 len) {
	for (const auto &range : ranges) {
		if (range_contains(range, addr, len)) {
			return true;
		}
	}
	return false;
}

const AddressRange *find_containing_range(const std::vector<AddressRange> &ranges, ut64 addr) {
	for (const auto &range : ranges) {
		if (addr >= range.start && addr < range.start + range.size) {
			return &range;
		}
	}
	return nullptr;
}

bool read_nul_terminated_text(
	RCore *core,
	const std::vector<AddressRange> &rodata_ranges,
	ut64 ptr,
	std::vector<uint1> &out)
{
	const AddressRange *range = find_containing_range(rodata_ranges, ptr);
	if (!range) {
		return false;
	}
	const ut64 max_available = range->start + range->size - ptr;
	if (max_available == 0) {
		return false;
	}
	const ut64 read_len_u64 = std::min<ut64>(kMaxStringBytes, max_available);
	if (read_len_u64 == 0 || read_len_u64 > static_cast<ut64>(std::numeric_limits<size_t>::max())) {
		return false;
	}
	std::vector<uint1> buf(static_cast<size_t>(read_len_u64));
	if (!read_virtual(core, ptr, buf.data(), buf.size())) {
		return false;
	}
	auto nul_it = std::find(buf.begin(), buf.end(), 0);
	if (nul_it == buf.end()) {
		return false;
	}
	const size_t text_len = static_cast<size_t>(std::distance(buf.begin(), nul_it));
	if (text_len == 0) {
		return false;
	}
	out.assign(buf.begin(), nul_it);
	return true;
}

bool looks_like_text_buffer(const std::vector<uint1> &buf) {
	if (buf.size() < 4) {
		return false;
	}
	size_t printable = 0;
	size_t letters_or_digits = 0;
	for (uint1 ch : buf) {
		if (ch == 0) {
			return false;
		}
		if (ch == '\n' || ch == '\r' || ch == '\t' || (ch >= 0x20 && ch <= 0x7e)) {
			printable++;
		}
		if (std::isalnum(static_cast<unsigned char>(ch))) {
			letters_or_digits++;
		}
	}
	return printable * 100 >= buf.size() * 85 && letters_or_digits > 0;
}

bool looks_like_base58_pubkey(const std::vector<uint1> &buf) {
	if (buf.size() < 32 || buf.size() > 44) {
		return false;
	}
	for (uint1 ch : buf) {
		const bool in_1_9 = ch >= '1' && ch <= '9';
		const bool in_A_H = ch >= 'A' && ch <= 'H';
		const bool in_J_N = ch >= 'J' && ch <= 'N';
		const bool in_P_Z = ch >= 'P' && ch <= 'Z';
		const bool in_a_k = ch >= 'a' && ch <= 'k';
		const bool in_m_z = ch >= 'm' && ch <= 'z';
		if (!(in_1_9 || in_A_H || in_J_N || in_P_Z || in_a_k || in_m_z)) {
			return false;
		}
	}
	return true;
}

std::string hex_u64(ut64 v) {
	std::ostringstream out;
	out << std::hex << v;
	return out.str();
}

std::string sanitize_component(const std::string &in) {
	std::string out;
	out.reserve(in.size());
	for (unsigned char ch : in) {
		if (std::isalnum(ch)) {
			out.push_back(static_cast<char>(ch));
		} else {
			out.push_back('_');
		}
	}
	while (!out.empty() && out.front() == '_') {
		out.erase(out.begin());
	}
	while (!out.empty() && out.back() == '_') {
		out.pop_back();
	}
	if (out.empty()) {
		out = "txt";
	}
	if (out.size() > 24) {
		out.resize(24);
	}
	return out;
}

std::string make_string_flag_name(ut64 ptr, const std::string &text, bool is_pubkey) {
	if (is_pubkey) {
		const std::string short_id = sanitize_component(text.substr(0, std::min<size_t>(10, text.size())));
		return "str.sol.pubkey_" + short_id + "_" + hex_u64(ptr);
	}
	const std::string short_text = sanitize_component(text.substr(0, std::min<size_t>(24, text.size())));
	return "str.sol." + short_text + "_" + hex_u64(ptr);
}

std::string make_ptr_flag_name(ut64 slot_addr, bool is_pubkey) {
	return std::string(is_pubkey ? "sym.sol.ptr_pubkey_" : "sym.sol.ptr_str_") + hex_u64(slot_addr);
}

void apply_flag(
	RCore *core,
	const char *space,
	const std::string &name,
	ut64 addr,
	ut32 size)
{
	if (!core || !core->flags || name.empty()) {
		return;
	}
	RFlagItem *existing = r_flag_get(core->flags, name.c_str());
	if (existing) {
		if (existing->addr == addr) {
			return;
		}
	}
	r_flag_set_inspace(core->flags, space, name.c_str(), addr, size);
}

DiscoveredString *register_discovered_string(
	RCore *core,
	std::unordered_map<PtrLenKey, DiscoveredString, PtrLenKeyHash> &by_ptr_len,
	std::unordered_map<ut64, std::string> &value_to_symbol,
	ut64 ptr,
	ut64 len,
	const std::vector<uint1> &bytes)
{
	const PtrLenKey key { ptr, len };
	auto it = by_ptr_len.find(key);
	if (it == by_ptr_len.end()) {
		DiscoveredString d;
		d.ptr = ptr;
		d.len = len;
		d.is_pubkey = looks_like_base58_pubkey(bytes);
		d.text.assign(bytes.begin(), bytes.end());
		d.string_flag_name = make_string_flag_name(ptr, d.text, d.is_pubkey);
		it = by_ptr_len.emplace(key, std::move(d)).first;
		apply_flag(core, R_FLAGS_FS_STRINGS, it->second.string_flag_name, ptr, static_cast<ut32>(len));
	}
	value_to_symbol.emplace(ptr, it->second.string_flag_name);
	return &it->second;
}

void discover_strings_from_ptr_len_tables(
	RCore *core,
	const std::vector<AddressRange> &rodata_ranges,
	const std::vector<AddressRange> &table_ranges,
	std::unordered_map<ut64, std::string> &value_to_symbol)
{
	std::unordered_map<PtrLenKey, DiscoveredString, PtrLenKeyHash> by_ptr_len;

	for (const auto &table : table_ranges) {
		if (table.size < 16 || table.size > static_cast<ut64>(std::numeric_limits<int>::max())) {
			continue;
		}
		std::vector<uint1> table_bytes(static_cast<size_t>(table.size));
		if (!read_virtual(core, table.start, table_bytes.data(), table_bytes.size())) {
			continue;
		}
		for (size_t off = 0; off + 16 <= table_bytes.size(); off += 8) {
			ut64 ptr = read_u64_le(table_bytes.data() + off);
			ut64 len = read_u64_le(table_bytes.data() + off + 8);
			if (len == 0 || len > kMaxStringBytes || !in_ranges(rodata_ranges, ptr, len)) {
				continue;
			}
			std::vector<uint1> bytes(static_cast<size_t>(len));
			if (!read_virtual(core, ptr, bytes.data(), bytes.size())) {
				continue;
			}
			if (!looks_like_text_buffer(bytes)) {
				continue;
			}
			DiscoveredString *d = register_discovered_string(core, by_ptr_len, value_to_symbol, ptr, len, bytes);
			const ut64 slot_addr = table.start + static_cast<ut64>(off);
			const std::string ptr_name = make_ptr_flag_name(slot_addr, d->is_pubkey);
			apply_flag(core, R_FLAGS_FS_SYMBOLS, ptr_name, slot_addr, 16);
			value_to_symbol.emplace(slot_addr, ptr_name);
		}
	}

	for (const auto &table : table_ranges) {
		if (table.size < 8 || table.size > static_cast<ut64>(std::numeric_limits<int>::max())) {
			continue;
		}
		std::vector<uint1> table_bytes(static_cast<size_t>(table.size));
		if (!read_virtual(core, table.start, table_bytes.data(), table_bytes.size())) {
			continue;
		}
		for (size_t off = 0; off + 8 <= table_bytes.size(); off += 8) {
			ut64 ptr = read_u64_le(table_bytes.data() + off);
			if (!in_ranges(rodata_ranges, ptr, 1)) {
				continue;
			}
			std::vector<uint1> bytes;
			if (!read_nul_terminated_text(core, rodata_ranges, ptr, bytes)) {
				continue;
			}
			if (bytes.size() > static_cast<size_t>(kMaxStringBytes) || !looks_like_text_buffer(bytes)) {
				continue;
			}
			DiscoveredString *d = register_discovered_string(
				core, by_ptr_len, value_to_symbol, ptr, bytes.size(), bytes);
			const ut64 slot_addr = table.start + static_cast<ut64>(off);
			const std::string ptr_name = make_ptr_flag_name(slot_addr, d->is_pubkey);
			apply_flag(core, R_FLAGS_FS_SYMBOLS, ptr_name, slot_addr, 8);
			value_to_symbol.emplace(slot_addr, ptr_name);
		}
	}
}

void apply_symbols_to_constant_hints(
	Funcdata *func,
	R2Architecture *arch,
	const std::unordered_map<ut64, std::string> &value_to_symbol)
{
	if (!func || !arch || value_to_symbol.empty()) {
		return;
	}
	for (auto it = func->beginOpAll(); it != func->endOpAll(); ++it) {
		PcodeOp *op = it->second;
		if (!op) {
			continue;
		}
		for (int4 i = 0; i < op->numInput(); ++i) {
			const Varnode *vn = op->getIn(i);
			if (!vn || !vn->isConstant()) {
				continue;
			}
			auto sit = value_to_symbol.find(vn->getOffset());
			if (sit == value_to_symbol.end()) {
				continue;
			}
			R2Architecture::SolanaInputOffsetHint hint;
			hint.value = vn->getOffset();
			hint.symbol = sit->second;
			arch->setSolanaInputOffsetHint(vn->getCreateIndex(), hint);
		}
	}
}

} // namespace

void SolanaGlobalPtrStringAnalyzer::run(Funcdata *func, R2Architecture *arch) {
	if (!func || !arch) {
		return;
	}
	std::unordered_map<ut64, std::string> value_to_symbol;
	{
		RCoreLock core(arch->getCore());
		if (!core || !core->bin || !core->io || !core->flags) {
			return;
		}
		std::vector<AddressRange> rodata_ranges;
		std::vector<AddressRange> table_ranges;
		collect_section_ranges(core, rodata_ranges, table_ranges);
		if (!rodata_ranges.empty() && !table_ranges.empty()) {
			discover_strings_from_ptr_len_tables(core, rodata_ranges, table_ranges, value_to_symbol);
		}
	}
	apply_symbols_to_constant_hints(func, arch, value_to_symbol);
}
