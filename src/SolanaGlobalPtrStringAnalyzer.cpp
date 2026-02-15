/* r2ghidra - LGPL - Copyright 2026 - pancake */

#include "SolanaGlobalPtrStringAnalyzer.h"

#include "R2Architecture.h"
#include "RCoreMutex.h"

#include <funcdata.hh>

#include <r_core.h>
#include <r_bin.h>
#include <r_flag.h>

#include <algorithm>
#include <array>
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

enum class PubkeyConfidence : uint8_t {
	None = 0,
	Maybe = 1,
	High = 2,
};

struct DiscoveredString {
	ut64 ptr = 0;
	ut64 len = 0;
	PubkeyConfidence pubkey_confidence = PubkeyConfidence::None;
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
	std::vector<AddressRange> &table_ranges,
	std::vector<AddressRange> *text_ranges)
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
		const bool is_rodata = contains_text_section_name(name, "rodata");
		if (is_rodata) {
			rodata_ranges.push_back({ start, size, name });
			// Rust and C const pointer tables can be emitted into rodata.
			table_ranges.push_back({ start, size, name });
		}
		if (contains_text_section_name(name, ".data.rel.ro")
				|| name == ".data"
				|| contains_text_section_name(name, ".data.rel.ro.")
				|| contains_text_section_name(name, ".data.rel")) {
			table_ranges.push_back({ start, size, name });
		}
		if (text_ranges && (name == ".text" || contains_text_section_name(name, "text"))) {
			text_ranges->push_back({ start, size, name });
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

bool is_base58_char(uint1 ch) {
	const bool in_1_9 = ch >= '1' && ch <= '9';
	const bool in_A_H = ch >= 'A' && ch <= 'H';
	const bool in_J_N = ch >= 'J' && ch <= 'N';
	const bool in_P_Z = ch >= 'P' && ch <= 'Z';
	const bool in_a_k = ch >= 'a' && ch <= 'k';
	const bool in_m_z = ch >= 'm' && ch <= 'z';
	return in_1_9 || in_A_H || in_J_N || in_P_Z || in_a_k || in_m_z;
}

PubkeyConfidence classify_base58_pubkey(const std::vector<uint1> &buf) {
	if (buf.size() < 32 || buf.size() > 44) {
		return PubkeyConfidence::None;
	}
	bool has_digit = false;
	bool has_upper = false;
	bool has_lower = false;
	std::array<bool, 128> seen {};
	size_t unique = 0;
	for (uint1 ch : buf) {
		if (!is_base58_char(ch)) {
			return PubkeyConfidence::None;
		}
		if (ch >= '1' && ch <= '9') {
			has_digit = true;
		} else if (ch >= 'A' && ch <= 'Z') {
			has_upper = true;
		} else if (ch >= 'a' && ch <= 'z') {
			has_lower = true;
		}
		if (ch < seen.size() && !seen[ch]) {
			seen[ch] = true;
			++unique;
		}
	}
	// High confidence: broad charset usage and mixed classes.
	if (has_digit && has_upper && has_lower && unique >= 12) {
		return PubkeyConfidence::High;
	}
	// Maybe: valid base58 token length for pubkey but weaker diversity.
	return PubkeyConfidence::Maybe;
}

bool is_pubkey_candidate(PubkeyConfidence confidence) {
	return confidence != PubkeyConfidence::None;
}

bool is_high_confidence_pubkey(PubkeyConfidence confidence) {
	return confidence == PubkeyConfidence::High;
}

struct PubkeySpan {
	size_t start = 0;
	size_t len = 0;
	PubkeyConfidence confidence = PubkeyConfidence::None;
};

void collect_base58_pubkey_spans(
	const std::vector<uint1> &buf,
	std::vector<PubkeySpan> &spans)
{
	spans.clear();
	size_t i = 0;
	while (i < buf.size()) {
		if (!is_base58_char(buf[i])) {
			++i;
			continue;
		}
		size_t j = i;
		while (j < buf.size() && is_base58_char(buf[j])) {
			++j;
		}
		const size_t len = j - i;
		if (len >= 32 && len <= 44) {
			std::vector<uint1> token(
				buf.begin() + static_cast<ptrdiff_t>(i),
				buf.begin() + static_cast<ptrdiff_t>(j));
			const PubkeyConfidence confidence = classify_base58_pubkey(token);
			if (is_pubkey_candidate(confidence)) {
				PubkeySpan span;
				span.start = i;
				span.len = len;
				span.confidence = confidence;
				spans.push_back(span);
			}
		}
		i = j;
	}
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

std::string make_string_flag_name(ut64 ptr, const std::string &text, PubkeyConfidence confidence) {
	if (is_pubkey_candidate(confidence)) {
		const std::string short_id = sanitize_component(text.substr(0, std::min<size_t>(10, text.size())));
		const char *prefix = is_high_confidence_pubkey(confidence)
			? "str.sol.pubkey_"
			: "str.sol.maybe_pubkey_";
		return std::string(prefix) + short_id + "_" + hex_u64(ptr);
	}
	const std::string short_text = sanitize_component(text.substr(0, std::min<size_t>(24, text.size())));
	return "str.sol." + short_text + "_" + hex_u64(ptr);
}

std::string make_ptr_flag_name(ut64 slot_addr, PubkeyConfidence confidence) {
	if (is_high_confidence_pubkey(confidence)) {
		return "sym.sol.ptr_pubkey_" + hex_u64(slot_addr);
	}
	if (is_pubkey_candidate(confidence)) {
		return "sym.sol.ptr_maybe_pubkey_" + hex_u64(slot_addr);
	}
	return "sym.sol.ptr_str_" + hex_u64(slot_addr);
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
		d.pubkey_confidence = classify_base58_pubkey(bytes);
		d.text.assign(bytes.begin(), bytes.end());
		d.string_flag_name = make_string_flag_name(ptr, d.text, d.pubkey_confidence);
		it = by_ptr_len.emplace(key, std::move(d)).first;
		apply_flag(core, R_FLAGS_FS_STRINGS, it->second.string_flag_name, ptr, static_cast<ut32>(len));
	}
	value_to_symbol.emplace(ptr, it->second.string_flag_name);
	return &it->second;
}

void register_embedded_pubkeys(
	RCore *core,
	std::unordered_map<PtrLenKey, DiscoveredString, PtrLenKeyHash> &by_ptr_len,
	std::unordered_map<ut64, std::string> &value_to_symbol,
	ut64 base_ptr,
	const std::vector<uint1> &bytes)
{
	if (bytes.size() < 32) {
		return;
	}
	std::vector<PubkeySpan> spans;
	collect_base58_pubkey_spans(bytes, spans);
	for (const auto &span : spans) {
		if (span.len < 32 || span.len > 44) {
			continue;
		}
		const size_t start = span.start;
		const size_t len = span.len;
		std::vector<uint1> token(
			bytes.begin() + static_cast<ptrdiff_t>(start),
			bytes.begin() + static_cast<ptrdiff_t>(start + len));
		DiscoveredString *d = register_discovered_string(
			core,
			by_ptr_len,
			value_to_symbol,
			base_ptr + static_cast<ut64>(start),
			static_cast<ut64>(len),
			token);
		if (d && is_pubkey_candidate(d->pubkey_confidence)) {
			value_to_symbol.emplace(base_ptr + static_cast<ut64>(start), d->string_flag_name);
		}
	}
}

void discover_strings_from_ptr_len_tables(
	RCore *core,
	const std::vector<AddressRange> &rodata_ranges,
	const std::vector<AddressRange> &table_ranges,
	bool allow_direct_rodata_scan,
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
			if (d && !is_pubkey_candidate(d->pubkey_confidence)) {
				register_embedded_pubkeys(core, by_ptr_len, value_to_symbol, ptr, bytes);
			}
			const ut64 slot_addr = table.start + static_cast<ut64>(off);
			const PubkeyConfidence confidence = d ? d->pubkey_confidence : PubkeyConfidence::None;
			const std::string ptr_name = make_ptr_flag_name(slot_addr, confidence);
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
			if (d && !is_pubkey_candidate(d->pubkey_confidence)) {
				register_embedded_pubkeys(core, by_ptr_len, value_to_symbol, ptr, bytes);
			}
			const ut64 slot_addr = table.start + static_cast<ut64>(off);
			const PubkeyConfidence confidence = d ? d->pubkey_confidence : PubkeyConfidence::None;
			const std::string ptr_name = make_ptr_flag_name(slot_addr, confidence);
			apply_flag(core, R_FLAGS_FS_SYMBOLS, ptr_name, slot_addr, 8);
			value_to_symbol.emplace(slot_addr, ptr_name);
		}
	}

	if (!allow_direct_rodata_scan) {
		return;
	}
	for (const auto &range : rodata_ranges) {
		if (range.size < 4 || range.size > static_cast<ut64>(std::numeric_limits<int>::max())) {
			continue;
		}
		std::vector<uint1> bytes(static_cast<size_t>(range.size));
		if (!read_virtual(core, range.start, bytes.data(), bytes.size())) {
			continue;
		}
		size_t i = 0;
		while (i < bytes.size()) {
			uint1 c = bytes[i];
			const bool printable_head = (c == '\n' || c == '\r' || c == '\t' || (c >= 0x20 && c <= 0x7e));
			if (!printable_head || c == 0) {
				++i;
				continue;
			}
			size_t j = i;
			bool malformed = false;
			while (j < bytes.size() && (j - i) < static_cast<size_t>(kMaxStringBytes)) {
				uint1 ch = bytes[j];
				if (ch == 0) {
					break;
				}
				if (!(ch == '\n' || ch == '\r' || ch == '\t' || (ch >= 0x20 && ch <= 0x7e))) {
					malformed = true;
					break;
				}
				++j;
			}
			if (malformed || j >= bytes.size() || bytes[j] != 0) {
				++i;
				continue;
			}
			const size_t len = j - i;
			if (len < 4) {
				i = j + 1;
				continue;
			}
			std::vector<uint1> text(bytes.begin() + static_cast<ptrdiff_t>(i), bytes.begin() + static_cast<ptrdiff_t>(j));
			if (!looks_like_text_buffer(text)) {
				i = j + 1;
				continue;
			}
			const ut64 ptr = range.start + static_cast<ut64>(i);
			DiscoveredString *d = register_discovered_string(
				core, by_ptr_len, value_to_symbol, ptr, static_cast<ut64>(len), text);
			if (d) {
				value_to_symbol.emplace(ptr, d->string_flag_name);
				if (!is_pubkey_candidate(d->pubkey_confidence)) {
					register_embedded_pubkeys(core, by_ptr_len, value_to_symbol, ptr, text);
				}
			}
			i = j + 1;
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
		std::vector<AddressRange> text_ranges;
		collect_section_ranges(core, rodata_ranges, table_ranges, &text_ranges);
		bool used_text_fallback = false;
		if (rodata_ranges.empty() && !text_ranges.empty()) {
			// sBPF v0 commonly keeps rodata in .text; use it as conservative fallback.
			rodata_ranges = text_ranges;
			used_text_fallback = true;
		}
		if (!rodata_ranges.empty() && !table_ranges.empty()) {
			discover_strings_from_ptr_len_tables(
				core, rodata_ranges, table_ranges, !used_text_fallback, value_to_symbol);
		}
	}
	apply_symbols_to_constant_hints(func, arch, value_to_symbol);
}
