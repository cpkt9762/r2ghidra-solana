/* r2ghidra - LGPL - Copyright 2026 - pancake */

#include "SolanaAnchorDispatcherAnalyzer.h"

#include "R2Architecture.h"
#include "RCoreMutex.h"
#include "SolanaCallResolver.h"

#include <funcdata.hh>
#include <block.hh>

#include <r_anal.h>
#include <r_bin.h>
#include <r_flag.h>
#include <r_hash.h>
#include <r_util/r_file.h>
#include <r_util/r_json.h>

#include <array>
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <map>
#include <queue>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace ghidra;

namespace {

constexpr size_t kDiscriminatorLen = 8;

struct CallCandidate {
	const PcodeOp *op = nullptr;
	ut64 target = 0;
	const BlockBasic *block = nullptr;
};

struct ByteConstraint {
	int index = -1;
	uint8_t value = 0;
};

struct InstructionMetadata {
	std::string idl_name;
	std::string normalized_name;
	std::vector<std::string> args;
	std::vector<std::string> accounts;
};

static bool try_resolve_constant_varnode(const Varnode *vn, uintb &out, int depth = 12) {
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
	case CPUI_SUBPIECE:
		return try_resolve_constant_varnode(def->getIn(0), out, depth - 1);
	case CPUI_PTRSUB:
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
	default:
		break;
	}
	return false;
}

static const Varnode *strip_simple_casts(const Varnode *vn, int depth = 10) {
	while (vn && depth-- > 0 && vn->isWritten()) {
		const PcodeOp *def = vn->getDef();
		if (!def || def->numInput() < 1) {
			break;
		}
		switch (def->code()) {
		case CPUI_COPY:
		case CPUI_CAST:
		case CPUI_INT_ZEXT:
		case CPUI_INT_SEXT:
		case CPUI_SUBPIECE:
			vn = def->getIn(0);
			continue;
		default:
			break;
		}
		break;
	}
	return vn;
}

static bool resolve_ptr_base_plus_offset(
	const Varnode *vn,
	const Varnode *&base,
	int64_t &offset,
	int depth = 12)
{
	if (!vn || depth <= 0) {
		return false;
	}
	vn = strip_simple_casts(vn, 2);
	if (!vn) {
		return false;
	}
	if (!vn->isWritten()) {
		base = vn;
		offset = 0;
		return true;
	}
	const PcodeOp *def = vn->getDef();
	if (!def) {
		return false;
	}
	switch (def->code()) {
	case CPUI_INT_ADD:
	case CPUI_PTRSUB: {
		if (def->numInput() < 2) {
			return false;
		}
		uintb cst = 0;
		if (try_resolve_constant_varnode(def->getIn(1), cst, depth - 1)
				&& resolve_ptr_base_plus_offset(def->getIn(0), base, offset, depth - 1)) {
			offset += static_cast<int64_t>(cst);
			return true;
		}
		if (try_resolve_constant_varnode(def->getIn(0), cst, depth - 1)
				&& resolve_ptr_base_plus_offset(def->getIn(1), base, offset, depth - 1)) {
			offset += static_cast<int64_t>(cst);
			return true;
		}
		break;
	}
	case CPUI_INT_SUB: {
		if (def->numInput() < 2) {
			return false;
		}
		uintb cst = 0;
		if (try_resolve_constant_varnode(def->getIn(1), cst, depth - 1)
				&& resolve_ptr_base_plus_offset(def->getIn(0), base, offset, depth - 1)) {
			offset -= static_cast<int64_t>(cst);
			return true;
		}
		break;
	}
	case CPUI_PTRADD: {
		if (def->numInput() < 3) {
			return false;
		}
		uintb idx = 0;
		uintb stride = 0;
		if (try_resolve_constant_varnode(def->getIn(1), idx, depth - 1)
				&& try_resolve_constant_varnode(def->getIn(2), stride, depth - 1)
				&& resolve_ptr_base_plus_offset(def->getIn(0), base, offset, depth - 1)) {
			offset += static_cast<int64_t>(idx * stride);
			return true;
		}
		break;
	}
	default:
		break;
	}
	base = vn;
	offset = 0;
	return true;
}

static int normalize_stack_delta(int64_t off) {
	switch (off) {
	case -0x1f8:
		return 0xfe08;
	case -0x200:
		return 0xfe00;
	case -0x208:
		return 0xfdf8;
	case -0x210:
		return 0xfdf0;
	default:
		break;
	}
	return static_cast<int>(off & 0xffff);
}

static bool map_stack_slot_to_index(int normalized_off, int &out_index) {
	switch (normalized_off) {
	case 0xfe08:
		out_index = 4;
		return true;
	case 0xfe00:
		out_index = 5;
		return true;
	case 0xfdf8:
		out_index = 6;
		return true;
	case 0xfdf0:
		out_index = 7;
		return true;
	default:
		break;
	}
	return false;
}

static bool resolve_discriminator_byte_index(
	const Varnode *vn,
	R2Architecture *arch,
	int &out_index,
	int depth = 18)
{
	if (!vn || !arch || depth <= 0) {
		return false;
	}
	vn = strip_simple_casts(vn, 4);
	if (!vn) {
		return false;
	}

	const Address r9 = arch->registerAddressFromR2Reg("r9");
	const Address r8 = arch->registerAddressFromR2Reg("r8");
	const Address r7 = arch->registerAddressFromR2Reg("r7");
	const Address r0 = arch->registerAddressFromR2Reg("r0");
	const Address r10 = arch->registerAddressFromR2Reg("r10");

	if (vn->getAddr() == r9) {
		out_index = 0;
		return true;
	}
	if (vn->getAddr() == r8) {
		out_index = 1;
		return true;
	}
	if (vn->getAddr() == r7) {
		out_index = 2;
		return true;
	}
	if (vn->getAddr() == r0 && !vn->isWritten()) {
		out_index = 3;
		return true;
	}

	if (!vn->isWritten()) {
		return false;
	}
	const PcodeOp *def = vn->getDef();
	if (!def) {
		return false;
	}
	switch (def->code()) {
	case CPUI_COPY:
	case CPUI_CAST:
	case CPUI_INT_ZEXT:
	case CPUI_INT_SEXT:
	case CPUI_SUBPIECE:
	case CPUI_INT_AND:
		return resolve_discriminator_byte_index(def->getIn(0), arch, out_index, depth - 1);
	case CPUI_MULTIEQUAL: {
		bool seen = false;
		int merged = -1;
		for (int4 i = 0; i < def->numInput(); ++i) {
			int cur = -1;
			if (!resolve_discriminator_byte_index(def->getIn(i), arch, cur, depth - 1)) {
				return false;
			}
			if (!seen) {
				seen = true;
				merged = cur;
				continue;
			}
			if (merged != cur) {
				return false;
			}
		}
		if (!seen) {
			return false;
		}
		out_index = merged;
		return true;
	}
	case CPUI_LOAD: {
		if (def->numInput() < 2) {
			return false;
		}
		const Varnode *base = nullptr;
		int64_t off = 0;
		if (!resolve_ptr_base_plus_offset(def->getIn(1), base, off, depth - 1)) {
			return false;
		}
		if (off >= 0 && off < static_cast<int64_t>(kDiscriminatorLen)) {
			out_index = static_cast<int>(off);
			return true;
		}
		int normalized = normalize_stack_delta(off);
		if (base && base->getAddr() == r10 && map_stack_slot_to_index(normalized, out_index)) {
			return true;
		}
		if (map_stack_slot_to_index(normalized, out_index)) {
			return true;
		}
		return false;
	}
	default:
		break;
	}
	return false;
}

static bool extract_byte_constraint_from_condition(
	const Varnode *cond,
	bool cond_true,
	R2Architecture *arch,
	ByteConstraint &out,
	int depth = 12)
{
	if (!cond || !arch || depth <= 0) {
		return false;
	}
	cond = strip_simple_casts(cond, 2);
	if (!cond || !cond->isWritten()) {
		return false;
	}
	const PcodeOp *def = cond->getDef();
	if (!def) {
		return false;
	}
	if (def->code() == CPUI_BOOL_NEGATE && def->numInput() >= 1) {
		return extract_byte_constraint_from_condition(def->getIn(0), !cond_true, arch, out, depth - 1);
	}
	if ((def->code() != CPUI_INT_EQUAL && def->code() != CPUI_INT_NOTEQUAL) || def->numInput() < 2) {
		return false;
	}

	const bool is_equal = def->code() == CPUI_INT_EQUAL;
	const bool requires_equal = cond_true ? is_equal : !is_equal;
	if (!requires_equal) {
		return false;
	}

	uintb cst = 0;
	int index = -1;
	if (try_resolve_constant_varnode(def->getIn(0), cst, depth - 1)
			&& cst <= 0xff
			&& resolve_discriminator_byte_index(def->getIn(1), arch, index, depth - 1)) {
		out.index = index;
		out.value = static_cast<uint8_t>(cst);
		return true;
	}
	if (try_resolve_constant_varnode(def->getIn(1), cst, depth - 1)
			&& cst <= 0xff
			&& resolve_discriminator_byte_index(def->getIn(0), arch, index, depth - 1)) {
		out.index = index;
		out.value = static_cast<uint8_t>(cst);
		return true;
	}
	return false;
}

static bool build_path_to_target_block(
	const FlowBlock *start,
	const FlowBlock *target,
	std::vector<const FlowBlock *> &path)
{
	if (!start || !target) {
		return false;
	}
	std::queue<const FlowBlock *> q;
	std::unordered_set<const FlowBlock *> visited;
	std::unordered_map<const FlowBlock *, const FlowBlock *> prev;
	q.push(start);
	visited.insert(start);
	bool found = false;
	while (!q.empty()) {
		const FlowBlock *cur = q.front();
		q.pop();
		if (cur == target) {
			found = true;
			break;
		}
		for (int4 i = 0; i < cur->sizeOut(); ++i) {
			const FlowBlock *next = cur->getOut(i);
			if (!next || visited.find(next) != visited.end()) {
				continue;
			}
			visited.insert(next);
			prev[next] = cur;
			q.push(next);
		}
	}
	if (!found) {
		return false;
	}
	path.clear();
	for (const FlowBlock *it = target; it; ) {
		path.push_back(it);
		if (it == start) {
			break;
		}
		auto pit = prev.find(it);
		if (pit == prev.end()) {
			return false;
		}
		it = pit->second;
	}
	std::reverse(path.begin(), path.end());
	return !path.empty() && path.front() == start && path.back() == target;
}

static bool collect_discriminator_for_call(
	const BlockGraph &graph,
	const BlockBasic *call_block,
	R2Architecture *arch,
	std::array<int, kDiscriminatorLen> &out)
{
	out.fill(-1);
	const FlowBlock *start = graph.getStartBlock();
	if (!start || !call_block) {
		return false;
	}
	std::vector<const FlowBlock *> path;
	if (!build_path_to_target_block(start, call_block, path) || path.size() < 2) {
		return false;
	}
	for (size_t i = 0; i + 1 < path.size(); ++i) {
		const FlowBlock *cur = path[i];
		const FlowBlock *next = path[i + 1];
		if (!cur || cur->getType() != FlowBlock::t_basic) {
			continue;
		}
		const auto *bb = static_cast<const BlockBasic *>(cur);
		PcodeOp *last = bb->lastOp();
		if (!last || last->code() != CPUI_CBRANCH || last->numInput() < 2 || cur->sizeOut() != 2) {
			continue;
		}
		const bool took_true = (cur->getTrueOut() == next);
		const bool took_false = (cur->getFalseOut() == next);
		if (!took_true && !took_false) {
			continue;
		}
		ByteConstraint c;
		if (!extract_byte_constraint_from_condition(last->getIn(1), took_true, arch, c)) {
			continue;
		}
		if (c.index < 0 || c.index >= static_cast<int>(kDiscriminatorLen)) {
			continue;
		}
		if (out[c.index] != -1 && out[c.index] != static_cast<int>(c.value)) {
			return false;
		}
		out[c.index] = static_cast<int>(c.value);
	}
	return true;
}

static ut64 read_le64(const uint8_t *p) {
	return static_cast<ut64>(p[0])
		| (static_cast<ut64>(p[1]) << 8)
		| (static_cast<ut64>(p[2]) << 16)
		| (static_cast<ut64>(p[3]) << 24)
		| (static_cast<ut64>(p[4]) << 32)
		| (static_cast<ut64>(p[5]) << 40)
		| (static_cast<ut64>(p[6]) << 48)
		| (static_cast<ut64>(p[7]) << 56);
}

static std::string to_snake_case(const std::string &in) {
	std::string out;
	out.reserve(in.size() * 2);
	for (size_t i = 0; i < in.size(); ++i) {
		const unsigned char c = static_cast<unsigned char>(in[i]);
		if (std::isalnum(c)) {
			const bool upper = std::isupper(c);
			if (upper && !out.empty()) {
				const unsigned char prev = static_cast<unsigned char>(in[i - 1]);
				const bool prev_lower_or_digit = std::islower(prev) || std::isdigit(prev);
				const bool next_lower = (i + 1 < in.size())
					? std::islower(static_cast<unsigned char>(in[i + 1]))
					: false;
				if (prev_lower_or_digit || next_lower) {
					out.push_back('_');
				}
			}
			out.push_back(static_cast<char>(std::tolower(c)));
		} else if (!out.empty() && out.back() != '_') {
			out.push_back('_');
		}
	}
	while (!out.empty() && out.front() == '_') {
		out.erase(out.begin());
	}
	while (!out.empty() && out.back() == '_') {
		out.pop_back();
	}
	return out;
}

static bool is_lower_snake(const std::string &name) {
	if (name.empty()) {
		return false;
	}
	for (unsigned char c : name) {
		if (!(std::islower(c) || std::isdigit(c) || c == '_')) {
			return false;
		}
	}
	return true;
}

static bool anchor_hash_preimage(const std::string &preimage, ut64 &out_hash) {
	RHash *ctx = r_hash_new (true, 0);
	if (!ctx) {
		return false;
	}
	ut8 *digest = r_hash_do_sha256(ctx, reinterpret_cast<const ut8 *>(preimage.data()), static_cast<int>(preimage.size()));
	if (!digest) {
		r_hash_free(ctx);
		return false;
	}
	out_hash = read_le64(digest);
	r_hash_free(ctx);
	return true;
}

static void add_name_mapping(std::unordered_map<ut64, std::string> &map, const std::string &snake_name) {
	if (snake_name.empty()) {
		return;
	}
	ut64 h = 0;
	if (!anchor_hash_preimage("global:" + snake_name, h)) {
		return;
	}
	map.emplace(h, snake_name);
}

static void add_builtin_anchor_mappings(std::unordered_map<ut64, std::string> &map) {
	map.emplace(0x0a69e9a778bcf440ULL, "anchor_idl");
	map.emplace(0x40f4bc78a7e9690aULL, "anchor_idl");
	map.emplace(0x1d9acb512ea545e4ULL, "anchor_event");
	ut64 h = 0;
	if (anchor_hash_preimage("anchor:idl", h)) {
		map.emplace(h, "anchor_idl");
	}
	if (anchor_hash_preimage("anchor:event", h)) {
		map.emplace(h, "anchor_event");
	}
}

static bool decode_discriminator_array(const RJson *disc_json, ut64 &out_disc) {
	if (!disc_json || disc_json->type != R_JSON_ARRAY || disc_json->children.count != kDiscriminatorLen) {
		return false;
	}
	uint8_t raw[kDiscriminatorLen] = {0};
	for (size_t i = 0; i < kDiscriminatorLen; ++i) {
		const RJson *item = r_json_item(disc_json, i);
		if (!item || item->type != R_JSON_INTEGER || item->num.u_value > 0xff) {
			return false;
		}
		raw[i] = static_cast<uint8_t>(item->num.u_value);
	}
	out_disc = read_le64(raw);
	return true;
}

static void collect_named_entries(const RJson *arr, std::vector<std::string> &out) {
	if (!arr || arr->type != R_JSON_ARRAY) {
		return;
	}
	for (size_t i = 0; i < arr->children.count; ++i) {
		const RJson *item = r_json_item(arr, i);
		const char *name = item ? r_json_get_str(item, "name") : nullptr;
		if (!name || !*name) {
			continue;
		}
		out.emplace_back(name);
	}
}

static bool json_truthy_property(const RJson *obj, const char *key) {
	if (!obj || !key || !*key) {
		return false;
	}
	const RJson *v = r_json_get(obj, key);
	if (!v) {
		return false;
	}
	switch (v->type) {
	case R_JSON_BOOLEAN:
	case R_JSON_INTEGER:
		return v->num.u_value != 0;
	case R_JSON_STRING:
		if (!v->str_value) {
			return false;
		}
		return !strcmp(v->str_value, "true")
			|| !strcmp(v->str_value, "1")
			|| !strcmp(v->str_value, "yes");
	default:
		break;
	}
	return false;
}

static void collect_account_entries_recursive(
	const RJson *arr,
	std::vector<std::string> &out,
	const std::string &prefix = std::string())
{
	if (!arr || arr->type != R_JSON_ARRAY) {
		return;
	}
	for (size_t i = 0; i < arr->children.count; ++i) {
		const RJson *item = r_json_item(arr, i);
		if (!item || item->type != R_JSON_OBJECT) {
			continue;
		}
		const char *name = r_json_get_str(item, "name");
		std::string current = prefix;
		if (name && *name) {
			if (!current.empty()) {
				current.push_back('.');
			}
			current += name;
		}
		const RJson *nested = r_json_get(item, "accounts");
		if (nested && nested->type == R_JSON_ARRAY) {
			collect_account_entries_recursive(nested, out, current);
			continue;
		}
		if (!current.empty()) {
			const bool signer = json_truthy_property(item, "signer") || json_truthy_property(item, "isSigner");
			const bool writable = json_truthy_property(item, "writable")
				|| json_truthy_property(item, "isMut")
				|| json_truthy_property(item, "mut");
			const bool optional = json_truthy_property(item, "optional") || json_truthy_property(item, "isOptional");
			if (signer || writable || optional) {
				current.push_back('[');
				if (signer) {
					current.push_back('s');
				}
				if (writable) {
					current.push_back('w');
				}
				if (optional) {
					current.push_back('o');
				}
				current.push_back(']');
			}
			out.push_back(current);
		}
	}
}

static std::string list_preview(const std::vector<std::string> &items, size_t limit = 8) {
	if (items.empty()) {
		return std::string();
	}
	std::ostringstream out;
	const size_t shown = std::min(items.size(), limit);
	for (size_t i = 0; i < shown; ++i) {
		if (i > 0) {
			out << ",";
		}
		out << items[i];
	}
	if (items.size() > shown) {
		out << ",+" << (items.size() - shown);
	}
	return out.str();
}

static std::string format_disc_hex(ut64 disc) {
	std::ostringstream out;
	out << "0x" << std::hex << std::setw(16) << std::setfill('0') << disc;
	return out.str();
}

static void collect_instruction_mappings_from_idl(
	const std::string &idl_path,
	std::unordered_map<ut64, std::string> &disc_to_name,
	std::set<std::string> &fallback_names,
	std::unordered_map<ut64, InstructionMetadata> &disc_to_meta)
{
	if (idl_path.empty()) {
		return;
	}
	size_t sz = 0;
	char *json_text = r_file_slurp(idl_path.c_str(), &sz);
	if (!json_text || sz == 0) {
		free(json_text);
		return;
	}
	RJson *json = r_json_parse(json_text);
	if (!json) {
		free(json_text);
		return;
	}
	const RJson *instructions = r_json_get(json, "instructions");
	if (instructions && instructions->type == R_JSON_ARRAY) {
		for (size_t i = 0; i < instructions->children.count; ++i) {
			const RJson *item = r_json_item(instructions, i);
			const char *name = item ? r_json_get_str(item, "name") : nullptr;
			if (!name || !*name) {
				continue;
			}
			std::string normalized = is_lower_snake(name) ? name : to_snake_case(name);
			if (!normalized.empty()) {
				InstructionMetadata meta;
				meta.idl_name = name;
				meta.normalized_name = normalized;
				collect_named_entries(r_json_get(item, "args"), meta.args);
				collect_account_entries_recursive(r_json_get(item, "accounts"), meta.accounts);
				ut64 disc = 0;
				const RJson *disc_json = r_json_get(item, "discriminator");
				if (decode_discriminator_array(disc_json, disc)) {
					disc_to_name.emplace(disc, normalized);
					disc_to_meta.emplace(disc, std::move(meta));
				} else {
					fallback_names.insert(normalized);
				}
			}
		}
	}
	r_json_free(json);
	free(json_text);
}

static void extract_instruction_tokens(const std::string &text, std::set<std::string> &out_names) {
	static const std::string kMarker = "Instruction:";
	size_t pos = 0;
	while ((pos = text.find(kMarker, pos)) != std::string::npos) {
		pos += kMarker.size();
		while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos]))) {
			pos++;
		}
		size_t start = pos;
		while (pos < text.size() && std::isalnum(static_cast<unsigned char>(text[pos]))) {
			pos++;
		}
		if (pos <= start) {
			continue;
		}
		std::string token = text.substr(start, pos - start);
		std::string normalized = is_lower_snake(token) ? token : to_snake_case(token);
		if (!normalized.empty()) {
			out_names.insert(normalized);
		}
	}
}

static void collect_instruction_names_from_binary(RCore *core, std::set<std::string> &out_names) {
	if (!core || !core->bin) {
		return;
	}
	const RList *strings = r_bin_get_strings(core->bin);
	if (!strings) {
		return;
	}
	RListIter *iter;
	void *pos;
	r_list_foreach (strings, iter, pos) {
		auto *s = reinterpret_cast<RBinString *>(pos);
		if (!s || !s->string || !*s->string) {
			continue;
		}
		extract_instruction_tokens(s->string, out_names);
	}
}

static std::string format_disc_fallback(const std::array<int, kDiscriminatorLen> &bytes) {
	std::ostringstream out;
	out << "disc_";
	for (size_t i = 0; i < bytes.size(); ++i) {
		const int b = bytes[i] < 0 ? 0 : bytes[i];
		out << std::hex << std::setw(2) << std::setfill('0') << b;
	}
	return out.str();
}

static bool is_generic_function_name(const char *name) {
	if (!name || !*name) {
		return true;
	}
	return r_str_startswith(name, "fcn.")
		|| r_str_startswith(name, "func_0x")
		|| r_str_startswith(name, "sub.")
		|| r_str_startswith(name, "sym.func_");
}

static std::string unique_ix_name(RCore *core, ut64 target, const std::string &leaf) {
	std::string base = "ix." + leaf;
	if (!core || !core->flags) {
		return base;
	}
	RFlagItem *existing = r_flag_get(core->flags, base.c_str());
	if (!existing || existing->addr == target) {
		return base;
	}
	for (int i = 1; i < 10000; ++i) {
		std::string candidate = base + "_" + std::to_string(i);
		existing = r_flag_get(core->flags, candidate.c_str());
		if (!existing || existing->addr == target) {
			return candidate;
		}
	}
	return base;
}

static std::string unique_dispatch_name(RCore *core, ut64 target) {
	const std::string base = "ix.dispatch";
	if (!core || !core->flags) {
		return base;
	}
	RFlagItem *existing = r_flag_get(core->flags, base.c_str());
	if (!existing || existing->addr == target) {
		return base;
	}
	for (int i = 1; i < 10000; ++i) {
		std::string candidate = base + "_" + std::to_string(i);
		existing = r_flag_get(core->flags, candidate.c_str());
		if (!existing || existing->addr == target) {
			return candidate;
		}
	}
	return base;
}

static void rename_target_if_needed(RCore *core, ut64 target, const std::string &leaf) {
	if (!core || !core->anal || leaf.empty()) {
		return;
	}
	RAnalFunction *fcn = r_anal_get_fcn_in(core->anal, target, R_ANAL_FCN_TYPE_NULL);
	if (!fcn || !is_generic_function_name(fcn->name)) {
		return;
	}
	const std::string desired = unique_ix_name(core, target, leaf);
	r_anal_function_rename(fcn, desired.c_str());
}

static void rename_dispatcher_if_needed(RCore *core, ut64 target) {
	if (!core || !core->anal) {
		return;
	}
	RAnalFunction *fcn = r_anal_get_fcn_in(core->anal, target, R_ANAL_FCN_TYPE_NULL);
	if (!fcn || !is_generic_function_name(fcn->name)) {
		return;
	}
	const std::string desired = unique_dispatch_name(core, target);
	r_anal_function_rename(fcn, desired.c_str());
}

static std::string basename_of(const std::string &path) {
	if (path.empty()) {
		return std::string();
	}
	size_t pos = path.find_last_of("/\\");
	return pos == std::string::npos ? path : path.substr(pos + 1);
}

static void apply_dispatcher_comment(
	RCore *core,
	ut64 target,
	size_t resolved_targets,
	size_t total_targets,
	size_t unique_discriminators,
	const std::string &idl_path)
{
	if (!core || !core->anal) {
		return;
	}
	std::ostringstream comment;
	comment << "solana.anchor.dispatch targets=" << resolved_targets << "/" << total_targets
		<< " unique_disc=" << unique_discriminators;
	const std::string idl_base = basename_of(idl_path);
	if (!idl_base.empty()) {
		comment << " idl=" << idl_base;
	}
	const char *existing = r_meta_get_string(core->anal, R_META_TYPE_COMMENT, target);
	if (existing && *existing && !r_str_startswith(existing, "solana.anchor.dispatch ")) {
		return;
	}
	r_meta_set_string(core->anal, R_META_TYPE_COMMENT, target, comment.str().c_str());
}

static void apply_ix_signature_and_comment(
	RCore *core,
	ut64 target,
	ut64 disc,
	const std::string &leaf_name,
	const InstructionMetadata *meta,
	int arity)
{
	if (!core || !core->anal || leaf_name.empty()) {
		return;
	}
	RAnalFunction *fcn = r_anal_get_fcn_in(core->anal, target, R_ANAL_FCN_TYPE_NULL);
	if (!fcn || !fcn->name || !*fcn->name) {
		return;
	}
	int effective_arity = arity;
	if (effective_arity < 0) {
		// Anchor ix handlers are context-driven and are typically called with one frame/context pointer.
		effective_arity = 1;
	}

	std::ostringstream sig_text;
	sig_text << "uint64_t " << fcn->name << "(";
	if (effective_arity == 0) {
		sig_text << "void";
	} else if (effective_arity == 1) {
		sig_text << "void *ctx";
	} else if (effective_arity > 1 && effective_arity <= 16) {
		for (int i = 0; i < effective_arity; ++i) {
			if (i > 0) {
				sig_text << ", ";
			}
			sig_text << "uint64_t arg" << i;
		}
	} else {
		sig_text << "...";
	}
	sig_text << ");";
	std::string sig_owned = sig_text.str();
	if (!sig_owned.empty()) {
		r_anal_str_to_fcn(core->anal, fcn, sig_owned.c_str());
	}

	std::ostringstream comment;
	comment << "solana.anchor.ix " << leaf_name << " disc=" << format_disc_hex(disc);
	if (effective_arity >= 0) {
		comment << " arity=" << effective_arity;
	}
	if (meta) {
		if (!meta->idl_name.empty() && meta->idl_name != leaf_name) {
			comment << " idl=" << meta->idl_name;
		}
		std::string args_preview = list_preview(meta->args);
		if (!args_preview.empty()) {
			comment << " args=[" << args_preview << "]";
		}
		std::string accounts_preview = list_preview(meta->accounts);
		if (!accounts_preview.empty()) {
			comment << " accts=[" << accounts_preview << "]";
		}
	}

	const char *existing = r_meta_get_string(core->anal, R_META_TYPE_COMMENT, target);
	if (existing && *existing && !r_str_startswith(existing, "solana.anchor.ix ")) {
		return;
	}
	r_meta_set_string(core->anal, R_META_TYPE_COMMENT, target, comment.str().c_str());
}

static void apply_callsite_comment(
	RCore *core,
	ut64 dispatcher_addr,
	const CallCandidate *candidate,
	const std::string &leaf_name,
	ut64 disc)
{
	if (!core || !core->anal || !candidate || !candidate->op || leaf_name.empty()) {
		return;
	}
	const ut64 at = candidate->op->getSeqNum().getAddr().getOffset();
	if (!at) {
		return;
	}
	auto sanitize_label = [](const std::string &in) -> std::string {
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
			out = "ix";
		}
		return out;
	};
	if (dispatcher_addr != 0) {
		RAnalFunction *dispatcher = r_anal_get_fcn_in(core->anal, dispatcher_addr, R_ANAL_FCN_TYPE_NULL);
		if (dispatcher) {
			const std::string base = "case_" + sanitize_label(leaf_name);
			if (!r_anal_function_set_label(dispatcher, base.c_str(), at)) {
				std::ostringstream fallback;
				fallback << base << "_" << std::hex << at;
				r_anal_function_set_label(dispatcher, fallback.str().c_str(), at);
			}
		}
	}
	std::ostringstream comment;
	comment << "solana.anchor.call " << leaf_name << " disc=" << format_disc_hex(disc);
	const std::string call_cmt = comment.str();
	const char *existing = r_meta_get_string(core->anal, R_META_TYPE_COMMENT, at);
	if (existing && *existing) {
		if (strstr(existing, call_cmt.c_str())) {
			return;
		}
		std::string merged = existing;
		if (!merged.empty()) {
			merged += " | ";
		}
		merged += call_cmt;
		r_meta_set_string(core->anal, R_META_TYPE_COMMENT, at, merged.c_str());
		return;
	}
	r_meta_set_string(core->anal, R_META_TYPE_COMMENT, at, call_cmt.c_str());
}

static int infer_stable_call_arity(const std::vector<const CallCandidate *> &callsites) {
	if (callsites.empty()) {
		return -1;
	}
	int stable = -1;
	for (const CallCandidate *candidate : callsites) {
		if (!candidate || !candidate->op) {
			return -1;
		}
		const int4 nin = candidate->op->numInput();
		if (nin < 1) {
			return -1;
		}
		const int cur = static_cast<int>(nin - 1);
		if (cur < 0 || cur > 16) {
			return -1;
		}
		if (stable < 0) {
			stable = cur;
			continue;
		}
		if (stable != cur) {
			return -1;
		}
	}
	return stable;
}

static std::vector<CallCandidate> collect_internal_call_candidates(Funcdata *func, R2Architecture *arch) {
	std::vector<CallCandidate> out;
	if (!func || !arch) {
		return out;
	}
	const ut64 self_addr = func->getAddress().getOffset();
	for (auto it = func->beginOpAll(); it != func->endOpAll(); ++it) {
		const PcodeOp *op = it->second;
		if (!op || op->code() != CPUI_CALL) {
			continue;
		}
		ut64 target = 0;
		if (!resolve_sbpf_internal_call_target(arch, op, &target)) {
			continue;
		}
		if (target == self_addr) {
			continue;
		}
		const auto *bb = op->getParent();
		if (!bb) {
			continue;
		}
		CallCandidate c;
		c.op = op;
		c.target = target;
		c.block = bb;
		out.push_back(c);
	}
	return out;
}

static bool discriminator_complete(const std::array<int, kDiscriminatorLen> &bytes) {
	for (int b : bytes) {
		if (b < 0 || b > 0xff) {
			return false;
		}
	}
	return true;
}

static bool is_anchor_builtin_discriminator(ut64 disc) {
	switch (disc) {
	case 0x0a69e9a778bcf440ULL:
	case 0x40f4bc78a7e9690aULL:
	case 0x1d9acb512ea545e4ULL:
		return true;
	default:
		break;
	}
	return false;
}

} // namespace

void SolanaAnchorDispatcherAnalyzer::run(Funcdata *func, R2Architecture *arch, const std::string &idl_path) {
	if (!func || !arch) {
		return;
	}

	std::vector<CallCandidate> candidates = collect_internal_call_candidates(func, arch);
	if (candidates.size() < 8) {
		return;
	}

	std::unordered_map<ut64, std::string> disc_to_name;
	std::unordered_map<ut64, InstructionMetadata> disc_to_meta;
	add_builtin_anchor_mappings(disc_to_name);

	std::set<std::string> instruction_names;
	collect_instruction_mappings_from_idl(idl_path, disc_to_name, instruction_names, disc_to_meta);
	{
		RCoreLock core(arch->getCore());
		collect_instruction_names_from_binary(core, instruction_names);
	}
	for (const std::string &name : instruction_names) {
		add_name_mapping(disc_to_name, name);
	}

	const BlockGraph &graph = func->getBasicBlocks();
	std::map<ut64, std::vector<const CallCandidate *>> calls_by_target;
	for (const auto &candidate : candidates) {
		calls_by_target[candidate.target].push_back(&candidate);
	}

	std::unordered_map<ut64, ut64> target_to_disc;
	std::unordered_map<ut64, int> target_to_arity;
	std::unordered_set<ut64> unique_discs;
	bool has_anchor_builtin = false;
	for (const auto &it : calls_by_target) {
		const ut64 target = it.first;
		const auto &callsites = it.second;
		if (callsites.empty()) {
			continue;
		}
		bool has_incomplete = false;
		ut64 resolved_disc = 0;
		bool have_disc = false;
		for (const CallCandidate *candidate : callsites) {
			if (!candidate || !candidate->block) {
				has_incomplete = true;
				break;
			}
			std::array<int, kDiscriminatorLen> bytes;
			if (!collect_discriminator_for_call(graph, candidate->block, arch, bytes)
					|| !discriminator_complete(bytes)) {
				has_incomplete = true;
				break;
			}
			uint8_t raw[kDiscriminatorLen] = {0};
			for (size_t i = 0; i < kDiscriminatorLen; ++i) {
				raw[i] = static_cast<uint8_t>(bytes[i]);
			}
			const ut64 disc = read_le64(raw);
			if (!have_disc) {
				have_disc = true;
				resolved_disc = disc;
				continue;
			}
			if (resolved_disc != disc) {
				has_incomplete = true;
				break;
			}
		}
		if (!have_disc || has_incomplete) {
			continue;
		}
		target_to_disc.emplace(target, resolved_disc);
		const int arity = infer_stable_call_arity(callsites);
		if (arity >= 0) {
			target_to_arity.emplace(target, arity);
		}
		unique_discs.insert(resolved_disc);
		if (is_anchor_builtin_discriminator(resolved_disc)) {
			has_anchor_builtin = true;
		}
	}

	// Only apply automatic ix.* renames on high-confidence dispatcher functions.
	if (target_to_disc.size() < 8 || unique_discs.size() < 8) {
		return;
	}
	if (!has_anchor_builtin && unique_discs.size() < 12) {
		return;
	}
	if (target_to_disc.size() * 2 < calls_by_target.size()) {
		return;
	}

	RCoreLock core(arch->getCore());
	ut64 dispatcher_addr = func->getAddress().getOffset();
	if (core) {
		dispatcher_addr = core->addr;
	}
	rename_dispatcher_if_needed(core, dispatcher_addr);
	apply_dispatcher_comment(
		core,
		dispatcher_addr,
		target_to_disc.size(),
		calls_by_target.size(),
		unique_discs.size(),
		idl_path);
	for (const auto &it : target_to_disc) {
		const ut64 target = it.first;
		const ut64 disc = it.second;
		auto name_it = disc_to_name.find(disc);
		std::array<int, kDiscriminatorLen> disc_bytes;
		disc_bytes.fill(0);
		for (size_t i = 0; i < kDiscriminatorLen; ++i) {
			disc_bytes[i] = static_cast<int>((disc >> (8 * i)) & 0xff);
		}
		const std::string leaf_name = (name_it != disc_to_name.end())
			? name_it->second
			: format_disc_fallback(disc_bytes);
		rename_target_if_needed(core, target, leaf_name);
		auto meta_it = disc_to_meta.find(disc);
		const InstructionMetadata *meta = meta_it != disc_to_meta.end() ? &meta_it->second : nullptr;
		const auto arity_it = target_to_arity.find(target);
		const int arity = arity_it != target_to_arity.end() ? arity_it->second : -1;
		apply_ix_signature_and_comment(core, target, disc, leaf_name, meta, arity);
		auto calls_it = calls_by_target.find(target);
		if (calls_it != calls_by_target.end()) {
			for (const CallCandidate *candidate : calls_it->second) {
				apply_callsite_comment(core, dispatcher_addr, candidate, leaf_name, disc);
			}
		}
	}
}
