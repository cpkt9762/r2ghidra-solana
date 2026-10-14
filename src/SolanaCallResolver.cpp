/* r2ghidra - LGPL - Copyright 2026 - pancake */

#include "SolanaCallResolver.h"

#include "R2Architecture.h"
#include "RCoreMutex.h"

#include <funcdata.hh>
#include <varnode.hh>

using namespace ghidra;

static uint32_t read_le32(const ut8 *p) {
	return static_cast<uint32_t>(p[0])
		| (static_cast<uint32_t>(p[1]) << 8)
		| (static_cast<uint32_t>(p[2]) << 16)
		| (static_cast<uint32_t>(p[3]) << 24);
}

static struct {
	uint32_t hash;
	const char *name;
} sbpf_syscall_hashes[] = {
	{0xb6fc1a11U, "abort"},
	{0x686093bbU, "sol_panic_"},
	{0x207559bdU, "sol_log_"},
	{0x5c2a3178U, "sol_log_64_"},
	{0x52ba5096U, "sol_log_compute_units_"},
	{0x7ef088caU, "sol_log_pubkey"},
	{0x7317b434U, "sol_log_data"},
	{0x9377323cU, "sol_create_program_address"},
	{0x48504a38U, "sol_try_find_program_address"},
	{0x11f49d86U, "sol_sha256"},
	{0xd7793abbU, "sol_keccak256"},
	{0x174c5122U, "sol_blake3"},
	{0xc4947c21U, "sol_poseidon"},
	{0x17e40350U, "sol_secp256k1_recover"},
	{0xaa2607caU, "sol_curve_validate_point"},
	{0xdd1c41a6U, "sol_curve_group_op"},
	{0x60a40880U, "sol_curve_multiscalar_mul"},
	{0xf111a47eU, "sol_curve_pairing_map"},
	{0x080c98b0U, "sol_curve_decompress"},
	{0xae0c318bU, "sol_alt_bn128_group_op"},
	{0x334fd5edU, "sol_alt_bn128_compression"},
	{0x780e4c15U, "sol_big_mod_exp"},
	{0xd56b5fe9U, "sol_get_clock_sysvar"},
	{0x23a29a61U, "sol_get_epoch_schedule_sysvar"},
	{0xbf7188f6U, "sol_get_rent_sysvar"},
	{0x3b97b73cU, "sol_get_fees_sysvar"},
	{0xfdba2b3bU, "sol_get_epoch_rewards_sysvar"},
	{0x188a0031U, "sol_get_last_restart_slot"},
	{0x13c1b505U, "sol_get_sysvar"},
	{0x5be92f4aU, "sol_get_epoch_stake"},
	{0x717cc4a3U, "sol_memcpy_"},
	{0x434371f8U, "sol_memmove_"},
	{0x5fdcde31U, "sol_memcmp_"},
	{0x3770fb22U, "sol_memset_"},
	{0x83f00e8fU, "sol_alloc_free_"},
	{0xa22b9c85U, "sol_invoke_signed_c"},
	{0xd7449092U, "sol_invoke_signed_rust"},
	{0xa226d3ebU, "sol_set_return_data"},
	{0x5d2245e4U, "sol_get_return_data"},
	{0xadb8efc8U, "sol_get_processed_sibling_instruction"},
	{0x85532d94U, "sol_get_stack_height"},
	{0xedef5aeeU, "sol_remaining_compute_units"},
	{0, nullptr}
};

const char *get_sbpf_syscall_name(uint64_t addr) {
	const uint32_t hash = static_cast<uint32_t>(addr);
	for (int i = 0; sbpf_syscall_hashes[i].name; i++) {
		if (sbpf_syscall_hashes[i].hash == hash) {
			return sbpf_syscall_hashes[i].name;
		}
	}
	return nullptr;
}

static const char *extract_sbpf_import_name(const char *flag_name) {
	if (r_str_startswith (flag_name, "reloc.")) {
		return flag_name + 6;
	}
	if (r_str_startswith (flag_name, "loc.imp.")) {
		return flag_name + 8;
	}
	if (r_str_startswith (flag_name, "sym.imp.")) {
		return flag_name + 8;
	}
	if (r_str_startswith (flag_name, "imp.")) {
		return flag_name + 4;
	}
	if (r_str_startswith (flag_name, "sol_") || !strcmp (flag_name, "abort")) {
		return flag_name;
	}
	return nullptr;
}

static bool is_sbpf_syscall_name(const char *name) {
	return name
		&& (r_str_startswith (name, "sol_") || !strcmp (name, "abort"));
}

static std::string resolve_sbpf_call_name_from_flags(R2Architecture *arch, const Address &call_addr) {
	RCoreLock core (arch->getCore ());
	const RList *flags = r_flag_get_list (core->flags, call_addr.getOffset ());
	if (!flags) {
		return {};
	}
	RListIter *iter;
	void *pos;
	r_list_foreach (flags, iter, pos) {
		auto flag = reinterpret_cast<RFlagItem *>(pos);
		if (!flag || !flag->name) {
			continue;
		}
		const char *name = extract_sbpf_import_name (flag->name);
		if (is_sbpf_syscall_name (name)) {
			return std::string (name);
		}
	}
	return {};
}

static std::string resolve_sbpf_call_name_from_reloc(R2Architecture *arch, const Address &call_addr) {
	RCoreLock core (arch->getCore ());
	RRBTree *relocs = r_bin_get_relocs (core->bin);
	if (!relocs) {
		return {};
	}
	RRBNode *node;
	RBinReloc *reloc;
	r_crbtree_foreach (relocs, node, RBinReloc, reloc) {
		if (!reloc) {
			continue;
		}
		if (reloc->vaddr != call_addr.getOffset () && reloc->paddr != call_addr.getOffset ()) {
			continue;
		}
		const char *name = nullptr;
		if (reloc->import && reloc->import->name) {
			name = r_bin_name_tostring (reloc->import->name);
		} else if (reloc->symbol && reloc->symbol->name) {
			name = r_bin_name_tostring (reloc->symbol->name);
		}
		if (is_sbpf_syscall_name (name)) {
			return std::string (name);
		}
	}
	return {};
}

static bool is_executable_target(RCore *core, ut64 addr) {
	if (!core || !core->bin) {
		return false;
	}
	const RList *sections = r_bin_get_sections (core->bin);
	if (!sections) {
		return false;
	}
	RListIter *iter;
	void *pos;
	r_list_foreach (sections, iter, pos) {
		auto *sec = reinterpret_cast<RBinSection *>(pos);
		if (!sec) {
			continue;
		}
		ut64 start = sec->vaddr ? sec->vaddr : sec->paddr;
		ut64 size = sec->vsize ? sec->vsize : sec->size;
		if (size == 0) {
			continue;
		}
		if (!(sec->perm & R_PERM_X)) {
			continue;
		}
		if (addr >= start && addr < start + size) {
			return true;
		}
	}
	return false;
}

static bool should_force_function_analysis(RAnalFunction *fcn) {
	if (!fcn) {
		return true;
	}
	return r_anal_function_realsize (fcn) == 0;
}

static RAnalFunction *materialize_function_at_target(RCore *core, ut64 target) {
	if (!core || !core->anal || !is_executable_target (core, target)) {
		return nullptr;
	}
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, target, R_ANAL_FCN_TYPE_NULL);
	if (should_force_function_analysis (fcn)) {
		r_core_anal_fcn (core, target, target, R_ANAL_REF_TYPE_CALL, 1);
		fcn = r_anal_get_fcn_in (core->anal, target, R_ANAL_FCN_TYPE_NULL);
	}
	if (!fcn) {
		r_anal_create_function (core->anal, nullptr, target, R_ANAL_FCN_TYPE_FCN, nullptr);
		fcn = r_anal_get_fcn_in (core->anal, target, R_ANAL_FCN_TYPE_NULL);
		if (should_force_function_analysis (fcn)) {
			r_core_anal_fcn (core, target, target, R_ANAL_REF_TYPE_CALL, 1);
			fcn = r_anal_get_fcn_in (core->anal, target, R_ANAL_FCN_TYPE_NULL);
		}
	}
	return fcn;
}

static std::string name_for_target_or_autocreate(RCore *core, ut64 target) {
	RAnalFunction *fcn = materialize_function_at_target (core, target);
	if (fcn && fcn->name) {
		return std::string (fcn->name);
	}
	const RList *flags = r_flag_get_list (core->flags, target);
	if (flags) {
		RListIter *iter;
		void *pos;
		r_list_foreach (flags, iter, pos) {
			auto flag = reinterpret_cast<RFlagItem *>(pos);
			if (flag && flag->name) {
				return std::string (flag->name);
			}
		}
	}
	return {};
}

enum class SbpfCallImm {
	Ok,
	NotCall,
	ReadFailed,
};

static SbpfCallImm read_sbpf_call_imm32(RCore *core, ut64 call_addr, uint32_t *imm) {
	if (!core || !core->io || !imm) {
		return SbpfCallImm::ReadFailed;
	}
	ut8 bytes[8] = {0};
	// r_io_read_at() returns bool, not the number of bytes read
	if (!r_io_read_at (core->io, call_addr, bytes, sizeof (bytes))) {
		return SbpfCallImm::ReadFailed;
	}
	if (bytes[0] != 0x85) {
		return SbpfCallImm::NotCall;
	}
	*imm = read_le32 (bytes + 4);
	return SbpfCallImm::Ok;
}

// The internal call target comes from the imm32 of the instruction itself. The pcode target is not used:
// it is only a copy of imm in the sleigh syscall space and says nothing when the bytes cannot be read.
static bool compute_sbpf_internal_call_target(
	RCore *core,
	const Address &call_addr,
	ut64 *out_target)
{
	uint32_t imm32 = 0;
	switch (read_sbpf_call_imm32 (core, call_addr.getOffset (), &imm32)) {
	case SbpfCallImm::Ok:
		break;
	case SbpfCallImm::NotCall:
		// not a plain `call imm` (for example the v3 syscall opcode): there is no internal target
		return false;
	case SbpfCallImm::ReadFailed:
		R_LOG_WARN ("Cannot read the call instruction at 0x%08" PFMT64x ", no internal call target is derived", call_addr.getOffset ());
		return false;
	}
	// Real Solana syscall hashes are encoded in imm32. If matched, this is not an internal call.
	if (get_sbpf_syscall_name (imm32)) {
		return false;
	}
	const int64_t call_base = static_cast<int64_t> (call_addr.getOffset () + 8);
	const int64_t target_signed = call_base + static_cast<int64_t> (static_cast<int32_t> (imm32)) * 8;
	if (target_signed < 0) {
		return false;
	}
	const ut64 target = static_cast<ut64> (target_signed);
	if (!is_executable_target (core, target)) {
		return false;
	}
	*out_target = target;
	return true;
}

static bool resolve_sbpf_internal_call_target_at(
	R2Architecture *arch,
	const Address &call_addr,
	ut64 *out_target)
{
	if (!arch || !out_target) {
		return false;
	}
	RCoreLock core (arch->getCore ());
	ut64 target = 0;
	if (!compute_sbpf_internal_call_target (core, call_addr, &target)) {
		return false;
	}
	materialize_function_at_target (core, target);
	*out_target = target;
	return true;
}

static std::string resolve_sbpf_internal_call_name(
	R2Architecture *arch,
	const Address &call_addr)
{
	ut64 target = 0;
	if (!resolve_sbpf_internal_call_target_at (arch, call_addr, &target)) {
		return {};
	}
	RCoreLock core (arch->getCore ());
	return name_for_target_or_autocreate (core, target);
}

bool resolve_sbpf_internal_call_target(
	R2Architecture *arch,
	const PcodeOp *op,
	uint64_t *out_target)
{
	if (!arch || !op || !out_target) {
		return false;
	}
	if (op->code () != CPUI_CALL || op->numInput () < 1) {
		return false;
	}
	const Varnode *target = op->getIn (0);
	if (!target) {
		return false;
	}
	if (target->getSpace () && target->getSpace ()->getType () == IPTR_FSPEC) {
		FuncCallSpecs *fc = FuncCallSpecs::getFspecFromConst (target->getAddr ());
		if (!fc) {
			return false;
		}
		const Address entry = fc->getEntryAddress ();
		if (entry.getSpace () && entry.getSpace ()->getName () == "syscall") {
			return resolve_sbpf_internal_call_target_at (arch, op->getAddr (), out_target);
		}
		RCoreLock core (arch->getCore ());
		if (!entry.isInvalid () && is_executable_target (core, entry.getOffset ())) {
			*out_target = entry.getOffset ();
			materialize_function_at_target (core, *out_target);
			return true;
		}
		return false;
	}
	if (!target->isConstant ()) {
		return false;
	}
	return resolve_sbpf_internal_call_target_at (arch, op->getAddr (), out_target);
}

std::string resolve_sbpf_call_name(R2Architecture *arch, const PcodeOp *op) {
	if (!arch || !op || op->numInput() < 1) {
		return {};
	}

	const Varnode *target = op->getIn(0);
	if (target && target->getSpace() && target->getSpace()->getName() == "syscall") {
		const char *name = get_sbpf_syscall_name(target->getOffset());
		if (name) {
			return std::string(name);
		}
	}
	if (target && target->getSpace() && target->getSpace()->getType() == IPTR_FSPEC) {
		FuncCallSpecs *fc = FuncCallSpecs::getFspecFromConst(target->getAddr());
		if (fc) {
			if (!fc->getName().empty()) {
				// Ghidra auto-generated placeholders like func_0x... should not
				// block Solana-specific resolution paths.
				if (!r_str_startswith (fc->getName().c_str (), "func_0x")) {
					return fc->getName();
				}
			}
			const Address entry = fc->getEntryAddress();
			if (entry.getSpace() && entry.getSpace()->getName() == "syscall") {
				const char *name = get_sbpf_syscall_name(entry.getOffset());
				if (name) {
					return std::string(name);
				}
				std::string internal = resolve_sbpf_internal_call_name(arch, op->getAddr());
				if (!internal.empty()) {
					return internal;
				}
			}
		}
	}

	if (target && target->isConstant()) {
		Address target_addr(target->getSpace(), target->getOffset());
		if (target_addr.getSpace() && target_addr.getSpace()->getName() == "syscall") {
			const char *name = get_sbpf_syscall_name(target_addr.getOffset());
			if (name) {
				return std::string(name);
			}
		}
	}

	const Address call_addr = op->getAddr();
	std::string from_flags = resolve_sbpf_call_name_from_flags(arch, call_addr);
	if (!from_flags.empty()) {
		return from_flags;
	}
	std::string from_reloc = resolve_sbpf_call_name_from_reloc(arch, call_addr);
	if (!from_reloc.empty()) {
		return from_reloc;
	}
	if (target && target->isConstant()) {
		std::string internal = resolve_sbpf_internal_call_name(arch, call_addr);
		if (!internal.empty()) {
			return internal;
		}
	}
	return {};
}
