/* r2ghidra - LGPL - Copyright 2019-2025 - thestr4ng3r, pancake */

#include <architecture.hh>
#include <varnode.hh>

#include "R2PrintC.h"
#include "R2Architecture.h"
#include "RCoreMutex.h"


using namespace ghidra;

// Constructing this registers the capability
R2PrintCCapability R2PrintCCapability::inst;

R2PrintCCapability::R2PrintCCapability(void) {
	name = "r2-c-language";
	isdefault = false;
}

PrintLanguage *R2PrintCCapability::buildLanguage(Architecture *glb) {
	return new R2PrintC (glb, name);
}

R2PrintC::R2PrintC(Architecture *g, const string &nm) : PrintC(g, nm) {
 	option_NULL = true;
	// unplaced option is necessary to show the inline ::user2 comments defined from radare2
	option_unplaced = false;
//	option_space_after_comma = true;
// 	option_nocasts = true;
///  option_convention = true;
///  option_hide_exts = true;
///  option_inplace_ops = false;
///  option_nocasts = false;
///  option_NULL = false;
///  option_space_after_comma = false;
///  option_newline_before_else = true;
///  option_newline_before_opening_brace = false;
///  option_newline_after_prototype = true;
// Default r2ghidra C printer options:
#if 0
	setNULLPrinting(true);                             // print NULL keyword for null pointers
	setNoCastPrinting(false);                          // show C casts by default
	setInplaceOps(false);                              // disable in-place operators (+=, *=, etc.)
	setConvention(true);                               // include calling convention in function prototypes
	setHideImpliedExts(true);                          // hide implied zero/sign extensions (ZEXT/SEXT)
	setCStyleComments();                               // use C-style /* */ comments
	setMaxLineSize(80);                                // wrap lines at 80 characters
	setIndentIncrement(2);                             // indent 2 spaces per nested block
	setLineCommentIndent(0);                           // align line comments with code
	setCommentStyle("c");                            // use traditional C comment style
	setBraceFormatFunction(Emit::skip_line);           // function opening brace on a separate line
	setBraceFormatIfElse(Emit::same_line);             // if/else opening brace on same line
	setBraceFormatLoop(Emit::same_line);               // loop opening brace on same line
	setBraceFormatSwitch(Emit::same_line);             // switch opening brace on same line
	setNamespaceStrategy(PrintLanguage::MINIMAL_NAMESPACES); // minimal namespace qualifiers
#endif
}

void R2PrintC::setOptionNoCasts(bool nc) {
	option_nocasts = nc;
}

#if 0
void R2PrintC::opCast(const PcodeOp *op)
{
	// do nothing
fprintf (stderr, "opCast%c", 10);
}
#endif

void R2PrintC::pushUnnamedLocation(const Address &addr, const Varnode *vn, const PcodeOp *op) {
//	option_nocasts = true;
	// print (*(type *)0x0000...) instead of ram00000...
	AddrSpace *space = addr.getSpace ();
	if (space->getType() == IPTR_PROCESSOR) {
		pushOp (&dereference, op);
		auto type = glb->types->getTypePointer (space->getAddrSize (), vn->getType (), space->getWordSize ());
		// pushConstant (addr.getOffset (), type, vn, op);
		pushConstant(addr.getOffset(),type,vartoken,vn, op);
	} else {
		PrintC::pushUnnamedLocation (addr,vn, op);
	}
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

static const char *get_sbpf_syscall_name(uint64_t addr) {
	uint32_t hash = (uint32_t)addr;
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

static std::string resolve_sbpf_internal_call_name(R2Architecture *arch, const Address &call_addr, uint64_t imm) {
	const int64_t rel = static_cast<int64_t> (static_cast<int32_t> (imm));
	const ut64 target = call_addr.getOffset () + 8 + (rel * 8);
	RCoreLock core (arch->getCore ());
	RAnalFunction *fcn = r_anal_get_function_at (core->anal, target);
	if (fcn && fcn->name) {
		return std::string (fcn->name);
	}
	const RList *flags = r_flag_get_list (core->flags, target);
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
		return std::string (flag->name);
	}
	return {};
}

void R2PrintC::opCall(const PcodeOp *op) {
	const PcodeOp *saved = current_call_op;
	current_call_op = op;
	try {
		PrintC::opCall (op);
	} catch (...) {
		current_call_op = saved;
		throw;
	}
	current_call_op = saved;
}

string R2PrintC::genericFunctionName(const Address &addr) {
	if (addr.getSpace()->getName() == "syscall") {
		const char *name = get_sbpf_syscall_name(addr.getOffset());
		if (name) {
			return string(name);
		}
		auto *arch = dynamic_cast<R2Architecture *>(glb);
		if (arch && current_call_op) {
			const Address call_addr = current_call_op->getAddr ();
			std::string from_flags = resolve_sbpf_call_name_from_flags (arch, call_addr);
			if (!from_flags.empty ()) {
				return from_flags;
			}
			std::string from_reloc = resolve_sbpf_call_name_from_reloc (arch, call_addr);
			if (!from_reloc.empty ()) {
				return from_reloc;
			}
			std::string internal = resolve_sbpf_internal_call_name (arch, call_addr, addr.getOffset ());
			if (!internal.empty ()) {
				return internal;
			}
		}
	}
	return PrintC::genericFunctionName(addr);
}
