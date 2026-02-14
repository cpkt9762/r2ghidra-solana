/* r2ghidra - LGPL - Copyright 2019-2025 - thestr4ng3r, pancake */

#include <architecture.hh>
#include <varnode.hh>

#include "R2PrintC.h"
#include "R2Architecture.h"
#include "SolanaCallResolver.h"


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

void R2PrintC::pushConstant(uintb val, const Datatype *ct, tagtype tag, const Varnode *vn, const PcodeOp *op) {
	auto *arch = dynamic_cast<R2Architecture *>(glb);
	if (arch && vn && vn->isConstant()) {
		const auto *hint = arch->findSolanaInputOffsetHint(vn->getCreateIndex());
		if (hint && hint->value == val && !hint->symbol.empty()) {
			pushAtom(Atom(hint->symbol, tag, EmitMarkup::const_color, op, vn, val));
			return;
		}
	}
	PrintC::pushConstant(val, ct, tag, vn, op);
}

string R2PrintC::resolveCurrentCallName(const PcodeOp *op) const {
	auto *arch = dynamic_cast<R2Architecture *>(glb);
	if (!arch) {
		return {};
	}
	return resolve_sbpf_call_name(arch, op);
}

void R2PrintC::opCall(const PcodeOp *op) {
	const PcodeOp *saved = current_call_op;
	current_call_op = op;
	try {
		auto *arch = dynamic_cast<R2Architecture *>(glb);
		const auto *hint = arch ? arch->findSolanaStringFromPtrLenHint(op->getAddr()) : nullptr;
		if (hint && hint->replace_slot > 0 && hint->replace_slot < op->numInput()) {
			const std::string call_name = resolveCurrentCallName(op);
			if (!call_name.empty()) {
				pushOp(&function_call, op);
				pushAtom(Atom(call_name, functoken, EmitMarkup::funcname_color, op, (const Funcdata *)0));
				const int4 count = op->numInput() - 1;
				if (count > 0) {
					for (int4 i = 0; i < count - 1; ++i) {
						pushOp(&comma, op);
					}
					for (int4 i = 1; i < op->numInput(); ++i) {
						if (i == hint->replace_slot) {
							pushAtom(Atom(hint->quoted, vartoken, EmitMarkup::const_color,
								op, op->getIn(i), hint->ptr_value));
						} else {
							pushVn(op->getIn(i), op, mods);
						}
					}
				} else {
					pushAtom(Atom(EMPTY_STRING, blanktoken, EmitMarkup::no_color));
				}
			} else {
				PrintC::opCall(op);
			}
		} else {
			PrintC::opCall(op);
		}
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
		if (current_call_op) {
			std::string resolved = resolveCurrentCallName(current_call_op);
			if (!resolved.empty()) {
				return resolved;
			}
		}
	}
	return PrintC::genericFunctionName(addr);
}
