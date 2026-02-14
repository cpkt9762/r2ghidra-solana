/* r2ghidra - LGPL - Copyright 2026 - pancake */

#ifndef R2GHIDRA_SOLANA_STRING_FROM_PTR_LEN_ANALYZER_H
#define R2GHIDRA_SOLANA_STRING_FROM_PTR_LEN_ANALYZER_H

namespace ghidra {
class Funcdata;
}

class R2Architecture;

class SolanaStringFromPtrLenAnalyzer {
public:
	static void run(ghidra::Funcdata *func, R2Architecture *arch);
};

#endif // R2GHIDRA_SOLANA_STRING_FROM_PTR_LEN_ANALYZER_H
