/* r2ghidra - LGPL - Copyright 2026 - pancake */

#ifndef R2GHIDRA_SOLANA_ANCHOR_DISPATCHER_ANALYZER_H
#define R2GHIDRA_SOLANA_ANCHOR_DISPATCHER_ANALYZER_H

#include <string>

namespace ghidra {
class Funcdata;
}

class R2Architecture;

class SolanaAnchorDispatcherAnalyzer {
public:
	static void run(ghidra::Funcdata *func, R2Architecture *arch, const std::string &idl_path);
};

#endif // R2GHIDRA_SOLANA_ANCHOR_DISPATCHER_ANALYZER_H
