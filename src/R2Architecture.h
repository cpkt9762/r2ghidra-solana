/* r2ghidra - LGPL - Copyright 2019-2023 - thestr4ng3r */

#ifndef R2GHIDRA_R2ARCHITECTURE_H
#define R2GHIDRA_R2ARCHITECTURE_H

#include "sleigh_arch.hh"
#include "architecture.hh"

#include "RCoreMutex.h"

#include <cstdint>

using namespace ghidra;

class R2TypeFactory;
typedef struct r_core_t RCore;

class R2Architecture : public SleighArchitecture {
private:
	RCoreMutex coreMutex;

public:
	struct SolanaStringFromPtrLenHint {
		std::string quoted;
		uintb ptr_value = 0;
		int4 replace_slot = 1;
	};

private:
	R2TypeFactory *r2TypeFactory_ = nullptr;
	std::map<std::string, VarnodeData> registers;
	std::vector<std::string> warnings;
	std::map<uint64_t, SolanaStringFromPtrLenHint> solanaStringFromPtrLenHints;

	bool rawptr = false;

	void loadRegisters(const Translate *translate);

public:
	explicit R2Architecture(RCore *core, const std::string &sleigh_id);

	RCoreMutex *getCore() { return &coreMutex; }

	R2TypeFactory *getTypeFactory() const { return r2TypeFactory_; }

	ProtoModel *protoModelFromR2CC(const char *cc);
	Address registerAddressFromR2Reg(const char *regname);
	void clearSolanaStringFromPtrLenHints();
	void setSolanaStringFromPtrLenHint(const Address &call_addr, const SolanaStringFromPtrLenHint &hint);
	const SolanaStringFromPtrLenHint *findSolanaStringFromPtrLenHint(const Address &call_addr) const;

	void addWarning(const std::string &warning)	{ warnings.push_back(warning); }
	const std::vector<std::string> getWarnings() const { return warnings; }
	ContextDatabase *getContextDatabase();
	static void collectSpecFiles(std::ostream &errs);
	static const std::vector<LanguageDescription> &getLanguageDescriptions();

	void setRawPtr(bool rawptr) { this->rawptr = rawptr; }

protected:
	Translate *buildTranslator(DocumentStorage &store) override;
	void buildLoader(DocumentStorage &store) override;
	Scope *buildDatabase(DocumentStorage &store) override;
	void buildTypegrp(DocumentStorage &store) override;
	void buildCoreTypes(DocumentStorage &store) override;
	void buildCommentDB(DocumentStorage &store) override;
	void postSpecFile() override;
	void buildAction(DocumentStorage &store) override;
};

#endif //R2GHIDRA_R2ARCHITECTURE_H
