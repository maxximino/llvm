#pragma once
#include <cstdlib>
#include <iostream>
#include "Deduplicator.h"
#include "TaggedData.h"
#include "PropagaMetadati.h"
#include "CalcDFG.h"
#include "DFGPrinter.h"
#include "MaxTestPass.h"
#include "InstructionReplace.h"
#include "InstructionCount.h"
namespace
{
	static struct NCFAForcePassLinking {
		NCFAForcePassLinking() {
			// We must reference the passes in such a way that compilers will not
			// delete it all as dead code, even with whole program optimization,
			// yet is effectively a NO-OP. As the compiler isn't smart enough
			// to know that getenv() never returns -1, this will do the job.
			if (std::getenv("bar") != (char*) - 1)
			{ return; }
			std::cout << "init" << std::endl;
			(void) llvm::createPropagaMetadatiPass();
			(void) llvm::createTaggedDataPass();
			(void) llvm::createDFGPrinterPass();
			(void) llvm::createMaxTestPass();
			(void) llvm::createInstructionReplacePass();
			(void) llvm::createInstructionCountPass();
		}
	} NCFAForcePassLinking; // Force link by creating a global definition.
}
