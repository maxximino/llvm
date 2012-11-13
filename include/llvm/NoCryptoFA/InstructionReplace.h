#pragma once
#include <llvm/Pass.h>
#include "llvm/Module.h"
namespace llvm
{
    void initializeInstructionReplacePass(PassRegistry& Registry);
class InstructionReplace : public llvm::ModulePass
	{
		public:
			static char ID;

            InstructionReplace() : llvm::ModulePass(ID) {
                initializeInstructionReplacePass(*PassRegistry::getPassRegistry());

            }

            virtual bool runOnModule(llvm::Module& M);

			virtual void getAnalysisUsage(llvm::AnalysisUsage& AU) const;

			virtual const char* getPassName() const {
                return "InstructionReplace";
			}

		private:
            void fixNextUses(Value* from, Value* to);
	};

    InstructionReplace* createInstructionReplacePass();

}
