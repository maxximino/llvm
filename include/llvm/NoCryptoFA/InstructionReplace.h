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

            InstructionReplace() : llvm::ModulePass(ID),deletionqueue() {
                initializeInstructionReplacePass(*PassRegistry::getPassRegistry());

            }

            virtual bool runOnModule(llvm::Module& M);

			virtual void getAnalysisUsage(llvm::AnalysisUsage& AU) const;

			virtual const char* getPassName() const {
                return "InstructionReplace";
			}

		private:
            std::set<Instruction*> deletionqueue;
            void fixNextUses(Value* from, Value* to);
            void phase1(llvm::Module& M);
            void phase2(llvm::Module& M);
            void phase3(llvm::Module& M);
            void Unmask(Instruction* ptr);

	};

    InstructionReplace* createInstructionReplacePass();

}
