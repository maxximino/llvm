#pragma once
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include <llvm/Instruction.h>
#include <map>
using namespace std;
using namespace llvm;

namespace llvm
{
    void initializeInstructionCountPass(PassRegistry& Registry);


    class InstructionCount : public llvm::ModulePass
	{
		public:
			static char ID;
            InstructionCount() : llvm::ModulePass(ID) { }
            InstructionCount(const InstructionCount& fp) : llvm::ModulePass(fp.ID) {
                initializeInstructionCountPass(*PassRegistry::getPassRegistry());
			}

            virtual bool runOnModule(llvm::Module& M);
			virtual void getAnalysisUsage(llvm::AnalysisUsage& AU) const;
            virtual void print(raw_ostream& OS, const Module*) const;

			virtual const char* getPassName() const {
                return "InstructionCount";
			}
        private:
            map<const Function*,unsigned long> functions;

	};
    InstructionCount* createInstructionCountPass();


}



