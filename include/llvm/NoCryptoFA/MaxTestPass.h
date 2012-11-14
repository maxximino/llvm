#pragma once
#include <llvm/Pass.h>
#include "llvm/Function.h"
namespace llvm
{
	void initializeMaxTestPassPass(PassRegistry& Registry);
	class MaxTestPass : public llvm::FunctionPass
	{
		public:
			static char ID;

		public:
			MaxTestPass() : llvm::FunctionPass(ID) {
				initializeMaxTestPassPass(*PassRegistry::getPassRegistry());
			}

		public:
			// This member function must implement the code of your pass.
			virtual bool runOnFunction(llvm::Function& F);

			// The getAnalysisUsage allows to tell LLVM pass manager which analysis are
			// used by the pass. It is also used to declare which analysis are preserved
			// by the pass.
			virtual void getAnalysisUsage(llvm::AnalysisUsage& AU) const;

			virtual const char* getPassName() const {
				return "MaxTestPass";
			}

		private:
			Instruction* makeFaultable(Instruction* ptr);
			void fixNextUses(Value* from, Value* to);
			Instruction* inquina(Instruction* stato, Instruction* shouldbezero);
	};

	MaxTestPass* createMaxTestPass();

}
