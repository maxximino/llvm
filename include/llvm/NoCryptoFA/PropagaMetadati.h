#pragma once
#include <llvm/Transforms/IPO/PassManagerBuilder.h>

namespace llvm
{
	void initializePropagaMetadatiPass(PassRegistry& Registry);

	class PropagaMetadati : public llvm::FunctionPass
	{
		public:
			static char ID;

		public:
			PropagaMetadati() : llvm::FunctionPass(ID) { }

		public:
			// This member function must implement the code of your pass.
			virtual bool runOnFunction(llvm::Function& F);

			// The getAnalysisUsage allows to tell LLVM pass manager which analysis are
			// used by the pass. It is also used to declare which analysis are preserved
			// by the pass.
			virtual void getAnalysisUsage(llvm::AnalysisUsage& AU) const;

			virtual const char* getPassName() const {
				return "PropagaMetadati";
			}
			static void registerPass(PassManagerBuilder& pm);
		private:
			//          Instruction* makeFaultable(Instruction* ptr);
			//          void fixNextUses(Value* from, Value* to);
			//          Instruction* inquina(Instruction* stato, Instruction* shouldbezero);
	};
	PropagaMetadati* createPropagaMetadatiPass();
} // End llvm namespace.
