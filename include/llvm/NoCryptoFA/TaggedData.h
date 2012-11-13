#pragma once

#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include <llvm/Instruction.h>
#include <map>
#include <set>
#include <bitset>
#include <array>
#define MAX_KEYBITS 128
#define MAX_OUTBITS 256

using namespace std;
using namespace llvm;

namespace llvm
{
	void initializeTaggedDataPass(PassRegistry& Registry);
	namespace NoCryptoFA
	{
		struct InstructionMetadata {
			bool isAKeyOperation;
			bool isAKeyStart;
            bool hasToBeProtected;
            bool hasMetPlaintext;
			std::vector<std::bitset<MAX_KEYBITS> > pre;
			std::bitset<MAX_KEYBITS> own;
			std::bitset<MAX_OUTBITS> post_sum;
			std::bitset<MAX_OUTBITS> post_min;
			Instruction* my_instruction;
			InstructionMetadata(Instruction* ptr): pre(0), own(0), post_sum(0), post_min(0) {
				isAKeyOperation = false;
				isAKeyStart = false;
                hasToBeProtected = false;
                hasMetPlaintext = false;
				post_sum.reset();
				post_min.set();
				my_instruction = ptr;
			}
		};
		extern std::map<llvm::Instruction*, llvm::NoCryptoFA::InstructionMetadata*> known;
	}


	class TaggedData : public llvm::FunctionPass
	{
		public:
			static char ID;
			TaggedData() : llvm::FunctionPass(ID) { }
            TaggedData(const TaggedData& fp) : llvm::FunctionPass(fp.ID) {
                initializeTaggedDataPass(*PassRegistry::getPassRegistry());

            }
			virtual NoCryptoFA::InstructionMetadata* getMD(llvm::Instruction* ptr);

			virtual bool runOnFunction(llvm::Function& Fun);
			virtual bool isMarkedAsKey(llvm::Instruction* ptr);
			virtual bool isMarkedAsStatus(llvm::Instruction* ptr);
			virtual void getAnalysisUsage(llvm::AnalysisUsage& AU) const;
			virtual const char* getPassName() const {
				return "TaggedData";
			}
			bool functionMarked(Function* ptr);

		private:
			// This is the information computed by the analysis.

			std::set<Function*> markedfunctions;
			void checkMeta(llvm::Instruction* ptr);
			void infect(llvm::Instruction* ptr);
            void infectPlain(llvm::Instruction* ptr);
			bool hasmd;
	};
	TaggedData* createTaggedDataPass();


}



