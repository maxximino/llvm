#pragma once

#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include <llvm/Instruction.h>
#include <map>
#include <set>
#include <bitset>
#include <array>
#define MAX_KEYBITS 128
#define MAX_OUTBITS 128

using namespace std;
using namespace llvm;

namespace llvm
{
	void initializeTaggedDataPass(PassRegistry& Registry);
	namespace NoCryptoFA
	{
		struct InstructionMetadata;
		extern std::map<llvm::Instruction*, llvm::NoCryptoFA::InstructionMetadata*> known;
		struct StatisticInfo {
			int max;
			int min;
			int min_nonzero;
			int avg;
			int avg_nonzero;
			StatisticInfo() {
				max = 0;
				min = 0;
				min_nonzero = 0;
				avg = 0;
				avg_nonzero = 0;
			}
		};
		struct InstructionMetadata {
				enum InstructionSource {
				    ORIGINAL_PROGRAM,
				    CREATE_MASK,
				    XOR_MASKED,
				    AND_MASKED,
				    CAST_MASKED,
				    SHIFT_MASKED,
				    SBOX_MASKED,
				    SELECT_MASKED,
				    REMOVE_MASK,
				    MASKED_FUNCTION
				};
				bool isAKeyOperation;
				bool isAKeyStart;
                bool isPostKeyStart;
                bool isPostKeyOperation;
				bool isSbox;
                bool hasToBeProtected_pre;
                bool hasToBeProtected_post;
                bool post_FirstToMeetKey;
				bool hasBeenMasked;
				bool hasMetPlaintext;
				InstructionSource origin;
				std::vector<std::bitset<MAX_KEYBITS> > pre;
				std::bitset<MAX_KEYBITS> own;
                std::vector<std::bitset<MAX_OUTBITS> > post;
                std::bitset<MAX_OUTBITS> post_own;
				Instruction* my_instruction;
				Instruction* unmasked_value;
				std::vector<Value*> MaskedValues;
				StatisticInfo pre_stats;
                InstructionMetadata(Instruction* ptr): pre(0), own(0), post(0), post_own(0), MaskedValues(0), pre_stats() {
					init();
					my_instruction = ptr;
					known[ptr] = this;
				}
				InstructionMetadata() {
					init();
				}
				static llvm::NoCryptoFA::InstructionMetadata* getNewMD(llvm::Instruction* ptr) {
					llvm::NoCryptoFA::InstructionMetadata* md;
					if(NoCryptoFA::known.find(ptr) != NoCryptoFA::known.end()) {
						md = NoCryptoFA::known[ptr];
					} else {
						md = new llvm::NoCryptoFA::InstructionMetadata(ptr);
					}
					return md;
				}
			private:
				void init() {
					origin = InstructionMetadata::ORIGINAL_PROGRAM;
					unmasked_value = NULL;
					isAKeyOperation = false;
					isAKeyStart = false;
					isSbox = false;
                    hasToBeProtected_pre = false;
                    hasToBeProtected_post = false;
					hasBeenMasked = false;
					hasMetPlaintext = false;
                    post_FirstToMeetKey=false;
                    post_own.reset();
                    own.reset();
                }

		};

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
			virtual void markFunction(llvm::Function* ptr);
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
			void infectSbox(llvm::Instruction* ptr);
			bool hasmd;
	};
	TaggedData* createTaggedDataPass();


}



