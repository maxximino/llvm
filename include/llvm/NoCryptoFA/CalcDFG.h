#pragma once
#include "TaggedData.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include <llvm/Instruction.h>
#include <map>
#include <list>
#include <set>
#include <bitset>

using namespace llvm;

namespace llvm
{
	void initializeCalcDFGPass(PassRegistry& Registry);
	namespace NoCryptoFA
	{
		struct KeyStartInfo {
			public:
				llvm::Value* ptr;
				long index;
				KeyStartInfo(llvm::Value* _ptr, long _idx) {
					ptr = _ptr;
					index = _idx;
				}
				KeyStartInfo(llvm::Value* _ptr) {
					ptr = _ptr;
					index = -1;
				}
				KeyStartInfo() {
					index = -1;
					ptr = NULL;
				}
				friend bool operator== (const KeyStartInfo& a, const KeyStartInfo& b);
				friend bool operator< (const KeyStartInfo& a, const KeyStartInfo& b);
		};
		inline bool operator== (const NoCryptoFA::KeyStartInfo& a, const NoCryptoFA::KeyStartInfo& b)
		{
			return a.index == b.index && a.ptr == b.ptr;
		}
		inline bool operator< (const NoCryptoFA::KeyStartInfo& a, const NoCryptoFA::KeyStartInfo& b)
		{
			if(a.ptr != b.ptr) {
				return a.ptr < b.ptr;
			} else {
				return a.index < b.index;
			}
		}



	}


	class CalcDFG : public llvm::FunctionPass
	{
		public:
			static char ID;
			CalcDFG() : llvm::FunctionPass(ID) { }
			CalcDFG(const CalcDFG& fp) : llvm::FunctionPass(fp.ID) {
				initializeCalcDFGPass(*PassRegistry::getPassRegistry());
			}

			virtual bool runOnFunction(llvm::Function& Fun);
			virtual NoCryptoFA::InstructionMetadata* getMD(llvm::Instruction* ptr);
			virtual void getAnalysisUsage(llvm::AnalysisUsage& AU) const;
			virtual const char* getPassName() const {
				return "CalcDFG";
			}
			bool shouldBeProtected(Instruction* ptr);
			bool functionMarked(Function* ptr);
			void setAsTransformed(Function* ptr) {
				alreadyTransformed.insert(ptr);
			}
            static unsigned int getOperandSize(llvm::Instruction* ptr);
            static unsigned int getOperandSize(llvm::Type* t);
            unsigned int getMSBEverSet();
		private:
			// This is the information computed by the analysis.
			std::map<llvm::Instruction*, std::bitset<MAX_KEYBITS> > instr_bs;
			std::map<NoCryptoFA::KeyStartInfo, std::bitset<MAX_KEYBITS> > GEPs;
            unsigned int keyLatestPos;
            unsigned int MSBEverSet;
			std::set<Function*> alreadyTransformed;
			std::set<Instruction*> toBeVisited;
            std::set<Instruction*> cipherOutPoints;
            std::multimap<int,Instruction*> candidateVulnerablePointsCT;
            std::multimap<int,Instruction*> candidateVulnerablePointsPT;
            void runBatched(set<Instruction*> initialSet, std::function<bool(Instruction*,long batchn)> func );
            void calcKeydep(llvm::Instruction* ptr);
            void searchCipherOutPoints(llvm::Instruction* ptr);
            //bool lookForBackwardsKeyPoints(llvm::Instruction* ptr);
            void lookForMostVulnerableInstructionRepresentingTheEntireUserKey(list<pair<int,Instruction*> >& sorted,set<Instruction*>* most_vulnerable_instructions,bool NoCryptoFA::InstructionMetadata::* marker);
            void calcPost(llvm::Instruction* ptr);
            void calcPre(llvm::Instruction* ptr);
            void fillCiphertextHeight(llvm::Instruction* ptr,int batchn);
            bitset<MAX_SUBBITS> getOutBitset(llvm::Instruction* ptr,unsigned int& latestPos);
			bitset<MAX_KEYBITS> getOwnBitset(llvm::Instruction* ptr);
            void assignKeyOwn(set<Instruction*> instructions,bitset<MAX_SUBBITS> NoCryptoFA::InstructionMetadata::*OWN);


	};
	CalcDFG* createCalcDFGPass();


}


