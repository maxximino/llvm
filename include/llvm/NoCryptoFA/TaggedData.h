#pragma once

#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include <llvm/Instruction.h>
#include <map>
#include <set>
#include <bitset>
#define MAX_KEYBITS 4096
using namespace std;
using namespace llvm;
namespace llvm
{
	void initializeTaggedDataPass(PassRegistry& Registry);
	namespace NoCryptoFA{
	  struct InstructionMetadata{
        bool isAKeyOperation;
        bool isAKeyStart;
        bool preCalc;
        std::bitset<MAX_KEYBITS> pre;
        std::bitset<MAX_KEYBITS> own;
         std::bitset<MAX_KEYBITS> post_sum;
         std::bitset<MAX_KEYBITS> post_min;
         InstructionMetadata():pre(0),own(0),post_sum(0),post_min(0){
          isAKeyOperation=false;
          isAKeyStart = false;
          preCalc=false;
	    }
	  };
	      
	      
	}
	
	
        class TaggedData : public llvm::FunctionPass
        {
                public:
                        static char ID;
                        TaggedData() : llvm::FunctionPass(ID),
                                known() { }
                        TaggedData(const TaggedData& fp) : llvm::FunctionPass(fp.ID),
                                known(fp.known){ }

                        virtual bool runOnFunction(llvm::Function& Fun);
                        virtual bool isMarkedAsKey(llvm::Instruction* ptr);
                        virtual bool isMarkedAsStatus(llvm::Instruction* ptr);
            virtual NoCryptoFA::InstructionMetadata* getMD(llvm::Instruction* ptr);
                        virtual void getAnalysisUsage(llvm::AnalysisUsage& AU) const;
			virtual const char* getPassName() const {
                                return "TaggedData";
                        }
                        bool hasmd;

                private:
                        // This is the information computed by the analysis.
                        std::map<llvm::Instruction*,llvm::NoCryptoFA::InstructionMetadata*> known;
                        std::map<llvm::Instruction*,std::bitset<MAX_KEYBITS> > instr_bs;
                        std::set<Function*> markedfunctions;
                        bool antenato(llvm::Instruction* ptr, llvm::Instruction* ricercato);
                        int latestPos;
                        void checkMeta(llvm::Instruction* ptr);
                        void calcAndSavePre(llvm::Instruction* ptr);
                        pair<bitset<MAX_KEYBITS>,bitset<MAX_KEYBITS> > calcPost(llvm::Instruction* ptr,Instruction*faulty,bitset<MAX_KEYBITS> sum,bitset<MAX_KEYBITS> min);
                        bitset<MAX_KEYBITS> getOwnBitset(llvm::Instruction* ptr);
                        void infect(llvm::Instruction* ptr);
                        int  getKeyLen(llvm::Instruction* ptr);
        };
	TaggedData* createTaggedDataPass();


} 

