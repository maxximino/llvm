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
        std::bitset<MAX_KEYBITS> pre;
        std::bitset<MAX_KEYBITS> own;
         std::bitset<MAX_KEYBITS> post_sum;
         std::bitset<MAX_KEYBITS> post_min;
         InstructionMetadata():pre(0),own(0),post_sum(0),post_min(0){
          isAKeyOperation=false;
          isAKeyStart = false;
          post_sum.reset();
          post_min.set();
	    }
	  };
       struct KeyStartInfo{
       public:
           llvm::Value* ptr;
           long index;
           KeyStartInfo(llvm::Value* _ptr,long _idx){
               ptr=_ptr;
               index=_idx;
           }
           KeyStartInfo(llvm::Value* _ptr){
               ptr=_ptr;
               index=-1;
           }
           KeyStartInfo(){
               index=-1;
               ptr=NULL;
           }
           friend bool operator== (const KeyStartInfo&a,const KeyStartInfo& b);
           friend bool operator< (const KeyStartInfo&a,const KeyStartInfo& b);
       };
       inline bool operator== (const NoCryptoFA::KeyStartInfo&a,const NoCryptoFA::KeyStartInfo& b){
           return a.index==b.index && a.ptr==b.ptr;
       }
       inline bool operator< (const NoCryptoFA::KeyStartInfo&a,const NoCryptoFA::KeyStartInfo& b){
           if(a.ptr != b.ptr){
               return a.ptr < b.ptr;
           }
           else{
               return a.index < b.index;
           }
       }


	      
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
bool functionMarked(Function* ptr);

                private:
                        // This is the information computed by the analysis.
                        std::map<llvm::Instruction*,llvm::NoCryptoFA::InstructionMetadata*> known;
                        std::map<llvm::Instruction*,std::bitset<MAX_KEYBITS> > instr_bs;
                        std::map<NoCryptoFA::KeyStartInfo,std::bitset<MAX_KEYBITS> > GEPs;
                        std::set<Function*> markedfunctions;
                        bool antenato(llvm::Instruction* ptr, llvm::Instruction* ricercato);
                        int keyLatestPos;
                        int outLatestPos;
                        std::set<Instruction*> toBeVisited;
                        std::set<Instruction*> endPoints;
                        void checkMeta(llvm::Instruction* ptr);
                        void calcPre(llvm::Instruction* ptr);
                        void calcPost(llvm::Instruction* ptr);
                        bitset<MAX_KEYBITS> getOutBitset(llvm::Instruction* ptr);
                        bitset<MAX_KEYBITS> getOwnBitset(llvm::Instruction* ptr);
                        void infect(llvm::Instruction* ptr);
                        int  getKeyLen(llvm::Instruction* ptr);
                        bool hasmd;

        };
	TaggedData* createTaggedDataPass();


} 


