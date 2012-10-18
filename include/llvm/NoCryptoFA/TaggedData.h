#pragma once

#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include <llvm/Instruction.h>
#include <map>

namespace llvm
{
	void initializeTaggedDataPass(PassRegistry& Registry);
	namespace NoCryptoFA{
	  struct InstructionMetadata{
	    char isAKeyOperation;
	      int preKeyQty;
	      int postKeyQty;
	      int keyQty;
          int directKeyQty;
	    InstructionMetadata(){
          isAKeyOperation=false;
	      preKeyQty=0;
	      keyQty=0;
	      postKeyQty=0;
          directKeyQty=0;
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

                private:
                        // This is the information computed by the analysis.
                        std::map<llvm::Instruction*,llvm::NoCryptoFA::InstructionMetadata*> known;
                        void checkMeta(llvm::Instruction* ptr);
                        void calcPre(llvm::Instruction* ptr);
                        void calcPost(llvm::Instruction* ptr);
                        void infect(llvm::Instruction* ptr, bool realkey=false,int directQty=0);
        };
	TaggedData* createTaggedDataPass();


} 
