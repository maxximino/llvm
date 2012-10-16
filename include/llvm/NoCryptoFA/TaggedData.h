#pragma once

#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include <llvm/Instruction.h>
#include <set>

namespace llvm
{
	void initializeTaggedDataPass(PassRegistry& Registry);

        // A Function pass analyze one function at time. Selecting the right pass type
        // allows LLVM to schedule them aggressively, improving compiler data-locality.
        class TaggedData : public llvm::FunctionPass
        {
                public:
                        static char ID;
                        TaggedData() : llvm::FunctionPass(ID),
                                markedAsKey(), notMarkedAsKey() { }
                        TaggedData(const TaggedData& fp) : llvm::FunctionPass(fp.ID),
                                markedAsKey(fp.markedAsKey), notMarkedAsKey(fp.notMarkedAsKey) { }
                        // This member function will be invoked on every function found on the module
                        // currently considered by the compiler.

                        virtual bool runOnFunction(llvm::Function& Fun);
                        virtual bool isMarkedAsKey(llvm::Instruction* ptr);
                        virtual bool isMarkedAsStatus(llvm::Instruction* ptr);
                        // Allows to require analysis and declare which analysis are invalidated by
                        // this pass.
                        virtual void getAnalysisUsage(llvm::AnalysisUsage& AU) const;

                        // Analysis passes should implement this member function to print a human
                        // readable version of analysis info. Its invocation is triggered by the
                        // '-analyze' 'opt' command line switch.
                        //virtual void print(llvm::raw_ostream &OS, const llvm::Module *Mod) const;

                        virtual const char* getPassName() const {
                                return "TaggedData";
                        }

                private:
                        // This is the information computed by the analysis.
                        std::set<llvm::Instruction*> markedAsKey;
                        std::set<llvm::Instruction*> notMarkedAsKey;
                        bool isAKeyOperation(llvm::Instruction* ptr);
        };
	TaggedData* createTaggedDataPass();


} 
