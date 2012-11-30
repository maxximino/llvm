#include "llvm/NoCryptoFA/InstructionCount.h"
#include "llvm/Function.h"
#include "llvm/Module.h"
#include "llvm/Support/ErrorHandling.h"
#include <llvm/Metadata.h>
#include <llvm/Type.h>
#include <llvm/Instructions.h>
#include <llvm/Analysis/Dominators.h>
#include <set>
#include <iostream>
#include <unistd.h>
#include <sys/time.h>
using namespace llvm;


char InstructionCount::ID = 219;
InstructionCount* llvm::createInstructionCountPass()
{
    return new InstructionCount();
}
bool InstructionCount::runOnModule(llvm::Module& M)
{
    for(auto Fun = M.begin(); Fun != M.end(); ++Fun){
        unsigned long size=0;

    for(llvm::Function::iterator FI = Fun->begin(),
        FE = Fun->end();
	    FI != FE;
	    ++FI) {
        size+=FI->size();
	}

    functions[&(*Fun)]=size;
    }
	return false;
}

 void InstructionCount::print(raw_ostream& OS, const Module* mod) const{
    for(auto F= mod->begin(); F != mod->end(); ++F ){
        const Function *fp=F.getNodePtrUnchecked();
        if(functions.count(fp) == 0){
            OS << (*F).getName() << " Not analyzed \n";
        }else{
        OS << (*F).getName() << " => " << functions.at(fp) << " instructions.\n";
        }

    }
}
void InstructionCount::getAnalysisUsage(llvm::AnalysisUsage& AU) const
{
	// This is an analysis, nothing is modified, so other analysis are preserved.
	AU.setPreservesAll();
}

using namespace llvm;

INITIALIZE_PASS_BEGIN(InstructionCount,
                      "InstructionCount",
                      "InstructionCount",
                      true,
                      true)


INITIALIZE_PASS_END(InstructionCount,
                    "InstructionCount",
                    "InstructionCount",
                    true,
                    true)
