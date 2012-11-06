#include "llvm/NoCryptoFA/TaggedData.h"
#include "llvm/Function.h"
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

std::map<llvm::Instruction*,llvm::NoCryptoFA::InstructionMetadata*> llvm::NoCryptoFA::known = std::map<llvm::Instruction*,llvm::NoCryptoFA::InstructionMetadata*>();
char TaggedData::ID = 212;
	TaggedData* llvm::createTaggedDataPass(){
		return new TaggedData();
	}
    bool TaggedData::functionMarked(Function* ptr){
        return (markedfunctions.count(ptr) > 0);
    }
    bool TaggedData::isMarkedAsKey(Instruction* ptr)
    {
        return NoCryptoFA::known[ptr]->isAKeyOperation;
    }
    bool TaggedData::isMarkedAsStatus(Instruction* ptr)
{
	return (ptr->getMetadata("status") != NULL);
}
bool TaggedData::runOnFunction(llvm::Function& Fun)
{
    hasmd=false;
	for(llvm::Function::iterator FI = Fun.begin(),
	    FE = Fun.end();
	    FI != FE;
	    ++FI) {
		for(llvm::BasicBlock::iterator I = FI->begin(),
		    E = FI->end();
		    I != E;
		    ++I) {
            checkMeta(I.getNodePtrUnchecked());
		}
	}
    if(hasmd){
        markedfunctions.insert(&Fun);
        }

    return true;
}

std::string readMetaMark(Instruction* ptr)
{
	MDNode* m = ptr->getMetadata("MetaMark");
	if(m != NULL) {
		if(isa<MDString>(m->getOperand(0))) {
			return cast<MDString>(m->getOperand(0))->getString().str();
		}
    }
	return "";
}
void TaggedData::infect(llvm::Instruction* ptr){
    llvm::NoCryptoFA::InstructionMetadata* md;
    hasmd=true;
    if(NoCryptoFA::known.find(ptr)!=NoCryptoFA::known.end()){
        md=NoCryptoFA::known[ptr];
    }else{
        md = new llvm::NoCryptoFA::InstructionMetadata(ptr);
        NoCryptoFA::known[ptr]=md;
    }

    if(!md->isAKeyOperation){
        md->isAKeyOperation = true;
        for(llvm::Instruction::use_iterator i = ptr->use_begin(); i!= ptr->use_end(); ++i) {
            if (Instruction *Inst = dyn_cast<Instruction>(*i)) {
                infect(Inst);
             }
        }
          md->isAKeyStart=true;
        for(User::const_op_iterator it = ptr->op_begin(); it != ptr->op_end(); ++it) {
        if(Instruction *_it = dyn_cast<Instruction>(*it)) {
            if(NoCryptoFA::known.find(_it) != NoCryptoFA::known.end()){
                if(NoCryptoFA::known[_it]->isAKeyOperation){
                    md->isAKeyStart=false;
                    break;
                }
            }
           }
        }
    }
}
llvm::NoCryptoFA::InstructionMetadata* TaggedData::getMD(llvm::Instruction* ptr){
    return NoCryptoFA::known[ptr];
}

void TaggedData::checkMeta(llvm::Instruction* ptr)
{
	if( !std::string("chiave").compare(readMetaMark(ptr))) {
        infect(ptr);
    }else if( !std::string("OPchiave").compare(readMetaMark(ptr))) {
        infect(ptr);
    }
    else if(NoCryptoFA::known.find(ptr)==NoCryptoFA::known.end()){
        llvm::NoCryptoFA::InstructionMetadata* md = new llvm::NoCryptoFA::InstructionMetadata(ptr);
        NoCryptoFA::known[ptr]=md;
        md->isAKeyOperation = false;
    }
}
void TaggedData::getAnalysisUsage(llvm::AnalysisUsage& AU) const
{
	// This is an analysis, nothing is modified, so other analysis are preserved.
    AU.addRequired<DominatorTree>();
    AU.setPreservesAll();
}

using namespace llvm;

INITIALIZE_PASS_BEGIN(TaggedData,
                      "TaggedData",
                      "TaggedData",
                      true,
                      true)
INITIALIZE_PASS_END(TaggedData,
                    "TaggedData",
                    "TaggedData",
                    true,
                    true)
