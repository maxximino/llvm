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

std::map<llvm::Instruction*, llvm::NoCryptoFA::InstructionMetadata*> llvm::NoCryptoFA::known = std::map<llvm::Instruction*, llvm::NoCryptoFA::InstructionMetadata*>();
char TaggedData::ID = 212;
TaggedData* llvm::createTaggedDataPass()
{
	return new TaggedData();
}
void TaggedData::markFunction(Function* ptr)
{
	markedfunctions.insert(ptr);
}
bool TaggedData::functionMarked(Function* ptr)
{
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
	hasmd = false;
	for(llvm::Function::iterator FI = Fun.begin(),
	    FE = Fun.end();
	    FI != FE;
	    ++FI) {
		for(llvm::BasicBlock::iterator I = FI->begin(),
		    E = FI->end();
		    I != E;
		    ++I) {
			checkMeta(I);
		}
	}
	if(hasmd) {
		markedfunctions.insert(&Fun);
	}
	return false;
}


static std::string readMetaMark(Instruction* ptr)
{
	MDNode* m = ptr->getMetadata("MetaMark");
	if(m != NULL) {
		if(isa<MDString>(m->getOperand(0))) {
			return cast<MDString>(m->getOperand(0))->getString().str();
		}
	}
	return "";
}

static bool hasMetaMark(Instruction* ptr, std::string mark)
{
	string marks = readMetaMark(ptr);
	return (marks.find(mark) != marks.npos);
}

void TaggedData::infect(llvm::Instruction* ptr)
{
	llvm::NoCryptoFA::InstructionMetadata* md = llvm::NoCryptoFA::InstructionMetadata::getNewMD(ptr);
	hasmd = true;
	if(!md->isAKeyOperation) {
		md->isAKeyOperation = true;
		for(llvm::Instruction::use_iterator i = ptr->use_begin(); i != ptr->use_end(); ++i) {
			if (Instruction* Inst = dyn_cast<Instruction>(*i)) {
				infect(Inst);
			}
		}
		md->isAKeyStart = true;
		for(User::const_op_iterator it = ptr->op_begin(); it != ptr->op_end(); ++it) {
			if(Instruction* _it = dyn_cast<Instruction>(*it)) {
				if(NoCryptoFA::known.find(_it) != NoCryptoFA::known.end()) {
					if(NoCryptoFA::known[_it]->isAKeyOperation) {
						md->isAKeyStart = false;
						break;
					}
				}
			}
		}
	}
}

void TaggedData::infectPlain(llvm::Instruction* ptr,long height)
{
	llvm::NoCryptoFA::InstructionMetadata* md = llvm::NoCryptoFA::InstructionMetadata::getNewMD(ptr);
	hasmd = true;
    if(!md->hasMetPlaintext) {
		md->hasMetPlaintext = true;
        md->PlaintextHeight = height;
		for(llvm::Instruction::use_iterator i = ptr->use_begin(); i != ptr->use_end(); ++i) {
			if (Instruction* Inst = dyn_cast<Instruction>(*i)) {
                infectPlain(Inst,(height + 1));
			}
		}
	}
}
void TaggedData::infectSbox(llvm::Instruction* ptr)
{
	llvm::NoCryptoFA::InstructionMetadata* md = llvm::NoCryptoFA::InstructionMetadata::getNewMD(ptr);
	if(md->isSbox) { return; }
	md->isSbox = true;
	hasmd = true;
	for(llvm::Instruction::op_iterator i = ptr->op_begin(); i != ptr->op_end(); ++i) {
		if (GetElementPtrInst* Inst = dyn_cast<GetElementPtrInst>(*i)) {
			infectSbox(Inst);
		}
	}
	for(llvm::Instruction::use_iterator i = ptr->use_begin(); i != ptr->use_end(); ++i) {
		if (Instruction* Inst = dyn_cast<Instruction>(*i)) {
			if(isa<GetElementPtrInst>(Inst) || isa<LoadInst>(Inst)) {
				infectSbox(Inst);
			}
		}
	}
}
llvm::NoCryptoFA::InstructionMetadata* TaggedData::getMD(llvm::Instruction* ptr)
{
	return NoCryptoFA::known[ptr];
}

void TaggedData::checkMeta(llvm::Instruction* ptr)
{
	if(hasMetaMark(ptr, "plain")) {
        infectPlain(ptr,0);
	}
	if(hasMetaMark(ptr, "sbox")) {
		infectSbox(ptr);
	}
	if(hasMetaMark(ptr, "chiave")) {
		infect(ptr);
	} else if( hasMetaMark(ptr, "OPchiave")) {
		infect(ptr);
	} else if(NoCryptoFA::known.find(ptr) == NoCryptoFA::known.end()) {
		llvm::NoCryptoFA::InstructionMetadata* md = new llvm::NoCryptoFA::InstructionMetadata(ptr);
		md->isAKeyOperation = false;
	}
}
void TaggedData::getAnalysisUsage(llvm::AnalysisUsage& AU) const
{
	// This is an analysis, nothing is modified, so other analysis are preserved.
	AU.setPreservesAll();
}

using namespace llvm;

INITIALIZE_PASS_BEGIN(TaggedData,
                      "TaggedData",
                      "TaggedData",
                      true,
                      true)
INITIALIZE_PASS_DEPENDENCY(DominatorTree)

INITIALIZE_PASS_END(TaggedData,
                    "TaggedData",
                    "TaggedData",
                    true,
                    true)
