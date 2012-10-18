#include "llvm/NoCryptoFA/TaggedData.h"
#include "llvm/Function.h"
#include "llvm/Support/ErrorHandling.h"
#include <llvm/Metadata.h>
#include <llvm/Type.h>
#include <llvm/Instructions.h>
using namespace llvm;

char TaggedData::ID = 4;
	TaggedData* llvm::createTaggedDataPass(){
		return new TaggedData();
	}

bool TaggedData::isMarkedAsStatus(Instruction* ptr)
{
	return (ptr->getMetadata("status") != NULL);
}
bool TaggedData::runOnFunction(llvm::Function& Fun)
{
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
    for(llvm::Function::iterator FI = Fun.begin(),
        FE = Fun.end();
        FI != FE;
        ++FI) {
        for(llvm::BasicBlock::iterator I = FI->begin(),
            E = FI->end();
            I != E;
            ++I) {
            if(known[I.getNodePtrUnchecked()]->directKeyQty > 0){
                calcPre(I.getNodePtrUnchecked());
            }
        }
    }
	return false;
}
llvm::NoCryptoFA::InstructionMetadata* TaggedData::getMD(llvm::Instruction* ptr){
    return known[ptr];
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
#include <iostream>
void TaggedData::infect(llvm::Instruction* ptr,bool realkey,int directQty){
    llvm::NoCryptoFA::InstructionMetadata* md;
    if(known.find(ptr)!=known.end()){
        md=known[ptr];
    }else{
        md = new llvm::NoCryptoFA::InstructionMetadata();
        known[ptr]=md;
    }
    if(realkey){
        Type* t = ptr->getType();
        if(t->isPointerTy()){
            md->keyQty=t->getPointerElementType()->getScalarSizeInBits();
        }
        else{
            md->keyQty=t->getScalarSizeInBits(); //TODO: Gestire array e cose diverse da valori scalari.
        }
    }
    md->directKeyQty = std::max(md->directKeyQty,directQty); //TODO: Dubbio sulla logica, sottostimo la vera quantita' ma non posso sommare.
    if(isa<llvm::LoadInst>(ptr)){
        md->keyQty=md->directKeyQty;
        md->directKeyQty=0;
    }
    if(!md->isAKeyOperation){
        md->isAKeyOperation = true;
        for(llvm::Instruction::use_iterator i = ptr->use_begin(); i!= ptr->use_end(); ++i) {
            if (Instruction *Inst = dyn_cast<Instruction>(*i)) {
                infect(Inst,false,md->keyQty);
             }
        }
    }
}

void TaggedData::calcPost(llvm::Instruction* ptr){
    //risalgo l'albero e calcolo i postKeyQty
    llvm::NoCryptoFA::InstructionMetadata *md = known[ptr];
    md->postKeyQty=0;
    for(llvm::Instruction::use_iterator it = ptr->use_begin(); it!= ptr->use_end(); ++it) {
        if(Instruction *_it = dyn_cast<Instruction>(*it)) {
            md->postKeyQty += known[_it]->postKeyQty + known[_it]->directKeyQty;
         }
    }
    for(User::const_op_iterator it = ptr->op_begin(); it != ptr->op_end(); ++it) {
        if(Instruction *_it = dyn_cast<Instruction>(*it)) {
            calcPost(_it);
        }
    }
}
void TaggedData::calcPre(llvm::Instruction* ptr){
    //qui parto dai direct, scendo nell'albero e arrivato alla fine risalgo.
    llvm::NoCryptoFA::InstructionMetadata *md = known[ptr];
    md->preKeyQty=0;
    for(User::const_op_iterator it = ptr->op_begin(); it != ptr->op_end(); ++it) {
        if(Instruction *_it = dyn_cast<Instruction>(*it)) {
            md->preKeyQty += known[_it]->preKeyQty + known[_it]->directKeyQty;
        }
    }
    for(llvm::Instruction::use_iterator it = ptr->use_begin(); it!= ptr->use_end(); ++it) {
        if(Instruction *_it = dyn_cast<Instruction>(*it)) {
            calcPre(_it);
         }
    }
    if(ptr->use_begin() == ptr->use_end()){
        calcPost(ptr);
    }
}
void TaggedData::checkMeta(llvm::Instruction* ptr)
{
	if( !std::string("chiave").compare(readMetaMark(ptr))) {
        infect(ptr,true);
    }else if( !std::string("OPchiave").compare(readMetaMark(ptr))) {
        infect(ptr,false);
    }
    else if(known.find(ptr)==known.end()){
        llvm::NoCryptoFA::InstructionMetadata* md = new llvm::NoCryptoFA::InstructionMetadata();
        known[ptr]=md;
        md->isAKeyOperation = false;
    }
}

bool TaggedData::isMarkedAsKey(llvm::Instruction* ptr)
{
	assert(known.count(ptr) > 0);
	return known[ptr]->isAKeyOperation?true:false;
	
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
INITIALIZE_PASS_END(TaggedData,
                    "TaggedData",
                    "TaggedData",
                    true,
                    true)
