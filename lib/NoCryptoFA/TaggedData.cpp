#include "llvm/NoCryptoFA/TaggedData.h"
#include "llvm/Function.h"
#include "llvm/Support/ErrorHandling.h"
#include <llvm/Metadata.h>
#include <llvm/Type.h>
#include <llvm/Instructions.h>
#include <llvm/Analysis/Dominators.h>
#include <set>
using namespace llvm;

char TaggedData::ID = 212;
	TaggedData* llvm::createTaggedDataPass(){
		return new TaggedData();
	}

bool TaggedData::isMarkedAsStatus(Instruction* ptr)
{
	return (ptr->getMetadata("status") != NULL);
}
bool TaggedData::runOnFunction(llvm::Function& Fun)
{
    latestPos=0;
    instr_bs.clear();
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
        for(llvm::Function::iterator FI = Fun.begin(),
            FE = Fun.end();
            FI != FE;
            ++FI) {
            for(llvm::BasicBlock::iterator I = FI->begin(),
                E = FI->end();
                I != E;
                ++I) {
                if(known[I]->isAKeyStart){
                    calcAndSavePre(I);
                }
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
                if(known[I]->isAKeyOperation){
                    known[I]->post_sum.reset();
                    known[I]->post_min.set();
                    auto ret = calcPost(I,I,known[I]->post_sum,known[I]->post_min);
                    known[I]->post_sum = ret.first;
                    known[I]->post_min = ret.second;
                }
            }
        }
    }
    return true;
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
bitset<MAX_KEYBITS> TaggedData::getOwnBitset(llvm::Instruction* ptr){
    if(instr_bs.find(ptr) != instr_bs.end()){
        return instr_bs[ptr];
    }
    Type* t = ptr->getType();
    while(t->isPointerTy()){
        t=t->getPointerElementType();
    }
       int keyQty=t->getScalarSizeInBits(); //TODO: Gestire array e cose diverse da valori scalari e puntatori.
       bitset<MAX_KEYBITS> mybs;
       mybs.reset();
       for(int i = latestPos; i <= (latestPos+keyQty); i++){
           mybs[i]=1;
       }
    latestPos +=keyQty;
    cerr << "kq: "<<keyQty<<  " lp " << latestPos << "--"<< mybs.to_string() << endl;

    instr_bs[ptr]=mybs;
    return mybs;

}
bool TaggedData::antenato(llvm::Instruction* ptr, llvm::Instruction* ricercato){
    static std::set<llvm::Instruction*> stack;
    return false;
    if(!known[ptr]->isAKeyOperation) return false;
    if(stack.count(ptr) >0 ) return false; //Devo rompere la ricorsione nei loop
    stack.insert(ptr);

    for(User::const_op_iterator it = ptr->op_begin(); it != ptr->op_end(); ++it) {
        if(Instruction *_it = dyn_cast<Instruction>(*it)) {
            if(_it==ricercato){
                stack.erase(stack.find(ptr));
                return true;
            }
            if(antenato(_it,ricercato)){
                stack.erase(stack.find(ptr));
                return true;}
        }
    }
        stack.erase(stack.find(ptr));
    return false;
}
pair<bitset<MAX_KEYBITS>,bitset<MAX_KEYBITS> > TaggedData::calcPost(Instruction *ptr,Instruction*faulty,bitset<MAX_KEYBITS> sum,bitset<MAX_KEYBITS> min){
    static std::set<llvm::Instruction*> stack;
    if(!known[ptr]->isAKeyOperation) return make_pair(sum,min);
    if(stack.count(ptr) >0 ) return make_pair(sum,min); //Devo rompere la ricorsione nei loop
    stack.insert(ptr);
    raw_fd_ostream rerr(2,false);
    if(ptr==faulty){
        sum.reset();
    }else{
        DominatorTree& dt = getAnalysis<DominatorTree>();
        for(User::const_op_iterator it = ptr->op_begin(); it != ptr->op_end(); ++it) {
            if(Instruction *_it = dyn_cast<Instruction>(*it)) {
                if(_it!=faulty){
                    if(!antenato(_it,faulty)){
                        sum |= known[_it]->pre;
                 //       rerr << *_it << " non antenato " << *faulty << "\n";
                    }
                    else{
               //         rerr << *_it << " antenato " << *faulty << "\n";
                    }
                    sum |= known[_it]->own;


                }
            }
        }
    }

    if(ptr->use_empty()){
        min=sum;
    }
    else{
        bitset<MAX_KEYBITS> orig_sum = sum;
        min.set();
        for(llvm::Instruction::use_iterator it = ptr->use_begin(); it!= ptr->use_end(); ++it) {
            if(Instruction *_it = dyn_cast<Instruction>(*it)) {
                auto p = calcPost(_it,faulty,orig_sum,min);
                sum |= p.first;
                if(p.second.count() < min.count()){
                    min = p.second;
                }
             }
        }
    }
    stack.erase(stack.find(ptr));
    return make_pair(sum,min);
}
void TaggedData::infect(llvm::Instruction* ptr){
    llvm::NoCryptoFA::InstructionMetadata* md;
    hasmd=true;
    if(known.find(ptr)!=known.end()){
        md=known[ptr];
    }else{
        md = new llvm::NoCryptoFA::InstructionMetadata();
        known[ptr]=md;
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
            if(known.find(_it) != known.end()){
                if(known[_it]->isAKeyOperation){
                    md->isAKeyStart=false;
                    break;
                }
            }
           }
        }
        if(md->isAKeyStart){  md->own = getOwnBitset(ptr); }


    }
}

void TaggedData::calcAndSavePre(llvm::Instruction* ptr){
    static std::set<llvm::Instruction*> stack;
    if(stack.count(ptr) >0 ) return; //Devo rompere la ricorsione nei loop
    stack.insert(ptr);
    NoCryptoFA::InstructionMetadata *md = known[ptr];
    if(md->preCalc){return;} //no!deve poterli rielaborare. Cerco bug.
    md->pre.reset();
    md->preCalc=true;
    for(User::const_op_iterator it = ptr->op_begin(); it != ptr->op_end(); ++it) {
        if(Instruction *_it = dyn_cast<Instruction>(*it)) {
            md->pre |= known[_it]->pre;
            md->pre |= known[_it]->own;
        }
    }
    for(llvm::Instruction::use_iterator it = ptr->use_begin(); it!= ptr->use_end(); ++it) {
        if(Instruction *_it = dyn_cast<Instruction>(*it)) {
            calcAndSavePre(_it);
         }
    }
    stack.erase(stack.find(ptr));
}
void TaggedData::checkMeta(llvm::Instruction* ptr)
{
	if( !std::string("chiave").compare(readMetaMark(ptr))) {
        infect(ptr);
    }else if( !std::string("OPchiave").compare(readMetaMark(ptr))) {
        infect(ptr);
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
