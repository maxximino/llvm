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
    bool TaggedData::functionMarked(Function* ptr){
        return (markedfunctions.count(ptr) > 0);
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
       Type* t;
    if(isa<llvm::GetElementPtrInst>(ptr)){
        GetElementPtrInst* gep = cast<GetElementPtrInst>(ptr);
        if(!gep->hasAllConstantIndices()){cerr << "GetOwnBitset on a non-constant GetElementPtr. Dow!" << endl;}
        if(!gep->getNumIndices()!= 1){cerr << "GetOwnBitset on a GetElementPtr with more than 1 index. Dow!" << endl;}
        Value *idx= gep->getOperand(1);
        if(isa<ConstantInt>(idx)){
            ConstantInt* ci = cast<ConstantInt>(idx);
            NoCryptoFA::KeyStartInfo* me = new NoCryptoFA::KeyStartInfo(gep->getPointerOperand(),ci->getZExtValue());
            if(GEPs.find(*me)!=GEPs.end()){
                return GEPs[*me];
            }
            else{
                //copiaincolla da rifattorizzare
                t = ptr->getType();
                while(t->isPointerTy()){
                    t=t->getPointerElementType();
                }
                   int keyQty=t->getScalarSizeInBits(); //TODO: Gestire array e cose diverse da valori scalari e puntatori.

                bitset<MAX_KEYBITS> mybs;
                mybs.reset();
                for(int i = latestPos; i < (latestPos+keyQty); i++){
                    mybs[i]=1;
                }
                latestPos +=keyQty;
               // cerr << "kq: "<<keyQty<<  " lp " << latestPos << "--"<< mybs.to_string() << endl;

            instr_bs[ptr]=mybs;
            return mybs;
            }
        }
        else{
        cerr << "not even the first is a costant index. Dow!" << endl;
        }
    }
    else{
     t = ptr->getType();
    }
        while(t->isPointerTy()){
            t=t->getPointerElementType();
        }
           int keyQty=t->getScalarSizeInBits(); //TODO: Gestire array e cose diverse da valori scalari e puntatori.

        bitset<MAX_KEYBITS> mybs;
        mybs.reset();
        for(int i = latestPos; i < (latestPos+keyQty); i++){
            mybs[i]=1;
        }
        latestPos +=keyQty;
      //  cerr << "kq: "<<keyQty<<  " lp " << latestPos << "--"<< mybs.to_string() << endl;

    instr_bs[ptr]=mybs;
    return mybs;

}
static std::set<llvm::Instruction*> stackpost;
void TaggedData::calcPost(Instruction *ptr){

    raw_fd_ostream rerr(2,false);
    //rerr << "entro:" << *ptr << "\n";
    if(!known[ptr]->isAKeyOperation) return;
    if(stackpost.count(ptr) >0 ) return; //Devo rompere la ricorsione nei loop
    stackpost.insert(ptr);

       for(auto it = ptr->op_begin(); it != ptr->op_end(); ++it) {
            if(Instruction *_it = dyn_cast<Instruction>(*it)) {
                auto itmd = known[_it];
               // rerr << "op:" << *_it<< "\n";
                for(auto u = _it->use_begin(); u != _it->use_end(); ++u) {
                    if(Instruction *_u = dyn_cast<Instruction>(*u)) {
                        auto umd = known[_u];
                        //rerr <<"istr:" << *_it << "uso" << *_u << "\n";
                        itmd->post_sum |= umd->post_sum;
                        if(itmd->post_min.count() >  umd->post_min.count()){
                            itmd->post_min = umd->post_min;
                        }
                    }
                }
                calcPost(_it);
            }
        }
    //stack.erase(stack.find(ptr));
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
void or_if_changed(bool &changed,bitset<MAX_KEYBITS>* var,bitset<MAX_KEYBITS> orvalue){
    bitset<MAX_KEYBITS> diff = (*var) ^ orvalue;
    if(diff.none()){return;}
    changed=true;
    (*var)|=orvalue;
}
void TaggedData::calcAndSavePre(llvm::Instruction* ptr){
    static std::set<llvm::Instruction*> stack;
    if(stack.count(ptr) >0 ) return; //Devo rompere la ricorsione nei loop
    stack.insert(ptr);
    NoCryptoFA::InstructionMetadata *md = known[ptr];
    bool changed = false;
   // if(md->preCalc){return;} //no!deve poterli rielaborare. Cerco bug.
    //md->pre.reset();
    for(User::const_op_iterator it = ptr->op_begin(); it != ptr->op_end(); ++it) {
        if(Instruction *_it = dyn_cast<Instruction>(*it)) {
            or_if_changed(changed,&(md->pre),known[_it]->pre);
            or_if_changed(changed,&(md->pre),known[_it]->own);
        }
    }
     if(changed || md->own.any()){
        if(!ptr->use_empty()){

                for(llvm::Instruction::use_iterator it = ptr->use_begin(); it!= ptr->use_end(); ++it) {
                    if(Instruction *_it = dyn_cast<Instruction>(*it)) {
                        calcAndSavePre(_it);
                     }
                }
        }
        else{
            raw_fd_ostream rerr(2,false);
          //  rerr << "estremo:" << *ptr << "\n";
            //siamo ad un estremo dell'albero
            md->post_sum = md->pre;
            md->post_min = md->pre;
            stackpost.clear();
            calcPost(ptr);
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
