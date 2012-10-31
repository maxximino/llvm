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
void set_if_changed(bool &changed,bitset<MAX_KEYBITS>* var,bitset<MAX_KEYBITS> newvalue){
    if((*var) == newvalue){return;}
    changed=true;
    (*var)=newvalue;
}

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
    keyLatestPos=0;
    outLatestPos=0;
    instr_bs.clear();
    endPoints.clear();

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
        endPoints.clear();
        toBeVisited.clear();
        struct timeval clk_start,clk_end;
        gettimeofday(&clk_start,NULL);
        for(llvm::Function::iterator FI = Fun.begin(),
            FE = Fun.end();
            FI != FE;
            ++FI) {

            for(llvm::BasicBlock::iterator I = FI->begin(),
                E = FI->end();
                I != E;
                ++I) {
                if(known[I]->isAKeyStart){
                    toBeVisited.insert(I);
                }
            }
           }
            while(toBeVisited.size() > 0){
                std::set<Instruction*> thisVisit = set<Instruction*>(toBeVisited);
                toBeVisited.clear();
                for(Instruction* p : thisVisit){
                    calcPre(p);
                }
            }
            gettimeofday(&clk_end,NULL);
            std::cerr << "Tempo visita pre: delta-sec" <<  clk_end.tv_sec - clk_start.tv_sec;
            std::cerr << " delta-usec" <<  clk_end.tv_usec - clk_start.tv_usec << endl;
            for(Instruction*p :endPoints){
                toBeVisited.clear();
                calcPost(p);
                while(toBeVisited.size() > 0){
                    std::set<Instruction*> thisVisit = set<Instruction*>(toBeVisited);
                    toBeVisited.clear();
                    for(Instruction* p : thisVisit){
                        calcPost(p);
                    }
                }
            }
            gettimeofday(&clk_end,NULL);
            std::cerr << "Tempo visita pre+post: delta-sec" <<  clk_end.tv_sec - clk_start.tv_sec;
            std::cerr << " delta-usec" <<  clk_end.tv_usec - clk_start.tv_usec << endl;
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
bitset<MAX_KEYBITS> TaggedData::getOutBitset(llvm::Instruction* ptr){ // sarebbe MAX_OUTBITS, fare refactoring
    Value *op;
    if(isa<StoreInst>(ptr)){
        StoreInst* s = cast<StoreInst>(ptr);
        op = s->getPointerOperand();
    }else if(isa<ReturnInst>(ptr)){
        ReturnInst* s = cast<ReturnInst>(ptr);
        op = s->getReturnValue();
    }else if(isa<CallInst>(ptr)){
        op = ptr;
        cerr << "La chiave passa ad una CALL.... warn!\n";
    }
    else{
        raw_fd_ostream rerr(2,false);
        rerr << *ptr;
        cerr << "Istruzione senza usi che non è una return nè una store nè una call... Segfaultiamo per far notare l'importanza del problema.."<< endl;
        int*ptr=0;
        *ptr=1;
    }
    Type* t = op->getType();
        while(t->isPointerTy()){
           t=t->getPointerElementType();
       }
          int outQty=t->getScalarSizeInBits(); //TODO: Gestire array e cose diverse da valori scalari e puntatori.
        //  cerr << "latestPos " << outLatestPos << " outQty:" << outQty << endl;
       bitset<MAX_KEYBITS> mybs;
       mybs.reset();
       for(int i = outLatestPos; i < (outLatestPos+outQty); i++){
           mybs[i]=1;
       }
       outLatestPos +=outQty;
   return mybs;
}
bitset<MAX_KEYBITS> TaggedData::getOwnBitset(llvm::Instruction* ptr){
    raw_fd_ostream rerr(2,false);
    if(instr_bs.find(ptr) != instr_bs.end()){
        return instr_bs[ptr];
    }
       Type* t;
    if(isa<llvm::GetElementPtrInst>(ptr)){
        GetElementPtrInst* gep = cast<GetElementPtrInst>(ptr);
        if(!gep->hasAllConstantIndices()){cerr << "GetOwnBitset on a non-constant GetElementPtr. Dow!" << endl;}
        if(gep->getNumIndices()!= 1){cerr << "GetOwnBitset on a GetElementPtr with more than 1 index. Dow!" << endl; }
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
                for(int i = keyLatestPos; i < (keyLatestPos+keyQty); i++){
                    mybs[i]=1;
                }
                keyLatestPos +=keyQty;
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
        for(int i = keyLatestPos; i < (keyLatestPos+keyQty); i++){
            mybs[i]=1;
        }
        keyLatestPos +=keyQty;
      //  cerr << "kq: "<<keyQty<<  " lp " << latestPos << "--"<< mybs.to_string() << endl;

    instr_bs[ptr]=mybs;
    return mybs;

}
void TaggedData::calcPost(Instruction *ptr){

    //raw_fd_ostream rerr(2,false);
    //rerr << "entro:" << *ptr << "\n";
    if(!known[ptr]->isAKeyOperation) return;
        for(auto it = ptr->op_begin(); it != ptr->op_end(); ++it) {
            if(Instruction *_it = dyn_cast<Instruction>(*it)) {
                auto itmd = known[_it];
               // rerr << "op:" << *_it<< "\n";
                bool changed = false;
                for(auto u = _it->use_begin(); u != _it->use_end(); ++u) {
                    if(Instruction *_u = dyn_cast<Instruction>(*u)) {
                        auto umd = known[_u];
                        //rerr <<"istr:" << *_it << "uso" << *_u << "\n";
                        set_if_changed(changed,&(itmd->post_sum),itmd->post_sum| umd->post_sum);
                        if(itmd->post_min.count() >  umd->post_min.count()){
                            set_if_changed(changed,&(itmd->post_min), umd->post_min);
                        }
                    }
                }
                if(changed) toBeVisited.insert(_it);
            }
        }
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
        if(md->isAKeyStart && md->own.none()){  md->own = getOwnBitset(ptr); }


    }
}
void TaggedData::calcPre(llvm::Instruction* ptr){
    NoCryptoFA::InstructionMetadata *md = known[ptr];
    bool changed = false;
    for(User::const_op_iterator it = ptr->op_begin(); it != ptr->op_end(); ++it) {
        if(Instruction *_it = dyn_cast<Instruction>(*it)) {
            set_if_changed(changed,&(md->pre),md->pre|known[_it]->pre);
            set_if_changed(changed,&(md->pre),md->pre|known[_it]->own);
        }
    }
     if(changed || md->own.any()){
        if(!ptr->use_empty()){
                for(llvm::Instruction::use_iterator it = ptr->use_begin(); it!= ptr->use_end(); ++it) {
                    if(Instruction *_it = dyn_cast<Instruction>(*it)) {
                        toBeVisited.insert(_it);
                     }
                }
        }
        else{
            endPoints.insert(ptr);
      //      raw_fd_ostream rerr(2,false);
  //          rerr << "estremo:" << *ptr << "\n";
            //siamo ad un estremo dell'albero
            md->post_sum = getOutBitset(ptr);
    //        cerr << "bs:" << md->post_sum << "\n";
            md->post_min = md->post_sum;
        }
    }
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
