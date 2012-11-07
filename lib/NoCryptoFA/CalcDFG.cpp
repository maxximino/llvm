#include "llvm/NoCryptoFA/CalcDFG.h"
#include "llvm/NoCryptoFA/All.h"
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
template<int SIZE>
void set_if_changed(bool& changed, bitset<SIZE>* var, bitset<SIZE> newvalue)
{
	if((*var) == newvalue) {return;}
	changed = true;
	(*var) = newvalue;
}
//#define set_if_changed(changed,var,newvalue) if(var!=(newvalue)){changed=true,var=newvalue;}
#include "InstrTraits.h"

char llvm::CalcDFG::ID = 213;

CalcDFG* llvm::createCalcDFGPass()
{
	return new CalcDFG();
}

bool CalcDFG::runOnFunction(llvm::Function& Fun)
{
	keyLatestPos = 0;
	outLatestPos = 0;
	cerr << "rOF " << Fun.getName().str() << endl;
	instr_bs.clear();
	endPoints.clear();
	llvm::TaggedData& td = getAnalysis<TaggedData>();
	if(!td.functionMarked(&Fun)) {return true;}
	endPoints.clear();
	toBeVisited.clear();
	struct timeval clk_start, clk_end;
	gettimeofday(&clk_start, NULL);
	for(llvm::Function::iterator FI = Fun.begin(),
	    FE = Fun.end();
	    FI != FE;
	    ++FI) {
		for(llvm::BasicBlock::iterator I = FI->begin(),
		    E = FI->end();
		    I != E;
		    ++I) {
			if(NoCryptoFA::known[I]->isAKeyStart) {
				if(NoCryptoFA::known[I]->own.none()) {  NoCryptoFA::known[I]->own = getOwnBitset(I); }
				toBeVisited.insert(I);
			}
			if(NoCryptoFA::known[I]->isAKeyOperation) {
				int size = getOperandSize(I);
				NoCryptoFA::known[I]->pre.resize(size);
				for(int i = 0; i < size; ++i) {
					NoCryptoFA::known[I]->pre[i] = bitset<MAX_KEYBITS>(0);
				}
			}
		}
	}
	while(toBeVisited.size() > 0) {
		std::set<Instruction*> thisVisit = set<Instruction*>(toBeVisited);
		toBeVisited.clear();
	for(Instruction * p : thisVisit) {
			calcPre(p);
		}
	}
	gettimeofday(&clk_end, NULL);
	std::cerr << "Tempo visita pre: delta-sec" <<  clk_end.tv_sec - clk_start.tv_sec;
	std::cerr << " delta-usec" <<  clk_end.tv_usec - clk_start.tv_usec << endl;
for(Instruction * p : endPoints) {
		toBeVisited.clear();
		calcPost(p);
		while(toBeVisited.size() > 0) {
			std::set<Instruction*> thisVisit = set<Instruction*>(toBeVisited);
			toBeVisited.clear();
		for(Instruction * p : thisVisit) {
				calcPost(p);
			}
		}
	}
	gettimeofday(&clk_end, NULL);
	std::cerr << "Tempo visita pre+post: delta-sec" <<  clk_end.tv_sec - clk_start.tv_sec;
	std::cerr << " delta-usec" <<  clk_end.tv_usec - clk_start.tv_usec << endl;
	return true;
}
llvm::NoCryptoFA::InstructionMetadata* CalcDFG::getMD(llvm::Instruction* ptr)
{
	return NoCryptoFA::known[ptr];
}

#include <iostream>
bitset<MAX_OUTBITS> CalcDFG::getOutBitset(llvm::Instruction* ptr)
{
	Value* op;
	if(isa<StoreInst>(ptr)) {
		StoreInst* s = cast<StoreInst>(ptr);
		op = s->getPointerOperand();
	} else if(isa<ReturnInst>(ptr)) {
		ReturnInst* s = cast<ReturnInst>(ptr);
		op = s->getReturnValue();
	} else if(isa<CallInst>(ptr)) {
		op = ptr;
		cerr << "La chiave passa ad una CALL.... warn!\n";
	} else {
		raw_fd_ostream rerr(2, false);
		rerr << *ptr;
		cerr << "Istruzione senza usi che non è una return nè una store nè una call... Segfaultiamo per far notare l'importanza del problema.." << endl;
		int* ptr = 0;
		*ptr = 1;
	}
	Type* t = op->getType();
	while(t->isPointerTy()) {
		t = t->getPointerElementType();
	}
	int outQty = t->getScalarSizeInBits(); //TODO: Gestire array e cose diverse da valori scalari e puntatori.
	//  cerr << "latestPos " << outLatestPos << " outQty:" << outQty << endl;
	bitset<MAX_OUTBITS> mybs;
	mybs.reset();
	for(int i = outLatestPos; i < (outLatestPos + outQty); i++) {
		mybs[i] = 1;
	}
	outLatestPos += outQty;
	cerr << " new outLatestPos " << outLatestPos << endl;
	return mybs;
}
int CalcDFG::getOperandSize(llvm::Instruction* ptr)
{
	return getOperandSize(ptr->getType());
}
int CalcDFG::getOperandSize(llvm::Type* t)
{
	while(t->isPointerTy()) {
		t = t->getPointerElementType();
	}
	return t->getScalarSizeInBits(); //TODO: Gestire array e cose diverse da valori scalari e puntatori.
}

bitset<MAX_KEYBITS> CalcDFG::getOwnBitset(llvm::Instruction* ptr)
{
	raw_fd_ostream rerr(2, false);
	if(instr_bs.find(ptr) != instr_bs.end()) {
		return instr_bs[ptr];
	}
	Type* t;
	if(isa<llvm::GetElementPtrInst>(ptr)) {
		GetElementPtrInst* gep = cast<GetElementPtrInst>(ptr);
		if(!gep->hasAllConstantIndices()) {cerr << "GetOwnBitset on a non-constant GetElementPtr. Dow!" << endl;}
		if(gep->getNumIndices() != 1) {cerr << "GetOwnBitset on a GetElementPtr with more than 1 index. Dow!" << endl; }
		Value* idx = gep->getOperand(1);
		if(isa<ConstantInt>(idx)) {
			ConstantInt* ci = cast<ConstantInt>(idx);
			NoCryptoFA::KeyStartInfo* me = new NoCryptoFA::KeyStartInfo(gep->getPointerOperand(), ci->getZExtValue());
			if(GEPs.find(*me) != GEPs.end()) {
				return GEPs[*me];
			} else {
				int keyQty = getOperandSize(ptr);
				bitset<MAX_KEYBITS> mybs;
				mybs.reset();
				for(int i = keyLatestPos; i < (keyLatestPos + keyQty); i++) {
					mybs[i] = 1;
				}
				keyLatestPos += keyQty;
				cerr << "nuovo kLP " << keyLatestPos << endl;
				// cerr << "kq: "<<keyQty<<  " lp " << latestPos << "--"<< mybs.to_string() << endl;
				instr_bs[ptr] = mybs;
				return mybs;
			}
		} else {
			cerr << "not even the first is a costant index. Dow!" << endl;
		}
	} else {
		t = ptr->getType();
	}
	int keyQty = getOperandSize(t);
	bitset<MAX_KEYBITS> mybs;
	mybs.reset();
	for(int i = keyLatestPos; i < (keyLatestPos + keyQty); i++) {
		mybs[i] = 1;
	}
	keyLatestPos += keyQty;
	cerr << "nuovo kLP " << keyLatestPos << endl;
	//  cerr << "kq: "<<keyQty<<  " lp " << latestPos << "--"<< mybs.to_string() << endl;
	instr_bs[ptr] = mybs;
	return mybs;
}
void CalcDFG::calcPost(Instruction* ptr)
{
	//raw_fd_ostream rerr(2,false);
	//rerr << "entro:" << *ptr << "\n";
	if(!NoCryptoFA::known[ptr]->isAKeyOperation) { return; }
	for(auto it = ptr->op_begin(); it != ptr->op_end(); ++it) {
		if(Instruction* _it = dyn_cast<Instruction>(*it)) {
			auto itmd = NoCryptoFA::known[_it];
			// rerr << "op:" << *_it<< "\n";
			bool changed = false;
			for(auto u = _it->use_begin(); u != _it->use_end(); ++u) {
				if(Instruction* _u = dyn_cast<Instruction>(*u)) {
					auto umd = NoCryptoFA::known[_u];
					//rerr <<"istr:" << *_it << "uso" << *_u << "\n";
					set_if_changed<MAX_OUTBITS>(changed, &(itmd->post_sum), itmd->post_sum | umd->post_sum);
					if(itmd->post_min.count() >  umd->post_min.count()) {
						set_if_changed<MAX_OUTBITS>(changed, &(itmd->post_min), umd->post_min);
					}
				}
			}
			if(changed) { toBeVisited.insert(_it); }
		}
	}
}
// FARE REFACTORING DI QUESTA PORCHERIA
void calcNeedsMasking(NoCryptoFA::InstructionMetadata* md){
    bool hasEmpty = false;
    Value* v1;
    Value* v2;

    if(isa<BinaryOperator>(md->my_instruction)){
           switch(md->my_instruction->getOpcode()){
           case Instruction::Shl:
           case Instruction::LShr:
           case Instruction::AShr:
               //orrido, ma vediamo se funziona
               md->hasToBeProtected=NoCryptoFA::known[cast<Instruction>(md->my_instruction->getOperand(0))]->hasToBeProtected;
               return;
           case Instruction::And:
               v1 = md->my_instruction->getOperand(0);
               v2 = md->my_instruction->getOperand(1);
               Instruction* i;
               if(isa<ConstantInt>(v2) && isa<Instruction>(v1)) {
                   i = cast<Instruction>(v1);
               } else if(isa<ConstantInt>(v1) && isa<Instruction>(v2)) {
                   i = cast<Instruction>(v2);
                }
               else{ break;}
                 md->hasToBeProtected=NoCryptoFA::known[i]->hasToBeProtected;
                 return;
            break;
           default:
               break;
           }
     }
    if(isa<CastInst>(md->my_instruction)){
               //orrido, ma vediamo se funziona
               md->hasToBeProtected=NoCryptoFA::known[cast<Instruction>(md->my_instruction->getOperand(0))]->hasToBeProtected;
               return;
     }
     for(bitset<MAX_KEYBITS> b : md->pre){
            if(!b.all()){
               hasEmpty=true; break;
            }
        }
         md->hasToBeProtected=hasEmpty;

}
void CalcDFG::calcPre(llvm::Instruction* ptr)
{
	NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[ptr];
	bool changed = false;
#define CHECK_TYPE(type) else if(isa<type>(ptr)) CalcPreTraits<type>::calc(changed,cast<type>(ptr),md)
	if(0) {}
	CHECK_TYPE(BinaryOperator);
	CHECK_TYPE(CastInst);
	CHECK_TYPE(GetElementPtrInst);
	else { CalcPreTraits<Instruction>::calc(changed, ptr, md); }
#undef CHECK_TYPE
	if(changed || md->own.any()) {
        calcNeedsMasking(md);
		if(!ptr->use_empty()) {
			for(llvm::Instruction::use_iterator it = ptr->use_begin(); it != ptr->use_end(); ++it) {
				if(Instruction* _it = dyn_cast<Instruction>(*it)) {
					toBeVisited.insert(_it);
				}
			}
		} else {
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
void CalcDFG::getAnalysisUsage(llvm::AnalysisUsage& AU) const
{
	// This is an analysis, nothing is modified, so other analysis are preserved.
	AU.addRequired<TaggedData>();
	AU.setPreservesAll();
}

using namespace llvm;

INITIALIZE_PASS_BEGIN(CalcDFG,
                      "CalcDFG",
                      "CalcDFG",
                      true,
                      true)
INITIALIZE_PASS_END(CalcDFG,
                    "CalcDFG",
                    "CalcDFG",
                    true,
                    true)
