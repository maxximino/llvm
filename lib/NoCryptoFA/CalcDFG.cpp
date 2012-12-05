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
#include "llvm/Support/CommandLine.h"

using namespace llvm;
static cl::opt<unsigned int>
SecurityMargin("nocryptofa-security-margin", cl::init(128), cl::ValueRequired,
               cl::desc("NoCryptoFA Security Margin (bits)"));
static cl::opt<bool>
MaskEverything("nocryptofa-mask-everything", cl::init(false), cl::ValueRequired,
               cl::desc("NoCryptoFA Mask Everything"));

template<int SIZE>
void set_if_changed(bool& changed, bitset<SIZE>* var, bitset<SIZE> newvalue)
{
	if((*var) == newvalue) {return;}
	changed = true;
	(*var) = newvalue;
}
void checkNeedsMasking_pre(Instruction* ptr, NoCryptoFA::InstructionMetadata* md);
void checkNeedsMasking_post(Instruction* ptr, NoCryptoFA::InstructionMetadata* md);
//#define set_if_changed(changed,var,newvalue) if(var!=(newvalue)){changed=true,var=newvalue;}
#include "InstrTraits.h"

char llvm::CalcDFG::ID = 218;

CalcDFG* llvm::createCalcDFGPass()
{
	return new CalcDFG();
}

bool CalcDFG::runOnFunction(llvm::Function& Fun)
{
	keyLatestPos = 0;
	outLatestPos = 0;
    cipherOutPoints.clear();
    candidatekeyPostPoints.clear();
    instr_bs.clear();
    instr_out_bs.clear();
    keyPostPoints.clear();
    if(alreadyTransformed.find(&Fun)!=alreadyTransformed.end()) {return false;}
	llvm::TaggedData& td = getAnalysis<TaggedData>();
    if(!td.functionMarked(&Fun)) {return false;}
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
                NoCryptoFA::known[I]->own = getOwnBitset(I);
                toBeVisited.insert(I);
			}
			if(NoCryptoFA::known[I]->isAKeyOperation) {
				int size = getOperandSize(I);
				NoCryptoFA::known[I]->pre.resize(size);
                NoCryptoFA::known[I]->post.resize(size);
				for(int i = 0; i < size; ++i) {
					NoCryptoFA::known[I]->pre[i] = bitset<MAX_KEYBITS>(0);
                    NoCryptoFA::known[I]->post[i] = bitset<MAX_OUTBITS>(0);
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
    toBeVisited=cipherOutPoints;
    cerr << "cipherOutPoints n°" << cipherOutPoints.size() << endl;
    cerr << "candidateKeyPOst n°" << candidatekeyPostPoints.size() << endl;
    cerr << "keyLatestPos " << keyLatestPos << endl;
    cerr << "outLatestPos " << outLatestPos << endl;
    bool stopIterations=false;
    while((toBeVisited.size() > 0) && !stopIterations) {
            std::set<Instruction*> thisVisit = set<Instruction*>(toBeVisited);
            toBeVisited.clear();
        for(Instruction * p : thisVisit) {
                if(lookForBackwardsKeyPoints(p)){stopIterations=true;};
            }
        }






    toBeVisited.clear();
    for(Instruction* p : keyPostPoints){
        for(auto u = p->use_begin(); u != p->use_end(); ++u){
            Instruction *Inst = dyn_cast<Instruction>(*u);
            toBeVisited.insert(Inst);
        }
    }
    while(toBeVisited.size() > 0) {
			std::set<Instruction*> thisVisit = set<Instruction*>(toBeVisited);
			toBeVisited.clear();
		for(Instruction * p : thisVisit) {
				calcPost(p);
			}
		}
	gettimeofday(&clk_end, NULL);
	std::cerr << "Tempo visita pre+post: delta-sec" <<  clk_end.tv_sec - clk_start.tv_sec;
	std::cerr << " delta-usec" <<  clk_end.tv_usec - clk_start.tv_usec << endl;
	return false;
}

llvm::NoCryptoFA::InstructionMetadata* CalcDFG::getMD(llvm::Instruction* ptr)
{
	return NoCryptoFA::known[ptr];
}

#include <iostream>
bitset<MAX_OUTBITS> CalcDFG::getOutBitset(llvm::Instruction* ptr)
{
    if(instr_out_bs.find(ptr) != instr_out_bs.end()) {
        return instr_out_bs[ptr];
    }

    Value* op = ptr;
    int outQty = getOperandSize(op->getType());
    if(outLatestPos+outQty > MAX_OUTBITS){
        cerr << "Something wrong with CalcDFG.";
                return bitset<MAX_OUTBITS>(0);
    }
	//  cerr << "latestPos " << outLatestPos << " outQty:" << outQty << endl;
	bitset<MAX_OUTBITS> mybs;
	mybs.reset();
	for(int i = outLatestPos; i < (outLatestPos + outQty); i++) {
		mybs[i] = 1;
	}
	outLatestPos += outQty;

    cerr << " new outLatestPos " << outLatestPos << " riga " << ptr->getDebugLoc().getLine()<< endl;

    instr_out_bs[ptr]=mybs;
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
bool CalcDFG::shouldBeProtected(Instruction* ptr)
{
	NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[ptr];
    return (MaskEverything && md->hasMetPlaintext) || md->hasToBeProtected_pre || md->hasToBeProtected_post;
	//   return NoCryptoFA::known[ptr]->hasMetPlaintext;
}
bitset<MAX_KEYBITS> CalcDFG::getOwnBitset(llvm::Instruction* ptr)
{
	raw_fd_ostream rerr(2, false);
	if(instr_bs.find(ptr) != instr_bs.end()) {
		return instr_bs[ptr];
	}
	Type* t = NULL;
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
template< int BITNUM>
static void ClearMatrix(vector<bitset<BITNUM> > &vec)
{
    for(unsigned int i = 0; i < vec.size(); i++) {
        vec[i].reset();
    }
}
void CalcDFG::calcPost(Instruction* ptr)
{
    NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[ptr];
    if(!md->isAKeyOperation) {return;}
   bool changed = false;
   ClearMatrix<MAX_OUTBITS>(md->post);
    for(llvm::Instruction::op_iterator it = ptr->op_begin(); it != ptr->op_end(); ++it) {
        if(Instruction* _it = dyn_cast<Instruction>(*it)) {
            NoCryptoFA::InstructionMetadata *opmd=NoCryptoFA::known[_it];
            if(opmd->post_own.count()>0){
                md->post_FirstToMeetKey=true;
                for(int i = 0; i < md->post.size();i++){
                    md->post[i] = md->post[i]|opmd->post_own; // DIAGONALE, non blocchettino!
                }
            }
        }
    }
    for(llvm::Instruction::use_iterator it = ptr->use_begin(); it != ptr->use_end(); ++it) {
        if(Instruction* _it = dyn_cast<Instruction>(*it)) {
            NoCryptoFA::InstructionMetadata *usemd=NoCryptoFA::known[_it];
 #define CHECK_TYPE(type) else if(isa<type>(_it)) CalcTraits<type>::calcPost(cast<type>(_it),md,usemd)
                if(0) {}
                CHECK_TYPE(BinaryOperator);
                CHECK_TYPE(CastInst);
                CHECK_TYPE(GetElementPtrInst);
                CHECK_TYPE(SelectInst);
                CHECK_TYPE(CallInst);
                else { CalcTraits<Instruction>::calcPost(_it,md,usemd); }
#undef CHECK_TYPE

        }
    }
    checkNeedsMasking_post(ptr, md);
            for(llvm::Instruction::op_iterator it = ptr->op_begin(); it != ptr->op_end(); ++it) {
                if(Instruction* _it = dyn_cast<Instruction>(*it)) {
                    toBeVisited.insert(_it);
                }
            }
}

void checkNeedsMasking_post(Instruction* ptr, NoCryptoFA::InstructionMetadata* md)
{
    // errs() << "checkNeedsMasking di " << *ptr << "\n";
#define CHECK_TYPE(type) else if(isa<type>(ptr)) CalcTraits<type>::needsMasking_post(cast<type>(ptr),md)
    if(0) {}
    CHECK_TYPE(SelectInst);
    CHECK_TYPE(BinaryOperator);
    CHECK_TYPE(CastInst);
    CHECK_TYPE(GetElementPtrInst);
    CHECK_TYPE(CallInst);
    else { CalcTraits<Instruction>::needsMasking_post(ptr, md); }
#undef CHECK_TYPE
}
void checkNeedsMasking_pre(Instruction* ptr, NoCryptoFA::InstructionMetadata* md)
{
	// errs() << "checkNeedsMasking di " << *ptr << "\n";
#define CHECK_TYPE(type) else if(isa<type>(ptr)) CalcTraits<type>::needsMasking_pre(cast<type>(ptr),md)
	if(0) {}
	CHECK_TYPE(SelectInst);
	CHECK_TYPE(BinaryOperator);
	CHECK_TYPE(CastInst);
	CHECK_TYPE(GetElementPtrInst);
    CHECK_TYPE(CallInst);
    else { CalcTraits<Instruction>::needsMasking_pre(ptr, md); }
#undef CHECK_TYPE
}
bool CalcDFG::lookForBackwardsKeyPoints(llvm::Instruction* ptr)
{
    NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[ptr];
    if(candidatekeyPostPoints.find(ptr) != candidatekeyPostPoints.end()){
        errs() << "#";
        keyPostPoints.insert(ptr);
        md->isPostKeyStart=true;
        md->isPostKeyOperation=true;
        md->post_own=getOutBitset(ptr);
    }
    for(llvm::Instruction::op_iterator it = ptr->op_begin(); it != ptr->op_end(); ++it) {
        if(Instruction* _it = dyn_cast<Instruction>(*it)) {
           toBeVisited.insert(_it);
        }
    }
    return outLatestPos >= keyLatestPos;
}
void CalcDFG::calcPre(llvm::Instruction* ptr)
{
	NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[ptr];
    bool changed = true;
    ClearMatrix<MAX_KEYBITS>(md->pre);
#define CHECK_TYPE(type) else if(isa<type>(ptr)) CalcTraits<type>::calcPre(changed,cast<type>(ptr),md)
	if(0) {}
	CHECK_TYPE(BinaryOperator);
	CHECK_TYPE(CastInst);
	CHECK_TYPE(GetElementPtrInst);
	CHECK_TYPE(SelectInst);
    CHECK_TYPE(CallInst);
    else { CalcTraits<Instruction>::calcPre(changed, ptr, md); }
#undef CHECK_TYPE
    bool oldProt = md->hasToBeProtected_pre;
    checkNeedsMasking_pre(ptr, md);
    if(oldProt != md->hasToBeProtected_pre) {changed = true;}
    if(md->hasMetPlaintext && md->isAKeyOperation && ptr->use_empty()) {
        cipherOutPoints.insert(ptr);
    }
	if(changed || md->own.any()) {
		if(!ptr->use_empty()) {
            bool everyUseIsInCipher = true;
            bool hasAtLeastOneUseInCipher = false;
			for(llvm::Instruction::use_iterator it = ptr->use_begin(); it != ptr->use_end(); ++it) {
				if(Instruction* _it = dyn_cast<Instruction>(*it)) {
					toBeVisited.insert(_it);
                    if(!(NoCryptoFA::known[_it]->hasMetPlaintext && NoCryptoFA::known[_it]->isAKeyOperation)){
                        everyUseIsInCipher = false;
                    }
                    else{
                        hasAtLeastOneUseInCipher=true;
                    }
				}
            }

            //Condizione originale: if(everyUseIsInCipher && (!(ptr->use_empty())) && (!md->hasMetPlaintext)){
           if(hasAtLeastOneUseInCipher && (!(ptr->use_empty())) && (!md->hasMetPlaintext)){ //  && (ptr->getDebugLoc().getLine()==254)
                    candidatekeyPostPoints.insert(ptr);
            }
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
                      false,
                      true)
INITIALIZE_PASS_DEPENDENCY(TaggedData)

INITIALIZE_PASS_END(CalcDFG,
                    "CalcDFG",
                    "CalcDFG",
                    false,
                    true)
