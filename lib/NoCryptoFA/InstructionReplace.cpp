#include <iostream>
#include "llvm/Constants.h"
#include "llvm/Instructions.h"
#include "llvm/Instruction.h"
#include "llvm/Intrinsics.h"
#include "llvm/Module.h"
#include "llvm/Analysis/Dominators.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/IRBuilder.h"
#include "llvm/Type.h"
#include "llvm/Metadata.h"
#include <llvm/Pass.h>
#include "llvm/Function.h"
#include <llvm/ADT/StringRef.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/NoCryptoFA/All.h>

using namespace llvm;
using namespace std;

namespace llvm
{

    char InstructionReplace::ID = 178;

} // End anonymous namespace.

void InstructionReplace::fixNextUses(Value* from, Value* to)
{
    Instruction* ptr = cast<Instruction>(from);
    DominatorTree& dt = getAnalysis<DominatorTree>(*(ptr->getParent()->getParent()));
	for(llvm::Value::use_iterator u = from->use_begin(), e = from->use_end(); u != e; ++u) {
		if(to == (Value*)(&u.getUse())) { continue; }
        if(dt.dominates(cast<Instruction>(to), cast<Instruction>(u.getUse()))) {
			u->replaceUsesOfWith(from, to);
		}
	}
}

llvm::Function& GetRand(llvm::Module* Mod)
{
    llvm::LLVMContext& Ctx = Mod->getContext();
    llvm::FunctionType* RandTy;
#if defined(__i386__) || defined(__x86_64__)
    RandTy = llvm::FunctionType::get(llvm::Type::getInt32Ty(Ctx),false);
#else
#error "Architecture not supported"
#endif
    llvm::Constant* FunSym = Mod->getOrInsertFunction("rand", RandTy);
    return *llvm::cast<llvm::Function>(FunSym);
}

llvm::Function& GetRandomFn(llvm::Module* Mod)
{
    llvm::Function* Fun = Mod->getFunction("__getrandom");
    if(Fun && !Fun->isDeclaration()) {
        return *Fun;
    }
    llvm::LLVMContext& Ctx = Mod->getContext();
    llvm::Constant* FunSym;
    FunSym = Mod->getOrInsertFunction("__getrandom",
                                     llvm::Type::getInt32Ty(Ctx),
                                     NULL);
    Fun = llvm::cast<llvm::Function>(FunSym);
    llvm::BasicBlock* Entry = llvm::BasicBlock::Create(Ctx, "entry", Fun);
    llvm::Function& rand = GetRand(Mod);
    CallInst* rndval = llvm::CallInst::Create(&rand, "", Entry);
  /*  llvm::IRBuilder<> ib = llvm::IRBuilder<>(Entry->getContext());
    ib.SetInsertPoint(Entry);
    Value* addr = ib.CreateIntToPtr(ConstantInt::get(Type::getInt32Ty(Ctx),12345,false),Type::getInt32PtrTy(Ctx));
    LoadInst* rndval = ib.CreateLoad(addr,true);*/
    llvm::ReturnInst::Create(Ctx, rndval,Entry);
    return *Fun;
}
void annota(Value* cosa, std::string commento){ // roba da primo debug, niente di serio. Destinato a sparire.
    Instruction* i;
    if((i=dyn_cast<Instruction>(cosa))){
        i->setMetadata(commento, llvm::MDNode::get(i->getContext(), llvm::ArrayRef<llvm::Value*>(MDString::get(i->getContext(),commento))));
    }
}
void SetInsertionPoint(bool after,IRBuilder<>& ib, Instruction* ptr){
    if(!after){
        ib.SetInsertPoint(ptr);
        return;
    }
    BasicBlock* BB = ptr->getParent();
    llvm::BasicBlock::iterator i;
    for( i = BB->begin(); i != BB->end(); i++) {
        if(i.getNodePtrUnchecked() ==ptr) break;
    }
    i++;
    ib.SetInsertPoint(i);

}
void BuildMetadata(Value* _newInstruction, Instruction* oldInstruction,NoCryptoFA::InstructionMetadata::InstructionSource origin){
    Instruction* newInstruction = cast<Instruction>(_newInstruction);
    NoCryptoFA::InstructionMetadata* newMd = new NoCryptoFA::InstructionMetadata(newInstruction);
    newMd->origin = origin;
    newMd->hasToBeProtected = false;
    if(oldInstruction != NULL){
        NoCryptoFA::InstructionMetadata* oldMd = NoCryptoFA::known[oldInstruction];
        newMd->hasMetPlaintext = oldMd->hasMetPlaintext;
        newMd->isAKeyOperation = oldMd->isAKeyOperation;
        newMd->isAKeyStart = oldMd->isAKeyStart;
        newMd->own = oldMd->own;
        newMd->post_sum = oldMd->post_sum;
        newMd->post_min = oldMd->post_min;
        newMd->pre = oldMd->pre;
     }
}

vector<Value*> MaskValue(Value* ptr,Instruction* relativepos){
    bool after = false;
    if(isa<Instruction>(ptr)){
    NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[cast<Instruction>(ptr)];
    if(md->MaskedValues.size() > 0) return md->MaskedValues;
    relativepos=cast<Instruction>(ptr);
    after=true;
    }
    llvm::Function& rand = GetRandomFn(relativepos->getParent()->getParent()->getParent());
    llvm::IRBuilder<> ib = llvm::IRBuilder<>(relativepos->getContext());
    SetInsertionPoint(after,ib,relativepos);
    /* Applico la maschera
       a[0] = rand()
       a[1] = a XOR rand();
        */
    llvm::Value* a0 = ib.CreateCall(&rand);
    annota(a0,"ins_maschera");
    BuildMetadata(a0,dyn_cast<Instruction>(ptr),NoCryptoFA::InstructionMetadata::CREATE_MASK);
    llvm::Value* a1 = ib.CreateXor(a0,ptr);
    annota(a1,"ins_maschera");
    BuildMetadata(a1,dyn_cast<Instruction>(ptr),NoCryptoFA::InstructionMetadata::CREATE_MASK);
    if(isa<Instruction>(ptr)){
        NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[cast<Instruction>(ptr)];

    md->MaskedValues.push_back(a0);
    md->MaskedValues.push_back(a1);
    return vector<Value*>(md->MaskedValues);
    }
    else{
    vector<Value*> v;
    v.push_back(a0);
    v.push_back(a1);
    return v;
    }
}

void InstructionReplace::phase1(llvm::Module& M){
    for(llvm::Module::iterator F= M.begin(),ME = M.end(); F != ME; ++F){
        for(llvm::Function::iterator BB = F->begin(),
            FE = F->end();
            BB != FE;
            ++BB) {
            CalcDFG& cd = getAnalysis<CalcDFG>(*F);

            for( llvm::BasicBlock::iterator i = BB->begin(); i != BB->end(); i++) {
                if(!cd.shouldBeProtected(i)) continue;

                NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[i];
                if(md->origin!=NoCryptoFA::InstructionMetadata::ORIGINAL_PROGRAM) continue;
                if(i->getOpcode() == Instruction::Xor){
                    llvm::IRBuilder<> ib = llvm::IRBuilder<>(BB->getContext());
                    ib.SetInsertPoint(i);
                    vector<Value*> op1 =MaskValue(i->getOperand(0),i);
                    vector<Value*> op2 =MaskValue(i->getOperand(1),i);
                    md->MaskedValues.push_back(ib.CreateXor(op1[0],op2[0]));
                    md->MaskedValues.push_back(ib.CreateXor(op1[1],op2[1]));
                    annota(md->MaskedValues[0],"xor_mascherato");
                    annota(md->MaskedValues[1],"xor_mascherato");
                    BuildMetadata(md->MaskedValues[0],i,NoCryptoFA::InstructionMetadata::XOR_MASKED);
                    BuildMetadata(md->MaskedValues[1],i,NoCryptoFA::InstructionMetadata::XOR_MASKED);
                    deletionqueue.insert(i);
                    md->hasBeenMasked=true;
                }
                else if(i->getOpcode() == Instruction::And){
                    llvm::Function& rand = GetRandomFn(&M);
                    llvm::IRBuilder<> ib = llvm::IRBuilder<>(BB->getContext());
                    ib.SetInsertPoint(i);
                    /* Applico la maschera
                       a[0] = rand()
                       a[1] = a XOR rand();
                       b[0] = rand()
                       b[1] = b XOR rand();
                        */
                    vector<Value*> op1 =MaskValue(i->getOperand(0),i);
                    vector<Value*> op2 =MaskValue(i->getOperand(1),i);
                    /*  x = rand()
                        %1=a[0] AND b[1]
                        %2=a[1] AND b[0]
                        %3= x XOR %1
                        y = %3 XOR %2
                        %4=a[0] AND b[0]
                        c[0] = %4 XOR x
                        %5=a[1] AND b[1]
                        c[1] = %5 XOR y
                     */
                    llvm::Value* x = ib.CreateCall(&rand);
                    llvm::Value* t1 = ib.CreateAnd(op1[0],op2[1]);
                    llvm::Value* t2 = ib.CreateAnd(op1[1],op2[0]);
                    llvm::Value* t3 = ib.CreateXor(x,t1);
                    llvm::Value* y = ib.CreateXor(t3,t2);
                    llvm::Value* t4 = ib.CreateAnd(op1[0],op2[0]);
                    llvm::Value* t5 = ib.CreateAnd(op1[1],op2[1]);
                    md->MaskedValues.push_back(ib.CreateXor(t4,x));
                    md->MaskedValues.push_back(ib.CreateXor(t5,y));
                    annota(x,"and_mascherato-temp");
                    annota(t1,"and_mascherato-temp");
                    annota(t2,"and_mascherato-temp");
                    annota(t3,"and_mascherato-temp");
                    annota(t4,"and_mascherato-temp");
                    annota(t5,"and_mascherato-temp");
                    annota(y,"and_mascherato-temp");
                    annota(md->MaskedValues[0],"and_mascherato");
                    annota(md->MaskedValues[1],"and_mascherato");
                    BuildMetadata(x,i,NoCryptoFA::InstructionMetadata::AND_MASKED);
                    BuildMetadata(t1,i,NoCryptoFA::InstructionMetadata::AND_MASKED);
                    BuildMetadata(t2,i,NoCryptoFA::InstructionMetadata::AND_MASKED);
                    BuildMetadata(t3,i,NoCryptoFA::InstructionMetadata::AND_MASKED);
                    BuildMetadata(y,i,NoCryptoFA::InstructionMetadata::AND_MASKED);
                    BuildMetadata(t4,i,NoCryptoFA::InstructionMetadata::AND_MASKED);
                    BuildMetadata(t5,i,NoCryptoFA::InstructionMetadata::AND_MASKED);
                    BuildMetadata(md->MaskedValues[0],i,NoCryptoFA::InstructionMetadata::AND_MASKED);
                    BuildMetadata(md->MaskedValues[1],i,NoCryptoFA::InstructionMetadata::AND_MASKED);
                    md->hasBeenMasked=true;
                    deletionqueue.insert(i);
                    /* tolgo la maschera
                     * c = c[0] XOR c[1]
                    llvm::Value* c = ib.CreateXor(c0,c1);
                    i->replaceAllUsesWith(c);
                    tbd = i;*/
                }
                else if(i->getOpcode() == Instruction::ZExt){
                    CastInst* ci = cast<CastInst>(i);
                    llvm::IRBuilder<> ib = llvm::IRBuilder<>(BB->getContext());
                    ib.SetInsertPoint(i);
                    vector<Value*> op =MaskValue(i->getOperand(0),i);
                    md->MaskedValues.push_back(ib.CreateZExt(op[0],ci->getDestTy()));
                    md->MaskedValues.push_back(ib.CreateZExt(op[1],ci->getDestTy()));
                    annota(md->MaskedValues[0],"zext_mask");
                    annota(md->MaskedValues[1],"zext_mask");
                    BuildMetadata(md->MaskedValues[0],i,NoCryptoFA::InstructionMetadata::ZEXT_MASKED);
                    BuildMetadata(md->MaskedValues[1],i,NoCryptoFA::InstructionMetadata::ZEXT_MASKED);
                    deletionqueue.insert(i);
                    md->hasBeenMasked=true;
                }
                else if(i->getOpcode() == Instruction::LShr){
                    llvm::IRBuilder<> ib = llvm::IRBuilder<>(BB->getContext());
                    ib.SetInsertPoint(i);
                    vector<Value*> op =MaskValue(i->getOperand(0),i);

                    md->MaskedValues.push_back(ib.CreateLShr(op[0],i->getOperand(1)));
                    md->MaskedValues.push_back(ib.CreateLShr(op[1],i->getOperand(1)));
                    annota(md->MaskedValues[0],"lshr_mask");
                    annota(md->MaskedValues[1],"lshr_mask");
                    BuildMetadata(md->MaskedValues[0],i,NoCryptoFA::InstructionMetadata::LSHR_MASKED);
                    BuildMetadata(md->MaskedValues[1],i,NoCryptoFA::InstructionMetadata::LSHR_MASKED);
                    deletionqueue.insert(i);
                    md->hasBeenMasked=true;
                }
                else{
                    cerr << "Missing opcode mask:" << i->getOpcodeName() << endl;
                }
            }
        }
    }

}
void InstructionReplace::Unmask(Instruction* ptr){
    NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[ptr];
    if(md->unmasked_value != NULL) return;

    llvm::IRBuilder<> ib = llvm::IRBuilder<>(ptr->getContext());
    SetInsertionPoint(true,ib,ptr); //NO, dopo l'ultimo masked

    llvm::Value* v = ib.CreateXor(md->MaskedValues[0],md->MaskedValues[1]);
    annota(v,"rimozi_maschera");
    BuildMetadata(v,ptr,NoCryptoFA::InstructionMetadata::REMOVE_MASK);
    md->unmasked_value = cast<Instruction>(v);
    //fixNextUses(ptr,v);
    llvm::raw_fd_ostream rerr(2,false);
    cerr << "Rimuovo maschera di ";
    rerr << *ptr;
    cerr << endl;
    ptr->replaceAllUsesWith(v);
}
void InstructionReplace::phase2(llvm::Module& M){
    for(llvm::Module::iterator F= M.begin(),ME = M.end(); F != ME; ++F){
        for(llvm::Function::iterator BB = F->begin(),
            FE = F->end();
            BB != FE;
            ++BB) {
            for( llvm::BasicBlock::iterator i = BB->begin(); i != BB->end(); i++) {
                NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[i];
                if(!md->hasBeenMasked) continue;
                for(Instruction::use_iterator u = i->use_begin(); u != i->use_end(); ++u){
                    Instruction* utilizzatore = cast<Instruction>(u.getUse().getUser());
                    NoCryptoFA::InstructionMetadata* usemd = NoCryptoFA::known[utilizzatore];
                    if(usemd->MaskedValues.empty()){
                        Unmask(i);
                    }
                }
            }
        }
    }

}
void InstructionReplace::phase3(llvm::Module& M){
    int delcnt;
    while(!deletionqueue.empty()){
        delcnt=0;
        for(Instruction* i : deletionqueue){
            if(i->use_empty()){
                delcnt++;
                i->eraseFromParent();
             //   annota(i,"to_be_deleted");
                deletionqueue.erase(i);
            }
        }
        //assert(delcnt>0 && "Altrimenti resto in un loop infinito!");
        if(delcnt==0) break; //Vediamo dov'è arrivato, almeno.
    }
}

bool InstructionReplace::runOnModule(llvm::Module& M)
{
    phase1(M);
    phase2(M);
    phase3(M);
	return true;
}

void InstructionReplace::getAnalysisUsage(llvm::AnalysisUsage& AU) const
{
AU.addRequired<DominatorTree>();
AU.addRequired<CalcDFG>();

}


InstructionReplace* llvm::createInstructionReplacePass()
{
    return new InstructionReplace();
}

using namespace llvm;


// The INITIALIZE_PASS_{BEGIN,END} macros generates some functions that can be
// used to register the pass to the LLVM pass registry.
// Parameters:
//
// HelloLLVM: pass class name
// "hello-llvm": command line switch to enable pass
// "Build an hello world": pass description
// false: the pass doesn't look only at the CFG
// false: the pass isn't an analysis.
INITIALIZE_PASS_BEGIN(InstructionReplace,
                      "ncfa-instruction-replace",
                      "Mask instructions",
                      false,
                      false)
INITIALIZE_PASS_DEPENDENCY(DominatorTree)
INITIALIZE_PASS_DEPENDENCY(TaggedData)
INITIALIZE_PASS_DEPENDENCY(CalcDFG)
INITIALIZE_PASS_END(InstructionReplace,
                    "ncfa-instruction-replace",
                    "Mask instructions",
                    false,
                    false)

