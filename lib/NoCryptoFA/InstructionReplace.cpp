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
	DominatorTree& dt = getAnalysis<DominatorTree>();
	for(llvm::Value::use_iterator u = from->use_begin(), e = from->use_end(); u != e; ++u) {
		if(to == (Value*)(&u.getUse())) { continue; }
		if(dt.dominates(cast<Instruction>(to), cast<Instruction>(u.getUse()))) {
			u->replaceUsesOfWith(from, to);
		}
	}
}

llvm::Function& GetRand(llvm::Module& Mod)
{
    llvm::LLVMContext& Ctx = Mod.getContext();
    llvm::FunctionType* RandTy;
#if defined(__i386__) || defined(__x86_64__)
    RandTy = llvm::FunctionType::get(llvm::Type::getInt32Ty(Ctx),false);
#else
#error "Architecture not supported"
#endif
    llvm::Constant* FunSym = Mod.getOrInsertFunction("rand", RandTy);
    return *llvm::cast<llvm::Function>(FunSym);
}

llvm::Function& GetRandomFn(llvm::Module& Mod)
{
    llvm::Function* Fun = Mod.getFunction("__getrandom");
    if(Fun && !Fun->isDeclaration()) {
        return *Fun;
    }
    llvm::LLVMContext& Ctx = Mod.getContext();
    llvm::Constant* FunSym;
    FunSym = Mod.getOrInsertFunction("__getrandom",
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

bool InstructionReplace::runOnModule(llvm::Module& M)
{
    llvm::raw_fd_ostream fd(2, false);
	llvm::Instruction* tbd = NULL;
    for(llvm::Module::iterator F= M.begin(),ME = M.end(); F != ME; ++F){
        for(llvm::Function::iterator BB = F->begin(),
            FE = F->end();
            BB != FE;
            ++BB) {
            CalcDFG& cd = getAnalysis<CalcDFG>(*F);

            for( llvm::BasicBlock::iterator i = BB->begin(); i != BB->end(); i++) {
                if(tbd != NULL) {
                    tbd->eraseFromParent();
                    tbd = NULL;
                }
                if(!cd.shouldBeProtected(i)) continue;
                if(i->getOpcode() == Instruction::Xor){
                    llvm::Function& rand = GetRandomFn(M);
                    llvm::IRBuilder<> ib = llvm::IRBuilder<>(BB->getContext());
                    ib.SetInsertPoint(i);
                    llvm::Value* rndval = ib.CreateCall(&rand);
                    llvm::Value* int1 = ib.CreateXor(rndval,i->getOperand(0));
                    llvm::Value* int2 = ib.CreateXor(rndval,i->getOperand(1));
                    llvm::Value* newone = ib.CreateXor(int1,int2);
                    i->replaceAllUsesWith(newone);
                    tbd = i;
                }
                else if(i->getOpcode() == Instruction::And){
                    llvm::Function& rand = GetRandomFn(M);
                    llvm::IRBuilder<> ib = llvm::IRBuilder<>(BB->getContext());
                    ib.SetInsertPoint(i);
                    /* Applico la maschera
                       a[0] = rand()
                       a[1] = a XOR rand();
                       b[0] = rand()
                       b[1] = b XOR rand();
                        */
                    llvm::Value* a0 = ib.CreateCall(&rand);
                    llvm::Value* b0 = ib.CreateCall(&rand);
                    llvm::Value* a1 = ib.CreateXor(a0,i->getOperand(0));
                    llvm::Value* b1 = ib.CreateXor(b0,i->getOperand(1));
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
                    llvm::Value* t1 = ib.CreateAnd(a0,b1);
                    llvm::Value* t2 = ib.CreateAnd(a1,b0);
                    llvm::Value* t3 = ib.CreateXor(x,t1);
                    llvm::Value* y = ib.CreateXor(t3,t2);
                    llvm::Value* t4 = ib.CreateAnd(a0,b0);
                    llvm::Value* t5 = ib.CreateAnd(a1,b1);
                    llvm::Value* c0 = ib.CreateXor(t4,x);
                    llvm::Value* c1 = ib.CreateXor(t5,y);
                    /* tolgo la maschera
                     * c = c[0] XOR c[1] */
                    llvm::Value* c = ib.CreateXor(c0,c1);
                    i->replaceAllUsesWith(c);
                    tbd = i;
                }
            }
            if(tbd != NULL) {
                tbd->eraseFromParent();
                tbd = NULL;
            }
        }
    }
	return true;
}

void InstructionReplace::getAnalysisUsage(llvm::AnalysisUsage& AU) const
{
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

