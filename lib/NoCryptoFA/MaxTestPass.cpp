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
#include <llvm/NoCryptoFA/TaggedData.h>
#include <llvm/NoCryptoFA/MaxTestPass.h>
using namespace llvm;
using namespace std;

namespace llvm
{

	char MaxTestPass::ID = 1;

} // End anonymous namespace.

Instruction* MaxTestPass::makeFaultable(Instruction* ptr)
{
	llvm::IRBuilder<> ib = llvm::IRBuilder<>(ptr->getParent()->getContext());
	ib.SetInsertPoint(ptr);
	Function* f = llvm::Intrinsic::getDeclaration(ptr->getParent()->getParent()->getParent(), Intrinsic::trap);
	Instruction* trap = ib.CreateCall(f);
	return ptr;
	/*
	llvm::Value* x1v = ib.CreateXor(ptr, (uint64_t)0);
	Instruction* x1i = dyn_cast<Instruction>(x1v);
	x1i->removeFromParent();
	x1i->insertAfter(ptr);
	fixNextUses(ptr, x1v);
	MDString* rec = MDString::get(x1v->getContext(), "Cambiare 0 in altro valore per renderlo un fault");
	x1i->setMetadata("FAULTPOINT", MDNode::get(x1v->getContext(), ArrayRef<Value*>(rec)));
	return x1i;*/
}
void MaxTestPass::fixNextUses(Value* from, Value* to)
{
	DominatorTree& dt = getAnalysis<DominatorTree>();
	for(llvm::Value::use_iterator u = from->use_begin(), e = from->use_end(); u != e; ++u) {
		if(to == (Value*)(&u.getUse())) { continue; }
		if(dt.dominates(cast<Instruction>(to), cast<Instruction>(u.getUse()))) {
			u->replaceUsesOfWith(from, to);
		}
	}
}
Instruction* MaxTestPass::inquina(Instruction* stato, Instruction* shouldbezero)
{
	if(stato == NULL) {
		cerr << "Stato nullo!" << endl;
		return NULL;
	}
	llvm::IRBuilder<> ib = llvm::IRBuilder<>(shouldbezero->getParent()->getContext());
	if(!stato->isDereferenceablePointer()) {
		llvm::Value* x2 = ib.CreateXor(stato, shouldbezero);
		llvm::Instruction* x2i = cast<Instruction>(x2);
		x2i->insertAfter(shouldbezero);
		fixNextUses(stato, x2);
		cerr << "inquinamento nei registri" << endl;
		return x2i;
	} else {
		cerr << "inquinamento con load/xor/store" << endl;
		Instruction* li = ib.CreateLoad(stato);
		//li->removeFromParent();
		li->insertAfter(shouldbezero);
		llvm::Value* x2 = ib.CreateXor(li, shouldbezero);
		llvm::Instruction* x2i = cast<Instruction>(x2);
		//x2i->removeFromParent();
		x2i->insertAfter(li);
		Instruction* si = ib.CreateStore(x2i, stato);
		//si->removeFromParent();
		si->insertAfter(x2i);
		return stato;
	}
}
bool MaxTestPass::runOnFunction(llvm::Function& F)
{
	llvm::raw_fd_ostream fd(2, false);
	llvm::Instruction* tbd = NULL;
	llvm::Instruction* latest_status = NULL;
	TaggedData td = getAnalysis<TaggedData>();
	for(llvm::Function::iterator BB = F.begin(),
	    FE = F.end();
	    BB != FE;
	    ++BB) {
		for( llvm::BasicBlock::iterator i = BB->begin(); i != BB->end(); i++) {
			if(td.isMarkedAsStatus(i)) {
				latest_status = i;
			}
			if(tbd != NULL && latest_status != tbd) {
				tbd->eraseFromParent();
				tbd = NULL;
			}
			if(td.isMarkedAsKey(i.getNodePtrUnchecked())) {
				MDString* rec = MDString::get(BB->getContext(), "operazione taggata");
				i->setMetadata("RECOGNIZED", MDNode::get(BB->getContext(), ArrayRef<Value*>(rec)));
				if(!string("add").compare(i->getOpcodeName()) || !string("sub").compare(i->getOpcodeName()) || !string("mul").compare(i->getOpcodeName()) || !string("div").compare(i->getOpcodeName())) {
					llvm::Instruction* x = i->clone();
					x->insertBefore(i);
					x = makeFaultable(x);
					MDString* sf = MDString::get(BB->getContext(), "value");
					x->setMetadata("key", MDNode::get(BB->getContext(), ArrayRef<Value*>(sf)));
					llvm::Instruction* y = i->clone();
					y->insertBefore(i);
					y = makeFaultable(y);
					y->setMetadata("key", MDNode::get(BB->getContext(), ArrayRef<Value*>(sf)));
					llvm::IRBuilder<> ib = llvm::IRBuilder<>(BB->getContext());
					ib.SetInsertPoint(i);
					llvm::Value* x1 = ib.CreateXor(y, x);
					latest_status = inquina(latest_status, cast<Instruction>(x1));
					i->replaceAllUsesWith(y);
					tbd = i;
				}
			}
		}
		if(tbd != NULL) {
			tbd->eraseFromParent();
			tbd = NULL;
		}
	}
	return true;
}

void MaxTestPass::getAnalysisUsage(llvm::AnalysisUsage& AU) const
{
	// Normally here we have to require analysis -- AU.addRequired -- and declare
	// preserved analysis -- AU.setPreserved. However, this pass does no require
	// any analysis and potentially invalidates all analysis. The default
	// behaviour is to invalidate all analysis.
	AU.addRequired<TaggedData>();
	AU.addRequired<DominatorTree>();
}


MaxTestPass* llvm::createMaxTestPass()
{
	return new MaxTestPass();
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
INITIALIZE_PASS_BEGIN(MaxTestPass,
                      "max-test",
                      "maxtest",
                      false,
                      false)
INITIALIZE_PASS_END(MaxTestPass,
                    "max-test",
                    "maxtest",
                    false,
                    false)

