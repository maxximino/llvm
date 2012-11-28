#include <iostream>
#include <sstream>
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
#include <llvm/NoCryptoFA/PropagaMetadati.h>
#include <llvm/NoCryptoFA/TaggedData.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include <llvm/PassManager.h>
#include <llvm/IntrinsicInst.h>

using namespace llvm;
using namespace std;


char llvm::PropagaMetadati::ID = 1;
PropagaMetadati* llvm::createPropagaMetadatiPass()
{
	initializePropagaMetadatiPass(*PassRegistry::getPassRegistry());
	return new PropagaMetadati();
}
static void addPropagaMetadatiPass(const PassManagerBuilder& Builder,
                                   PassManagerBase& PM)
{
	std::cerr << "Registro?\n";
	PM.add(createPropagaMetadatiPass());
	std::cerr << "Registrato\n";
}
void PropagaMetadati::registerPass(PassManagerBuilder& pm)
{
	std::cerr << "RP?\n";
	pm.addExtension(pm.EP_EarlyAsPossible, addPropagaMetadatiPass);
	pm.addGlobalExtension(pm.EP_OptimizerLast, addPropagaMetadatiPass);
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
static void addMetaMark(Instruction* ptr, std::string mark)
{
	if(hasMetaMark(ptr, mark)) { return; }
	string marks = readMetaMark(ptr);
	stringstream ss("");
	ss << marks << " " << mark;
	MDString* rec = MDString::get(ptr->getContext(), ss.str());
	ptr->setMetadata("MetaMark", MDNode::get(ptr->getContext(), ArrayRef<Value*>(rec)));
}
bool PropagaMetadati::runOnFunction(llvm::Function& F)
{
	llvm::raw_fd_ostream fd(2, false);
	llvm::Instruction* latest_status = NULL;
	TaggedData td = getAnalysis<TaggedData>();
	for(llvm::Function::iterator BB = F.begin(),
	    FE = F.end();
	    BB != FE;
	    ++BB) {
		for( llvm::BasicBlock::iterator i = BB->begin(); i != BB->end(); i++) {
			if(isa<llvm::DbgInfoIntrinsic>(i)) {continue;}
			llvm::NoCryptoFA::InstructionMetadata* md = td.getMD(i);
			if(td.isMarkedAsStatus(i)) {
				latest_status = i;
			}
			if(md->isAKeyOperation && !md->isAKeyStart) {
				addMetaMark(i, "OPchiave");
			}
			if(md->isSbox) {
				addMetaMark(i, "sbox");
			}
			if(md->hasMetPlaintext) {
				addMetaMark(i, "plain");
			}
			/*if(md->isAKeyOperation  && isa<llvm::StoreInst>(i)) {
			    for(auto o = i->op_begin();o != i->op_end(); o++ ){
			        MDString* rec = MDString::get(BB->getContext(), "OPchiave");
			        if(isa<Instruction>(o)){
			        (cast<llvm::Instruction>(o))->setMetadata("MetaMark", MDNode::get(BB->getContext(), ArrayRef<Value*>(rec)));
			        }
			    }
			 }*/
		}
	}
	return false;
}

void PropagaMetadati::getAnalysisUsage(llvm::AnalysisUsage& AU) const
{
	// Normally here we have to require analysis -- AU.addRequired -- and declare
	// preserved analysis -- AU.setPreserved. However, this pass does no require
	// any analysis and potentially invalidates all analysis. The default
	// behaviour is to invalidate all analysis.
	AU.addRequired<TaggedData>();
}


// The INITIALIZE_PASS_{BEGIN,END} macros generates some functions that can be
// used to register the pass to the LLVM pass registry.
// Parameters:
//
// HelloLLVM: pass class name
// "hello-llvm": command line switch to enable pass
// "Build an hello world": pass description
// false: the pass doesn't look only at the CFG
// false: the pass isn't an analysis.
INITIALIZE_PASS_BEGIN(PropagaMetadati,
                      "propagametadati",
                      "propagametadati",
                      false,
                      false)
INITIALIZE_PASS_DEPENDENCY(TaggedData)

INITIALIZE_PASS_END(PropagaMetadati,
                    "propagametadati",
                    "propagametadati",
                    false,
                    false)
