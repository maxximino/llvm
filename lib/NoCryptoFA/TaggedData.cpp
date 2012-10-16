#include "llvm/NoCryptoFA/TaggedData.h"
#include "llvm/Function.h"
#include "llvm/Support/ErrorHandling.h"
#include <llvm/Metadata.h>

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
			isAKeyOperation(I.getNodePtrUnchecked());
		}
	}
	return false;
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
bool TaggedData::isAKeyOperation(llvm::Instruction* ptr)
{
	if (markedAsKey.find(ptr) != markedAsKey.end()) { return true; }
	if (notMarkedAsKey.find(ptr) != notMarkedAsKey.end()) { return false; }
	if( !std::string("chiave").compare(readMetaMark(ptr))) {
		markedAsKey.insert(ptr);
		return true;
	}
	for(unsigned int i = 0; i < ptr->getNumOperands(); i++) {
		Value* v = ptr->getOperand(i);
		if(isa<Instruction>(*v)) {
			if(isAKeyOperation(&cast<Instruction>(*v))) {
				markedAsKey.insert(ptr);
				return true;
			}
		}
	}
	notMarkedAsKey.insert(ptr);
	return false;
}

bool TaggedData::isMarkedAsKey(llvm::Instruction* ptr)
{
	return (markedAsKey.find(ptr) != markedAsKey.end());
}
void TaggedData::getAnalysisUsage(llvm::AnalysisUsage& AU) const
{
	// This is an analysis, nothing is modified, so other analysis are preserved.
//	AU.setPreservesAll();
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
