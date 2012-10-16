#include <iostream>
#include <map>
#include "llvm/Constants.h"
#include "llvm/Instructions.h"
#include "llvm/Instruction.h"
#include "llvm/Analysis/DOTGraphTraitsPass.h"
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
#include <llvm/Support/GraphWriter.h>
#include <llvm/ADT/GraphTraits.h>
#include <llvm/NoCryptoFA/TaggedData.h>
#include <llvm/NoCryptoFA/DFGPrinter.h>
using namespace llvm;
using namespace std;
template <typename tipo>
bool exists_in_vector(std::vector<tipo>* v, tipo el)
{
	for(typename std::vector<tipo>::iterator it = v->begin(); it != v->end(); ++it) {
		if(*it == el) { return true; }
	}
	return false;
}
namespace llvm
{

      	template<> struct GraphTraits<MyNodeType*> {
		typedef MyNodeType NodeType;
		typedef std::vector<MyNodeType*>::iterator nodes_iterator;
		typedef std::vector<MyNodeType*>::iterator ChildIteratorType;
		static NodeType* getEntryNode(MyNodeType* n) { return n; }
		static inline nodes_iterator nodes_begin(NodeType* N) {
			return N->subnodes.begin();
		}
		static inline nodes_iterator nodes_end(NodeType* N) {
			return N->subnodes.end();
		}
		static inline ChildIteratorType child_begin(NodeType* N) { return N->children.begin();}
		static inline ChildIteratorType child_end(NodeType* N) { return N->children.end();}
	};


	template<>
	struct DOTGraphTraits<MyNodeType*> : public DefaultDOTGraphTraits {

		DOTGraphTraits (bool isSimple = false)
			: DefaultDOTGraphTraits(isSimple) {}

		std::string getNodeLabel(MyNodeType* Node, MyNodeType* Graph) {
			return Node->name;
		}

		std::string getNodeAttributes(MyNodeType* Node,
		                              const MyNodeType* Graph) {
			if(Node->key) {
				return "style=filled,color=blue";
			}
			return "";
		}
		template<typename EdgeIter>
		std::string getEdgeAttributes(const MyNodeType* Node, EdgeIter EI,
		                              const MyNodeType* Graph) {
			if(Node->key) {
				return "color=blue";
			}
			return "";
		}
	};


	
	char DFGPrinter::ID = 2;

}
			void MyNodeType::addSubNode(MyNodeType* nuovo) {
				if(!exists_in_vector(&subnodes, nuovo)) {
					subnodes.push_back(nuovo);
				}
				for(std::vector<MyNodeType*>::iterator it = parents.begin(); it != parents.end(); ++it) {
					(*it)->addSubNode(nuovo);
				}
			}
			void MyNodeType::addChildren(MyNodeType* nuovo) {
				if(!exists_in_vector(&children, nuovo)) {
					children.push_back(nuovo);
				}
				if(!exists_in_vector(&nuovo->parents, this)) {
					nuovo->parents.push_back(this);
				}
				addSubNode(nuovo);
				for(std::vector<MyNodeType*>::iterator it = nuovo->subnodes.begin(); it != nuovo->subnodes.end(); ++it) {
					addSubNode(*it);
				}
			}

void DFGPrinter::print(raw_ostream& OS, const Module* ) const
{
	MyNodeType root("radice");
	MyNodeType* ptr = new MyNodeType("uno");
	ptr->addChildren(new MyNodeType("tre_sottouno"));
	root.addChildren(ptr);
	root.addChildren(new MyNodeType("due"));
	GraphWriter<MyNodeType*> gw(OS, rootptr, true);
	gw.writeGraph("gt");
}

bool DFGPrinter::runOnModule(llvm::Module& M)
{
	MyNodeType* cur;
	bool added;
	for(llvm::Module::iterator F = M.begin(), ME = M.end(); F != ME; ++F) {
		MyNodeType* me = new MyNodeType(F->getName());
		rootptr->addChildren(me);
		instrnodemap.clear();
		for(llvm::Function::iterator BB = F->begin(),
		    FE = F->end();
		    BB != FE;
		    ++BB) {
			TaggedData td = getAnalysis<TaggedData>(*F);
			for( llvm::BasicBlock::iterator i = BB->begin(); i != BB->end(); i++) {
				cur = new MyNodeType(i->getOpcodeName());
				instrnodemap.insert(std::make_pair<Instruction*, MyNodeType*>(i, cur)); //verificare che non ci sia
				if(td.isMarkedAsKey(i)) {
					cur->key = true;
				}
				added = false;
				for(User::const_op_iterator it = i->op_begin(); it != i->op_end(); ++it) {
					if(isa<Instruction>(it->get())) {
						instrnodemap.at(cast<Instruction>(it->get()))->addChildren(cur);
						added = true; //verificare che ci sia....
					}
				}
				if(!added) { me->addChildren(cur); }
			}
		}
	}
	return true;
}


void DFGPrinter::getAnalysisUsage(llvm::AnalysisUsage& AU) const
{
	// Normally here we have to require analysis -- AU.addRequired -- and declare
	// preserved analysis -- AU.setPreserved. However, this pass does no require
	// any analysis and potentially invalidates all analysis. The default
	// behaviour is to invalidate all analysis.
	AU.addRequired<TaggedData>();
}


DFGPrinter* llvm::createDFGPrinterPass()
{
	return new DFGPrinter();
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
INITIALIZE_PASS_BEGIN(DFGPrinter,
                      "dfgprint",
                      "dfgprint",
                      false,
                      false)
INITIALIZE_PASS_END(DFGPrinter,
                    "dfgprint",
                    "dfgprint",
                    false,
                    false)
