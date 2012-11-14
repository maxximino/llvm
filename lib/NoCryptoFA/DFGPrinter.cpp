#include <iostream>
#include <map>
#include <list>
#include <fstream>
#include <sstream>
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
#include <llvm/IntrinsicInst.h>
#include <llvm/NoCryptoFA/All.h>

using namespace llvm;
using namespace std;

MyNodeType* MyNodeType::rootnode = NULL;
namespace llvm
{

	template<> struct GraphTraits<MyNodeType*> {
		typedef MyNodeType NodeType;

		typedef std::set<MyNodeType*>::iterator nodes_iterator;
		typedef std::set<MyNodeType*>::iterator ChildIteratorType;
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
            if(Node->md){
                switch(Node->md->origin){  //Sta diventando piu spaghettoso di quanto sia giusto. Refactor?
                  case NoCryptoFA::InstructionMetadata::ORIGINAL_PROGRAM:
                    if(Node->md->hasToBeProtected) {
                        return "style=filled,color=\"#f458f4\"";
                    } else if(Node->md->isAKeyOperation) {
                        return "style=filled,color=\"#58faf4\"";
                    }
                    break;
                  case NoCryptoFA::InstructionMetadata::CREATE_MASK:
                          return "style=filled,color=\"#181af4\"";
                    break;
                case NoCryptoFA::InstructionMetadata::REMOVE_MASK:
                        return "style=filled,color=\"#ff1a04\"";
                  break;
                default:
                        return "style=filled,color=\"#18fa04\"";
                  break;
                }
            }
			return "style=filled,color=\"#e0e0e0\"";
		}
		template<typename EdgeIter>
		std::string getEdgeAttributes(const MyNodeType* Node, EdgeIter EI,
		                              const MyNodeType* Graph) {
            if(Node->md){
                if(Node->md->hasToBeProtected) {
                    return "color=\"#f458f4\"";
                } else if(Node->md->isAKeyOperation) {
                    return "color=\"#58faf4\"";
                }
            }
			return "color=\"#e0e0e0\"";
		}
	};



	char DFGPrinter::ID = 22;

}
void MyNodeType::addChildren(MyNodeType* nuovo)
{
	children.insert(nuovo);
	MyNodeType::rootnode->subnodes.insert(nuovo);
}

void DFGPrinter::print(raw_ostream& OS, const Module* ) const
{
	GraphWriter<MyNodeType*> gw(OS, rootptr, true);
	gw.writeGraph("");
}
void replaceAll(std::string& str, const std::string& from, const std::string& to)
{
	if(from.empty())
	{ return; }
	size_t start_pos = 0;
	while((start_pos = str.find(from, start_pos)) != std::string::npos) {
		str.replace(start_pos, from.length(), to);
		start_pos += to.length(); // In case 'to' contains 'from', like replacing 'x' with 'yx'
	}
}
template <int SIZE>
string printvec_small(std::vector<bitset<SIZE> >& v)
{
	stringstream ss("");
	size_t max = 0;
for(bitset<SIZE> b : v) {
		max = std::max(max, b.count());
	}
	ss << "max:" << max << "bit";
	return ss.str();
}
template <int SIZE>
string printvec_large(std::vector<bitset<SIZE> >& v)
{
	stringstream ss("");
	ss << "<div class=\"matrice\">";
for(bitset<SIZE> b : v) {
		ss << "<div class=\"row\">";
		for(unsigned int s = 0; s < b.size(); ++s) {
			if(b[s]) {
				ss << "<b></b>";
			} else {
				ss << "<i></i>";
			}
		}
		ss << "</div>";
	}
	ss << "</div>";
	return ss.str();
}

template <int SIZE>
string printbs_small(bitset<SIZE>& bs)
{
	stringstream ss("");
	ss << bs.count();
	return ss.str();
}
template <int SIZE>
string printbs_large(bitset<SIZE>& bs)
{
	string in = bs.to_string();
	/*in = string ( in.rbegin(), in.rend() );
	in = string("-").append(in);
	string::size_type last= in.find_last_not_of('0');
	if(last != in.npos){
	    in=in.erase(1+last);
	}*/
	replaceAll(in, "00000000", "a");
	replaceAll(in, "11111111", "A");
	/*replaceAll(in,"aaaaaaaa","b");
	replaceAll(in,"AAAAAAAA","B");
	replaceAll(in,"bbbbbbbb","c");
	replaceAll(in,"BBBBBBBB","C");*/
	return in.append("-");
}

void outFile(std::string nodename, std::string contenuto)
{
	string fname("out.dir/");
	ofstream out(fname.append(nodename));
	out << contenuto;
}
bool DFGPrinter::runOnModule(llvm::Module& M)
{
	MyNodeType* cur;
	bool added;
	multimap<Instruction*, MyNodeType*> future_edges;
	for(llvm::Module::iterator F = M.begin(), ME = M.end(); F != ME; ++F) {
		MyNodeType* me = new MyNodeType(F->getName());
		rootptr->addChildren(me);
		instrnodemap.clear();
		future_edges.clear();
		for(llvm::Function::iterator BB = F->begin(),
		    FE = F->end();
		    BB != FE;
		    ++BB) {
			CalcDFG& cd = getAnalysis<CalcDFG>(*F);
			TaggedData& td = getAnalysis<TaggedData>(*F);
			if(!td.functionMarked(&(*F))) { continue; }
			for( llvm::BasicBlock::iterator i = BB->begin(); i != BB->end(); i++) {
				if(isa<llvm::DbgInfoIntrinsic>(i)) {continue;}
				std::string outp;
				llvm::raw_string_ostream os (outp);
				std::stringstream boxcont("");
				std::stringstream fname("");
				boxcont << "<html><head><LINK REL=StyleSheet HREF=\"../node.css\" TYPE=\"text/css\"/></head><body><pre>";
				os << *i << "\n";
				llvm::NoCryptoFA::InstructionMetadata* md = cd.getMD(i);
				if(md->isAKeyOperation) {
					if(md->isAKeyStart) {
						os << "KeyStart" << "\n";
					}
					os << "<Own:" << printbs_small<MAX_KEYBITS>(md->own) << ",Pre:" << printvec_small<MAX_KEYBITS>(md->pre) << ",Post_sum:" << printbs_small<MAX_OUTBITS>(md->post_sum) << ",Post_min:" << printbs_small<MAX_OUTBITS>(md->post_min) << ">" << "\n";
				}
				boxcont << os.str() << "\n";
				if(md->hasMetPlaintext) {
					boxcont << "Ha incontrato il plaintext\n";
				} else {
					boxcont << "Non ha incontrato il plaintext\n";
				}
                switch(md->origin){
                case NoCryptoFA::InstructionMetadata::AND_MASKED:
                    boxcont << "Origine istruzione: Mascheratura di un AND\n";break;
                case NoCryptoFA::InstructionMetadata::CREATE_MASK:
                    boxcont << "Origine istruzione: Inserimento maschera\n";break;
                case NoCryptoFA::InstructionMetadata::SHIFT_MASKED:
                    boxcont << "Origine istruzione: Mascheratura di uno shift\n";break;
                case NoCryptoFA::InstructionMetadata::ORIGINAL_PROGRAM:
                    boxcont << "Origine istruzione: Programma originale\n";break;
                case NoCryptoFA::InstructionMetadata::REMOVE_MASK:
                    boxcont << "Origine istruzione: Rimozione maschera\n";break;
                    case NoCryptoFA::InstructionMetadata::XOR_MASKED:
                    boxcont << "Origine istruzione: Mascheratura di uno XOR\n";break;
                    case NoCryptoFA::InstructionMetadata::CAST_MASKED:
                    boxcont << "Origine istruzione: Mascheratura di un CAST\n";break;
                }
				boxcont << "Value size:" << md->pre.size() << "\n";
				if(!i->getDebugLoc().isUnknown()) {
					boxcont << "Nel sorgente a riga:" << i->getDebugLoc().getLine() << " colonna:" << i->getDebugLoc().getCol()  << "\n";
				}
				if(md->isAKeyOperation) {
					boxcont << "Own:" << printbs_large<MAX_KEYBITS>(md->own) << "\nPre:" << printvec_large<MAX_KEYBITS>(md->pre) << "\nPost_sum:" << printbs_large<MAX_OUTBITS>(md->post_sum) << "\nPost_min:" << printbs_large<MAX_OUTBITS>(md->post_min);
				}
				cur = new MyNodeType(os.str());
				fname << "Node" << cur << ".html";
				boxcont << "</pre></body></html>";
				outFile(fname.str(), boxcont.str());
				instrnodemap.insert(std::make_pair(i, cur));
				pair<multimap<Instruction*, MyNodeType*>::iterator, multimap<Instruction*, MyNodeType*>::iterator> range = future_edges.equal_range(i);
				for(multimap<Instruction*, MyNodeType*>::iterator it = range.first; it != range.second; ++it) {
					cur->addChildren(it->second);
				}
				cur->md = td.getMD(i);
				added = false;
				if(isa<PHINode>(i)) {
					PHINode* p = cast<PHINode>(i);
					for(unsigned int n = 0; n < p->getNumIncomingValues(); n++) {
						if(isa<Instruction>(p->getIncomingValue(n))) {
							Instruction* _it = cast<Instruction>(p->getIncomingValue(n));
							if(instrnodemap.find(_it) != instrnodemap.end()) {
								instrnodemap.at(_it)->addChildren(cur);
								added = true;
							} else {
								future_edges.insert(std::make_pair(_it, cur));
								// added=true; // Rischio "isole" sconnesse, che non apparirebbero nel grafo.
							}
						}
					}
				} else {
					for(User::const_op_iterator it = i->op_begin(); it != i->op_end(); ++it) {
						if(isa<Instruction>(it->get())) {
							Instruction* _it = cast<Instruction>(it->get());
							if(instrnodemap.find(_it) != instrnodemap.end()) {
								instrnodemap.at(_it)->addChildren(cur);
								added = true;
							} else {
								future_edges.insert(std::make_pair(_it, cur));
								// added=true; // Rischio "isole" sconnesse, che non apparirebbero nel grafo.
							}
						}
					}
				}
				if(!added) { me->addChildren(cur); }
			}
		}
	}
    return false;
}


void DFGPrinter::getAnalysisUsage(llvm::AnalysisUsage& AU) const
{
	// Normally here we have to require analysis -- AU.addRequired -- and declare
	// preserved analysis -- AU.setPreserved. However, this pass does no require
	// any analysis and potentially invalidates all analysis. The default
	// behaviour is to invalidate all analysis.
	AU.addRequired<TaggedData>();
	AU.addRequired<CalcDFG>();
	AU.setPreservesAll();
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
INITIALIZE_PASS_DEPENDENCY(TaggedData)
INITIALIZE_PASS_DEPENDENCY(CalcDFG)


INITIALIZE_PASS_END(DFGPrinter,
                    "dfgprint",
                    "dfgprint",
                    false,
                    false)
