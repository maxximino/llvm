#pragma once
#include <llvm/Pass.h>
#include "llvm/Function.h"
#include <llvm/Support/GraphWriter.h>
#include <llvm/ADT/GraphTraits.h>
#include <map>
namespace llvm{
  	class MyNodeType
	{
		public:
			std::string name;
			bool key;
			std::vector<MyNodeType*> children;
			std::vector<MyNodeType*> subnodes; //in sostituzione temporanea di un iteratore intelligente che visita tutti i sottonodi
			std::vector<MyNodeType*> parents;
			MyNodeType(std::string n): children(), subnodes(), parents() {
				name = n;
				key = false;
			}
			void addSubNode(MyNodeType* nuovo);
			void addChildren(MyNodeType* nuovo);


	};

	  class DFGPrinter : public llvm::ModulePass
	  {
		  public:
			  static char ID;
			  DFGPrinter() : llvm::ModulePass(ID), instrnodemap() { rootptr = new MyNodeType("root");}
			  virtual ~DFGPrinter() { delete rootptr;}
			  // This member function must implement the code of your pass.
			  virtual bool runOnModule(llvm::Module& M);

			  // The getAnalysisUsage allows to tell LLVM pass manager which analysis are
			  // used by the pass. It is also used to declare which analysis are preserved
			  // by the pass.
			  virtual void getAnalysisUsage(llvm::AnalysisUsage& AU) const;

			  virtual const char* getPassName() const {
				  return "DFGPrinter";
			  }
			  virtual void print(raw_ostream& OS, const Module*) const;

		  private:
			  std::map<Instruction*, MyNodeType*> instrnodemap;
			  MyNodeType* rootptr;

	  };
	  void initializeDFGPrinterPass(PassRegistry &Registry);
	  DFGPrinter* createDFGPrinterPass();
}
