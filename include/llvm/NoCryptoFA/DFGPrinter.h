#pragma once
#include <llvm/Pass.h>
#include "llvm/Function.h"
#include <llvm/Support/GraphWriter.h>
#include <llvm/ADT/GraphTraits.h>
#include <map>
namespace llvm
{
	class MyNodeType
	{
		public:
			std::string name;
			NoCryptoFA::InstructionMetadata* md;
			std::set<MyNodeType*> children;
			std::set<MyNodeType*> subnodes; //in sostituzione temporanea di un iteratore intelligente che visita tutti i sottonodi
			static MyNodeType* rootnode;
			bool hasToBeProtected;
			MyNodeType(std::string n): children(), subnodes() {
				name = n;
				md = NULL;
			}
			void addChildren(MyNodeType* nuovo);


	};
	void initializeDFGPrinterPass(PassRegistry& Registry);

	class DFGPrinter : public llvm::ModulePass
	{
		public:
			static char ID;
			DFGPrinter() : llvm::ModulePass(ID), instrnodemap() {
				initializeDFGPrinterPass(*PassRegistry::getPassRegistry());
				rootptr = new MyNodeType("root");
				MyNodeType::rootnode = rootptr;
			}
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
	DFGPrinter* createDFGPrinterPass();
}
