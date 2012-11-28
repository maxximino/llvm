#include <sstream>
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
#include <llvm/Support/CommandLine.h>
#include <llvm/IntrinsicInst.h>
#include <llvm/Transforms/Utils/Cloning.h>

using namespace llvm;
using namespace std;
static cl::opt<unsigned int>
MaskingOrder("nocryptofa-masking-order", cl::init(1), cl::ValueRequired,
             cl::desc("NoCryptoFA Masking order"));


namespace llvm
{

	char InstructionReplace::ID = 178;

} // End anonymous namespace.
void BuildMetadata(Value* _newInstruction, Instruction* oldInstruction, NoCryptoFA::InstructionMetadata::InstructionSource origin);
vector<Value*> MaskValue(Value* ptr, Instruction* relativepos);
llvm::Function& GetRandomFn(llvm::Module* Mod, int size);
void annota(Value* cosa, std::string commento);
#include "MaskTraits.h"

std::map<Function*, Function*> InstructionReplace::maskedfn;
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
	RandTy = llvm::FunctionType::get(llvm::Type::getInt32Ty(Ctx), false);
#else
#error "Architecture not supported"
#endif
	llvm::Constant* FunSym = Mod->getOrInsertFunction("rand", RandTy);
	return *llvm::cast<llvm::Function>(FunSym);
}

llvm::Function& GetRandomFn(llvm::Module* Mod, int size)
{
	stringstream ss("");
	ss << "__getrandom" << size;
	llvm::Function* Fun = Mod->getFunction(ss.str());
	if(Fun && !Fun->isDeclaration()) {
		return *Fun;
	}
	llvm::LLVMContext& Ctx = Mod->getContext();
	llvm::Constant* FunSym;
	FunSym = Mod->getOrInsertFunction(ss.str(),
	                                  llvm::Type::getIntNTy(Ctx, size),
	                                  NULL);
	Fun = llvm::cast<llvm::Function>(FunSym);
	llvm::BasicBlock* Entry = llvm::BasicBlock::Create(Ctx, "entry", Fun);
	llvm::Function& rand = GetRand(Mod);
	llvm::IRBuilder<> ib = llvm::IRBuilder<>(Entry->getContext());
	ib.SetInsertPoint(Entry);
	CallInst* rndval = ib.CreateCall(&rand);
	Value* retval = rndval;
	if(size < 32) {
		retval = ib.CreateTrunc(rndval, llvm::Type::getIntNTy(Ctx, size));
	}
	/*
	  Value* addr = ib.CreateIntToPtr(ConstantInt::get(Type::getInt32Ty(Ctx),12345,false),Type::getInt32PtrTy(Ctx));
	  LoadInst* rndval = ib.CreateLoad(addr,true);*/
	llvm::ReturnInst::Create(Ctx, retval, Entry);
	//llvm::ReturnInst::Create(Ctx, ConstantInt::get(Type::getIntNTy(Ctx, size), 4, false) , Entry);
	return *Fun;
}
void annota(Value* cosa, std::string commento)  // roba da primo debug, niente di serio. Destinato a sparire.
{
	Instruction* i;
	if((i = dyn_cast<Instruction>(cosa))) {
		i->setMetadata(commento, llvm::MDNode::get(i->getContext(), llvm::ArrayRef<llvm::Value*>(MDString::get(i->getContext(), commento))));
	}
}
void SetInsertionPoint(bool after, IRBuilder<>& ib, Instruction* ptr)
{
	if(!after) {
		ib.SetInsertPoint(ptr);
		return;
	}
	BasicBlock* BB = ptr->getParent();
	llvm::BasicBlock::iterator i;
	for( i = BB->begin(); i != BB->end(); i++) {
		if(i.getNodePtrUnchecked() == ptr) { break; }
	}
	i++;
	ib.SetInsertPoint(i);
}
void BuildMetadata(Value* _newInstruction, Instruction* oldInstruction, NoCryptoFA::InstructionMetadata::InstructionSource origin)
{
	Instruction* newInstruction = cast<Instruction>(_newInstruction);
	NoCryptoFA::InstructionMetadata* newMd = new NoCryptoFA::InstructionMetadata(newInstruction);
	newMd->origin = origin;
	newMd->hasToBeProtected = false;
	if(oldInstruction != NULL) {
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

vector<Value*> MaskValue(Value* ptr, Instruction* relativepos)
{
	bool after = false;
	if(isa<Instruction>(ptr)) {
		NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[cast<Instruction>(ptr)];
		if(md->MaskedValues.size() > 0) { return md->MaskedValues; }
		relativepos = cast<Instruction>(ptr);
		after = true;
	}
	int size = ptr->getType()->getScalarSizeInBits();
	llvm::Function& rand = GetRandomFn(relativepos->getParent()->getParent()->getParent(), size);
	llvm::IRBuilder<> ib = llvm::IRBuilder<>(relativepos->getContext());
	SetInsertionPoint(after, ib, relativepos);
	/* Applico la maschera
	   t = val;
	   a[0] = rand()
	   t = t XOR a[0];
	   a[1] = rand();
	   t = t XOR a[1];
	   //ecc
	   a[n+1]=t;
	    */
	vector<Value*> v;
	llvm::Value* latestXor = ptr;
	for(unsigned int i = 0; i < MaskingOrder; i++) {
		llvm::Value* rnd = ib.CreateCall(&rand);
		v.push_back(rnd);
		annota(rnd, "ins_maschera");
		BuildMetadata(rnd, dyn_cast<Instruction>(ptr), NoCryptoFA::InstructionMetadata::CREATE_MASK);
		latestXor = ib.CreateXor(latestXor, rnd);
		annota(latestXor, "ins_maschera");
		BuildMetadata(latestXor, dyn_cast<Instruction>(ptr), NoCryptoFA::InstructionMetadata::CREATE_MASK);
	}
	v.push_back(latestXor);
	if(isa<Instruction>(ptr)) {
		NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[cast<Instruction>(ptr)];
		md->MaskedValues = v;
	}
	return v;
}

void InstructionReplace::phase1(llvm::Module& M)
{
	for(llvm::Module::iterator F = M.begin(), ME = M.end(); F != ME; ++F) {
		for(llvm::Function::iterator BB = F->begin(),
		    FE = F->end();
		    BB != FE;
		    ++BB) {
			TaggedData& td = getAnalysis<TaggedData>(*F);
			if(!td.functionMarked(F)) {continue;}
			cerr << "phase1 " << F->getName().str() << endl;
			CalcDFG& cd = getAnalysis<CalcDFG>(*F);
			for( llvm::BasicBlock::iterator i = BB->begin(); i != BB->end(); i++) {
				if(isa<llvm::DbgInfoIntrinsic>(i)) {continue;}
				if(!cd.shouldBeProtected(i)) { continue; }
				cerr << ".";
				NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[i];
				if(md->origin != NoCryptoFA::InstructionMetadata::ORIGINAL_PROGRAM && md->origin != NoCryptoFA::InstructionMetadata::MASKED_FUNCTION) { continue; }
				bool masked = false;
#define CHECK_TYPE(type) else if(isa<type>(i)) masked=MaskTraits<type>::replaceWithMasked(cast<type>(i),md)
				if(0) {}
				CHECK_TYPE(BinaryOperator);
				CHECK_TYPE(CastInst);
				CHECK_TYPE(GetElementPtrInst);
				CHECK_TYPE(LoadInst);
				CHECK_TYPE(StoreInst);
				CHECK_TYPE(CallInst);
				CHECK_TYPE(SelectInst);
				else { masked = MaskTraits<Instruction>::replaceWithMasked(i, md); }
#undef CHECK_TYPE
				if(masked) {
					cerr << "|";
					deletionqueue.insert(i);
					md->hasBeenMasked = true;
				}
			}
		}
	}
}
void InstructionReplace::Unmask(Instruction* ptr)
{
	NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[ptr];
	if(md->unmasked_value != NULL) { return; }
	llvm::IRBuilder<> ib = llvm::IRBuilder<>(ptr->getContext());
	SetInsertionPoint(true, ib, ptr); //NO, dopo l'ultimo masked
	llvm::Value*  v = md->MaskedValues[0];
	for(unsigned int i = 1; i <= MaskingOrder; i++) {
		v = ib.CreateXor(v, md->MaskedValues[i]);
		annota(v, "rimozi_maschera");
		BuildMetadata(v, ptr, NoCryptoFA::InstructionMetadata::REMOVE_MASK);
	}
	md->unmasked_value = cast<Instruction>(v);
	//fixNextUses(ptr,v);
	llvm::raw_fd_ostream rerr(2, false);
	cerr << "Rimuovo maschera di ";
	rerr << *ptr;
	cerr << endl;
	ptr->replaceAllUsesWith(v);
}
void InstructionReplace::phase2(llvm::Module& M)
{
	for(llvm::Module::iterator F = M.begin(), ME = M.end(); F != ME; ++F) {
		for(llvm::Function::iterator BB = F->begin(),
		    FE = F->end();
		    BB != FE;
		    ++BB) {
			TaggedData& td = getAnalysis<TaggedData>(*F);
			if(!td.functionMarked(F)) {continue;}
			for( llvm::BasicBlock::iterator i = BB->begin(); i != BB->end(); i++) {
				NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[i];
				if(!md->hasBeenMasked) { continue; }
				for(Instruction::use_iterator u = i->use_begin(); u != i->use_end(); ++u) {
					Instruction* utilizzatore = cast<Instruction>(u.getUse().getUser());
					NoCryptoFA::InstructionMetadata* usemd = NoCryptoFA::known[utilizzatore];
					if(usemd->MaskedValues.empty()) {
						Unmask(i);
					}
				}
			}
		}
	}
}
void InstructionReplace::phase3(llvm::Module& M)
{
	int delcnt;
	while(!deletionqueue.empty()) {
		delcnt = 0;
	for(Instruction * i : deletionqueue) {
			if(i->use_empty()) {
				delcnt++;
				i->eraseFromParent();
				deletionqueue.erase(i);
			}
		}
		//assert(delcnt > 0 && "Altrimenti resto in un loop infinito!");
		if(delcnt == 0) {
			cerr <<  deletionqueue.size() << " unmasked instructions survived :( They are:" << endl;
		for(Instruction * survivor : deletionqueue) {
				errs() << *survivor << "\n";
			}
			break;
		}
	}
}
void setFullyMasked(Function* F)
{
	for(llvm::Function::iterator BB = F->begin(),
	    FE = F->end();
	    BB != FE;
	    ++BB) {
		for( llvm::BasicBlock::iterator i = BB->begin(); i != BB->end(); i++) {
			NoCryptoFA::InstructionMetadata* md = llvm::NoCryptoFA::InstructionMetadata::getNewMD(i);
			md->isAKeyOperation = true;
			md->isAKeyStart = false;
			md->hasToBeProtected = true;
			md->hasMetPlaintext = true;
			md->origin = NoCryptoFA::InstructionMetadata::MASKED_FUNCTION;
		}
	}
}
void InstructionReplace::cloneFunctions(llvm::Module& M)
{
	for(llvm::Module::iterator F = M.begin(), ME = M.end(); F != ME; ++F) {
		if(!F->getFnAttributes().hasAttribute(Attributes::AttrVal::MaskedCopy)) { continue; }
		cerr << "Masking " << F->getName().str();
		assert(F->arg_size() == 1);
		Type* rettype = F->getReturnType();
		auto args = F->arg_begin();
		Argument* a1 = args++;
		Type* paramtype = a1->getType();
		assert(isa<IntegerType>(rettype));
		assert(isa<IntegerType>(paramtype));
		stringstream ss("");
		ss << "__masked__" << F->getName().str();
		llvm::LLVMContext& Ctx = M.getContext();
		llvm::Constant* FunSym;
		std::vector<Type*> paramtypes;
		for(unsigned int i = 0; i <= MaskingOrder; i++) { paramtypes.push_back(paramtype); } //TODO riducibile?
		for(unsigned int i = 0; i <= MaskingOrder; i++) { paramtypes.push_back(rettype->getPointerTo()); }
		llvm::FunctionType* ftype = llvm::FunctionType::get(llvm::Type::getVoidTy(Ctx), llvm::ArrayRef<Type*>(paramtypes), false);
		FunSym = M.getOrInsertFunction(ss.str(), ftype);
		llvm::Function* newF = llvm::cast<llvm::Function>(FunSym);
		maskedfn[F] = newF;
		SmallVector<llvm::ReturnInst*, 4> rets;
		ValueToValueMapTy vmap;
		llvm::BasicBlock* Entry = llvm::BasicBlock::Create(Ctx, "entry", newF);
		llvm::IRBuilder<> ib_entry = llvm::IRBuilder<>(Entry->getContext());
		ib_entry.SetInsertPoint(Entry);
		NoCryptoFA::InstructionMetadata* md = new NoCryptoFA::InstructionMetadata();
		md->hasBeenMasked = true;
		auto arg = newF->arg_begin();
		for(unsigned int i = 0; i <= MaskingOrder; i++) { md->MaskedValues.push_back(arg++); }
		Value* fakevalue = ib_entry.CreateAdd(md->MaskedValues[0], md->MaskedValues[1]);
		md->my_instruction = cast<Instruction>(fakevalue);
		NoCryptoFA::known[ md->my_instruction] = md;
		deletionqueue.insert(md->my_instruction);
		vmap.insert(std::make_pair(a1, fakevalue));
		CloneFunctionInto(newF, F, vmap, true, rets);
		ib_entry.CreateBr(cast<BasicBlock>(vmap[&F->getEntryBlock()]));
		AttrBuilder toremove;
		toremove.addAttribute(Attributes::AttrVal::MaskedCopy);
		toremove.addAttribute(Attributes::AttrVal::ZExt);
		toremove.addAttribute(Attributes::AttrVal::SExt);
		toremove.addAttribute(Attributes::AttrVal::NoAlias);
		toremove.addAttribute(Attributes::AttrVal::NoCapture);
		toremove.addAttribute(Attributes::AttrVal::StructRet);
		toremove.addAttribute(Attributes::AttrVal::ByVal);
		toremove.addAttribute(Attributes::AttrVal::Nest);
		newF->removeFnAttr(Attributes::get(Ctx, toremove));
		newF->removeAttribute(0, Attributes::get(Ctx, toremove)); //Thr..ehm,Zero is a magic number! Toglie gli attributi zeroext e simili dal valore di ritorno.
		/*for(auto it = rets.begin(); it!=rets.end();++it){
		    llvm::ReturnInst* ri = llvm::ReturnInst::Create(newF->getContext());
		    ri->insertBefore(*it);
		    (*it)->eraseFromParent();
		}*/
		TaggedData& td = getAnalysis<TaggedData>(*F);
		td.markFunction(newF);
		setFullyMasked(newF);
	}
}
void InstructionReplace::insertStores(llvm::Module& M)
{
	for(llvm::Module::iterator F = M.begin(), ME = M.end(); F != ME; ++F) {
		if(!F->getFnAttributes().hasAttribute(Attributes::AttrVal::MaskedCopy)) { continue; }
		llvm::Function* Fun = maskedfn[F];
		vector<Value*> outputshares;
		ReturnInst* tbd = NULL;
		auto arg = Fun->arg_begin();
		for(unsigned int i = 0; i <= MaskingOrder; i++) { ++arg; }
		for(unsigned int i = 0; i <= MaskingOrder; i++) { outputshares.push_back(arg++); }
		for(llvm::Function::iterator BB = Fun->begin(),
		    FE = Fun->end();
		    BB != FE;
		    ++BB) {
			for( llvm::BasicBlock::iterator i = BB->begin(); i != BB->end(); i++) {
				if(tbd != NULL) {tbd->eraseFromParent(); tbd = NULL;}
				if(!isa<ReturnInst>(i)) {continue;}
				ReturnInst* ri = cast<ReturnInst>(i);
				IRBuilder<> ib = llvm::IRBuilder<>(BB->getContext());
				ib.SetInsertPoint(i);
				vector<Value*> shares = MaskValue(ri->getReturnValue(), ri);
				for(unsigned int i = 0; i <= MaskingOrder; i++) { ib.CreateStore(shares[i], outputshares[i]); }
				ib.CreateRetVoid();
				tbd = ri;
			}
		}
		if(tbd != NULL) {tbd->eraseFromParent(); tbd = NULL;}
	}
}

bool InstructionReplace::runOnModule(llvm::Module& M)
{
	cloneFunctions(M);
	phase1(M);
	insertStores(M);
	phase2(M);
	phase3(M);
	return true;
}

void InstructionReplace::getAnalysisUsage(llvm::AnalysisUsage& AU) const
{
	AU.addRequired<DominatorTree>();
	AU.addRequired<TaggedData>();
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


