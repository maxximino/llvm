#pragma once
#include <map>
#include <llvm/IRBuilder.h>
#include <llvm/Function.h>

using namespace std;
using namespace llvm;
struct GEPReplacer {
	protected:
		static map<pair<Function*, Type*>, vector<Value*> > shareTemps;

		static vector<Value*> getShareTemps(Type* t, Function* f) {
			auto key = std::make_pair(f, t);
			if(shareTemps.find(key) != shareTemps.end()) {
				return shareTemps[key];
			}
			vector<Value*> v;
			IRBuilder<> ib = IRBuilder<>(&f->getEntryBlock().front());
			v.resize(MaskingOrder + 1);
#define I(var,val) do {var=val; BuildMetadata(var, NULL, NoCryptoFA::InstructionMetadata::SBOX_MASKED);}while(0)
			for(unsigned int i = 0; i <= MaskingOrder; i++)  { I(v[i], ib.CreateAlloca(t)); }
#undef I
			shareTemps[key] = v;
			return v;
		}
		static llvm::Function& GetMaskingFn(llvm::Module* Mod, int size, int len) {
			int len_roundup = len;
			len_roundup |= len_roundup >> 1;
			len_roundup |= len_roundup >> 2;
			len_roundup |= len_roundup >> 4;
			len_roundup |= len_roundup >> 8;
			len_roundup |= len_roundup >> 16;
			/*
			post_sbox_s2 = rand_n1
			post_sbox_s3 = rand_n2
			for (i = 0; i<256; i++){
			sbox_masked[i^rand_v1^rand_v2]= sbox[i]^rand_n1^rand_n2
			}
			post_sbox_s1= sbox_masked[s1]
			*/
			stringstream ss("");
			ss << "__sboxmask" << size << "_" << len;
			llvm::Function* Fun = Mod->getFunction(ss.str());
			if(Fun && !Fun->isDeclaration()) {
				return *Fun;
			}
			llvm::LLVMContext& Ctx = Mod->getContext();
			llvm::Constant* FunSym;
			std::vector<Type*> paramtypes;
			paramtypes.push_back(llvm::ArrayType::get(llvm::Type::getIntNTy(Ctx, size), len)->getPointerTo());
			for(unsigned int i = 0; i <= MaskingOrder; i++) { paramtypes.push_back(llvm::Type::getInt64Ty(Ctx)); }
			for(unsigned int i = 0; i <= MaskingOrder; i++) { paramtypes.push_back(llvm::Type::getIntNPtrTy(Ctx, size)); }
			llvm::FunctionType* ftype = llvm::FunctionType::get(llvm::Type::getVoidTy(Ctx), llvm::ArrayRef<Type*>(paramtypes), false);
			FunSym = Mod->getOrInsertFunction(ss.str(), ftype);
			Fun = llvm::cast<llvm::Function>(FunSym);
			Function::arg_iterator args = Fun->arg_begin();
			Value* sboxptr = args++;
			sboxptr->setName("sboxptr");
			std::vector<Value*> inputshares;
			std::vector<Value*> outputshares;
			for(unsigned int i = 0; i <= MaskingOrder; i++) { inputshares.push_back(args++); }
			for(unsigned int i = 0; i <= MaskingOrder; i++) { outputshares.push_back(args++); }
			/*  %i.01 = phi i32 [ 0, %0 ], [ %3, %1 ]
			  %2 = tail call i32 (...)* @getchar() nounwind
			  %3 = add nsw i32 %i.01, 1
			  %exitcond = icmp eq i32 %3, 256
			  br i1 %exitcond, label %4, label %1
			*/
			/*sbox_masked[i^rand_1]= sbox[i]^rand_2
			post_sbox_s1= sbox_masked[s1]*/
			llvm::BasicBlock* Entry = llvm::BasicBlock::Create(Ctx, "entry", Fun);
			llvm::Function& rand = GetRandomFn(Mod, size);
			llvm::IRBuilder<> ib_entry = llvm::IRBuilder<>(Entry->getContext());
			ib_entry.SetInsertPoint(Entry);
			llvm::BasicBlock* ForBody = llvm::BasicBlock::Create(Ctx, "for_body", Fun);
			llvm::IRBuilder<> ib_for = llvm::IRBuilder<>(ForBody->getContext());
			ib_for.SetInsertPoint(ForBody);
			llvm::BasicBlock* FuncOut = llvm::BasicBlock::Create(Ctx, "out", Fun);
			llvm::IRBuilder<> ib_fo = llvm::IRBuilder<>(FuncOut->getContext());
			ib_fo.SetInsertPoint(FuncOut);
			vector<Value*> newshares;
			for(unsigned int i = 0; i < MaskingOrder; i++) { newshares.push_back(ib_entry.CreateCall(&rand)); }
			Value* tmpsbox = ib_entry.CreateAlloca(llvm::Type::getIntNTy(Ctx, size), llvm::ConstantInt::get(llvm::Type::getInt64Ty(Ctx), len_roundup, false));
			ib_entry.CreateBr(ForBody);
			PHINode* i_start = ib_for.CreatePHI(llvm::Type::getInt64Ty(Ctx), 2);
			i_start->addIncoming(llvm::ConstantInt::get(llvm::Type::getInt64Ty(Ctx), 0, false), Entry);
			Value* idx = i_start;
			for(unsigned int i = 0; i < MaskingOrder; i++) { idx = ib_for.CreateXor(idx, inputshares[i]); }
			idx = ib_for.CreateAnd(idx, len_roundup);
			Value* newelptr = ib_for.CreateGEP(tmpsbox, idx);
			vector<Value*> idxs;
			idxs.push_back(llvm::ConstantInt::get(llvm::Type::getInt64Ty(Ctx), 0, false));
			idxs.push_back(i_start);
			Value* oldelptr = ib_for.CreateGEP(sboxptr, llvm::ArrayRef<Value*>(idxs));
			Value* realval = ib_for.CreateLoad(oldelptr);
			Value* newval = realval;
			for(unsigned int i = 0; i < MaskingOrder; i++) { newval = ib_for.CreateXor(newval, newshares[i]); }
			ib_for.CreateStore(newval, newelptr);
			Value* newi = ib_for.CreateAdd(i_start, llvm::ConstantInt::get(llvm::Type::getInt64Ty(Ctx), 1, false));
			i_start->addIncoming(newi, ForBody);
			Value* exitcond = ib_for.CreateICmpEQ(newi, llvm::ConstantInt::get(llvm::Type::getInt64Ty(Ctx), len, false));
			ib_for.CreateCondBr(exitcond, FuncOut, ForBody);
			idx = ib_fo.CreateAnd(inputshares[MaskingOrder], len_roundup);
			Value* retptr = ib_fo.CreateGEP(tmpsbox, idx);
			newshares.push_back(ib_fo.CreateLoad(retptr));
			for(unsigned int i = 0; i <= MaskingOrder; i++) { ib_fo.CreateStore(newshares[i], outputshares[i]); }
			ib_fo.CreateRetVoid();
			return *Fun;
		}

	public:
		static void replaceWithComputational(GetElementPtrInst* ptr, NoCryptoFA::InstructionMetadata* md) {
			Module* mod = ptr->getParent()->getParent()->getParent();
			stringstream ss("");
			ss << "__masked__" << ptr->getOperand(0)->getName().str() << "_computational";
			Function* fp = mod->getFunction(ss.str());
			Type* paramType = fp->getFunctionType()->getParamType(0);
			llvm::IRBuilder<> ib = llvm::IRBuilder<>(ptr->getContext());
			ib.SetInsertPoint(ptr);
			Value* prevInst = ptr->getOperand(2);
			if(!paramType->isIntegerTy(prevInst->getType()->getIntegerBitWidth())) {
				if(isa<CastInst>(prevInst)) {
					CastInst* ci = cast<CastInst>(prevInst);
					prevInst = ci->getOperand(0);
				}
			}
			vector<Value*> idx = MaskValue(prevInst, ptr);
#define I(var,val) do {var=val; BuildMetadata(var, ptr, NoCryptoFA::InstructionMetadata::SBOX_MASKED);}while(0)
			Type* basetype = ptr->getPointerOperand()->getType()->getPointerElementType()->getSequentialElementType();
			std::vector<Value*> v = getShareTemps(basetype, ptr->getParent()->getParent());
			std::vector<Value*> parameters;
			for(unsigned int i = 0; i <= MaskingOrder; i++) { parameters.push_back(idx[i]); }
			for(unsigned int i = 0; i <= MaskingOrder; i++) { parameters.push_back(v[i]); }
			Value* t;
			I(t, ib.CreateCall(fp, llvm::ArrayRef<Value*>(parameters)));
			for(unsigned int i = 0; i <= MaskingOrder; i++) {
				I(t, ib.CreateLoad(v[i]));
				md->MaskedValues.push_back(t);
			}
#undef I
		}
		static void replaceWithBoxRecalc(GetElementPtrInst* ptr, NoCryptoFA::InstructionMetadata* md) {
			int size = ptr->getType()->getPointerElementType()->getScalarSizeInBits();
			int len = ptr->getPointerOperandType()->getPointerElementType()->getArrayNumElements();
			Function& msk = GetMaskingFn(ptr->getParent()->getParent()->getParent(), size, len);
			llvm::IRBuilder<> ib = llvm::IRBuilder<>(ptr->getContext());
			ib.SetInsertPoint(ptr);
			vector<Value*> idx = MaskValue(ptr->getOperand(2), ptr);
#define I(var,val) do {var=val; BuildMetadata(var, ptr, NoCryptoFA::InstructionMetadata::SBOX_MASKED);}while(0)
			Type* basetype = ptr->getPointerOperand()->getType()->getPointerElementType()->getSequentialElementType();
			std::vector<Value*> v = getShareTemps(basetype, ptr->getParent()->getParent());
			std::vector<Value*> parameters;
			parameters.push_back(ptr->getPointerOperand());
			for(unsigned int i = 0; i <= MaskingOrder; i++) { parameters.push_back(idx[i]); }
			for(unsigned int i = 0; i <= MaskingOrder; i++) { parameters.push_back(v[i]); }
			Value* t;
			I(t, ib.CreateCall(&msk, llvm::ArrayRef<Value*>(parameters)));
			for(unsigned int i = 0; i <= MaskingOrder; i++) {
				I(t, ib.CreateLoad(v[i]));
				md->MaskedValues.push_back(t);
			}
#undef I
		}
		static bool verify(GetElementPtrInst* ptr, NoCryptoFA::InstructionMetadata* md) {
			raw_fd_ostream rerr(2, false);
			if(!md->isSbox) {rerr << *ptr; cerr << "! is sbox " << endl; return false;}
			if(ptr->getNumIndices() != 2) {cerr << "ptr->getNumIndices() == " << ptr->getNumIndices() << endl; return false;}
			if(!isa<ConstantInt>(ptr->getOperand(1))) {cerr << "first index is not constant" << endl; return false;}
			if(!(cast<ConstantInt>(ptr->getOperand(1))->getZExtValue() == 0)) {cerr << "first index is not zero" << endl; return false;}
			return true;
		}

		static bool haveEquivalentFunction(GetElementPtrInst* ptr, NoCryptoFA::InstructionMetadata* md) {
			Module* mod = ptr->getParent()->getParent()->getParent();
			stringstream ss("");
			ss << "__masked__" << ptr->getOperand(0)->getName().str() << "_computational";
			Function* fp = mod->getFunction(ss.str());
			return fp != NULL;
		}
};
map<pair<Function*, Type*>, vector<Value*> > GEPReplacer::shareTemps = map<pair<Function*, Type*>, vector<Value*> >();
