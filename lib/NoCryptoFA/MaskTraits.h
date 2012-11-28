#pragma once
#include <vector>
#include "llvm/Constants.h"
#include "llvm/Instructions.h"
#include "llvm/Instruction.h"
#include "llvm/Intrinsics.h"
#include "llvm/Module.h"
#include "llvm/Analysis/Dominators.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/IRBuilder.h"
#include "llvm/Type.h"


static bool unsupportedInstruction(Instruction* ptr)
{
	cerr << "Missing opcode mask equivalent:" << ptr->getOpcodeName() << endl;
	return false;
}
template<typename T>
struct MaskTraits {
	public:
		static bool replaceWithMasked(T* ptr, NoCryptoFA::InstructionMetadata* md) {
			return unsupportedInstruction(cast<Instruction>(ptr));
		}
};

template <>
struct MaskTraits<BinaryOperator> {
	public:
		static bool replaceWithMasked(BinaryOperator* ptr, NoCryptoFA::InstructionMetadata* md) {
			llvm::IRBuilder<> ib = llvm::IRBuilder<>(ptr->getContext());
			ib.SetInsertPoint(ptr);
			int size = ptr->getType()->getScalarSizeInBits();
			switch(ptr->getOpcode()) {
				case Instruction::And: {
						llvm::Function& rand = GetRandomFn(ptr->getParent()->getParent()->getParent(), size);
						vector<Value*> op1 = MaskValue(ptr->getOperand(0), ptr);
						vector<Value*> op2 = MaskValue(ptr->getOperand(1), ptr);
						/* z[i][j] con i < j = rand()
						 * z[i][j] con i > j = z[j][i] ^ a[j]&b[i]  ^ a[i]&b[j]
						 * c[i] = a[i]&b[i] ^ XOR( z[i][k] con k != i)
						 */
#define I(var,val) var=val; BuildMetadata(var, ptr, NoCryptoFA::InstructionMetadata::AND_MASKED)
						Value* z[MaskingOrder + 1][MaskingOrder + 1];
						for(unsigned int j = 0; j <= MaskingOrder; j++) {
							for(unsigned int i = 0; i < j; i++) {
								I(z[i][j], ib.CreateCall(&rand));
							}
						}
						Value* t1, *t2, *t3;
						for(unsigned int j = 0; j <= MaskingOrder; j++) {
							for(unsigned int i = j + 1; i <= MaskingOrder; i++) {
								I(t1, ib.CreateAnd(op1[j], op2[i]));
								I(t2, ib.CreateAnd(op1[i], op2[j]));
								I(t3, ib.CreateXor(z[j][i], t1));
								I(z[i][j], ib.CreateXor(t3, t2));
							}
						}
						for(unsigned int i = 0; i <= MaskingOrder; i++) {
							I(t1, ib.CreateAnd(op1[i], op2[i]));
							for(unsigned int k = 0; k <= MaskingOrder; k++) {
								if(i == k) { continue; }
								I(t1, ib.CreateXor(t1, z[i][k]));
							}
							md->MaskedValues.push_back(t1);
						}
						return true;
					}
					break;
#undef I
				case Instruction::Xor: {
						/* Esempio per ordine tre:
						 *input operando1: r1,r2,r3,a^r1^r2^r3
						 *input operando2: r4,r5,r6,b^r4^r5^r6
						 * nuovi random: r7,r8,r9
						 *le nuove share saranno:
						 *r1^r4^r7
						 *r2^r5^r8
						 *r3^r6^r9
						 *a^r1^r2^r3^r8  ^  b^r4^r5^r6^r7^r9
						 *lo XOR di tutte le share, come previsto, produce a^b.
						 */
						vector<Value*> op1 = MaskValue(ptr->getOperand(0), ptr);
						vector<Value*> op2 = MaskValue(ptr->getOperand(1), ptr);
						llvm::Function& randF = GetRandomFn(ptr->getParent()->getParent()->getParent(), size);
						Value* v_op1 = op1[MaskingOrder];
						Value* v_op2 = op2[MaskingOrder];
						for(unsigned int o = 0; o < MaskingOrder; o++) {
							llvm::Value* rand = ib.CreateCall(&randF);
							BuildMetadata(rand, ptr, NoCryptoFA::InstructionMetadata::XOR_MASKED);
							Value* t1 = ib.CreateXor(op1[o], rand);
							Value* t2 = ib.CreateXor(t1, op2[o]);
							BuildMetadata(t1, ptr, NoCryptoFA::InstructionMetadata::XOR_MASKED);
							BuildMetadata(t2, ptr, NoCryptoFA::InstructionMetadata::XOR_MASKED);
							md->MaskedValues.push_back(t2);
							if(o % 2) {
								v_op1 = ib.CreateXor(v_op1, rand);
								BuildMetadata(v_op1, ptr, NoCryptoFA::InstructionMetadata::XOR_MASKED);
							} else {
								v_op2 = ib.CreateXor(v_op2, rand);
								BuildMetadata(v_op2, ptr, NoCryptoFA::InstructionMetadata::XOR_MASKED);
							}
						}
						Value* v_last = ib.CreateXor(v_op1, v_op2);
						BuildMetadata(v_last, ptr, NoCryptoFA::InstructionMetadata::XOR_MASKED);
						md->MaskedValues.push_back(v_last);
						return true;
					}
					break;
				case Instruction::AShr:
				case Instruction::Shl:
				case Instruction::LShr:
					if(isa<ConstantInt>(ptr->getOperand(1))) {
						vector<Value*> op = MaskValue(ptr->getOperand(0), ptr);
						for(unsigned int o = 0; o <= MaskingOrder; o++) {
							md->MaskedValues.push_back(ib.CreateBinOp(ptr->getOpcode(), op[o], ptr->getOperand(1)));
							BuildMetadata(md->MaskedValues[o], ptr, NoCryptoFA::InstructionMetadata::SHIFT_MASKED);
						}
						return true;
					} else {
						return unsupportedInstruction(ptr);
					}
					break;
				case Instruction::Or:
				case Instruction::Add:
				case Instruction::FAdd:
				case Instruction::Sub:
				case Instruction::FSub:
				case Instruction::Mul:
				case Instruction::FMul:
				case Instruction::UDiv:
				case Instruction::SDiv:
				case Instruction::FDiv:
				case Instruction::URem:
				case Instruction::SRem:
				case Instruction::FRem:
				case Instruction::BinaryOpsEnd:
					return unsupportedInstruction(ptr);
			}
		}
};

template <>
struct MaskTraits<CastInst> {
	public:
		static bool replaceWithMasked(CastInst* i, NoCryptoFA::InstructionMetadata* md) {
			switch(i->getOpcode()) {
				case Instruction::Trunc:
				case Instruction::ZExt:
				case Instruction::SExt:
				case Instruction::BitCast: {
						llvm::IRBuilder<> ib = llvm::IRBuilder<>(i->getContext());
						ib.SetInsertPoint(i);
						vector<Value*> op = MaskValue(i->getOperand(0), i);
						for(unsigned int o = 0; o <= MaskingOrder; o++) {
							md->MaskedValues.push_back(ib.CreateCast(i->getOpcode(), op[o], i->getDestTy()));
							BuildMetadata(md->MaskedValues[o], i, NoCryptoFA::InstructionMetadata::CAST_MASKED);
						}
						return true;
					}
					break;
					/*Masking FP values is currently not supported*/
				case Instruction::FPToUI:
				case Instruction::FPToSI:
				case Instruction::UIToFP:
				case Instruction::SIToFP:
				case Instruction::FPTrunc:
				case Instruction::FPExt:
					/*Masking pointers can lead to interesting SEGFAULTs*/
				case Instruction::PtrToInt:
				case Instruction::IntToPtr:
				case Instruction::CastOpsEnd:
					return unsupportedInstruction(i);
			}
		}
};

template <>
struct MaskTraits<GetElementPtrInst> {
	public:
		static bool replaceWithMasked(GetElementPtrInst* ptr, NoCryptoFA::InstructionMetadata* md) {
			if(!verify(ptr, md)) { return false; }
			md->isSbox = true;
			if(MaskingOrder <= 2) {
				replaceWithBoxRecalc(ptr, md);
			} else {
				if(haveEquivalentFunction(ptr, md)) {
					replaceWithComputational(ptr, md);
				} else {
					errs() << "Sorry, this is not safe. Provide a function called " << ptr->getOperand(0)->getName() << "_computational (marked with maskedcopy) or lower the masking order.\n";
					abort();
				}
			}
			return true;
		}
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
			Value* v[MaskingOrder + 1];
			Type* basetype = ptr->getPointerOperand()->getType()->getPointerElementType()->getSequentialElementType();
			for(unsigned int i = 0; i <= MaskingOrder; i++)  { I(v[i], ib.CreateAlloca(basetype)); } // Far dimagrire lo stack.
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
			Function& msk = GetMaskingFn(ptr->getParent()->getParent()->getParent(), size);
			llvm::IRBuilder<> ib = llvm::IRBuilder<>(ptr->getContext());
			ib.SetInsertPoint(ptr);
			vector<Value*> idx = MaskValue(ptr->getOperand(2), ptr);
#define I(var,val) do {var=val; BuildMetadata(var, ptr, NoCryptoFA::InstructionMetadata::SBOX_MASKED);}while(0)
			Value* v[MaskingOrder + 1];
			Type* basetype = ptr->getPointerOperand()->getType()->getPointerElementType()->getSequentialElementType();
			for(unsigned int i = 0; i <= MaskingOrder; i++)  { I(v[i], ib.CreateAlloca(basetype)); } // Far dimagrire lo stack.
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
		static llvm::Function& GetMaskingFn(llvm::Module* Mod, int size) {
			/*
			post_sbox_s2 = rand_n1
			post_sbox_s3 = rand_n2
			for (i = 0; i<256; i++){
			sbox_masked[i^rand_v1^rand_v2]= sbox[i]^rand_n1^rand_n2
			}
			post_sbox_s1= sbox_masked[s1]
			*/
			stringstream ss("");
			ss << "__sboxmask" << size;
			llvm::Function* Fun = Mod->getFunction(ss.str());
			if(Fun && !Fun->isDeclaration()) {
				return *Fun;
			}
			llvm::LLVMContext& Ctx = Mod->getContext();
			llvm::Constant* FunSym;
			std::vector<Type*> paramtypes;
			paramtypes.push_back(llvm::ArrayType::get(llvm::Type::getIntNTy(Ctx, size), 256)->getPointerTo()); //TODO non hardcoded il 256!
			for(unsigned int i = 0; i <= MaskingOrder; i++) { paramtypes.push_back(llvm::Type::getInt64Ty(Ctx)); } //TODO riducibile?
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
			Value* tmpsbox = ib_entry.CreateAlloca(llvm::Type::getIntNTy(Ctx, size), llvm::ConstantInt::get(llvm::Type::getInt64Ty(Ctx), 256, false));
			ib_entry.CreateBr(ForBody);
			PHINode* i_start = ib_for.CreatePHI(llvm::Type::getInt64Ty(Ctx), 2);
			i_start->addIncoming(llvm::ConstantInt::get(llvm::Type::getInt64Ty(Ctx), 0, false), Entry);
			Value* idx = i_start;
			for(unsigned int i = 0; i < MaskingOrder; i++) { idx = ib_for.CreateXor(idx, inputshares[i]); }
			idx = ib_for.CreateAnd(idx, 0xff); // non hardcoded!
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
			Value* exitcond = ib_for.CreateICmpEQ(newi, llvm::ConstantInt::get(llvm::Type::getInt64Ty(Ctx), 256, false));
			ib_for.CreateCondBr(exitcond, FuncOut, ForBody);
			idx = ib_fo.CreateAnd(inputshares[MaskingOrder], 0xff); // non hardcoded!
			Value* retptr = ib_fo.CreateGEP(tmpsbox, idx);
			newshares.push_back(ib_fo.CreateLoad(retptr));
			for(unsigned int i = 0; i <= MaskingOrder; i++) { ib_fo.CreateStore(newshares[i], outputshares[i]); }
			ib_fo.CreateRetVoid();
			return *Fun;
		}

};

template <>
struct MaskTraits<CallInst> {
	public:
		static bool replaceWithMasked(CallInst* ptr, NoCryptoFA::InstructionMetadata* md) {
			if(ptr->getNumArgOperands() != 1) {cerr << "ptr->getNumArgOperands() != 1 but == " << ptr->getNumArgOperands() << endl; return false;}
			if(!isa<IntegerType>(ptr->getArgOperand(0)->getType())) {cerr << "first argument is not integer" << endl; return false;}
			if(!isa<IntegerType>(ptr->getType())) {cerr << "return value is not integer" << endl; return false;}
			Function* origFn = ptr->getCalledFunction();
			map<Function*, Function*>& maskedfn = llvm::InstructionReplace::maskedfn;
			if(maskedfn.find(origFn) == maskedfn.end()) {cerr << "There is not a masked equivalent of " << origFn->getName().str() << endl; return false;}
			md->isSbox = true;
			Function* newFn = maskedfn[origFn];
			llvm::IRBuilder<> ib = llvm::IRBuilder<>(ptr->getContext());
			ib.SetInsertPoint(ptr);
			vector<Value*> argshares = MaskValue(ptr->getArgOperand(0), ptr);
#define I(var,val) do {var=val; BuildMetadata(var, ptr, NoCryptoFA::InstructionMetadata::SBOX_MASKED);}while(0)
			Value* v[MaskingOrder + 1];
			Type* basetype = ptr->getArgOperand(0)->getType();
			for(unsigned int i = 0; i <= MaskingOrder; i++)  { I(v[i], ib.CreateAlloca(basetype)); } // Far dimagrire lo stack.
			std::vector<Value*> parameters;
			for(unsigned int i = 0; i <= MaskingOrder; i++) { parameters.push_back(argshares[i]); }
			for(unsigned int i = 0; i <= MaskingOrder; i++) { parameters.push_back(v[i]); }
			Value* t;
			I(t, ib.CreateCall(newFn, llvm::ArrayRef<Value*>(parameters)));
			for(unsigned int i = 0; i <= MaskingOrder; i++) {
				I(t, ib.CreateLoad(v[i]));
				md->MaskedValues.push_back(t);
			}
#undef I
			return true;
		}
};
template <>
struct MaskTraits<StoreInst> {
	public:
		static bool replaceWithMasked(StoreInst* ptr, NoCryptoFA::InstructionMetadata* md) {
			//Non mascherabile.
			return false;
		}
};
template <>
struct MaskTraits<LoadInst> {
	public:
		static bool replaceWithMasked(LoadInst* ptr, NoCryptoFA::InstructionMetadata* md) {
			if(!isa<Instruction>(ptr->getPointerOperand())) {return false;}
			if(!llvm::NoCryptoFA::known[cast<Instruction>(ptr->getPointerOperand())]->isSbox) {return false;}
			md->isSbox = true;
			vector<Value*> idx = MaskValue(ptr->getPointerOperand(), ptr);
			for(unsigned int i = 0; i <= MaskingOrder; i++) {
				md->MaskedValues.push_back(idx[i]);
			}
			return true;
		}
};
template <>
struct MaskTraits<SelectInst> {
	public:
		static bool replaceWithMasked(SelectInst* ptr, NoCryptoFA::InstructionMetadata* md) {
			llvm::IRBuilder<> ib = llvm::IRBuilder<>(ptr->getContext());
			ib.SetInsertPoint(ptr);
			vector<Value*> c = MaskValue(ptr->getCondition(), ptr);
			vector<Value*> vTrue = MaskValue(ptr->getTrueValue(), ptr);
			vector<Value*> vFalse = MaskValue(ptr->getFalseValue(), ptr);
			md->MaskedValues.clear();
			for(unsigned int i = 0; i <= MaskingOrder; i++) {
				md->MaskedValues.push_back(ib.CreateSelect(c[i], vTrue[i], vFalse[i]));
				BuildMetadata(md->MaskedValues[i], ptr, NoCryptoFA::InstructionMetadata::SELECT_MASKED);
			}
			return true;
		}
};
