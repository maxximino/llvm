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
						/*  x = rand()
						    %1=a[0] AND b[1]
						    %2=a[1] AND b[0]
						    %3= x XOR %1
						    y = %3 XOR %2
						    %4=a[0] AND b[0]
						    c[0] = %4 XOR x
						    %5=a[1] AND b[1]
						    c[1] = %5 XOR y
						 */
						//TODO: Higher order masking
						llvm::Value* x = ib.CreateCall(&rand);
						llvm::Value* t1 = ib.CreateAnd(op1[0], op2[1]);
						llvm::Value* t2 = ib.CreateAnd(op1[1], op2[0]);
						llvm::Value* t3 = ib.CreateXor(x, t1);
						llvm::Value* y = ib.CreateXor(t3, t2);
						llvm::Value* t4 = ib.CreateAnd(op1[0], op2[0]);
						llvm::Value* t5 = ib.CreateAnd(op1[1], op2[1]);
						md->MaskedValues.push_back(ib.CreateXor(t4, x));
						md->MaskedValues.push_back(ib.CreateXor(t5, y));
						BuildMetadata(x, ptr, NoCryptoFA::InstructionMetadata::AND_MASKED);
						BuildMetadata(t1, ptr, NoCryptoFA::InstructionMetadata::AND_MASKED);
						BuildMetadata(t2, ptr, NoCryptoFA::InstructionMetadata::AND_MASKED);
						BuildMetadata(t3, ptr, NoCryptoFA::InstructionMetadata::AND_MASKED);
						BuildMetadata(y, ptr, NoCryptoFA::InstructionMetadata::AND_MASKED);
						BuildMetadata(t4, ptr, NoCryptoFA::InstructionMetadata::AND_MASKED);
						BuildMetadata(t5, ptr, NoCryptoFA::InstructionMetadata::AND_MASKED);
						BuildMetadata(md->MaskedValues[0], ptr, NoCryptoFA::InstructionMetadata::AND_MASKED);
						BuildMetadata(md->MaskedValues[1], ptr, NoCryptoFA::InstructionMetadata::AND_MASKED);
						return true;
					}
					break;
				case Instruction::Xor: {
						//TODO: Higher order masking
						vector<Value*> op1 = MaskValue(ptr->getOperand(0), ptr);
						vector<Value*> op2 = MaskValue(ptr->getOperand(1), ptr);
						llvm::Function& randF = GetRandomFn(ptr->getParent()->getParent()->getParent(), size);
						llvm::Value* rand = ib.CreateCall(&randF);
						Value* a0 = ib.CreateXor(op1[0], rand);
						Value* a1 = ib.CreateXor(op1[1], rand);
						Value* b0 = ib.CreateXor(op2[0], rand);
						Value* b1 = ib.CreateXor(op2[1], rand);
						md->MaskedValues.push_back(ib.CreateXor(a0, b0));
						md->MaskedValues.push_back(ib.CreateXor(a1, b1));
						BuildMetadata(rand, ptr, NoCryptoFA::InstructionMetadata::XOR_MASKED);
						BuildMetadata(a0, ptr, NoCryptoFA::InstructionMetadata::XOR_MASKED);
						BuildMetadata(a1, ptr, NoCryptoFA::InstructionMetadata::XOR_MASKED);
						BuildMetadata(b0, ptr, NoCryptoFA::InstructionMetadata::XOR_MASKED);
						BuildMetadata(b1, ptr, NoCryptoFA::InstructionMetadata::XOR_MASKED);
						BuildMetadata(md->MaskedValues[0], ptr, NoCryptoFA::InstructionMetadata::XOR_MASKED);
						BuildMetadata(md->MaskedValues[1], ptr, NoCryptoFA::InstructionMetadata::XOR_MASKED);
						return true;
					}
					break;
				case Instruction::AShr:
				case Instruction::Shl:
				case Instruction::LShr:
					//TODO: Higher order masking
					if(isa<ConstantInt>(ptr->getOperand(1))) {
						vector<Value*> op = MaskValue(ptr->getOperand(0), ptr);
						md->MaskedValues.push_back(ib.CreateBinOp(ptr->getOpcode(), op[0], ptr->getOperand(1)));
						md->MaskedValues.push_back(ib.CreateBinOp(ptr->getOpcode(), op[1], ptr->getOperand(1)));
						BuildMetadata(md->MaskedValues[0], ptr, NoCryptoFA::InstructionMetadata::SHIFT_MASKED);
						BuildMetadata(md->MaskedValues[1], ptr, NoCryptoFA::InstructionMetadata::SHIFT_MASKED);
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
						//TODO: Higher order masking
						llvm::IRBuilder<> ib = llvm::IRBuilder<>(i->getContext());
						ib.SetInsertPoint(i);
						vector<Value*> op = MaskValue(i->getOperand(0), i);
						md->MaskedValues.push_back(ib.CreateCast(i->getOpcode(), op[0], i->getDestTy()));
						md->MaskedValues.push_back(ib.CreateCast(i->getOpcode(), op[1], i->getDestTy()));
						BuildMetadata(md->MaskedValues[0], i, NoCryptoFA::InstructionMetadata::CAST_MASKED);
						BuildMetadata(md->MaskedValues[1], i, NoCryptoFA::InstructionMetadata::CAST_MASKED);
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
			//TODO: Higher order masking
			raw_fd_ostream rerr(2, false);
			if(!md->isSbox) {rerr << *ptr; cerr << "! is sbox " << endl; return false;}
			cerr << "WOW is sbox " << endl;
			if(ptr->getNumIndices() != 2) {cerr << "ptr->getNumIndices() == " << ptr->getNumIndices() << endl; return false;}
			if(!isa<ConstantInt>(ptr->getOperand(1))) {cerr << "first index is not constant" << endl; return false;}
			if(!(cast<ConstantInt>(ptr->getOperand(1))->getZExtValue() == 0)) {cerr << "first index is not zero" << endl; return false;}
			md->isSbox = true;
			int size = ptr->getType()->getPointerElementType()->getScalarSizeInBits();
			Function& msk = GetMaskingFn(ptr->getParent()->getParent()->getParent(), size);
			llvm::IRBuilder<> ib = llvm::IRBuilder<>(ptr->getContext());
			ib.SetInsertPoint(ptr);
			vector<Value*> idx = MaskValue(ptr->getOperand(2), ptr);
			Value* v1 = ib.CreateAlloca(ptr->getPointerOperand()->getType()->getPointerElementType()->getSequentialElementType()); //Far dimagrire lo stack.
			Value* v2 = ib.CreateAlloca(ptr->getPointerOperand()->getType()->getPointerElementType()->getSequentialElementType()); //Far dimagrire lo stack.
			Value* call = ib.CreateCall5(&msk, ptr->getPointerOperand(), idx[0], idx[1], v1, v2);
			Value* m1 = ib.CreateLoad(v1);
			Value* m2 = ib.CreateLoad(v2);
			md->MaskedValues.push_back(m1);
			md->MaskedValues.push_back(m2);
			BuildMetadata(v1, ptr, NoCryptoFA::InstructionMetadata::SBOX_MASKED);
			BuildMetadata(v2, ptr, NoCryptoFA::InstructionMetadata::SBOX_MASKED);
			BuildMetadata(call, ptr, NoCryptoFA::InstructionMetadata::SBOX_MASKED);
			BuildMetadata(m1, ptr, NoCryptoFA::InstructionMetadata::SBOX_MASKED);
			BuildMetadata(m2, ptr, NoCryptoFA::InstructionMetadata::SBOX_MASKED);
			return true;
		}
		static llvm::Function& GetMaskingFn(llvm::Module* Mod, int size) {
			//TODO: Higher order masking
			stringstream ss("");
			ss << "__sboxmask" << size;
			llvm::Function* Fun = Mod->getFunction(ss.str());
			if(Fun && !Fun->isDeclaration()) {
				return *Fun;
			}
			llvm::LLVMContext& Ctx = Mod->getContext();
			llvm::Constant* FunSym;
			FunSym = Mod->getOrInsertFunction(ss.str(),
			                                  llvm::Type::getVoidTy(Ctx),
			                                  llvm::ArrayType::get(llvm::Type::getIntNTy(Ctx, size), 256)->getPointerTo(),
			                                  llvm::Type::getInt64Ty(Ctx),
			                                  llvm::Type::getInt64Ty(Ctx),
			                                  llvm::Type::getIntNPtrTy(Ctx, size),
			                                  llvm::Type::getIntNPtrTy(Ctx, size),
			                                  NULL);
			Fun = llvm::cast<llvm::Function>(FunSym);
			Function::arg_iterator args = Fun->arg_begin();
			Value* sboxptr = args++;
			sboxptr->setName("sboxptr");
			Value* inmask1 = args++;
			inmask1->setName("inmask1");
			Value* inmask2 = args++;
			inmask2->setName("inmask2");
			Value* outmask1 = args++;
			outmask1->setName("outmask1");
			Value* outmask2 = args++;
			outmask2->setName("outmask2");
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
			CallInst* rndval = ib_entry.CreateCall(&rand);
			Value* tmpsbox = ib_entry.CreateAlloca(llvm::Type::getIntNTy(Ctx, size), llvm::ConstantInt::get(llvm::Type::getInt64Ty(Ctx), 256, false));
			ib_entry.CreateBr(ForBody);
			PHINode* i_start = ib_for.CreatePHI(llvm::Type::getInt64Ty(Ctx), 2);
			i_start->addIncoming(llvm::ConstantInt::get(llvm::Type::getInt64Ty(Ctx), 0, false), Entry);
			Value* i = ib_for.CreateXor(i_start, inmask2);
			Value* newelptr = ib_for.CreateGEP(tmpsbox, i);
			vector<Value*> idxs;
			idxs.push_back(llvm::ConstantInt::get(llvm::Type::getInt64Ty(Ctx), 0, false));
			idxs.push_back(i_start);
			Value* oldelptr = ib_for.CreateGEP(sboxptr, llvm::ArrayRef<Value*>(idxs));
			Value* realval = ib_for.CreateLoad(oldelptr);
			Value* newval = ib_for.CreateXor(realval, rndval);
			ib_for.CreateStore(newval, newelptr);
			Value* newi = ib_for.CreateAdd(i_start, llvm::ConstantInt::get(llvm::Type::getInt64Ty(Ctx), 1, false));
			i_start->addIncoming(newi, ForBody);
			Value* exitcond = ib_for.CreateICmpEQ(newi, llvm::ConstantInt::get(llvm::Type::getInt64Ty(Ctx), 256, false));
			ib_for.CreateCondBr(exitcond, FuncOut, ForBody);
			Value* retptr = ib_fo.CreateGEP(tmpsbox, inmask1);
			Value* retval = ib_fo.CreateLoad(retptr);
			ib_fo.CreateStore(rndval, outmask1);
			ib_fo.CreateStore(retval, outmask2);
			ib_fo.CreateRetVoid();
			return *Fun;
		}

};
template <>
struct MaskTraits<LoadInst> {
	public:
		static bool replaceWithMasked(LoadInst* ptr, NoCryptoFA::InstructionMetadata* md) {
			//TODO: Higher order masking
			if(!isa<Instruction>(ptr->getPointerOperand())) {return false;}
			if(!llvm::NoCryptoFA::known[cast<Instruction>(ptr->getPointerOperand())]->isSbox) {return false;}
			md->isSbox = true;
			vector<Value*> idx = MaskValue(ptr->getPointerOperand(), ptr);
			md->MaskedValues.push_back(idx[0]);
			md->MaskedValues.push_back(idx[1]);
			return true;
		}
};
template <>
struct MaskTraits<SelectInst> {
	public:
		static bool replaceWithMasked(SelectInst* ptr, NoCryptoFA::InstructionMetadata* md) {
			//TODO: Higher order masking
			llvm::IRBuilder<> ib = llvm::IRBuilder<>(ptr->getContext());
			ib.SetInsertPoint(ptr);
			vector<Value*> c = MaskValue(ptr->getCondition(), ptr);
			vector<Value*> vTrue = MaskValue(ptr->getTrueValue(), ptr);
			vector<Value*> vFalse = MaskValue(ptr->getFalseValue(), ptr);
			md->MaskedValues.push_back(ib.CreateSelect(c[0], vTrue[0], vFalse[0]));
			md->MaskedValues.push_back(ib.CreateSelect(c[0], vTrue[1], vFalse[1]));
			BuildMetadata(md->MaskedValues[0], ptr, NoCryptoFA::InstructionMetadata::SELECT_MASKED);
			BuildMetadata(md->MaskedValues[1], ptr, NoCryptoFA::InstructionMetadata::SELECT_MASKED);
			return true;
		}
};
