#include <vector>
#include "llvm/Constants.h"
#include "llvm/Instructions.h"
#include "llvm/Instruction.h"
#include "llvm/Intrinsics.h"
#include "llvm/Module.h"
#include "llvm/Analysis/Dominators.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/IRBuilder.h"
#include "llvm/Type.h"

#include <llvm/Support/InstVisitor.h>
using namespace llvm;
#include "GEPReplacer.h"

class MaskingVisitor : public InstVisitor<MaskingVisitor, bool>
{
	protected:

		bool maskMaskableCasts(CastInst& inst) {
			NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[&inst];
			llvm::IRBuilder<> ib = llvm::IRBuilder<>(inst.getContext());
			ib.SetInsertPoint(&inst);
			vector<Value*> op = MaskValue(inst.getOperand(0), &inst);
			for(unsigned int o = 0; o <= MaskingOrder; o++) {
				md->MaskedValues.push_back(ib.CreateCast(inst.getOpcode(), op[o], inst.getDestTy()));
				BuildMetadata(md->MaskedValues[o], &inst, NoCryptoFA::InstructionMetadata::CAST_MASKED);
			}
			return true;
		}
		bool maskShift(BinaryOperator& inst) {
			NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[&inst];
			llvm::IRBuilder<> ib = llvm::IRBuilder<>(inst.getContext());
			ib.SetInsertPoint(&inst);
			if(isa<ConstantInt>(inst.getOperand(1))) {
				vector<Value*> op = MaskValue(inst.getOperand(0), &inst);
				for(unsigned int o = 0; o <= MaskingOrder; o++) {
					md->MaskedValues.push_back(ib.CreateBinOp(inst.getOpcode(), op[o], inst.getOperand(1)));
					BuildMetadata(md->MaskedValues[o], &inst, NoCryptoFA::InstructionMetadata::SHIFT_MASKED);
				}
				return true;
			} else {
				return false;
			}
		}
	public:
		bool visitInstruction(Instruction& inst) {
			cerr << "Missing opcode mask equivalent:" << inst.getOpcodeName() << endl;
			return false;
		}
		bool visitAnd(BinaryOperator& inst) {
			NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[&inst];
			llvm::IRBuilder<> ib = llvm::IRBuilder<>(inst.getContext());
			ib.SetInsertPoint(&inst);
			int size = inst.getType()->getScalarSizeInBits();
			llvm::Function& rand = GetRandomFn(inst.getParent()->getParent()->getParent(), size);
			vector<Value*> op1 = MaskValue(inst.getOperand(0), &inst);
			vector<Value*> op2 = MaskValue(inst.getOperand(1), &inst);
			/* z[i][j] con i < j = rand()
			 * z[i][j] con i > j = z[j][i] ^ a[j]&b[i]  ^ a[i]&b[j]
			 * c[i] = a[i]&b[i] ^ XOR( z[i][k] con k != i)
			 */
#define I(var,val) var=val; BuildMetadata(var, &inst, NoCryptoFA::InstructionMetadata::AND_MASKED)
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
#undef I
			return true;
		}

		bool visitXor(BinaryOperator& inst) {
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
			NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[&inst];
			llvm::IRBuilder<> ib = llvm::IRBuilder<>(inst.getContext());
			ib.SetInsertPoint(&inst);
			int size = inst.getType()->getScalarSizeInBits();
			vector<Value*> op1 = MaskValue(inst.getOperand(0), &inst);
			vector<Value*> op2 = MaskValue(inst.getOperand(1), &inst);
			llvm::Function& randF = GetRandomFn(inst.getParent()->getParent()->getParent(), size);
			Value* v_op1 = op1[MaskingOrder];
			Value* v_op2 = op2[MaskingOrder];
			for(unsigned int o = 0; o < MaskingOrder; o++) {
				llvm::Value* rand = ib.CreateCall(&randF);
				BuildMetadata(rand, &inst, NoCryptoFA::InstructionMetadata::XOR_MASKED);
				Value* t1 = ib.CreateXor(op1[o], rand);
				Value* t2 = ib.CreateXor(t1, op2[o]);
				BuildMetadata(t1, &inst, NoCryptoFA::InstructionMetadata::XOR_MASKED);
				BuildMetadata(t2, &inst, NoCryptoFA::InstructionMetadata::XOR_MASKED);
				md->MaskedValues.push_back(t2);
				if(o % 2) {
					v_op1 = ib.CreateXor(v_op1, rand);
					BuildMetadata(v_op1, &inst, NoCryptoFA::InstructionMetadata::XOR_MASKED);
				} else {
					v_op2 = ib.CreateXor(v_op2, rand);
					BuildMetadata(v_op2, &inst, NoCryptoFA::InstructionMetadata::XOR_MASKED);
				}
			}
			Value* v_last = ib.CreateXor(v_op1, v_op2);
			BuildMetadata(v_last, &inst, NoCryptoFA::InstructionMetadata::XOR_MASKED);
			md->MaskedValues.push_back(v_last);
			return true;
		}
		bool visitLoadInst(LoadInst& inst) {
			NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[&inst];
			if(!isa<Instruction>(inst.getPointerOperand())) {return false;}
			if(!llvm::NoCryptoFA::known[cast<Instruction>(inst.getPointerOperand())]->isSbox) {return false;}
			md->isSbox = true;
			vector<Value*> idx = MaskValue(inst.getPointerOperand(), &inst);
			for(unsigned int i = 0; i <= MaskingOrder; i++) {
				md->MaskedValues.push_back(idx[i]);
			}
			return true;
		}
		bool visitGetElementPtrInst(GetElementPtrInst& inst) {
			NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[&inst];
			if(!GEPReplacer::verify(&inst, md)) { return false; }
			md->isSbox = true;
			if((MaskingOrder <= 2) && !ForceComputational) {
				GEPReplacer::replaceWithBoxRecalc(&inst, md);
			} else {
				if(GEPReplacer::haveEquivalentFunction(&inst, md)) {
					GEPReplacer::replaceWithComputational(&inst, md);
				} else {
					errs() << "Sorry, this is not safe. Provide a function called " << inst.getOperand(0)->getName() << "_computational (marked with maskedcopy) or lower the masking order.\n";
					abort();
				}
			}
			return true;
		}
		bool visitShl(BinaryOperator& inst) { return maskShift(inst);}
		bool visitAShr(BinaryOperator& inst) { return maskShift(inst);}
		bool visitLShr(BinaryOperator& inst) { return maskShift(inst);}
		bool visitTrunc(CastInst& inst) { return maskMaskableCasts(inst);}
		bool visitSExt(CastInst& inst) { return maskMaskableCasts(inst);}
		bool visitZExt(CastInst& inst) { return maskMaskableCasts(inst);}
		bool visitBitCast(CastInst& inst) { return maskMaskableCasts(inst);}
		bool visitCallInst(CallInst& inst) {
			NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[&inst];
			if(inst.getNumArgOperands() != 1) {cerr << "inst.getNumArgOperands() != 1 but == " << inst.getNumArgOperands() << endl; return false;}
			if(!isa<IntegerType>(inst.getArgOperand(0)->getType())) {cerr << "first argument is not integer" << endl; return false;}
			if(!isa<IntegerType>(inst.getType())) {cerr << "return value is not integer" << endl; return false;}
			Function* origFn = inst.getCalledFunction();
			map<Function*, Function*>& maskedfn = llvm::InstructionReplace::maskedfn;
			if(maskedfn.find(origFn) == maskedfn.end()) {cerr << "There is not a masked equivalent of " << origFn->getName().str() << endl; return false;}
			md->isSbox = true;
			Function* newFn = maskedfn[origFn];
			llvm::IRBuilder<> ib = llvm::IRBuilder<>(inst.getContext());
			ib.SetInsertPoint(&inst);
			vector<Value*> argshares = MaskValue(inst.getArgOperand(0), &inst);
#define I(var,val) do {var=val; BuildMetadata(var, &inst, NoCryptoFA::InstructionMetadata::SBOX_MASKED);}while(0)
			Value* v[MaskingOrder + 1];
			Type* basetype = inst.getArgOperand(0)->getType();
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
		bool visitSelectInst(SelectInst& inst) {
			NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[&inst];
			llvm::IRBuilder<> ib = llvm::IRBuilder<>(inst.getContext());
			ib.SetInsertPoint(&inst);
			vector<Value*> c = MaskValue(inst.getCondition(), &inst);
			vector<Value*> vTrue = MaskValue(inst.getTrueValue(), &inst);
			vector<Value*> vFalse = MaskValue(inst.getFalseValue(), &inst);
			md->MaskedValues.clear();
			for(unsigned int i = 0; i <= MaskingOrder; i++) {
				md->MaskedValues.push_back(ib.CreateSelect(c[i], vTrue[i], vFalse[i]));
				BuildMetadata(md->MaskedValues[i], &inst, NoCryptoFA::InstructionMetadata::SELECT_MASKED);
			}
			return true;
		}

};

