#include <llvm/Support/InstVisitor.h>
using namespace llvm;

class CalcPreVisitor : public InstVisitor<CalcPreVisitor>
{
	protected:
		template<int NUMBITS>
		static void ShiftKeyBitset(int direction, unsigned int idx, std::vector<std::bitset<NUMBITS> >& vec) {
			std::vector<std::bitset<NUMBITS> > tmp;
			tmp.resize(vec.size());
			if(idx >= vec.size()) {
				cerr << "Shifting by " << idx << " a " << vec.size() << "bit  data type.Expect something wrong." << endl;
			}
			unsigned int maxcp = (vec.size() - idx);
			if(direction) {
				//a sinistra
				for(unsigned int i = 0; i < maxcp; i++) { tmp[i] = vec[i + idx]; }
				for(unsigned int i = 0; i < idx; i++) { tmp[maxcp + i] = bitset<NUMBITS>(0); }
			} else {
				//a destra
				for(unsigned int i = 0; i < idx; i++) { tmp[i] = bitset<NUMBITS>(0); }
				for(unsigned int i = 0; i < maxcp; i++) { tmp[idx + i] = vec[i]; }
			}
			for(unsigned int i = 0; i < vec.size(); i++) { vec[i] = tmp[i]; }
		}
	public:
		void visitInstruction(Instruction& inst) {
			NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[&inst];
			for(User::const_op_iterator it = inst.op_begin(); it != inst.op_end(); ++it) {
				if(Instruction* _it = dyn_cast<Instruction>(*it)) {
					int size = std::min(NoCryptoFA::known[_it]->pre.size(), md->pre.size());
					for(int i = 0; i < size; ++i) {
						md->pre[i] =  md->pre[i] | NoCryptoFA::known[_it]->pre[i];
						if(NoCryptoFA::known[_it]->own.any()) {
							md->pre[i] = md->pre[i] | NoCryptoFA::known[_it]->own; //TODO: diagonale, non blocchettino!
						}
					}
				}
			}
		}
		void visitTrunc(CastInst& inst) {
			NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[&inst];
			unsigned int from = CalcDFG::getOperandSize(inst.getSrcTy());
			unsigned int to = CalcDFG::getOperandSize(inst.getDestTy());
			unsigned int diff = from - to;
			NoCryptoFA::InstructionMetadata* other = NoCryptoFA::known[cast<Instruction>(inst.getOperand(0))];
			for(unsigned int i = 0; i < md->pre.size(); i++) { md->pre[i] = other->pre[diff + i]; }
		}
		void visitZExt(CastInst& inst) {
			NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[&inst];
			visitInstruction(inst);
			int from = CalcDFG::getOperandSize(inst.getSrcTy());
			int to = CalcDFG::getOperandSize(inst.getDestTy());
			ShiftKeyBitset<MAX_KEYBITS>(0, to - from, md->pre);
		}
		void visitSExt(CastInst& inst) { visitZExt(inst); }
		void calcShift(BinaryOperator& inst, int direction) { //0=>right, 1=>left
			NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[&inst];
			Value* v_idx = inst.getOperand(1);
            unsigned long idx = -1;
            if(!isa<ConstantInt>(v_idx)) {
                cerr << "Shift by a non-constant index. Results approximated.\n";
                idx=0;
            }
            else{
                ConstantInt* ci = cast<ConstantInt>(v_idx);
                idx = ci->getLimitedValue();
            }
			visitInstruction(inst);
			ShiftKeyBitset<MAX_KEYBITS>(direction, idx, md->pre);
		}
		void visitShl(BinaryOperator& inst) { calcShift(inst, 1); }
		void visitLShr(BinaryOperator& inst) { calcShift(inst, 0);}
		void visitAShr(BinaryOperator& inst) { calcShift(inst, 0); }
		void visitAnd(BinaryOperator& inst) {
			NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[&inst];
			Value* v1 = inst.getOperand(0);
			Value* v2 = inst.getOperand(1);
			ConstantInt* ci;
			Instruction* i;
			if(isa<ConstantInt>(v2) && isa<Instruction>(v1)) {
				ci = cast<ConstantInt>(v2);
				i = cast<Instruction>(v1);
			} else if(isa<ConstantInt>(v1) && isa<Instruction>(v2)) {
				ci = cast<ConstantInt>(v1);
				i = cast<Instruction>(v2);
			} else {
				visitInstruction(inst);
				return;
			}
			unsigned long mask = ci->getLimitedValue();
			NoCryptoFA::InstructionMetadata* other = NoCryptoFA::known[i];
			auto size = md->pre.size();
#define is_bit_set(what,num) ((what) & (1<<(num)))
			for(unsigned int i = 0; i < size; i++) {
				if(is_bit_set(mask, i)) {
					md->pre[size - 1 - i] = other->pre[size - 1 - i];
				} else {
					md->pre[size - 1 - i] = bitset<MAX_KEYBITS>(0);
				}
			}
		}
		void calcAsBiggestSum(Instruction& inst) {
			NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[&inst];
			bitset<MAX_KEYBITS> max(0);
			for(User::const_op_iterator it = inst.op_begin(); it != inst.op_end(); ++it) {
				if(Instruction* _it = dyn_cast<Instruction>(*it)) {
					int size = NoCryptoFA::known[_it]->pre.size();
					for(int i = 0; i < size; ++i) {
						max |= NoCryptoFA::known[_it]->pre[i];
						if(NoCryptoFA::known[_it]->own.any()) {
							max |= NoCryptoFA::known[_it]->own;
						}
					}
				}
			}
			int size = md->pre.size();
			for(int i = 0; i < size; ++i) {
				md->pre[i] =  max;
			}
		}
		void visitMul(BinaryOperator& inst) {calcAsBiggestSum(inst);}
		void visitUDiv(BinaryOperator& inst) {calcAsBiggestSum(inst);}
		void visitSMul(BinaryOperator& inst) {calcAsBiggestSum(inst);}
		void visitURem(BinaryOperator& inst) {calcAsBiggestSum(inst);}
		void visitSRem(BinaryOperator& inst) {calcAsBiggestSum(inst);}

		void visitGetElementPtrInst(GetElementPtrInst& inst) {calcAsBiggestSum(inst);}
		void visitCallInst(CallInst& inst) {calcAsBiggestSum(inst);}
		void visitSelectInst(SelectInst& inst) {
			NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[&inst];
			bitset<MAX_KEYBITS> tmp(0);
			int size = md->pre.size();
			Instruction* trueval = cast<Instruction>(inst.getTrueValue());
			Instruction* falseval = cast<Instruction>(inst.getFalseValue());
			for(int i = 0; i < size; ++i) {
				tmp |= NoCryptoFA::known[trueval]->pre[i];
				tmp |= NoCryptoFA::known[falseval]->pre[i];
				if(NoCryptoFA::known[trueval]->own.any()) {
					tmp |= NoCryptoFA::known[trueval]->own;
				}
				if(NoCryptoFA::known[falseval]->own.any()) {
					tmp |= NoCryptoFA::known[falseval]->own;
				}
				md->pre[i] = tmp;
			}
		}
};
