#include <llvm/Support/InstVisitor.h>
#include <llvm/NoCryptoFA/All.h>
using namespace llvm;
template<int MAXBITS,vector<bitset<MAXBITS> > NoCryptoFA::InstructionMetadata::*DATA,bitset<MAXBITS> NoCryptoFA::InstructionMetadata::*OWN>
/*
This template requires some explaination:
This class is an InstructionVisitor (see LLVM doc.)
 that writes correct key dependency information on instruction metadata, by reading
 key dependency information on operands.
This algorithm has TWO use cases:
    * Propagating key dependency information from the userkey
    * Propagating key dependency information from the vulnerable subkeys at the top of the algorithm.
This means that the same algorithm should work on the same instructions, but referring to two different sets of dependencies.

This is implemented through the use of pointers-to-members, that means that everything is resolved at compile-time.

So through this class you'll find *DATA and *OWN. They are not usual pointers-to-memory, but pointers-to-member.
Template parameter MAXBITS is introduced to keep all of the bitsets of the first case smaller than those of the second.
*/
class CalcForwardVisitor : public InstVisitor<CalcForwardVisitor<MAXBITS, DATA, OWN> >
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
                    int size = std::min((NoCryptoFA::known[_it]->*DATA).size(), (md->*DATA).size());
					for(int i = 0; i < size; ++i) {
                        (md->*DATA)[i] =  (md->*DATA)[i] | (NoCryptoFA::known[_it]->*DATA)[i];
                        if((NoCryptoFA::known[_it]->*OWN).any()) {
                            (md->*DATA)[i] = (md->*DATA)[i] | NoCryptoFA::known[_it]->*OWN; //TODO: diagonale, non blocchettino!
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
            for(unsigned int i = 0; i < (md->*DATA).size(); i++) { (md->*DATA)[i] = (other->*DATA)[diff + i]; }
		}
		void visitZExt(CastInst& inst) {
			NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[&inst];
			visitInstruction(inst);
			int from = CalcDFG::getOperandSize(inst.getSrcTy());
			int to = CalcDFG::getOperandSize(inst.getDestTy());
            ShiftKeyBitset<MAXBITS>(0, to - from, md->*DATA);
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
            ShiftKeyBitset<MAXBITS>(direction, idx, md->*DATA);
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
            auto size = (md->*DATA).size();
#define is_bit_set(what,num) ((what) & (1<<(num)))
			for(unsigned int i = 0; i < size; i++) {
				if(is_bit_set(mask, i)) {
                    (md->*DATA)[size - 1 - i] = (other->*DATA)[size - 1 - i];
				} else {
                    (md->*DATA)[size - 1 - i] = bitset<MAXBITS>(0);
				}
			}
		}
		void calcAsBiggestSum(Instruction& inst) {
			NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[&inst];
            bitset<MAXBITS> max(0);
			for(User::const_op_iterator it = inst.op_begin(); it != inst.op_end(); ++it) {
				if(Instruction* _it = dyn_cast<Instruction>(*it)) {
                    int size = (NoCryptoFA::known[_it]->*DATA).size();
					for(int i = 0; i < size; ++i) {
                        max |= (NoCryptoFA::known[_it]->*DATA)[i];
                        if((NoCryptoFA::known[_it]->*OWN).any()) {
                            max |= NoCryptoFA::known[_it]->*OWN;
						}
					}
				}
			}
            int size = (md->*DATA).size();
			for(int i = 0; i < size; ++i) {
                (md->*DATA)[i] =  max;
			}
		}
		void visitMul(BinaryOperator& inst) {calcAsBiggestSum(inst);}
		void visitUDiv(BinaryOperator& inst) {calcAsBiggestSum(inst);}
		void visitSMul(BinaryOperator& inst) {calcAsBiggestSum(inst);}
		void visitURem(BinaryOperator& inst) {calcAsBiggestSum(inst);}
		void visitSRem(BinaryOperator& inst) {calcAsBiggestSum(inst);}

        void visitGetElementPtrInst(GetElementPtrInst& inst) {
            calcAsBiggestSum(inst);
            NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[&inst];
            for(unsigned long i = 0; i < (md->*DATA).size();i++ )
            {
                if(md->deadBits[i]) (md->*DATA)[i].reset();
            }
        }
		void visitCallInst(CallInst& inst) {calcAsBiggestSum(inst);}
		void visitSelectInst(SelectInst& inst) {
			NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[&inst];
            bitset<MAXBITS> tmp(0);
            int size = (md->*DATA).size();
			Instruction* trueval = cast<Instruction>(inst.getTrueValue());
			Instruction* falseval = cast<Instruction>(inst.getFalseValue());
			for(int i = 0; i < size; ++i) {
                tmp |= (NoCryptoFA::known[trueval]->*DATA)[i];
                tmp |= (NoCryptoFA::known[falseval]->*DATA)[i];
                if((NoCryptoFA::known[trueval]->*OWN).any()) {
                    tmp |= NoCryptoFA::known[trueval]->*OWN;
				}
                if((NoCryptoFA::known[falseval]->*OWN).any()) {
                    tmp |= NoCryptoFA::known[falseval]->*OWN;
				}
                (md->*DATA)[i] = tmp;
			}
		}
};
