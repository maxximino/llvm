#include <llvm/Support/InstVisitor.h>
using namespace llvm;
template<int MAXBITS,vector<bitset<MAXBITS> > NoCryptoFA::InstructionMetadata::*DATA,bitset<MAXBITS> NoCryptoFA::InstructionMetadata::*OWN>
// For your own mental sanity, please see the comment about CalcForwardVisitor
// This is exactly the same thing, but this sees everything from the bottom.
class CalcBackwardVisitor : public InstVisitor<CalcBackwardVisitor<MAXBITS,DATA,OWN> >
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
		NoCryptoFA::InstructionMetadata* md;
		NoCryptoFA::InstructionMetadata* usemd;
		void visitInstruction(Instruction& inst) {
            int size = std::min((md->*DATA).size(), (usemd->*DATA).size());
			for(int i = 0; i < size; i++) {
                (md->*DATA)[i] |= (usemd->*DATA)[i];
			}
		}
		void visitTrunc(CastInst& inst) {
            int delta = (md->*DATA).size() - (usemd->*DATA).size();
            for(unsigned int i = 0; i < (usemd->*DATA).size(); i++) {
                (md->*DATA)[delta + i] |= (usemd->*DATA)[i];
			}
		}
		void visitZExt(CastInst& inst) {
            int delta = (usemd->*DATA).size() - (md->*DATA).size();
            for(unsigned int i = 0; i < (md->*DATA).size(); i++) {
                (md->*DATA)[i] |= (usemd->*DATA)[delta + i];
			}
		}
		void visitSExt(CastInst& inst) { visitZExt(inst); }
		void calcShift(BinaryOperator& inst, int direction) { //dir 0 =>right ,1 =>left
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
            vector<bitset<MAX_SUBBITS> > toadd = (usemd->*DATA);
            ShiftKeyBitset<MAX_SUBBITS>((direction ? 0 : 1), idx, toadd); //Invert direction.
            for(unsigned int i = 0; i < (md->*DATA).size(); i++) {
                (md->*DATA)[i] |= toadd[i];
			}
		}
		void visitShl(BinaryOperator& inst) { calcShift(inst, 1); }
		void visitLShr(BinaryOperator& inst) { calcShift(inst, 0); }
		void visitAShr(BinaryOperator& inst) {  calcShift(inst, 0);}
		void visitAnd(BinaryOperator& inst) {
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
            auto size = (md->*DATA).size();
			for(unsigned int i = 0; i < size; i++) {
				if(is_bit_set(mask, i)) {
                    (md->*DATA)[size - 1 - i] = (md->*DATA)[size - 1 - i] | (usemd->*DATA)[size - 1 - i];
				}
			}
		}
		void calcAsBiggestSum(Instruction& inst) {
            bitset<MAX_SUBBITS> ob(0);
        for(bitset<MAX_SUBBITS> b: (usemd->*DATA)) {
				ob |= b;
			}
            for(unsigned int i = 0; i < (md->*DATA).size(); i++) {
                (md->*DATA)[i] |= ob;
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
            for(int i = 0; i < (md->*DATA).size();i++ )
            {
                if(md->deadBits[i]) (md->*DATA)[i].reset();
            }
        }
		void visitCallInst(CallInst& inst) {calcAsBiggestSum(inst);}
};
