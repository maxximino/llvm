#include <llvm/Support/InstVisitor.h>
#include <llvm/NoCryptoFA/All.h>
using namespace llvm;
template<int MAXBITS,vector<bitset<MAXBITS> > NoCryptoFA::InstructionMetadata::*DATA,bitset<MAXBITS> NoCryptoFA::InstructionMetadata::*OWN, unsigned int UNPACKFLAGS>
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
class CalcForwardVisitor : public InstVisitor<CalcForwardVisitor<MAXBITS, DATA, OWN, UNPACKFLAGS> >
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
        void setDiagonal(vector<bitset<MAXBITS> >& data,bitset<MAXBITS> ownkey){
            int datapos=0;
            for(int pos=0;pos<MAXBITS;pos++){
                if(ownkey[pos]){
                    data[datapos][pos] = 1;
                    datapos++;
                    assert((size_t)datapos <= data.size());
                }
            }
        }
	public:
		void visitInstruction(Instruction& inst) {
			NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[&inst];
            md->unpack(UNPACKFLAGS);
            if((md->*OWN).any() ){
                /*for(int i = 0; i< (md->*DATA).size(); i++)
                {
                    (md->*DATA)[i]|=md->*OWN;
                }*/
                setDiagonal(md->*DATA,md->*OWN);
            }
			for(User::const_op_iterator it = inst.op_begin(); it != inst.op_end(); ++it) {
				if(Instruction* _it = dyn_cast<Instruction>(*it)) {
                    NoCryptoFA::InstructionMetadata* tmpmd = NoCryptoFA::known[_it];
                    tmpmd->unpack(UNPACKFLAGS);
                    int size = std::min((tmpmd->*DATA).size(), (md->*DATA).size());
					for(int i = 0; i < size; ++i) {
                        (md->*DATA)[i] =  (md->*DATA)[i] | (tmpmd->*DATA)[i];

					}
                    if((tmpmd->*OWN).any()) {
     //                   (md->*DATA)[i] = (md->*DATA)[i] | tmpmd->*OWN; //TODO: diagonale, non blocchettino!
                        setDiagonal(md->*DATA,tmpmd->*OWN);
                    }
                    tmpmd->pack();
				}
            }
            md->pack();
		}
		void visitTrunc(CastInst& inst) {
			NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[&inst];
			unsigned int from = CalcDFG::getOperandSize(inst.getSrcTy());
			unsigned int to = CalcDFG::getOperandSize(inst.getDestTy());
			unsigned int diff = from - to;
            NoCryptoFA::InstructionMetadata* other = NoCryptoFA::known[cast<Instruction>(inst.getOperand(0))];
            md->unpack(UNPACKFLAGS);
            other->unpack(UNPACKFLAGS);
            for(unsigned int i = 0; i < (md->*DATA).size(); i++) { (md->*DATA)[i] = (other->*DATA)[diff + i]; }
            md->pack();
            other->pack();
		}
		void visitZExt(CastInst& inst) {
			NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[&inst];
			visitInstruction(inst);
            md->unpack(UNPACKFLAGS);
			int from = CalcDFG::getOperandSize(inst.getSrcTy());
			int to = CalcDFG::getOperandSize(inst.getDestTy());
            ShiftKeyBitset<MAXBITS>(0, to - from, md->*DATA);
            md->pack();
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
            md->unpack(UNPACKFLAGS);
            ShiftKeyBitset<MAXBITS>(direction, idx, md->*DATA);
            md->pack();
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
            md->unpack(UNPACKFLAGS);
            other->unpack(UNPACKFLAGS);
            auto size = (md->*DATA).size();
			for(unsigned int i = 0; i < size; i++) {
				if(is_bit_set(mask, i)) {
                    (md->*DATA)[size - 1 - i] = (other->*DATA)[size - 1 - i];
				} else {
                    (md->*DATA)[size - 1 - i] = bitset<MAXBITS>(0);
				}
			}
            md->pack();
            other->pack();
		}
		void calcAsBiggestSum(Instruction& inst) {
			NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[&inst];
            md->unpack(UNPACKFLAGS);
            bitset<MAXBITS> max(0);
			for(User::const_op_iterator it = inst.op_begin(); it != inst.op_end(); ++it) {
				if(Instruction* _it = dyn_cast<Instruction>(*it)) {
                    NoCryptoFA::InstructionMetadata* tmpmd = NoCryptoFA::known[_it];
                    tmpmd->unpack(UNPACKFLAGS);
                    int size = (tmpmd->*DATA).size();
					for(int i = 0; i < size; ++i) {
                        max |= (NoCryptoFA::known[_it]->*DATA)[i];
                        if((NoCryptoFA::known[_it]->*OWN).any()) {
                            max |= NoCryptoFA::known[_it]->*OWN;
						}
					}
                    tmpmd->pack();
				}
			}
            int size = (md->*DATA).size();
			for(int i = 0; i < size; ++i) {
                (md->*DATA)[i] =  max;
			}
            md->pack();
		}
		void visitMul(BinaryOperator& inst) {calcAsBiggestSum(inst);}
		void visitUDiv(BinaryOperator& inst) {calcAsBiggestSum(inst);}
		void visitSMul(BinaryOperator& inst) {calcAsBiggestSum(inst);}
		void visitURem(BinaryOperator& inst) {calcAsBiggestSum(inst);}
		void visitSRem(BinaryOperator& inst) {calcAsBiggestSum(inst);}

        void visitGetElementPtrInst(GetElementPtrInst& inst) {
            calcAsBiggestSum(inst);
            NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[&inst];
            md->unpack(UNPACKFLAGS);
            for(unsigned long i = 0; i < (md->*DATA).size();i++ )
            {
                if(md->deadBits[i]) (md->*DATA)[i].reset();
            }
            md->pack();
        }
		void visitCallInst(CallInst& inst) {calcAsBiggestSum(inst);}
		void visitSelectInst(SelectInst& inst) {
			NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[&inst];
            md->unpack(UNPACKFLAGS);
            bitset<MAXBITS> tmp(0);
            int size = (md->*DATA).size();
			Instruction* trueval = cast<Instruction>(inst.getTrueValue());
			Instruction* falseval = cast<Instruction>(inst.getFalseValue());
            NoCryptoFA::InstructionMetadata* true_md = NoCryptoFA::known[trueval];
            NoCryptoFA::InstructionMetadata* false_md = NoCryptoFA::known[falseval];
            true_md->unpack(UNPACKFLAGS);
            false_md->unpack(UNPACKFLAGS);
			for(int i = 0; i < size; ++i) {
                tmp |= (true_md->*DATA)[i];
                tmp |= (false_md->*DATA)[i];
                if((true_md->*OWN).any()) {
                    tmp |= true_md->*OWN;
				}
                if((false_md->*OWN).any()) {
                    tmp |= false_md->*OWN;
				}
                (md->*DATA)[i] = tmp;
			}
            true_md->pack();
            false_md->pack();
            md->pack();
		}
};
