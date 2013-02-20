#include <llvm/Support/InstVisitor.h>
using namespace llvm;

class NeedsMaskPreVisitor : public InstVisitor<NeedsMaskPreVisitor>
{
	public:
		void visitInstruction(Instruction& inst) {
			NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[&inst];
			bool hasEmpty = false;
			bool retval = false;
        for(bitset<MAX_KEYBITS> b : md->keydep) {
				if(b.count() < SecurityMargin.getValue()) {
					hasEmpty = true;
					break;
				}
			}
			retval = hasEmpty;
			if(retval) {
				bool removeFlag = true;
				for(auto it = inst.op_begin(); it != inst.op_end(); ++it) {
					if(!isa<Instruction>(it)) { continue; }
					NoCryptoFA::InstructionMetadata* opmd = NoCryptoFA::known[cast<Instruction>(it)];
					if(!opmd->hasMetPlaintext) { removeFlag = false; break; }
					if(opmd->hasMetPlaintext && opmd->hasToBeProtected_pre) { removeFlag = false; break; }
				}
				if(removeFlag) { retval = false; }
			}
			md->hasToBeProtected_pre = retval;
		}
		void visitCastInst(CastInst& inst) {
			NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[&inst];
			md->hasToBeProtected_pre = NoCryptoFA::known[cast<Instruction>(inst.getOperand(0))]->hasToBeProtected_pre;
		}
		void calcShift(BinaryOperator& inst, int direction) { //0=>right, 1=>left
			NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[&inst];
			md->hasToBeProtected_pre = NoCryptoFA::known[cast<Instruction>(inst.getOperand(0))]->hasToBeProtected_pre;
		}
		void visitShl(BinaryOperator& inst) { calcShift(inst, 1); }
		void visitLShr(BinaryOperator& inst) { calcShift(inst, 0);}
		void visitAShr(BinaryOperator& inst) { calcShift(inst, 0); }
		void visitAnd(BinaryOperator& inst) {
			NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[&inst];
			Value* v1 = inst.getOperand(0);
			Value* v2 = inst.getOperand(1);
			Instruction* i;
			if(isa<ConstantInt>(v2) && isa<Instruction>(v1)) {
				i = cast<Instruction>(v1);
				md->hasToBeProtected_pre = NoCryptoFA::known[i]->hasToBeProtected_pre;
			} else if(isa<ConstantInt>(v1) && isa<Instruction>(v2)) {
				i = cast<Instruction>(v2);
				md->hasToBeProtected_pre = NoCryptoFA::known[i]->hasToBeProtected_pre;
			} else {
				visitInstruction(inst);
			}
		}
		void visitSelectInst(SelectInst& inst) {
			NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[&inst];
			md->hasToBeProtected_pre = false;
			if(isa<Instruction>(inst.getTrueValue())) {
				md->hasToBeProtected_pre |= NoCryptoFA::known[cast<Instruction>(inst.getTrueValue())]->hasToBeProtected_pre;
			}
			if(isa<Instruction>(inst.getFalseValue())) {
				md->hasToBeProtected_pre |= NoCryptoFA::known[cast<Instruction>(inst.getFalseValue())]->hasToBeProtected_pre;
			}
		}
};
