#include <llvm/Support/InstVisitor.h>
using namespace llvm;

class NeedsMaskPostVisitor : public InstVisitor<NeedsMaskPostVisitor>
{
	public:
		void visitInstruction(Instruction& inst) {
			NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[&inst];
			bool hasEmpty = false;
			bool retval = false;
        for(bitset<MAX_SUBBITS> b : md->post) {
                if(b.count() < SecurityMargin.getValue()) { // todo: FIX
					hasEmpty = true;
					break;
				}
			}
			retval = hasEmpty;
			if(retval && !md->post_FirstToMeetKey) {
				bool removeFlag = true;
				for(auto it = md->my_instruction->use_begin(); it != md->my_instruction->use_end(); ++it) {
					if(!isa<Instruction>(*it)) { continue; }
					Instruction* _it = cast<Instruction>(*it);
					NoCryptoFA::InstructionMetadata* usemd = NoCryptoFA::known[_it];
					if(usemd->hasMetPlaintext && usemd->hasToBeProtected_post) { removeFlag = false; break; }
				}
				if(removeFlag) { retval = false; }
			}
			md->hasToBeProtected_post = retval;
		}
		void visitCastInst(CastInst& inst) {
			NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[&inst];
			md->hasToBeProtected_post = false;
			for(auto it = md->my_instruction->use_begin(); it != md->my_instruction->use_end(); ++it) {
				if(!isa<Instruction>(*it)) { continue; }
				NoCryptoFA::InstructionMetadata* usemd = NoCryptoFA::known[cast<Instruction>(*it)];
				if(usemd->hasToBeProtected_post) { md->hasToBeProtected_post = true; break; }
			}
		}

};
