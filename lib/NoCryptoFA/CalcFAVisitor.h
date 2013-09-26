#include <llvm/Support/InstVisitor.h>
using namespace llvm;
/*template<int MAXBITS,vector<bitset<MAXBITS> > NoCryptoFA::InstructionMetadata::*DATA,bitset<MAXBITS>
         NoCryptoFA::InstructionMetadata::*OWN>*/
class CalcFAVisitor : public InstVisitor<CalcFAVisitor>
{
    protected:
        template<int NUMBITS>
        static void ShiftKeyBitset(int direction, unsigned int idx, vector<vector<std::bitset<NUMBITS> > >& vec) {
            vector< vector<std::bitset<NUMBITS> > > tmp;
            tmp.resize(vec.size());
            if(idx >= vec.size()) {
                cerr << "Shifting by " << idx << " a " << vec.size() << "bit  data type.Expect something wrong." << endl;
            }
            unsigned int maxcp = (vec.size() - idx);
            if(direction) {
                //a sinistra
                for(unsigned int i = 0; i < maxcp; i++) { tmp[i] = vec[i + idx]; }
                for(unsigned int i = 0; i < idx; i++) { tmp[maxcp + i] = vector<bitset<NUMBITS> >(MAX_OUTBITS,bitset<NUMBITS>(0)); }
            } else {
                //a destra
                for(unsigned int i = 0; i < idx; i++) { tmp[i] = vector<bitset<NUMBITS> >(MAX_OUTBITS,bitset<NUMBITS>(0)); }
                for(unsigned int i = 0; i < maxcp; i++) { tmp[idx + i] = vec[i]; }
            }
            for(unsigned int i = 0; i < vec.size(); i++) { vec[i] = tmp[i]; }
        }
    public:
        NoCryptoFA::InstructionMetadata* md;
        NoCryptoFA::InstructionMetadata* usemd;
        void visitInstruction(Instruction& inst) {
            unsigned long size = std::min(md->fault_keys.size(), usemd->fault_keys.size());
            unsigned long outbits = md->fault_keys[0].size(); //performance opt.
            for(unsigned long i = 0; i < size; i++) {
                for(unsigned long j = 0; j < outbits; j++){
                    md->fault_keys[i][j] |= usemd->fault_keys[i][j];
                }
            }
        }
        void visitTrunc(CastInst& inst) {
            int delta = md->fault_keys.size() - usemd->fault_keys.size();
            for(unsigned int i = 0; i < usemd->fault_keys.size(); i++) {
                for(unsigned long j = 0; j < md->fault_keys[i].size(); j++){
                    md->fault_keys[delta + i][j] |= usemd->fault_keys[i][j];
                }
            }
        }
        void visitZExt(CastInst& inst) {
            int delta = usemd->fault_keys.size() - md->fault_keys.size();
            for(unsigned int i = 0; i < md->fault_keys.size(); i++) {
                for(unsigned long j = 0; j < md->fault_keys[i].size(); j++){
                    md->fault_keys[i][j] |= usemd->fault_keys[delta + i][j];
                }
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
            vector<vector<bitset<MAX_KMBITS> > > toadd = usemd->fault_keys;
            ShiftKeyBitset<MAX_KMBITS>((direction?0:1), idx, toadd); // Invert direction.
            for(unsigned int i = 0; i < md->fault_keys.size(); i++) {
                for(unsigned long j = 0; j < md->fault_keys[i].size(); j++){
                    md->fault_keys[i][j] |= toadd[i][j];
                }
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
            auto size = md->fault_keys.size();
            for(unsigned long i = 0; i < size; i++) {
                if(is_bit_set(mask, size-1-i)) {
                    for(unsigned long j = 0; j < md->fault_keys[i].size(); j++){
                        md->fault_keys[i][j] |= usemd->fault_keys[i][j];
                    }
                }
            }
        }
        void calcAsBiggestSum(Instruction& inst) {

            for(int outputbit = 0; outputbit < MAX_OUTBITS; outputbit++){
                bitset<MAX_KMBITS>  tmp(0);
                for(unsigned long databit = 0; databit < usemd->fault_keys.size(); databit++){
                    tmp |= usemd->fault_keys[databit][outputbit];
                }
                for(unsigned long databit = 0; databit < md->fault_keys.size(); databit++){
                    md->fault_keys[databit][outputbit] |= tmp;
                }
            }
        }
        void visitMul(BinaryOperator& inst) {calcAsBiggestSum(inst);}
        void visitUDiv(BinaryOperator& inst) {calcAsBiggestSum(inst);}
        void visitSMul(BinaryOperator& inst) {calcAsBiggestSum(inst);}
        void visitURem(BinaryOperator& inst) {calcAsBiggestSum(inst);}
        void visitSRem(BinaryOperator& inst) {calcAsBiggestSum(inst);}
        void visitGetElementPtrInst(GetElementPtrInst& inst) {
            calcAsBiggestSum(inst);
            for(unsigned long i = 0; i < md->fault_keys.size();i++ )
            {
                if(usemd->deadBits[i]) md->fault_keys[i] = vector<bitset<MAX_KMBITS > >(MAX_OUTBITS,bitset<MAX_KMBITS>(0));
            }

        }
        void visitCallInst(CallInst& inst) {calcAsBiggestSum(inst);}
};
