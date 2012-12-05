#include <algorithm>
using namespace llvm;
// Save Our Souls per debugging:
static void dump(NoCryptoFA::InstructionMetadata* md){
for(bitset<MAX_OUTBITS> b: md->post){
cerr << b.count() << "-";
}
cerr << endl;
}
//name = shl12345
static void debug(int pre,std::string name,NoCryptoFA::InstructionMetadata* md){
    if(!md->my_instruction->getName().str().compare(name)){
        cerr << name << " - " << (pre?"pre":"post")<< " - ";
    dump(md);
    }

}

template<typename T>
static void Calc_Pre_BitwiseOr(bool& changed, T* ptr, NoCryptoFA::InstructionMetadata* md)
{
	for(User::const_op_iterator it = ptr->op_begin(); it != ptr->op_end(); ++it) {
		if(Instruction* _it = dyn_cast<Instruction>(*it)) {
			int size = std::min(NoCryptoFA::known[_it]->pre.size(), md->pre.size());
			for(int i = 0; i < size; ++i) {
				set_if_changed<MAX_KEYBITS>(changed, &(md->pre[i]), md->pre[i] | NoCryptoFA::known[_it]->pre[i]);
				if(NoCryptoFA::known[_it]->own.any()) {
                    set_if_changed<MAX_KEYBITS>(changed, &(md->pre[i]), md->pre[i] | NoCryptoFA::known[_it]->own); // diagonale, non blocchettino!
				}
			}
		}
	}
}

template<typename T>
static void Calc_Pre_TFMatrixOr(bool& changed, T* ptr, NoCryptoFA::InstructionMetadata* md)
{
	bitset<MAX_KEYBITS> tmp(0);
	int size = md->pre.size();
	Instruction* trueval = cast<Instruction>(ptr->getTrueValue());
	Instruction* falseval = cast<Instruction>(ptr->getFalseValue());
	for(int i = 0; i < size; ++i) {
		tmp |= NoCryptoFA::known[trueval]->pre[i];
		tmp |= NoCryptoFA::known[falseval]->pre[i];
		if(NoCryptoFA::known[trueval]->own.any()) {
			tmp |= NoCryptoFA::known[trueval]->own;
		}
		if(NoCryptoFA::known[falseval]->own.any()) {
			tmp |= NoCryptoFA::known[falseval]->own;
		}
		set_if_changed<MAX_KEYBITS>(changed, &(md->pre[i]), tmp);
	}
}
template<typename T>
static void Calc_Pre_BiggestSum(bool& changed, T* ptr, NoCryptoFA::InstructionMetadata* md)
{
	bitset<MAX_KEYBITS> max(0);
	for(User::const_op_iterator it = ptr->op_begin(); it != ptr->op_end(); ++it) {
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
		set_if_changed<MAX_KEYBITS>(changed, &(md->pre[i]), max);
	}
}
template<int NUMBITS>
static void ShiftKeyBitset(int direction, unsigned int idx, bool& changed, std::vector<std::bitset<NUMBITS> > &vec)
{
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
	changed = true; //dovrei confrontare....ne val la pena? TBD
}
#define is_bit_set(what,num) ((what) & (1<<(num)))
static void Calc_Pre_And(bool& changed, BinaryOperator* ptr, NoCryptoFA::InstructionMetadata* md)
{
	Value* v1 = ptr->getOperand(0);
	Value* v2 = ptr->getOperand(1);
	ConstantInt* ci;
	Instruction* i;
	if(isa<ConstantInt>(v2) && isa<Instruction>(v1)) {
		ci = cast<ConstantInt>(v2);
		i = cast<Instruction>(v1);
	} else if(isa<ConstantInt>(v1) && isa<Instruction>(v2)) {
		ci = cast<ConstantInt>(v1);
		i = cast<Instruction>(v2);
	} else {
		Calc_Pre_BitwiseOr(changed, ptr, md);
		return;
	}
	unsigned long mask = ci->getLimitedValue();
	NoCryptoFA::InstructionMetadata* other = NoCryptoFA::known[i];
	auto size = md->pre.size();
	for(unsigned int i = 0; i < size; i++) {
		if(is_bit_set(mask, i)) {
			md->pre[size - 1 - i] = other->pre[size - 1 - i];
		} else {
			md->pre[size - 1 - i] = bitset<MAX_KEYBITS>(0);
		}
	}
	changed = true; //dovrei confrontare....ne val la pena? TBD
}
void postCopyUp( NoCryptoFA::InstructionMetadata* md, NoCryptoFA::InstructionMetadata* usemd)
{
    int size = std::min(md->post.size(), usemd->post.size());
    for(int i = 0; i < size;i++){
        md->post[i] |= usemd->post[i];
    }
}

static void Calc_Post_And(BinaryOperator* ptr, NoCryptoFA::InstructionMetadata* md, NoCryptoFA::InstructionMetadata* usemd)
{
    Value* v1 = ptr->getOperand(0);
    Value* v2 = ptr->getOperand(1);
    ConstantInt* ci;
    Instruction* i;
    if(isa<ConstantInt>(v2) && isa<Instruction>(v1)) {
        ci = cast<ConstantInt>(v2);
        i = cast<Instruction>(v1);
    } else if(isa<ConstantInt>(v1) && isa<Instruction>(v2)) {
        ci = cast<ConstantInt>(v1);
        i = cast<Instruction>(v2);
    } else {
        postCopyUp( md,usemd);
        return;
    }
    unsigned long mask = ci->getLimitedValue();
    auto size = md->post.size();
    for(unsigned int i = 0; i < size; i++) {
        if(is_bit_set(mask, i)) {
            md->post[size - 1 - i] = md->post[size - 1 - i] | usemd->post[size - 1 - i];
        }
    }

}
static void Calc_Pre_Shift(bool& changed, BinaryOperator* ptr, NoCryptoFA::InstructionMetadata* md)
{
	Value* v_idx = ptr->getOperand(1);
	if(!isa<ConstantInt>(v_idx)) { cerr << "Shift by a non-constant index. Results undefined."; return; }
	ConstantInt* ci = cast<ConstantInt>(v_idx);
	unsigned long idx = ci->getLimitedValue();
	Calc_Pre_BitwiseOr(changed, ptr, md);
	if(ptr->getOpcode() == Instruction::Shl) {
        ShiftKeyBitset<MAX_KEYBITS>(1, idx, changed, md->pre);
	} else {
        ShiftKeyBitset<MAX_KEYBITS>(0, idx, changed, md->pre);
	}
	changed = true; //dovrei confrontare....ne val la pena? TBD
}
static void Calc_Post_BiggestSum(Instruction* ptr, NoCryptoFA::InstructionMetadata* md,NoCryptoFA::InstructionMetadata* usemd){
    bitset<MAX_OUTBITS> ob(0);
    for(bitset<MAX_OUTBITS> b: usemd->post){
        ob |= b;
    }
    for(int i = 0; i < md->post.size();i++){
        md->post[i] |= ob;
    }
}
static void Calc_Post_Shift(BinaryOperator* ptr, NoCryptoFA::InstructionMetadata* md,NoCryptoFA::InstructionMetadata* usemd)
{
    Value* v_idx = ptr->getOperand(1);
    if(!isa<ConstantInt>(v_idx)) { cerr << "Shift by a non-constant index. Results undefined."; return; }
    ConstantInt* ci = cast<ConstantInt>(v_idx);
    unsigned long idx = ci->getLimitedValue();
    vector<bitset<MAX_OUTBITS> > toadd = usemd->post;
    bool changed=false;
    if(ptr->getOpcode() == Instruction::Shl) {
        ShiftKeyBitset<MAX_OUTBITS>(0, idx, changed, toadd); //left => right
    } else {
        ShiftKeyBitset<MAX_OUTBITS>(1, idx, changed, toadd); //right => left
    }
    for(int i = 0; i < md->post.size();i++){
        md->post[i] |= toadd[i];
    }
}

static void Calc_Pre_Extend(bool& changed, CastInst* ptr, NoCryptoFA::InstructionMetadata* md)
{
	Calc_Pre_BitwiseOr(changed, ptr, md);
	int from = CalcDFG::getOperandSize(ptr->getSrcTy());
	int to = CalcDFG::getOperandSize(ptr->getDestTy());
    ShiftKeyBitset<MAX_KEYBITS>(0, to - from, changed, md->pre);
}
static void Calc_Pre_Trunc(bool& changed, CastInst* ptr, NoCryptoFA::InstructionMetadata* md)
{
	unsigned int from = CalcDFG::getOperandSize(ptr->getSrcTy());
	unsigned int to = CalcDFG::getOperandSize(ptr->getDestTy());
	unsigned int diff = from - to;
	NoCryptoFA::InstructionMetadata* other = NoCryptoFA::known[cast<Instruction>(ptr->getOperand(0))];
	for(unsigned int i = 0; i < md->pre.size(); i++) { md->pre[i] = other->pre[diff + i]; }
	changed = true; //dovrei confrontare....ne val la pena? TBD
}

static void usualMaskingLogic_post(Instruction* ptr, NoCryptoFA::InstructionMetadata* md)
{
    bool hasEmpty = false;
    bool retval = false;
if(!md->hasMetPlaintext) {md->hasToBeProtected_pre=false; return; }
for(bitset<MAX_OUTBITS> b : md->post) {
        if(b.count() < SecurityMargin.getValue()) {
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
md->hasToBeProtected_post=retval;
    return ;
}
static void usualMaskingLogic_pre(Instruction* ptr, NoCryptoFA::InstructionMetadata* md)
{
	bool hasEmpty = false;
    bool retval = false;
    if(!md->hasMetPlaintext) {md->hasToBeProtected_post=false; return; }

for(bitset<MAX_KEYBITS> b : md->pre) {
		if(b.count() < SecurityMargin.getValue()) {
			hasEmpty = true;
			break;
		}
	}
    retval = hasEmpty;
    if(retval) {
		bool removeFlag = true;
		for(auto it = md->my_instruction->op_begin(); it != md->my_instruction->op_end(); ++it) {
			if(!isa<Instruction>(it)) { continue; }
			NoCryptoFA::InstructionMetadata* opmd = NoCryptoFA::known[cast<Instruction>(it)];
			if(!opmd->hasMetPlaintext) { removeFlag = false; break; }
            if(opmd->hasMetPlaintext && opmd->hasToBeProtected_pre) { removeFlag = false; break; }
		}
        if(removeFlag) { retval = false; }
	}
    md->hasToBeProtected_pre=retval;
    return ;
}

template<typename T>
struct CalcTraits {
	public:
    static void calcPost(T* ptr, NoCryptoFA::InstructionMetadata* md, NoCryptoFA::InstructionMetadata* usemd) {
        postCopyUp(md,usemd);
    }
        static void calcPre(bool& changed, T* ptr, NoCryptoFA::InstructionMetadata* md) {
			Calc_Pre_BitwiseOr(changed, ptr, md);
		}
        static void needsMasking_pre(T* ptr, NoCryptoFA::InstructionMetadata* md) {
            usualMaskingLogic_pre(ptr, md);
		}
        static void needsMasking_post(T* ptr, NoCryptoFA::InstructionMetadata* md) {
            usualMaskingLogic_post(ptr, md);
        }
};

template<>
struct CalcTraits<SelectInst> {
	public:
    static void calcPost(SelectInst*ptr, NoCryptoFA::InstructionMetadata* md, NoCryptoFA::InstructionMetadata* usemd) {
        postCopyUp(md,usemd);
    }

        static void calcPre(bool& changed, SelectInst* ptr, NoCryptoFA::InstructionMetadata* md) {
			Calc_Pre_TFMatrixOr(changed, ptr, md);
		}
        static void needsMasking_pre(SelectInst* ptr, NoCryptoFA::InstructionMetadata* md) {
            md->hasToBeProtected_pre = false;
			if(!md->hasMetPlaintext) { return; }
			Instruction* trueval = cast<Instruction>(ptr->getTrueValue());
			Instruction* falseval = cast<Instruction>(ptr->getFalseValue());
			// checkNeedsMasking(trueval,NoCryptoFA::known[trueval]);
			//checkNeedsMasking(falseval,NoCryptoFA::known[falseval]);
            md->hasToBeProtected_pre |= NoCryptoFA::known[trueval]->hasToBeProtected_pre; //rischio segfault se non è istruzione

            md->hasToBeProtected_pre |= NoCryptoFA::known[falseval]->hasToBeProtected_pre; //rischio segfault se non  è istuzione
			return;
		}
        static void needsMasking_post(SelectInst* ptr, NoCryptoFA::InstructionMetadata* md) {
            usualMaskingLogic_post(ptr, md);
        }

};
template<>
struct CalcTraits<CallInst> {
    public:
    static void calcPost(CallInst* ptr, NoCryptoFA::InstructionMetadata* md, NoCryptoFA::InstructionMetadata* usemd) {
        Calc_Post_BiggestSum(ptr,md,usemd);
    }
        static void calcPre(bool& changed, CallInst* ptr, NoCryptoFA::InstructionMetadata* md) {
            Calc_Pre_BiggestSum(changed, ptr, md);
        }
        static void needsMasking_pre(CallInst* ptr, NoCryptoFA::InstructionMetadata* md) {
            usualMaskingLogic_pre(ptr, md);
        }
        static void needsMasking_post(CallInst* ptr, NoCryptoFA::InstructionMetadata* md) {
            usualMaskingLogic_post(ptr, md);
        }
};
template<>
struct CalcTraits<GetElementPtrInst> {
	public:
    static void calcPost(GetElementPtrInst* ptr, NoCryptoFA::InstructionMetadata* md, NoCryptoFA::InstructionMetadata* usemd) {
        Calc_Post_BiggestSum(ptr,md,usemd);
}
        static void calcPre(bool& changed, GetElementPtrInst* ptr, NoCryptoFA::InstructionMetadata* md) {
			Calc_Pre_BiggestSum(changed, ptr, md);
		}
        static void needsMasking_pre(GetElementPtrInst* ptr, NoCryptoFA::InstructionMetadata* md) {
            usualMaskingLogic_pre(ptr, md);
		}
        static void needsMasking_post(GetElementPtrInst* ptr, NoCryptoFA::InstructionMetadata* md) {
            usualMaskingLogic_post(ptr, md);
        }


};

template<>
struct CalcTraits<BinaryOperator> {
	public:
    static void calcPost( BinaryOperator* ptr, NoCryptoFA::InstructionMetadata* md, NoCryptoFA::InstructionMetadata* usemd) {
        switch(ptr->getOpcode()) {
            case Instruction::And:
                Calc_Post_And(ptr, md,usemd);
                break;
            case Instruction::Or:
            case Instruction::Xor:
            case Instruction::Add:
            case Instruction::FAdd:
            case Instruction::Sub:
            case Instruction::FSub:
                postCopyUp(md,usemd);
                break;
            case Instruction::Mul:
            case Instruction::FMul:
            case Instruction::UDiv:
            case Instruction::SDiv:
            case Instruction::FDiv:
            case Instruction::URem:
            case Instruction::SRem:
            case Instruction::FRem:
                Calc_Post_BiggestSum(ptr, md,usemd);
                break;
            case Instruction::Shl:
            case Instruction::LShr:
            case Instruction::AShr:
                Calc_Post_Shift(ptr, md,usemd);
                break;
            case Instruction::BinaryOpsEnd:
                break;
        }

}
        static void calcPre(bool& changed, BinaryOperator* ptr, NoCryptoFA::InstructionMetadata* md) {
			switch(ptr->getOpcode()) {
				case Instruction::And:
					Calc_Pre_And(changed, ptr, md);
					break;
				case Instruction::Or:
				case Instruction::Xor:
				case Instruction::Add:
				case Instruction::FAdd:
				case Instruction::Sub:
				case Instruction::FSub:
					Calc_Pre_BitwiseOr(changed, ptr, md);
					break;
				case Instruction::Mul:
				case Instruction::FMul:
				case Instruction::UDiv:
				case Instruction::SDiv:
				case Instruction::FDiv:
				case Instruction::URem:
				case Instruction::SRem:
				case Instruction::FRem:
					Calc_Pre_BiggestSum(changed, ptr, md);
					break;
				case Instruction::Shl:
				case Instruction::LShr:
				case Instruction::AShr:
					Calc_Pre_Shift(changed, ptr, md);
					break;
				case Instruction::BinaryOpsEnd:
					break;
			}
		}
        static void needsMasking_pre(BinaryOperator* ptr, NoCryptoFA::InstructionMetadata* md) {
			Value* v1;
			Value* v2;
			if(!md->hasMetPlaintext) { return; }
			switch(md->my_instruction->getOpcode()) {
				case Instruction::Shl:
				case Instruction::LShr:
				case Instruction::AShr:
					//orrido, ma funziona
                    md->hasToBeProtected_pre = NoCryptoFA::known[cast<Instruction>(ptr->getOperand(0))]->hasToBeProtected_pre;
					return;
				case Instruction::And:
					v1 = ptr->getOperand(0);
					v2 = ptr->getOperand(1);
					Instruction* i;
					if(isa<ConstantInt>(v2) && isa<Instruction>(v1)) {
						i = cast<Instruction>(v1);
					} else if(isa<ConstantInt>(v1) && isa<Instruction>(v2)) {
						i = cast<Instruction>(v2);
					} else { break;}
                    md->hasToBeProtected_pre = NoCryptoFA::known[i]->hasToBeProtected_pre;
					return;
					break;
			}
            usualMaskingLogic_pre(ptr, md);
		}
        static void needsMasking_post(BinaryOperator* ptr, NoCryptoFA::InstructionMetadata* md) {
            usualMaskingLogic_post(ptr, md);
        }
};
template<>
struct CalcTraits<CastInst> {
	public:
    static void calcPost(CastInst* ptr, NoCryptoFA::InstructionMetadata* md, NoCryptoFA::InstructionMetadata* usemd) {
        int delta;
            switch(ptr->getOpcode()) {
                case Instruction::Trunc:
                 delta=md->post.size()-usemd->post.size();
                    for(int i = 0; i < usemd->post.size();i++){
                        md->post[delta+i] |= usemd->post[i];
                    }
                    break;
                case Instruction::ZExt:
                case Instruction::SExt:
                 delta=usemd->post.size()-md->post.size();
                    for(int i = 0; i < md->post.size();i++){
                        md->post[i] |= usemd->post[delta+i];
                    }
                    break;
                case Instruction::FPToUI:
                case Instruction::FPToSI:
                case Instruction::UIToFP:
                case Instruction::SIToFP:
                case Instruction::FPTrunc:
                case Instruction::FPExt:
                case Instruction::PtrToInt:
                case Instruction::IntToPtr:
                case Instruction::BitCast:
                case Instruction::CastOpsEnd:
                    postCopyUp(md,usemd);
                    break;
            }
        }
        static void calcPre(bool& changed, CastInst* ptr, NoCryptoFA::InstructionMetadata* md) {
			switch(ptr->getOpcode()) {
				case Instruction::Trunc:
					Calc_Pre_Trunc(changed, ptr, md);
					break;
				case Instruction::ZExt:
				case Instruction::SExt:
					Calc_Pre_Extend(changed, ptr, md);
					break;
				case Instruction::FPToUI:
				case Instruction::FPToSI:
				case Instruction::UIToFP:
				case Instruction::SIToFP:
				case Instruction::FPTrunc:
				case Instruction::FPExt:
				case Instruction::PtrToInt:
				case Instruction::IntToPtr:
				case Instruction::BitCast:
				case Instruction::CastOpsEnd:
					Calc_Pre_BitwiseOr(changed, ptr, md);
					break;
			}
		}
        static void needsMasking_pre(CastInst* ptr, NoCryptoFA::InstructionMetadata* md) {

			if(!md->hasMetPlaintext) { return; }
            md->hasToBeProtected_pre = NoCryptoFA::known[cast<Instruction>(ptr->getOperand(0))]->hasToBeProtected_pre;
        }
        static void needsMasking_post(CastInst* ptr, NoCryptoFA::InstructionMetadata* md) {
                md->hasToBeProtected_post=false;
                for(auto it = md->my_instruction->use_begin(); it != md->my_instruction->use_end(); ++it) {
                    if(!isa<Instruction>(*it)) { continue; }
                    NoCryptoFA::InstructionMetadata* usemd = NoCryptoFA::known[cast<Instruction>(*it)];
                    if(usemd->hasToBeProtected_post) { md->hasToBeProtected_post=true; break; }
                }

		}
};
