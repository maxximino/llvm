#include <algorithm>
using namespace llvm;

template<typename T>
static void Calc_Pre_BitwiseOr(bool& changed, T* ptr, NoCryptoFA::InstructionMetadata* md)
{
	for(User::const_op_iterator it = ptr->op_begin(); it != ptr->op_end(); ++it) {
		if(Instruction* _it = dyn_cast<Instruction>(*it)) {
			int size = std::min(NoCryptoFA::known[_it]->pre.size(), md->pre.size());
			for(int i = 0; i < size; ++i) {
				set_if_changed<MAX_KEYBITS>(changed, &(md->pre[i]), md->pre[i] | NoCryptoFA::known[_it]->pre[i]);
				if(NoCryptoFA::known[_it]->own.any()) {
					set_if_changed<MAX_KEYBITS>(changed, &(md->pre[i]), md->pre[i] | NoCryptoFA::known[_it]->own);
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
static void ShiftKeyBitset(int direction, unsigned int idx, bool& changed, NoCryptoFA::InstructionMetadata* md)
{
	std::vector<std::bitset<MAX_KEYBITS> > tmp;
	tmp.resize(md->pre.size());
	if(idx >= md->pre.size()) {
		cerr << "Shifting by " << idx << " a " << md->pre.size() << "bit  data type.Expect something wrong." << endl;
		raw_fd_ostream rerr(2, false);
		rerr << "in:" << *(md->my_instruction) << "\n";
	}
	unsigned int maxcp = (md->pre.size() - idx);
	if(direction) {
		//a sinistra
		for(unsigned int i = 0; i < maxcp; i++) { tmp[i] = md->pre[i + idx]; }
		for(unsigned int i = 0; i < idx; i++) { tmp[maxcp + i] = bitset<MAX_KEYBITS>(0); }
	} else {
		//a destra
		for(unsigned int i = 0; i < idx; i++) { tmp[i] = bitset<MAX_KEYBITS>(0); }
		for(unsigned int i = 0; i < maxcp; i++) { tmp[idx + i] = md->pre[i]; }
	}
	for(unsigned int i = 0; i < md->pre.size(); i++) { md->pre[i] = tmp[i]; }
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
static void Calc_Pre_Shift(bool& changed, BinaryOperator* ptr, NoCryptoFA::InstructionMetadata* md)
{
	Value* v_idx = ptr->getOperand(1);
	if(!isa<ConstantInt>(v_idx)) { cerr << "Shift by a non-constant index. Results undefined."; return; }
	ConstantInt* ci = cast<ConstantInt>(v_idx);
	unsigned long idx = ci->getLimitedValue();
	Calc_Pre_BitwiseOr(changed, ptr, md);
	if(ptr->getOpcode() == Instruction::Shl) {
		ShiftKeyBitset(1, idx, changed, md);
	} else {
		ShiftKeyBitset(0, idx, changed, md);
	}
	changed = true; //dovrei confrontare....ne val la pena? TBD
}

static void Calc_Pre_Extend(bool& changed, CastInst* ptr, NoCryptoFA::InstructionMetadata* md)
{
	Calc_Pre_BitwiseOr(changed, ptr, md);
	int from = CalcDFG::getOperandSize(ptr->getSrcTy());
	int to = CalcDFG::getOperandSize(ptr->getDestTy());
	ShiftKeyBitset(0, to - from, changed, md);
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

static void usualMaskingLogic(Instruction* ptr, NoCryptoFA::InstructionMetadata* md)
{
	bool hasEmpty = false;
	if(!md->hasMetPlaintext) { return; }
for(bitset<MAX_KEYBITS> b : md->pre) {
		if(b.count() < SecurityMargin.getValue()) {
			hasEmpty = true;
			break;
		}
	}
	md->hasToBeProtected = hasEmpty;
	if(md->hasToBeProtected) {
		bool removeFlag = true;
		for(auto it = md->my_instruction->op_begin(); it != md->my_instruction->op_end(); ++it) {
			if(!isa<Instruction>(it)) { continue; }
			NoCryptoFA::InstructionMetadata* opmd = NoCryptoFA::known[cast<Instruction>(it)];
			if(!opmd->hasMetPlaintext) { removeFlag = false; break; }
			if(opmd->hasMetPlaintext && opmd->hasToBeProtected) { removeFlag = false; break; }
		}
		if(removeFlag) { md->hasToBeProtected = false; }
	}
}



template<typename T>
struct CalcPreTraits {
	public:
		static void calc(bool& changed, T* ptr, NoCryptoFA::InstructionMetadata* md) {
			Calc_Pre_BitwiseOr(changed, ptr, md);
		}
		static void needsMasking(T* ptr, NoCryptoFA::InstructionMetadata* md) {
			usualMaskingLogic(ptr, md);
		}
};

template<>
struct CalcPreTraits<SelectInst> {
	public:
		static void calc(bool& changed, SelectInst* ptr, NoCryptoFA::InstructionMetadata* md) {
			Calc_Pre_TFMatrixOr(changed, ptr, md);
		}
		static void needsMasking(SelectInst* ptr, NoCryptoFA::InstructionMetadata* md) {
			md->hasToBeProtected = false;
			if(!md->hasMetPlaintext) { return; }
			Instruction* trueval = cast<Instruction>(ptr->getTrueValue());
			Instruction* falseval = cast<Instruction>(ptr->getFalseValue());
			// checkNeedsMasking(trueval,NoCryptoFA::known[trueval]);
			//checkNeedsMasking(falseval,NoCryptoFA::known[falseval]);
			cerr << "Select masked?T" << NoCryptoFA::known[trueval]->hasToBeProtected;
			md->hasToBeProtected |= NoCryptoFA::known[trueval]->hasToBeProtected; //rischio segfault se non è istruzione
			cerr << " F " << NoCryptoFA::known[falseval]->hasToBeProtected;
			md->hasToBeProtected |= NoCryptoFA::known[falseval]->hasToBeProtected; //rischio segfault se non  è istuzione
			cerr << " RIS " << md->hasToBeProtected;
			raw_fd_ostream rerr(2, false);
			rerr << " in:" << *(ptr) << "\n";
			return;
		}

};

template<>
struct CalcPreTraits<GetElementPtrInst> {
	public:
		static void calc(bool& changed, GetElementPtrInst* ptr, NoCryptoFA::InstructionMetadata* md) {
			Calc_Pre_BiggestSum(changed, ptr, md);
		}
		static void needsMasking(GetElementPtrInst* ptr, NoCryptoFA::InstructionMetadata* md) {
			usualMaskingLogic(ptr, md);
		}

};

template<>
struct CalcPreTraits<BinaryOperator> {
	public:
		static void calc(bool& changed, BinaryOperator* ptr, NoCryptoFA::InstructionMetadata* md) {
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
		static void needsMasking(BinaryOperator* ptr, NoCryptoFA::InstructionMetadata* md) {
			Value* v1;
			Value* v2;
			if(!md->hasMetPlaintext) { return; }
			switch(md->my_instruction->getOpcode()) {
				case Instruction::Shl:
				case Instruction::LShr:
				case Instruction::AShr:
					//orrido, ma funziona
					md->hasToBeProtected = NoCryptoFA::known[cast<Instruction>(ptr->getOperand(0))]->hasToBeProtected;
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
					md->hasToBeProtected = NoCryptoFA::known[i]->hasToBeProtected;
					return;
					break;
			}
			usualMaskingLogic(ptr, md);
		}
};
template<>
struct CalcPreTraits<CastInst> {
	public:
		static void calc(bool& changed, CastInst* ptr, NoCryptoFA::InstructionMetadata* md) {
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
		static void needsMasking(CastInst* ptr, NoCryptoFA::InstructionMetadata* md) {
			if(!md->hasMetPlaintext) { return; }
			md->hasToBeProtected = NoCryptoFA::known[cast<Instruction>(ptr->getOperand(0))]->hasToBeProtected;
		}
};
