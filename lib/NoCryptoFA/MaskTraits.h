#pragma once

static bool unsupportedInstruction(Instruction* ptr){
    cerr << "Missing opcode mask equivalent:" << ptr->getOpcodeName() << endl;
    return false;
}
template<typename T>
struct MaskTraits {
    public:
        static bool replaceWithMasked(T* ptr,NoCryptoFA::InstructionMetadata* md) {
            return unsupportedInstruction(cast<Instruction>(ptr));
        }
};

template <>
struct MaskTraits<BinaryOperator> {
    public:
        static bool replaceWithMasked(BinaryOperator* ptr,NoCryptoFA::InstructionMetadata* md) {
            llvm::IRBuilder<> ib = llvm::IRBuilder<>(ptr->getContext());
            ib.SetInsertPoint(ptr);

            switch(ptr->getOpcode()) {
                case Instruction::And:
                    {
                        llvm::Function& rand = GetRandomFn(ptr->getParent()->getParent()->getParent());
                        vector<Value*> op1 =MaskValue(ptr->getOperand(0),ptr);
                        vector<Value*> op2 =MaskValue(ptr->getOperand(1),ptr);
                        /*  x = rand()
                            %1=a[0] AND b[1]
                            %2=a[1] AND b[0]
                            %3= x XOR %1
                            y = %3 XOR %2
                            %4=a[0] AND b[0]
                            c[0] = %4 XOR x
                            %5=a[1] AND b[1]
                            c[1] = %5 XOR y
                         */
                        llvm::Value* x = ib.CreateCall(&rand);
                        llvm::Value* t1 = ib.CreateAnd(op1[0],op2[1]);
                        llvm::Value* t2 = ib.CreateAnd(op1[1],op2[0]);
                        llvm::Value* t3 = ib.CreateXor(x,t1);
                        llvm::Value* y = ib.CreateXor(t3,t2);
                        llvm::Value* t4 = ib.CreateAnd(op1[0],op2[0]);
                        llvm::Value* t5 = ib.CreateAnd(op1[1],op2[1]);
                        md->MaskedValues.push_back(ib.CreateXor(t4,x));
                        md->MaskedValues.push_back(ib.CreateXor(t5,y));
                        BuildMetadata(x,ptr,NoCryptoFA::InstructionMetadata::AND_MASKED);
                        BuildMetadata(t1,ptr,NoCryptoFA::InstructionMetadata::AND_MASKED);
                        BuildMetadata(t2,ptr,NoCryptoFA::InstructionMetadata::AND_MASKED);
                        BuildMetadata(t3,ptr,NoCryptoFA::InstructionMetadata::AND_MASKED);
                        BuildMetadata(y,ptr,NoCryptoFA::InstructionMetadata::AND_MASKED);
                        BuildMetadata(t4,ptr,NoCryptoFA::InstructionMetadata::AND_MASKED);
                        BuildMetadata(t5,ptr,NoCryptoFA::InstructionMetadata::AND_MASKED);
                        BuildMetadata(md->MaskedValues[0],ptr,NoCryptoFA::InstructionMetadata::AND_MASKED);
                        BuildMetadata(md->MaskedValues[1],ptr,NoCryptoFA::InstructionMetadata::AND_MASKED);
                        return true;
                       }
                    break;
                case Instruction::Xor:
                    {
                        vector<Value*> op1 =MaskValue(ptr->getOperand(0),ptr);
                        vector<Value*> op2 =MaskValue(ptr->getOperand(1),ptr);
                        md->MaskedValues.push_back(ib.CreateXor(op1[0],op2[0]));
                        md->MaskedValues.push_back(ib.CreateXor(op1[1],op2[1]));
                        BuildMetadata(md->MaskedValues[0],ptr,NoCryptoFA::InstructionMetadata::XOR_MASKED);
                        BuildMetadata(md->MaskedValues[1],ptr,NoCryptoFA::InstructionMetadata::XOR_MASKED);
                        return true;
                     }
                    break;
                case Instruction::LShr:
                case Instruction::AShr:
                case Instruction::Shl:
                    if(isa<ConstantInt>(ptr->getOperand(1))){
                        vector<Value*> op =MaskValue(ptr->getOperand(0),ptr);
                        md->MaskedValues.push_back(ib.CreateLShr(op[0],ptr->getOperand(1)));
                        md->MaskedValues.push_back(ib.CreateLShr(op[1],ptr->getOperand(1)));
                        BuildMetadata(md->MaskedValues[0],ptr,NoCryptoFA::InstructionMetadata::SHIFT_MASKED);
                        BuildMetadata(md->MaskedValues[1],ptr,NoCryptoFA::InstructionMetadata::SHIFT_MASKED);
                        return true;
                    }else{
                        return unsupportedInstruction(ptr);
                    }
                    break;
                case Instruction::Or:
                case Instruction::Add:
                case Instruction::FAdd:
                case Instruction::Sub:
                case Instruction::FSub:
                case Instruction::Mul:
                case Instruction::FMul:
                case Instruction::UDiv:
                case Instruction::SDiv:
                case Instruction::FDiv:
                case Instruction::URem:
                case Instruction::SRem:
                case Instruction::FRem:
                case Instruction::BinaryOpsEnd:
                return unsupportedInstruction(ptr);
            }

        }
};

template <>
struct MaskTraits<CastInst> {
    public:
        static bool replaceWithMasked(CastInst* i,NoCryptoFA::InstructionMetadata* md) {
            switch(i->getOpcode()) {
                case Instruction::Trunc:
                case Instruction::ZExt:
                case Instruction::SExt:
                case Instruction::BitCast:
                    {
                        llvm::IRBuilder<> ib = llvm::IRBuilder<>(i->getContext());
                        ib.SetInsertPoint(i);
                        vector<Value*> op =MaskValue(i->getOperand(0),i);
                        md->MaskedValues.push_back(ib.CreateCast(i->getOpcode(),op[0],i->getDestTy()));
                        md->MaskedValues.push_back(ib.CreateCast(i->getOpcode(),op[1],i->getDestTy()));
                        BuildMetadata(md->MaskedValues[0],i,NoCryptoFA::InstructionMetadata::CAST_MASKED);
                        BuildMetadata(md->MaskedValues[1],i,NoCryptoFA::InstructionMetadata::CAST_MASKED);
                        return true;
                     }

                    break;
                    /*Masking FP values is currently not supported*/
                case Instruction::FPToUI:
                case Instruction::FPToSI:
                case Instruction::UIToFP:
                case Instruction::SIToFP:
                case Instruction::FPTrunc:
                case Instruction::FPExt:
                    /*Masking pointers can lead to interesting SEGFAULTs*/
                case Instruction::PtrToInt:
                case Instruction::IntToPtr:
                case Instruction::CastOpsEnd:
                return unsupportedInstruction(i);
            }

        }
};
