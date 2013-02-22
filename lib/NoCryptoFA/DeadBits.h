#pragma once
#include "llvm/NoCryptoFA/All.h"
#include <llvm/Constants.h>
using namespace llvm;
std::map<Value*,bitset<MAX_VALBITS> > cache;

void calcDeadBits(Instruction* ptr){
    if(!isa<GetElementPtrInst>(ptr)) return;

    NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[ptr];
    if(md->deadBitsCalculated){return;}
    md->deadBits.reset();
    md->deadBitsCalculated = true;
    Value* pointed = (cast<GetElementPtrInst>(ptr))->getPointerOperand();
    Value* symbol = pointed;
    if(cache.find(symbol) == cache.end()){
        if(isa<GlobalVariable>(pointed)){ pointed=(dyn_cast<GlobalVariable>(pointed))->getInitializer();}
        if(dyn_cast<ConstantDataSequential>(pointed) == NULL)  return;
        ConstantDataSequential *v = cast<ConstantDataSequential>(pointed);
        if(!isa<IntegerType>(v->getElementType())) return;
        bitset<MAX_VALBITS> or_all;
        bitset<MAX_VALBITS> and_all;
        bitset<MAX_VALBITS> *thisone;
        and_all.set();
        or_all.reset();
        for(unsigned int i = 0; i < v->getNumElements();i++){
            thisone=new bitset<MAX_VALBITS>(v->getElementAsInteger(i));
            and_all &= *thisone;
            or_all |= *thisone;
            delete thisone;
        }
        md->deadBits.reset();
        md->deadBits |= ~or_all;
        md->deadBits |= and_all;
        bitset<MAX_VALBITS> mask_notexisting;
        mask_notexisting.set();
        mask_notexisting <<= cast<IntegerType>(v->getElementType())->getBitWidth();
        md->deadBits &= ~mask_notexisting;
        if(md->deadBits.count() > 0){
            errs() << "Are you aware that " << symbol->getName() << " has " << md->deadBits.count() << " dead bits?\n";
        }
        cache[symbol]=md->deadBits;
    }
    else{
        md->deadBits = cache[symbol];
    }
}

