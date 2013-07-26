#include "llvm/NoCryptoFA/CalcDFG.h"
#include "llvm/NoCryptoFA/All.h"
#include "llvm/Function.h"
#include "llvm/Support/ErrorHandling.h"
#include <llvm/Metadata.h>
#include <llvm/Type.h>
#include <llvm/Instructions.h>
#include <llvm/Analysis/Dominators.h>
#include <set>
#include <list>
#include <iostream>
#include <unistd.h>
#include <sys/time.h>
#include "llvm/Support/CommandLine.h"

using namespace llvm;
static cl::opt<unsigned int>
SecurityMargin("nocryptofa-security-margin", cl::init(128), cl::ValueRequired,
               cl::desc("NoCryptoFA Security Margin (bits)"));
static cl::opt<bool>
MaskEverything("nocryptofa-mask-everything", cl::init(false), cl::ValueRequired,
               cl::desc("NoCryptoFA Mask Everything"));

void checkNeedsMasking_pre(Instruction* ptr, NoCryptoFA::InstructionMetadata* md);
void checkNeedsMasking_post(Instruction* ptr, NoCryptoFA::InstructionMetadata* md);
#define is_bit_set(what,num) ((what) & (1<<(num)))
#include "CalcPreVisitor.h"
#include "CalcPostVisitor.h"
#include "CalcFAVisitor.h"
#include "NeedsMaskPreVisitor.h"
#include "NeedsMaskPostVisitor.h"
#include "DeadBits.h"
char llvm::CalcDFG::ID = 218;

template<int MAXBITS>
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
template<int NUMBITS,int NUMBITS2>
void calcStatistics(llvm::NoCryptoFA::StatisticInfo& stat, vector<bitset<NUMBITS> >& vect,vector<bitset<NUMBITS2> >& vect2)
{
    int avgcnt = 0;
    int avgnzcnt = 0;
    int cnt = 0;
    stat.min = MAX_PROTECTION;
    stat.min_nonzero = MAX_PROTECTION;
    //std::cerr << "vect.size() == " << vect.size() << " vect2.size() == " << vect2.size() << std::endl;
    assert(vect.size() == vect2.size());
    for(unsigned long i = 0;i<vect.size();i++) {

        cnt = std::min(vect[i].count(),vect2[i].count());
        avgcnt++;
        stat.max = std::max(stat.max,cnt);
        stat.min = std::min(stat.min,cnt);
        if(cnt > 0) {
            stat.avg_nonzero += cnt;
            stat.avg += cnt;
            avgnzcnt++;
            stat.min_nonzero = std::min(stat.min_nonzero,cnt);
        }
    }
    if(stat.min == 0 && stat.min_nonzero==MAX_PROTECTION) {stat.min_nonzero=0;}
    if(avgcnt > 0) { stat.avg = stat.avg / avgcnt; }
    if(avgnzcnt > 0) { stat.avg_nonzero = stat.avg_nonzero / avgnzcnt; }
}
template<int NUMBITS>
void calcStatistics_singlevect(llvm::NoCryptoFA::StatisticInfo& stat, vector<bitset<NUMBITS> >& vect)
{
    int avgcnt = 0;
    int avgnzcnt = 0;
    int cnt = 0;
    stat.min = MAX_PROTECTION;
    stat.min_nonzero = MAX_PROTECTION;
    for(unsigned long i = 0;i<vect.size();i++) {

        cnt = vect[i].count();
        avgcnt++;
        stat.max = std::max(stat.max,cnt);
        stat.min = std::min(stat.min,cnt);
        if(cnt > 0) {
            stat.avg_nonzero += cnt;
            stat.avg += cnt;
            avgnzcnt++;
            stat.min_nonzero = std::min(stat.min_nonzero,cnt);
        }
    }
    if(stat.min == 0 && stat.min_nonzero==MAX_PROTECTION) {stat.min_nonzero=0;}
    if(avgcnt > 0) { stat.avg = stat.avg / avgcnt; }
    if(avgnzcnt > 0) { stat.avg_nonzero = stat.avg_nonzero / avgnzcnt; }
}
/*
As the structure that holds data for each instruction, about each bit and the key bit that it meets till the output
is a three-dimensional structure (DATA BIT, OUTPUT BIT, KEY BIT) => 0/1
I define the min/max/avg as:
min = min[for each data bit]( min[for each output bit](key bits at 1)) <--- the minimum protection order
max = hw(or[for each data bit]( or[for each output bit](key bits at 1))) <--- all the bits that you can get info about by faulting the instruction
avg =  Not defined, always 0.
Excluding any non-meaningful output bit by using out_hit information.
*/
void calcStatistics_faultkeybits(llvm::NoCryptoFA::StatisticInfo& stat, vector<vector<bitset<MAX_KMBITS> > >& databits, vector<bitset<MAX_OUTBITS>>& out_hit)
{
    int cnt;
    int cnt_min;
    int cnt_min_nz;
    stat.min = MAX_PROTECTION;
    stat.min_nonzero = MAX_PROTECTION;
    bitset<MAX_KMBITS> max_bs;
    max_bs.reset();
    assert(databits.size() == out_hit.size());
    for(unsigned long i = 0;i<databits.size();i++) {
        assert(databits[i].size() == MAX_OUTBITS);
        cnt_min=MAX_PROTECTION;
        cnt_min_nz = MAX_PROTECTION;
        for(unsigned long j = 0;j<databits[i].size();j++) {
            if(out_hit[i][j] == 0) continue;
            cnt=databits[i][j].count();
            cnt_min=std::min(cnt,cnt_min);
            if(cnt > 0){
                cnt_min_nz=std::min(cnt,cnt_min_nz);
            }
        }
        stat.min = std::min(stat.min,cnt_min);
        stat.min_nonzero = std::min(stat.min_nonzero,cnt_min_nz);
        for(unsigned long j = 0; j < databits[i].size(); j++){
             if(out_hit[i][j] == 0) continue;
             max_bs |= databits[i][j];
        }
    }
    stat.max=max_bs.count();
    stat.avg=0;
    stat.avg_nonzero=0;
    if(stat.min == 0 && stat.min_nonzero==MAX_PROTECTION) {stat.min_nonzero=0;}
}

CalcDFG* llvm::createCalcDFGPass()
{
    return new CalcDFG();
}

bool compare_line_number(Instruction* a,Instruction* b){
    return a->getDebugLoc().getLine() < b->getDebugLoc().getLine();
}

template <int SIZE>
vector<bitset<MAX_KEYBITS> > CalcDFG::assignKeyOwn(set<Instruction*> instructions,bitset<SIZE> NoCryptoFA::InstructionMetadata::*OWN,unsigned int* msb,std::string dbginfo){
    unsigned int latestPos=0;
    vector<bitset<MAX_KEYBITS> > subkeytokey;
    subkeytokey.resize(SIZE);
    vector<Instruction*> ptrs(instructions.size());
    std::copy(instructions.begin(),instructions.end(),ptrs.begin());
    std::stable_sort(ptrs.begin(),ptrs.end(),compare_line_number);

    for(Instruction* p: ptrs){
        getMD(p)->*OWN=getOutBitset<SIZE>(p,latestPos,dbginfo);
        int setbit = 0;
        for(int i = 0;i < SIZE; i++){
            if((getMD(p)->*OWN).test(i)){
                subkeytokey[i] = getMD(p)->keydep[setbit++];
            }
        }
    }
    *msb=std::max(latestPos,*msb);
    return subkeytokey;
}
unsigned int CalcDFG::getMSBEverSet_Fault()
{
    return MSBEverSet_Fault;
}
unsigned int CalcDFG::getMSBEverSet()
{
    return MSBEverSet;
}

bool CalcDFG::runOnFunction(llvm::Function& Fun)
{
	keyLatestPos = 0;
    cipherOutPoints.clear();
    candidateVulnerablePointsPT.clear();
    candidateVulnerablePointsCT.clear();
    allKeyMaterial.clear();
	instr_bs.clear();
	set<Instruction*> keyStarts;
	if(alreadyTransformed.find(&Fun) != alreadyTransformed.end()) {return false;}
	llvm::TaggedData& td = getAnalysis<TaggedData>();
	if(!td.functionMarked(&Fun)) {return false;}
	for(llvm::Function::iterator FI = Fun.begin(),
	    FE = Fun.end();
	    FI != FE;
	    ++FI) {
		for(llvm::BasicBlock::iterator I = FI->begin(),
		    E = FI->end();
		    I != E;
		    ++I) {
            NoCryptoFA::known[I]->reset();
			if(NoCryptoFA::known[I]->isAKeyStart) {
                NoCryptoFA::known[I]->keydep_own = getOwnBitset(I);
				keyStarts.insert(I);
			}
			if(NoCryptoFA::known[I]->isAKeyOperation) {
                unsigned int size = getOperandSize(I);
                NoCryptoFA::known[I]->keydep.resize(size);
				NoCryptoFA::known[I]->post.resize(size);
                NoCryptoFA::known[I]->pre.resize(size);
                NoCryptoFA::known[I]->out_hit.resize(size);
                NoCryptoFA::known[I]->fault_keys.resize(size);
                for(unsigned int i = 0; i < size; ++i) {
                    NoCryptoFA::known[I]->keydep[i] = bitset<MAX_KEYBITS>(0);
                    NoCryptoFA::known[I]->pre[i] = bitset<MAX_SUBBITS>(0);
                    NoCryptoFA::known[I]->post[i] = bitset<MAX_SUBBITS>(0);
                    NoCryptoFA::known[I]->out_hit[i] = bitset<MAX_OUTBITS>(0);
                    NoCryptoFA::known[I]->fault_keys[i] = vector<bitset<MAX_KMBITS> >(MAX_OUTBITS,bitset<MAX_KMBITS>(0));
				}
                calcDeadBits(I);
			}
		}
	}
    MSBEverSet=keyLatestPos;
    runBatched(keyStarts, [this](Instruction * p,long batchn)->bool {searchCipherOutPoints(p); return false;});
    runBatched(cipherOutPoints, [this](Instruction * p,long batchn)->bool {fillCiphertextHeight(p,batchn); return false;});
    runBatched(keyStarts, [this](Instruction * p,long batchn)->bool {calcKeydep(p); return false;});
    set<Instruction*> vulnerableTop;
    set<Instruction*> vulnerableBottom;
    list<pair<int,Instruction*> > sortedList;
    sortedList.insert(sortedList.begin(),candidateVulnerablePointsPT.begin(),candidateVulnerablePointsPT.end());
    /*for(auto p: sortedList){
        errs() << "SortedList: " << p.first << " - " << *(p.second) << "\n";
    }*/
    lookForMostVulnerableInstructionRepresentingTheEntireUserKey(sortedList,&vulnerableTop,&NoCryptoFA::InstructionMetadata::isVulnerableTopSubKey);
    /*for(auto p: vulnerableTop){
        errs() << "vulnerableTop: riga "<< p->getDebugLoc().getLine() << *p << "\n";
    }*/
    sortedList.clear();
    sortedList.insert(sortedList.begin(),candidateVulnerablePointsCT.begin(),candidateVulnerablePointsCT.end());
    lookForMostVulnerableInstructionRepresentingTheEntireUserKey(sortedList,&vulnerableBottom,&NoCryptoFA::InstructionMetadata::isVulnerableBottomSubKey);
    /*for(auto p: vulnerableBottom){
        errs() << "vulnerableBottom: riga "<< p->getDebugLoc().getLine() << *p << "\n";
    }*/
    cerr << "There were " << candidateVulnerablePointsPT.size() << " possibly vulnerable subkeys. T " << vulnerableTop.size() << " B " << vulnerableBottom.size() << " \n";
    vector<bitset<MAX_KEYBITS> > pre_subkeytokey = assignKeyOwn<MAX_SUBBITS>(vulnerableTop,&NoCryptoFA::InstructionMetadata::pre_own,&MSBEverSet,"vuln_top");
    vector<bitset<MAX_KEYBITS> > post_subkeytokey = assignKeyOwn<MAX_SUBBITS>(vulnerableBottom,&NoCryptoFA::InstructionMetadata::post_own,&MSBEverSet,"vuln_bottom");
    MSBEverSet_Fault=0;
    vector<bitset<MAX_KEYBITS> > fault_subkeytokey = assignKeyOwn<MAX_KMBITS>(allKeyMaterial,&NoCryptoFA::InstructionMetadata::fullsubkey_own,&MSBEverSet_Fault,"subkey");

    runBatched(vulnerableTop, [this](Instruction * p,long batchn)->bool {calcPre(p);return false;});
    set<Instruction*> firstVulnerableUses = set<Instruction*>();
    for(Instruction * p : vulnerableBottom) {
            for(auto u = p->use_begin(); u != p->use_end(); ++u) {
                Instruction* Inst = dyn_cast<Instruction>(*u);
                firstVulnerableUses.insert(Inst);
            }
        }

    runBatched(firstVulnerableUses, [this](Instruction * p,long batchn)->bool {calcPost(p);return false;});
    /*
       If doing it right with pointers to member as parameter of functions called inside the lambda function leads to:
       => 0x00007ffff6c00df9 <+57>:    ud2
       (yes,that's the output of gdb disass after a segfault)
       then allow me a copy&paste. I'm the first one that hates to do it.
    */
    runBatched(keyStarts, [pre_subkeytokey,this](Instruction * p,long batchn)->bool {
            llvm::NoCryptoFA::InstructionMetadata*md = getMD(p);
            if(md->pre_keydep.size() > 0){return false;}
            md->pre_keydep.resize(md->pre.size());
            for(unsigned long i =0;i< md->pre.size();i++){
                bitset<MAX_KEYBITS> kb=0;
                for(unsigned long j =0;j< MAX_SUBBITS;j++){
                    if(md->pre[i][j]){
                        kb |= pre_subkeytokey[j];
                    }
                }
                md->pre_keydep[i] = kb;
            }
            for(llvm::Instruction::use_iterator it = p->use_begin(); it != p->use_end(); ++it) {
                if(Instruction* _it = dyn_cast<Instruction>(*it)) {
                    toBeVisited.insert(_it);
                }
            }
            return false;
        });
    runBatched(keyStarts, [post_subkeytokey,this](Instruction * p,long batchn)->bool {
            llvm::NoCryptoFA::InstructionMetadata*md = getMD(p);
            if(md->post_keydep.size() > 0){return false;}
            md->post_keydep.resize(md->post.size());
            for(unsigned long i =0;i< md->post.size();i++){
                bitset<MAX_KEYBITS> kb=0;
                for(unsigned long j =0;j< MAX_SUBBITS;j++){
                    if(md->post[i][j]){
                        kb |= post_subkeytokey[j];
                    }
                }
                md->post_keydep[i] = kb;
            }
            for(llvm::Instruction::use_iterator it = p->use_begin(); it != p->use_end(); ++it) {
                if(Instruction* _it = dyn_cast<Instruction>(*it)) {
                    toBeVisited.insert(_it);
                }
            }
            return false;
        });

    /*Qui dobbiamo mettere i calcoli per gli attacchi a guasti */
    unsigned int lp=0;
    set<Instruction*> cipherOutValues;
    for( Instruction* co :cipherOutPoints){
        StoreInst* si = dyn_cast<StoreInst>(co);
        if(si==NULL){
            errs() << co << " IS NOT A STORE BUT IS A CIPHEROUTPOINT. SKIPPING!\n";
            continue;
        }
        cipherOutValues.insert(dyn_cast<Instruction>(si->getValueOperand()));
    }
     //Assegniamo gli out_hit ai primi
    for( Instruction* co :cipherOutValues){
        llvm::NoCryptoFA::InstructionMetadata*md = getMD(co);
        md->out_hit_own = getOutBitset<MAX_OUTBITS>(co,lp,"out_hits");
    }
    runBatched(cipherOutValues, [this](Instruction * p,long batchn)->bool { calcOuthit(p); return false;});
    runBatched(cipherOutValues, [this](Instruction * p,long batchn)->bool { calcFAKeyProp(p); return false;});

    /*calcolo statistiche*/
    runBatched(cipherOutPoints, [this](Instruction * p,long batchn)->bool {
                llvm::NoCryptoFA::InstructionMetadata* md = getMD(p);
                md->faultkeybits_stats_calculated = false;
                for(llvm::Instruction::op_iterator it = p->op_begin(); it != p->op_end(); ++it) {
                    if(Instruction* _it = dyn_cast<Instruction>(*it)) {
                        toBeVisited.insert(_it);
                    }
                }
                return false;
    });
    runBatched(cipherOutPoints, [this](Instruction * p,long batchn)->bool {
                llvm::NoCryptoFA::InstructionMetadata* md = getMD(p);
                if(md->faultkeybits_stats_calculated == false){
                    calcStatistics_singlevect<MAX_OUTBITS>(md->outhit_stats,md->out_hit);
                    calcStatistics_faultkeybits(md->faultkeybits_stats,md->fault_keys,md->out_hit);
                    md->faultkeybits_stats_calculated = true;
                }
                for(llvm::Instruction::op_iterator it = p->op_begin(); it != p->op_end(); ++it) {
                    if(Instruction* _it = dyn_cast<Instruction>(*it)) {
                        toBeVisited.insert(_it);
                    }
                }
                return false;
    });

    runBatched(vulnerableTop, [this](Instruction * p,long batchn)->bool {checkPre_masking(p);return false;});
    runBatched(firstVulnerableUses, [this](Instruction * p,long batchn)->bool {checkPost_masking(p);return false;});
	return false;
}
bitset<MAX_KEYBITS> massiveOR(std::vector<bitset<MAX_KEYBITS> >& input){
    bitset<MAX_KEYBITS> max(0);
    for(auto &v : input ){
                max |= v;
    }
    return max;
}

//TODO:spostare
struct doubt{
public:
    bitset<MAX_KEYBITS> taken;
    bitset<MAX_KEYBITS> leftover;
    int valuesize;
    doubt(bitset<MAX_KEYBITS> _taken,bitset<MAX_KEYBITS> _left,int n){
        taken=_taken; leftover=_left; valuesize=n;
    }
};

bitset<MAX_KEYBITS> getFirstNSetBit(bitset<MAX_KEYBITS> input,unsigned int howmany){
      bitset<MAX_KEYBITS> newbits_mask = 0x1;
      while(input.count() > howmany){
          input &= ~newbits_mask;
          newbits_mask <<= 1; //If it's not enough, try clearing the next one.
      } // End of while(newbits.countOnes() >howmany)
    return input;
}

bitset<MAX_KEYBITS> checkForOptimizations(bitset<MAX_KEYBITS>& covered,bitset<MAX_KEYBITS>& covering,bitset<MAX_KEYBITS>& userkey_dep_full,unsigned int num,list<doubt>& doubts){
        bitset<MAX_KEYBITS> mandatory = 0;
        bitset<MAX_KEYBITS> new_previously_covered = 0;
        bitset<MAX_KEYBITS> new_mandatory= 0;
        int howmany;
        doubts.remove_if([covered,covering](doubt& val){
            return ((val.leftover & covered & covering).count() == 0); //Housekeeping
        });


        for(auto u = doubts.begin(); u != doubts.end(); ++u){
              if((u->leftover &~ userkey_dep_full).count()>0){   //Bits to be covered with high priority, which I can't take care of.
                 if((u->taken & userkey_dep_full).count() > 0) { //Bits already covered, which I can re-cover.
                  //sposto un bit da quell'insieme all'altro
                  howmany = num-mandatory.count();
                  new_mandatory =getFirstNSetBit(u->taken & userkey_dep_full,howmany);
                  mandatory |= new_mandatory;
                  u->taken &= ~new_mandatory;
                  covered &= ~new_mandatory;
                  howmany = new_mandatory.count();
                  new_previously_covered = getFirstNSetBit(u->leftover & ~userkey_dep_full,howmany);
                  u->taken |= new_previously_covered;
                  u->leftover &= ~new_previously_covered;
                  covered |= new_previously_covered;
                  if(mandatory.count() == num){break;}
                }
            }

        }
      return mandatory;
    }
bitset<MAX_KEYBITS> limitTakenBits(unsigned int max,bitset<MAX_KEYBITS>& newbits,bitset<MAX_KEYBITS>& mandatory, list<doubt>& doubts ){
      bitset<MAX_KEYBITS> tobereturned=newbits;
      bitset<MAX_KEYBITS> newbits_mask = 0x1;
      assert(mandatory.count() <= max);
      if(newbits.count() <= max) { return newbits;}
      while(tobereturned.count() > max){
        tobereturned &= ~newbits_mask;
        tobereturned |= mandatory;
        newbits_mask <<= 1; //If it's not enough, try clearing the next one.
      } // End of while(newbits.countOnes() > max)
      doubts.push_front(doubt(tobereturned,newbits &~ tobereturned, max));
      return tobereturned;
}
void CalcDFG::lookForMostVulnerableInstructionRepresentingTheEntireUserKey(list<pair<int,Instruction*> >& sorted,set<Instruction*>* most_vulnerable_instructions,bool NoCryptoFA::InstructionMetadata::* marker)
{
  bitset<MAX_KEYBITS> covered = 0; //Covered from the previous generation
  bitset<MAX_KEYBITS> covering = 0; //Covered in this generation
  bitset<MAX_KEYBITS> newbits,userkey_dep_full,mandatory = 0;
  list<doubt> doubts = list<doubt>();
  NoCryptoFA::InstructionMetadata* md;
  int old_gen=-1;
  for(auto it = sorted.begin(); it!= sorted.end();++it ){
        if( it->first != old_gen){ // We are crossing a "generation". Do some "housekeeping" work.
        //cerr << "From gen " << old_gen << " to gen " << it->first << " - already covered " << covered.count() << " bits with " << covering.count() << " new\n";
        covered |= covering;
        covering=0;
        old_gen=it->first;
        if(covered.count() == keyLatestPos) {break;} //If now we have covered all of the bits of the userkey, we are done.
        }
     md = getMD(it->second);
     userkey_dep_full = massiveOR(md->keydep);
     //cerr << "Evaluating instruction that depends from " << userkey_dep_full.count() << " bits\n";
     newbits = userkey_dep_full & ~covered;
     mandatory=checkForOptimizations(covered,covering,userkey_dep_full,md->keydep.size(),doubts);
     newbits |= mandatory;
     //cerr << "newbits A " << newbits.count() << " bits\n";
     if(newbits.count() > 0){ //This SSA register covers a userkey bit not covered in the previous generation.
      //Already covered bits in this generation should not be "assigned" as leakable from this instruction,
      //if this instruction can leak new bits. Otherwise it's like thinking that an attacker can look for those "new" bits only in a later generation. FALSE!
      /* Example:
       * R1(16 bit) depends on so can leak 64 bits of key.
       * R2(16 bit) depends on so can leak the same 64 bits of the key.
       * R1 and R2 have the same distance from the plaintext.
       * This algorithm "marks as leakable" the first 16 leftmost bits to R1.
       * In order to not assign the same bits to R2, we need to remove it from the mask.
       * We cannot do it earlier, because those bits are USEFUL in determining if this instruction is vulnerable in this generation,
       * but are NOT USEFUL in marking those bits as "leakable".
       */
      newbits=newbits &~ covering;
      assert((newbits & mandatory) == mandatory);
      newbits |= mandatory;
      //A byte cannot give informations on more than 8 new key bits! So let's filter them out. Another instruction will "pick" them.
      newbits=limitTakenBits(md->keydep.size(),newbits,mandatory,doubts);
      covering |= newbits;
      most_vulnerable_instructions->insert(it->second);
      md->*marker=true;
    }
  } // End of foreach(Instruction v in sorted)
  doubts.clear();
}

void CalcDFG::runBatched(set<Instruction*> initialSet, std::function<bool (Instruction*,long batchn)> func)
{
	bool stopIterations = false;
	toBeVisited = initialSet;
    long counter = 0;
	while((toBeVisited.size() > 0) && !stopIterations) {
		std::set<Instruction*> thisVisit = set<Instruction*>(toBeVisited);
		toBeVisited.clear();
	for(Instruction * p : thisVisit) {
            if(func(p,counter)) {stopIterations = true;}
		}
        counter++;
	}
}
llvm::NoCryptoFA::InstructionMetadata* CalcDFG::getMD(llvm::Instruction* ptr)
{
	return NoCryptoFA::known[ptr];
}
void CalcDFG::fillCiphertextHeight(Instruction *ptr, int batchn){
    llvm::NoCryptoFA::InstructionMetadata* md = getMD(ptr);
    if(batchn < md->CiphertextHeight){
        md->CiphertextHeight = batchn;
    }
    for(llvm::Instruction::op_iterator it = ptr->op_begin(); it != ptr->op_end(); ++it) {
        if(Instruction* _it = dyn_cast<Instruction>(*it)) {
            toBeVisited.insert(_it);
        }
    }
}
#include <iostream>

template<int SIZE>
bitset<SIZE> CalcDFG::getOutBitset(llvm::Instruction* ptr,unsigned int& latestPos,std::string dbginfo)
{
	Value* op = ptr;
    unsigned int outQty = getOperandSize(op->getType());
    if(latestPos + outQty > SIZE) {
        errs() << "Something wrong with CalcDFG: " << latestPos << " + " << outQty << " > " << SIZE << " for instruction " << *ptr <<"\n";
        return bitset<SIZE>(0);
	}
    //  cerr << "latestPos " << latestPos << " outQty:" << outQty << endl;
    bitset<SIZE> mybs;
	mybs.reset();
    cerr << dbginfo << " bits " << latestPos << "-" << latestPos+outQty << " assigned at line " << ptr->getDebugLoc().getLine() << endl;
    for(unsigned int i = latestPos; i < (latestPos + outQty); i++) {
		mybs[i] = 1;
	}
    latestPos += outQty;

    //cerr << " new latestPos " << latestPos << " riga " << ptr->getDebugLoc().getLine() << endl;
	return mybs;
}
unsigned int CalcDFG::getOperandSize(llvm::Instruction* ptr)
{
	return getOperandSize(ptr->getType());
}
unsigned int CalcDFG::getOperandSize(llvm::Type* t)
{
    if(t->isVoidTy()) return 0;
	while(t->isPointerTy()) {
		t = t->getPointerElementType();
	}
    //TODO: espandere strutture supportate
    int dim = t->getScalarSizeInBits();
    if(dim > 0) return dim;
    dim = t->getPrimitiveSizeInBits();
    if(dim > 0) return dim;
    errs() << "Errore: OperandSize==0 per tipo " << t << "\n";
    return 0;

}
bool CalcDFG::shouldBeProtected(Instruction* ptr)
{
	NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[ptr];
	return (MaskEverything && md->hasMetPlaintext) || md->hasToBeProtected_pre || md->hasToBeProtected_post;
	//   return NoCryptoFA::known[ptr]->hasMetPlaintext;
}

bitset<MAX_KEYBITS> CalcDFG::getOwnBitset(llvm::Instruction* ptr)
{
	raw_fd_ostream rerr(2, false);
	if(instr_bs.find(ptr) != instr_bs.end()) {
		return instr_bs[ptr];
	}
	Type* t = NULL;
	if(isa<llvm::GetElementPtrInst>(ptr)) {
		GetElementPtrInst* gep = cast<GetElementPtrInst>(ptr);
		if(!gep->hasAllConstantIndices()) {cerr << "GetOwnBitset on a non-constant GetElementPtr. Dow!" << endl;}
		if(gep->getNumIndices() != 1) {cerr << "GetOwnBitset on a GetElementPtr with more than 1 index. Dow!" << endl; }
		Value* idx = gep->getOperand(1);
		if(isa<ConstantInt>(idx)) {
			ConstantInt* ci = cast<ConstantInt>(idx);
			NoCryptoFA::KeyStartInfo* me = new NoCryptoFA::KeyStartInfo(gep->getPointerOperand(), ci->getZExtValue());
			if(GEPs.find(*me) != GEPs.end()) {
				return GEPs[*me];
			} else {
				int keyQty = getOperandSize(ptr);
				bitset<MAX_KEYBITS> mybs;
				mybs.reset();
                for(unsigned int i = keyLatestPos; i < (keyLatestPos + keyQty); i++) {
					mybs[i] = 1;
				}
				keyLatestPos += keyQty;
				// cerr << "kq: "<<keyQty<<  " lp " << latestPos << "--"<< mybs.to_string() << endl;
				instr_bs[ptr] = mybs;
				return mybs;
			}
		} else {
			cerr << "not even the first is a costant index. Dow!" << endl;
		}
	} else {
		t = ptr->getType();
	}
	int keyQty = getOperandSize(t);
	bitset<MAX_KEYBITS> mybs;
	mybs.reset();
    for(unsigned int i = keyLatestPos; i < (keyLatestPos + keyQty); i++) {
		mybs[i] = 1;
	}
	keyLatestPos += keyQty;
    //cerr << "nuovo kLP " << keyLatestPos << endl;
	//  cerr << "kq: "<<keyQty<<  " lp " << latestPos << "--"<< mybs.to_string() << endl;
	instr_bs[ptr] = mybs;
	return mybs;
}
template< int BITNUM>
static bool areVectorOfBitsetEqual(vector<bitset<BITNUM> >& vec1, vector<bitset<BITNUM> >& vec2)
{
	if(vec1.size() != vec2.size()) { return false; }
	return (memcmp(vec1.data(), vec2.data(), sizeof(bitset<BITNUM>) * vec1.size()) == 0);
}
template< int BITNUM>
static void ClearMatrix(vector<bitset<BITNUM> >& vec)
{
	for(unsigned int i = 0; i < vec.size(); i++) {
		vec[i].reset();
	}
}

void CalcDFG::calcFAKeyProp(Instruction* ptr)
{
    NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[ptr];
    if(!md->isAKeyOperation) {return;}
    bool changed = false;
    vector<vector<bitset<MAX_KMBITS> > > oldFK = md->fault_keys; //This should be deep copy.
    for(vector<bitset<MAX_KMBITS> > &v: md->fault_keys)  ClearMatrix<MAX_KMBITS>(v);

    vector<bitset<MAX_KMBITS> > data_key = vector<bitset<MAX_KMBITS> >(getOperandSize(ptr),bitset<MAX_KMBITS>(0));
    for(llvm::Instruction::op_iterator it = ptr->op_begin(); it != ptr->op_end(); ++it) {
        if(Instruction* _it = dyn_cast<Instruction>(*it)) {
            NoCryptoFA::InstructionMetadata* opmd = NoCryptoFA::known[_it];
            if(opmd->fullsubkey_own.count() > 0) {
                setDiagonal<MAX_KMBITS>(data_key,opmd->fullsubkey_own);
            }
        }
    }
    /*repeat information on all out_hit bytes on the real structure*/
    for(unsigned long i = 0; i < data_key.size(); i++){
        for(unsigned long j = 0; j < md->fault_keys[i].size(); j++){
            if(md->out_hit[i][j]) md->fault_keys[i][j] = data_key[i];
            else md->fault_keys[i][j].reset();
        }
    }
    CalcFAVisitor fav;
    for(llvm::Instruction::use_iterator it = ptr->use_begin(); it != ptr->use_end(); ++it) {
        if(Instruction* _it = dyn_cast<Instruction>(*it)) {
            NoCryptoFA::InstructionMetadata* usemd = NoCryptoFA::known[_it];
            fav.md = md;
            fav.usemd = usemd;
            fav.visit(_it);
        }
    }

    for(unsigned long i = 0; i < md->fault_keys.size(); i++){
        if(!areVectorOfBitsetEqual<MAX_KMBITS>(oldFK[i], md->fault_keys[i])) { changed = true; break;}
    }
    if(changed) {
        for(llvm::Instruction::op_iterator it = ptr->op_begin(); it != ptr->op_end(); ++it) {
            if(Instruction* _it = dyn_cast<Instruction>(*it)) {
                toBeVisited.insert(_it);
            }
        }
    }
}
void CalcDFG::calcOuthit(Instruction* ptr)
{
    NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[ptr];
    if(!md->isAKeyOperation) {return;}
    bool changed = false;
    vector<bitset<MAX_OUTBITS> > oldOuthit = md->out_hit;
    ClearMatrix<MAX_OUTBITS>(md->out_hit);
      if(md->out_hit_own.count() > 0) {
                setDiagonal<MAX_OUTBITS>(md->out_hit,md->out_hit_own);
      }
    CalcBackwardVisitor<MAX_OUTBITS,&NoCryptoFA::InstructionMetadata::out_hit,&NoCryptoFA::InstructionMetadata::out_hit_own> cbv;
    for(llvm::Instruction::use_iterator it = ptr->use_begin(); it != ptr->use_end(); ++it) {
        if(Instruction* _it = dyn_cast<Instruction>(*it)) {
            NoCryptoFA::InstructionMetadata* usemd = NoCryptoFA::known[_it];
            cbv.md = md;
            cbv.usemd = usemd;
            cbv.visit(_it);
        }
    }

    if(!areVectorOfBitsetEqual<MAX_OUTBITS>(oldOuthit, md->out_hit)) { changed = true; }
    if(changed) {
        for(llvm::Instruction::op_iterator it = ptr->op_begin(); it != ptr->op_end(); ++it) {
            if(Instruction* _it = dyn_cast<Instruction>(*it)) {
                toBeVisited.insert(_it);
            }
        }
    }
}


void CalcDFG::calcPost(Instruction* ptr)
{
	NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[ptr];
	if(!md->isAKeyOperation) {return;}
	bool changed = false;
    vector<bitset<MAX_SUBBITS> > oldPost = md->post;
    ClearMatrix<MAX_SUBBITS>(md->post);
	for(llvm::Instruction::op_iterator it = ptr->op_begin(); it != ptr->op_end(); ++it) {
		if(Instruction* _it = dyn_cast<Instruction>(*it)) {
			NoCryptoFA::InstructionMetadata* opmd = NoCryptoFA::known[_it];
			if(opmd->post_own.count() > 0) {
				md->post_FirstToMeetKey = true;
                /*for(unsigned int i = 0; i < md->post.size(); i++) {
					md->post[i] = md->post[i] | opmd->post_own; // DIAGONALE, non blocchettino!
                }*/
                setDiagonal<MAX_SUBBITS>(md->post,opmd->post_own);
			}
		}
	}
    CalcBackwardVisitor<MAX_SUBBITS,&NoCryptoFA::InstructionMetadata::post,&NoCryptoFA::InstructionMetadata::post_own> cbv;
	for(llvm::Instruction::use_iterator it = ptr->use_begin(); it != ptr->use_end(); ++it) {
		if(Instruction* _it = dyn_cast<Instruction>(*it)) {
			NoCryptoFA::InstructionMetadata* usemd = NoCryptoFA::known[_it];
            cbv.md = md;
            cbv.usemd = usemd;
            cbv.visit(_it);
		}
	}

    if(!areVectorOfBitsetEqual<MAX_SUBBITS>(oldPost, md->post)) { changed = true; }
	if(changed) {
		for(llvm::Instruction::op_iterator it = ptr->op_begin(); it != ptr->op_end(); ++it) {
			if(Instruction* _it = dyn_cast<Instruction>(*it)) {
				toBeVisited.insert(_it);
			}
		}
	}
}

void CalcDFG::checkPost_masking(Instruction* ptr)
{
    NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[ptr];
    if(!md->isAKeyOperation) {return;}
    bool changed = false;
    bool oldProt = md->hasToBeProtected_post;
    if(!md->hasMetPlaintext) { md->hasToBeProtected_post = false;}
    else{
        calcStatistics<MAX_SUBBITS,MAX_KEYBITS>(md->post_stats, md->post,md->post_keydep);
        NeedsMaskPostVisitor nmpv;
        nmpv.visit(ptr);
        if(oldProt != md->hasToBeProtected_post) { changed = true; }
        for(llvm::Instruction::op_iterator it = ptr->op_begin(); it != ptr->op_end(); ++it) {
             if(Instruction* _it = dyn_cast<Instruction>(*it)) {
                toBeVisited.insert(_it);
             }
         }
    }
}


void CalcDFG::checkPre_masking(llvm::Instruction* ptr)
{
    NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[ptr];
    bool changed = false;
    bool oldProtected = md->hasToBeProtected_pre;
    if(!md->hasMetPlaintext) { md->hasToBeProtected_pre = false;}
    else{
        calcStatistics<MAX_SUBBITS,MAX_KEYBITS>(md->pre_stats, md->pre,md->pre_keydep);
        NeedsMaskPreVisitor nmpv;
        nmpv.visit(ptr);
    }
    if(md->hasToBeProtected_pre != oldProtected){changed=true;}
        if(!ptr->use_empty()) {
            for(llvm::Instruction::use_iterator it = ptr->use_begin(); it != ptr->use_end(); ++it) {
                if(Instruction* _it = dyn_cast<Instruction>(*it)) {
                    toBeVisited.insert(_it);
                }
            }
        }
 }

void CalcDFG::calcPre(llvm::Instruction* ptr)
{
    NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[ptr];
    bool changed = false;
    vector<bitset<MAX_SUBBITS> > oldPre = md->pre;
    ClearMatrix<MAX_SUBBITS>(md->pre);
    CalcForwardVisitor<MAX_SUBBITS,&NoCryptoFA::InstructionMetadata::pre,&NoCryptoFA::InstructionMetadata::pre_own> cfv;
    cfv.visit(ptr);
    if(!areVectorOfBitsetEqual<MAX_SUBBITS>(oldPre, md->pre)) { changed = true; }
    if(changed || md->pre_own.any()) {
        if(!ptr->use_empty()) {
            for(llvm::Instruction::use_iterator it = ptr->use_begin(); it != ptr->use_end(); ++it) {
                if(Instruction* _it = dyn_cast<Instruction>(*it)) {
                    toBeVisited.insert(_it);
                }
            }
        }
    }
}
void CalcDFG::searchCipherOutPoints(llvm::Instruction* ptr){
    NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[ptr];
    if(md->hasMetPlaintext && md->isAKeyOperation && ptr->use_empty()) {
        cipherOutPoints.insert(ptr);
    }
            for(llvm::Instruction::use_iterator it = ptr->use_begin(); it != ptr->use_end(); ++it) {
                if(Instruction* _it = dyn_cast<Instruction>(*it)) {
                    toBeVisited.insert(_it);
                }
            }

}
void CalcDFG::calcKeydep(llvm::Instruction* ptr)
{
	NoCryptoFA::InstructionMetadata* md = NoCryptoFA::known[ptr];
	bool changed = false;
    vector<bitset<MAX_KEYBITS> > oldKeydep = md->keydep;
    ClearMatrix<MAX_KEYBITS>(md->keydep);
    CalcForwardVisitor<MAX_KEYBITS,&NoCryptoFA::InstructionMetadata::keydep,&NoCryptoFA::InstructionMetadata::keydep_own> cfv;
    cfv.visit(ptr);
    if(!areVectorOfBitsetEqual<MAX_KEYBITS>(oldKeydep, md->keydep)) { changed = true; }
    if(changed || md->keydep_own.any()) {
        calcStatistics<MAX_KEYBITS,MAX_KEYBITS>(md->keydep_stats, md->keydep,md->keydep);
		if(!ptr->use_empty()) {
			for(llvm::Instruction::use_iterator it = ptr->use_begin(); it != ptr->use_end(); ++it) {
				if(Instruction* _it = dyn_cast<Instruction>(*it)) {
					toBeVisited.insert(_it);
                    if((NoCryptoFA::known[_it]->hasMetPlaintext && NoCryptoFA::known[_it]->isAKeyOperation)) {
                        if(!md->hasMetPlaintext){
                            //Insert the edge of the graph into the multimap.
                            //Each element can appear multiple times with different heights
                            //but only one time for each height
                            { // for plaintext
                                const int h = NoCryptoFA::known[_it]->PlaintextHeight;
                                auto equalheight = candidateVulnerablePointsPT.equal_range(h);
                                if(std::find(equalheight.first,equalheight.second,std::pair<const int,Instruction*>(h,ptr)) == equalheight.second){
                                        //It's new, let's insert it.
                                    candidateVulnerablePointsPT.insert(std::make_pair(h,ptr));
                                    md->isSubKey=true;
                                }
                            }
                            { // for ciphertext
                                const int h = NoCryptoFA::known[_it]->CiphertextHeight;
                                auto equalheight = candidateVulnerablePointsCT.equal_range(h);
                                if(std::find(equalheight.first,equalheight.second,std::pair<const int,Instruction*>(h,ptr)) == equalheight.second){
                                        //It's new, let's insert it.
                                    candidateVulnerablePointsCT.insert(std::make_pair(h,ptr));
                                    md->isSubKey=true;
                                }
                            }
                            { //for faults
                                allKeyMaterial.insert(ptr);
                            }
                        }
					}
				}
			}
		}
	}
}
void CalcDFG::getAnalysisUsage(llvm::AnalysisUsage& AU) const
{
	// This is an analysis, nothing is modified, so other analysis are preserved.
	AU.addRequired<TaggedData>();
	AU.setPreservesAll();
}

using namespace llvm;


INITIALIZE_PASS_BEGIN(CalcDFG,
                      "CalcDFG",
                      "CalcDFG",
                      false,
                      true)
INITIALIZE_PASS_DEPENDENCY(TaggedData)

INITIALIZE_PASS_END(CalcDFG,
                    "CalcDFG",
                    "CalcDFG",
                    false,
                    true)
