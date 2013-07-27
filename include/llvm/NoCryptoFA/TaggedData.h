#pragma once

#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include <llvm/Instruction.h>
#include <map>
#include <set>
#include <bitset>
#include <array>
#define MAX_KEYBITS 256
#define MAX_SUBBITS 512
#define MAX_VALBITS 64
#define MAX_PROTECTION 999999
#define MAX_OUTBITS (8*16)
#define MAX_KMBITS (32*128) //serpent.
using namespace std;
using namespace llvm;

namespace llvm
{
	void initializeTaggedDataPass(PassRegistry& Registry);
	namespace NoCryptoFA
	{
		struct InstructionMetadata;
		extern std::map<llvm::Instruction*, llvm::NoCryptoFA::InstructionMetadata*> known;
		struct StatisticInfo {
            int max;
            int min;
            int min_nonzero;
            int avg;
            int avg_nonzero;
			StatisticInfo() {
				max = 0;
				min = 0;
				min_nonzero = 0;
				avg = 0;
				avg_nonzero = 0;
			}
		};
		struct InstructionMetadata {
				enum InstructionSource {
				    ORIGINAL_PROGRAM,
				    CREATE_MASK,
				    XOR_MASKED,
                    OR_MASKED,
				    AND_MASKED,
				    CAST_MASKED,
				    SHIFT_MASKED,
				    SBOX_MASKED,
				    SELECT_MASKED,
				    REMOVE_MASK,
				    MASKED_FUNCTION
				};
				bool isAKeyOperation;
				bool isAKeyStart;
                bool isVulnerableTopSubKey;
                bool isVulnerableBottomSubKey;
                bool isSubKey;
				bool isSbox;
				bool hasToBeProtected_pre;
				bool hasToBeProtected_post;
				bool post_FirstToMeetKey;
				bool hasBeenMasked;
				bool hasMetPlaintext;
                long PlaintextHeight;
                long CiphertextHeight;
                std::string NodeName;
				InstructionSource origin;
                std::vector<std::bitset<MAX_KEYBITS> > keydep;
                std::bitset<MAX_KEYBITS> keydep_own;
                std::vector<std::bitset<MAX_SUBBITS> > pre;
                std::vector<std::bitset<MAX_KEYBITS> > pre_keydep;
                std::bitset<MAX_SUBBITS> pre_own;
                std::vector<std::bitset<MAX_SUBBITS> > post;
                std::vector<std::bitset<MAX_KEYBITS> > post_keydep;
                std::bitset<MAX_SUBBITS> post_own;
				Instruction* my_instruction;
				Instruction* unmasked_value;
				std::vector<Value*> MaskedValues;
                StatisticInfo keydep_stats;
                StatisticInfo pre_stats;
				StatisticInfo post_stats;
                /*Only for SBOXes {*/
                bool deadBitsCalculated;
                std::bitset<MAX_VALBITS> deadBits;
                /* } */
                /*For fault analysis {*/
                std::vector<std::bitset<MAX_OUTBITS> > out_hit;
                std::bitset<MAX_OUTBITS> out_hit_own;
                std::bitset<MAX_KMBITS> fullsubkey_own;
                std::vector<std::vector<std::bitset<MAX_KMBITS> > > fault_keys;
                /*      {  //Statistics for output  */
                            struct {
                                char calculated = false;
                                int min_keylen_nz;
                                int hw_outhit_of_min_keylen_nz;
                                bitset<MAX_OUTBITS> outhit_of_min_keylen_nz;
                            } faultable_stats;
                /*      } */
                /* } */
                InstructionMetadata(Instruction* ptr): keydep(0), keydep_own(0),pre(0),pre_keydep(0),pre_own(0), post(0),post_keydep(0), post_own(0), MaskedValues(0), keydep_stats(),pre_stats(),post_stats() {
					init();
					my_instruction = ptr;
					known[ptr] = this;
				}
				InstructionMetadata() {
					init();
				}
				static llvm::NoCryptoFA::InstructionMetadata* getNewMD(llvm::Instruction* ptr) {
					llvm::NoCryptoFA::InstructionMetadata* md;
					if(NoCryptoFA::known.find(ptr) != NoCryptoFA::known.end()) {
						md = NoCryptoFA::known[ptr];
					} else {
						md = new llvm::NoCryptoFA::InstructionMetadata(ptr);
					}
					return md;
				}
                void reset(){
                    unmasked_value = NULL;
                    isVulnerableBottomSubKey=false;
                    isVulnerableTopSubKey=false;
                    isSubKey=false;
                    post_FirstToMeetKey = false;
                    pre_own.reset();
                    post_own.reset();
                    keydep_own.reset();
                    out_hit_own.reset();
                    fullsubkey_own.reset();
                    hasToBeProtected_pre = false;
                    hasToBeProtected_post = false;
                    CiphertextHeight= 0xffffffff;
                    hasBeenMasked = false;

                }
                std::string& getAsString(){
                    if(representation.length() > 0) return representation;
                    llvm::raw_string_ostream os(representation);
                    os << *my_instruction;
                    return representation;
                }
                unsigned int getMySecurityMargin_pre(){
                    return std::min(keydep_stats.min_nonzero,pre_stats.min_nonzero);
                }
                unsigned int getMySecurityMargin_post(){
                    return std::min(keydep_stats.min_nonzero,post_stats.min_nonzero);
                }

                int getMySecurityMargin(){
                    return std::min(getMySecurityMargin_pre(),getMySecurityMargin_post());
                }
			private:
                std::string representation;
				void init() {
					origin = InstructionMetadata::ORIGINAL_PROGRAM;
                    isAKeyOperation = false;
					isAKeyStart = false;
					isSbox = false;
					hasMetPlaintext = false;
                    PlaintextHeight=0;
                    deadBitsCalculated = false;
                    reset();
				}

		};

	}


	class TaggedData : public llvm::FunctionPass
	{
		public:
			static char ID;
			TaggedData() : llvm::FunctionPass(ID) { }
			TaggedData(const TaggedData& fp) : llvm::FunctionPass(fp.ID) {
				initializeTaggedDataPass(*PassRegistry::getPassRegistry());
			}
			virtual NoCryptoFA::InstructionMetadata* getMD(llvm::Instruction* ptr);

			virtual bool runOnFunction(llvm::Function& Fun);
			virtual bool isMarkedAsKey(llvm::Instruction* ptr);
			virtual void markFunction(llvm::Function* ptr);
			virtual bool isMarkedAsStatus(llvm::Instruction* ptr);
			virtual void getAnalysisUsage(llvm::AnalysisUsage& AU) const;
			virtual const char* getPassName() const {
				return "TaggedData";
			}
			bool functionMarked(Function* ptr);

		private:
			// This is the information computed by the analysis.

			std::set<Function*> markedfunctions;
			void checkMeta(llvm::Instruction* ptr);
			void infect(llvm::Instruction* ptr);
            void infectPlain(llvm::Instruction* ptr,long height);
			void infectSbox(llvm::Instruction* ptr);
			bool hasmd;
	};
	TaggedData* createTaggedDataPass();


}



