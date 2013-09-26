#pragma once
#include <unordered_map>
#include <vector>
#include <bitset>
namespace llvm
{
    namespace NoCryptoFA
    {
        class Deduplicator{
        public:
            template<unsigned long BS_SIZE>
            static void Dedup(std::vector<std::bitset<BS_SIZE> > *target);
            template<unsigned long BS_SIZE>
            static void Dedup(std::vector<std::vector<std::bitset<BS_SIZE> > > *target);
            template<unsigned long BS_SIZE>
            static void Restore(std::vector<std::bitset<BS_SIZE> > *target);
            template<unsigned long BS_SIZE>
            static void Restore(std::vector<std::vector<std::bitset<BS_SIZE> > > *target);
        };
    }
}
