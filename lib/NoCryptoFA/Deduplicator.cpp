#include "llvm/NoCryptoFA/All.h"
#include <cstdint>
#include <mutex>
#include <atomic>
#include <vector>
#include <bitset>
#include <cstring>
#include <pthread.h>
/* Adler code adapted from zlib's Adler code.
 * Copyright (C) 1995-2003 Mark Adler
 * For conditions of distribution and use, see copyright notice in zlib.h
 */

#define BASE 65521UL    /* largest prime smaller than 65536 */
#define NMAX 5552
/* NMAX is the largest n such that 255n(n+1)/2 + (n+1)(BASE-1) <= 2^32-1 */
#define DO1(buf,i)  {adler += (buf)[i]; sum2 += adler;}
#define DO2(buf,i)  DO1(buf,i); DO1(buf,i+1);
#define DO4(buf,i)  DO2(buf,i); DO2(buf,i+2);
#define DO8(buf,i)  DO4(buf,i); DO4(buf,i+4);
#define DO16(buf)   DO8(buf,0); DO8(buf,8);
#define MOD(a) a %= BASE

uint32_t adler32(const char* buf, uint32_t len)
{
    unsigned long sum2 = 0;
    unsigned n;
    uint32_t adler = 0;
    /* in case user likes doing a byte at a time, keep it fast */
    if (len == 1) {
        adler += buf[0];
        if (adler >= BASE)
            adler -= BASE;
        sum2 += adler;
        if (sum2 >= BASE)
            sum2 -= BASE;
        return adler | (sum2 << 16);
    }

    /* initial Adler-32 value (deferred check for len == 1 speed) */
    if (buf == NULL)
        return 1L;

    /* in case short lengths are provided, keep it somewhat fast */
    if (len < 16) {
        while (len--) {
            adler += *buf++;
            sum2 += adler;
        }
        if (adler >= BASE)
            adler -= BASE;
        MOD(sum2);            /* only added so many BASE's */
        return adler | (sum2 << 16);
    }

    /* do length NMAX blocks -- requires just one modulo operation */
    while (len >= NMAX) {
        len -= NMAX;
        n = NMAX / 16;          /* NMAX is divisible by 16 */
        do {
            DO16(buf);          /* 16 sums unrolled */
            buf += 16;
        } while (--n);
        MOD(adler);
        MOD(sum2);
    }

    /* do remaining bytes (less than NMAX, still just one modulo) */
    if (len) {                  /* avoid modulos if none remaining */
        while (len >= 16) {
            len -= 16;
            DO16(buf);
            buf += 16;
        }
        while (len--) {
            adler += *buf++;
            sum2 += adler;
        }
        MOD(adler);
        MOD(sum2);
    }

    /* return recombined sums */
    return adler | (sum2 << 16);
}
/* =============================END ADLER CODE============================================ */
template<unsigned long BS_SIZE>
class StorageElement{
public:
    std::vector<std::bitset<BS_SIZE> > elem;
    uint32_t hash = 0;
    std::atomic_ullong refcount;
    StorageElement(const std::vector<std::bitset<BS_SIZE> >& data,uint32_t _hash){
        elem = data;
        hash = _hash;
        refcount.store(0);
    }
    StorageElement(const StorageElement<BS_SIZE>& old){
        elem = old.elem;
        refcount.store(0);
    }
};
static pthread_rwlock_t  rwlock = PTHREAD_RWLOCK_INITIALIZER;

template<unsigned long BS_SIZE>
std::unordered_map<uint32_t,std::list<StorageElement<BS_SIZE>* > >* getHashTable();


template<unsigned long BS_SIZE>
void Deduplicator::Dedup(std::vector<std::bitset<BS_SIZE> > *target){
    if(target->size() == 0){return;}
    uint32_t hash = adler32((char*)target->data(),sizeof(std::bitset<BS_SIZE>)*target->size());
    auto ht = getHashTable<BS_SIZE>();
    StorageElement<BS_SIZE> *found = NULL;
    pthread_rwlock_rdlock(&rwlock);
    for(StorageElement<BS_SIZE> *sep : (*ht)[hash]){
        if(sep->elem.size() != target->size()){continue;}
        if(memcmp((char*)sep->elem.data(),(char*)target->data(),sizeof(std::bitset<BS_SIZE>)*target->size())){continue;}
        //Found!
        unsigned long prev_val = sep->refcount.fetch_add(1);
        if(prev_val == 0){
            //Qualcuno lo sta già distruggendo, peccato :(
            continue;
        }
        found=sep;
        break;
    }
    pthread_rwlock_unlock(&rwlock);
    if(!found){
        found = new StorageElement<BS_SIZE>(*target,hash);
        pthread_rwlock_wrlock(&rwlock);
        (*ht)[hash].push_front(found);
        pthread_rwlock_unlock(&rwlock);
    }
    assert(sizeof(std::bitset<BS_SIZE>) >= sizeof(void*)); //si è una assert "a compile time";
    std::vector<std::bitset<BS_SIZE>>(1).swap(*target);
    target->resize(1);
    target->shrink_to_fit();
    *((StorageElement<BS_SIZE> **)target->data())=found;
}
template<unsigned long BS_SIZE>
void Deduplicator::Dedup(std::vector<std::vector<std::bitset<BS_SIZE> > > *target){
    for(std::vector<std::bitset<BS_SIZE> >& cur : *target){
        Deduplicator::Dedup(&cur);
    }
}
template<unsigned long BS_SIZE>
void Deduplicator::Restore(std::vector<std::bitset<BS_SIZE> > *target){
    if(target->size() == 0){return;}
    StorageElement<BS_SIZE>* el = *((StorageElement<BS_SIZE>**)target->data());
    (*target) = el->elem; //deep copy!
    unsigned long prev_val = el->refcount.fetch_sub(1);
    if(prev_val == 1){
        std::vector<std::bitset<BS_SIZE> >().swap(el->elem);
        auto ht = getHashTable<BS_SIZE>();
        pthread_rwlock_wrlock(&rwlock);
        (*ht)[el->hash].remove(el);
        pthread_rwlock_unlock(&rwlock);
        delete el;
    }
}

template<unsigned long BS_SIZE>
void Deduplicator::Restore(std::vector<std::vector<std::bitset<BS_SIZE> > > *target){
    for(std::vector<std::bitset<BS_SIZE> >& cur : *target){
        Deduplicator::Restore(&cur);
    }
}



#define istanzia_tpl(LEN,NAME)  \
template void Deduplicator::Dedup(std::vector<std::bitset<LEN> >  *target);\
template void  Deduplicator::Restore(std::vector<std::bitset<LEN> >  *target);\
template void  Deduplicator::Dedup(std::vector<std::vector<std::bitset<LEN> > > *target);\
template void  Deduplicator::Restore(std::vector<std::vector<std::bitset<LEN> > > *target);\
static std::unordered_map<uint32_t,std::list<StorageElement<LEN>* > > NAME;\
template<>\
std::unordered_map<uint32_t,std::list<StorageElement<LEN>* > >* getHashTable(){return &NAME;}


istanzia_tpl(MAX_KEYBITS,hashbuf_kb)
istanzia_tpl(MAX_KMBITS,hashbuf_km)
istanzia_tpl(MAX_SUBBITS,hashbuf_sb)
istanzia_tpl(MAX_OUTBITS,hashbuf_ob)
