#ifndef SHA33_H
#define SHA33_H

#include <stdint.h>

class Sha33 {

 public:

    static void
    ComputeSHAVM (const uint32_t MT[], uint32_t hash[]);

    static void
    ComputeSHAVM (const uint8_t MT[], uint32_t hash[]);
    
    static void
    HashToMAC(const uint32_t hash[], uint8_t MAC[]);

 private:

    static uint32_t
    NLF (uint32_t B, uint32_t C, uint32_t D, uint8_t n);
};


#endif
