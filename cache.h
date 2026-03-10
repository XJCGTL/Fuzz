#ifndef CACHE_H
#define CACHE_H

#include <stdint.h>

/* L1 cache block (line) size in bytes */
#define L1_BLOCK_SZ_BYTES   64

/**
 * Flush the cache for the memory region starting at addr with the given size.
 * Returns a side-channel value that is XOR'd into useless to prevent the
 * compiler from eliminating the call as dead code.
 */
uint64_t flushCache(uint64_t addr, uint64_t size);

/**
 * Probe each of the 256 possible byte values by measuring the access time to
 * array2[i * L1_BLOCK_SZ_BYTES] and record the result in results[i].
 */
void ProbeCache(uint64_t *results);

/**
 * Display the two highest-scoring entries in results[] to identify the leaked
 * secret byte.  useless is printed to prevent dead-code elimination of the
 * flush loop.
 */
void High_two_result(uint64_t useless, uint64_t *results);

#endif /* CACHE_H */
