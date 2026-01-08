#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "api.h"
#include "crypto_aead.h"
#include "elephant_160.h"

#define PERM_BLOCKS_MAX 32
#define PERM_ITERS 1

#if defined(__riscv) || defined(__riscv__)
#ifndef MTIME_ADDR
#define MTIME_ADDR 0x0200BFF8u
#endif

static inline uint64_t read_mtime(void) {
#if defined(__riscv_xlen) && (__riscv_xlen == 64)
    volatile uint64_t *mtime = (volatile uint64_t *)MTIME_ADDR;
    return *mtime;
#else
    volatile uint32_t *mtime = (volatile uint32_t *)MTIME_ADDR;
    uint32_t hi = 0;
    uint32_t lo = 0;
    uint32_t hi2 = 0;
    do {
        hi = mtime[1];
        lo = mtime[0];
        hi2 = mtime[1];
    } while (hi != hi2);
    return ((uint64_t)hi << 32) | lo;
#endif
}
#else
static inline uint64_t read_mtime(void) {
    return 0;
}
#endif

static uint32_t xorshift32(uint32_t *state) {
    uint32_t x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

static void fill_buffer(unsigned char *buf, size_t len, uint32_t *state) {
    for (size_t i = 0; i < len; ++i)
        buf[i] = (unsigned char)xorshift32(state);
}

static uint32_t checksum32(const unsigned char *buf, size_t len, uint32_t acc) {
    for (size_t i = 0; i < len; ++i)
        acc = (acc << 5) ^ (acc >> 27) ^ buf[i];
    return acc;
}

int main(void) {
    uint32_t prng = 0x12345678u;
    volatile uint32_t sink = 0;

    static BYTE perm_states_single[PERM_BLOCKS_MAX][BLOCK_SIZE];
    static BYTE perm_states_many[PERM_BLOCKS_MAX][BLOCK_SIZE];
    for (unsigned int i = 0; i < PERM_BLOCKS_MAX; ++i) {
        fill_buffer(perm_states_single[i], BLOCK_SIZE, &prng);
        memcpy(perm_states_many[i], perm_states_single[i], BLOCK_SIZE);
    }

    printf("Benchmarking...\n");

    for (unsigned int blocks = 1; blocks <= PERM_BLOCKS_MAX; ++blocks) {
        for (unsigned int iters = 1; iters <= 1; ++iters) {
            uint64_t start = read_mtime();
            for (unsigned int i = 0; i < iters; ++i) {
                for (unsigned int j = 0; j < blocks; ++j) {
                    permutation(perm_states_single[j]);
                }
            }
            uint64_t single_ticks = read_mtime() - start;

            start = read_mtime();
            for (unsigned int i = 0; i < iters; ++i) {
                permutation_many(perm_states_many, blocks);
            }
            uint64_t many_ticks = read_mtime() - start;

            const double total_blocks = (double)iters * (double)blocks;
            const double single_per_block = (total_blocks > 0.0) ? (double)single_ticks / total_blocks : 0.0;
            const double many_per_block = (total_blocks > 0.0) ? (double)many_ticks / total_blocks : 0.0;
            const double speedup = (many_ticks > 0) ? (double)single_ticks / (double)many_ticks : 0.0;

            if (single_ticks == 0 && many_ticks == 0) {
                printf("Warning: mtime counter unavailable in simulator.\n");
                blocks = PERM_BLOCKS_MAX;
                break;
            }
            printf("Permutation mtime ticks (blocks=%u, iters=%u)\n", blocks, iters);
            printf("Single: %llu total, %.1f per block\n",
                   (unsigned long long)single_ticks, single_per_block);
            printf("Batch : %llu total, %.1f per block\n",
                   (unsigned long long)many_ticks, many_per_block);
            printf("Speedup (single/batch): %.2fx\n", speedup);
        }
    }

    sink = checksum32(perm_states_single[0], BLOCK_SIZE, sink);
    sink = checksum32(perm_states_many[0], BLOCK_SIZE, sink);
    (void)sink;

    printf("Test complete\n");
    return 0;
}
