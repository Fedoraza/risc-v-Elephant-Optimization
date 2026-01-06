#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "api.h"
#include "crypto_aead.h"
#include "elephant_160.h"

#define PERM_BLOCKS 32
#define PERM_ITERS 3

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

    // const unsigned char key[CRYPTO_KEYBYTES] = {
    //     0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    //     0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    // };
    // unsigned char nonce[CRYPTO_NPUBBYTES] = {0};
    // unsigned char ad[16] = "AD";
    // unsigned char msg[32] = "Test message";
    // unsigned char ciphertext[sizeof msg + CRYPTO_ABYTES];
    // unsigned char decrypted[sizeof msg];
    // unsigned long long clen = 0;
    // unsigned long long outlen = 0;

    // int enc_ret = crypto_aead_encrypt(
    //     ciphertext, &clen,
    //     msg, (unsigned long long)strlen((char *)msg),
    //     ad, (unsigned long long)strlen((char *)ad),
    //     NULL, nonce, key);
    // int dec_ret = crypto_aead_decrypt(
    //     decrypted, &outlen, NULL,
    //     ciphertext, clen,
    //     ad, (unsigned long long)strlen((char *)ad),
    //     nonce, key);

    // if (enc_ret != 0 || dec_ret != 0 ||
    //     outlen != (unsigned long long)strlen((char *)msg) ||
    //     memcmp(decrypted, msg, (size_t)outlen) != 0) {
    //     printf("Test failed\n");
    //     return 2;
    // }

    static BYTE perm_states_single[PERM_BLOCKS][BLOCK_SIZE];
    static BYTE perm_states_many[PERM_BLOCKS][BLOCK_SIZE];
    for (unsigned int i = 0; i < PERM_BLOCKS; ++i) {
        fill_buffer(perm_states_single[i], BLOCK_SIZE, &prng);
        memcpy(perm_states_many[i], perm_states_single[i], BLOCK_SIZE);
    }

    printf("Benchmarking...\n");

    for (unsigned int iters = 1; iters <= 10; ++iters) {
        uint64_t start = read_mtime();
        for (unsigned int i = 0; i < iters; ++i) {
            for (unsigned int j = 0; j < PERM_BLOCKS; ++j) {
                permutation(perm_states_single[j]);
            }
        }
        uint64_t single_ticks = read_mtime() - start;

        start = read_mtime();
        for (unsigned int i = 0; i < iters; ++i) {
            permutation_many(perm_states_many, PERM_BLOCKS);
        }
        uint64_t many_ticks = read_mtime() - start;

        const double total_blocks = (double)iters * (double)PERM_BLOCKS;
        const double single_per_block = (total_blocks > 0.0) ? (double)single_ticks / total_blocks : 0.0;
        const double many_per_block = (total_blocks > 0.0) ? (double)many_ticks / total_blocks : 0.0;
        const double speedup = (many_ticks > 0) ? (double)single_ticks / (double)many_ticks : 0.0;

        if (single_ticks == 0 && many_ticks == 0) {
            printf("Warning: mtime counter unavailable in simulator.\n");
            break;
        }
        printf("Permutation mtime ticks (iters=%u)\n", iters);
        printf("Single: %llu total, %.1f per block\n",
               (unsigned long long)single_ticks, single_per_block);
        printf("Batch : %llu total, %.1f per block\n",
               (unsigned long long)many_ticks, many_per_block);
        printf("Speedup (single/batch): %.2fx\n", speedup);
    }

    sink = checksum32(perm_states_single[0], BLOCK_SIZE, sink);
    sink = checksum32(perm_states_many[0], BLOCK_SIZE, sink);
    (void)sink;

    printf("Test complete\n");
    for (;;) {
        // Halt here so the debugger cycle counter can be read.
    }
    return 0;
}
