#include "api.h"
#include "crypto_aead.h"
#include <string.h> 
#include <stdio.h>
#include "elephant_160.h"


extern void spongent_permute_32(BYTE states[32][20]);

#if defined(SPONGENT160)
#define nBits 160
#define nSBox 20
#define nRounds 80
#define lfsrIV 0x75
#elif defined(SPONGENT176)
#define nBits 176
#define nSBox 22
#define nRounds 90
#define lfsrIV 0x45
#else
#define nBits 0
#define nSBox 0
#define nRounds 0
#define lfsrIV 0
#endif

#define GET_BIT(x, y) (((x) >> (y)) & 0x1u)

/* Spongent 8-bit S-box */
static const BYTE sBoxLayer[256] = {
    0xee, 0xed, 0xeb, 0xe0, 0xe2, 0xe1, 0xe4, 0xef, 0xe7, 0xea, 0xe8, 0xe5, 0xe9, 0xec, 0xe3, 0xe6,
    0xde, 0xdd, 0xdb, 0xd0, 0xd2, 0xd1, 0xd4, 0xdf, 0xd7, 0xda, 0xd8, 0xd5, 0xd9, 0xdc, 0xd3, 0xd6,
    0xbe, 0xbd, 0xbb, 0xb0, 0xb2, 0xb1, 0xb4, 0xbf, 0xb7, 0xba, 0xb8, 0xb5, 0xb9, 0xbc, 0xb3, 0xb6,
    0x0e, 0x0d, 0x0b, 0x00, 0x02, 0x01, 0x04, 0x0f, 0x07, 0x0a, 0x08, 0x05, 0x09, 0x0c, 0x03, 0x06,
    0x2e, 0x2d, 0x2b, 0x20, 0x22, 0x21, 0x24, 0x2f, 0x27, 0x2a, 0x28, 0x25, 0x29, 0x2c, 0x23, 0x26,
    0x1e, 0x1d, 0x1b, 0x10, 0x12, 0x11, 0x14, 0x1f, 0x17, 0x1a, 0x18, 0x15, 0x19, 0x1c, 0x13, 0x16,
    0x4e, 0x4d, 0x4b, 0x40, 0x42, 0x41, 0x44, 0x4f, 0x47, 0x4a, 0x48, 0x45, 0x49, 0x4c, 0x43, 0x46,
    0xfe, 0xfd, 0xfb, 0xf0, 0xf2, 0xf1, 0xf4, 0xff, 0xf7, 0xfa, 0xf8, 0xf5, 0xf9, 0xfc, 0xf3, 0xf6,
    0x7e, 0x7d, 0x7b, 0x70, 0x72, 0x71, 0x74, 0x7f, 0x77, 0x7a, 0x78, 0x75, 0x79, 0x7c, 0x73, 0x76,
    0xae, 0xad, 0xab, 0xa0, 0xa2, 0xa1, 0xa4, 0xaf, 0xa7, 0xaa, 0xa8, 0xa5, 0xa9, 0xac, 0xa3, 0xa6,
    0x8e, 0x8d, 0x8b, 0x80, 0x82, 0x81, 0x84, 0x8f, 0x87, 0x8a, 0x88, 0x85, 0x89, 0x8c, 0x83, 0x86,
    0x5e, 0x5d, 0x5b, 0x50, 0x52, 0x51, 0x54, 0x5f, 0x57, 0x5a, 0x58, 0x55, 0x59, 0x5c, 0x53, 0x56,
    0x9e, 0x9d, 0x9b, 0x90, 0x92, 0x91, 0x94, 0x9f, 0x97, 0x9a, 0x98, 0x95, 0x99, 0x9c, 0x93, 0x96,
    0xce, 0xcd, 0xcb, 0xc0, 0xc2, 0xc1, 0xc4, 0xcf, 0xc7, 0xca, 0xc8, 0xc5, 0xc9, 0xcc, 0xc3, 0xc6,
    0x3e, 0x3d, 0x3b, 0x30, 0x32, 0x31, 0x34, 0x3f, 0x37, 0x3a, 0x38, 0x35, 0x39, 0x3c, 0x33, 0x36,
    0x6e, 0x6d, 0x6b, 0x60, 0x62, 0x61, 0x64, 0x6f, 0x67, 0x6a, 0x68, 0x65, 0x69, 0x6c, 0x63, 0x66
};

BYTE rotl3(BYTE b)
{
    return (b << 3) | (b >> 5);
}

static void print_states(const char *label, BYTE states[32][20]) {
    printf("%s\n", label);
    for (int s = 0; s < 32; s++) {
        printf("state[%2d]: ", s);
        for (int i = 0; i < 20; i++) {
            printf("%02X ", states[s][i]);
        }
        printf("\n");
    }
    printf("\n");
}

// Helper to print a block in hex
static void print_block(const char* label, const BYTE* data, SIZE len)
{
    printf("%s (len=%zu):", label, (size_t)len);
    for(SIZE i = 0; i < len; ++i)
        printf(" %02X", (unsigned)data[i]);
    printf("\n");
}

static BYTE lCounter(BYTE lfsr)
{
    // x^7 + x^6 + 1
    lfsr = (BYTE)((lfsr << 1) | (((0x40 & lfsr) >> 6) ^ ((0x20 & lfsr) >> 5)));
    lfsr &= 0x7f;
    return lfsr;
}

static BYTE retnuoCl(BYTE lfsr)
{
    // Bit-reverse the byte: bit 0->7, 1->6, 2->5, 3->4, 4->3, 5->2, 6->1, 7->0.
    return (BYTE)(((lfsr & 0x01) << 7) | ((lfsr & 0x02) << 5) | ((lfsr & 0x04) << 3) |
                  ((lfsr & 0x08) << 1) | ((lfsr & 0x10) >> 1) | ((lfsr & 0x20) >> 3) |
                  ((lfsr & 0x40) >> 5) | ((lfsr & 0x80) >> 7));
}

static int Pi(int i)
{
    if (i != nBits - 1)
        return (i * nBits / 4) % (nBits - 1);
    return nBits - 1;
}

static void pLayer(BYTE* state)
{
    int permuted_bit_no;
    BYTE tmp[nSBox];
    BYTE x;
    BYTE y;

    for (int i = 0; i < nSBox; i++)
        tmp[i] = 0;

    for (int i = 0; i < nSBox; i++) {
        for (int j = 0; j < 8; j++) {
            x = (BYTE)GET_BIT(state[i], j);
            permuted_bit_no = Pi(8 * i + j);
            y = (BYTE)(permuted_bit_no / 8);
            tmp[y] ^= (BYTE)(x << (permuted_bit_no - 8 * y));
        }
    }
    memcpy(state, tmp, nSBox);
}

// Reference SPONGENT permutation.
void permutation(BYTE* state)
{
    BYTE iv = lfsrIV;
    BYTE inv_iv;

    for (int i = 0; i < nRounds; i++) {
        /* Add counter values */
        state[0] ^= iv;
        inv_iv = retnuoCl(iv);
        state[nSBox - 1] ^= inv_iv;
        iv = lCounter(iv);

        /* sBoxLayer */
        for (int j = 0; j < nSBox; j++)
            state[j] = sBoxLayer[state[j]];

        /* pLayer */
        pLayer(state);
    }
}

// Batch wrapper: permute up to 32 states in one call to the bitsliced assembly.
// Remaining slots are zero-padded to avoid leaking old stack data.
void permutation_many(BYTE states[][BLOCK_SIZE], SIZE count)
{
    SIZE offset = 0;
    while (count > 0) {
        const SIZE n = (count > 32) ? 32 : count;
        if (n == 32) {
            spongent_permute_32((BYTE (*)[20])&states[offset]);
        } else {
            BYTE buf[32][BLOCK_SIZE] = {0};
            for (SIZE i = 0; i < n; ++i)
                memcpy(buf[i], states[offset + i], BLOCK_SIZE);
            spongent_permute_32(buf);
            for (SIZE i = 0; i < n; ++i)
                memcpy(states[offset + i], buf[i], BLOCK_SIZE);
        }
        offset += n;
        count -= n;
    }
}

int constcmp(const BYTE* a, const BYTE* b, SIZE length)
{
    BYTE r = 0;

    for (SIZE i = 0; i < length; ++i)
        r |= a[i] ^ b[i];
    return r; 
}


// State should be BLOCK_SIZE bytes long
// Note: input may be equal to output
void lfsr_step(BYTE* output, BYTE* input)
{
    // https://www.youtube.com/watch?v=Ks1pw1X22y4
    print_block("LFSR input", input, BLOCK_SIZE);
    BYTE temp = rotl3(input[0]) ^ (input[3] << 7) ^ (input[13] >> 7);
    for(SIZE i = 0; i < BLOCK_SIZE - 1; ++i)
        output[i] = input[i + 1];
    output[BLOCK_SIZE - 1] = temp;
    print_block("LFSR output", output, BLOCK_SIZE);
}

void xor_block(BYTE* state, const BYTE* block, SIZE size)
{
    // It is assumed that size <= BLOCK_SIZE
    print_block("XOR state before", state, size);
    print_block("XOR block", block, size);
    for(SIZE i = 0; i < size; ++i)
        // XOR operation
        state[i] ^= block[i];
    print_block("XOR state after", state, size);
}

// Write the ith assocated data block to "output".
// The nonce is prepended and padding is added as required.
// adlen is the length of the associated data in bytes
void get_ad_block(BYTE* output, const BYTE* ad, SIZE adlen, const BYTE* npub, SIZE i)
{
    SIZE len = 0;
    // First block contains nonce
    // Remark: nonce may not be longer then BLOCK_SIZE
    if(i == 0) {
        memcpy(output, npub, CRYPTO_NPUBBYTES);
        len += CRYPTO_NPUBBYTES;
    }

    const SIZE block_offset = i * BLOCK_SIZE - (i != 0) * CRYPTO_NPUBBYTES;
    // If adlen is divisible by BLOCK_SIZE, add an additional padding block
    if(i != 0 && block_offset == adlen) {
        memset(output, 0x00, BLOCK_SIZE);
        output[0] = 0x01;
        return;
    }
    const SIZE r_outlen = BLOCK_SIZE - len;
    const SIZE r_adlen  = adlen - block_offset;
    // Fill with associated data if available
    if(r_outlen <= r_adlen) { // enough AD
        memcpy(output + len, ad + block_offset, r_outlen);
    } else { // not enough AD, need to pad
        if(r_adlen > 0) // ad might be nullptr
            memcpy(output + len, ad + block_offset, r_adlen);
        memset(output + len + r_adlen, 0x00, r_outlen - r_adlen);
        output[len + r_adlen] = 0x01;
    }
    print_block("AD block", output, BLOCK_SIZE);
}

// Return the ith ciphertext block.
// clen is the length of the ciphertext in bytes 
void get_c_block(BYTE* output, const BYTE* c, SIZE clen, SIZE i)
{
    const SIZE block_offset = i * BLOCK_SIZE;
    // If clen is divisible by BLOCK_SIZE, add an additional padding block
    if(block_offset == clen) {
        memset(output, 0x00, BLOCK_SIZE);
        output[0] = 0x01;
        return;
    }
    const SIZE r_clen  = clen - block_offset;
    // Fill with ciphertext if available
    if(BLOCK_SIZE <= r_clen) { // enough ciphertext
        memcpy(output, c + block_offset, BLOCK_SIZE);
    } else { // not enough ciphertext, need to pad
        if(r_clen > 0) // c might be nullptr
            memcpy(output, c + block_offset, r_clen);
        memset(output + r_clen, 0x00, BLOCK_SIZE - r_clen);
        output[r_clen] = 0x01;
    }
    print_block("C/M block", output, BLOCK_SIZE);
}

// It is assumed that c is sufficiently long
// Also, tag and c should not overlap
void crypto_aead_impl(
    BYTE* c, BYTE* tag, const BYTE* m, SIZE mlen, const BYTE* ad, SIZE adlen,
    const BYTE* npub, const BYTE* k, int encrypt)
{ 
    printf("--- crypto_aead_impl start (encrypt=%d) ---\n", encrypt);
    print_block("Key", k, CRYPTO_KEYBYTES);
    print_block("Nonce (npub)", npub, CRYPTO_NPUBBYTES);
    if(mlen > 0) print_block("Message input (first block)", m, (mlen < BLOCK_SIZE) ? mlen : BLOCK_SIZE);
    if(adlen > 0) print_block("AD input (first block)", ad, (adlen < BLOCK_SIZE) ? adlen : BLOCK_SIZE);

    // Compute number of blocks
    
    // +1 because of nonce block for AD
    const SIZE nblocks_c  = 1 + mlen / BLOCK_SIZE; 

    // If mlen is a multiple of BLOCK_SIZE, the last block is a padding block
    const SIZE nblocks_m  = (mlen % BLOCK_SIZE) ? nblocks_c : nblocks_c - 1;

    // +1 because of nonce block for AD
    const SIZE nblocks_ad = 1 + (CRYPTO_NPUBBYTES + adlen) / BLOCK_SIZE;

    // Number of iterations of the main loop(max number of blocks to process)
    const SIZE nb_it = (nblocks_c + 1 > nblocks_ad - 1) ? nblocks_c + 1 : nblocks_ad - 1;

    // Storage for the expanded key L
    // So the key itself is 16 bytes, we need to expand it to 20 bytes
    BYTE expanded_key[BLOCK_SIZE] = {0};
    memcpy(expanded_key, k, CRYPTO_KEYBYTES);

    // Compute L = p^2(K)
    printf("Permutation on expanded_key (L = p^2(K)) - before\n");
    print_block("expanded_key before perm", expanded_key, BLOCK_SIZE);
    permutation(expanded_key);
    printf("Permutation on expanded_key - after\n");
    print_block("expanded_key after perm", expanded_key, BLOCK_SIZE);

    // Buffers for storing previous, current and next mask
    BYTE mask_buffer_1[BLOCK_SIZE] = {0};
    BYTE mask_buffer_2[BLOCK_SIZE] = {0};
    BYTE mask_buffer_3[BLOCK_SIZE] = {0};
    memcpy(mask_buffer_2, expanded_key, BLOCK_SIZE);

    BYTE* previous_mask = mask_buffer_1;
    BYTE* current_mask = mask_buffer_2;
    BYTE* next_mask = mask_buffer_3;

    // Buffer to store current ciphertext/AD block
    BYTE buffer[BLOCK_SIZE];
    
    // Tag buffer and initialization of tag to first AD block
    BYTE tag_buffer[BLOCK_SIZE] = {0};
    get_ad_block(tag_buffer, ad, adlen, npub, 0);
    print_block("Initial tag_buffer (after AD block 0)", tag_buffer, BLOCK_SIZE);

    SIZE offset = 0;
    // nb_it iterations to process all blocks
    for(SIZE i = 0; i < nb_it; ++i) {
        // Compute mask for the next message
        printf("\n--- Iteration %zu ---\n", (size_t)i);
        lfsr_step(next_mask, current_mask);
        print_block("previous_mask", previous_mask, BLOCK_SIZE);
        print_block("current_mask", current_mask, BLOCK_SIZE);
        print_block("next_mask", next_mask, BLOCK_SIZE);
        
        if(i < nblocks_m) {
            // Compute ciphertext block
            memcpy(buffer, npub, CRYPTO_NPUBBYTES);
            memset(buffer + CRYPTO_NPUBBYTES, 0, BLOCK_SIZE - CRYPTO_NPUBBYTES);

            //
            printf("Compute ciphertext block %zu - prepare buffer with nonce\n", (size_t)i);
            print_block("buffer before masks", buffer, BLOCK_SIZE);
            xor_block(buffer, current_mask, BLOCK_SIZE);
            xor_block(buffer, next_mask, BLOCK_SIZE);
            printf("Calling permutation for ciphertext block %zu - before\n", (size_t)i);
            print_block("buffer before perm", buffer, BLOCK_SIZE);
            permutation(buffer);
            printf("After permutation for ciphertext block %zu\n", (size_t)i);
            print_block("buffer after perm", buffer, BLOCK_SIZE);

            //
            xor_block(buffer, current_mask, BLOCK_SIZE);
            xor_block(buffer, next_mask, BLOCK_SIZE);
            const SIZE r_size = (i == nblocks_m - 1) ? mlen - offset : BLOCK_SIZE;
            print_block("message block to xor", m + offset, r_size);
            xor_block(buffer, m + offset, r_size);
            print_block("ciphertext output (partial)", buffer, r_size);
            memcpy(c + offset, buffer, r_size);
        }

        if(i > 0 && i <= nblocks_c) {
            // Compute tag for ciphertext block

            // If encrypting, get ciphertext block, otherwise get message block
            get_c_block(buffer, encrypt ? c : m, mlen, i - 1);
            xor_block(buffer, previous_mask, BLOCK_SIZE);
            xor_block(buffer, next_mask, BLOCK_SIZE);
            permutation(buffer);
            xor_block(buffer, previous_mask, BLOCK_SIZE);
            xor_block(buffer, next_mask, BLOCK_SIZE);
            xor_block(tag_buffer, buffer, BLOCK_SIZE);
            print_block("tag_buffer after including C/M block", tag_buffer, BLOCK_SIZE);
        }

        // If there is any AD left, compute tag for AD block 
        if(i + 1 < nblocks_ad) {
            get_ad_block(buffer, ad, adlen, npub, i + 1);
            xor_block(buffer, next_mask, BLOCK_SIZE);
            permutation(buffer);
            xor_block(buffer, next_mask, BLOCK_SIZE);
            xor_block(tag_buffer, buffer, BLOCK_SIZE);
            print_block("tag_buffer after including AD block", tag_buffer, BLOCK_SIZE);
        }

        // Cyclically shift the mask buffers 
        // Value of next_mask will be computed in the next iteration
        BYTE* const temp = previous_mask;
        previous_mask = current_mask;
        current_mask = next_mask;
        next_mask = temp;

        offset += BLOCK_SIZE;
    }
    // Compute tag
    printf("Finalizing tag - before final ops\n");
    print_block("tag_buffer before final XOR", tag_buffer, BLOCK_SIZE);
    xor_block(tag_buffer, expanded_key, BLOCK_SIZE);
    printf("After XOR with expanded_key, before permutation\n");
    print_block("tag_buffer", tag_buffer, BLOCK_SIZE);
    permutation(tag_buffer);
    printf("After permutation in final tag step\n");
    print_block("tag_buffer", tag_buffer, BLOCK_SIZE);
    xor_block(tag_buffer, expanded_key, BLOCK_SIZE);
    print_block("tag_buffer final", tag_buffer, BLOCK_SIZE);
    memcpy(tag, tag_buffer, CRYPTO_ABYTES);
    printf("--- crypto_aead_impl end ---\n");
}

// Remark: c must be at least mlen + CRYPTO_ABYTES long
int crypto_aead_encrypt(
  unsigned char *ciphertext, unsigned long long *ciphertext_length,
  const unsigned char *message, unsigned long long message_length,
  const unsigned char *associated_data, unsigned long long associated_data_length,
  const unsigned char *nsec,
  const unsigned char *nonce,
  const unsigned char *key)
{ 
    (void)nsec;

    // The length of the ciphertext is the length of the message plus the length of the tag
    *ciphertext_length = message_length + CRYPTO_ABYTES;
    // create bytes to hold the tag
    BYTE tag[CRYPTO_ABYTES];
    // call the function that does the heavy lifting
    crypto_aead_impl(ciphertext, tag, message, message_length, associated_data, associated_data_length, nonce, key, 1);
    // append the tag to the ciphertext
    memcpy(ciphertext + message_length, tag, CRYPTO_ABYTES);
    return 0;
}

int crypto_aead_decrypt(
  unsigned char *m, unsigned long long *mlen,
  unsigned char *nsec,
  const unsigned char *c, unsigned long long clen,
  const unsigned char *ad, unsigned long long adlen,
  const unsigned char *npub,
  const unsigned char *k)
{
    (void)nsec;
    if(clen < CRYPTO_ABYTES)
        return -1;
    *mlen = clen - CRYPTO_ABYTES;
    BYTE tag[CRYPTO_ABYTES];
    crypto_aead_impl(m, tag, c, *mlen, ad, adlen, npub, k, 0);
    return (constcmp(c + *mlen, tag, CRYPTO_ABYTES) == 0) ? 0 : -1;
}
