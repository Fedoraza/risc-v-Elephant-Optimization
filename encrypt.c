#include "api.h"
#include "crypto_aead.h"
#include <string.h> 
#include <stdio.h>
#include "elephant_160.h"


extern void spongent_permute_32(BYTE states[32][20]);

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

// Wrapper so the assembly bitsliced permutation (operates on 32 states in parallel)
// can be used where we only have a single 20-byte state.
void permutation(BYTE* state)
{
    BYTE states[32][BLOCK_SIZE] = {0};
    memcpy(states[0], state, BLOCK_SIZE);
    spongent_permute_32(states);
    memcpy(state, states[0], BLOCK_SIZE);
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
