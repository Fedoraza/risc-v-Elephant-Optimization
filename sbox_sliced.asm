###############################################################################
#  perm_table[] for Spongent-π[160]
#  P(b) = perm_table[b]  for b in 0..159
###############################################################################
    .section .rodata
    .align 4
perm_table:
    .byte 0,40,80,120,1,41,81,121,2,42,82,122,3,43,83,123
    .byte 4,44,84,124,5,45,85,125,6,46,86,126,7,47,87,127
    .byte 8,48,88,128,9,49,89,129,10,50,90,130,11,51,91,131
    .byte 12,52,92,132,13,53,93,133,14,54,94,134,15,55,95,135
    .byte 16,56,96,136,17,57,97,137,18,58,98,138,19,59,99,139
    .byte 20,60,100,140,21,61,101,141,22,62,102,142,23,63,103,143
    .byte 24,64,104,144,25,65,105,145,26,66,106,146,27,67,107,147
    .byte 28,68,108,148,29,69,109,149,30,70,110,150,31,71,111,151
    .byte 32,72,112,152,33,73,113,153,34,74,114,154,35,75,115,155
    .byte 36,76,116,156,37,77,117,157,38,78,118,158,39,79,119,159


###############################################################################
#  void sbox_perm_bitsliced(uint32_t slices[160]);
###############################################################################
    .section .text
    .globl sbox_perm_bitsliced
sbox_perm_bitsliced:
    # a0 = slices pointer
    mv      t0, a0              # t0 = slices base pointer
    la      t1, perm_table      # t1 = &perm_table[0]

    addi    sp, sp, -640        # tmp[160] on stack (160 * 4 bytes)

    li      t2, 0               # t2 = nibble index n = 0..39

sbox_loop:
    li      t3, 40
    bge     t2, t3, finish_sbox # if n >= 40: done

    #################################################################
    # Load 4 slices (one nibble): X0..X3
    #################################################################
    slli    t3, t2, 4           # offsetBytes = 4*n * 4 bytes = n * 16
    add     t3, t3, t0          # &slices[4*n]

    lw      a3,  0(t3)          # X3 = slices[4*n + 0] (bit 0)
    lw      a2,  4(t3)          # X2 = slices[4*n + 1] (bit 1)
    lw      a1,  8(t3)          # X1 = slices[4*n + 2] (bit 2)
    lw      a0, 12(t3)          # X0 = slices[4*n + 3] (bit 3)

    #################################################################
    # S-BOX: Boolean circuit (bitsliced)
    #
    # Inputs:
    #   X0 = a0, X1 = a1, X2 = a2, X3 = a3
    #
    # Temps mapping:
    #   q0  -> a4
    #   q1  -> a5
    #   t0  -> a6
    #   q2  -> a7
    #   q3  -> t3
    #   t1  -> t4
    #   q4  -> a4 (reuse)
    #   q5  -> a5 (reuse)
    #   t2  -> t5
    #   q6  -> a7 (reuse)
    #   q7  -> t3 (reuse)
    #   t3  -> t6
    #
    # Outputs (logical S-box outputs):
    #   y0 -> a4  (bit 3)
    #   y1 -> a5  (bit 2)
    #   y2 -> a7  (bit 1)
    #   y3 -> t5  (bit 0)
    #################################################################

    # q0 = X0 ^ X2
    xor     a4, a0, a2          # q0

    # q1 = X1 ^ X2
    xor     a5, a1, a2          # q1

    # t0 = q0 & q1
    and     a6, a4, a5          # t0

    # q2 = 1 ^ X0 ^ X1 ^ X3 ^ t0
    xori    a7, a0, -1          # 1 ^ X0  (using 0xFFFFFFFF for '1' bit-sliced)
    xor     a7, a7, a1
    xor     a7, a7, a3
    xor     a7, a7, a6          # q2

    # q3 = 1 ^ X0
    xori    t3, a0, -1          # q3

    # t1 = q2 & q3
    and     t4, a7, t3          # t1

    # q4 = X1 ^ t1
    xor     a4, a1, t4          # q4

    # q5 = X1 ^ X2 ^ X3 ^ t0 ^ t1
    xor     a5, a1, a2
    xor     a5, a5, a3
    xor     a5, a5, a6
    xor     a5, a5, t4          # q5

    # t2 = q4 & q5
    and     t5, a4, a5          # t2

    # q6 = X2 ^ t0
    xor     a7, a2, a6          # q6

    # q7 = 1 ^ X1 ^ t0
    xori    t3, a1, -1
    xor     t3, t3, a6          # q7

    # t3 = q6 & q7
    and     t6, a7, t3          # t3 (in Lustre notation)

    # y0 = X1 ^ X2 ^ X3 ^ t2
    xor     a4, a1, a2
    xor     a4, a4, a3
    xor     a4, a4, t5          # y0 (bit 3)

    # y1 = X0 ^ X2 ^ X3 ^ t0 ^ t1
    xor     a5, a0, a2
    xor     a5, a5, a3
    xor     a5, a5, a6          # t0
    xor     a5, a5, t4          # t1 => y1 (bit 2)

    # y2 = X0 ^ X1 ^ X2 ^ t1
    xor     a7, a0, a1
    xor     a7, a7, a2
    xor     a7, a7, t4          # y2 (bit 1)

    # y3 = X0 ^ X3 ^ t0 ^ t3
    xor     t5, a0, a3
    xor     t5, t5, a6          # t0
    xor     t5, t5, t6          # t3 => y3 (bit 0)

    #################################################################
    # PERMUTATION:
    #
    # Global bit index b = 4*n + k, k = 0..3.
    #   bb0 = bit 0 of nibble n -> y3
    #   bb1 = bit 1 of nibble n -> y2
    #   bb2 = bit 2 of nibble n -> y1
    #   bb3 = bit 3 of nibble n -> y0
    #
    # For each k:
    #   dest = perm_table[4*n + k]
    #   tmp[dest] = corresponding y_k
    #################################################################

    slli    t3, t2, 2           # baseBit = n * 4

    # bit 0 (LSB) = y3 -> tmp[ perm_table[baseBit + 0] ]
    add     t4, t1, t3          # &perm_table[baseBit + 0]
    lbu     t6, 0(t4)           # dest0
    slli    t6, t6, 2           # dest0 * 4
    add     t6, sp, t6
    sw      t5, 0(t6)           # store y3

    # bit 1 = y2 -> tmp[ perm_table[baseBit + 1] ]
    addi    t4, t3, 1
    add     t4, t1, t4
    lbu     t6, 0(t4)           # dest1
    slli    t6, t6, 2
    add     t6, sp, t6
    sw      a7, 0(t6)           # store y2

    # bit 2 = y1 -> tmp[ perm_table[baseBit + 2] ]
    addi    t4, t3, 2
    add     t4, t1, t4
    lbu     t6, 0(t4)           # dest2
    slli    t6, t6, 2
    add     t6, sp, t6
    sw      a5, 0(t6)           # store y1

    # bit 3 (MSB) = y0 -> tmp[ perm_table[baseBit + 3] ]
    addi    t4, t3, 3
    add     t4, t1, t4
    lbu     t6, 0(t4)           # dest3
    slli    t6, t6, 2
    add     t6, sp, t6
    sw      a4, 0(t6)           # store y0

    #################################################################
    # Next nibble
    #################################################################
    addi    t2, t2, 1
    j       sbox_loop


###############################################################################
# Copy tmp[0..159] → slices[0..159]
###############################################################################
finish_sbox:
    li      t2, 0               # i = 0

copy_tmp:
    li      t3, 160
    bge     t2, t3, end_sbox

    slli    t4, t2, 2           # byte offset = i * 4
    add     t5, sp, t4
    lw      t6, 0(t5)           # tmp[i]

    add     t5, t0, t4          # t0 = slices base
    sw      t6, 0(t5)           # slices[i] = tmp[i]

    addi    t2, t2, 1
    j       copy_tmp

end_sbox:
    addi    sp, sp, 640
    ret
