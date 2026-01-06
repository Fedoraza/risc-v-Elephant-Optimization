###############################################################################
# void add_counter_bitsliced(uint32_t slices[160], uint32_t lfsr[7]);
#
# a0 = slices
# a1 = lfsr
###############################################################################

    .section .text
    .globl add_counter_bitsliced
    .type  add_counter_bitsliced, @function

add_counter_bitsliced:
    ###########################################################################
    # Load LFSR bit-slices
    ###########################################################################
    lw  t0,  0(a1)   # bit 0
    lw  t1,  4(a1)   # bit 1
    lw  t2,  8(a1)   # bit 2
    lw  t3, 12(a1)   # bit 3
    lw  t4, 16(a1)   # bit 4
    lw  t5, 20(a1)   # bit 5
    lw  t6, 24(a1)   # bit 6

    ###########################################################################
    # XOR IV into state bits 0..6 (no bit reversal)
    ###########################################################################
    lw  a2,  0(a0)    // xor slice[0] ^= bit0
    xor a2, a2, t0
    sw  a2,  0(a0)

    lw  a2,  4(a0)    // slice[1] ^= bit1
    xor a2, a2, t1
    sw  a2,  4(a0)

    lw  a2,  8(a0)    // slice[2] ^= bit2
    xor a2, a2, t2
    sw  a2,  8(a0)

    lw  a2, 12(a0)    // slice[3] ^= bit3
    xor a2, a2, t3
    sw  a2, 12(a0)

    lw  a2, 16(a0)    // slice[4] ^= bit4
    xor a2, a2, t4
    sw  a2, 16(a0)

    lw  a2, 20(a0)    // slice[5] ^= bit5
    xor a2, a2, t5
    sw  a2, 20(a0)

    lw  a2, 24(a0)    // slice[6] ^= bit6
    xor a2, a2, t6
    sw  a2, 24(a0)

    ###########################################################################
    # XOR retnuoCl(IV) into state bits 153..159
    # (bit reversal: bit i <- bit 6-i)
    ###########################################################################
    li  a3, 612       # 153 * 4
    add a3, a0, a3

    lw  a2,  0(a3)    // slice[153] ^= bit6
    xor a2, a2, t6
    sw  a2,  0(a3)

    lw  a2,  4(a3)    // slice[154] ^= bit5
    xor a2, a2, t5
    sw  a2,  4(a3)

    lw  a2,  8(a3)    // slice[155] ^= bit4
    xor a2, a2, t4
    sw  a2,  8(a3)

    lw  a2, 12(a3)    // slice[156] ^= bit3
    xor a2, a2, t3
    sw  a2, 12(a3)

    lw  a2, 16(a3)    // slice[157] ^= bit2
    xor a2, a2, t2
    sw  a2, 16(a3)

    lw  a2, 20(a3)    // slice[158] ^= bit1
    xor a2, a2, t1
    sw  a2, 20(a3)

    lw  a2, 24(a3)    // slice[159] ^= bit0
    xor a2, a2, t0
    sw  a2, 24(a3)

    ###########################################################################
    # LFSR update: x^7 + x^6 + 1
    # new_bit0 = bit6 ^ bit5
    ###########################################################################
    xor a2, t6, t5   # new bit 0

    mv  t6, t5
    mv  t5, t4
    mv  t4, t3
    mv  t3, t2
    mv  t2, t1
    mv  t1, t0
    mv  t0, a2

    ###########################################################################
    # Store updated LFSR
    ###########################################################################
    sw  t0,  0(a1)
    sw  t1,  4(a1)
    sw  t2,  8(a1)
    sw  t3, 12(a1)
    sw  t4, 16(a1)
    sw  t5, 20(a1)
    sw  t6, 24(a1)

    ret
