###############################################################################
# void spongent_permute_32(uint8_t states[32][20]);
#
# a0 = pointer to states[32][20]
#
# Calls:
#   bitslice_32x160(states, slices)
#   init_lfsr_bitsliced(lfsr)
#   add_counter_bitsliced(slices, lfsr)
#   sbox_perm_bitsliced(slices)
#   unbitslice_32x160(slices, states)
###############################################################################

    .section .text
    .globl spongent_permute_32
    .type  spongent_permute_32, @function

spongent_permute_32:
    # Stack frame:
    #  0..639   slices[160]  (160*4 = 640)
    # 640..667  lfsr[7]      (7*4  = 28)
    # 668..679  saved s0,s1,s2 (12)
    # 680..683  saved ra      (4)
    # 684..687  padding for 16-byte alignment
    addi    sp, sp, -688

    # Save callee-saved regs we use
    sw      s0, 668(sp)
    sw      s1, 672(sp)
    sw      s2, 676(sp)
    sw      ra, 680(sp)

    # Keep important pointers in callee-saved regs across calls
    mv      s0, a0          # s0 = states pointer (must survive)
    addi    s1, sp, 0       # s1 = &slices[0]   (must survive)

    ###########################################################################
    # bitslice_32x160(states, slices)
    ###########################################################################
    mv      a0, s0          # states
    mv      a1, s1          # slices
    jal     bitslice_32x160

    ###########################################################################
    # init_lfsr_bitsliced(lfsr)
    ###########################################################################
    addi    a0, sp, 640     # &lfsr[0]
    jal     init_lfsr_bitsliced

    ###########################################################################
    # 80 rounds
    ###########################################################################
    li      s2, 80          # round counter

1:  # round_loop
    # add_counter_bitsliced(slices, lfsr)
    mv      a0, s1          # slices
    addi    a1, sp, 640     # lfsr
    jal     add_counter_bitsliced

    # sbox_perm_bitsliced(slices)
    mv      a0, s1
    jal     sbox_perm_bitsliced

    addi    s2, s2, -1
    bnez    s2, 1b

    ###########################################################################
    # unbitslice_32x160(slices, states)
    ###########################################################################
    mv      a0, s1          # slices
    mv      a1, s0          # states
    jal     unbitslice_32x160

    # Restore callee-saved regs + stack
    lw      s0, 668(sp)
    lw      s1, 672(sp)
    lw      s2, 676(sp)
    lw      ra, 680(sp)
    addi    sp, sp, 688
    ret
