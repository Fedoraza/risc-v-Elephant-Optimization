    .section .text
    .globl bitslice_32x160
    .type  bitslice_32x160, @function

    # void bitslice_32x160(const uint8_t states[32][20], uint32_t out[160]);
    # a0 = states pointer
    # a1 = out pointer

bitslice_32x160:
    mv      t0, a0              # t0 = states base
    mv      t1, a1              # t1 = out base

    li      t2, 0               # t2 = b (bit index 0..159)

bit_loop:
    li      t3, 0               # t3 = acc = 0
    li      t4, 0               # t4 = j = 0 (state index 0..31)

state_loop:
    ########################################################
    # Compute address of states[j][b >> 3]
    #   offsetBytes = j*20 + (b >> 3)
    #   j*20 = (j<<4) + (j<<2)
    ########################################################
    slli    t5, t4, 4           # t5 = j * 16
    slli    t6, t4, 2           # t6 = j * 4
    add     t5, t5, t6          # t5 = j * 20

    srli    t6, t2, 3           # t6 = b >> 3  (byte index)
    add     t5, t5, t6          # t5 = j*20 + (b>>3)
    add     t5, t5, t0          # t5 = &states[j][b>>3]

    lbu     t6, 0(t5)           # t6 = states[j][b>>3] (byte)

    ########################################################
    # Extract bit: val = (byte >> (b & 7)) & 1
    ########################################################
    andi    t5, t2, 7           # t5 = bit_in_byte = b & 7
    srl     t6, t6, t5          # t6 = byte >> bit_in_byte
    andi    t6, t6, 1           # t6 = val = 0 or 1

    beq     t6, x0, skip_or     # if val == 0: skip

    ########################################################
    # acc |= (val << j)
    ########################################################
    sll     t6, t6, t4          # t6 = val << j
    or      t3, t3, t6          # acc |= t6

skip_or:
    addi    t4, t4, 1           # j++
    li      t5, 32
    bne     t4, t5, state_loop  # while j != 32

    ########################################################
    # out[b] = acc
    ########################################################
    slli    t4, t2, 2           # t4 = b * 4
    add     t4, t4, t1          # &out[b]
    sw      t3, 0(t4)

    ########################################################
    # b++
    ########################################################
    addi    t2, t2, 1
    li      t5, 160
    bne     t2, t5, bit_loop    # while b != 160

    ret
