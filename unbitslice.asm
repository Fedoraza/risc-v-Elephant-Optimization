    .section .text
    .globl unbitslice_32x160
    .type  unbitslice_32x160, @function

# void unbitslice_32x160(const uint32_t slices[160], uint8_t states[32][20]);
# a0 = slices pointer
# a1 = states pointer

unbitslice_32x160:
    mv      t0, a0          # t0 = slices base
    mv      t1, a1          # t1 = states base

    li      t2, 0           # t2 = j (state index 0..31)

outer_state:
    li      t3, 0           # t3 = byte_index 0..19

byte_loop:
    li      t5, 0           # t5 = acc byte = 0
    li      t4, 0           # t4 = bit_in_byte 0..7

bit_loop:
    # b = byte_index*8 + bit_in_byte
    slli    t6, t3, 3       # t6 = byte_index * 8
    add     t6, t6, t4      # t6 = b

    li      a2, 160
    bge     t6, a2, store_byte   # if b >= 160, skip remaining bits

    # slice = slices[b]
    slli    a2, t6, 2       # a2 = b * 4
    add     a2, a2, t0
    lw      a2, 0(a2)       # a2 = slices[b]

    # bit = (slice >> j) & 1
    srl     a2, a2, t2
    andi    a2, a2, 1

    # acc |= bit << bit_in_byte
    sll     a2, a2, t4
    or      t5, t5, a2

    # next bit_in_byte
    addi    t4, t4, 1
    li      a2, 8
    blt     t4, a2, bit_loop

store_byte:
    # states[j][byte_index] = acc
    # offset = j*20 + byte_index
    slli    t6, t2, 4       # j * 16
    slli    a2, t2, 2       # j * 4
    add     t6, t6, a2      # j * 20
    add     t6, t6, t3      # + byte_index
    add     t6, t6, t1      # + base
    sb      t5, 0(t6)

    # next byte_index
    addi    t3, t3, 1
    li      a2, 20
    blt     t3, a2, byte_loop

    # next state j
    addi    t2, t2, 1
    li      a2, 32
    blt     t2, a2, outer_state

    ret
