/* SPDX-License-Identifier: MIT
 * eBPF instruction encoding (see Documentation/bpf/standardization/
 * instruction-set.rst in the Linux kernel tree). */
#ifndef ESPBPF_OPCODES_H
#define ESPBPF_OPCODES_H

/* instruction classes */
#define BPF_CLASS(c)  ((c) & 0x07)
#define BPF_LD        0x00
#define BPF_LDX       0x01
#define BPF_ST        0x02
#define BPF_STX       0x03
#define BPF_ALU       0x04
#define BPF_JMP       0x05
#define BPF_JMP32     0x06
#define BPF_ALU64     0x07

/* arithmetic / jump source */
#define BPF_SRC(c)    ((c) & 0x08)
#define BPF_K         0x00
#define BPF_X         0x08

/* arithmetic operations */
#define BPF_OP(c)     ((c) & 0xf0)
#define BPF_ADD       0x00
#define BPF_SUB       0x10
#define BPF_MUL       0x20
#define BPF_DIV       0x30
#define BPF_OR        0x40
#define BPF_AND       0x50
#define BPF_LSH       0x60
#define BPF_RSH       0x70
#define BPF_NEG       0x80
#define BPF_MOD       0x90
#define BPF_XOR       0xa0
#define BPF_MOV       0xb0
#define BPF_ARSH      0xc0
#define BPF_END       0xd0

/* jump operations */
#define BPF_JA        0x00
#define BPF_JEQ       0x10
#define BPF_JGT       0x20
#define BPF_JGE       0x30
#define BPF_JSET      0x40
#define BPF_JNE       0x50
#define BPF_JSGT      0x60
#define BPF_JSGE      0x70
#define BPF_CALL      0x80
#define BPF_EXIT      0x90
#define BPF_JLT       0xa0
#define BPF_JLE       0xb0
#define BPF_JSLT      0xc0
#define BPF_JSLE      0xd0

/* load / store sizes and modes */
#define BPF_SIZE(c)   ((c) & 0x18)
#define BPF_W         0x00
#define BPF_H         0x08
#define BPF_B         0x10
#define BPF_DW        0x18
#define BPF_MODE(c)   ((c) & 0xe0)
#define BPF_IMM       0x00
#define BPF_MEM       0x60
#define BPF_MEMSX     0x80

/* LD_IMM64 src_reg values we understand */
#define ESPBPF_PSEUDO_NONE    0
#define ESPBPF_PSEUDO_RODATA  2  /* imm = offset into prog->rodata */

#define BPF_REG_FP    10

static inline unsigned bpf_size_bytes(unsigned code)
{
    switch (BPF_SIZE(code)) {
    case BPF_B:  return 1;
    case BPF_H:  return 2;
    case BPF_W:  return 4;
    default:     return 8;
    }
}

#endif
