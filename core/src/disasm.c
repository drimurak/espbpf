/* SPDX-License-Identifier: MIT
 * Minimal disassembler in a syntax close to llvm-objdump / bpftool. */
#include <stdio.h>

#include "espbpf.h"
#include "opcodes.h"

static const char *alu_op(uint8_t op)
{
    static const char *const names[] = {
        "+=", "-=", "*=", "/=", "|=", "&=", "<<=", ">>=",
        "neg", "%=", "^=", "=", "s>>=", "end",
    };
    unsigned i = op >> 4;
    return i < sizeof(names) / sizeof(names[0]) ? names[i] : "?";
}

static const char *jmp_op(uint8_t op)
{
    static const char *const names[] = {
        "ja", "==", ">", ">=", "&", "!=", "s>", "s>=",
        "call", "exit", "<", "<=", "s<", "s<=",
    };
    unsigned i = op >> 4;
    return i < sizeof(names) / sizeof(names[0]) ? names[i] : "?";
}

static const char *size_name(uint8_t code)
{
    switch (BPF_SIZE(code)) {
    case BPF_B: return "u8";
    case BPF_H: return "u16";
    case BPF_W: return "u32";
    default:    return "u64";
    }
}

int espbpf_disasm(const struct espbpf_insn *insns, uint32_t n, uint32_t pc,
                  char *buf, size_t len)
{
    if (pc >= n)
        return snprintf(buf, len, "<out of range>");
    const struct espbpf_insn *in = &insns[pc];
    uint8_t cls = BPF_CLASS(in->code), op = BPF_OP(in->code);
    const char *w = (cls == BPF_ALU || cls == BPF_JMP32) ? "w" : "r";

    switch (cls) {
    case BPF_ALU:
    case BPF_ALU64:
        if (op == BPF_NEG)
            return snprintf(buf, len, "%s%u = -%s%u", w, in->dst, w, in->dst);
        if (op == BPF_END)
            return snprintf(buf, len, "r%u = %s%d r%u", in->dst,
                            cls == BPF_ALU64 ? "bswap"
                            : BPF_SRC(in->code) == BPF_X ? "be" : "le",
                            (int)in->imm, in->dst);
        {
            /* v4: off=1 marks signed div/mod, off=8/16/32 sign-extending mov */
            const char *sgn = (in->off && (op == BPF_DIV || op == BPF_MOD)) ? "s" : "";
            if (op == BPF_MOV && in->off)
                return snprintf(buf, len, "%s%u = (s%d)%s%u", w, in->dst, in->off,
                                w, in->src);
            if (BPF_SRC(in->code) == BPF_X)
                return snprintf(buf, len, "%s%u %s%s %s%u", w, in->dst, sgn,
                                alu_op(op), w, in->src);
            return snprintf(buf, len, "%s%u %s%s %d", w, in->dst, sgn, alu_op(op),
                            (int)in->imm);
        }

    case BPF_LD:
        if (in->src == ESPBPF_PSEUDO_RODATA)
            return snprintf(buf, len, "r%u = &rodata[%u]", in->dst,
                            (unsigned)(uint32_t)in->imm);
        if (pc + 1 < n)
            return snprintf(buf, len, "r%u = 0x%llx ll", in->dst,
                            (unsigned long long)((uint64_t)(uint32_t)in->imm |
                                ((uint64_t)(uint32_t)insns[pc + 1].imm << 32)));
        return snprintf(buf, len, "lddw <truncated>");

    case BPF_LDX:
        return snprintf(buf, len, "r%u = *(%s%s *)(r%u %+d)", in->dst,
                        BPF_MODE(in->code) == BPF_MEMSX ? "s" : "",
                        size_name(in->code), in->src, in->off);
    case BPF_ST:
        return snprintf(buf, len, "*(%s *)(r%u %+d) = %d", size_name(in->code),
                        in->dst, in->off, (int)in->imm);
    case BPF_STX:
        return snprintf(buf, len, "*(%s *)(r%u %+d) = r%u", size_name(in->code),
                        in->dst, in->off, in->src);

    default:
        if (op == BPF_EXIT)
            return snprintf(buf, len, "exit");
        if (op == BPF_CALL)
            return snprintf(buf, len, "call %d", (int)in->imm);
        if (op == BPF_JA)
            return snprintf(buf, len, "goto pc%+d",
                            (int)(cls == BPF_JMP32 ? in->imm : in->off));
        if (BPF_SRC(in->code) == BPF_X)
            return snprintf(buf, len, "if %s%u %s %s%u goto pc%+d", w, in->dst,
                            jmp_op(op), w, in->src, in->off);
        return snprintf(buf, len, "if %s%u %s %d goto pc%+d", w, in->dst,
                        jmp_op(op), (int)in->imm, in->off);
    }
}
