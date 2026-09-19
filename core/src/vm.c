/* SPDX-License-Identifier: MIT
 * Portable eBPF interpreter. Semantics follow the Linux kernel interpreter
 * (kernel/bpf/core.c): division by zero yields 0, modulo by zero leaves the
 * dividend, shift amounts are masked, 32-bit operations zero-extend.
 */
#include <stdlib.h>
#include <string.h>

#include "espbpf.h"
#include "opcodes.h"

_Static_assert(sizeof(struct espbpf_insn) == 8, "insn must be 8 bytes");

int espbpf_load_raw(const struct espbpf_insn *insns, uint32_t n,
                    struct espbpf_prog *out)
{
    if (!insns || !out || n == 0 || n > ESPBPF_MAX_INSNS)
        return ESPBPF_E_INVAL;
    memset(out, 0, sizeof(*out));
    out->insns = malloc(n * sizeof(*insns));
    if (!out->insns)
        return ESPBPF_E_NOMEM;
    memcpy(out->insns, insns, n * sizeof(*insns));
    out->n_insns = n;
    strcpy(out->name, "raw");
    return ESPBPF_OK;
}

void espbpf_prog_free(struct espbpf_prog *prog)
{
    if (!prog)
        return;
    free(prog->insns);
    free(prog->rodata);
    memset(prog, 0, sizeof(*prog));
}

/* Is [addr, addr+len) inside [base, base+size)? Written without overflow. */
static bool in_range(uint64_t addr, uint64_t len, uintptr_t base,
                     uint64_t size)
{
    return base != 0 && len <= size && addr >= base &&
           addr - base <= size - len;
}

void *espbpf_vm_mem(struct espbpf_vm *vm, uint64_t ptr, uint64_t len,
                    bool write)
{
    if (len == 0)
        return NULL;
    if (in_range(ptr, len, (uintptr_t)vm->stack, sizeof(vm->stack)))
        return (void *)(uintptr_t)ptr;
    if (vm->ctx && vm->env->ctx_size &&
        in_range(ptr, len, (uintptr_t)vm->ctx, vm->env->ctx_size) &&
        (!write || vm->env->ctx_writable))
        return (void *)(uintptr_t)ptr;
    if (!write && vm->prog->rodata &&
        in_range(ptr, len, (uintptr_t)vm->prog->rodata,
                 vm->prog->rodata_len))
        return (void *)(uintptr_t)ptr;
    return NULL;
}

static const struct espbpf_helper *find_helper(const struct espbpf_env *env,
                                               uint32_t id)
{
    for (size_t i = 0; i < env->n_helpers; i++)
        if (env->helpers[i].id == id)
            return &env->helpers[i];
    return NULL;
}

static uint64_t bswap(uint64_t v, int bits)
{
    switch (bits) {
    case 16: return (uint16_t)((v >> 8) | (v << 8));
    case 32: return __builtin_bswap32((uint32_t)v);
    default: return __builtin_bswap64(v);
    }
}

static uint64_t load_mem(const uint8_t *p, unsigned size, bool sx)
{
    switch (size) {
    case 1: { uint8_t v = *p; return sx ? (uint64_t)(int64_t)(int8_t)v : v; }
    case 2: { uint16_t v; memcpy(&v, p, 2);
              return sx ? (uint64_t)(int64_t)(int16_t)v : v; }
    case 4: { uint32_t v; memcpy(&v, p, 4);
              return sx ? (uint64_t)(int64_t)(int32_t)v : v; }
    default: { uint64_t v; memcpy(&v, p, 8); return v; }
    }
}

static void store_mem(uint8_t *p, unsigned size, uint64_t v)
{
    switch (size) {
    case 1: *p = (uint8_t)v; break;
    case 2: { uint16_t t = (uint16_t)v; memcpy(p, &t, 2); break; }
    case 4: { uint32_t t = (uint32_t)v; memcpy(p, &t, 4); break; }
    default: memcpy(p, &v, 8); break;
    }
}

static int64_t sext(uint64_t v, int bits)
{
    switch (bits) {
    case 8:  return (int8_t)v;
    case 16: return (int16_t)v;
    default: return (int32_t)v;
    }
}

/* 64-bit arithmetic. Returns false for an invalid opcode. */
static bool alu64(uint8_t op, int16_t off, uint64_t *dst, uint64_t src)
{
    int64_t sd = (int64_t)*dst, ss = (int64_t)src;
    switch (op) {
    case BPF_ADD:  *dst += src; break;
    case BPF_SUB:  *dst -= src; break;
    case BPF_MUL:  *dst *= src; break;
    case BPF_OR:   *dst |= src; break;
    case BPF_AND:  *dst &= src; break;
    case BPF_XOR:  *dst ^= src; break;
    case BPF_LSH:  *dst <<= (src & 63); break;
    case BPF_RSH:  *dst >>= (src & 63); break;
    case BPF_ARSH: *dst = (uint64_t)(sd >> (src & 63)); break;
    case BPF_NEG:  *dst = (uint64_t)0 - *dst; break;
    case BPF_MOV:
        *dst = off ? (uint64_t)sext(src, off) : src;
        break;
    case BPF_DIV:
        if (off == 0)
            *dst = src ? *dst / src : 0;
        else if (ss == 0)
            *dst = 0;
        else if (ss == -1)
            *dst = (uint64_t)0 - *dst;  /* avoids INT64_MIN / -1 UB */
        else
            *dst = (uint64_t)(sd / ss);
        break;
    case BPF_MOD:
        if (off == 0) {
            if (src)
                *dst %= src;
        } else if (ss == -1) {
            *dst = 0;
        } else if (ss != 0) {
            *dst = (uint64_t)(sd % ss);
        }
        break;
    default:
        return false;
    }
    return true;
}

static bool alu32(uint8_t op, int16_t off, uint64_t *dst64, uint64_t src64)
{
    uint32_t dst = (uint32_t)*dst64, src = (uint32_t)src64;
    int32_t sd = (int32_t)dst, ss = (int32_t)src;
    switch (op) {
    case BPF_ADD:  dst += src; break;
    case BPF_SUB:  dst -= src; break;
    case BPF_MUL:  dst *= src; break;
    case BPF_OR:   dst |= src; break;
    case BPF_AND:  dst &= src; break;
    case BPF_XOR:  dst ^= src; break;
    case BPF_LSH:  dst <<= (src & 31); break;
    case BPF_RSH:  dst >>= (src & 31); break;
    case BPF_ARSH: dst = (uint32_t)(sd >> (src & 31)); break;
    case BPF_NEG:  dst = 0u - dst; break;
    case BPF_MOV:
        dst = off ? (uint32_t)sext(src64, off) : src;
        break;
    case BPF_DIV:
        if (off == 0)
            dst = src ? dst / src : 0;
        else if (ss == 0)
            dst = 0;
        else if (ss == -1)
            dst = 0u - dst;
        else
            dst = (uint32_t)(sd / ss);
        break;
    case BPF_MOD:
        if (off == 0) {
            if (src)
                dst %= src;
        } else if (ss == -1) {
            dst = 0;
        } else if (ss != 0) {
            dst = (uint32_t)(sd % ss);
        }
        break;
    default:
        return false;
    }
    *dst64 = dst;  /* zero-extend */
    return true;
}

static bool cond64(uint8_t op, uint64_t a, uint64_t b)
{
    int64_t sa = (int64_t)a, sb = (int64_t)b;
    switch (op) {
    case BPF_JEQ:  return a == b;
    case BPF_JNE:  return a != b;
    case BPF_JGT:  return a > b;
    case BPF_JGE:  return a >= b;
    case BPF_JLT:  return a < b;
    case BPF_JLE:  return a <= b;
    case BPF_JSET: return (a & b) != 0;
    case BPF_JSGT: return sa > sb;
    case BPF_JSGE: return sa >= sb;
    case BPF_JSLT: return sa < sb;
    case BPF_JSLE: return sa <= sb;
    default:       return false;
    }
}

int espbpf_exec(const struct espbpf_prog *prog, const struct espbpf_env *env,
                void *ctx, void *user, uint64_t *ret)
{
    if (!prog || !env || !prog->verified || !prog->insns)
        return ESPBPF_E_INVAL;
    if (env->ctx_size && !ctx)
        return ESPBPF_E_INVAL;

    struct espbpf_vm vm;
    memset(&vm, 0, sizeof(vm));   /* also zeroes the guest stack */
    vm.prog = prog;
    vm.env = env;
    vm.ctx = ctx;
    vm.user = user;
    vm.reg[1] = (uintptr_t)ctx;
    vm.reg[BPF_REG_FP] = (uintptr_t)vm.stack + sizeof(vm.stack);

    const struct espbpf_insn *code = prog->insns;
    const uint32_t n = prog->n_insns;
    uint32_t pc = 0;

    while (pc < n) {
        /* The verifier proves the CFG is a DAG, so this cannot trigger;
         * it is here so a verifier bug cannot hang the device. */
        if (++vm.steps > n)
            return ESPBPF_E_FAULT;

        const struct espbpf_insn *in = &code[pc];
        uint64_t *dst = &vm.reg[in->dst];
        uint64_t src = vm.reg[in->src];
        uint8_t cls = BPF_CLASS(in->code);
        uint8_t op = BPF_OP(in->code);

        switch (cls) {
        case BPF_ALU64:
        case BPF_ALU: {
            if (op == BPF_END) {
                if (cls == BPF_ALU64)
                    *dst = bswap(*dst, in->imm);          /* v4 bswap */
                else if (BPF_SRC(in->code) == BPF_X)
                    *dst = bswap(*dst, in->imm);          /* to_be */
                else if (in->imm == 16)
                    *dst = (uint16_t)*dst;                /* to_le */
                else if (in->imm == 32)
                    *dst = (uint32_t)*dst;
                break;
            }
            uint64_t s = BPF_SRC(in->code) == BPF_X ? src
                                                     : (uint64_t)(int64_t)in->imm;
            bool ok = cls == BPF_ALU64 ? alu64(op, in->off, dst, s)
                                       : alu32(op, in->off, dst, s);
            if (!ok)
                return ESPBPF_E_FAULT;
            break;
        }

        case BPF_LD:  /* only LD_IMM64 passes the verifier */
            if (in->src == ESPBPF_PSEUDO_RODATA)
                *dst = (uintptr_t)prog->rodata + (uint32_t)in->imm;
            else
                *dst = (uint64_t)(uint32_t)in->imm |
                       ((uint64_t)(uint32_t)code[pc + 1].imm << 32);
            pc++;
            break;

        case BPF_LDX: {
            unsigned sz = bpf_size_bytes(in->code);
            uint8_t *p = espbpf_vm_mem(&vm, src + (uint64_t)(int64_t)in->off,
                                       sz, false);
            if (!p)
                return ESPBPF_E_FAULT;
            *dst = load_mem(p, sz, BPF_MODE(in->code) == BPF_MEMSX);
            break;
        }

        case BPF_ST:
        case BPF_STX: {
            unsigned sz = bpf_size_bytes(in->code);
            uint8_t *p = espbpf_vm_mem(&vm, *dst + (uint64_t)(int64_t)in->off,
                                       sz, true);
            if (!p)
                return ESPBPF_E_FAULT;
            store_mem(p, sz, cls == BPF_STX ? src : (uint64_t)(int64_t)in->imm);
            break;
        }

        case BPF_JMP:
        case BPF_JMP32:
            if (op == BPF_EXIT) {
                if (ret)
                    *ret = vm.reg[0];
                return ESPBPF_OK;
            }
            if (op == BPF_CALL) {
                const struct espbpf_helper *h = find_helper(env, (uint32_t)in->imm);
                if (!h)
                    return ESPBPF_E_FAULT;
                vm.reg[0] = h->fn(&vm, vm.reg[1], vm.reg[2], vm.reg[3],
                                  vm.reg[4], vm.reg[5]);
                break;
            }
            if (op == BPF_JA) {
                pc += (uint32_t)(cls == BPF_JMP32 ? in->imm : in->off);
                break;
            }
            {
                uint64_t a = *dst;
                uint64_t b = BPF_SRC(in->code) == BPF_X ? src
                                                        : (uint64_t)(int64_t)in->imm;
                if (cls == BPF_JMP32) {
                    /* Narrow to 32 bits, extending the way cond64() will
                     * compare: sign-extend for signed ops. */
                    bool sgn = op == BPF_JSGT || op == BPF_JSGE ||
                               op == BPF_JSLT || op == BPF_JSLE;
                    a = sgn ? (uint64_t)(int64_t)(int32_t)a : (uint32_t)a;
                    b = sgn ? (uint64_t)(int64_t)(int32_t)b : (uint32_t)b;
                }
                if (cond64(op, a, b))
                    pc += (uint32_t)(int32_t)in->off;
            }
            break;

        default:
            return ESPBPF_E_FAULT;
        }
        pc++;
    }
    return ESPBPF_E_FAULT;  /* fell off the end; verifier forbids this */
}
