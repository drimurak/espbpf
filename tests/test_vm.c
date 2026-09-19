/* SPDX-License-Identifier: MIT
 * Unit tests: interpreter semantics, verifier accept/reject, run-time
 * bounds checks. Instructions are written with kernel-style macros. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "espbpf.h"
#include "../core/src/opcodes.h"

#define INSN(c, d, s, o, i) ((struct espbpf_insn){ .code = (c), .dst = (d), .src = (s), .off = (o), .imm = (i) })
#define MOV64_IMM(d, i)     INSN(BPF_ALU64 | BPF_MOV | BPF_K, d, 0, 0, i)
#define MOV64_REG(d, s)     INSN(BPF_ALU64 | BPF_MOV | BPF_X, d, s, 0, 0)
#define MOV32_IMM(d, i)     INSN(BPF_ALU | BPF_MOV | BPF_K, d, 0, 0, i)
#define ALU64_IMM(op, d, i) INSN(BPF_ALU64 | (op) | BPF_K, d, 0, 0, i)
#define ALU64_REG(op, d, s) INSN(BPF_ALU64 | (op) | BPF_X, d, s, 0, 0)
#define ALU32_IMM(op, d, i) INSN(BPF_ALU | (op) | BPF_K, d, 0, 0, i)
#define ALU32_REG(op, d, s) INSN(BPF_ALU | (op) | BPF_X, d, s, 0, 0)
#define JMP_IMM(op, d, i, o) INSN(BPF_JMP | (op) | BPF_K, d, 0, o, i)
#define JMP_REG(op, d, s, o) INSN(BPF_JMP | (op) | BPF_X, d, s, o, 0)
#define JMP32_IMM(op, d, i, o) INSN(BPF_JMP32 | (op) | BPF_K, d, 0, o, i)
#define JA(o)               INSN(BPF_JMP | BPF_JA, 0, 0, o, 0)
#define LDX(sz, d, s, o)    INSN(BPF_LDX | BPF_MEM | (sz), d, s, o, 0)
#define STX(sz, d, s, o)    INSN(BPF_STX | BPF_MEM | (sz), d, s, o, 0)
#define ST_IMM(sz, d, o, i) INSN(BPF_ST | BPF_MEM | (sz), d, 0, o, i)
#define CALL(id)            INSN(BPF_JMP | BPF_CALL, 0, 0, 0, id)
#define EXIT()              INSN(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)

static int failures, total;

static uint64_t h_add(struct espbpf_vm *vm, uint64_t a, uint64_t b,
                      uint64_t c, uint64_t d, uint64_t e)
{
    (void)vm; (void)c; (void)d; (void)e;
    return a + b;
}

static uint64_t h_sum(struct espbpf_vm *vm, uint64_t ptr, uint64_t len,
                      uint64_t c, uint64_t d, uint64_t e)
{
    (void)c; (void)d; (void)e;
    const uint8_t *p = espbpf_vm_mem(vm, ptr, len, false);
    if (!p)
        return (uint64_t)-1;
    uint64_t s = 0;
    for (uint64_t i = 0; i < len; i++)
        s += p[i];
    return s;
}

static const struct espbpf_helper helpers[] = {
    { 1, "add", h_add, { ESPBPF_ARG_SCALAR, ESPBPF_ARG_SCALAR } },
    { 2, "sum", h_sum, { ESPBPF_ARG_PTR_MEM, ESPBPF_ARG_SIZE } },
};

struct ctx8 { uint32_t a, b; };

static const struct espbpf_env env = {
    .helpers = helpers, .n_helpers = 2,
    .ctx_size = sizeof(struct ctx8), .ctx_writable = false,
};
static const struct espbpf_env env_rw = {
    .helpers = helpers, .n_helpers = 2,
    .ctx_size = sizeof(struct ctx8), .ctx_writable = true,
};

#define N(a) (uint32_t)(sizeof(a) / sizeof((a)[0]))

static void expect_ret(const char *name, const struct espbpf_insn *code,
                       uint32_t n, uint64_t want)
{
    struct espbpf_prog p;
    char log[200];
    struct ctx8 ctx = { 7, 5 };
    uint64_t ret = 0;
    total++;
    if (espbpf_load_raw(code, n, &p)) {
        printf("FAIL %s: load\n", name);
        failures++;
        return;
    }
    int rc = espbpf_verify(&p, &env, log, sizeof(log));
    if (rc) {
        printf("FAIL %s: rejected: %s\n", name, log);
        failures++;
    } else if ((rc = espbpf_exec(&p, &env, &ctx, NULL, &ret)) != 0) {
        printf("FAIL %s: exec rc=%d\n", name, rc);
        failures++;
    } else if (ret != want) {
        printf("FAIL %s: got 0x%llx want 0x%llx\n", name,
               (unsigned long long)ret, (unsigned long long)want);
        failures++;
    }
    espbpf_prog_free(&p);
}

static void expect_reject(const char *name, const struct espbpf_insn *code,
                          uint32_t n, const struct espbpf_env *e,
                          const char *needle)
{
    struct espbpf_prog p;
    char log[200];
    total++;
    if (espbpf_load_raw(code, n, &p)) {
        printf("FAIL %s: load\n", name);
        failures++;
        return;
    }
    int rc = espbpf_verify(&p, e, log, sizeof(log));
    if (rc != ESPBPF_E_VERIFY) {
        printf("FAIL %s: accepted, expected rejection\n", name);
        failures++;
    } else if (needle && !strstr(log, needle)) {
        printf("FAIL %s: wrong reason: %s (want '%s')\n", name, log, needle);
        failures++;
    } else {
        printf("  ok  %-28s %s\n", name, log);
    }
    espbpf_prog_free(&p);
}

static void expect_fault(const char *name, const struct espbpf_insn *code,
                         uint32_t n)
{
    struct espbpf_prog p;
    char log[200];
    struct ctx8 ctx = { 7, 5 };
    uint64_t ret = 0;
    total++;
    espbpf_load_raw(code, n, &p);
    if (espbpf_verify(&p, &env, log, sizeof(log))) {
        printf("FAIL %s: rejected statically: %s\n", name, log);
        failures++;
    } else if (espbpf_exec(&p, &env, &ctx, NULL, &ret) != ESPBPF_E_FAULT) {
        printf("FAIL %s: expected run-time fault\n", name);
        failures++;
    }
    espbpf_prog_free(&p);
}

int main(void)
{
    /* ---------------- semantics ---------------- */
    {
        struct espbpf_insn c[] = { MOV64_IMM(0, 42), EXIT() };
        expect_ret("mov", c, N(c), 42);
    }
    {
        struct espbpf_insn c[] = { MOV64_IMM(0, -1), EXIT() };
        expect_ret("mov64 sign-extends imm", c, N(c), UINT64_MAX);
    }
    {
        struct espbpf_insn c[] = { MOV64_IMM(0, -1), ALU32_IMM(BPF_ADD, 0, 0), EXIT() };
        expect_ret("alu32 zero-extends", c, N(c), 0xffffffffull);
    }
    {
        struct espbpf_insn c[] = { MOV64_IMM(0, 10), MOV64_IMM(1, 0),
                                   ALU64_REG(BPF_DIV, 0, 1), EXIT() };
        expect_ret("div by zero -> 0", c, N(c), 0);
    }
    {
        struct espbpf_insn c[] = { MOV64_IMM(0, 10), MOV64_IMM(1, 0),
                                   ALU64_REG(BPF_MOD, 0, 1), EXIT() };
        expect_ret("mod by zero -> dividend", c, N(c), 10);
    }
    {
        struct espbpf_insn c[] = {
            INSN(BPF_LD | BPF_IMM | BPF_DW, 0, 0, 0, 0), INSN(0, 0, 0, 0, (int32_t)0x80000000),
            MOV64_IMM(1, -1),
            INSN(BPF_ALU64 | BPF_DIV | BPF_X, 0, 1, 1, 0),   /* sdiv INT64_MIN / -1 */
            EXIT() };
        expect_ret("sdiv overflow", c, N(c), 0x8000000000000000ull);
    }
    {
        struct espbpf_insn c[] = { MOV64_IMM(0, -20), MOV64_IMM(1, 3),
                                   INSN(BPF_ALU64 | BPF_MOD | BPF_X, 0, 1, 1, 0), EXIT() };
        expect_ret("smod", c, N(c), (uint64_t)-2);
    }
    {
        struct espbpf_insn c[] = { MOV64_IMM(0, 1), MOV64_IMM(1, 65),
                                   ALU64_REG(BPF_LSH, 0, 1), EXIT() };
        expect_ret("shift masked to 63", c, N(c), 2);
    }
    {
        struct espbpf_insn c[] = { MOV64_IMM(0, -16), ALU64_IMM(BPF_ARSH, 0, 2), EXIT() };
        expect_ret("arsh", c, N(c), (uint64_t)-4);
    }
    {
        struct espbpf_insn c[] = {
            INSN(BPF_LD | BPF_IMM | BPF_DW, 0, 0, 0, 0x55667788), INSN(0, 0, 0, 0, 0x11223344),
            EXIT() };
        expect_ret("lddw", c, N(c), 0x1122334455667788ull);
    }
    {
        struct espbpf_insn c[] = { MOV64_IMM(0, 0x1234),
                                   INSN(BPF_ALU | BPF_END | BPF_X, 0, 0, 0, 16), EXIT() };
        expect_ret("be16", c, N(c), 0x3412);
    }
    {
        struct espbpf_insn c[] = { MOV64_IMM(1, 0x80),
                                   INSN(BPF_ALU64 | BPF_MOV | BPF_X, 0, 1, 8, 0), EXIT() };
        expect_ret("movsx8", c, N(c), (uint64_t)-128);
    }
    {
        /* w1 = -1 (0xffffffff, zero-extended); unsigned 64-bit 0xffffffff > 5,
         * but signed 32-bit -1 < 5 */
        struct espbpf_insn c[] = { MOV32_IMM(1, -1), MOV64_IMM(0, 0),
                                   JMP32_IMM(BPF_JSLT, 1, 5, 1), EXIT(),
                                   MOV64_IMM(0, 1), EXIT() };
        expect_ret("jmp32 signed", c, N(c), 1);
    }
    {
        struct espbpf_insn c[] = { MOV32_IMM(1, -1), MOV64_IMM(0, 0),
                                   JMP_IMM(BPF_JSLT, 1, 5, 1), EXIT(),
                                   MOV64_IMM(0, 1), EXIT() };
        expect_ret("jmp64 on zero-extended", c, N(c), 0);
    }
    {
        /* read ctx->a + ctx->b */
        struct espbpf_insn c[] = { LDX(BPF_W, 0, 1, 0), LDX(BPF_W, 2, 1, 4),
                                   ALU64_REG(BPF_ADD, 0, 2), EXIT() };
        expect_ret("ctx read", c, N(c), 12);
    }
    {
        /* stack store/load through a copied frame pointer */
        struct espbpf_insn c[] = { MOV64_REG(2, 10), ALU64_IMM(BPF_ADD, 2, -8),
                                   ST_IMM(BPF_DW, 2, 0, 1234), LDX(BPF_DW, 0, 10, -8), EXIT() };
        expect_ret("stack via copy", c, N(c), 1234);
    }
    {
        struct espbpf_insn c[] = { MOV64_IMM(1, 40), MOV64_IMM(2, 2), CALL(1), EXIT() };
        expect_ret("helper call", c, N(c), 42);
    }
    {
        /* sum 3 bytes stored on the stack via helper pointer argument */
        struct espbpf_insn c[] = { ST_IMM(BPF_B, 10, -3, 1), ST_IMM(BPF_B, 10, -2, 2),
                                   ST_IMM(BPF_B, 10, -1, 3), MOV64_REG(1, 10),
                                   ALU64_IMM(BPF_ADD, 1, -3), MOV64_IMM(2, 3), CALL(2), EXIT() };
        expect_ret("helper ptr arg", c, N(c), 6);
    }
    {
        /* helper gets a size that runs past the stack top -> helper sees NULL */
        struct espbpf_insn c[] = { MOV64_REG(1, 10), ALU64_IMM(BPF_ADD, 1, -3),
                                   MOV64_IMM(2, 100), CALL(2), EXIT() };
        expect_ret("helper rejects oob size", c, N(c), UINT64_MAX);
    }
    {
        /* both branches initialise r0 -> merge ok */
        struct espbpf_insn c[] = { LDX(BPF_W, 2, 1, 0), JMP_IMM(BPF_JGT, 2, 3, 2),
                                   MOV64_IMM(0, 1), JA(1), MOV64_IMM(0, 2), EXIT() };
        expect_ret("diamond merge", c, N(c), 2);
    }

    /* ---------------- verifier rejections ---------------- */
    printf("verifier rejections:\n");
    {
        struct espbpf_insn c[] = { MOV64_IMM(0, 0), JA(-2), EXIT() };
        expect_reject("back-edge", c, N(c), &env, "back-edge");
    }
    {
        struct espbpf_insn c[] = { MOV64_IMM(0, 0), JA(-1) };
        expect_reject("self loop", c, N(c), &env, "back-edge");
    }
    {
        struct espbpf_insn c[] = { EXIT() };
        expect_reject("uninit r0", c, N(c), &env, "r0 is not initialised");
    }
    {
        struct espbpf_insn c[] = { LDX(BPF_W, 2, 1, 0), JMP_IMM(BPF_JEQ, 2, 0, 1),
                                   MOV64_IMM(0, 1), EXIT() };
        expect_reject("uninit on one path", c, N(c), &env, "every path");
    }
    {
        struct espbpf_insn c[] = { MOV64_IMM(0, 0) };
        expect_reject("fall off end", c, N(c), &env, "fall off");
    }
    {
        struct espbpf_insn c[] = { MOV64_IMM(10, 0), EXIT() };
        expect_reject("write r10", c, N(c), &env, "read only");
    }
    {
        struct espbpf_insn c[] = { MOV64_IMM(0, 0), LDX(BPF_DW, 0, 10, -520), EXIT() };
        expect_reject("stack below limit", c, N(c), &env, "out of bounds");
    }
    {
        struct espbpf_insn c[] = { MOV64_IMM(0, 0), LDX(BPF_DW, 0, 10, -4), EXIT() };
        expect_reject("stack above fp", c, N(c), &env, "out of bounds");
    }
    {
        struct espbpf_insn c[] = { LDX(BPF_W, 0, 1, 6), EXIT() };
        expect_reject("ctx out of bounds", c, N(c), &env, "out of bounds");
    }
    {
        struct espbpf_insn c[] = { ST_IMM(BPF_W, 1, 0, 1), MOV64_IMM(0, 0), EXIT() };
        expect_reject("ctx read only", c, N(c), &env, "read only");
    }
    {
        struct espbpf_insn c[] = { MOV64_IMM(2, 0x1000), LDX(BPF_W, 0, 2, 0), EXIT() };
        expect_reject("scalar deref", c, N(c), &env, "scalar");
    }
    {
        struct espbpf_insn c[] = { LDX(BPF_DW, 2, 10, -8), LDX(BPF_W, 0, 2, 0), EXIT() };
        expect_reject("pointer from memory", c, N(c), &env, "scalar");
    }
    {
        struct espbpf_insn c[] = { LDX(BPF_W, 3, 1, 0), MOV64_IMM(2, 0),
                                   JMP_IMM(BPF_JEQ, 3, 0, 1), MOV64_REG(2, 10),
                                   LDX(BPF_B, 0, 2, -1), EXIT() };
        expect_reject("mixed ptr/scalar", c, N(c), &env, "pointer on one path");
    }
    {
        struct espbpf_insn c[] = { MOV64_IMM(0, 0), JMP_IMM(BPF_JEQ, 0, 0, 1),
                                   INSN(BPF_LD | BPF_IMM | BPF_DW, 0, 0, 0, 1),
                                   INSN(0, 0, 0, 0, 0), EXIT() };
        expect_reject("jump into lddw", c, N(c), &env, "middle of lddw");
    }
    {
        struct espbpf_insn c[] = { MOV64_IMM(0, 0), EXIT(), MOV64_IMM(0, 1), EXIT() };
        expect_reject("unreachable", c, N(c), &env, "unreachable");
    }
    {
        struct espbpf_insn c[] = { CALL(77), EXIT() };
        expect_reject("unknown helper", c, N(c), &env, "unknown helper");
    }
    {
        struct espbpf_insn c[] = { MOV64_IMM(1, 0x1000), MOV64_IMM(2, 4), CALL(2), EXIT() };
        expect_reject("scalar as ptr arg", c, N(c), &env, "must be a pointer");
    }
    {
        struct espbpf_insn c[] = { MOV64_REG(1, 10), MOV64_IMM(2, 1), CALL(1), EXIT() };
        expect_reject("ptr as scalar arg", c, N(c), &env, "must be a scalar");
    }
    {
        struct espbpf_insn c[] = { MOV64_IMM(1, 1), MOV64_IMM(2, 2), CALL(1),
                                   ALU64_REG(BPF_ADD, 0, 1), EXIT() };
        expect_reject("r1 clobbered by call", c, N(c), &env, "r1 is not initialised");
    }
    {
        struct espbpf_insn c[] = { MOV64_IMM(0, 1), ALU64_IMM(BPF_DIV, 0, 0), EXIT() };
        expect_reject("div by const zero", c, N(c), &env, "division by zero");
    }
    {
        struct espbpf_insn c[] = { INSN(0xff, 0, 0, 0, 0), EXIT() };
        expect_reject("bad opcode", c, N(c), &env, NULL);
    }
    {
        struct espbpf_insn c[] = { INSN(BPF_STX | 0xc0 | BPF_DW, 10, 1, -8, 0),
                                   MOV64_IMM(0, 0), EXIT() };
        expect_reject("atomic", c, N(c), &env, "atomic");
    }
    {
        struct espbpf_insn c[] = { MOV64_IMM(0, 0), JMP_IMM(BPF_JEQ, 0, 0, 5), EXIT() };
        expect_reject("jump out of range", c, N(c), &env, "out of range");
    }
    {
        struct espbpf_insn c[] = { ST_IMM(BPF_W, 1, 0, 1), MOV64_IMM(0, 0), EXIT() };
        struct espbpf_prog p;
        char log[200];
        struct ctx8 ctx = { 0, 0 };
        uint64_t r;
        total++;
        espbpf_load_raw(c, N(c), &p);
        if (espbpf_verify(&p, &env_rw, log, sizeof(log)) ||
            espbpf_exec(&p, &env_rw, &ctx, NULL, &r) || ctx.a != 1) {
            printf("FAIL writable ctx: %s\n", log);
            failures++;
        }
        espbpf_prog_free(&p);
    }

    {
        /* i = ctx->a & 7; *(fp - 8 + i) : provable, no run-time check */
        struct espbpf_insn c[] = { LDX(BPF_W, 3, 1, 0), ALU64_IMM(BPF_AND, 3, 7),
                                   MOV64_REG(2, 10), ALU64_IMM(BPF_ADD, 2, -8),
                                   ALU64_REG(BPF_ADD, 2, 3), ST_IMM(BPF_B, 2, 0, 5),
                                   LDX(BPF_B, 0, 10, -1), EXIT() };
        expect_ret("masked index is bounded", c, N(c), 5);
    }
    {
        /* same, but the mask allows 0..65535: statically out of bounds */
        struct espbpf_insn c[] = { LDX(BPF_W, 3, 1, 0), ALU64_IMM(BPF_AND, 3, 0xffff),
                                   MOV64_REG(2, 10), ALU64_IMM(BPF_ADD, 2, -8),
                                   ALU64_REG(BPF_ADD, 2, 3), LDX(BPF_B, 0, 2, 0), EXIT() };
        expect_reject("unmasked index rejected", c, N(c), &env, "out of bounds");
    }
    {
        /* if (i <= 7) { *(fp - 8 + i) } : the compare bounds i */
        struct espbpf_insn c[] = { LDX(BPF_W, 3, 1, 0), MOV64_IMM(0, 0),
                                   JMP_IMM(BPF_JGT, 3, 7, 4),
                                   MOV64_REG(2, 10), ALU64_IMM(BPF_ADD, 2, -8),
                                   ALU64_REG(BPF_ADD, 2, 3), LDX(BPF_B, 0, 2, 0),
                                   EXIT() };
        expect_ret("compare bounds the index", c, N(c), 0);
    }
    {
        /* a byte load is 0..255, still too wide for a 512-byte stack at -8 */
        struct espbpf_insn c[] = { LDX(BPF_B, 3, 1, 0), MOV64_REG(2, 10),
                                   ALU64_IMM(BPF_ADD, 2, -8), ALU64_REG(BPF_ADD, 2, 3),
                                   LDX(BPF_B, 0, 2, 0), EXIT() };
        expect_reject("byte-wide index still too wide", c, N(c), &env, "out of bounds");
    }
    {
        /* n % 8 is 0..7 */
        struct espbpf_insn c[] = { LDX(BPF_W, 3, 1, 0), ALU64_IMM(BPF_MOD, 3, 8),
                                   MOV64_REG(2, 10), ALU64_IMM(BPF_ADD, 2, -8),
                                   ALU64_REG(BPF_ADD, 2, 3), ST_IMM(BPF_B, 2, 0, 9),
                                   LDX(BPF_B, 0, 10, -1), EXIT() };
        expect_ret("modulo is bounded", c, N(c), 9);
    }
    /* ---------------- run-time bounds (unknown offsets) ---------------- */
    {
        /* clang idiom: ptr |= small scalar (see comfort_leds.c) */
        struct espbpf_insn c[] = { LDX(BPF_W, 3, 1, 4), ALU64_IMM(BPF_AND, 3, 3),
                                   MOV64_REG(2, 10), ALU64_IMM(BPF_ADD, 2, -8),
                                   ALU64_REG(BPF_OR, 2, 3), ST_IMM(BPF_B, 2, 0, 77),
                                   LDX(BPF_B, 0, 10, -7), EXIT() };
        expect_ret("ptr |= scalar", c, N(c), 77);
    }
    {
        /* ...but OR-ing an absolute address into a pointer is now provably
         * out of bounds, so the verifier rejects it without running it */
        struct espbpf_insn c[] = { MOV64_REG(2, 10), MOV64_IMM(3, 0x7ff00000),
                                   ALU64_REG(BPF_OR, 2, 3), LDX(BPF_B, 0, 2, 0), EXIT() };
        expect_reject("ptr |= address", c, N(c), &env, "out of bounds");
    }
    {
        /* r2 = fp + ctx->a*100 (unknown offset); load -> must fault, not read */
        struct espbpf_insn c[] = { LDX(BPF_W, 3, 1, 0), ALU64_IMM(BPF_MUL, 3, 100),
                                   MOV64_REG(2, 10), ALU64_REG(BPF_ADD, 2, 3),
                                   LDX(BPF_DW, 0, 2, 0), EXIT() };
        expect_fault("runtime oob above stack", c, N(c));
    }
    {
        struct espbpf_insn c[] = { LDX(BPF_W, 3, 1, 0), ALU64_IMM(BPF_MUL, 3, 1000),
                                   MOV64_REG(2, 10), ALU64_REG(BPF_SUB, 2, 3),
                                   ST_IMM(BPF_B, 2, 0, 0x41), MOV64_IMM(0, 0), EXIT() };
        expect_fault("runtime oob write below", c, N(c));
    }
    {
        /* same pattern, in bounds: fp - ctx->a (7) */
        struct espbpf_insn c[] = { LDX(BPF_W, 3, 1, 0), MOV64_REG(2, 10),
                                   ALU64_REG(BPF_SUB, 2, 3), ST_IMM(BPF_B, 2, 0, 9),
                                   LDX(BPF_B, 0, 10, -7), EXIT() };
        expect_ret("runtime in-bounds index", c, N(c), 9);
    }

    printf("\n%d/%d tests passed\n", total - failures, total);
    return failures ? 1 : 0;
}
