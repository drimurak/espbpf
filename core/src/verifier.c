/* SPDX-License-Identifier: MIT
 *
 * Static verifier.
 *
 * Pass 1 (structural): every instruction is a known opcode with valid
 * fields, registers are in range, r10 is never written, jumps are forward
 * only and land on an instruction boundary, helpers exist.
 *
 * Because all jumps go forward, the control-flow graph is a DAG whose
 * topological order is simply the instruction order. That makes pass 2 a
 * single linear sweep, which is cheap enough for a microcontroller:
 *
 * Pass 2 (abstract interpretation): track the type of every register
 * (uninitialised / scalar / pointer to ctx, stack or rodata, with a known
 * or unknown offset). At join points the incoming states are merged, so a
 * register is usable only if it is valid on *every* path. Memory accesses
 * through known-offset pointers are range checked statically; accesses
 * through pointers with an unknown offset are allowed and caught by the
 * interpreter's run-time bounds checks. Dereferencing a scalar is always
 * rejected.
 *
 * Memory cost: 44 bytes per jump target plus 2 bytes per instruction.
 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "espbpf.h"
#include "opcodes.h"

enum rtype {
    T_UNINIT = 0,
    T_SCALAR,
    T_PTR_CTX,
    T_PTR_STACK,
    T_PTR_RODATA,
    T_MIXED,          /* scalar on one path, pointer on another */
};

static const char *const rtype_name[] = {
    "uninit", "scalar", "ctx", "fp", "rodata", "mixed",
};

/* Value range tracking (like bpf_reg_state's umin/umax in the kernel, but
 * clamped to 32 bits to keep a state small enough for a microcontroller).
 *
 * For a scalar, [lo, hi] bounds the value; for a pointer, it bounds the
 * offset from the start of the region. RLO/RHI mean "could be anything".
 * A pointer offset is exact when lo == hi. */
#define RLO INT32_MIN
#define RHI INT32_MAX

struct reg {
    uint8_t type;
    uint8_t pad;
    int32_t lo, hi;
};

static bool r_unknown(const struct reg *r)
{
    return r->lo == RLO || r->hi == RHI;
}

/* Saturating helpers: anything that leaves the tracked range becomes
 * "unknown" rather than wrapping, so a bound is never claimed wrongly. */
static int64_t clamp64(int64_t v)
{
    return v < RLO ? RLO : v > RHI ? RHI : v;
}

static struct reg r_range(int64_t lo, int64_t hi)
{
    if (lo < RLO || hi > RHI || lo > hi)
        return (struct reg){ T_SCALAR, 0, RLO, RHI };
    return (struct reg){ T_SCALAR, 0, (int32_t)lo, (int32_t)hi };
}

static struct reg r_const(int64_t v)
{
    return r_range(v, v);
}

static const struct reg R_ANY = { T_SCALAR, 0, RLO, RHI };

struct vstate {
    struct reg r[11];
};

#define NO_SLOT 0xffff

struct verifier {
    struct espbpf_prog      *prog;
    const struct espbpf_env *env;
    char                    *log;
    size_t                   log_len;
    uint16_t                *slot;      /* per insn: index into states, or NO_SLOT */
    struct vstate           *states;    /* pending state at each jump target */
    uint8_t                 *have;      /* states[i] holds a merged state */
    uint8_t                 *is_tail;   /* second half of LD_IMM64 */
    uint32_t                 static_checks;   /* accesses proven statically */
    uint32_t                 dynamic_checks;  /* left to the interpreter */
};

static int fail(struct verifier *v, uint32_t pc, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static int fail(struct verifier *v, uint32_t pc, const char *fmt, ...)
{
    if (v->log && v->log_len) {
        char dis[64] = "";
        if (pc < v->prog->n_insns)
            espbpf_disasm(v->prog->insns, v->prog->n_insns, pc, dis, sizeof(dis));
        int n = snprintf(v->log, v->log_len, "pc %u: %s: ", (unsigned)pc, dis);
        if (n >= 0 && (size_t)n < v->log_len) {
            va_list ap;
            va_start(ap, fmt);
            vsnprintf(v->log + n, v->log_len - (size_t)n, fmt, ap);
            va_end(ap);
        }
    }
    return ESPBPF_E_VERIFY;
}

static bool is_ptr(uint8_t t)
{
    return t == T_PTR_CTX || t == T_PTR_STACK || t == T_PTR_RODATA;
}

static const struct espbpf_helper *helper_by_id(const struct espbpf_env *env,
                                                int32_t id)
{
    for (size_t i = 0; i < env->n_helpers; i++)
        if ((int32_t)env->helpers[i].id == id)
            return &env->helpers[i];
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Pass 1: structure                                                   */
/* ------------------------------------------------------------------ */

static int check_alu(struct verifier *v, uint32_t pc,
                     const struct espbpf_insn *in)
{
    bool is64 = BPF_CLASS(in->code) == BPF_ALU64;
    uint8_t op = BPF_OP(in->code);
    bool x = BPF_SRC(in->code) == BPF_X;

    if (in->dst == BPF_REG_FP)
        return fail(v, pc, "frame pointer is read only");
    if (in->dst > 10 || in->src > 10)
        return fail(v, pc, "invalid register");

    switch (op) {
    case BPF_END:
        if (in->src || in->off)
            return fail(v, pc, "reserved fields must be zero");
        if (is64 && x)
            return fail(v, pc, "invalid bswap opcode");
        if (in->imm != 16 && in->imm != 32 && in->imm != 64)
            return fail(v, pc, "invalid byteswap width %d", (int)in->imm);
        return ESPBPF_OK;
    case BPF_NEG:
        if (x || in->src || in->off || in->imm)
            return fail(v, pc, "invalid neg");
        return ESPBPF_OK;
    case BPF_MOV:
        if (!x && in->off)
            return fail(v, pc, "invalid mov offset");
        if (x && in->off && in->off != 8 && in->off != 16 &&
            !(is64 && in->off == 32))
            return fail(v, pc, "invalid movsx width %d", in->off);
        break;
    case BPF_DIV:
    case BPF_MOD:
        if (in->off != 0 && in->off != 1)
            return fail(v, pc, "invalid div/mod offset");
        if (!x && in->imm == 0)
            return fail(v, pc, "division by zero");
        break;
    case BPF_LSH:
    case BPF_RSH:
    case BPF_ARSH:
        if (!x && (in->imm < 0 || in->imm >= (is64 ? 64 : 32)))
            return fail(v, pc, "invalid shift %d", (int)in->imm);
        /* fallthrough */
    case BPF_ADD: case BPF_SUB: case BPF_MUL:
    case BPF_OR:  case BPF_AND: case BPF_XOR:
        if (in->off)
            return fail(v, pc, "reserved off must be zero");
        break;
    default:
        return fail(v, pc, "unknown arithmetic opcode 0x%02x", in->code);
    }
    if (x ? in->imm != 0 : in->src != 0)
        return fail(v, pc, "reserved fields must be zero");
    return ESPBPF_OK;
}

static int check_jmp(struct verifier *v, uint32_t pc,
                     const struct espbpf_insn *in)
{
    const uint32_t n = v->prog->n_insns;
    bool j32 = BPF_CLASS(in->code) == BPF_JMP32;
    uint8_t op = BPF_OP(in->code);
    int64_t rel;

    switch (op) {
    case BPF_EXIT:
        if (j32 || in->code != (BPF_JMP | BPF_EXIT) || in->dst || in->src ||
            in->off || in->imm)
            return fail(v, pc, "invalid exit");
        return ESPBPF_OK;
    case BPF_CALL:
        if (j32 || BPF_SRC(in->code) != BPF_K || in->dst || in->off)
            return fail(v, pc, "invalid call");
        if (in->src == 1)
            return fail(v, pc, "bpf-to-bpf calls are not supported "
                               "(mark functions static inline)");
        if (in->src != 0)
            return fail(v, pc, "invalid call type %u", in->src);
        if (!helper_by_id(v->env, in->imm))
            return fail(v, pc, "unknown helper %d", (int)in->imm);
        return ESPBPF_OK;
    case BPF_JA:
        if (BPF_SRC(in->code) != BPF_K || in->dst || in->src)
            return fail(v, pc, "invalid ja");
        if (j32 ? in->off != 0 : in->imm != 0)
            return fail(v, pc, "reserved fields must be zero");
        rel = j32 ? in->imm : in->off;
        break;
    case BPF_JEQ: case BPF_JGT: case BPF_JGE: case BPF_JSET:
    case BPF_JNE: case BPF_JSGT: case BPF_JSGE:
    case BPF_JLT: case BPF_JLE: case BPF_JSLT: case BPF_JSLE:
        if (in->dst > 10 || in->src > 10)
            return fail(v, pc, "invalid register");
        if (BPF_SRC(in->code) == BPF_X ? in->imm != 0 : in->src != 0)
            return fail(v, pc, "reserved fields must be zero");
        rel = in->off;
        break;
    default:
        return fail(v, pc, "unknown jump opcode 0x%02x", in->code);
    }

    if (rel < 0)
        return fail(v, pc, "back-edge: loops are not allowed");
    int64_t target = (int64_t)pc + 1 + rel;
    if (target >= n)
        return fail(v, pc, "jump out of range");
    return ESPBPF_OK;
}

static int check_mem_insn(struct verifier *v, uint32_t pc,
                          const struct espbpf_insn *in)
{
    uint8_t cls = BPF_CLASS(in->code);
    uint8_t mode = BPF_MODE(in->code);

    if (in->dst > 10 || in->src > 10)
        return fail(v, pc, "invalid register");

    switch (cls) {
    case BPF_LDX:
        if (mode != BPF_MEM && mode != BPF_MEMSX)
            return fail(v, pc, "unsupported load mode 0x%02x", mode);
        if (mode == BPF_MEMSX && BPF_SIZE(in->code) == BPF_DW)
            return fail(v, pc, "invalid sign-extending load");
        if (in->dst == BPF_REG_FP)
            return fail(v, pc, "frame pointer is read only");
        if (in->imm)
            return fail(v, pc, "reserved fields must be zero");
        return ESPBPF_OK;
    case BPF_ST:
        if (mode != BPF_MEM || in->src)
            return fail(v, pc, "invalid store");
        return ESPBPF_OK;
    case BPF_STX:
        if (mode == 0xc0)
            return fail(v, pc, "atomic operations are not supported");
        if (mode != BPF_MEM || in->imm)
            return fail(v, pc, "invalid store");
        return ESPBPF_OK;
    default: /* BPF_LD */
        if (in->code != (BPF_LD | BPF_IMM | BPF_DW))
            return fail(v, pc, "legacy packet access is not supported");
        if (in->dst == BPF_REG_FP)
            return fail(v, pc, "frame pointer is read only");
        if (in->off)
            return fail(v, pc, "reserved fields must be zero");
        if (pc + 1 >= v->prog->n_insns)
            return fail(v, pc, "truncated lddw");
        {
            const struct espbpf_insn *t = &v->prog->insns[pc + 1];
            if (t->code || t->dst || t->src || t->off)
                return fail(v, pc, "invalid lddw second half");
            if (in->src == ESPBPF_PSEUDO_RODATA) {
                if (t->imm || (uint32_t)in->imm >= v->prog->rodata_len)
                    return fail(v, pc, "rodata offset out of range");
            } else if (in->src != ESPBPF_PSEUDO_NONE) {
                return fail(v, pc, "maps/pseudo lddw type %u not supported",
                            in->src);
            }
        }
        v->is_tail[pc + 1] = 1;
        return ESPBPF_OK;
    }
}

static int pass1(struct verifier *v, uint32_t *n_targets)
{
    const uint32_t n = v->prog->n_insns;
    const struct espbpf_insn *code = v->prog->insns;
    uint32_t targets = 0;

    for (uint32_t pc = 0; pc < n; pc++) {
        const struct espbpf_insn *in = &code[pc];
        int rc;
        switch (BPF_CLASS(in->code)) {
        case BPF_ALU:
        case BPF_ALU64:
            rc = check_alu(v, pc, in);
            break;
        case BPF_JMP:
        case BPF_JMP32:
            rc = check_jmp(v, pc, in);
            if (rc == ESPBPF_OK && BPF_OP(in->code) != BPF_EXIT &&
                BPF_OP(in->code) != BPF_CALL) {
                uint32_t t = pc + 1 + (uint32_t)(BPF_CLASS(in->code) == BPF_JMP32 &&
                                                         BPF_OP(in->code) == BPF_JA
                                                     ? in->imm : in->off);
                if (v->slot[t] == NO_SLOT)
                    v->slot[t] = (uint16_t)targets++;
            }
            break;
        default:
            rc = check_mem_insn(v, pc, in);
            if (rc == ESPBPF_OK && BPF_CLASS(in->code) == BPF_LD)
                pc++;   /* skip the second half */
            break;
        }
        if (rc)
            return rc;
    }

    for (uint32_t pc = 0; pc < n; pc++)
        if (v->is_tail[pc] && v->slot[pc] != NO_SLOT)
            return fail(v, pc, "jump into the middle of lddw");

    *n_targets = targets;
    return ESPBPF_OK;
}

/* ------------------------------------------------------------------ */
/* Pass 2: types                                                       */
/* ------------------------------------------------------------------ */

static void merge(struct vstate *into, const struct vstate *from)
{
    for (int i = 0; i < 11; i++) {
        struct reg *a = &into->r[i];
        const struct reg *b = &from->r[i];
        if (a->type == b->type) {
            /* union of the two ranges */
            if (b->lo < a->lo)
                a->lo = b->lo;
            if (b->hi > a->hi)
                a->hi = b->hi;
        } else if (a->type == T_UNINIT || b->type == T_UNINIT) {
            *a = (struct reg){ T_UNINIT, 0, 0, 0 };
        } else {
            *a = (struct reg){ T_MIXED, 0, 0, 0 };
        }
    }
}

static void propagate(struct verifier *v, uint32_t target,
                      const struct vstate *st)
{
    uint16_t s = v->slot[target];
    if (!v->have[s]) {
        v->states[s] = *st;
        v->have[s] = 1;
    } else {
        merge(&v->states[s], st);
    }
}

static int need_value(struct verifier *v, uint32_t pc, const struct vstate *st,
                      unsigned r)
{
    if (st->r[r].type == T_UNINIT)
        return fail(v, pc, "r%u is not initialised on every path", r);
    if (st->r[r].type == T_MIXED)
        return fail(v, pc, "r%u is a pointer on one path and a scalar on another", r);
    return ESPBPF_OK;
}

/* [lo,hi] += delta, saturating to "unknown". */
static void add_off(struct reg *r, int64_t delta)
{
    if (r_unknown(r))
        return;
    int64_t lo = (int64_t)r->lo + delta, hi = (int64_t)r->hi + delta;
    if (lo < RLO || hi > RHI) {
        r->lo = RLO;
        r->hi = RHI;
    } else {
        r->lo = (int32_t)lo;
        r->hi = (int32_t)hi;
    }
}

/* Narrow `r` so that it satisfies `r <op> imm`; used on both sides of a
 * conditional jump. Unsigned comparisons only narrow non-negative ranges. */
static void refine(struct reg *r, uint8_t op, int64_t imm, bool taken)
{
    if (r->type != T_SCALAR || r_unknown(r))
        return;
    bool uns = op == BPF_JGT || op == BPF_JGE || op == BPF_JLT || op == BPF_JLE;
    if (uns && (r->lo < 0 || imm < 0))
        return;
    int64_t lo = r->lo, hi = r->hi;

    switch (op) {
    case BPF_JEQ:
        if (taken) lo = hi = imm;
        break;
    case BPF_JNE:
        if (!taken) lo = hi = imm;
        break;
    case BPF_JSGT: case BPF_JGT:
        if (taken) lo = lo > imm + 1 ? lo : imm + 1;
        else       hi = hi < imm ? hi : imm;
        break;
    case BPF_JSGE: case BPF_JGE:
        if (taken) lo = lo > imm ? lo : imm;
        else       hi = hi < imm - 1 ? hi : imm - 1;
        break;
    case BPF_JSLT: case BPF_JLT:
        if (taken) hi = hi < imm - 1 ? hi : imm - 1;
        else       lo = lo > imm ? lo : imm;
        break;
    case BPF_JSLE: case BPF_JLE:
        if (taken) hi = hi < imm ? hi : imm;
        else       lo = lo > imm + 1 ? lo : imm + 1;
        break;
    default:
        return;         /* JSET: no useful bound */
    }
    if (lo > hi)        /* branch is impossible; keep the state harmless */
        return;
    r->lo = (int32_t)clamp64(lo);
    r->hi = (int32_t)clamp64(hi);
}

static int check_access(struct verifier *v, uint32_t pc, const struct vstate *st,
                        unsigned base, int16_t off, unsigned size, bool write)
{
    const struct reg *r = &st->r[base];
    int rc = need_value(v, pc, st, base);
    if (rc)
        return rc;

    int64_t lo, hi;   /* allowed [lo, hi) relative to the region pointer */
    switch (r->type) {
    case T_PTR_CTX:
        if (!v->env->ctx_size)
            return fail(v, pc, "this hook has no context");
        if (write && !v->env->ctx_writable)
            return fail(v, pc, "context is read only");
        lo = 0;
        hi = v->env->ctx_size;
        break;
    case T_PTR_STACK:
        lo = -(int64_t)ESPBPF_STACK_SIZE;
        hi = 0;
        break;
    case T_PTR_RODATA:
        if (write)
            return fail(v, pc, "rodata is read only");
        lo = 0;
        hi = v->prog->rodata_len;
        break;
    default:
        return fail(v, pc, "r%u is a scalar, not a pointer: invalid memory access",
                    base);
    }
    if (r_unknown(r)) {
        /* No bound could be derived (e.g. `ptr |= scalar`). The access is
         * still safe: the interpreter range-checks every load and store. */
        v->dynamic_checks++;
        return ESPBPF_OK;
    }

    int64_t olo = (int64_t)r->lo + off, ohi = (int64_t)r->hi + off;
    if (olo < lo || ohi + (int64_t)size > hi) {
        if (olo == ohi)
            return fail(v, pc, "%s access at offset %lld size %u out of bounds [%lld, %lld)",
                        rtype_name[r->type], (long long)olo, size,
                        (long long)lo, (long long)hi);
        return fail(v, pc, "%s access at offset %lld..%lld size %u out of bounds [%lld, %lld)",
                    rtype_name[r->type], (long long)olo, (long long)ohi, size,
                    (long long)lo, (long long)hi);
    }
    v->static_checks++;     /* proven in the verifier, no run-time check needed */
    return ESPBPF_OK;
}

/* Range transfer function for arithmetic on scalars. Returns the new
 * register state; anything not modelled becomes an unbounded scalar. */
static struct reg alu_range(uint8_t op, bool is64, bool x, const struct reg *d,
                            const struct reg *s, int32_t imm)
{
    int64_t dlo = d->lo, dhi = d->hi;
    int64_t slo = x ? s->lo : imm, shi = x ? s->hi : imm;
    bool src_known = x ? !r_unknown(s) : true;
    bool known = !r_unknown(d) && src_known;
    struct reg out = R_ANY;

    /* AND and MOD bound the result no matter what went in, which is how
     * `buf[i & 7]` and `buf[i % 8]` become provable. */
    if (src_known && slo == shi && slo >= 0) {
        if (op == BPF_AND)
            return is64 || slo <= INT32_MAX ? r_range(0, slo) : R_ANY;
        if (op == BPF_MOD && slo > 0 && (is64 || dlo >= 0))
            return r_range(0, slo - 1);
    }
    if (!known)
        return out;

    switch (op) {
    case BPF_ADD: out = r_range(dlo + slo, dhi + shi); break;
    case BPF_SUB: out = r_range(dlo - shi, dhi - slo); break;
    case BPF_NEG: out = r_range(-dhi, -dlo); break;
    case BPF_MUL:
        if (dlo >= 0 && slo >= 0)
            out = r_range(dlo * slo, dhi * shi);
        break;
    case BPF_AND:              /* the classic `i & 7` */
        if (slo >= 0 && slo == shi)
            out = r_range(0, shi);
        else if (dlo >= 0 && slo >= 0)
            out = r_range(0, dhi < shi ? dhi : shi);
        break;
    case BPF_OR:
        if (dlo >= 0 && slo >= 0)
            out = r_range(0, dhi + shi);
        break;
    case BPF_MOD:
        if (dlo >= 0 && slo > 0)
            out = r_range(0, shi - 1);
        break;
    case BPF_DIV:
        if (dlo >= 0 && slo > 0)
            out = r_range(dlo / shi, dhi / slo);
        break;
    case BPF_RSH:
        if (dlo >= 0 && slo >= 0 && shi < 63)
            out = r_range(dlo >> shi, dhi >> slo);
        break;
    case BPF_LSH:
        if (dlo >= 0 && slo >= 0 && shi < 31)
            out = r_range(dlo << slo, dhi << shi);
        break;
    default:
        break;
    }
    /* 32-bit ALU zero-extends its result, so a value that could go negative
     * or overflow 32 bits is no longer bounded by what we computed. */
    if (!is64 && (out.lo < 0 || r_unknown(&out)))
        return R_ANY;
    return out;
}

static int step_alu(struct verifier *v, uint32_t pc, struct vstate *st,
                    const struct espbpf_insn *in)
{
    bool is64 = BPF_CLASS(in->code) == BPF_ALU64;
    bool x = BPF_SRC(in->code) == BPF_X;
    uint8_t op = BPF_OP(in->code);
    struct reg *d = &st->r[in->dst];
    const struct reg s = st->r[in->src];
    int rc;

    if (x && (rc = need_value(v, pc, st, in->src)))
        return rc;
    if (op != BPF_MOV && (rc = need_value(v, pc, st, in->dst)))
        return rc;

    if (op == BPF_MOV) {
        if (x && in->off)                       /* sign-extending mov */
            *d = R_ANY;
        else if (x && is64)
            *d = s;
        else if (x)
            *d = s.type == T_SCALAR && s.lo >= 0 ? s : R_ANY;
        else
            *d = is64 ? r_const(in->imm) : r_const((uint32_t)in->imm);
        return ESPBPF_OK;
    }

    if (is64 && (op == BPF_ADD || op == BPF_SUB)) {
        if (is_ptr(d->type) && !x) {
            add_off(d, op == BPF_ADD ? (int64_t)in->imm : -(int64_t)in->imm);
            return ESPBPF_OK;
        }
        if (is_ptr(d->type) && s.type == T_SCALAR) {
            /* ptr +- scalar: the offset range grows by the scalar's range,
             * which is what makes `buf[i]` provable when i is bounded. */
            if (r_unknown(&s) || r_unknown(d)) {
                d->lo = RLO;
                d->hi = RHI;
            } else if (op == BPF_ADD) {
                struct reg n = r_range((int64_t)d->lo + s.lo, (int64_t)d->hi + s.hi);
                d->lo = n.lo;
                d->hi = n.hi;
            } else {
                struct reg n = r_range((int64_t)d->lo - s.hi, (int64_t)d->hi - s.lo);
                d->lo = n.lo;
                d->hi = n.hi;
            }
            return ESPBPF_OK;
        }
        if (op == BPF_ADD && d->type == T_SCALAR && is_ptr(s.type)) {
            struct reg p = s;                   /* scalar + ptr */
            if (r_unknown(&p) || r_unknown(d)) {
                p.lo = RLO;
                p.hi = RHI;
            } else {
                struct reg n = r_range((int64_t)p.lo + d->lo, (int64_t)p.hi + d->hi);
                p.lo = n.lo;
                p.hi = n.hi;
            }
            *d = p;
            return ESPBPF_OK;
        }
    }
    /* clang turns `fp_aligned + small` into `ptr |= small` when it knows the
     * low bits are zero. The Linux verifier rejects that; here the offset
     * simply grows by at most the scalar's upper bound. */
    if (is64 && op == BPF_OR && x && is_ptr(d->type) && s.type == T_SCALAR) {
        if (r_unknown(&s) || r_unknown(d) || s.lo < 0) {
            d->lo = RLO;
            d->hi = RHI;
        } else {
            struct reg n = r_range(d->lo, (int64_t)d->hi + s.hi);
            d->lo = n.lo;
            d->hi = n.hi;
        }
        return ESPBPF_OK;
    }

    /* Anything else produces a plain number. Converting a pointer to a
     * scalar is harmless: scalars can never be dereferenced. */
    if (d->type == T_SCALAR && (!x || s.type == T_SCALAR))
        *d = alu_range(op, is64, x, d, &s, in->imm);
    else
        *d = R_ANY;
    return ESPBPF_OK;
}

static int step_call(struct verifier *v, uint32_t pc, struct vstate *st,
                     const struct espbpf_insn *in)
{
    const struct espbpf_helper *h = helper_by_id(v->env, in->imm);
    for (unsigned i = 0; i < 5; i++) {
        unsigned r = i + 1;
        int rc;
        switch (h->args[i]) {
        case ESPBPF_ARG_NONE:
            continue;
        case ESPBPF_ARG_ANY:
            if ((rc = need_value(v, pc, st, r)))
                return rc;
            break;
        case ESPBPF_ARG_SCALAR:
        case ESPBPF_ARG_SIZE:
            if ((rc = need_value(v, pc, st, r)))
                return rc;
            if (st->r[r].type != T_SCALAR)
                return fail(v, pc, "%s: arg%u must be a scalar", h->name, r);
            break;
        case ESPBPF_ARG_PTR_MEM:
            if ((rc = need_value(v, pc, st, r)))
                return rc;
            if (!is_ptr(st->r[r].type))
                return fail(v, pc, "%s: arg%u must be a pointer", h->name, r);
            break;
        }
    }
    for (unsigned r = 1; r <= 5; r++)
        st->r[r] = (struct reg){ T_UNINIT, 0, 0, 0 };
    st->r[0] = R_ANY;
    return ESPBPF_OK;
}

static int pass2(struct verifier *v)
{
    const uint32_t n = v->prog->n_insns;
    const struct espbpf_insn *code = v->prog->insns;
    struct vstate st;
    bool live = true;   /* current state reachable by fallthrough */

    memset(&st, 0, sizeof(st));
    if (v->env->ctx_size)
        st.r[1] = (struct reg){ T_PTR_CTX, 0, 0, 0 };
    st.r[BPF_REG_FP] = (struct reg){ T_PTR_STACK, 0, 0, 0 };

    for (uint32_t pc = 0; pc < n; pc++) {
        uint16_t s = v->slot[pc];
        if (s != NO_SLOT && v->have[s]) {
            if (live)
                merge(&st, &v->states[s]);
            else
                st = v->states[s];
            live = true;
        }
        if (!live)
            return fail(v, pc, "unreachable instruction");

        const struct espbpf_insn *in = &code[pc];
        uint8_t cls = BPF_CLASS(in->code);
        uint8_t op = BPF_OP(in->code);
        int rc = ESPBPF_OK;

        switch (cls) {
        case BPF_ALU:
        case BPF_ALU64:
            rc = step_alu(v, pc, &st, in);
            break;

        case BPF_LD:
            if (in->src == ESPBPF_PSEUDO_RODATA)
                st.r[in->dst] = (struct reg){ T_PTR_RODATA, 0, in->imm, in->imm };
            else
                st.r[in->dst] = R_ANY;   /* a 64-bit constant may not fit */
            pc++;
            break;

        case BPF_LDX: {
            unsigned sz = bpf_size_bytes(in->code);
            rc = check_access(v, pc, &st, in->src, in->off, sz, false);
            /* The loaded value is bounded by the width of the load. */
            bool sx = BPF_MODE(in->code) == BPF_MEMSX;
            if (sz == 1)
                st.r[in->dst] = sx ? r_range(-128, 127) : r_range(0, 255);
            else if (sz == 2)
                st.r[in->dst] = sx ? r_range(-32768, 32767) : r_range(0, 65535);
            else
                st.r[in->dst] = R_ANY;
            break;
        }

        case BPF_ST:
            rc = check_access(v, pc, &st, in->dst, in->off,
                              bpf_size_bytes(in->code), true);
            break;

        case BPF_STX:
            if (!(rc = need_value(v, pc, &st, in->src)))
                rc = check_access(v, pc, &st, in->dst, in->off,
                                  bpf_size_bytes(in->code), true);
            break;

        default: /* JMP, JMP32 */
            if (op == BPF_EXIT) {
                rc = need_value(v, pc, &st, 0);
                live = false;
            } else if (op == BPF_CALL) {
                rc = step_call(v, pc, &st, in);
            } else if (op == BPF_JA) {
                propagate(v, pc + 1 + (uint32_t)(cls == BPF_JMP32 ? in->imm : in->off),
                          &st);
                live = false;
            } else {
                if (!(rc = need_value(v, pc, &st, in->dst)) &&
                    BPF_SRC(in->code) == BPF_X)
                    rc = need_value(v, pc, &st, in->src);
                if (!rc) {
                    /* Narrow the compared register differently on the two
                     * branches, so `if (i < 8)` bounds i inside the body. */
                    struct vstate taken = st;
                    bool have_imm = BPF_SRC(in->code) == BPF_K;
                    int64_t imm = in->imm;
                    if (!have_imm) {          /* r_dst <op> r_src, src constant */
                        const struct reg *sr = &st.r[in->src];
                        if (sr->type == T_SCALAR && !r_unknown(sr) && sr->lo == sr->hi) {
                            have_imm = true;
                            imm = sr->lo;
                        }
                    }
                    if (have_imm) {
                        refine(&taken.r[in->dst], op, imm, true);
                        refine(&st.r[in->dst], op, imm, false);
                    }
                    propagate(v, pc + 1 + (uint32_t)in->off, &taken);
                }
            }
            break;
        }
        if (rc)
            return rc;
    }
    if (live)
        return fail(v, n - 1, "program can fall off the end (missing return?)");
    return ESPBPF_OK;
}

int espbpf_verify(struct espbpf_prog *prog, const struct espbpf_env *env,
                  char *log, size_t log_len)
{
    if (log && log_len)
        log[0] = '\0';
    if (!prog || !env || !prog->insns)
        return ESPBPF_E_INVAL;
    prog->verified = false;

    struct verifier v = { .prog = prog, .env = env, .log = log, .log_len = log_len };
    const uint32_t n = prog->n_insns;
    if (n == 0 || n > ESPBPF_MAX_INSNS)
        return fail(&v, n, "program must have 1..%u instructions", ESPBPF_MAX_INSNS);

    int rc = ESPBPF_E_NOMEM;
    uint32_t targets = 0;
    v.slot = malloc(n * sizeof(*v.slot));
    v.is_tail = calloc(n, 1);
    if (!v.slot || !v.is_tail)
        goto out;
    memset(v.slot, 0xff, n * sizeof(*v.slot));

    if ((rc = pass1(&v, &targets)))
        goto out;
    if (targets > ESPBPF_MAX_TARGETS) {
        rc = fail(&v, 0, "too many branch targets: %u (max %u)",
                  (unsigned)targets, ESPBPF_MAX_TARGETS);
        goto out;
    }

    rc = ESPBPF_E_NOMEM;
    v.states = targets ? malloc(targets * sizeof(*v.states)) : NULL;
    v.have = targets ? calloc(targets, 1) : NULL;
    if (targets && (!v.states || !v.have))
        goto out;

    if ((rc = pass2(&v)))
        goto out;

    prog->verified = true;
    if (log && log_len)
        snprintf(log, log_len,
                 "ok: %u insns, %u jump targets, %u bytes rodata, "
                 "%u accesses proven statically, %u checked at run time",
                 (unsigned)n, (unsigned)targets, (unsigned)prog->rodata_len,
                 (unsigned)v.static_checks, (unsigned)v.dynamic_checks);
out:
    if (rc == ESPBPF_E_NOMEM && log && log_len)
        snprintf(log, log_len, "out of memory");
    free(v.slot);
    free(v.is_tail);
    free(v.states);
    free(v.have);
    return rc;
}
