/* SPDX-License-Identifier: MIT
 *
 * ELF loader for eBPF object files (`clang -target bpf -c`).
 * The input is untrusted (it arrives over the network), so every offset
 * and size is validated before use.
 *
 * Supported: one program section, string/constant data in .rodata*
 * referenced through R_BPF_64_64 relocations. Not supported (rejected with
 * a clear message): maps, global writable variables, bpf-to-bpf calls.
 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "espbpf.h"
#include "opcodes.h"

#define EM_BPF          247
#define SHT_PROGBITS    1
#define SHT_SYMTAB      2
#define SHT_RELA        4
#define SHT_REL         9
#define SHF_WRITE       0x1
#define SHF_ALLOC       0x2
#define SHF_EXECINSTR   0x4
#define SHN_UNDEF       0
#define STT_FUNC        2
#define SHN_LORESERVE   0xff00
#define R_BPF_64_64     1
#define R_BPF_64_32     10

#define SHDR_SIZE 64
#define SYM_SIZE  24
#define REL_SIZE  16

struct shdr {
    uint32_t name, type;
    uint64_t flags, offset, size;
    uint32_t link, info;
    uint64_t entsize;
};

struct elf {
    const uint8_t *data;
    size_t         len;
    uint16_t       shnum;
    uint64_t       shoff;
    uint16_t       shstrndx;
    char          *log;
    size_t         log_len;
};

static int fail(struct elf *e, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static int fail(struct elf *e, const char *fmt, ...)
{
    if (e->log && e->log_len) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(e->log, e->log_len, fmt, ap);
        va_end(ap);
    }
    return ESPBPF_E_ELF;
}

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | p[1] << 8); }
static uint32_t rd32(const uint8_t *p) { return rd16(p) | (uint32_t)rd16(p + 2) << 16; }
static uint64_t rd64(const uint8_t *p) { return rd32(p) | (uint64_t)rd32(p + 4) << 32; }

static bool range_ok(const struct elf *e, uint64_t off, uint64_t size)
{
    return off <= e->len && size <= e->len - off;
}

static void get_shdr(const struct elf *e, uint16_t i, struct shdr *s)
{
    const uint8_t *p = e->data + e->shoff + (uint64_t)i * SHDR_SIZE;
    s->name = rd32(p);
    s->type = rd32(p + 4);
    s->flags = rd64(p + 8);
    s->offset = rd64(p + 24);
    s->size = rd64(p + 32);
    s->link = rd32(p + 40);
    s->info = rd32(p + 44);
    s->entsize = rd64(p + 56);
}

/* NUL-terminated string at `off` inside string-table section `strndx`,
 * or "" if anything is out of bounds. */
static const char *str_at(const struct elf *e, uint16_t strndx, uint32_t off)
{
    struct shdr s;
    if (strndx >= e->shnum)
        return "";
    get_shdr(e, strndx, &s);
    if (!range_ok(e, s.offset, s.size) || off >= s.size)
        return "";
    const char *p = (const char *)e->data + s.offset + off;
    if (!memchr(p, '\0', s.size - off))
        return "";
    return p;
}

static const char *sec_name(const struct elf *e, uint16_t i)
{
    struct shdr s;
    get_shdr(e, i, &s);
    return str_at(e, e->shstrndx, s.name);
}

int espbpf_load_elf(const uint8_t *data, size_t len, const char *section,
                    struct espbpf_prog *out, char *log, size_t log_len)
{
    struct elf e = { .data = data, .len = len, .log = log, .log_len = log_len };
    uint32_t *rodata_base = NULL;
    int rc;

    if (log && log_len)
        log[0] = '\0';
    if (!data || !out)
        return ESPBPF_E_INVAL;
    memset(out, 0, sizeof(*out));

    /* --- header --- */
    if (len < 64 || memcmp(data, "\x7f" "ELF", 4) != 0)
        return fail(&e, "not an ELF file");
    if (data[4] != 2 || data[5] != 1)
        return fail(&e, "need ELF64 little-endian (clang -target bpfel)");
    if (rd16(data + 18) != EM_BPF)
        return fail(&e, "not an eBPF object (e_machine=%u)", rd16(data + 18));
    e.shoff = rd64(data + 0x28);
    e.shnum = rd16(data + 0x3c);
    e.shstrndx = rd16(data + 0x3e);
    if (rd16(data + 0x3a) != SHDR_SIZE || e.shnum == 0 ||
        !range_ok(&e, e.shoff, (uint64_t)e.shnum * SHDR_SIZE) ||
        e.shstrndx >= e.shnum)
        return fail(&e, "bad section header table");

    /* --- pick the program section --- */
    int prog_idx = -1;
    struct shdr ps;
    for (uint16_t i = 1; i < e.shnum; i++) {
        struct shdr s;
        get_shdr(&e, i, &s);
        if (s.type != SHT_PROGBITS || !(s.flags & SHF_EXECINSTR) || s.size == 0)
            continue;
        if (section && strcmp(sec_name(&e, i), section) != 0)
            continue;
        prog_idx = i;
        ps = s;
        break;
    }
    if (prog_idx < 0)
        return section ? fail(&e, "section '%s' not found", section)
                       : fail(&e, "no program section found");
    if (!range_ok(&e, ps.offset, ps.size) || ps.size % 8 != 0)
        return fail(&e, "program section is truncated or misaligned");
    if (ps.size / 8 > ESPBPF_MAX_INSNS)
        return fail(&e, "program too large: %llu insns (max %u)",
                    (unsigned long long)(ps.size / 8), ESPBPF_MAX_INSNS);

    snprintf(out->name, sizeof(out->name), "%s", sec_name(&e, (uint16_t)prog_idx));
    out->n_insns = (uint32_t)(ps.size / 8);
    out->insns = malloc(ps.size);
    if (!out->insns)
        return ESPBPF_E_NOMEM;
    for (uint32_t i = 0; i < out->n_insns; i++) {
        const uint8_t *p = data + ps.offset + (uint64_t)i * 8;
        struct espbpf_insn *in = &out->insns[i];
        in->code = p[0];
        in->dst = p[1] & 0x0f;
        in->src = (p[1] >> 4) & 0x0f;
        in->off = (int16_t)rd16(p + 2);
        in->imm = (int32_t)rd32(p + 4);
    }

    /* --- concatenate read-only data sections --- */
    rc = ESPBPF_E_NOMEM;
    rodata_base = malloc(e.shnum * sizeof(*rodata_base));
    if (!rodata_base)
        goto err;
    uint32_t ro_len = 0;
    for (uint16_t i = 0; i < e.shnum; i++) {
        struct shdr s;
        get_shdr(&e, i, &s);
        rodata_base[i] = UINT32_MAX;
        if (i == 0 || s.type != SHT_PROGBITS || !(s.flags & SHF_ALLOC) ||
            (s.flags & (SHF_WRITE | SHF_EXECINSTR)) ||
            strncmp(sec_name(&e, i), ".rodata", 7) != 0)
            continue;
        ro_len = (ro_len + 7u) & ~7u;
        if (!range_ok(&e, s.offset, s.size) ||
            s.size > ESPBPF_MAX_RODATA || ro_len + s.size > ESPBPF_MAX_RODATA) {
            rc = fail(&e, "rodata too large (max %u bytes)", ESPBPF_MAX_RODATA);
            goto err;
        }
        rodata_base[i] = ro_len;
        ro_len += (uint32_t)s.size;
    }
    if (ro_len) {
        out->rodata = calloc(ro_len, 1);
        if (!out->rodata)
            goto err;
        out->rodata_len = ro_len;
        for (uint16_t i = 0; i < e.shnum; i++) {
            struct shdr s;
            if (rodata_base[i] == UINT32_MAX)
                continue;
            get_shdr(&e, i, &s);
            memcpy(out->rodata + rodata_base[i], data + s.offset, s.size);
        }
    }

    /* --- relocations for the program section --- */
    for (uint16_t i = 1; i < e.shnum; i++) {
        struct shdr rs, sym;
        get_shdr(&e, i, &rs);
        if ((rs.type != SHT_REL && rs.type != SHT_RELA) || rs.info != (uint32_t)prog_idx)
            continue;
        if (rs.type == SHT_RELA) {
            rc = fail(&e, "RELA relocations are not supported");
            goto err;
        }
        if (rs.link >= e.shnum || !range_ok(&e, rs.offset, rs.size) ||
            rs.size % REL_SIZE) {
            rc = fail(&e, "bad relocation section");
            goto err;
        }
        get_shdr(&e, (uint16_t)rs.link, &sym);
        if (sym.type != SHT_SYMTAB || !range_ok(&e, sym.offset, sym.size) ||
            sym.size % SYM_SIZE) {
            rc = fail(&e, "bad symbol table");
            goto err;
        }

        for (uint64_t r = 0; r < rs.size / REL_SIZE; r++) {
            const uint8_t *rp = data + rs.offset + r * REL_SIZE;
            uint64_t r_off = rd64(rp);
            uint64_t r_info = rd64(rp + 8);
            uint32_t r_sym = (uint32_t)(r_info >> 32);
            uint32_t r_type = (uint32_t)r_info;

            if (r_sym >= sym.size / SYM_SIZE) {
                rc = fail(&e, "relocation references bad symbol");
                goto err;
            }
            const uint8_t *sp = data + sym.offset + (uint64_t)r_sym * SYM_SIZE;
            const char *sname = str_at(&e, (uint16_t)sym.link, rd32(sp));
            uint16_t shndx = rd16(sp + 6);
            if (!*sname && shndx > 0 && shndx < e.shnum)
                sname = sec_name(&e, shndx);    /* section symbol */
            uint64_t value = rd64(sp + 8);

            if (r_type == R_BPF_64_32) {
                rc = fail(&e, "call to non-inlined function '%s': "
                              "use static inline or __always_inline", sname);
                goto err;
            }
            if (r_type != R_BPF_64_64) {
                rc = fail(&e, "unsupported relocation type %u", (unsigned)r_type);
                goto err;
            }
            if (r_off % 8 || r_off / 8 + 1 >= out->n_insns) {
                rc = fail(&e, "relocation offset out of range");
                goto err;
            }
            struct espbpf_insn *in = &out->insns[r_off / 8];
            if (in->code != (BPF_LD | BPF_IMM | BPF_DW)) {
                rc = fail(&e, "relocation does not target lddw");
                goto err;
            }
            if (shndx == SHN_UNDEF || shndx >= SHN_LORESERVE) {
                rc = fail(&e, "unresolved symbol '%s'", sname);
                goto err;
            }
            if (shndx >= e.shnum || rodata_base[shndx] == UINT32_MAX) {
                rc = fail(&e, "'%s' lives in %s: maps and writable globals are "
                              "not supported, use the map helpers", sname,
                          shndx < e.shnum ? sec_name(&e, shndx) : "?");
                goto err;
            }
            uint64_t target = (uint64_t)rodata_base[shndx] + value +
                              (uint64_t)(int64_t)in->imm;
            if (target >= out->rodata_len) {
                rc = fail(&e, "relocation to '%s' out of range", sname);
                goto err;
            }
            in->src = ESPBPF_PSEUDO_RODATA;
            in->imm = (int32_t)target;
            in[1].imm = 0;
        }
    }

    /* --- name the program after its function symbol, like bpftool --- */
    for (uint16_t i = 1; i < e.shnum; i++) {
        struct shdr sym;
        get_shdr(&e, i, &sym);
        if (sym.type != SHT_SYMTAB || !range_ok(&e, sym.offset, sym.size))
            continue;
        for (uint64_t k = 0; k < sym.size / SYM_SIZE; k++) {
            const uint8_t *sp = data + sym.offset + k * SYM_SIZE;
            if ((sp[4] & 0xf) == STT_FUNC && rd16(sp + 6) == (uint16_t)prog_idx &&
                rd64(sp + 8) == 0) {
                const char *fn = str_at(&e, (uint16_t)sym.link, rd32(sp));
                if (*fn)
                    snprintf(out->name, sizeof(out->name), "%s", fn);
                break;
            }
        }
        break;
    }

    free(rodata_base);
    return ESPBPF_OK;

err:
    free(rodata_base);
    espbpf_prog_free(out);
    return rc;
}
