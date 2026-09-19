/* SPDX-License-Identifier: MIT
 *
 * espbpf — a tiny, verified eBPF virtual machine for microcontrollers.
 *
 * Programs are ordinary eBPF object files produced by
 *     clang -O2 -target bpf -mcpu=v4 -c prog.c -o prog.o
 * They are loaded from ELF, statically verified, and executed by a
 * portable interpreter. The verifier guarantees that an accepted program:
 *   - terminates (the control-flow graph is acyclic, so the number of
 *     executed instructions is bounded by the program length);
 *   - never reads an uninitialised register;
 *   - dereferences only pointers it was given (context, stack, rodata),
 *     never scalars;
 *   - calls only helpers registered by the host, with correctly typed
 *     arguments.
 * Every memory access is additionally bounds-checked at run time, so a
 * verifier bug cannot turn into memory corruption on the device.
 */
#ifndef ESPBPF_H
#define ESPBPF_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ESPBPF_STACK_SIZE   512u    /* same as the Linux kernel */
#define ESPBPF_MAX_INSNS    1024u
#define ESPBPF_MAX_RODATA   1024u
#define ESPBPF_MAX_TARGETS  256u    /* branch targets: each costs one state */
#define ESPBPF_NAME_LEN     32u

struct espbpf_insn {
    uint8_t  code;
    uint8_t  dst : 4;
    uint8_t  src : 4;
    int16_t  off;
    int32_t  imm;
};

enum espbpf_err {
    ESPBPF_OK = 0,
    ESPBPF_E_NOMEM = -1,
    ESPBPF_E_ELF = -2,       /* malformed or unsupported object file */
    ESPBPF_E_VERIFY = -3,    /* rejected by the verifier */
    ESPBPF_E_FAULT = -4,     /* run-time fault (should be unreachable) */
    ESPBPF_E_INVAL = -5,
};

/* Argument kinds a helper may declare. */
enum espbpf_arg {
    ESPBPF_ARG_NONE = 0,     /* argument unused */
    ESPBPF_ARG_ANY,          /* any initialised value */
    ESPBPF_ARG_SCALAR,       /* must be a number, not a pointer */
    ESPBPF_ARG_PTR_MEM,      /* pointer to readable memory; next arg is its size */
    ESPBPF_ARG_SIZE,         /* size belonging to the preceding PTR_MEM */
};

struct espbpf_vm;

typedef uint64_t (*espbpf_helper_fn)(struct espbpf_vm *vm, uint64_t a1,
                                     uint64_t a2, uint64_t a3, uint64_t a4,
                                     uint64_t a5);

struct espbpf_helper {
    uint32_t         id;
    const char      *name;
    espbpf_helper_fn fn;
    uint8_t          args[5];  /* enum espbpf_arg */
};

/* Describes what a program attached to a particular hook may do. */
struct espbpf_env {
    const struct espbpf_helper *helpers;
    size_t                      n_helpers;
    uint32_t                    ctx_size;     /* bytes; 0 = no context */
    bool                        ctx_writable;
};

struct espbpf_prog {
    char                name[ESPBPF_NAME_LEN];  /* function (or section) name */
    uint32_t            n_insns;
    struct espbpf_insn *insns;
    uint32_t            rodata_len;
    uint8_t            *rodata;
    bool                verified;
};

/* Per-execution state; helpers receive it so they can validate pointers. */
struct espbpf_vm {
    const struct espbpf_prog *prog;
    const struct espbpf_env  *env;
    void                     *ctx;
    void                     *user;     /* opaque host data for helpers */
    uint64_t                  reg[11];
    uint8_t                   stack[ESPBPF_STACK_SIZE];
    uint32_t                  steps;
};

/* Parse an ELF64 little-endian eBPF object. `section` selects the program
 * section by name; NULL takes the first executable section.
 * On success *out owns heap memory; release it with espbpf_prog_free(). */
int espbpf_load_elf(const uint8_t *data, size_t len, const char *section,
                    struct espbpf_prog *out, char *log, size_t log_len);

/* Load raw instructions (no rodata). Used by tests. */
int espbpf_load_raw(const struct espbpf_insn *insns, uint32_t n,
                    struct espbpf_prog *out);

void espbpf_prog_free(struct espbpf_prog *prog);

/* Static verification against an environment. Writes a human readable
 * reason to `log` on failure. Marks prog->verified on success. */
int espbpf_verify(struct espbpf_prog *prog, const struct espbpf_env *env,
                  char *log, size_t log_len);

/* Execute a verified program. `ctx` must point to env->ctx_size bytes. */
int espbpf_exec(const struct espbpf_prog *prog, const struct espbpf_env *env,
                void *ctx, void *user, uint64_t *ret);

/* For helpers: resolve a guest pointer to host memory, or NULL if the
 * range [ptr, ptr+len) is not entirely inside memory the program may
 * access. */
void *espbpf_vm_mem(struct espbpf_vm *vm, uint64_t ptr, uint64_t len,
                    bool write);

/* Human readable disassembly of one instruction (for logs and tools). */
int espbpf_disasm(const struct espbpf_insn *insns, uint32_t n, uint32_t pc,
                  char *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* ESPBPF_H */
