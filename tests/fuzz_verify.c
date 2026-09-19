/* libFuzzer: arbitrary instruction streams -> verifier -> exec.
 * The invariant: an accepted program must never fault at run time on
 * statically-known accesses, and must never touch memory outside its
 * regions (ASan catches that). */
#include <stdlib.h>
#include <string.h>
#include "espbpf.h"

static uint64_t h_any(struct espbpf_vm *vm, uint64_t a, uint64_t b, uint64_t c,
                      uint64_t d, uint64_t e)
{
    (void)vm; (void)b; (void)c; (void)d; (void)e;
    return a * 2654435761u;
}
static uint64_t h_mem(struct espbpf_vm *vm, uint64_t p, uint64_t n, uint64_t c,
                      uint64_t d, uint64_t e)
{
    (void)c; (void)d; (void)e;
    const uint8_t *m = espbpf_vm_mem(vm, p, n, false);
    uint64_t s = 0;
    if (m)
        for (uint64_t i = 0; i < n; i++)
            s += m[i];
    return s;
}
/* Same IDs and argument kinds as the firmware (sdk/espbpf_prog.h). */
#define P ESPBPF_ARG_PTR_MEM
#define Z ESPBPF_ARG_SIZE
#define S ESPBPF_ARG_SCALAR
static const struct espbpf_helper helpers[] = {
    { 1, "trace", h_mem, { P, Z } },   { 2, "time", h_any, { 0 } },
    { 3, "get",   h_any, { S } },      { 4, "set",  h_any, { S, S } },
    { 5, "relay", h_any, { S } },      { 6, "rget", h_any, { 0 } },
    { 7, "led",   h_any, { S, S } },   { 8, "disp", h_mem, { P, Z } },
    { 9, "rand",  h_any, { 0 } },
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 9 || size / 8 > ESPBPF_MAX_INSNS)
        return 0;
    struct espbpf_env env = { helpers, 9, 16, data[0] & 1 };
    struct espbpf_prog p;
    uint32_t n = (uint32_t)((size - 1) / 8);
    struct espbpf_insn *insns = malloc(n * 8);
    memcpy(insns, data + 1, n * 8);
    if (espbpf_load_raw(insns, n, &p) == 0) {
        char log[128];
        p.rodata = calloc(1, 64);          /* fake rodata for lddw src=2 */
        p.rodata_len = p.rodata ? 64 : 0;
        if (espbpf_verify(&p, &env, log, sizeof(log)) == 0) {
            uint8_t ctx[16] = { 0 };
            uint64_t r;
            espbpf_exec(&p, &env, ctx, NULL, &r);
        }
        espbpf_prog_free(&p);
    }
    free(insns);
    return 0;
}
