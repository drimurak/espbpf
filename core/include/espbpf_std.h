/* SPDX-License-Identifier: MIT
 * Building blocks shared by hosts (firmware, bpfrun) for common helpers. */
#ifndef ESPBPF_STD_H
#define ESPBPF_STD_H

#include "espbpf.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Format a guest printf-style string (%d %i %u %x %c %%, with l/ll) with up
 * to three arguments. The format pointer is validated against guest memory.
 * Returns the number of characters written (excluding NUL) or -1. */
int espbpf_format(struct espbpf_vm *vm, char *out, size_t out_len,
                  uint64_t fmt, uint64_t fmt_size,
                  uint64_t a1, uint64_t a2, uint64_t a3);

/* Small persistent key/value array backing map_get / map_set. */
#define ESPBPF_KV_SLOTS 16
struct espbpf_kv {
    uint64_t val[ESPBPF_KV_SLOTS];
};

static inline uint64_t espbpf_kv_get(const struct espbpf_kv *kv, uint64_t key)
{
    return key < ESPBPF_KV_SLOTS ? kv->val[key] : 0;
}

static inline int64_t espbpf_kv_set(struct espbpf_kv *kv, uint64_t key,
                                    uint64_t value)
{
    if (key >= ESPBPF_KV_SLOTS)
        return -1;
    kv->val[key] = value;
    return 0;
}

#ifdef __cplusplus
}
#endif

#endif
