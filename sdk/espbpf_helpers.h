/* SPDX-License-Identifier: MIT
 *
 * The single source of truth for helper signatures, shared by the firmware
 * and the host simulator (bpfrun). If they disagree, a program that passes
 * `bpfrun` can be rejected on the board — which is exactly the bug this
 * header exists to prevent.
 *
 * Host-side only (needs espbpf.h); BPF programs include espbpf_prog.h.
 *
 * Argument kinds: P pointer to readable memory, Z its size, S scalar,
 * N not checked. trace/display are printf-like: the up to three values
 * after the format are optional, so they are N (the helper only reads as
 * many as the format string asks for).
 */
#ifndef ESPBPF_HELPERS_H
#define ESPBPF_HELPERS_H

#include "espbpf.h"
#include "espbpf_prog.h"

/*        name       arg1 arg2 arg3 arg4 arg5 */
#define ESPBPF_HELPERS(X)                        \
    X(trace,         P,   Z,   N,   N,   N)     \
    X(time_ms,       N,   N,   N,   N,   N)     \
    X(map_get,       S,   N,   N,   N,   N)     \
    X(map_set,       S,   S,   N,   N,   N)     \
    X(relay_set,     S,   N,   N,   N,   N)     \
    X(relay_get,     N,   N,   N,   N,   N)     \
    X(led_set,       S,   S,   N,   N,   N)     \
    X(display,       P,   Z,   N,   N,   N)     \
    X(random,        N,   N,   N,   N,   N)

#define ESPBPF_A_P ESPBPF_ARG_PTR_MEM
#define ESPBPF_A_Z ESPBPF_ARG_SIZE
#define ESPBPF_A_S ESPBPF_ARG_SCALAR
#define ESPBPF_A_N ESPBPF_ARG_NONE

/* Declare `uint64_t h_<name>(struct espbpf_vm *, uint64_t x5)` for every
 * helper, then build the table with:
 *   static const struct espbpf_helper helpers[] = {
 *       ESPBPF_HELPERS(ESPBPF_HELPER_ENTRY)
 *   };
 */
#define ESPBPF_HELPER_ENTRY(name, a1, a2, a3, a4, a5)                  \
    { ESPBPF_FN_##name, #name, h_##name,                               \
      { ESPBPF_A_##a1, ESPBPF_A_##a2, ESPBPF_A_##a3, ESPBPF_A_##a4,    \
        ESPBPF_A_##a5 } },

#endif
