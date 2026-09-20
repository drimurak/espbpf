/* SPDX-License-Identifier: MIT
 *
 * One program, two verifiers. The context is read at offset 0 as u32,
 * which is a valid read in both worlds: struct sensor_ctx starts with
 * temp_x10, and struct __sk_buff starts with len. The section name
 * "socket" is what the kernel expects for a socket filter; espbpf takes
 * the section to load as an argument, so the same object file goes into
 * both verifiers byte for byte.
 */
#pragma once

#define SEC(name) __attribute__((section(name), used))

struct ctx {
    unsigned int v;     /* sensor_ctx.temp_x10 / __sk_buff.len */
};

/* Keep the optimiser from folding away the very thing a case is about. */
#define OPAQUE(x) __asm__ __volatile__("" : "+r"(x))
