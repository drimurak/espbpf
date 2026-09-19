/* SPDX-License-Identifier: MIT */
#include <stdio.h>
#include <string.h>

#include "espbpf_std.h"

int espbpf_format(struct espbpf_vm *vm, char *out, size_t out_len,
                  uint64_t fmt, uint64_t fmt_size,
                  uint64_t a1, uint64_t a2, uint64_t a3)
{
    if (!out || out_len == 0 || fmt_size == 0 || fmt_size > 256)
        return -1;
    const char *f = espbpf_vm_mem(vm, fmt, fmt_size, false);
    if (!f)
        return -1;

    const uint64_t args[3] = { a1, a2, a3 };
    unsigned next = 0;
    size_t o = 0;

#define PUT(s) do {                                                  \
        const char *p_ = (s);                                        \
        while (*p_ && o + 1 < out_len) out[o++] = *p_++;             \
    } while (0)

    for (size_t i = 0; i < fmt_size && f[i]; i++) {
        if (f[i] != '%') {
            if (o + 1 < out_len)
                out[o++] = f[i];
            continue;
        }
        if (++i >= fmt_size || !f[i])
            break;
        if (f[i] == '%') {
            PUT("%");
            continue;
        }
        int longs = 0;
        while (i < fmt_size && f[i] == 'l' && longs < 2) {
            longs++;
            i++;
        }
        if (i >= fmt_size)
            break;
        if (next >= 3) {
            PUT("<?>");
            continue;
        }
        uint64_t v = args[next++];
        char tmp[24];
        switch (f[i]) {
        case 'd':
        case 'i':
            if (longs)
                snprintf(tmp, sizeof(tmp), "%lld", (long long)v);
            else
                snprintf(tmp, sizeof(tmp), "%d", (int)(int32_t)v);
            break;
        case 'u':
            snprintf(tmp, sizeof(tmp), "%llu",
                     longs ? (unsigned long long)v : (unsigned long long)(uint32_t)v);
            break;
        case 'x':
            snprintf(tmp, sizeof(tmp), "%llx",
                     longs ? (unsigned long long)v : (unsigned long long)(uint32_t)v);
            break;
        case 'c':
            tmp[0] = (v >= 32 && v < 127) ? (char)v : '?';
            tmp[1] = '\0';
            break;
        default:
            snprintf(tmp, sizeof(tmp), "<%%%c?>", f[i]);
            next--;
            break;
        }
        PUT(tmp);
    }
#undef PUT
    out[o] = '\0';
    return (int)o;
}
