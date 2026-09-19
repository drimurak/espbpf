/* SPDX-License-Identifier: MIT
 *
 * Header for writing espbpf programs. Included by BPF programs
 * (clang -target bpf) and by the firmware, so both agree on helper IDs and
 * context layouts.
 */
#ifndef ESPBPF_PROG_H
#define ESPBPF_PROG_H

#include <stdint.h>

/* ---- helper IDs --------------------------------------------------- */
enum espbpf_helper_id {
    ESPBPF_FN_trace       = 1,  /* (fmt, fmt_size, a1, a2, a3) -> chars written */
    ESPBPF_FN_time_ms     = 2,  /* () -> milliseconds since boot */
    ESPBPF_FN_map_get     = 3,  /* (key) -> value, 0 if unset */
    ESPBPF_FN_map_set     = 4,  /* (key, value) -> 0 or -1 */
    ESPBPF_FN_relay_set   = 5,  /* (on) -> 0 */
    ESPBPF_FN_relay_get   = 6,  /* () -> 0/1 */
    ESPBPF_FN_led_set     = 7,  /* (index, on) -> 0 or -1 */
    ESPBPF_FN_display     = 8,  /* (fmt, fmt_size, a1, a2, a3): text line on the screen */
    ESPBPF_FN_random      = 9,  /* () -> 32 random bits */
};

#define ESPBPF_MAP_SLOTS 16     /* keys 0..15, values persist between runs */

/* ---- hook "sensor": runs after every DHT11 sample ------------------ */
struct sensor_ctx {
    int32_t  temp_x10;      /* temperature, 0.1 °C */
    int32_t  hum_x10;       /* relative humidity, 0.1 % */
    uint32_t uptime_ms;
    uint32_t flags;         /* SENSOR_OK if the read succeeded */
};
#define SENSOR_OK 0x1

#if defined(__bpf__)
/* ---- program-side declarations ------------------------------------ */
#define SEC(name) __attribute__((section(name), used))

static long (*espbpf_trace)(const char *fmt, uint32_t fmt_size, ...) =
    (void *)ESPBPF_FN_trace;
static uint64_t (*time_ms)(void) = (void *)ESPBPF_FN_time_ms;
static uint64_t (*map_get)(uint32_t key) = (void *)ESPBPF_FN_map_get;
static long (*map_set)(uint32_t key, uint64_t value) = (void *)ESPBPF_FN_map_set;
static long (*relay_set)(uint32_t on) = (void *)ESPBPF_FN_relay_set;
static long (*relay_get)(void) = (void *)ESPBPF_FN_relay_get;
static long (*led_set)(uint32_t index, uint32_t on) = (void *)ESPBPF_FN_led_set;
static long (*espbpf_display)(const char *fmt, uint32_t fmt_size, ...) =
    (void *)ESPBPF_FN_display;
static uint32_t (*random32)(void) = (void *)ESPBPF_FN_random;

/* printf-like tracing with at most 3 arguments: %d %u %x %c %%, with
 * optional l/ll. Output goes to the serial log and `bpfctl.py trace`. */
#define trace(fmt, ...)                                              \
    ({                                                               \
        static const char ____fmt[] = fmt;                           \
        espbpf_trace(____fmt, sizeof(____fmt), ##__VA_ARGS__);       \
    })

/* Same format rules; replaces the program's line on the display. */
#define show(fmt, ...)                                               \
    ({                                                               \
        static const char ____fmt[] = fmt;                           \
        espbpf_display(____fmt, sizeof(____fmt), ##__VA_ARGS__);     \
    })
#endif

#endif /* ESPBPF_PROG_H */
