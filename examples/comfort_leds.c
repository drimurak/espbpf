// SPDX-License-Identifier: MIT
// Comfort indicator on three LEDs: 0 = too dry, 1 = ok, 2 = too humid.
// Uses a small lookup table in .rodata and an on-stack buffer.
#include "espbpf_prog.h"

static const uint8_t thresholds[2] = { 35, 60 };

SEC("sensor")
int comfort(struct sensor_ctx *ctx)
{
    uint8_t hist[8] = {0};
    uint32_t h = ctx->hum_x10 / 10;
    uint32_t level = 0;

    for (int i = 0; i < 2; i++)          // constant bound: clang unrolls it
        if (h >= thresholds[i])
            level = i + 1;

    // shift a tiny history buffer on the stack, exercise array indexing
    hist[level % 8] = 1;

    for (int i = 0; i < 3; i++)
        led_set(i, i == level);

    show("hum %u%% level %u %c", h, level, hist[1] ? (long)'*' : (long)' ');
    return level;
}
