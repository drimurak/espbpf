// SPDX-License-Identifier: MIT
// Running min / max / exponential moving average of temperature, kept in
// the key/value map so they survive between runs.
#include "espbpf_prog.h"

enum { K_INIT, K_MIN, K_MAX, K_EMA };

SEC("sensor")
int stats(struct sensor_ctx *ctx)
{
    if (!(ctx->flags & SENSOR_OK))
        return 1;

    long t = ctx->temp_x10;
    if (!map_get(K_INIT)) {
        map_set(K_MIN, t);
        map_set(K_MAX, t);
        map_set(K_EMA, t * 16);       // fixed point, 4 fractional bits
        map_set(K_INIT, 1);
    }

    long mn = (long)map_get(K_MIN), mx = (long)map_get(K_MAX);
    if (t < mn)
        map_set(K_MIN, mn = t);
    if (t > mx)
        map_set(K_MAX, mx = t);

    // ema += (t - ema) / 8
    long ema = (long)map_get(K_EMA);
    ema += (t * 16 - ema) / 8;
    map_set(K_EMA, ema);

    show("min %d max %d avg %d", mn / 10, mx / 10, ema / 160);
    return 0;
}
