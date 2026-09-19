// SPDX-License-Identifier: MIT
// Wiring check: runs LEDs one after another, toggles the relay every
// other run, shows the sensor state on the screen.
#include "espbpf_prog.h"

SEC("sensor")
int hwtest(struct sensor_ctx *ctx)
{
    uint64_t n = map_get(0);
    map_set(0, n + 1);

    for (int i = 0; i < 3; i++)
        led_set(i, n % 3 == i);
    relay_set(n % 4 < 2);

    if (ctx->flags & SENSOR_OK)
        show("step %u  DHT ok", n);
    else
        show("step %u  DHT ERROR", n);
    trace("step %u relay=%u temp=%d", n, relay_get(), ctx->temp_x10);
    return 0;
}
