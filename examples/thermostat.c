// SPDX-License-Identifier: MIT
// Thermostat with hysteresis: the relay drives a heater.
// Heater turns on below 22.0 °C and off above 24.0 °C.
#include "espbpf_prog.h"

#define ON_BELOW_X10  220
#define OFF_ABOVE_X10 240
#define KEY_SWITCHES  0

SEC("sensor")
int thermostat(struct sensor_ctx *ctx)
{
    if (!(ctx->flags & SENSOR_OK)) {
        led_set(0, 1);                    // red LED: sensor error
        show("sensor error");
        return 0;
    }
    led_set(0, 0);

    int t = ctx->temp_x10;
    long heating = relay_get();

    if (!heating && t < ON_BELOW_X10) {
        relay_set(1);
        map_set(KEY_SWITCHES, map_get(KEY_SWITCHES) + 1);
        trace("heater on at %d.%d C", t / 10, t % 10);
    } else if (heating && t > OFF_ABOVE_X10) {
        relay_set(0);
        map_set(KEY_SWITCHES, map_get(KEY_SWITCHES) + 1);
        trace("heater off at %d.%d C", t / 10, t % 10);
    }

    show("heat %c, %u sw", relay_get() ? (long)'+' : (long)'-',
         map_get(KEY_SWITCHES));
    return 0;
}
