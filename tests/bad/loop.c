#include "espbpf_prog.h"
SEC("sensor")
int loop(struct sensor_ctx *ctx)
{
    long n = ctx->flags;
    while (random32() & 1)            // unbounded loop -> back-edge
        n++;
    return n;
}
