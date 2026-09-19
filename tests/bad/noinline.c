#include "espbpf_prog.h"
__attribute__((noinline)) static int twice(int x) { return x * 2 + 1; }
SEC("sensor")
int noinline(struct sensor_ctx *ctx)
{
    return twice(ctx->temp_x10);
}
