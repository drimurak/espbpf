#include "espbpf_prog.h"
SEC("sensor")
int scalar_deref(struct sensor_ctx *ctx)
{
    long addr = 0x3ff44004 + ctx->flags;   // try to poke a GPIO register
    return *(int *)addr;
}
