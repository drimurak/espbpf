#include "espbpf_prog.h"
SEC("sensor")
int ctx_write(struct sensor_ctx *ctx)
{
    ctx->temp_x10 = 999;                  // hook context is read only
    return 0;
}
