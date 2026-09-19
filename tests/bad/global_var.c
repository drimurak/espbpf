#include "espbpf_prog.h"
static int counter;
SEC("sensor")
int global_var(struct sensor_ctx *ctx)
{
    return ++counter + ctx->flags;
}
