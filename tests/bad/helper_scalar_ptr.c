#include "espbpf_prog.h"
SEC("sensor")
int helper_scalar_ptr(struct sensor_ctx *ctx)
{
    // pass an arbitrary number where the helper expects a pointer
    return espbpf_trace((const char *)(long)ctx->temp_x10, 16);
}
