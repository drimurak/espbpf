#include "espbpf_prog.h"
static long (*format_flash)(void) = (void *)99;
SEC("sensor")
int bad_helper(struct sensor_ctx *ctx)
{
    return format_flash() + ctx->flags;
}
