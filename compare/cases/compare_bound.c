// The bound comes from a comparison instead of a mask.
#include "common.h"

SEC("socket")
int prog(struct ctx *ctx)
{
    volatile char buf[8] = { 0 };
    unsigned i = ctx->v;
    if (i < 8)
        buf[i] = 1;
    return buf[0];
}
