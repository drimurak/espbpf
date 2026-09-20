// Index into a stack array, masked to the array size.
#include "common.h"

SEC("socket")
int prog(struct ctx *ctx)
{
    volatile char buf[8] = { 0 };
    unsigned i = ctx->v & 7;
    buf[i] = 1;
    return buf[i];
}
