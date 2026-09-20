// Read a stack slot that was never written.
#include "common.h"

SEC("socket")
int prog(struct ctx *ctx)
{
    volatile char buf[8];
    unsigned i = ctx->v & 7;
    return buf[i];
}
