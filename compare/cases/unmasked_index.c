// Same, but the index comes straight from the context.
#include "common.h"

SEC("socket")
int prog(struct ctx *ctx)
{
    volatile char buf[8] = { 0 };
    unsigned i = ctx->v;
    buf[i] = 1;
    return buf[i];
}
