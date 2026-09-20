// Write into the context.
#include "common.h"

SEC("socket")
int prog(struct ctx *ctx)
{
    ctx->v = 5;
    return 0;
}
