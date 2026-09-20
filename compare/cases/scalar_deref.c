// Dereference a number that came from the context.
#include "common.h"

SEC("socket")
int prog(struct ctx *ctx)
{
    unsigned long addr = ctx->v;
    return *(int *)addr;
}
