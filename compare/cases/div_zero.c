// Division by a value that may be zero at run time.
#include "common.h"

SEC("socket")
int prog(struct ctx *ctx)
{
    int d = (int)ctx->v;
    OPAQUE(d);
    return 100 / d;
}
