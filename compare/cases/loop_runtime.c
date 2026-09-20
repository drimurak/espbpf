// Loop whose bound is only known at run time.
#include "common.h"

SEC("socket")
int prog(struct ctx *ctx)
{
    unsigned n = ctx->v & 15;
    int sum = 0;
    for (unsigned i = 0; i < n; i++) {
        sum += (int)i;
        OPAQUE(sum);            // no closed form: the loop must stay a loop
    }
    return sum;
}
