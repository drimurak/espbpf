// Write far below the stack frame.
#include "common.h"

SEC("socket")
int prog(struct ctx *ctx)
{
    volatile char buf[8] = { 0 };
    char *p = (char *)buf;
    OPAQUE(p);                  // hide the pointer, then walk off the frame
    p[-600] = (char)ctx->v;
    return buf[0];
}
