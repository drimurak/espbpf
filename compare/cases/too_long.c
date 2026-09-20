// A program longer than the espbpf instruction limit (1024).
#include "common.h"

#define R8(x) x x x x x x x x
#define STEP  s += 3; OPAQUE(s);

SEC("socket")
int prog(struct ctx *ctx)
{
    int s = (int)ctx->v;
    R8(R8(R8(R8(STEP))))        // 4096 additions, no branches
    return s;
}
