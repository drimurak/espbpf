/* Tiny mutation fuzzer driver for environments without libFuzzer.
 * Links against any LLVMFuzzerTestOneInput(). Build with ASan/UBSan.
 *   minifuzz <iterations> <seed files...> */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static uint64_t rng = 0x9e3779b97f4a7c15ull;
static uint64_t rnd(void)
{
    rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
    return rng;
}

static const int64_t interesting[] = { 0, 1, -1, 7, 8, 16, 63, 64, 127, 255,
    256, 511, 512, 1023, 1024, 0x7fff, 0x8000, 0xffff, 0x7fffffff,
    (int64_t)0x80000000u, (int64_t)0xffffffffu };

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s iterations seeds...\n", argv[0]);
        return 2;
    }
    long iters = atol(argv[1]);
    int nseeds = argc - 2;
    uint8_t **seed = calloc(nseeds, sizeof(*seed));
    size_t *seed_len = calloc(nseeds, sizeof(*seed_len));
    for (int i = 0; i < nseeds; i++) {
        FILE *f = fopen(argv[i + 2], "rb");
        if (!f) { perror(argv[i + 2]); return 1; }
        seed[i] = malloc(1 << 16);
        seed_len[i] = fread(seed[i], 1, 1 << 16, f);
        fclose(f);
    }
    uint8_t *buf = malloc(1 << 16);
    for (long it = 0; it < iters; it++) {
        int s = (int)(rnd() % nseeds);
        size_t len = seed_len[s];
        memcpy(buf, seed[s], len);
        int muts = 1 + (int)(rnd() % 8);
        for (int m = 0; m < muts && len; m++) {
            size_t pos = rnd() % len;
            switch (rnd() % 6) {
            case 0: buf[pos] ^= (uint8_t)(1u << (rnd() % 8)); break;
            case 1: buf[pos] = (uint8_t)rnd(); break;
            case 2: {                                  /* interesting value */
                int64_t v = interesting[rnd() % (sizeof(interesting) / sizeof(*interesting))];
                size_t w = 1u << (rnd() % 4);
                if (pos + w <= len) memcpy(buf + pos, &v, w);
                break;
            }
            case 3:                                    /* truncate */
                len = pos + 1;
                break;
            case 4: {                                  /* copy a block (insn) */
                size_t from = rnd() % len, n = 8;
                if (from + n <= len && pos + n <= len) memmove(buf + pos, buf + from, n);
                break;
            }
            default: {                                 /* byte arith on a code/field */
                buf[pos] = (uint8_t)(buf[pos] + (int8_t)(rnd() % 35 - 17));
                break;
            }
            }
        }
        LLVMFuzzerTestOneInput(buf, len);
    }
    /* Free everything: the fuzzers run under LeakSanitizer in CI, and a
     * leaking harness would hide a leak in the code under test. */
    for (int i = 0; i < nseeds; i++)
        free(seed[i]);
    free(seed);
    free(seed_len);
    free(buf);
    printf("%ld iterations ok\n", iters);
    return 0;
}
