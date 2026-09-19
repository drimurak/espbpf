/* SPDX-License-Identifier: MIT
 *
 * bpfrun — load, verify, disassemble and simulate espbpf programs on Linux
 * before sending them to the board.
 *
 *   bpfrun prog.o                      verify only
 *   bpfrun -d prog.o                   verify and disassemble
 *   bpfrun -t 22,25.5,31,29 prog.o     run the "sensor" hook once per value
 *   bpfrun -H 45 -t ... prog.o         set humidity (default 40 %)
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "espbpf.h"
#include "espbpf_std.h"
#include "espbpf_helpers.h"

struct sim {
    struct espbpf_kv kv;
    int     relay;
    uint8_t leds[4];
    char    line[64];
    uint64_t now_ms;
};

#define SIM(vm) ((struct sim *)(vm)->user)

static uint64_t h_trace(struct espbpf_vm *vm, uint64_t fmt, uint64_t sz,
                        uint64_t a1, uint64_t a2, uint64_t a3)
{
    char buf[128];
    int n = espbpf_format(vm, buf, sizeof(buf), fmt, sz, a1, a2, a3);
    if (n < 0)
        return (uint64_t)-1;
    printf("    trace: %s%s", buf, n && buf[n - 1] == '\n' ? "" : "\n");
    return (uint64_t)n;
}

static uint64_t h_time_ms(struct espbpf_vm *vm, uint64_t a, uint64_t b,
                       uint64_t c, uint64_t d, uint64_t e)
{
    (void)a; (void)b; (void)c; (void)d; (void)e;
    return SIM(vm)->now_ms;
}

static uint64_t h_map_get(struct espbpf_vm *vm, uint64_t key, uint64_t b,
                          uint64_t c, uint64_t d, uint64_t e)
{
    (void)b; (void)c; (void)d; (void)e;
    return espbpf_kv_get(&SIM(vm)->kv, key);
}

static uint64_t h_map_set(struct espbpf_vm *vm, uint64_t key, uint64_t val,
                          uint64_t c, uint64_t d, uint64_t e)
{
    (void)c; (void)d; (void)e;
    return (uint64_t)espbpf_kv_set(&SIM(vm)->kv, key, val);
}

static uint64_t h_relay_set(struct espbpf_vm *vm, uint64_t on, uint64_t b,
                            uint64_t c, uint64_t d, uint64_t e)
{
    (void)b; (void)c; (void)d; (void)e;
    int v = on != 0;
    if (v != SIM(vm)->relay)
        printf("    relay: %s\n", v ? "ON" : "off");
    SIM(vm)->relay = v;
    return 0;
}

static uint64_t h_relay_get(struct espbpf_vm *vm, uint64_t a, uint64_t b,
                            uint64_t c, uint64_t d, uint64_t e)
{
    (void)a; (void)b; (void)c; (void)d; (void)e;
    return (uint64_t)SIM(vm)->relay;
}

static uint64_t h_led_set(struct espbpf_vm *vm, uint64_t idx, uint64_t on,
                          uint64_t c, uint64_t d, uint64_t e)
{
    (void)c; (void)d; (void)e;
    if (idx >= 4)
        return (uint64_t)-1;
    if (SIM(vm)->leds[idx] != (on != 0))
        printf("    led%llu: %s\n", (unsigned long long)idx, on ? "on" : "off");
    SIM(vm)->leds[idx] = on != 0;
    return 0;
}

static uint64_t h_display(struct espbpf_vm *vm, uint64_t fmt, uint64_t sz,
                          uint64_t a1, uint64_t a2, uint64_t a3)
{
    char buf[sizeof(SIM(vm)->line)];
    if (espbpf_format(vm, buf, sizeof(buf), fmt, sz, a1, a2, a3) < 0)
        return (uint64_t)-1;
    if (strcmp(buf, SIM(vm)->line) != 0)
        printf("    display: \"%s\"\n", buf);
    memcpy(SIM(vm)->line, buf, sizeof(buf));
    return 0;
}

static uint64_t h_random(struct espbpf_vm *vm, uint64_t a, uint64_t b,
                         uint64_t c, uint64_t d, uint64_t e)
{
    (void)vm; (void)a; (void)b; (void)c; (void)d; (void)e;
    return (uint32_t)rand();
}

static const struct espbpf_helper helpers[] = {
    ESPBPF_HELPERS(ESPBPF_HELPER_ENTRY)   /* same table as the firmware */
};

static const struct espbpf_env sensor_env = {
    .helpers = helpers,
    .n_helpers = sizeof(helpers) / sizeof(helpers[0]),
    .ctx_size = sizeof(struct sensor_ctx),
    .ctx_writable = false,
};

static uint8_t *read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    uint8_t *buf = NULL;
    size_t cap = 0, n = 0;
    for (;;) {
        if (n == cap) {
            cap = cap ? cap * 2 : 4096;
            uint8_t *nb = realloc(buf, cap);
            if (!nb) {
                free(buf);
                fclose(f);
                return NULL;
            }
            buf = nb;
        }
        size_t r = fread(buf + n, 1, cap - n, f);
        n += r;
        if (r == 0)
            break;
    }
    fclose(f);
    *len = n;
    return buf;
}

static void usage(void)
{
    fprintf(stderr,
            "usage: bpfrun [-d] [-s section] [-t t1,t2,...] [-H humidity] prog.o\n");
    exit(2);
}

int main(int argc, char **argv)
{
    const char *section = "sensor", *temps = NULL;
    double hum = 40.0;
    int disasm = 0, opt;

    while ((opt = getopt(argc, argv, "ds:t:H:")) != -1) {
        switch (opt) {
        case 'd': disasm = 1; break;
        case 's': section = optarg; break;
        case 't': temps = optarg; break;
        case 'H': hum = strtod(optarg, NULL); break;
        default:  usage();
        }
    }
    if (optind != argc - 1)
        usage();

    size_t len;
    uint8_t *data = read_file(argv[optind], &len);
    if (!data) {
        fprintf(stderr, "%s: %s\n", argv[optind], strerror(errno));
        return 1;
    }

    char log[256];
    struct espbpf_prog prog;
    int rc = espbpf_load_elf(data, len, section, &prog, log, sizeof(log));
    free(data);
    if (rc) {
        fprintf(stderr, "load failed: %s\n", log);
        return 1;
    }

    rc = espbpf_verify(&prog, &sensor_env, log, sizeof(log));
    printf("%s [%s]: %s\n", argv[optind], prog.name, rc ? "REJECTED" : "verified");
    printf("  %s\n", log);

    if (disasm) {
        for (uint32_t pc = 0; pc < prog.n_insns; pc++) {
            char line[80];
            espbpf_disasm(prog.insns, prog.n_insns, pc, line, sizeof(line));
            printf("  %4u: %s\n", pc, line);
            if (prog.insns[pc].code == 0x18)
                pc++;
        }
    }
    if (rc) {
        espbpf_prog_free(&prog);
        return 1;
    }

    if (temps) {
        struct sim sim = { 0 };
        char *list = strdup(temps), *save = NULL;
        unsigned i = 0;
        for (char *tok = strtok_r(list, ",", &save); tok;
             tok = strtok_r(NULL, ",", &save), i++) {
            struct sensor_ctx ctx = {
                .temp_x10 = (int32_t)(strtod(tok, NULL) * 10.0 + (tok[0] == '-' ? -0.5 : 0.5)),
                .hum_x10 = (int32_t)(hum * 10.0 + 0.5),
                .uptime_ms = (uint32_t)(i * 2000),
                .flags = SENSOR_OK,
            };
            sim.now_ms = ctx.uptime_ms;
            printf("run %u: temp=%d.%d hum=%d.%d\n", i, ctx.temp_x10 / 10,
                   abs(ctx.temp_x10 % 10), ctx.hum_x10 / 10, ctx.hum_x10 % 10);

            struct timespec t0, t1;
            uint64_t ret = 0;
            clock_gettime(CLOCK_MONOTONIC, &t0);
            rc = espbpf_exec(&prog, &sensor_env, &ctx, &sim, &ret);
            clock_gettime(CLOCK_MONOTONIC, &t1);
            long ns = (t1.tv_sec - t0.tv_sec) * 1000000000L + (t1.tv_nsec - t0.tv_nsec);
            if (rc) {
                printf("    FAULT %d\n", rc);
                break;
            }
            printf("    -> r0=%lld (%ld ns)\n", (long long)ret, ns);
        }
        free(list);
    }
    espbpf_prog_free(&prog);
    return rc ? 1 : 0;
}
