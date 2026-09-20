/* SPDX-License-Identifier: MIT
 *
 * kverify — hand an eBPF object file to the Linux kernel verifier and print
 * its verdict, so the same .o can be judged by espbpf and by the kernel.
 *
 *   kverify [-s section] [-v] prog.o
 *
 * The ELF is parsed here rather than by core/src/elf.c on purpose: if the
 * espbpf loader refused a file, the kernel would never get to see it, and
 * the comparison would measure the loader instead of the verifier.
 *
 * Programs are loaded as BPF_PROG_TYPE_SOCKET_FILTER: it is the type with
 * the fewest privileges and its context (struct __sk_buff) is readable at
 * offset 0, which is all the test programs need.
 */
#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static char verifier_log[256 * 1024];

static void *read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    struct stat st;
    if (fstat(fileno(f), &st)) {
        fclose(f);
        return NULL;
    }
    void *buf = malloc((size_t)st.st_size);
    if (buf && fread(buf, 1, (size_t)st.st_size, f) != (size_t)st.st_size) {
        free(buf);
        buf = NULL;
    }
    fclose(f);
    *len = buf ? (size_t)st.st_size : 0;
    return buf;
}

/* Find an executable section: by name if one was given, else the first. */
static const void *find_section(const uint8_t *elf, size_t len, const char *want,
                                size_t *out_len, const char **out_name)
{
    if (len < sizeof(Elf64_Ehdr))
        return NULL;
    const Elf64_Ehdr *eh = (const void *)elf;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) || eh->e_machine != EM_BPF)
        return NULL;
    const Elf64_Shdr *sh = (const void *)(elf + eh->e_shoff);
    const char *str = (const char *)(elf + sh[eh->e_shstrndx].sh_offset);
    for (unsigned i = 1; i < eh->e_shnum; i++) {
        const char *name = str + sh[i].sh_name;
        if (sh[i].sh_type != SHT_PROGBITS || !(sh[i].sh_flags & SHF_EXECINSTR))
            continue;
        if (want && strcmp(name, want))
            continue;
        *out_len = sh[i].sh_size;
        *out_name = name;
        return elf + sh[i].sh_offset;
    }
    return NULL;
}

/* The last line of the verifier log that is not the statistics footer. */
static const char *last_message(const char *log)
{
    static char out[256];
    const char *best = "";
    const char *p = log;
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        if (n && strncmp(p, "processed ", 10) != 0)
            best = p;
        if (!nl)
            break;
        p = nl + 1;
    }
    size_t n = strcspn(best, "\n");
    if (n >= sizeof(out))
        n = sizeof(out) - 1;
    memcpy(out, best, n);
    out[n] = '\0';
    return out;
}

int main(int argc, char **argv)
{
    const char *section = NULL;
    int verbose = 0, argi = 1;
    while (argi < argc && argv[argi][0] == '-') {
        if (!strcmp(argv[argi], "-s") && argi + 1 < argc)
            section = argv[++argi];
        else if (!strcmp(argv[argi], "-v"))
            verbose = 1;
        else
            break;
        argi++;
    }
    if (argi >= argc) {
        fprintf(stderr, "usage: kverify [-s section] [-v] prog.o\n");
        return 2;
    }

    /* Old kernels charge BPF memory against RLIMIT_MEMLOCK; lift it so a
     * resource limit is never mistaken for a verifier verdict. */
    struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
    setrlimit(RLIMIT_MEMLOCK, &rl);

    size_t len;
    uint8_t *elf = read_file(argv[argi], &len);
    if (!elf) {
        perror(argv[argi]);
        return 2;
    }
    size_t code_len;
    const char *sec_name;
    const void *code = find_section(elf, len, section, &code_len, &sec_name);
    if (!code || !code_len || code_len % 8) {
        fprintf(stderr, "no usable eBPF section in %s\n", argv[argi]);
        return 2;
    }

    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = (uint32_t)(code_len / 8);
    attr.insns = (uint64_t)(unsigned long)code;
    attr.license = (uint64_t)(unsigned long)"GPL";
    attr.log_level = 1;
    attr.log_size = sizeof(verifier_log);
    attr.log_buf = (uint64_t)(unsigned long)verifier_log;

    int fd = (int)syscall(SYS_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
    if (verbose)
        fputs(verifier_log, stdout);
    if (fd >= 0) {
        printf("ACCEPT  %s (%u insns)\n", sec_name, attr.insn_cnt);
        close(fd);
        return 0;
    }
    /* The verifier prints its statistics footer only after a program has
     * passed. If it is there and no error message is, the program was not
     * rejected by the verifier at all — the load failed afterwards, on a
     * resource limit or in the JIT. Reporting that as a verdict would be a
     * lie, so it gets its own outcome. */
    const char *why = last_message(verifier_log);
    if (!*why) {
        if (strstr(verifier_log, "processed "))
            printf("PASSED  verifier ok (%u insns), load refused: errno %d (%s)\n",
                   attr.insn_cnt, errno, strerror(errno));
        else
            printf("REJECT  no verifier message, errno %d (%s)\n", errno,
                   strerror(errno));
        return 1;
    }
    printf("REJECT  %s\n", why);
    return 1;
}
