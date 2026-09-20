#!/bin/sh
# Same object file, two verifiers: espbpf's and the one in the running kernel.
# Needs clang with the BPF target, and CAP_BPF/root for bpf(BPF_PROG_LOAD).
set -u
cd "$(dirname "$0")/.."

CLANG=${CLANG:-clang}
OUT=build/compare
mkdir -p "$OUT"

[ -x build/bpfrun ] || make build/bpfrun >/dev/null || exit 1
cc -O2 -Wall -Wextra -o build/kverify compare/kverify.c || exit 1

printf 'kernel: %s\n\n' "$(uname -r)"

for src in compare/cases/*.c; do
    name=$(basename "$src" .c)
    $CLANG -O2 -g -target bpf -mcpu=v4 -ffreestanding -Icompare/cases \
        -c "$src" -o "$OUT/$name.o" || exit 1

    k=$(./build/kverify -s socket "$OUT/$name.o" 2>&1 | head -1)
    e=$(./build/bpfrun  -s socket "$OUT/$name.o" 2>&1 | tail -1 | sed 's/^ *//')
    case "$e" in
        ok:*) e="ACCEPT  $e" ;;
        *)    e="REJECT  $e" ;;
    esac

    printf '%s\n  linux   %s\n  espbpf  %s\n' "$name" "$k" "$e"
done
