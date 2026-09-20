#!/bin/sh
# Same object file, two verifiers: espbpf's and the one in the running kernel.
# Needs clang with the BPF target, and CAP_BPF for bpf(BPF_PROG_LOAD).
set -u
cd "$(dirname "$0")/.."

CLANG=${CLANG:-clang}
OUT=build/compare
mkdir -p "$OUT"

[ -x build/bpfrun ] || make build/bpfrun >/dev/null || exit 1
cc -O2 -Wall -Wextra -o build/kverify compare/kverify.c || exit 1

# Loading a BPF program needs CAP_BPF, and on most distributions unprivileged
# BPF is disabled outright. Without it there is no kernel verdict at all —
# which is a different thing from the kernel rejecting the program, and must
# not be printed as one.
KVERIFY=./build/kverify
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        echo "note: the kernel side needs root — asking sudo"
        KVERIFY="sudo ./build/kverify"
    else
        echo "note: not root and no sudo — the kernel column will stay empty"
    fi
fi

printf 'kernel: %s\n\n' "$(uname -r)"

for src in compare/cases/*.c; do
    name=$(basename "$src" .c)
    $CLANG -O2 -g -target bpf -mcpu=v4 -ffreestanding -Icompare/cases \
        -c "$src" -o "$OUT/$name.o" || exit 1

    # kverify prints a verdict on stdout and nothing else; if stdout is empty
    # it never got one (denied, or the file was unusable).
    k=$($KVERIFY -s socket "$OUT/$name.o" 2>/dev/null | head -1)
    [ -n "$k" ] || k="(no verdict — bpf(BPF_PROG_LOAD) needs root)"
    e=$(./build/bpfrun -s socket "$OUT/$name.o" 2>&1 | tail -1 | sed 's/^ *//')
    case "$e" in
        ok:*) e="ACCEPT  $e" ;;
        *)    e="REJECT  $e" ;;
    esac

    printf '%s\n  linux   %s\n  espbpf  %s\n' "$name" "$k" "$e"
done
