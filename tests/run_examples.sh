#!/bin/sh
# Examples must verify and run; tests/bad programs must be rejected.
set -u
cd "$(dirname "$0")/.."
fail=0

for o in build/examples/*.o; do
    if ./build/bpfrun -t 25,21.5,21,23,24.5,19 -H 50 "$o"; then
        echo "  ok  $o"
    else
        echo "FAIL  $o should be accepted"; fail=1
    fi
done

echo "programs that must be rejected:"
for o in build/tests/bad/*.o; do
    if out=$(./build/bpfrun "$o" 2>&1); then
        echo "FAIL  $o was accepted"; echo "$out"; fail=1
    else
        printf '  ok  %-32s %s\n' "$(basename "$o")" "$(echo "$out" | tail -1 | sed 's/^ *//')"
    fi
done
exit $fail
