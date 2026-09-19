#!/usr/bin/env python3
"""Extract the 'sensor' section from eBPF objects as fuzz_verify seeds."""
import os
import subprocess
import sys
import tempfile

out_dir = sys.argv[1]
objcopy = next((c for c in ("llvm-objcopy", "llvm-objcopy-18") if subprocess.run(
    ["which", c], capture_output=True).returncode == 0), None)
if not objcopy:
    sys.exit("llvm-objcopy not found")
for obj in sys.argv[2:]:
    with tempfile.NamedTemporaryFile() as t:
        subprocess.run([objcopy, "-O", "binary", "--only-section=sensor", obj, t.name], check=True)
        code = bytearray(open(t.name, "rb").read())
    for i in range(0, len(code) - 7, 8):
        if code[i] == 0x18:                     # lddw -> &rodata[0]
            code[i + 1] = (code[i + 1] & 0x0F) | 0x20
            code[i + 4:i + 8] = b"\0\0\0\0"
    # first byte selects writable ctx in the harness
    open(os.path.join(out_dir, os.path.basename(obj) + ".bin"), "wb").write(b"\0" + code)
