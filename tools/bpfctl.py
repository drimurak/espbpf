#!/usr/bin/env python3
"""bpfctl — talk to an espbpf board over Wi-Fi.

  bpfctl.py <ip> load prog.o      verify on the board and attach
  bpfctl.py <ip> unload
  bpfctl.py <ip> status
  bpfctl.py <ip> dump             disassembly of the attached program
  bpfctl.py <ip> pins             pin map the firmware is actually using
  bpfctl.py <ip> trace            follow trace() output (Ctrl-C to stop)

Set ESPBPF_TOKEN in the environment if the firmware requires auth.
Debug info is stripped before upload when llvm-strip is available.
"""
import os
import shutil
import socket
import subprocess
import sys
import tempfile

PORT = int(os.environ.get("ESPBPF_PORT", "5555"))


def connect(host):
    s = socket.create_connection((host, PORT), timeout=10)
    token = os.environ.get("ESPBPF_TOKEN")
    if token:
        s.sendall(f"AUTH {token}\n".encode())
        reply = s.makefile("r").readline()
        if not reply.startswith("OK"):
            sys.exit(reply.strip())
    return s


def read_reply(s):
    """Print lines until OK/ERR; return exit code."""
    f = s.makefile("r")
    for line in f:
        print(line.rstrip())
        if line.startswith("OK"):
            return 0
        if line.startswith("ERR"):
            return 1
    return 1


def stripped(path):
    strip = shutil.which("llvm-strip") or shutil.which("llvm-strip-18")
    data = open(path, "rb").read()
    if not strip:
        return data
    with tempfile.NamedTemporaryFile(suffix=".o", delete=False) as t:
        t.write(data)
    try:
        subprocess.run([strip, "-g", t.name], check=True)
        return open(t.name, "rb").read()
    except subprocess.CalledProcessError:
        return data
    finally:
        os.unlink(t.name)


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    host, cmd = sys.argv[1], sys.argv[2]
    s = connect(host)
    if cmd == "load":
        elf = stripped(sys.argv[3])
        print(f"uploading {len(elf)} bytes")
        s.sendall(f"LOAD {len(elf)}\n".encode() + elf)
        sys.exit(read_reply(s))
    if cmd in ("unload", "status", "dump", "pins"):
        s.sendall(f"{cmd.upper()}\n".encode())
        sys.exit(read_reply(s))
    if cmd == "trace":
        s.sendall(b"TRACE\n")
        s.settimeout(None)
        try:
            for line in s.makefile("r"):
                print(line.rstrip(), flush=True)
        except KeyboardInterrupt:
            pass
        return
    sys.exit(f"unknown command {cmd}\n{__doc__}")


if __name__ == "__main__":
    main()
