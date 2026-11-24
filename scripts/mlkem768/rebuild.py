#!/usr/bin/env python3
"""Build a candidate and compare it with the checked-in WASM (no downloads)."""

import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
SHIPPED = HERE.parent.parent / "src/utils/mlkem768/mlkem768.wasm"
EXPECTED_SHA256 = "3877680a811f50bd948dd0ad9bfb83214df267fc3e4376f22aad5edcfd9790a0"


def uleb(data, pos):
    value = 0
    for shift in range(0, 35, 7):
        byte = data[pos]
        pos += 1
        value |= (byte & 127) << shift
        if byte < 128:
            return value, pos
    raise ValueError("invalid WASM u32")


def bound_memory(data):
    # Replace Go's single defined memory32 without a max with one fixed at 4 MiB.
    # This precludes a memory grow relocating any backing store with seed material.
    if data[:8] != b"\0asm\x01\0\0\0":
        raise ValueError("not WebAssembly v1")
    pos = 8
    while pos < len(data):
        size, start = uleb(data, pos + 1)
        end = start + size
        if end > len(data):
            raise ValueError("truncated WASM section")
        if data[pos] == 5:
            pages, after = uleb(data, start + 2)
            if data[start:start + 2] != b"\x01\x00" or after != end or not 0 < pages <= 64:
                raise ValueError("unexpected Go WASM memory declaration")
            # Section 5, payload length 4, one memory, min+max present, 64 pages each.
            return data[:pos] + bytes([5, 4, 1, 1, 64, 64]) + data[end:]
        pos = end
    raise ValueError("WASM memory section missing")


def main():
    go = str(Path(sys.argv[1]).resolve(strict=True))
    scratch = Path(sys.argv[2]).resolve(strict=True)
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="mlkem-rebuild-", dir=scratch) as name:
        temp = Path(name)
        env = dict(HOME=name, PATH=os.defpath, TMPDIR=name, GOCACHE=str(temp / "cache"),
                   GOPATH=str(temp / "gopath"), GOENV="off", GOTOOLCHAIN="local", GOTELEMETRY="off",
                   GO111MODULE="off", GOWORK="off", GOPROXY="off", GOSUMDB="off", GOMAXPROCS="2",
                   GOOS="wasip1", GOARCH="wasm", CGO_ENABLED="0")
        version = subprocess.check_output([go, "version"], env=env, text=True).split()
        if version[:3] != ["go", "version", "go1.26.5"]:
            sys.exit("requires Go 1.26.5")
        raw = temp / "raw.wasm"
        subprocess.run([go, "build", "-p=2", "-trimpath", "-buildvcs=false", "-buildmode=c-shared",
                        "-ldflags=-s -w -buildid=", "-o", raw, "main.go"], cwd=HERE, env=env, check=True)
        data = bound_memory(raw.read_bytes())
        digest = hashlib.sha256(data).hexdigest()
        print(f"{digest}  ({len(data)} bytes)")
        if len(sys.argv) == 4 and sys.argv[3] == "--candidate":
            with (scratch / "mlkem768.wasm").open("xb") as output:
                output.write(data)
        elif digest != EXPECTED_SHA256 or data != SHIPPED.read_bytes():
            sys.exit("rebuilt artifact differs from checked-in WASM or its SHA-256 pin")


if __name__ == "__main__":
    if len(sys.argv) != 3 and (len(sys.argv) != 4 or sys.argv[3] != "--candidate"):
        sys.exit("usage: rebuild.py /path/to/go /path/to/private-scratch [--candidate]")
    main()
