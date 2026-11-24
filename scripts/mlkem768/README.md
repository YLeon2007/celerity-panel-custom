# Offline ML-KEM-768 portable backend

`src/utils/mlkem768/mlkem768.wasm` is a `wasip1/wasm` reactor built with the Go
1.26.5 standard library ([source tag `go1.26.5`](https://github.com/golang/go/tree/go1.26.5/src/crypto/mlkem)).
No third-party runtime packages or platform binaries are used. `GO-LICENSE` and
`GO-PATENTS` beside the artifact come unmodified from that Go release. The
local Linux/amd64 toolchain used for the artifact had these SHA-256 digests:

```text
8da5fd321795754b994c64e3eb8a5a14ff47bd285559a7e876f3c79abafc67f9  bin/go
10c67b9de41c1e546b9bf416ceef410e5e3dd87a76d129b08b74a9570db9c463  pkg/tool/linux_amd64/compile
e58a36e6550a32ed7175cd6e2a1824dc66c034d1e3539ebeac8af719a9150d5d  pkg/tool/linux_amd64/link
```

## Rebuild and verify

Use an already installed, trusted Go 1.26.5, Python 3, and an existing private
scratch directory. From the repository root:

```sh
python3 scripts/mlkem768/rebuild.py /absolute/path/to/go /absolute/private/scratch
node --test src/services/tests/mlkem768Portable.test.js
```

The rebuild uses a fresh cache, no module or toolchain downloads, and no VCS
metadata. It pins the reactor's single linear memory at 64 pages (4 MiB), then
compares the complete output with the checked-in binary. Expected size:
**2,407,226 bytes**. Expected SHA-256 (also checked before runtime compilation):
`3877680a811f50bd948dd0ad9bfb83214df267fc3e4376f22aad5edcfd9790a0`.
For an intentional update, pass `--candidate` to write a new file to the given
scratch directory, review the changes and re-run the KAT before replacing the
artifact and updating the loader and rebuild pins.

## Interface and known-answer tests

The JavaScript loader accepts exactly 64 bytes (`d || z`) and returns the
1,184-byte encapsulation key as unpadded base64url. The reactor has no usable
file descriptors, network, shell, environment or stdin. Go has only a clock,
empty argv/env and host entropy for its runtime; key derivation is deterministic.
The compiled module is lazy and cached, but every derivation gets a fresh linear
memory, wiped in `finally` and discarded. This is best-effort secret cleanup,
not protection against process dumps. Go/WASM is not a validated FIPS module;
Node's FIPS mode does not select it. The synchronous operation is restricted to
key generation and pair validation, not subscription rendering.

The portable and native ML-KEM KAT uses `d`, `z` and SHA-256 of the published `ek`
from [NIST ACVP-Server ML-KEM-keyGen-FIPS203](https://github.com/usnistgov/ACVP-Server/tree/f38183487eebff2952da0e5a3441371218acfe3f/gen-val/json-files/ML-KEM-keyGen-FIPS203),
group 2, case 26. The vector came from the offline copy in Cloudflare CIRCL
v1.6.5 (`kem/mlkem/testdata/ML-KEM-keyGen-FIPS203`), not from Go or OpenSSL
output. CIRCL is not a runtime or build dependency. SHA-256 of the source
fixtures in that copy:

```text
1daed3c5730a9cf22ab85858173004e66510339352b600abcd969fc2508f06bc  prompt.json.gz
a02dcd5d9112588bd9c309d985bf22a2c4c63bb8393d1c17f6cdb14ed7d83bd9  expectedResults.json.gz
```

The same test uses the Alice X25519 public-key vector from RFC 7748 §6.1.
