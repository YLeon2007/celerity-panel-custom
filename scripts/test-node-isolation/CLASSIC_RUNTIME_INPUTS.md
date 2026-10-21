# Offline runtime inputs — not physical root acceptance

`classic_runtime_inputs.py` proposes explicit, locally hashed Node/Python/stdlib
and recursive ELF interpreter/DT_NEEDED inputs for a separate filesystem root
producer. It never invokes ldd, the inspected binaries, a shell, an installer,
network operations, namespaces, mounts, cgroups, services or privileged commands.
Only ELF64 little-endian x86-64 is supported. RPATH/RUNPATH, noncanonical loader
paths, escaping library symlinks, ambiguous/missing libraries and source drift
refuse. Shared libraries must resolve inside explicitly supplied directories;
virtual library destinations use the supported Debian x86-64 loader search path.
Each explicit interpreter path is also materialized, not installed as a symlink.

The supported Python payload layout is `/usr/bin/python3` with stdlib under
`/usr/lib/python3.13`. Stdlib internal file symlinks are materialized, external
ones refuse. Symlinked directories refuse. Host sitecustomize/usercustomize,
site-packages/dist-packages, bytecode caches and development config-* directories
are deliberately omitted; this avoids importing host startup customization.
All files are rehashed at the end and proposals carry `physicalAccepted=false`.

Example capture (all inputs are operator-selected candidates, not authority):

```
python3 -B classic_runtime_inputs.py \
  --node /explicit/node --python /explicit/python3 \
  --stdlib /explicit/python3.13 \
  --library-directory /explicit/x86_64-libraries \
  --output /private/new-runtime-inputs.json
```

The output is mode0600 and exclusive-create. No overwrite/adoption/retry is
implemented. Each entry has `source`, `target`, `sha256`, `executable`; these are
inputs to a separately reviewed materializing producer, not executable policy.
A proposal is not an accepted source-pin authority. No live PID, namespace,
root/mount, fd, route or loaded-unit pin is produced. Do not splice proposal data
into an already-held Coordinator config or assert that ownership is installed.

## What remains to prove

- The separate producer must verify the captured hashes again and materialize
  new regular files with no xattrs/hardlinks/symlinks and an exact manifest.
- ELF NEEDED closure is not a proof of all possible dlopen-by-name paths, native
  addon compatibility, operational DNS/TLS data or app/database readiness.
- Python and Node local bundle execution is a separate test. It does not prove
  chroot/private namespace/root ownership/capability/cgroup/direct-ingress facts.
- Installed root:root ownership, readonly mount and independently accepted live
  supervisor descriptors/identities remain external acceptance requirements.
- No live TEST/PROD authorization follows from construction or these tests.

`test_classic_runtime_inputs.py` covers actual local file hashing and drift,
static ELF header/bounds/interpreter/NEEDED parsing, explicit library recursion,
escaping/dangling stdlib inputs, ambient customization exclusions and a malicious
shell fixture that is refused without execution. Parser byte fixtures are not
claimed to be real system executable evidence. Actual runtime capture is recorded
separately outside this source tree.
