# Offline classic root bundle producer — candidate only

`classic_root_bundle.py` builds bytes for `fresh_classic_launch.verify_files`
and the actual-files closure enforced by `Platform.check`. It **does not**
install anything, fabricate policy/inventory, change ownership, mount, start
services, or emit GO. `physicalAccepted` is always `false`.

## Inputs and fixed paths

- `--source-allowlist`: JSON with `repo`, exact 40-hex committed `commit`, and
  absolute payload `files`. Application files are mapped from `/app/<git-path>`.
  Only Git regular blobs (`100644` or `100755`) are allowed. Gitlinks, links,
  uncommitted files, reserved `node_modules` source paths, `.env`/`.env.*`, `.git`
  and `logs` path components refuse; no ambient working-tree bytes are copied.
- Optional `pins` in the same allowlist is an **exact** SHA-256 map of the
  selected fixed supervisor paths below. Each source is read from the same
  committed revision and compared with that separately supplied digest:

  | Payload path | Committed source under `scripts/test-node-isolation/` |
  |---|---|
  | `/usr/local/libexec/c3-test-coordinated-restore.py` | `coordinated_restore.py` |
  | `/usr/local/libexec/c3-test-fresh-classic.py` | `fresh_classic_launch.py` |
  | `/usr/local/libexec/c3-test-fresh-prepare.py` | `prepare_fresh_supervisor.py` |

  These are offline source pins, **not** installed-source acceptance.
- `--node-modules`, `--package-lock`, `--snapshot-index`: lock-exact installed
  dependency inputs. Snapshot JSON maps **every materialized root file path**
  `/app/node_modules/...` to `{ "sha256": <digest>, "size": <integer> }`.
  Zero-byte files are valid. For a symlink alias, the pin describes the actual
  resolved target bytes at the alias payload path, **not** the link string or
  a marker file. Directory aliases expand into separately pinned files.
  Escapes, dangling links, directory cycles, special files, xattrs, missing or
  unexpected snapshot entries, read/tree drift and version drift refuse.
  Reads retain the opened file identity and open resolved components with
  `O_NOFOLLOW`; bytes are hashed and written from the same read buffer. The
  copied package versions are checked again against the lock. Installed roots
  are distinguished from package.json files inside package examples/lib data.
- `--node-executable` and `--node-digest` independently pin `/runtime/node`.
- `--runtime-inputs`: optional explicit `classic_runtime_inputs.py` proposal
  (`kind: offline-runtime-inputs`, `physicalAccepted: false`). The reviewed
  `verify` function rechecks all source bytes; each file is read and checked
  again while copying. Allowed targets are `/runtime/node`, `/usr/bin/python3`,
  `/usr/lib/python3.13/...`, `/lib/...`, `/lib64/...`; the absolute ELF interpreter
  `/lib64/ld-linux-x86-64.so.2` is required. True executables retain execute
  permission. The proposal is not an accepted inventory or dlopen-completeness
  assertion.
- `--elf-allowlist`: legacy explicitly hashed `/runtime/lib/...` additions;
  `{}` is appropriate with the complete runtime proposal. That legacy layout
  alone is **not** enough to satisfy an absolute ELF interpreter.
- `--settings`: private, singly linked, non-symlink regular JSON input, at most
  16384 bytes and not group/world writable. Only strict BOM-free UTF-8 JSON is
  accepted; UTF-8 BOM and UTF-16/32 are refused before publication, because the
  actual application decodes UTF-8 without stripping BOM. The supported application
  schema is `version`, `context`, `stateDirectory`, `listenAddress`,
  `environment` — **not** the obsolete mode/flags/statePath/ingress fixture.
  Version is integer `1`, context `test.infograd.online`, state `/state`, address
  `212.119.42.100`, environment port string `3000`. Environment keys match
  `src/classicSettings.js` exactly; all five `*ENABLED` flags are string `false`,
  `USE_CADDY` is string `true`, and required URI/email/key/secret values must
  validate. Secrets are permitted required inputs, never printed or included
  in report values. The exact validated input buffer becomes `/etc/classic.json`;
  the producer does not reopen a potentially changed settings file for copying.

The verified real dependency snapshot has **409 lock package paths, 399 installed
packages, 10 explicitly foreign-platform optional absences**. Its package-lock
SHA-256 is `5298202cf6ca2ce8da44f0578bd54c1146def29fd698c41bc62ac3b5982e6eac`.
Snapshot hashes establish installed-byte identity, not npm archive integrity.

## Output/publication

`<output>/root` contains regular singly linked files only, no xattrs, links or
devices, each at most 256 MiB. Root and all payload directories are `0755`;
regular source/config/library files are `0644`, executables `0755` (no suid,
sgid or group/world-write bits). The **outer candidate directory is `0700`**,
so private settings remain protected before a separately authorized installer
handles ownership and sealed-root setup. No dedicated-UID traversal across that
private outer directory is claimed.

`manifest.json` is the deterministic sorted complete payload file SHA-256 map;
`report.json` contains counts, committed source identity, supervisor pins,
settings key/type metadata and explicit pending acceptance gates. The policy
`/etc/c3-test-fresh-classic.json` is never manufactured or included in the map.
`/state` and `/proc` are not populated by the producer.

The whole root, manifest and report stage in a new private sibling. Final bytes
are rehashed against the complete manifest before publication. Linux
`renameat2(RENAME_NOREPLACE)` publishes the candidate atomically; there is no
check-then-overwriting-rename fallback. Existing targets (including empty
racing directories or dangling links) refuse. Failure removes only this
invocation's stage and leaves prior output untouched. Filesystem and unexpected
input failures become stable redacted codes, not exception paths/JSON/URIs.
This is atomic publication, not a crash-durable installation protocol.

## Bounded local verification

Run only the owned test module, with bytecode disabled:

```sh
PYTHONDONTWRITEBYTECODE=1 hermes-heavy python3 -B -m unittest test_classic_root_bundle -v
```

Tests use tiny fixtures for fault boundaries, the actual application settings
reader, real pinned Node, the real lock tree, the real 680-file runtime proposal
and real `fresh_classic_launch.verify_files` over constructed bytes. Separate
full-bundle replay must use the parent's actual app harness with real local
Mongo/Redis and copied Node, no `NODE_PATH`, two serving generations and finite
SIGTERM/SIGINT shutdown. Use a fresh evidence directory and retain failed logs.
Tests must not modify the original fixed candidate settings; local loopback
settings and mutable state live outside the payload.

Local serving and explicit-candidate-loader runtime probes are **not** chroot,
root-owned read-only mounts, namespaces, dedicated UID, live TEST ingress,
accepted inventory, operational maintenance authority or physical acceptance.
Those remain independent gates with the integration/platform owner.
