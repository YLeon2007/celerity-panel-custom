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

## Explicit B132 TEST runtime `/etc` data

`--etc-inputs /absolute/private/etc-inputs.json` selects the additive
`b132-test` data layout. It is **not** a general copy allowlist. The JSON has
exactly these keys:

```json
{
  "version": 1,
  "context": "test.infograd.online",
  "layout": "b132-test",
  "files": {
    "/etc/hosts": {"source": "/private/hosts", "sha256": "<64 lowercase hex>", "size": 551, "mode": 420},
    "/etc/nsswitch.conf": {"source": "/private/nsswitch.conf", "sha256": "<64 lowercase hex>", "size": 526, "mode": 420},
    "/etc/resolv.conf": {"source": "/private/resolver", "sha256": "<64 lowercase hex>", "size": 784, "mode": 420},
    "/etc/ssl/certs/ca-certificates.crt": {"source": "/private/ca-bundle", "sha256": "<64 lowercase hex>", "size": 180744, "mode": 420}
  }
}
```

The illustrative paths/digests are placeholders, **not executable accepted
inputs**; sizes above describe the observed B132 copies, not universal pins.
Supply separately reviewed real bytes and their exact digests/sizes. All four
paths are mandatory; extra targets (including settings, policy or trust-path
aliases) refuse. `mode` is the integer decimal `420` (`0644`), never executable.
The proposal and every source must be singly linked regular **0600** files,
without xattrs, reached through canonical absolute paths without any symlink
hop. Each data file is nonempty and at most 2 MiB; proposal at most 16 KiB.
Reads use `O_NOFOLLOW|O_NOATIME`, check stable descriptor metadata, hash and size,
and write the same checked buffer. No noatime-permission fallback exists.

Every delivered file joins the existing complete manifest and both final image
checks. The report adds `etcInputs` (layout and target-only hash/size/mode pins)
and `counts.etcFiles`; it includes neither raw data nor private source paths.
The unchanged private settings input remains byte-for-byte `/etc/classic.json`.
Without this option the old producer/CLI/report behavior remains available; it
is **not** evidence of the new B132 data layout. An explicitly empty option,
missing input, incomplete layout, changed hash/size or outside target refuses
without publishing. Existing output is never amended/replaced. A future full
B132 root must be a fresh independently reviewed candidate, not an augmentation
of the previously accepted manifest/root.

### Actual consumers and the network-owner handoff

- `fresh_network.Linux.preflight` reads
  `/var/lib/c3-test-fresh-input/root/etc/hosts` and compares its bytes with the
  independently supplied `hostsSha256`. Set that field to the new manifest's
  **exact `/etc/hosts` digest** only after acceptance. This producer does not
  publish a network plan or install that path.
- Node's ordinary hostname socket resolution uses `dns.lookup`/libc
  `getaddrinfo`; NSS selects files/DNS. The observed B132 `nsswitch.conf` has
  `hosts: files dns`. Resolver data also serves c-ares DNS consumers. Do not
  create backend/DB aliases as a substitute for the real endpoint contract.
- B132 `/etc/resolv.conf` is a symlink to the host's systemd stub. The observed
  regular `/run/systemd/resolve/resolv.conf` contains upstream
  `nameserver 77.88.8.8` (and `search .`); its exact privately captured bytes can
  be proposed for **regular** `/etc/resolv.conf`. No blind host-stub copy,
  invented hostname or automatically harvested resolver is supplied by code.
  This is a genuine upstream **source**, not a private-netns reachability proof.
- B132's regular `/etc/ssl/certs/ca-certificates.crt` is a genuine PEM trust
  source. The file delivers explicit trust data only. Node can use its bundled
  roots; Python/OpenSSL may default to a different compiled path. Do not claim
  that placing this file configures every TLS consumer or add symlink aliases,
  environment switches or settings changes here. Full runtime/trust-path
  acceptance remains separate.
- Actual application callers are `index.js:connectMongo` →
  `mongoose.connect(config.MONGO_URI)` and `cacheService.connect` →
  `new Redis(process.env.REDIS_URL)`. Accepted settings select numeric
  `127.0.0.1:27017` / `127.0.0.1:6379`; `/etc/hosts` cannot remap numeric IPs.
  Mongo selects `replicaSet=rs0&directConnection=true&authSource=admin`.
  Direct mode selects the seed rather than discovering advertised replica
  endpoints; it does **not** prove primary/set compatibility or DB readiness.
  Retain credentials/settings unchanged and have the existing network
  constructor map those exact loopback endpoints to independently pinned
  original containers. No DB command or advertisement observation is part of
  this producer repair.
- The existing network output policy admits only loopback, established traffic
  and exact Mongo/Redis TCP destinations. DNS/TLS egress is not implied by file
  presence. Network-owner acceptance must keep that restriction explicit;
  there is no new DNS service, proxy, general NAT or egress exception here.

The source-only handoff consists of these four exact target pins, the new
complete manifest, and independently accepted network endpoint/routing facts.
Neither producer output nor a small file-check fixture is physical root,
DNS/TLS, database, live application or launch acceptance.

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
and real `fresh_classic_launch.verify_files` over constructed bytes.

The tests accept `C3_ROOT_BUNDLE_ETC_INPUTS` for the private B132 proposal; they
copy its pinned real data into disposable 0600 fixture inputs. Without it, only
the four named public local data files are used as explicitly labeled unit
fixture sources, never by the producer. `C3_ROOT_BUNDLE_LOCK_SOURCE` relocates
the existing dependency fixture (the exact historical lock digest/count/version
assertions remain), and `C3_ROOT_BUNDLE_RUNTIME_INPUTS` permits an unchanged
private proposal copy instead of reading a frozen original. Neither changes
producer defaults/acceptance or qualifies local fixture bytes for B132.

Separate full-bundle replay must use the parent's actual app harness with real local
Mongo/Redis and copied Node, no `NODE_PATH`, two serving generations and finite
SIGTERM/SIGINT shutdown. Use a fresh evidence directory and retain failed logs.
Tests must not modify the original fixed candidate settings; local loopback
settings and mutable state live outside the payload.

Local serving and explicit-candidate-loader runtime probes are **not** chroot,
root-owned read-only mounts, namespaces, dedicated UID, live TEST ingress,
accepted inventory, operational maintenance authority or physical acceptance.
Those remain independent gates with the integration/platform owner.
