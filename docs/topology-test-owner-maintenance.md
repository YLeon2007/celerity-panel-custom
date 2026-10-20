# TEST-only held physical config-owner maintenance

Source-only; no SSH, live TEST/PROD, systemd, Docker, isolation parser or runner
changes are performed by this slice. This is **not** shared-host handback and does
not enable a production path.

## Implemented seam

`createRootTestPhysicalAuthority` retains its ordinary fixed private root-owned
config and TEST eligibility checks. Its held capability now implements
`withVerifiedMaintenance({ binding, proofRef }, work)`. The existing
`TopologyExecutionAuthorityLifecycle.withVerifiedMaintenance` forwards it only
inside `lifecycle.run(...)`, with awaited, one-shot callbacks and scoped checks.
This is a real implementation for `TopologyConfigTransfer`'s existing evidence
contract, not a supplied proof callback or owner-row seed. Pass the bound method:

```js
const transfer = new TopologyConfigTransfer({
    executionContext: TEST,
    TopologyConfigOwner, // actual same-connection registered model/index
    withVerifiedMaintenance: lifecycle.withVerifiedMaintenance.bind(lifecycle),
});
await lifecycle.run(async () => {
    const classic = await transfer.initializeClassic({ node, profile, nodeIdentity });
    const adopted = await transfer.adopt({ node, profile,
        generation: classic.generation, proofRef: acceptedOriginalRef });
    // Explicit public store.preEnroll uses adopted.generation, independently
    // checked endpoint/boot and the SAME held lifecycle's binding authority.
});
```

This example is an internal API composition, not a runnable inventory, HTTP/MCP
route or automatic startup migration. Parent integration owns when it is invoked.
Missing owner/index/accepted evidence still refuses; never raw-seed topology
ownership or copy a document's `originalSnapshot` to impersonate readback.

## Independent original pins

Each eligible node entry in `/etc/celerity/topology-test-physical.json` may have
exactly this additional field. Its values must be separately accepted by the
operator **before** constructing the controller, not taken from a response:

```text
originalSnapshot:
  proofRef: bounded [A-Za-z0-9][A-Za-z0-9._-]{0,127} evidence reference
  configSha256: 64 lowercase hex characters, SHA256 of accepted original bytes
  unitSha256: 64 lowercase hex characters, SHA256 of accepted original bytes
  serviceActive: active | inactive
  serviceEnabled: enabled | disabled
```

The config's existing root-owned/non-symlink/non-writable ancestor checks apply.
Absent pins leave binding/runner authority compatible but **cannot authorize an
owner transfer**. The controller clones/freezes pins before any await and checks
exact TEST context, node/profile, physical machine/key, generations, fixed paths,
proof reference, all five guard/boot/plan/endpoint identities and shared old-backend
identity. Caller binding/path fields only correlate; they do not select paths.

## Actual bytes and service readback

The installed read-only `physical_attestor.py` keeps its exact existing request
`{ nonce, predecessor }`. No opcode, arbitrary command, upload, restoration,
SFTP, shell or runner grammar is introduced. Its observation additionally has
`configTransfer`, containing canonical bounded base64 config/unit bytes and a
`source: node-readback` digest/state projection. Existing installation,
predecessor, terminal, physical and guard observations remain intact.

Only these current profile files are read:

* main: `/usr/local/etc/xray/config.json`,
  `/etc/systemd/system/xray.service`, `xray.service`;
* bridge: `/usr/local/etc/xray-bridge/config.json`,
  `/etc/systemd/system/xray-bridge.service`, `xray-bridge.service`.

Each is a root:root regular non-writable-by-group/world file reached through the
existing descriptor-walk reader. Each file is bounded to 512 KiB. Symlinked,
missing, alternative or masked fragments, drop-ins, pending jobs, unknown service
states and changing bytes refuse. Actual `Host.unit` (`systemctl show`, fixed
service only) must report the exact loaded fragment, no drop-ins/jobs, stable
active/inactive and enabled/disabled state on both sides of the read. Exact bytes
are read twice. `observe` checks actual held isolation on both sides as before.
There is no interpretation of config contents and no path from request to argv.

The application validates canonical base64, size, actual hashes and independent
pins. On adoption it retains **both original byte Buffers** in a lexical private
map **before** the awaited database callback, tagged with its exact next owner
generation. Mongo proofs/rows/public results contain digests/states only. The raw
private SSH observation stream contains secrets: **never tee/log/print it**.
Exceptions remain redacted. Checks reread the full hold and exact original bytes
before/after the awaited callback, including transaction and majority confirmation
inside that callback. Optional checks supplied to the caller are scoped and latch
failure even if a caller swallows it and puts bytes back. No new external read is
placed inside Mongo's retryable transaction.

A handback proof requires that this controller actually captured that adoption's
original bytes and that the current bytes **and all service states** match them
again under the same independently pinned hold. A restarted controller cannot
adopt an existing topology owner or reconstruct backup authority from Mongo.

## Error and recovery boundary

The byte cache is **process-local, not a crash-durable backup or a restoration
executor**. There is deliberately no restore command, byte-export route, automatic
restart/unmask/thaw, DB cleanup or owner release. Retain independently secured
operator backups for any real operation that can change serving bytes. A process
restart, missing capture, guard replacement/loss, drift, uncertain commit or failed
confirmation leaves maintenance/ownership retained and the controller poisoned;
it must be independently reconciled, not restarted to bless a new snapshot.
One controller permits one original capture per node, not recapture after failure.

This slice can adopt and verify unchanged/restored originals, but does not itself
restore changed files or service states. That finite restoration writer (if
needed), crash-durable backup/recovery, serving rollback and the separately owned
shared-host recovery/handback are explicit remaining operational gates. Successful
config-owner handback is only a Mongo owner transition: it does not release
external isolation, node locks/admissions, shared freezer, classic dispatch or
operation history. In particular a guard loss while a majority confirmation is
delivered can leave the owner committed as topology; the adapter rejects and
**retains** it instead of pretending the commit rolled back.

## Executable local evidence

* `test_physical_config_snapshot.py`: exact binary bytes, current file metadata,
  independent stable loaded-service observations, drift/overflow/symlink refusal;
* `testPhysicalController.test.js`: actual finite Python `serve → observe →
  config_snapshot` over real subprocess nonce pipes and scratch files; accepted
  pin/challenge/guard/state/generation negatives, escaped checks and swallowed
  failure revocation;
* same Node test with `C3_MONGOD`: actual loopback replica set, public
  `initializeClassic → adopt → actual binding store preEnroll → handback`, exact
  majority readback, no raw adopted owner, no operations/locks, plus postcommit
  guard-loss retention. Scratch database is dropped/absence checked; Mongo exits.

UID, physical/kernel/SSH/guard/systemd authority in these fixtures is explicitly
**simulated**. File bytes, codec, Python/Node protocol, lifecycle, service, models,
store, transactions and readbacks execute real repository code. The positive
handback keeps originals unchanged; it is not a filesystem/systemd restoration or
live physical/traffic acceptance. PROD remains closed at all existing guards.
