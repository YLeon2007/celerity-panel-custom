# Finite TEST legacy topology release (CURRENT baseline, not restoration)

Internal API only; no HTTP/MCP/startup path and no environment bypass. Original topology operations are never updated, deleted, renamed or moved. Native owners/enrollments/bindings must remain empty: this does not initialize or fabricate any of them. Both `TOPOLOGY_TEST_EXECUTION_ENABLED` and `TOPOLOGY_PRODUCTION_EXECUTION_ENABLED` must be the literal string `false` throughout maintenance and recognition.

## Parent-operated root entry API

```js
const { TestLegacyTopologyRelease } = require('./src/services/testLegacyTopologyRelease');
const { TEST_TOPOLOGY_EXECUTION_CONTEXT: TEST } = require('./src/modules/relay-l2tp/domain/topologyExecutionContext');
const service = new TestLegacyTopologyRelease({
  db, // connected native Mongo Db; no model autoCreate/autoIndex
  executionContext: TEST, // canonical TEST even though actual PANEL_DOMAIN is lm1.infograd.online
  expectedDeployment: { database: 'hysteria', setName: 'rs0', replicaSetId: '6ab3717b28a9e4d82b5ee86a' },
  acceptedBaseline, // independently accepted private capture projection below, ordered exactly
  env: process.env,
  withVerifiedMaintenance, // trusted root-owned closure, NEVER from a request
});
const receipt = await service.retire(); // one attempt per instance; no retries/overwrite/release verb
```

This source deliberately pins that exact database + replica-set deployment. A hostname is not TEST authority. Consumption obtains the real `replSetGetConfig.settings.replicaSetId`; a clone/foreign DB or new replica set cannot reuse a receipt. The five node IDs are source-fixed, sorted:

- `6ab189dc63913ebd4a917399`
- `6ab18adc63913ebd4a917471`
- `6ab18d9c63913ebd4a917670`
- `6ab4b53bc4c0304573e06c72`
- `6ab93ad2646b4b7d2f43c907`

### acceptedBaseline schema

Array of exactly five `{node, nodeIdentity:{machineId,sshHostKeySha256}, profiles}` records in the above order. Machine ID is 32 lowercase hex; host key is SHA-256 of actual raw SSH key bytes (64 lowercase hex). Each profiles array has exactly `xray-main` then `xray-bridge`:

```js
{ profile: 'xray-main',
  config: { state:'present', sha256:'<64 hex>', uid:0, gid:0, mode:420 },
  unit: { state:'present', sha256:'<64 hex>', uid:0, gid:0, mode:420 },
  additionalUnitFiles: [ { path:'/etc/systemd/system/xray.service.d/override.conf',
    artifact:{state:'present',sha256:'<64 hex>',uid:0,gid:0,mode:420} } ],
  serviceActive:'active', serviceEnabled:'enabled' }
```

Explicit file absence is exactly `{state:'absent'}`. `mode` is an integer permission bitmask, not an octal string. Active states are `active|inactive`; enabled states `enabled|disabled|masked|not-found`. An absent unit requires inactive/not-found, but **absent config with present, loaded, inactive unit is supported**. Main and bridge active states are independent. Additional unit files must be the complete sorted actual drop-in/extra-file inventory (empty array is explicit absence); each absolute path is scoped to that profile's systemd unit/drop-in directory and has an actual artifact record. All ten profiles must be observed, not just the historically selected profile. Retain raw captures/backups privately; this receipt stores digests and metadata, not restoration bytes.

### withVerifiedMaintenance({binding}, work)

The service supplies a deeply frozen challenge containing `version:1`, `action:'accept-current-test-legacy-baseline'`, `receiptId:'test-legacy-current-v1'`, random UUID `nonce`, canonical TEST context, actual `panelHost`, complete deployment identity, canonical full `historySha256`, all-five endpoint/credential binding hashes, independently accepted baseline, fixed per-profile paths, and finite epoch-millisecond `deadline`.

The **trusted** adapter must independently verify the complete binding against accepted pins and live facts, then invoke and await exactly once:

```js
await work({
  authority:'test-legacy-maintenance-v1', binding,
  proofId:'<UUID>', maintenanceId:'<UUID>',
  oldBackend:{instanceId:'<exact container id>',pid:728546,processStartTime:'<start ticks>',
              processTree:'stopped',dispatch:'disabled'},
  async recheck(exactBinding) {
    // Actual independent held-root channel + NodeSSH observations, not copies.
    // Re-prove exact old backend/cgroup retirement, future-dispatch exclusion,
    // no competing backend/SSH/artifact/scheduler writer, no pending systemd jobs,
    // actual physical identities, endpoints, config/unit/drop-in bytes/permissions,
    // loaded unit/fragment inventory, independent service active/enabled states.
    // Compare independently accepted pins; throw on drift, EOF or uncertainty.
    return actualFreshBaselineProjection;
  }
});
// Recheck actual held exclusion after work before returning from the adapter.
```

A copied `binding`, marker, process inventory, stopped flag, or declaration is **not** a live attestor. `recheck` must perform the actual observations on **every** call and retain exclusion while Mongo operations await. It must authenticate its private channel and hold the real stopped-backend/dispatch boundary continuously. The source checks repeated baseline equality, deadlines, live callback scope and DB state before provisioning, immediately before insert, after insert and after majority readback. Escaped/reused/non-awaited callbacks refuse. Swallowed attestation failures poison the attempt. Existing independently running old writers cannot be excluded by a DB row.

## Durable evidence / recognition

Maintenance alone explicitly creates `testlegacytopologyreleases`; runtime does no DDL. Insert-only fixed `_id` allows exactly one record. Existing namespace collision, duplicate, read/write uncertainty or postcommit loss is UNKNOWN_RETAINED, not retryable success. Keep all external holds on every error, including error after a possibly durable insert. A durable receipt may exist after an unacknowledged insert/post-write attestation failure; **never resume automatically**. Independently reconcile while still held. There is no delete/rollback/retry helper or release command.

Receipt fields are exact: `_id,version,executionContext,panelHost,deployment,nodeBindings,historySha256,acceptedBaseline,proofId,maintenanceId,oldBackend,acceptedAt`. Each node binding has exactly `node,endpointCredentialSha256`; private SSH material and agent token are hashed, never included. History hashing canonicalizes all BSON fields with canonical Extended JSON, preserving types and array order; document order/object key order are normalized. It includes **every** topology operation, not merely terminal rows matching one node. Added/deleted/edited history or endpoint/credential drift invalidates the receipt.

The unchanged historical veto query remains in `topologyConfigOwnership`; only a valid scoped receipt can override its result. Native topology owners or malformed/native enrollment state remain vetoes/refusals. Any nonterminal/held topology operation, retained admission, drain or replacement reservation refuses. Reader uses bounded native primary/majority reads with no model registration. Complete history/node/native/admission state is re-read at consumption. Transfer baseline bytes are **not compared to future generated classic/L2TP config forever**; legitimate ordinary generated configuration, users and telemetry may change.

Maintenance requires zero locks/active remote admissions and terminal L2TP/intents/empty queue work. Recognition does not authorize a competing active writer: an existing classic/L2TP lock is accepted only inside the real already-held `classicNodeConfigWrite` async scope, whose exact persisted generation/lease is independently revalidated. Active remote admissions must then be running for that same node and operation. It does not acquire/release locks or admit work, and does not alter general runner behavior.

## Evidence boundary

The external physical/root attestor and finite stop/restart entry are **parent-owned and not implemented here**. This service provides the concrete callback and persistence/consumer implementation for that entry; it does not stop Docker, run SSH, install anything or assert the current backend is stopped. Local tests explicitly simulate physical authority. No physical TEST activation, L2TP connectivity, PROD PASS or PROD mutation is claimed. Parent must independently review the exact source/commit, integrate it, implement the trusted adapter, then exercise the real held maintenance before activation.

## Bounds and local verification

- One 300-second challenge; each DB operation uses a 5-second bound. Each scanned namespace is limited to 1,000 documents and 32 MiB canonical evidence, otherwise fail closed. All topology operation contexts must be absent legacy context or canonical TEST, and all historical node references must belong to the five pinned IDs.
- Runtime recognition deliberately requires either zero active locks/admissions, or one exact current-node held classic/L2TP lock with only its matching running admissions. It does not authorize concurrent unrelated retained work. No counters/locks/admissions are changed by the receipt service.
- The adapter must exclude competing DB/DDL maintenance too. Absence is explicitly checked with `listCollections` before provisioning; this read is not a lock against a separate privileged actor. Mongo can acknowledge a compatible pre-existing collection, so no inference of exclusive creation may replace that external exclusion.
- Root capture's digest of an SSH `.pub` **file** is not the raw SSH wire-key digest. Obtain the latter independently for `nodeIdentity.sshHostKeySha256`; never relabel a file digest. Convert captured octal permission strings to integer mode values explicitly in the trusted entry.
- Serial local verification: **205 passed, 0 failed/cancelled/skipped**, natural exit, across the new release tests, existing ownership tests, classic writer tests and topology runtime composition tests. RED logs cover absent implementation, foreign contexts/history, missing drop-in evidence, missing guard integration, callback/flag lifetime bugs, native BSON identity type and existing-namespace refusal. A first regression launch lacked `ACME_EMAIL` and failed before that unchanged fixture loaded; its log is retained separately.
- Tests use real service/guard code, BSON encoding and existing held-write scope, with simulated persistence/physical authority. No local `mongod` binary was available; **real Mongo command/DDL behavior is not verified by this slice**. Dependencies were borrowed read-only from `/home/leon/celerity-panel-custom/node_modules`: MongoDB driver 6.20.0 matches the lockfile; Mongoose 8.23.0 differs from locked 8.24.1. This is qualified source-unit evidence, not a lock-exact bundle or activation result. Detailed evidence and dependency comparison are under `l2tp-fastpath-20261026/legacy-compat-implementation/` outside the worktree.
