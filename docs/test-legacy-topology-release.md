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

Receipt fields are exact: `_id,version,executionContext,panelHost,deployment,nodeBindings,historySha256,acceptedBaseline,proofId,maintenanceId,oldBackend,acceptedAt`. Each node binding has exactly `node,endpointCredentialSha256`; private SSH material and agent token are hashed, never included. History is read once with native `find({},{raw:true,...bounds})`. The same BSON bytes are decoded separately into the ordinary semantic validator view and lossless fingerprint view (`promoteValues:false,bsonRegExp:true`). Canonical Extended JSON therefore preserves original Int32/Double/small Long and other BSON types plus array order; document order/object key order are normalized. Numeric wrappers are not introduced into admission/counter or execution-context validation. It includes **every** topology operation, not merely terminal rows matching one node. Added/deleted/edited history or endpoint/credential drift invalidates the receipt.

The unchanged historical veto query remains in `topologyConfigOwnership`; only a valid scoped receipt can override its result. Native topology owners or malformed/native enrollment state remain vetoes/refusals. Any nonterminal/held topology operation, retained admission, drain or replacement reservation refuses. Reader uses bounded native primary/majority reads with no model registration. Complete history/node/native/admission state is re-read at consumption. Transfer baseline bytes are **not compared to future generated classic/L2TP config forever**; legitimate ordinary generated configuration, users and telemetry may change.

Maintenance requires zero locks/active remote admissions and terminal L2TP/intents/empty queue work. Recognition does not authorize a competing active writer: an existing classic/L2TP lock is accepted only inside the real already-held `classicNodeConfigWrite` async scope, whose exact persisted generation/lease is independently revalidated. Worker admissions must then be running for that same node and operation. The simple uninstall path instead holds its real acquired standalone invocation ID in that private scope, checked against the actual `RemoteAdmissionRepository` and same-connection lock model: running `standalone_preflight`, exact `_id`/node, ownerGeneration 1, and absent operationId/leaseOwner. Those absent fields are intentional repository/schema behavior, not fabricated worker links. Recognition requires exactly that one counted standalone admission and freshly verifies the exact persisted lock owner/generation/live lease. A bare admission ID, persisted lock, receipt or request flag cannot open the scope. It does not acquire/release locks or admit work, and does not alter general runner behavior.

## Evidence boundary

The external physical/root attestor and finite stop/restart entry are **parent-owned and not implemented here**. This service provides the concrete callback and persistence/consumer implementation for that entry; it does not stop Docker, run SSH, install anything or assert the current backend is stopped. Local tests explicitly simulate physical authority. No physical TEST activation, L2TP connectivity, PROD PASS or PROD mutation is claimed. Parent must independently review the exact source/commit, integrate it, implement the trusted adapter, then exercise the real held maintenance before activation.

## Bounds and local verification

- One 300-second challenge; each DB operation uses a 5-second bound. Each scanned namespace is limited to 1,000 documents and 32 MiB canonical evidence, otherwise fail closed. All topology operation contexts must be absent legacy context or canonical TEST, and all historical node references must belong to the five pinned IDs.
- Runtime recognition deliberately requires either zero active locks/admissions, or one exact current-node held classic/L2TP lock with only its matching running admissions. It does not authorize concurrent unrelated retained work. No counters/locks/admissions are changed by the receipt service.
- The adapter must exclude competing DB/DDL maintenance too. Absence is explicitly checked with `listCollections` before provisioning; this read is not a lock against a separate privileged actor. Mongo can acknowledge a compatible pre-existing collection, so no inference of exclusive creation may replace that external exclusion.
- Root capture's digest of an SSH `.pub` **file** is not the raw SSH wire-key digest. Obtain the latter independently for `nodeIdentity.sshHostKeySha256`; never relabel a file digest. Convert captured octal permission strings to integer mode values explicitly in the trusted entry.
- Prior implementation-only evidence (before independent B1/B2 FAIL review): **205 passed, 0 failed/cancelled/skipped**, natural exit, across the new release tests, existing ownership tests, classic writer tests and topology runtime composition tests. RED logs cover absent implementation, foreign contexts/history, missing drop-in evidence, missing guard integration, callback/flag lifetime bugs, native BSON identity type and existing-namespace refusal. A first regression launch lacked `ACME_EMAIL` and failed before that unchanged fixture loaded; its log is retained separately.
- That prior run used real service/guard code, BSON encoding and an already-open held-write scope, with simulated persistence/physical authority; it did not cover real worker/uninstall caller ordering. No local `mongod` binary was available; **real Mongo command/DDL behavior is not verified by this slice**. Dependencies were borrowed read-only from `/home/leon/celerity-panel-custom/node_modules`: MongoDB driver 6.20.0 matches the lockfile; Mongoose 8.23.0 differs from locked 8.24.1. This is qualified source-unit evidence, not a lock-exact bundle or activation result. Detailed evidence and dependency comparison are under `l2tp-fastpath-20261026/legacy-compat-implementation/` outside the worktree.

## B1/B2 source repair qualification

The worker now enters its actual already-acquired held generation **before** the first ownership/receipt guard for both install and sync_users. Install ingress/live MAIN/candidate calls stay inside that preparation scope. Sync snapshot resolution enters the same exact-generation scope and repeats the guard; secret/artifact materialization remains local. Scope final verification finishes **before** worker settlement/exact release, never around release. Simple uninstall likewise holds its exact standalone admission + generation across guard and checked SSH completion, then exits the verified scope before state transition, exact lock release and admission completion. Failed final verification or uncertain/replaced standalone binding retains the fences; native ownership and competing admissions still refuse before SSH.

Public `retire()`, maintenance `binding` and `acceptedBaseline` shapes are unchanged. The internal held-scope bridge gains an optional server-owned standalone repository/ID capability. The execution-lifecycle factory also forwards the already existing root-owned `candidateService.assertConfigWriteAllowed` closure into simple uninstall (`configWriteGuard`); its former domain-only reconstruction omitted recognition flags and actual-host aliases. The actual-factory RED proves this wiring is necessary for B1, not new authorization or a general runner change. No receipt existed to migrate; a default-promoted historical hash must not be treated as lossless evidence.

Repair evidence is under `l2tp-fastpath-20261026/legacy-compat-repair-v2/`: preserved B2 RED numeric-type failures in both mint/recognize, corrected B1 actual-caller RED, intermediate harness failures, and naturally exiting serial acceptance results with file/dependency hashes. The assembled real default root + runtime/worker/typed executor tests exercise install and sync_users after `retire()`, and the real simple service + admission repository exercise standalone acquire/uninstall/release without invented operation fields. Negative coverage includes outside/escaped/replaced generations, foreign standalone IDs/node/kind/ownerGeneration/phase/connection, post-SSH drift, native owners, competing worker admission, and retained unknown held completion. BSON controls use the actual locked driver codec, including document/key-order-only positive changes during mint and recognition.

Final serial source acceptance: **371/371 PASS**, 0 failed/cancelled/skipped, natural exit; isolated per-file cardinalities agree with the aggregate (release 61, ownership 102, classic 28, runtime composition 22, default-root integration 49, worker 50, simple 36, active factory 9, authorization 14). All added persistence, SSH and physical-attestor seams are **SIMULATED**. The source tests use Node **22.23.1**, locked Mongoose **8.24.1**, MongoDB driver **6.20.0**, ssh2 **1.17.0**, winston **3.19.0**, sift **17.1.3** from the parent-verified read-only `lock-exact-deps/node_modules`; only the logger preload is replaced. This is not a Node20 deployed-runtime replay, real Mongo transaction/DDL acceptance, physical TEST activation, writer-exclusion proof or PROD PASS. No remote actions were performed. Independent re-review of this repair and the separately owned root adapter remains required before activation.
