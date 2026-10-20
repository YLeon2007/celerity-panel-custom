# Explicit TEST / production config-ownership maintenance contract

**Not activation.** `TopologyConfigTransfer` has no route, MCP tool, module registration, startup consumer or runtime caller. This service change adds no automatic provisioning or adoption. Existing TEST and classic PROD runtime policy is unchanged. Do not wire operational transfers until the blockers below are closed.

## Bounded state machine

- Server explicitly selects canonical `test` / `test.infograd.online` **or** `production` / `lm1.infograd.online`, never a request identity. The constructor validates the complete pair and retains the frozen canonical object, not the caller's mutable input. Missing, extra-field, foreign and cross-paired contexts refuse before persistence/external work; there is no default context. Initialization is insert-only and **classic-owned**. Missing records cannot adopt; neither execution flags nor operation history initialize/transfer ownership.
- Unique `(node, profile)` slot; only `xray-main` and `xray-bridge` are accepted, each with fixed config/unit/service paths. Inventory binds the node's machine ID and SSH-host-key SHA-256. Every transition compares the exact pair, context, identity, previous owner and UUID generation.
- `adopt`: classic → topology, new UUID generation, original config/unit digests plus active/enabled service states and adoption receipt committed together.
- `handback`: topology → classic only after externally verified **node readback** matches every original snapshot field. Receipt must identify the adoption generation. CAS also compares the original snapshot and adoption receipt; flags, rollback labels, operation history or lease expiry never imply restoration. The adoption receipt is retained.
- Transitions use a majority Mongo transaction and bounded primary/majority readback. No transport or external verification is inside a retryable transaction. A race has one winner. Unknown commit/readback failure is not success and never causes implicit handback/retry.
- V1 requires existing config and unit files and known service states. It does not adopt absent artifacts, unsupported unit states, drop-ins or alternative paths by guessing. Snapshot hashes are evidence references, **not backup bytes**; an external backup/restoration implementation remains required.

## Minimal accepted maintenance API

Supply the explicit server context, same-connection `TopologyConfigOwner` model and trusted `withVerifiedMaintenance`; provision the required unique index separately. Use `initializeClassic({ node, profile, nodeIdentity })`, then `adopt({ node, profile, generation: classic.generation, proofRef })`. Initialization only inventories classic ownership; it is not dispatch authority. Keep the original config/unit **bytes** and service active/enabled state in the external backup implementation. An adopted owner can be passed to the existing `TopologyExecutionBindingStore.preEnroll` using its exact generation plus separately attested endpoint/physical/empty-head evidence; an owner row is not that evidence. Restore those original bytes and service states under held exclusion before `handback({ node, profile, generation: adopted.generation, proofRef })`. Use each returned generation, never an inferred/replayed one.

No DB seed, snapshot default, worker claim, bootstrap or automatic controller is added. Physical aliases, endpoint reassignment, port/key drift and real systemd restoration remain external authority / existing binding-store obligations.

## Required trusted external authority

A TEST-only held physical implementation now exists in
`testPhysicalController` / `TopologyExecutionAuthorityLifecycle`; see
[`docs/topology-test-owner-maintenance.md`](../../docs/topology-test-owner-maintenance.md).
It reads current exact bytes/service states and retains private process-local
originals against independently accepted root pins. It adds no automatic owner
migration, restoration writer, crash-durable backup or production authority.
Parent integration must explicitly invoke the public service in its held scope.

`withVerifiedMaintenance({ binding, proofRef }, work)` remains a server-injected
authority, with **no production default implementation**. An opaque proof reference is not authority by itself. The adapter must authenticate its evidence, compare the complete challenge (including next generation, physical node identity and fixed paths), then await exactly one `work(evidence)` while exclusion remains held.

Evidence must establish an externally observed old-backend instance/PID/start identity, stopped process tree, disabled future dispatch, held maintenance and **all** relevant writers drained. A new DB marker cannot constrain an already running old backend. The adapter must independently read the actual node config, unit and service states; a caller's `verified` boolean or copied document is not proof. Maintenance must survive callback errors, ambiguous commits and failed confirmation until independently reconciled; do not resume the old dispatcher merely because the promise rejected. These obligations are trusted integration preconditions, not proven host enforcement by these local tests.

## Exact release blockers / remaining wiring

1. No external old-PID/process-tree + credential/dispatcher exclusion authority exists in this slice. The service is deliberately unreachable in normal runtime.
2. Classic `syncService.updateXrayNodeConfig` and `cascadeService._deployPortalConfig` currently perform conservative ownership/history **reads**, not a durable writer scope spanning remote upload/restart. Adding an owner read would still leave a DB-check-to-SSH TOCTOU race, so this slice does not add one or claim they consume the new owner model.
3. `cascadeService._deployRelayNode`, `_deployPureBridge`, standalone `_deployForwardHopConfig`, `_deployBridgeConfig`, stop/disable paths, and `accessLogs/provisionService` bridge uploads are additional writers of the same profiles. All must join one durable maintenance/generation-enforced remote boundary, including in-flight work and bypass credentials, before any adoption/production mutation. Also audit node setup/installer paths before claiming an exhaustive writer inventory.
4. Provision/register the model and verify its persisted **non-sparse, non-partial unique `(node, profile)` index** before initialization/transfer (the service refuses a missing/weaker index; it does not provision one). Admission/worker/materializer/finalizer must bind the exact adopted node/profile/generation; restore actual backup bytes and verify node readback before calling handback. Operation-history veto remains conservative after handback until separately reconciled; this service does not erase history or release admissions/locks.
5. The assembled production worker must continue returning `TOPOLOGY_EXECUTION_QUIESCENCE_UNPROVEN` before claim/transport, even with all flags enabled. No flags or marker in this change override that guard.

## Local verification

`src/services/tests/topologyConfigTransfer.test.js` starts its own loopback-only replica set under `TMPDIR` when `C3_MONGOD` names a local binary, uses scratch-bound models, drops the scratch DB, verifies absence and terminates Mongo. The complete regression matrix runs for both TEST and PROD: paired/physical identity negatives, unknown/missing snapshot evidence, stale replay, restoration mismatches, concurrent CAS, transaction rollback and injected unknown post-commit with retained simulated hold. The public positive path uses `initializeClassic → adopt → real store preEnroll → handback` on actual same-connection schemas, never a raw-seeded adopted owner. It hashes/restores scratch config/unit bytes and a simulated service-state file, checks exact receipts, and observes maintenance held through adoption CAS/commit/majority confirmation. Opposite canonical services cannot overwrite the globally occupied node/profile or consult their external verifier on a foreign transfer. Positive physical authority and systemd state remain explicitly simulated; local byte restoration is not remote backup/systemd or PROD readback evidence.

`topologyConfigOwnership.test.js` additionally checks that all ten online legacy links retain their actual classic-generated reverse/forward listeners under both production opt-in values. `topologyRuntimeComposition.test.js` retains the assembled production no-dispatch guard.
