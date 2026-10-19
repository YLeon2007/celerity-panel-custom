# Dormant production config-ownership transfer contract

**Not activation.** `TopologyConfigTransfer` has no route, MCP tool, module registration, startup consumer or runtime caller. Its model is not imported by normal startup. Existing TEST and classic PROD policy is unchanged. Do not create production ownership rows with a script or wire this service until the blockers below are closed.

## Bounded state machine

- Server selects the canonical `production` / `lm1.infograd.online` context, never a request identity. Initialization is insert-only and **classic-owned**. Missing records cannot adopt; neither execution flags nor operation history initialize/transfer ownership.
- Unique `(node, profile)` slot; only `xray-main` and `xray-bridge` are accepted, each with fixed config/unit/service paths. Inventory binds the node's machine ID and SSH-host-key SHA-256. Every transition compares the exact pair, context, identity, previous owner and UUID generation.
- `adopt`: classic → topology, new UUID generation, original config/unit digests plus active/enabled service states and adoption receipt committed together.
- `handback`: topology → classic only after externally verified **node readback** matches every original snapshot field. Receipt must identify the adoption generation. CAS also compares the original snapshot and adoption receipt; flags, rollback labels, operation history or lease expiry never imply restoration. The adoption receipt is retained.
- Transitions use a majority Mongo transaction and bounded primary/majority readback. No transport or external verification is inside a retryable transaction. A race has one winner. Unknown commit/readback failure is not success and never causes implicit handback/retry.
- V1 requires existing config and unit files and known service states. It does not adopt absent artifacts, unsupported unit states, drop-ins or alternative paths by guessing. Snapshot hashes are evidence references, **not backup bytes**; an external backup/restoration implementation remains required.

## Required trusted external authority — not implemented here

`withVerifiedMaintenance({ binding, proofRef }, work)` is a server-injected authority, with **no default implementation**. An opaque proof reference is not authority by itself. The adapter must authenticate its evidence, compare the complete challenge (including next generation, physical node identity and fixed paths), then await exactly one `work(evidence)` while exclusion remains held.

Evidence must establish an externally observed old-backend instance/PID/start identity, stopped process tree, disabled future dispatch, held maintenance and **all** relevant writers drained. A new DB marker cannot constrain an already running old backend. The adapter must independently read the actual node config, unit and service states; a caller's `verified` boolean or copied document is not proof. Maintenance must survive callback errors, ambiguous commits and failed confirmation until independently reconciled; do not resume the old dispatcher merely because the promise rejected. These obligations are trusted integration preconditions, not proven host enforcement by these local tests.

## Exact release blockers / remaining wiring

1. No external old-PID/process-tree + credential/dispatcher exclusion authority exists in this slice. The service is deliberately unreachable in normal runtime.
2. Classic `syncService.updateXrayNodeConfig` and `cascadeService._deployPortalConfig` currently perform conservative ownership/history **reads**, not a durable writer scope spanning remote upload/restart. Adding an owner read would still leave a DB-check-to-SSH TOCTOU race, so this slice does not add one or claim they consume the new owner model.
3. `cascadeService._deployRelayNode`, `_deployPureBridge`, standalone `_deployForwardHopConfig`, `_deployBridgeConfig`, stop/disable paths, and `accessLogs/provisionService` bridge uploads are additional writers of the same profiles. All must join one durable maintenance/generation-enforced remote boundary, including in-flight work and bypass credentials, before any adoption/production mutation. Also audit node setup/installer paths before claiming an exhaustive writer inventory.
4. Provision/register the model and verify its persisted **non-sparse, non-partial unique `(node, profile)` index** before initialization/transfer (the service refuses a missing/weaker index; it does not provision one). Admission/worker/materializer/finalizer must bind the exact adopted node/profile/generation; restore actual backup bytes and verify node readback before calling handback. Operation-history veto remains conservative after handback until separately reconciled; this service does not erase history or release admissions/locks.
5. The assembled production worker must continue returning `TOPOLOGY_EXECUTION_QUIESCENCE_UNPROVEN` before claim/transport, even with all flags enabled. No flags or marker in this change override that guard.

## Local verification

`src/services/tests/topologyConfigTransfer.test.js` starts its own loopback-only replica set under `TMPDIR` when `C3_MONGOD` names a local binary, uses scratch-bound models, drops the scratch DB, verifies absence and terminates Mongo. Positive evidence is explicitly simulated at the injected authority seam. Tests cover paired/physical identity negatives, unknown/missing evidence, stale replay, restoration mismatches, concurrent CAS, transaction rollback and injected unknown post-commit. These are local persistence/contract tests, not live maintenance, backup/restoration or PROD readback evidence.

`topologyConfigOwnership.test.js` additionally checks that all ten online legacy links retain their actual classic-generated reverse/forward listeners under both production opt-in values. `topologyRuntimeComposition.test.js` retains the assembled production no-dispatch guard.
