# Selected apply integration slice

## Implemented protocol

The existing coordinator, operation repository, worker and finalizer now share the `admissionScope: 'selected'` protocol. The default topology runtime supplies the real selected reader to admission, worker revalidation and settlement; the panel host forwards the joined intent adapters. No second operation store or lock framework is introduced.

- Private immutable operation data binds `baselineTopology`, `effectiveTopology`, `resourceNodeIds`, requested `desiredVersion`, settled owner pins and route state to the frozen candidates' admission fingerprint.
- The applied reader follows existing config-owner `lastSettledOperation` pointers, validates selected snapshot provenance and terminal evidence, and takes the relevant connected component including shared route-group paths. Desired lifecycle status is not applied authority. An initial baseline without a settled pointer is accepted only with the existing adoption receipt and an exact original config digest for `{}` or `{}\n`; arbitrary classic configuration import is not implemented.
- Selected materialization receives the private before/after descriptors. The resource union includes removed and new endpoints. Known physical aliases are refused rather than assigned independent lock slots.
- Admission, competing remote admission, worker and scoped settlement preserve initialized legacy counters and explicit global drain/reservation semantics. Disjoint verified selected resources may coexist; uncertain operation ownership remains scoped and counted.
- The worker checks every actual lock acquisition, releases only proven no-dispatch exact generations, waits without spending an attempt on a known lock conflict, and revalidates the selected pins before preparation. Stale undispatched work can be rejected transactionally; possible remote effects do not authorize release.
- Successful selected publication updates the affected owner pointers and requested link, releases its exact locks, and decrements only its own admission. Independent global revision changes do not invalidate that publication or advance global `deployedRevision`.
- Joined `intentDraftWriter.createLink` and `intentOperationAdmission.queue` use the caller's active same-connection transaction. Creating a pending desired neighbor may wait behind selected work without altering the frozen operation. No worker is started from the transaction; the existing recovery/consumer handoff schedules committed work.
- The existing attach/replacement finalization shape now accepts one-hop/source-less suffixes and preserves peer path metadata through exact-array CAS. Owner, credential and ingress/readback checks are retained.

## Dependencies and ownership boundaries

This branch imports the existing versioned-intent and L2TP preparation changes and the descriptor-aware composer/materializer change. The prerequisite `node: nodeId` candidate identity fix is committed separately. No public routes, CascadeLink model, intent service/model, PPP/attach gates or L2tpSimpleService implementation is changed by this integration commit.

## Verification scope

`src/modules/relay-l2tp/tests/cascadeAnyOrderSelectedApply.test.js` assembles the actual coordinator, materializer, admission/operation repositories, lock service, worker, runtime and finalizer over lightweight query-aware persistence and executor seams. It also exercises the actual V2 settlement module with explicit local synthetic terminal evidence and the actual strict Mongoose schema round trip. These are **transaction-shaped local fixtures, not Mongo atomicity or physical deployment proof**.

The changed-area regression invocation additionally covers existing admission, draft, worker claim fences, finalization, remote admission, runtime composition, L2TP preservation and V2 publication suites. The final local run exited naturally with code 0: 23 files, 447 tests, 446 passed, 0 failed/cancelled and 1 skipped. The skipped existing atomic-Mongo claim test requires `C3_MONGOD`; it was not enabled. No force-exit flag is needed. The durable TAP log for the local final run is `/home/leon/.hermes/cache/scratch/c3-selected-admission-final-regression.tap` (not a repository artifact).

## Explicit remaining work

1. Real isolated Mongo transaction abort/rollback, concurrent CAS, unknown-commit and majority-readback validation. This slice intentionally does not start a database or contact any live system.
2. Cross-owner end-to-end HTTP/intent acceptance and restart integration after merging the public lifecycle/schema owner. The host forwards `createDeleteIntentWriter` only when that separately owned adapter exists.
3. Selected delete settlement and physical row/graph cleanup are not integrated. Delete resource resolution deliberately refuses; a tombstone writer alone is not deletion completion.
4. Installed empty-path ingress cutover is not integrated into selected apply. Such admission explicitly refuses with `TOPOLOGY_INSTALLED_ROUTE_PUBLICATION_REQUIRED`; the separate owned-path attach preparation/readback/publication path must be joined before enabling it. The repository shape/peer-preservation fixes alone do not prove that vertical path.
5. Selected client-proof queue scheduling remains disabled. Config application, route completeness, PPP outcomes and client readiness are not interchangeable.
6. Real SSH/Xray, PPP, remote writer completion and production activation remain outside this local slice. Existing production authority/refusal boundaries are not relaxed.
