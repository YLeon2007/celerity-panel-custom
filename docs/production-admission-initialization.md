# Production admission initialization — dormant maintenance API

## Delivered boundary

Two separate modules exist; neither is wired into startup, routes, workers or legacy writers:

- `services/productionAdmissionInitializationPreflight.js` remains an unchanged **read-only diagnostic**. It exports no write/execute method and always reports `mode: 'preflight-only'`, `ready: false`, `initialized: false`, with permanent blockers `EXTERNAL_MAINTENANCE_AUTHORITY_UNAVAILABLE` and `PRODUCTION_ACCEPTED_PIN_AUTHORITY_UNAVAILABLE`. Those blockers were not removed to manufacture a write gate.
- `services/productionAdmissionInitializer.js` implements a separate explicit **insert-only, one-shot Mongo write** under an injected held-maintenance authority. Successful local initialization still reports `ready: false`, `dormant: true`. It never activates a worker, adopts links, writes ownership, executes SSH, connects from a URI, or changes environment flags.

**There is no operational external-maintenance adapter or accepted production record/revision authority in this repository. No production initialization was performed. This is not deployment approval.** The only authority implementation in the new integration suite is explicitly simulated and excludes no real processes. No default-authorizing adapter, URI-taking CLI, startup switch or production pins are supplied.

## Independent operator prerequisites

The server-side assembler must independently accept and retain:

1. Exact native Mongo database handle and database name, canonical frozen `PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT` **by reference** (`production` / `lm1.infograd.online`), and expected replica-set identity `{ setName, replicaSetId }`. `replicaSetId` is a lowercase 24-character ObjectId string. The initializer checks `replSetGetConfig` and writable-primary `hello` before DDL, before the transaction and before confirmation; access to these commands is required. A database name alone is not deployment identity.
2. A separately reviewed backup/restoration baseline and ten `{ id, sha256 }` full-record pins, not pins regenerated from a changed live scan. IDs must be distinct lowercase ObjectId strings; digests are lowercase SHA-256. `rawDocumentFingerprint` uses complete unprojected driver BSON serialized as non-relaxed Extended JSON, recursively key-sorted without sorting arrays. These are semantic record fingerprints, not raw BSON-byte hashes or proof of classic ownership.
3. A separately reviewed explicit `initialState`, with **exactly** `_id: 'singleton'`, `revision`, `deployedRevision`, `stateTransitionRevision`, `replacementEpoch`, `remoteAdmissionCount`, and `topologyAdmissionCount`. All numeric fields must be nonnegative safe integers, both admission counters must explicitly be zero, and revision must equal deployedRevision. Nothing is inferred from source defaults, link counts or absent legacy fields. There are no generated timestamps, default revision, drain, reservation or ownership markers. The complete inserted state is compared on confirmation.
4. Explicit review of exported deeply frozen `REVIEWED_MANIFEST` and independent acceptance of `REVIEWED_MANIFEST_SHA256`. Passing the exported digest in a fixture is **not** evidence of independent operator review. The manifest names all reviewed collections and source-schema indexes without importing live Mongoose models. All collections must already exist as ordinary collections with empty options and stable UUIDs; missing collections/views/options refuse rather than silently creating history.
5. An independently fixed lowercase UUID `maintenanceGeneration`, bound to all preceding values by the external held authority. This identifier is data, not authority.

The ten raw link rows must be exactly eight explicit `reverse` and two explicit `forward`, all `active: true`, status `online` or `deployed`, with scalar ObjectId portal/bridge references. Missing mode is not silently reverse. No extra/inactive row is admitted by this conservative first-install subset. Links remain byte-semantically unchanged and classic-owned; initialization is not import, topology revision adoption or ownership transfer.

## Held-maintenance adapter contract — operationally unavailable

`createProductionAdmissionInitializer(options)` requires a **trusted server-assembled dependency**, never a browser/request-supplied adapter or boolean:

```js
maintenanceAuthority.withHeldMaintenance(frozenChallenge, async scope => {
    // The initializer performs and awaits all work here.
});
```

The challenge deeply freezes canonical context, database name, replica-set identity, maintenance generation, accepted pins, initial state and manifest digest before the first await. The adapter must independently verify this exact challenge rather than copying it back as proof. It must exclude **all** old/new ingress, worker processes, classic writers, aliases and remote in-flight processes throughout the entire callback and its cleanup, not merely hold a database lease. Read-only database checks cannot establish that exclusion.

The scope has two awaited capabilities:

- `assertHeld(theExactChallenge)` checks the still-held exact generation/exclusion, completes with `undefined`, and throws on any uncertainty. A return value of `true` is refused. The initializer checks before and after each awaited ordinary DDL/read/write/confirmation operation, and after session cleanup. Abort/session cleanup on failure may still be attempted to close an uncommitted local transaction; it does not authorize release or external execution.
- `retainUnknown(theExactChallenge)` durably latches maintenance/dormancy for explicit operator reconciliation. It must never release on failure to record the latch. The adapter itself must fail closed on callback rejection, scope loss, early return, retention failure, or its own cleanup failure, even if the callback cannot deliver a final retention request. It may not release an uncertain scope in a `finally` block. Only an explicitly confirmed safe outcome may finish its exclusion protocol.

The adapter must call the callback exactly once, **await it**, return its exact result and prevent scope escape. The initializer refuses missing/late/reused callbacks, scope flags and a fabricated return value. These checks do not make a malicious or incorrect injected adapter trustworthy. No operational authority is inferred from empty history, flags, a successful fixture, matching pins, completed labels, expired leases or callbacks returning true.

## Additive schema and one-shot transaction

Within that held scope:

1. Verify deployment, full catalog identity, exact reviewed index inventory, baseline pins, singleton absence and empty reviewed histories **before DDL**. Any existing singleton—including valid zeros, partial fields, a drain, reservation or foreign `_id`—requires separate review and is untouched.
2. Compute the missing-index plan from the exact reviewed manifest. Only absent reviewed non-`_id_` indexes are eligible. Existing names must have exact ordered keys, uniqueness, sparseness and partial filters; extra indexes and hidden/TTL/collation/storage-engine/unknown options refuse. `background` is tolerated as nonsemantic historical metadata. There is no `syncIndexes`, drop, replacement, conflict repair or collection creation.
3. Build eligible indexes individually with majority write concern **outside the transaction**, then recheck all index readiness and stable collection UUIDs. This DDL is not atomic. Any failure after a DDL attempt is conservatively `PRODUCTION_INITIALIZATION_UNKNOWN_HOLD`, even if some additions succeeded or a later precommit refusal is known. Never compensate, remove foreign indexes, auto-resume or retry the initializer.
4. Start exactly one manual transaction with snapshot reads and majority write concern. Recheck every full link pin, all histories and complete singleton absence in that snapshot immediately before `insertOne` of the explicit state. There is no upsert, update, default, callback retry, snapshot retry or identity regeneration. A competing singleton insertion wins by Mongo uniqueness/write-conflict enforcement; it is never repaired or deleted. A confirmed precommit abort rolls back the initializer's own insertion.
5. Send exactly one bounded majority `commitTransaction` command. All commit errors, write-concern errors, error labels, scope loss or uncertain acknowledgement remain unknown, without retry, success, compensating writes or an abort after attempted commit.
6. After a clean commit, while still held, verify deployment, all links/history, **the sole exact state**, exact indexes and unchanged collection UUIDs. Document reads are bounded outside-transaction **primary/majority** reads with a two-second client/server budget each. Catalog/index reads are bounded primary diagnostics, not majority snapshots. End the session and recheck held authority before returning `{ initialized: true, ready: false, dormant: true, mode: 'insert-only', stateSha256 }`.

Reviewed histories are `topologyoperations` (including retained/client-proof work), `topologycreateintents`, `topologyintentqueuestates`, `l2tpoperations`, `nodeoperationlocks`, `remoteadmissions`, `topologyexecutionbindings`, `topologyexecutionenrollments`, and `cascaderoutegroups`. **Any row**, including terminal/completed/expired rows or an apparently empty queue-state singleton, vetoes this first-install path. This initializer writes only `cascadetopologystates`; it does not initialize/adopt the intent queue. Other historic module data and external writer exclusion remain an independent audit responsibility.

A snapshot is not serializable exclusion: a writer violating maintenance can insert a phantom into a history collection or change a read-only pinned link after the transaction snapshot without conflicting with the singleton insertion. Postcommit majority confirmation detects the tested violations and retains **both** persisted initialization and foreign winner as unknown. It cannot promise rollback or replace the missing external writer fence. The real adapter is a hard prerequisite, not a future optimization.

### Driver-specific non-retry boundary

The Mongo Node driver's `session.commitTransaction()` can internally retry even when `withTransaction()` is not used and `retryWrites` is false. The initializer therefore uses one raw admin command with the existing session and explicit majority write concern, rejects raw `ok: 1` replies containing `writeConcernError`/error labels, and closes only the driver's local transaction bookkeeping via `session.transaction.transition`. That internal API is a deliberate compatibility limitation; it is checked before transactional writes and exercised against the installed driver. It does not establish server commit/abort and sends no cleanup/compensation command. Any driver upgrade requires replay of these command-count regressions before operational review. This slice supports replica sets, not sharded/mongos deployments.

Each initializer object allows one call, including refused/unknown attempts. Creating another object does not authorize an automatic retry or reconcile an unknown outcome. Unknown DDL/commit/readback always requires separate majority-confirmed operator reconciliation under retained external maintenance; the module offers no resume/release/recovery method. Errors are fixed allowlisted codes, without raw Mongo errors, credentials, full records or owner tokens.

## Local verification

The suites require `C3_MONGOD` and `TMPDIR`, fail rather than skip when unavailable, and start disposable loopback replica sets and uniquely named databases. Verified locally with Node 22.23.1, Mongoose 8.24.1, Mongo Node driver 6.20.0 and MongoDB 8.0.16. They use synthetic full BSON records and source-schema indexes; they do not access production, backups, SSH or remote nodes. All temporary Mongo files are under configured scratch and removed on teardown.

Run the two focused suites serially in an isolated scope (no full source suite/build):

```sh
/home/leon/.local/bin/hermes-heavy env \
  NODE_PATH=/home/leon/c3-int-verify/node_modules \
  C3_MONGOD=/home/leon/.hermes/cache/scratch/c3-queue-mongo/mongodb-linux-x86_64-debian12-8.0.16/bin/mongod \
  node --test --test-concurrency=1 \
  src/modules/relay-l2tp/tests/productionAdmissionInitializationPreflightMongo.test.js \
  src/modules/relay-l2tp/tests/productionAdmissionInitializerMongo.test.js
```

The preflight suite retains observational/read-only safety coverage. The new write suite first failed on the absent initializer (RED), then exercised actual insertion (GREEN), explicit fields and identity refusal, existing/partial singleton preservation, every reviewed history winner arriving before the transaction snapshot, a competing singleton after snapshot, pin drift before/after snapshot, successful additive index creation, conflicts/views/missing collections, real `failCommand` partial DDL, real uncertain commit write-concern replies, real postcommit majority-read failure, scope loss before/after commit, one-shot invocation and command counts. The WCE failpoint can return an unknown reply without committing on this server; that case is not claimed as a durable commit. Separate postcommit failures prove preservation of a genuinely committed singleton. A deliberately injected snapshot phantom demonstrates why held exclusion is indispensable.

This is local Mongo execution evidence with a **simulated** authority, not proof of deployed quiescence, production record acceptance, operational authorization, client readiness or release readiness.
