# Production admission initialization: dormant preflight-only slice

## Delivered boundary

`services/productionAdmissionInitializationPreflight.js` is a **read-only diagnostic**, not a migration, initializer, execution gate, or database ownership authority. It is not imported by application startup, routes, workers, or legacy writers. It exports no write/execute method and opens no connection itself. Invoke it only from an explicitly assembled local/server maintenance tool with an already selected database handle.

The workspace contains validated source schemas, but **does not contain the separately accepted ten production link IDs/full-record fingerprints or an implemented external maintenance/quiescence authority**. The authorized fallback therefore applies: do not invent production records, ownership evidence, initial revision history, or a successful commit. Every returned report has `mode: 'preflight-only'`, `ready: false`, `initialized: false` and the permanent blockers:

- `EXTERNAL_MAINTENANCE_AUTHORITY_UNAVAILABLE`
- `PRODUCTION_ACCEPTED_PIN_AUTHORITY_UNAVAILABLE`

`initialized: false` means this diagnostic did not initialize anything; it is not a judgment that an existing singleton is uninitialized. `zeroWorkObserved` only describes empty reviewed history collections across the two observations. Neither it, matching pins, nor exact-ready indexes authorizes writes, adoption, execution, or handback.

## Input and observation contract

```js
const { PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT } = require('../domain/topologyExecutionContext');
const { inspectProductionAdmissionInitialization } = require('./productionAdmissionInitializationPreflight');
const report = await inspectProductionAdmissionInitialization({
    db: explicitlySelectedNativeMongoDb,
    serverContext: PRODUCTION_TOPOLOGY_EXECUTION_CONTEXT,
    expectedDatabaseName: separatelyVerifiedDatabaseName,
    acceptedClassicLinks: separatelyAcceptedComparisonPins,
});
```

This is an internal API illustration, not a runnable production command or permission to connect to PROD. There is deliberately no URI-taking CLI, startup switch, authority boolean, or automatic index builder.

- Require the canonical frozen server context by reference (`production` / `lm1.infograd.online`), exact database-name agreement, and ten distinct lowercase ObjectId strings plus lowercase SHA-256 strings before reading persistence. Clones, TEST, cross-pairs, missing/malformed pins, and extra pin fields refuse without reads. No TEST code path is changed.
- Comparison pins are `{ id, sha256 }`. `rawDocumentFingerprint` hashes complete unprojected driver BSON values serialized as non-relaxed Extended JSON, recursively key-sorted without sorting arrays. Generate/accept these pins independently under the future maintenance authority; do not regenerate pins from a changed live scan to bless drift. They are semantic record fingerprints, not raw BSON-byte digests or proof of classic ownership. No actual PROD pins are embedded here.
- Require exactly ten raw rows, eight explicit reverse and two explicit forward, all `active: true`, status `online` or `deployed`, and scalar ObjectId portal/bridge references. Missing mode is unresolved, not a reverse default. Inactive/excess/missing/changed rows refuse comparison. This intentionally conservative first-install subset does not review additional inactive link history.
- Read raw collections without Mongoose document defaults. An absent singleton remains `missing`; an absent collection is `collection-missing`/`missing`, not an empty collection or zero counters. Views and nonempty collection options are `unresolved`. Any existing singleton, including apparently valid zeros, requires separate review; no missing field is normalized or backfilled.
- Inspect topology operations (including client-proof/retained-admission history), create intents and queue state, PPP/L2TP jobs, node locks, remote admissions, execution bindings/enrollments, and route groups. **Any row**, including terminal/completed/expired rows, vetoes a zero-history observation. This does not adjudicate old history or infer that a lease expiry/completed label proves remote quiescence. Other historic module data and all external writers remain a separate audit responsibility.
- Compare all expected source-schema indexes, including `_id_`, with exact name, ordered key, uniqueness, sparseness and partial filter. Extra, hidden, TTL, collation, storage-engine or otherwise unexpected index options refuse. Missing indexes are diagnosed, never created. The reviewed manifest deliberately does not load model modules onto a live application connection, avoiding Mongoose auto-index side effects. The local integration fixture builds indexes from the actual source schemas and verifies manifest agreement.
- Perform two bounded outside-transaction observations. Document reads explicitly use primary/majority with a 2-second server/client budget per read; catalog/index reads use primary and bounded deadlines (Mongo catalog commands are not claimed as majority snapshots). Compare raw document/catalog/collection-UUID/index evidence between passes, refusing detected drift. These sequential scans are **not a transactional snapshot or a TOCTOU fence**; an unobserved concurrent writer can still race after the scan. Read failures return a fixed redacted refusal, without raw Mongo errors or causes.
- Return only allowlisted statuses/counts/refusal codes; never return credentials, full records, operation payloads or owner tokens. No links, ownership, counters, indexes, queue rows, locks, or admissions are mutated or released.

## Required future one-shot write contract — NOT IMPLEMENTED

Do not add a write path merely by removing the permanent blockers. A separately reviewed implementation must first have:

1. Accepted exact PROD database/deployment identity, restored backup validation, accepted ten classic-owned link pins, validated singleton initialization fields/revisions, and an explicit reviewed history/collection/index manifest. Source defaults and an absent collection are not migration evidence.
2. An external maintenance authority that excludes **all** old and new database ingress, worker processes, legacy/classic writers, remote in-flight processes and alternate aliases. It must hold the exact target/generation/pins challenge throughout the awaited write/verification scope. An environment flag, request field, lease, empty query, callback returning `true`, or successful local fixture is not this authority. Keep the first installation dormant independently of initialized counters.
3. Exact baseline catalog/index verification and an explicit additive-index plan. Build only reviewed absent indexes under that authority; never `syncIndexes`, drop, overwrite, or replace a conflicting existing index. Mongo index DDL must not be presented as an atomic part of a multi-collection singleton transaction. On partial/ambiguous DDL, remain dormant and refuse for operator audit; do not remove potentially foreign indexes or automatically resume.
4. A single non-retrying transaction with snapshot reads and majority write concern. Recheck every pinned link and all reviewed history, singleton absence, locks, admissions, replacement/drain absence and authority immediately before an **insert-only** singleton/counter write. Never upsert, `$set` a legacy singleton, adopt classic links, infer missing counters as zero, or retry a callback to acquire a new snapshot/identity. Abort confirmed pre-commit conflicts; preserve every competing winner exactly.
5. A bounded outside-transaction primary-majority readback of the exact inserted bytes/identity and index readiness while authority is still held. Missing, mismatched, timed-out or uncertain confirmation cannot acknowledge initialization. On unknown commit, never report success, auto-retry, backfill, delete a possibly committed singleton, or run compensating writes against foreign state. Retain dormancy and require explicit majority-confirmed operator reconciliation. Only a confirmed abort is rollback; unknown commit cannot safely promise rollback.
6. Actual isolated-Mongo RED→GREEN tests for insert-only success, all concurrent ingress/CAS winners, transaction rollback, true uncertain commit/write-concern errors, failed majority confirmation, partial index creation, and external scope loss. Those **write-path** tests are intentionally not claimed by this read-only slice.

Initialization of counters is not topology import/adoption or classic ownership transfer. The ten links must remain classic-owned, and deployment gates must stay closed even after a future successful initialization.

## Local verification

The new integration suite requires `C3_MONGOD` and `TMPDIR` and fails rather than skips when unavailable. It starts a disposable loopback replica set and unique database, populates ten explicitly synthetic mixed-mode raw legacy links, constructs real source-schema indexes, and tears down its database/process/directory. It never opens remote connections or reads actual production backups.

```sh
NODE_PATH=/home/leon/c3-int-verify/node_modules \
C3_MONGOD=/home/leon/.hermes/cache/scratch/c3-queue-mongo/mongodb-linux-x86_64-debian12-8.0.16/bin/mongod \
node --test src/modules/relay-l2tp/tests/productionAdmissionInitializationPreflightMongo.test.js
```

Tests cover exact input refusal before persistence; missing/partial/present singleton preservation; full-record inventory drift; all reviewed history collections; missing collection vs unresolved view; exact/missing/conflicting indexes; real competing writes between observation passes with complete winning-row/index readback; redacted failures; bounded majority-read commands; and an allowlist of read-only commands during preflight. This is local observational safety evidence, **not** a deployed migration, external quiescence proof, or successful initialization.
