# Durable rapid-create auto-deploy intents

## Contract

`POST /api/cascade/links` with explicit `autoDeploy: true` persists a version-1 intent and returns **202** with `autoDeployJob`. This is not a created link, a frozen operation, a saved draft snapshot, or a readiness claim. `GET /api/cascade/links/auto-deploy-jobs/:jobId` exposes its durable status. Send a stable `Idempotency-Key` for retries; the same key with different request content is rejected. Acceptance checks the supplied exact current topology revision; a stale request is refused, not silently rebased on acceptance. The queued intent is revalidated against the current graph when it reaches the head.

Defaults are 32 outstanding jobs (configurable service bound 1–128), 3 preparation attempts (bound 1–10), a 30-second generation-fenced claim lease, and bounded linear retry backoff. Failed/blocked records remain queryable. A blocked uncertain predecessor continues occupying capacity and stops successors. No legacy `autoDeploy` metadata is interpreted as a job.

The opted-in panel host supplies the service to the existing supervised startup/recovery lifecycle. No import-time timer or route-created consumer exists. Stop joins the in-flight consumption/execution tick. Restart reconstructs consumption from persisted state, not process memory.

## Atomic assembly and ownership

At the queue head one MongoDB transaction creates the link, maintains paths, prepares configured ingress, reserves topology ownership, freezes a scoped `link.apply` operation, and binds its exact operation ID/revision/prior-deployed-revision/admission fingerprint to the intent. Nested preparation uses the caller's active session. Default intent transactions explicitly require primary snapshot reads and majority commit acknowledgement. No external node execution runs in a transaction or before a durable binding.

Draft/path/revision writers require zero active topology admission. Successors therefore do not advance the exact revision owned by an active operation. Only confirmed applied (`deployed`, `online`, or physically persisted `staged`) links enter the scoped baseline; unrelated pending links do not. Existing worker/finalizer/PPP fences are unchanged. A terminal operation whose ownership is still held is **uncertain**, not permission to decrement counters, requeue execution, or skip the head.

Unknown commit responses are reconciled through exact persisted identity. Known local preparation aborts roll back assembly together and may retry within the attempt bound. Expired claim generations cannot mutate or bind work. Remote execution remains the operation worker's responsibility; this queue never calls general Sync.

## Server execution identity (admission only)

The service and consumer require an explicit server-selected allowlisted `executionContext` (`test` / `test.infograd.online` or `production` / `lm1.infograd.online`). Both pin a canonical frozen copy; request bodies cannot choose it. Each new intent persists the pair as an immutable subdocument without a default. Replays, including unknown-commit/duplicate readbacks, require the same pair as well as the payload hash. Missing or foreign queue-head identity is refused before claiming, changing admission/capacity, or materializing a plan. A malformed head is not skipped or automatically repaired.

The consumer passes the pinned context explicitly to the coordinator. New operations persist immutable execution identity and a host-bound run idempotency key; their admission fingerprint includes both. Intent binding pins the exact operation key alongside its existing revision/fingerprint fences. Settlement rejects missing/foreign identities or keys without releasing outstanding ownership. Historical unbound intents/operations require a separate audited migration or reconciliation, not a reader-side TEST default.

**Not a production-execution readiness claim:** this slice proves PROD HTTP 202 → persisted intent → consumer → scoped frozen operation on an isolated local MongoDB replica set. It does not enable the PROD worker or modify serving state. The runtime/worker repository claim and recovery scanner still need independent execution-context fencing before PROD execution can be enabled; the operation claim projection/filter in this baseline does not yet enforce the persisted pair/key. Recovery lifecycle changes are separately owned.

## Prerequisites and verification

A transaction-capable MongoDB replica set, initialized topology admission counters, normal model/index initialization, and the existing exact TEST execution opt-ins are required. Missing queue state alongside existing intents fails closed; this implementation does not repair deployed state or initialize legacy counters opportunistically.

`topologyIntentQueue.test.js` starts an isolated loopback replica set only when `C3_MONGOD` names a local MongoDB binary. Without that opt-in it skips rather than connecting to the configured panel database. Test files and DB storage are created under `TMPDIR` and removed afterward.

Run with the repository's synthetic test environment:

```
C3_MONGOD=/path/to/mongod node --test --test-force-exit \
  src/modules/relay-l2tp/tests/*.test.js src/modules/tests/*.test.js \
  src/routes/tests/cascadeLinks*.test.js scripts/test-network-edit-ui.js
node scripts/test-network-ui.js
git diff --check
```

Coverage includes four durable acceptances; four actual HTTP POSTs while the first real worker is suspended; assembled host stop/drain/restart; serial exact revisions; real worker/lock/finalizer/PPP-gate integration; no portal direct-selection rules; duplicate/conflicting keys; concurrent overflow; foreign pending-link exclusion; expired-generation fencing; transactional preparation rollback and exhaustion; unknown commit readback; and retained uncertain predecessor ownership. External executor and dynamic-user RPC are deterministic local seams. This is local transaction/orchestration evidence, not a live deployed-node or client-connectivity smoke test.

The older synchronous POST auto-deploy tests were superseded by durable acceptance/queue tests; non-autoDeploy POST and synchronous PUT behavior retain their existing coverage. Parent integration must retain its independently developed worker/install shutdown and composer sink-last fixes; this change deliberately does not edit those files.
