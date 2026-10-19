# Bounded V2 executor wiring — dormant, not execution enablement

## Delivered boundary

- Runtime selects the existing canonical server pair once. Executor keeps those
  selected primitives and supplies the canonical host string to the real
  `TopologyNodeTransportFactory`; target/host/role still reach the bootstrapper.
- Worker forwards an immutable expected fence containing the **already acquired**
  exact node-lock generation, current claim owner and current numeric attempt to
  prepare, commit, verify, cleanup and rollback. It does not manufacture an
  attempt ID, command ID or predecessor from a request.
- Executor requires a trusted constructor-injected
  `executionBindingReader.readVerified(expected)` before node resolution,
  again before bootstrap, after bootstrap before prepare dispatch, and before
  every prepared lifecycle command. It rejects missing, foreign, stale,
  mutable, incomplete or changed bindings. Rehydration also requires matching
  durable authority; a newly acquired generation cannot adopt an old binding.
- The reader's returned immutable record binds host, operation, revisions, node,
  target profile, candidate hash, backup, claim owner/attempt, lock generation,
  attempt ID, predecessor and distinct IDs for each lifecycle command. Requests
  use only those durable IDs. Changed records are not silently adopted.
- Real V2 transport receipts are validated without accepting the old receipt
  shape. Existing public typed executor receipt fields retain their meaning;
  they are deliberately not terminal/handback evidence.
- The worker snapshots the real executor's V2 protocol marker. All V2 lock
  release helpers, rollback admission release and PPP release/recovery paths
  remain closed. Verified commands stop in `committing` with
  `TOPOLOGY_V2_HANDOFF_UNPROVEN`, before user resync/PPP/other classic writers or
  success publication. Unknown verify completion does not trigger rollback.
  Missing initial binding leaves `preparing`, locks and counted admission held;
  it does not manufacture a terminal rollback.
- Existing TEST fake-executor behavioral tests retain their prior lifecycle
  semantics. Real V2 rollback receipts instead retain ownership, including the
  assembled local pre-dispatch rejection regression.

## Intentionally absent / release blockers

**No real binding reader is installed by `createTopologyOperationRuntime`.**
There is no new flag, environment bypass, production worker activation, node
write, deployment or remote smoke test. The production worker's pre-claim
quiescence refusal is unchanged. Default real executors on **both** canonical
hosts refuse before node lookup/bootstrap because durable V2 authority is absent.

A frozen object alone is not durability, enrollment or quiescence evidence. The
executor's injected reader remains a server-owned integration seam. A real,
**dormant** Mongo implementation now exists in `TopologyExecutionBindingStore`;
see [the storage contract](topology-v2-execution-binding-store.md). It is not
installed by any runtime, host, route or worker. Its local replica-set tests use
explicitly simulated external maintenance/physical/predecessor authority and
local-only SSH adapters, never a production database or real node.

Before any real reader/worker enablement, separately implement and verify:

1. Provision and review the dormant insert-only enrollment/binding indexes and
   explicitly supply its connected replica-set models plus trustworthy external
   authority. The separate immutable models now persist the execution record;
   real-operation/claim/node-lock/physical-owner CAS and bounded primary-majority
   readback are tested locally. No production schema migration, authority,
   successor enrollment or runtime reader installation is delivered. Do not infer
   ownership from a phase label, lease, reacquired lock or test authority.
2. Authoritative predecessor enrollment and physical execution-host/profile
   ownership, including aliases. `none` is permitted in the simulated fixtures
   only as explicit initial enrollment; runtime does not default or synthesize
   it. Old runner binaries, classic config writers and bootstrap uploads need
   external exclusion/join authority before any enrollment can be trusted.
3. Persisted exact close + fresh terminal status readback, including command,
   generation, attempt, boot identity and recovery fences. This executor does
   not implement terminal close/status dispatch or authorize database release.
   Even a correct V2 terminal readback covers protocol-admitted commands only,
   not all classic/bootstrap/independent writers.
4. Safe user/PPP/ingress writer integration and atomic ownership handback before
   exact lock release and terminal admission decrement. Current V2 outcomes keep
   these retained rather than asserting all host writers have stopped.

## Test evidence

Baseline assembled executor test: **7 passed, 7 failed** after the runner merge.
The failures were not fixed by weakening transport validation or removing
negative cases. Fixtures now carry explicit simulated durable records and V2
completion fields.

RED was observed for:

- missing authority (remote-bound failure instead of local binding refusal);
- absent worker exact acquired-generation/claim context;
- V2 success/rollback/unknown verification incorrectly reaching release paths;
- ownership lost during bootstrap still dispatching prepare;
- ownership lost during node lookup still entering bootstrap;
- absent persisted binding being mislabeled as a terminal rollback.

GREEN local verification: **269 passed, 0 failed, 0 skipped, 0 cancelled** across
these suites (no force-exit option, no MongoDB or remote SSH):

```
NODE_PATH=/home/leon/c3-int-verify/node_modules node --test --test-concurrency=1 \
  src/modules/relay-l2tp/tests/{topologyOperationExecutor,topologyOperationWorker,topologyCommitUncertainty,topologyRuntimeComposition,topologyExecutionContext,topologyOperationWorkerClaimFence,topologyNodeTransport,topologyNodeTransportFactory,topologyOperationRecoveryLifecycle,topologyOperationRecoveryIdentity,topologyOperationAttachFinalization,topologyOperationFinalizer,topologyRunnerFence}.test.js \
  src/modules/tests/createL2tpPanelHost.test.js
```

Runner tests execute the existing runner in a disposable fake root. The
uncertainty tests keep simulated remote writers alive and prove exact generations,
counted admission and the blocked intent queue remain retained. These results
are local orchestration/protocol evidence, not deployed connectivity or arbitrary
host-writer quiescence proof. `runner.sh`, transport and factory sources are not
modified by this slice.
