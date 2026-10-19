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
3. The [dormant data-only close API](topology-v2-terminal-proof.md) now dispatches
   the persisted close ID and a fresh exact status query under scoped authority.
   It matches generation, attempt, boot and original maintenance identity and
   does not authorize database release. Durable terminal-result persistence and
   restart/successor recovery remain absent. Even correct V2 terminal readback
   covers protocol-admitted commands only, not classic/bootstrap/independent writers.
4. Safe user/PPP/ingress writer integration and atomic ownership handback before
   exact lock release and terminal admission decrement. Current V2 outcomes keep
   these retained rather than asserting all host writers have stopped.

## Trusted SSH connection authority (dormant executor contract)

After every successful `readVerified(expected)`, the executor now requires the
**same server-injected reader** to implement
`readVerifiedConnection(expected, verifiedBinding)`. It must return exactly:

```js
// All levels deeply frozen; binding is the entire exact readVerified record.
{
    binding: verifiedBinding,
    connection: {
        expectedEndpoint: { ip: '192.0.2.17', port: 22, username: 'synthetic' },
        expectedHostKeySha256: '<64 lowercase hexadecimal characters>',
    },
}
```

The address/key above describe the local test fixture, **not production trust**.
The full binding includes immutable accepted operation/node/profile/candidate,
claim owner/attempt, acquired generation, command IDs, predecessor, boot and
original `maintenanceId`. The reader must freshly establish that exact binding
and the still-held maintenance/external-writer exclusion scope, and verify the
independently accepted endpoint + SSH public-key wire-blob SHA-256 enrollment.
A request, mutable HyNode document or frozen object alone is not authority.

The executor rejects absent/mutable/malformed/cross-bound authority, compares
later pins to the original endpoint/key rather than silently adopting changes,
and passes **only `connection` as resolver argument two**; argument one remains
exactly `{ nodeId, role }`. Revalidation occurs before initial resolution,
after resolution before bootstrap, after bootstrap before prepare, and before
every commit/verify/rollback/cleanup dispatch. Rehydration has the same checks.
The dormant terminal scope revalidates before both close and fresh status.
No new worker gate, runtime reader installation, release or handback is added.

**Required follow-up, intentionally not implemented here:** the real
`TopologyExecutionBindingStore` has no `readVerifiedConnection` method and its
enrollment does not bind an accepted endpoint. Extend the separately owned
immutable enrollment/authority contract with exact endpoint + physical key and
current scoped verification before implementing this method. Merely projecting
mutable node fields or adding a fallback pin is unsafe. Until then, even an
otherwise verified real store passed directly to the executor refuses locally
before resolution/bootstrap/SSH.

Positive integration tests explicitly wrap the real store with a **simulated
trusted authority adapter**. It holds a separately captured immutable accepted
binding, checks current real-store ownership/maintenance, and supplies a fixed
local fixture endpoint/key independent of mutable HyNode fields. Terminal
checks use the original held `withVerifiedBinding` scope. These tests exercise
the real resolver's second argument and exact endpoint checks with local-only
SSH/runner adapters, not a production authority or live network handshake.

## Test evidence

### Pinned resolver reconciliation

- Reproduced **23 failures / 98 tests** in the unmodified real-Mongo binding
  suite after the resolver's production pin requirement (no skips). The failures
  were the missing executor second argument, not authorization to weaken PROD.
- Additional RED→GREEN cases: a verified binding without the explicit connection
  reader incorrectly dispatched; the resolver received no trusted pin; and
  terminal status dispatched after close revoked connection authority.
- Final focused run: **298 passed, 0 failed, 0 skipped, 0 cancelled**, serial
  Node tests without force-exit. It includes real scratch replica-set binding
  tests plus executor, commit uncertainty, resolver, execution context, runtime
  composition, worker claim fence and worker suites.
- Existing loopback `nodeSSHHostKeyPin.test.js`: **14 passed, 0 failed,
  0 skipped, 0 cancelled**, including direct/pooled mismatch before authentication.
- Syntax checks and `git diff --check` pass. Repository/model, resolver,
  NodeSSH, SSH pool, runtime and worker sources are unchanged.

Final focused command (synthetic local configuration only):

```sh
NODE_PATH=/home/leon/c3-int-verify/node_modules \
C3_MONGOD=/home/leon/.hermes/cache/scratch/c3-queue-mongo/mongodb-linux-x86_64-debian12-8.0.16/bin/mongod \
PANEL_DOMAIN=synthetic.invalid ACME_EMAIL=synthetic@example.invalid \
ENCRYPTION_KEY=01234567890123456789012345678901 SESSION_SECRET=synthetic-local-session \
node --test --test-concurrency=1 \
  src/modules/relay-l2tp/tests/{topologyExecutionBindingStore,topologyOperationExecutor,topologyCommitUncertainty,topologyNodeExecutionResolver,topologyExecutionContext,topologyRuntimeComposition,topologyOperationWorkerClaimFence,topologyOperationWorker}.test.js
```

The Mongo suite creates/drops a uniquely named scratch database and stops/removes
its loopback replica set. Local negative-path transport logs are expected. No
remote deployment, production database access or worker gate change occurred.

### Earlier V2 wiring evidence

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
