# Dormant V2 terminal protocol proof — data, never handback

## Delivered boundary

`TopologyOperationExecutor.close(lifecycleContext)` is an explicit server-only
API after this executor has validated `verify` or `rollback`. It is **not wired
into the worker, runtime, routes or host**. Existing public lifecycle receipts
are unchanged. Successful rollback retains its private executor binding only so
that this optional close can run; further mutation through that receipt refuses.

The insert-only binding has five distinct globally indexed command IDs:
`prepare`, `commit`, `verify`, `rollback`, `close`. Status queries the exact
persisted **close ID**, with `completedCommand: 'close'`; a separate status token
would contradict the runner's exact-command lookup protocol. Old four-command
rows are refused, not upgraded or adopted. No migration is included.

The immutable executor record includes enrolled `bootId` and `maintenanceId`.
Every receipt must match the boot. Enrollment, binding creation, ordinary reads
and scoped terminal reads must retain the original maintenance identity. No
request can mint/replace attempt, command, predecessor, boot or maintenance IDs.

`withVerifiedBinding(expected, awaitedCallback)` holds the store's trusted
external authority with an explicit `action: 'terminal'` challenge (not a
read-only grant) across initial transactional validation, close dispatch,
fresh status dispatch and final primary-majority validation. The callback gets
an immutable record and an `assertCurrent()` function. Close checks the original
binding against this record, calls `assertCurrent` before each dispatch and after
status, and the store checks again before returning. Each check validates the
same accepted operation/revisions/node/profile/candidate, exact live claim
owner/attempt, acquired lock generation, physical owner and immutable enrollment.
The held authority must continue to exclude bootstrap/classic/alias writers;
missing or changed evidence refuses. This is not a replacement for the externally
sustained whole-lifecycle exclusion required by the storage contract.

Both close and fresh status must return exact V2 receipts for the expected host,
operation, node, profile, candidate, backup, attempt, generation, predecessor,
close command ID and boot, with completed systemd work, `phase: 'closed'`, the
expected verified/rolledback outcome, and `ownershipRetained: true`. Status must
match the close receipt field-for-field except its command name. An uncertain
close/status poisons the local prepared binding; it is not retried or used for
rollback/mutation. A terminal receipt is returned as **frozen protocol data**.

No code releases a node lock, decrements admission, invokes a classic writer,
changes physical ownership, publishes operation success or opens the queue.
The PROD preclaim gate and `TOPOLOGY_V2_HANDOFF_UNPROVEN` remain unchanged.

## Local evidence

Observed RED before implementation:

- Real scratch Mongo binding returned four IDs, not five.
- Held terminal binding scope was absent.
- Actual runner lifecycle completed verify/rollback, but executor close was absent.
- Creating a binding under switched post-enrollment maintenance was accepted.

GREEN: **468 passed, 0 failed, 0 cancelled, 0 skipped**, serial Node test runner,
no force-exit flag. This includes the store, executor, worker, uncertainty,
runtime/context/claim/recovery/finalization, runner, transport/factory/resolver,
bootstrapper, operation repositories and panel-host suites. The scratch suites
start loopback-only Mongo replica sets, use fresh guarded databases and clean up
their child processes and data; no remote Mongo/SSH is used.

New assembled tests run the real resolver, executor, transport/factory and
**actual runner entry point** in a disposable fake root alongside the actual
Mongo repositories/models. External authority and systemd/Xray are explicitly
local simulations. They prove verified and rolledback close/status, rejection of
late prepare/commit without further service effects, unknown/corrupt/missing
journals, a real held `flock`, reboot identity, altered status, missing scoped
reader, missing classic/bootstrap exclusion, switched maintenance and lock loss
before/after status. All uncertain cases retain admission, lock ownership (or
the injected winner), and topology config ownership.

Nearest-suite expansion found an inherited stale bootstrapper **test fixture**
digest. Both parent and working runner bytes hashed to
`fd5ed2f985841e9b8e1fa9e84597839cf60f10240f28343a2575b7067889b98c`;
only that fixture pin was corrected. Neither bootstrapper nor runner source was
changed. An initial optional Mongo claim test lacked `C3_MONGOD`; the final full
run supplied the scratch binary and reported zero skips.

`bash -n` passed for the runner and topology artifact test script; the existing
payload-only topology artifact shell fixtures also passed. Those fixtures are
not independently claimed as entry-point exclusion evidence. `git diff --check`
passed. Synthetic config and an unusable loopback fallback Mongo URI were used
for config-importing tests; only explicit scratch connections were exercised.

## Still NO-GO for production

This slice does not provide real external writer exclusion or endpoint physical
attestation, deploy/register models or indexes, enroll a production node, install
a reader into runtime, activate a worker/flag, or touch the serving backend/TEST.

Still required before any execution/release enablement:

1. Real externally sustained old-PID/dispatch/classic/bootstrap/alias exclusion,
   physical SSH endpoint attestation and recoverable operational transfer.
2. Reviewed production provisioning/adoption/predecessor+boot enrollment under
   that authority. Empty-runner enrollment remains unsupported.
3. Persisted terminal-result/restart reconciliation and successor/recovery
   authority. This API only returns fresh proof to its live caller; rehydrated
   handles must revalidate verify/rollback before close and cannot adopt another
   attempt/generation. No uncertain-status reconciliation/retry is implemented.
4. Safe user/PPP/ingress integration, atomic physical ownership handback and exact
   lock/admission release. Terminal protocol data alone authorizes **none** of it.

This is local protocol/orchestration evidence, not deployed smoke evidence or
proof that arbitrary host writers have stopped.
