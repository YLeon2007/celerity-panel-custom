# Explicit TEST owner enrollment command

**Source-only, not a live-operation authorization.** The finite capture hook is
now selected by the default factory; actual all-five capture/UDS is implemented.
Default operational enrollment nevertheless stays refused: the separate installed
physical observer conflicts with the capture holder's retained outer flock.
See [the exact known-negative boundary and operator pins](topology-test-durable-capture.md).
The original hook contract below describes the interface, not closure of that
remaining observation-composition dependency.

## Invocation and real composition

```sh
node scripts/test-topology-owner.js enroll
```

This is the sole CLI verb. No inventory, node ID, receipt, module, config path,
command or bootstrap argument is accepted. Existing private `dotenv`/`config.js`
provides database credentials; credentials, config/unit bytes and driver errors
are never printed. Required eligibility is the exact TEST host
`test.infograd.online`, all three TEST runtime flags already configured as
`true`, and neither production execution flag. Flags are eligibility, not physical
or backup authority. The existing physical controller still independently reads
only its fixed root-controlled `/etc/celerity/topology-test-physical.json` and
requires all five accepted node/endpoint/machine/key/boot/guard/plan/original pins.

The CLI calls `createL2tpRootLifecycle().enrollTestOwnersAfterDatabase()`:

1. Compose the real runtime lifecycle/startup/panel host without calling `start`.
   Do **not** run migration/bootstrap, install indexes or schedule any workers.
   The same-connection schema and unique indexes must already be installed.
2. The existing `createTopologyOperationRuntime` composes its ordinary default
   typed executor, worker and actual `TopologyExecutionBindingStore`. Its new
   internal explicit entry closes over **that same** private held lifecycle/store
   and actual config-owner model; no alternate store or controller is constructed.
3. Enter `TopologyExecutionAuthorityLifecycle.run`, then the controller's
   `withCapturedTestOwnerEnrollment`. Require all-five durable capture before the
   first candidate DB write, not just before runner dispatch.
4. For each accepted fixed pin, call the public
   `TopologyConfigTransfer.initializeClassic → adopt`, using the returned classic
   generation and independently accepted `originalSnapshot.proofRef`.
5. Call that actual store's public `preEnroll` with the returned adopted
   generation, exact accepted endpoint/machine/key/boot and predecessor `none`.
   **`preEnroll` already executes the `action: enroll` held protocol**; no second
   public `store.enroll` API exists or is invented here.
6. Return only node/profile/enrollment ID/owner generation metadata after all
   public transaction and majority-readback checks succeed. Stop joins the entry
   and closes observers only. It never releases guards, locks or admission.

Normal `index.js` startup never calls this entry. A root instance used for
explicit enrollment cannot subsequently start its background workers or repeat
that command. This is deliberately one-shot: no implicit adoption, raw owner
rewrite, upsert, retry, rollback or cleanup after partial/uncertain writes.
Existing owners cause the public insert/CAS path to refuse. Recovery is separate.

## Precise remaining parent hook — default stays closed

The installed physical observer is read-only. Its process-local secret byte
cache is **not** crash-durable NodeOriginals capture. The finite installed capture
hook now executes the required capture protocol, but the separate observer's
outer-lock reacquisition is still incompatible with the retained capture hold.
No environment/request/config receipt alternative is supplied:

```js
createTestPhysicalController({
  config, openChannel,
  withDurableNodeOriginals: async (challenge, callback) => {
    // Parent-owned implementation, NOT supplied by this slice:
    // actual fixed NodeOriginals capture protocol + fsync + independent exact
    // readback on every one of the FIVE nodes under the already held guards.
    // If ANY node is missing, changed, uncertain or not captured: throw.
    return await callback(async function checkDurable() {
      // Freshly validate ALL exact durable bundles and held capture authority.
      // Throw on drift/loss/unknown; returning a receipt is not this capability.
    });
  },
});
```

The snippet states the trusted interface, not runnable operational code. The
ordinary `createRootTestPhysicalAuthority` now supplies the fixed installed helper
adapter; no arbitrary module/path/opcode loader is provided. It does **not**
close default enrollment: observation must first be composed inside the actual
capture-held OFD, as documented in `topology-test-durable-capture.md`. A no-op
checker or successful-looking JSON receipt cannot substitute for that closure.

`challenge` is deeply frozen:

```text
{ version: 1, executionContext: exact TEST,
  nodes: exactly the five accepted entries, each:
    { nodeId, targetProfile, endpoint, nodeIdentity, bootId,
      maintenanceId, planHash, guard, originalSnapshot },
  host: complete accepted shared host owner/guard/backend identity }
```

Accepted pins precede observation and may never be populated from the capture
response or mutable HyNode rows. Require the actual NodeOriginals protocol's
installed helper/pin identity, held node/shared authority, private durable bytes,
fsync and exact postcapture readback. The hook must invoke its callback exactly
once and await it through cleanup, keeping external authority held throughout.
Its `checkDurable` must recheck all five bundles against these exact pins, without
printing secret bytes or changing accepted values. The application additionally
checks actual current config/unit hashes/states and the full five-node hold before
and after every awaited public owner/store operation. Missing hooks, booleans,
receipts, unawaited/escaped callbacks and checker failures refuse and revoke the
scope. This is a trusted-capability boundary, not proof that arbitrary injected
JavaScript implements durable capture.

## Local evidence and boundaries

`test-topology-owner*.test.js` covers finite CLI/context refusal, no startup/schema
writes, one-shot mode, actual controller/lifecycle callback authority, all-five
capture ordering, last-node drift and escaped checks. With `C3_MONGOD` set to a
reviewed local binary, it starts a loopback-only replica set beneath `TMPDIR`,
composes the ordinary root/default worker/default executor/real store, verifies
zero DB mutations after capture refusal, and performs all five public
initialize/adopt/preEnroll transitions with exact stored generations, snapshots,
physical endpoints and maintenance identities. It drops/verifies absence of its
exact scratch database and terminates its Mongo process. It does not dispatch a
runner or claim nonempty client traffic. Non-topology services are inert local
seams; physical/kernel/systemd/SSH and durable-backup authority are explicitly
**simulated** in this assembled fixture.

DB settlement, restoration/serving rollback, live TEST acceptance and safe shared
handback remain separate. `SHARED_HANDBACK_UNAVAILABLE` is unchanged. No successful
owner enrollment, metadata receipt or command exit authorizes shared thaw,
old-writer restart, admission/lock release or production activation.
