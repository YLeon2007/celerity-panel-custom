# Explicit TEST owner enrollment command

**Source-only, not a live-operation authorization.** The default factory now
selects actual all-five capture plus fresh installed-attestor observation inside
each retained capture-holder OFD. The former separate-observer lock conflict is
closed on this one-shot enrollment path. Independent installed pins, physical
acceptance and the full serving lifecycle remain required; source tests are not
live authority. See [the actual composition and operator pins](topology-test-durable-capture.md).

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

## Actual installed capture hook

The fixed `testDurableOriginals` adapter is supplied by
`createRootTestPhysicalAuthority`; no arbitrary module/path/opcode loader or
request-provided receipt selects authority. It opens the fixed installed
`owner-channel` before the first lifecycle/controller assertion, carries fresh
all-five observations from the actual pinned attestor inside the same capture
holders, and keeps that channel through both final assertions and the final
bundle check. It never reacquires a holder's outer flock from another observer.

The generic `createTestPhysicalController({ withDurableNodeOriginals })`
constructor remains a trusted programmatic seam. Its callback checker is a live
lexical capability, not a boolean or successful-looking JSON receipt. The default
implementation executes the real NodeOriginals capture/publication/fsync/readback
protocol and refuses missing independent pins. This one-shot enrollment capability
does not authorize later candidate dispatch, restoration or global handback.

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
