# Held TEST owner settlement (internal, not global handback)

`HeldTestOwnerSettlement.settle(plan)` is the explicit final DB owner step after
**all five** nodes have been physically restored under the existing coordinator's
actual `NodeOriginals.restoration_hold()` scopes. It calls the **unchanged public**
`TopologyConfigTransfer.handback` for each node. Each public transfer preserves
its existing original-snapshot check, generation-fenced transaction and fresh
primary-majority owner readback. No new retirement/schema/admission protocol is
introduced.

## Preconditions and result

- Canonical TEST only; exact five node/profile IDs are source-owned. The plan
  independently pins each enrollment ID and original topology owner generation,
  plus exact topology/deployed revisions. No automatic discovery/adoption.
- The real external restoration scope must remain continuously live through every
  transfer, final readback and durable journal write. A receipt, bool, restored
  phase string or DB marker is never authority.
- Primary-majority bounded reads require **zero** NodeOperationLocks, topology
  admissions and remote admissions; no running/queued operations, uncertain
  retained admissions, pending/blocked intents, outstanding queue work, candidate
  active links, remote drain or replacement reservation. Missing counters/queue
  state or oversized histories refuse. Existing finalizers must settle retained
  operation locks/admissions first; this entry never deletes/zeros them.
- Existing RestorationChannel fresh checks call all five NodeServer checks,
  which verify actual restored bytes/unit/service/runtime, original outer/runner
  flock OFDs, closed dispatch admission and exact pinned terminal/current-head
  journal state. An uncertain/in-flight command cannot pass that channel.
- Existing immutable enrollment/binding history remains untouched. Changing the
  config owner to classic with a fresh generation invalidates the existing store's
  exact topology-owner-generation predicate. There is no retirement collection.
- Output `TEST_DB_SETTLED_ALL_EXTERNAL_HOLDS_RETAINED` means only a checkpoint
  **inside that still-live held scope**, with `handbackAllowed: false`. It never
  thaws, unmasks, reopens dispatch/SSH, restarts old writers or authorizes serving.

## Finite operational entry

`node scripts/test-node-isolation/settle-held-owner.js` is a separate root-only,
argument-free operator entry. It is not mounted in HTTP/MCP or panel startup and
creates no collections/indexes. It requires an already discovered Mongo replica
set and already initialized TEST models/indexes. It never connects via SSH or
installs anything.

The small installed bridge is
`/usr/local/libexec/c3-test-owner-restoration-channel.py`, sourced from
`scripts/test-node-isolation/owner_restoration_channel.py`. It imports the
**pinned existing** coordinator and opens its existing root-peer
`RestorationChannel`. Its private parent/child stdio contract is exactly:

```
{"version":1,"op":"check","nonce":"<64 lower-case hex>"}
{"version":1,"op":"checked","nonce":"<same fresh nonce>"}
```

No release/finish/restore/dispatch verb, shell fallback, JSON GO or extension of
the coordinator protocol exists. EOF, unexpected output, nonce mismatch, timeout,
peer/source/pin drift and swallowed validation failures revoke permanently. The
Python bridge uses the existing root UDS SO_PEERCRED/PID/start/nonces validation;
it deliberately never calls `RestorationChannel.__exit__`, which sends `finish`.

The fixed root-owned private config is
`/etc/celerity/topology-test-owner-settlement.json` (version 1), with exactly:

- `mongoUri`: independently approved TEST discovered replica-set URI;
- `coordinatorSha256`, `bridgeSha256`: installed exact source hashes;
- `plan`: `{revision, deployedRevision, nodes:[{nodeId,targetProfile,enrollmentId,ownerGeneration}]}`;
- `acceptedOriginalsBase64`: exact original accepted-manifest raw bytes, keyed by
  the five node IDs. Their SHA-256 must match each existing coordinator
  `nodes[id].files.accepted` pin. All manifest identities must match the existing
  coordinator, including boot/maintenance/plan/physical key identity;
- `oldBackend`: independently accepted `{instanceId,pid,processStartTime}` from
  the already held/drained original backend, diagnostic metadata for public
  transfer receipts (never a substitute for the live guard).

The live all-five verification checks originals against those exact accepted
manifest bytes; only then can the adapter project their config/unit digests and
service states into the public handback proof. DB enrollment identity, boot,
maintenance, runner endpoint (`2222`, `c3-test-runner`) and owner generation must
match the independently held scope as well. No secrets/original bytes are printed.
All config/helper ancestors must be root-controlled and non-writable by others.
This source change does **not** install/provision that config, helper or a root
launcher; deployment requires separate review/authorization.

After DB settlement the entry prints its checkpoint **while all holds are still
open** and keeps checking the actual channel for the remaining existing finite
restoration lifetime. It cannot extend that lifetime or perform combined release.
Expiry/EOF/error ends with exit 75 and retained uncertainty; it does not turn the
earlier checkpoint into a reusable permission. The callback API can instead be
owned by a separately reviewed combined orchestrator, which must keep the scope
live itself. No such global release is implemented here.

## Durable partial progress / failures

`/var/lib/c3-test-node-isolation/owner-settlement.json` is a private fsynced
no-overwrite intent. Before each public transfer it records `inFlightNode`; only
confirmed majority owner readback records the fresh classic generation and moves
to the next node. File and parent directory are fsynced before acknowledgement.
The journal contains no credentials or raw receipts. Five confirmed handbacks
produce `phase: settled-held`; every existing journal or `.next` refuses replay.

Transfers are intentionally the existing **per-owner** public transactions, not
a new all-five transaction. A failure can leave some owners classic and others
topology. Such partial progress is durable, remaining fences stay held, and no
later owner is transferred. Unknown commits/readbacks are not remotely rolled
back. A visible/fsynced progress record is still not live authority. There is no
cleanup, startup repair or re-adoption; reconciliation must inspect the journal
and exact Mongo generations under independent holds. The entry never automatically
retries/resumes a partial transfer sequence; the existing public handback
transaction implementation is unchanged.

## Local proof boundary

The Mongo suite uses a real isolated MongoDB 8.0.16 replica set and public
`initializeClassic -> adopt -> real-store preEnroll/createBinding` paths. It runs
the actual JS adapter and Python finite codec with **SIMULATED independent
physical/root authority**. Prior operation terminal reconciliation in the fixture
is explicitly simulated through public model/exact-generation lock methods; the
new entry does not perform it. It proves zero-lock/admission refusal, all-five
owner handback/readback, immutable history, genuine transaction abort, postcommit
guard-loss partial progress, stale-generation store refusal and escaped-scope
revocation.

The separate Python suite runs actual local five-node restoration processes,
original flock OFDs, the existing root-peer UDS channel, and the new bridge's
real codec; physical/kernel/systemd/SSH and UID authority are **SIMULATED**.
It proves the flocks are still held at acknowledgement, one-node loss revokes,
and the bridge cannot finish/release. None of these tests is a live GO, deployed
physical attestation, combined host handback or production activation proof.
