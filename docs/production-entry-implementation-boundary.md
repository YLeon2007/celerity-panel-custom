# Supported PROD topology entry (source v2; no deployment)

## Default assembly

The ordinary `index.js → createL2tpRootLifecycle().startAfterDatabase()` now selects
`createRootTopologyExecutionAuthority`. TEST retains its previous factory and
wrappers. Canonical PROD opt-in selects the separate production producer; flags
alone do not admit startup. Missing private accepted configuration refuses before
model/host/worker effects. Default PROD remains dormant.

The PROD branch attaches the physical scope, verifies actual deployment/schema
and explicit admission state read-only, constructs the normal root/host with the
SAME producer and `startWorkers:false`, enrolls owners, then starts the ordinary
consumers. It does not run generic migrations/index creation. Topology-only PROD
is not disabled by the separate L2TP production flag; existing PPP/L2TP guards
remain independent. Connection `autoIndex:false, autoCreate:false` is unchanged.

`verifyProductionStartupSchema` checks accepted database/replica/manifest against
actual completed indexes (`includeBuildUUIDs`), stable collection UUIDs and the
explicit current singleton. Later revisions, nonzero counters, reservations and
history are neither reset nor treated as first-install absence. Existing
admission/recovery/CAS consumers still decide whether work is admissible.
`verifyInitializedProductionAdmission` remains a separate first-activation
baseline helper; its ten classic pins/initial state are NOT a restart gate.

## First classic activation and temporary reentry restriction

For nonempty selected profiles without explicit `legacyTopology`, ordinary PROD
enrollment reads descriptors and fixed profile bytes under the held scope before
capture. `verifyLegacyAppliedProfile` checks every peer, including the exact
scoped classic bootstrap rule order. Desired status alone is never applied
authority. Mismatches retain the bounded `CLASSIC_BASELINE_IMPORT_REFUSED`
diagnostic; no owner/settled record is manufactured.

After public handback to classic, settled metadata or retained native
operation/binding history prohibits another activation with
`TOPOLOGY_BUSINESS_REENTRY_BLOCKED` and a fixed Russian explanation. The
restriction is enforced at ordinary production entry and TEST activation API;
`GET /api/cascade/topology/activation-policy` is a read-only UI projection.
The network UI disables repeat activation, not classic Deploy or operations in
the first active epoch. Zero-business reentry still requires all existing
authority/enrollment checks. No history, aliases or users are reset. Full
business reentry is intentionally not implemented in this release.

## Physical producer and exact installation contract (not installed here)

Server policy is the private root-controlled regular file
`/etc/celerity/topology-production.json`, with no symlink/writable ancestor:

    version: 1
    executionContext: { target: production, hostIdentity: lm1.infograd.online }
    mode: enroll | runtime
    admission: { serverContext, databaseName, maintenanceGeneration,
                 deployment: { setName, replicaSetId }, manifestSha256 }
    host: host pin
    nodes: selected node/profile pins
    legacyTopology: optional independently accepted APPLIED descriptors/bytes

Each physical pin binds `kind` (host/node), exact `policySha256`,
`physical:{machineId,bootId,sshHostKeySha256}`, `endpoint:{ip,port,username:'root'}`,
`privateKeyPath` below `/etc/celerity/`, and `maintenanceId`. Node pins additionally
bind `nodeId`, `targetProfile`, `proofRef`, exact original readback and
`acceptedOwner:{owner:'absent'|'classic'|'topology',generation?}`. Runtime pins must
also carry separately accepted `originalScope:{epoch,bundleSha256,ownerGeneration}`.
No accepted pin is generated from the live DB or desired configuration.

Normal host-key-pinned production SSH invokes:

    /usr/bin/python3 -I -B /usr/local/libexec/c3-production-physical.py

Install source `scripts/production-topology-physical.py` at that path, and the
shared `scripts/test-node-isolation/original_effects.py` as
`/usr/local/libexec/c3-production-original-effects.py`. Existing fixed
`c3-prod-maintenance/authority_helper.py` and `exclusion_guard.py` are reused;
there is no TEST runner, port 2222/2223 or preinstalled-runner bypass. The ordinary
executor retains the existing shell/SFTP bootstrapper (`runnerTransport` absent).

Each execution host has private accepted
`/etc/celerity/topology-production-node.json`. Required fields are `version:1`,
`serverContext` canonical PROD, `kind`, exact physical/endpoint identity,
`maintenanceId`, `guardChallenge` with canonical PROD context and its
`guardChallengeSha256`, accepted `guards`, `oldBackend`, and `codePins` for the
three fixed producer/core/effects files. A node policy also binds `nodeId`,
`targetProfile`, complete accepted `profiles`, `originalSnapshot`, `xraySha256`.
Create the private root-owned store `/var/lib/celerity/production-physical` before
use; do not pre-create original/binding/restore records. Nothing is installed or
created on any host by this source task.

Guard pin fields and resident guard policy remain exactly the existing
production-maintenance guard contract (see `production-admission-maintenance-authority.md`).
This producer reuses only low-level authenticated peer identity/SCM_RIGHTS/OFD
exchange, not `withHeldMaintenance`, its one-shot broker or its 300s lifetime.
The already resident guard retains independently established exclusion. Actual
PID/start/boot/executable/argv/source/OFD identities are checked; guard argv stays
exactly `/usr/bin/python3.13 -I /usr/local/libexec/c3-prod-maintenance/exclusion_guard.py`.
The full independently accepted old process-tree inventory includes the named
old backend PID/start. Every original process must actually be absent (or a
reused PID must have a different start), not merely frozen. Machine/boot/raw SSH
host-key and actual `SSH_CONNECTION` server endpoint are checked independently.

Completeness of the pre-established old-writer/future-dispatch/bootstrap/alias/
endpoint exclusion envelope is still an independently accepted physical premise,
not something matching flags or a sampled local process list establishes.
Root administrators remain the existing TCB. No new global write barrier,
privilege framework, rearm, thaw, source-context bypass or recovery protocol is
introduced. The fixed guard's one-attach/no-reattach/UNKNOWN behavior is preserved.
A prior owner row, old result or saved bundle cannot authorize reattaching a
consumed/poisoned guard. Such a cold restart refuses and retains exclusion rather
than reconstructing an original holder or replaying work. `runtime` validates an
independently accepted authentic retained epoch; it does not repair a lost one.

A cohost may use one actual helper/OFD only when the COMPLETE independently
accepted physical policy, machine/boot/key, endpoint, maintenance ID and key path
are identical. Logical host and selected node/profile roles remain separately
checked; equal IP alone never aliases MAIN/SIDECAR or host identity.

## Original epoch, ownership and handback

Capture is before adoption and requires genuinely absent V2/operation/backup
state. Exact original config/unit bytes, metadata, service state and supported
runtime users are captured with shared `OriginalEffects` into a new private
no-overwrite bundle. They are not reconstructed from current config or a DB
receipt. Guard/source/physical identities and the durable bundle are rechecked.
Binding to the actual `binding.nextGeneration` is durable BEFORE owner CAS.

The actual public `initializeClassic → adopt → preEnroll` APIs are used. Existing
classic ownership needs its exact independently accepted generation; existing
rows are never overwritten by initialization. The store receives exactly seven
public fields, with `ownerGeneration=adopted.generation`. Optional legacy import
uses only separately accepted APPLIED bytes and the unchanged profile verifier.
TEST captured-enrollment wrappers retain their context guards; only their
callback-lifetime core is shared with the new explicit PROD method.

For the same running root instance, the internal operational method
`handbackProductionOriginalsAfterDatabase(acceptedCurrent)` first joins the actual
consumer stop/drain WITHOUT closing the sole producer. It retains unknown locks,
admissions, reservations and history, compares the exact accepted CURRENT with
fresh physical readback, prepares ALL participants, then restores captured bytes
and verifies files, service state and runtime users. A genuinely pristine
undispatched scope has an explicit absent-journal branch; absence is not inferred
for an existing operations/backups directory. Existing native journal, terminal
receipt, predecessor and original-epoch checks remain required otherwise.

Public `TopologyConfigTransfer.handback` performs its unchanged actual-generation
CAS and majority readback against originalSnapshot/adoptionReceipt. The existing
full-history ownership predicate must also allow classic before the original
holder releases runner FDs. This never thaws the independently retained resident
exclusion guard, erases history or dispatches an old backend. Failure is retained,
not compensated or retried. Whole-scope operation/lease caps and the restoration
115s bound are not extended.

## What local evidence does and does not prove

The focused ROOT test uses the actual new producer constructor, ordinary default
root/host/consumers, real OWN Mongo, actual public transfer/store and actual local
exclusive flock. The private-config/SSH/node IO seam is explicitly MODELED. It
verifies both prior entry failures against saved old root bytes, accepted startup,
real adopt generation/preEnroll, default normal bootstrapper selection,
cohost role separation, before-host stale/mismatched refusal and exact captured
OWN bytes restored before real verified handback. It does not execute a topology
job, live SSH, native runner, service, tunnel or production rollout.

A separate bounded mechanism check executes the actual production Python Holder
class body and shared byte effects against real OWN files/cache/metadata/flock;
remote path/physical identity/systemd observations are MODELED. It does not
pretend to exercise the privileged installed guard/SSH path. Shared TEST default
context remains exactly TEST. The installed default helper is syntax-checked;
its privileged physical installation and actual production baseline remain
unobserved. SOURCE/local-assembly evidence is not PHYSICAL or PROD readiness.
