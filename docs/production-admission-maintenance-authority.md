# Canonical-PROD admission maintenance: bounded, dormant entry

This is **not production activation or an approval to run maintenance**. It adds
an attach-only operational entry for the existing insert-only
`productionAdmissionInitializer`. No application startup, TEST controller,
launcher, lifecycle, worker or executor guard is changed. Success remains
`initialized: true, ready: false, dormant: true`; every external hold remains
retained. Failure reports `initialized: null`, not an invented rollback.

## Trust and supported exclusion envelope

The canonical context is exactly `{target: "production", hostIdentity:
"lm1.infograd.online"}`. No TEST alias, UI receipt, environment switch, scanned
pin acceptance or configurable executable is available on the public CLI.

The authority **attaches to already established exclusion**. Its resident root
guard checks independently accepted, root-controlled cgroup-v2 frozen scopes,
the exact complete PID/start inventory below those scopes, their accepted
device/inode identities and the accepted host boot ID. It owns one actual flock
for its entire lifetime. The finite broker receives a duplicate of that same
open-file description using `SCM_RIGHTS`; it never acquires or reacquires a lock.
Kernel `fdinfo` is checked for the exact flock kind, write mode, owner PID,
device, inode and range. A root-peer UDS, pidfd, process start, executable digest,
argv digest and the exact private guard/codec source digests are checked too.

**Scope completeness is an independently accepted physical prerequisite, not a
conclusion this inventory can establish.** Every old writer and every future
dispatch source must already be excluded, including old backend/updater/SSH
sessions, queued systemd/Docker jobs, alternate roots and remote writers. A
frozen backend alone is NOT eligible. The guard does not discover the complete
writer universe, attest a remote host, cancel manager jobs, enforce a systemd
mask, establish host-route isolation or prove that an absent remote writer
cannot return. Root administrators and the pre-established exclusion envelope
are the TCB. The guard cannot defend against an administrator deliberately
thawing a scope between observations. Its no-release resource lifetime prevents
this implementation's cleanup from causing thaw/reactivation; it does not turn
sampled freezer reads into a new kernel exclusion mechanism.

Thus the local protocol/constructor closure does **not** by itself close PROD's
physical old-writer/dispatch-exclusion gate. Independently prove that envelope
on actual TEST, review the exact source and obtain the production
backup/rollback/remote-exclusion acceptance before installing or invoking it.
No installation, privileged hold, network access or deployment was performed
as part of this source slice.

## Fixed inputs and installation contract (not installed here)

All input files are root-owned regular files with no symlink component and no
group/world writable ancestor. Private files and journal parents disallow all
group/world permissions. Runtime guard sockets and lock files are root-owned
and non-writable by other users. The root CLI has no arguments.

* Entry policy: `/etc/celerity/prod-admission-entry.json`.
* Broker policy: `/etc/celerity/prod-admission-maintenance.json`.
* Resident guard policy: `/etc/celerity/prod-admission-exclusion.json`.
* Broker and guard: `/usr/local/libexec/c3-prod-maintenance/authority_helper.py`
  and sibling `exclusion_guard.py`, installed as private root executables.
* Pinned interpreter: `/usr/bin/python3.13`. Its presence and reviewed digest
  on the destination are explicit prerequisites, not assumed from local tests.
* Future finite invocation, **only after separate acceptance**:
  `node scripts/production-admission-maintenance.js`.

The entry policy has exactly `version` (1), `challenge`, private `mongoUri`,
`helperSha256` and `pythonSha256`. Its independently reviewed challenge uses the
initializer's exact fields:

* `serverContext`: canonical PROD above;
* `databaseName` and `deployment: {setName, replicaSetId}`: exact accepted
  database and replica identity, not selected from the current scan;
* `maintenanceGeneration`: independently accepted UUID;
* `acceptedClassicLinks`: ten distinct `{id, sha256}` pins over complete raw
  BSON records, not IDs alone or a projection;
* `initialState`: the initializer's complete explicit singleton state;
* `manifestSha256`: independently accepted reviewed schema manifest digest;
* `acceptedMissingCollections`: exact first-install `{name, options: {}}`
  eligibility. Missing collections are not inferred to be empty histories.

The broker policy has exactly `version`, `generation`, that same full
`challenge`, `bootId`, `guards`, `journal`, `lifetimeMs` (100..300000).
Each guard pin has `socket`, `pid`, `startTicks`, `executableSha256`,
`argvSha256`, `holderId`, `lock: {path, device, inode}`, and ordered
`sources: [{path, sha256}, ...]`. Operational sources must be the two fixed
installed Python files above, in broker/guard order. The guard's operational
argv is exactly the NUL-separated invocation of `/usr/bin/python3.13 -I` and
the fixed guard path. Do not generate accepted policy by copying current
observations. Do not put credentials or complete link records in logs.

The guard policy has exactly `version`, `generation`, `holderId`, `bootId`,
`challengeSha256`, `scopes`, `lock`, `journal`, `socket`. Each scope has
`path`, accepted `device` and `inode`, and complete `processes:
[{pid, startTicks}, ...]`. Operational scopes are nonempty real cgroup-v2
scopes below `/sys/fs/cgroup`. The helper challenge digest uses UTF-8 JSON
with sorted object keys, compact separators, and no nonfinite numbers.

The resident guard must be independently started in the already established
exclusion envelope, outside the frozen writer scopes. Its journal, lock and
socket must not already exist. Its PID/start/boot/code/argv/OFD pins must then
be independently accepted. Neither public executable has an arm, restore,
release, thaw, resume, retry or automatic stale-file-removal verb.

## Protocol and lifetime

1. The guard creates/fsyncs a no-replay journal, opens its new lock once,
   acquires the flock once and refuses any drift in the accepted frozen scopes.
   The lock is a resource/provenance fence; ordinary legacy writers do not gain
   an enforcement dependency on this newly added lock.
2. The broker creates/fsyncs a separate no-replay attempt journal **before**
   requesting authority. It verifies every guard identity and attaches to its
   existing OFD. An unlocked descriptor, replacement path, wrong peer,
   missing/extra rights or stale holder is refused; every received FD is disposed.
3. Guard frames contain exactly `version`, random 32-byte hex `nonce`, `verb`,
   `generation`, `holderId`, `challengeSha256`; replies add only
   `state: "held-retained"`. `attach` transfers one FD; `check`/`retain` transfer
   none. There is no finish/release operation. A second attach is invalid.
4. Broker frames contain exactly `version`, `nonce`, `verb`, full `challenge`.
   Replies contain exactly `version`, `nonce`, `verb`, `state`. `check` and
   `retain` acknowledge `held-retained`. `close` acknowledges `closed-retained`
   only after required broker cleanup. This closes the observer, NOT exclusion.
5. Newline framing is bounded to 128 KiB. Duplicate Python JSON keys,
   unsolicited frames, extra fields, pipelining, EOF, partial frames, nonce
   drift, deadline loss and revocation fail closed. Broker requests have a
   finite two-second I/O budget, within the unchanged whole-scope deadline.
   The resident guard also bounds an incomplete frame and watches its scopes
   while idle. The guard remains resident holding its OFD after ambiguity.
6. The finite Node entry acquires the external scope before constructing or
   connecting its native Mongo client. It invokes the **real** existing
   initializer through the same scope, not another helper or lock. It checks
   around connection, initializer completion and DB disposal. DB disposal is
   attempted even after revocation; no application pools are imported.
7. The initializer retains its existing exact primary/majority identity,
   full-record, schema, first-install, one-shot commit and unknown-outcome
   rules. This change does not rewrite or relax them. No DDL rollback,
   counter repair, transaction retry or ordinary runtime enablement is added.
8. Callback/precommit/postcommit/DB-close/channel errors retain unknown and
   preserve the primary exception. Scope methods reject after disposal.
   Required stream cleanup and bounded child reap are attempted despite a
   secondary cleanup failure. Only the process-owned broker may be signaled
   for disposal, NEVER its independent resident guards. Ordinary paths finish
   naturally, without `process.exit`, timer `unref` or test force-exit flags.
9. Journals, sockets and lock paths are never removed by product code.
   A second attempt in the same generation is refused even after success.
   Guard disposal closes its own resources but never writes `cgroup.freeze`,
   restores services or resumes any old writer. A separately designed,
   reviewed recovery/handback procedure is still necessary.

The broker's finite transport budget is not a proof that arbitrary application
callbacks or a faulty DB driver cannot block. The production entry uses only
bounded native-driver operations and the existing initializer, not arbitrary
callbacks or startup infrastructure. Revalidate its actual pinned driver and
interpreter on the destination.

## Local verification and its limits

Run from the repository using its lock-exact installed dependencies:

```
python3 -m unittest scripts/prod-maintenance/tests/test_authority_helper.py -v
node --test src/modules/relay-l2tp/tests/productionMaintenanceAuthority.test.js
```

Tests use actual subprocesses, a separate resident guard PID, UDS peer
credentials, pidfds, `SCM_RIGHTS`, kernel flock/OFD identity, finite streams and
process reap. A competing real `flock` is attempted at each modeled DB command,
query and DB close, including after broker revocation. Local files explicitly
model cgroup/systemd/remote eligibility; no real cgroup or host service is
modified. An ordinary scratch filesystem is separately rejected by the actual
`fstatfs` cgroup2 predicate. Filesystem/PID/FD/protocol tests are not proof of
actual remote quiescence.

The constructor test calls the unchanged real initializer but **models Mongo
persistence and replies**. It does not establish real transaction isolation,
majority durability, index-build cancellation or unknown-commit semantics.
The existing real-Mongo initializer suite remains a required integration gate
under the exclusive heavy budget, with the exact deployed dependency set.
During this source task the only borrowed local Mongoose was 8.23.0 versus the
repository requirement `^8.24.1`; its use is limited to BSON/model-free local
orchestration evidence, not lockfile or production driver acceptance.

The public CLI's refusal path is exercised as a real naturally terminating
process. Privileged default-path installation, successful root-policy CLI use,
actual DB connection, physical exclusion, actual TEST rehearsal, source review,
backup/rollback and production activation remain unperformed. No green local
count should be promoted into an all-PROD execution/readiness claim.
