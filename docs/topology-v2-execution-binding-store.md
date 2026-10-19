# Durable V2 execution binding — dormant, one-shot storage/reader contract

## Scope and non-activation

`TopologyExecutionBindingStore` is a server-only implementation of the existing
executor `readVerified(expected)` seam. It is deliberately **not imported or
constructed** by `createTopologyOperationRuntime`, host composition, routes, MCP
or workers. No flag, migration/startup registration, TEST enablement, PROD
pre-claim bypass, SSH implementation change or deployment is included. Existing
PROD serving backend and TEST candidate are untouched. Default real executors on
both canonical hosts still refuse without a reader; the PROD pre-claim
quiescence refusal and all V2 retained-lock/admission/handback gates remain.

Only the exact canonical **production** server pair is accepted by this bounded
store. The constructor requires all five actual models on one connected,
discovered replica-set connection and a trusted `withVerifiedAuthority`
function. It rejects `directConnection`: the Mongo driver can rewrite a primary
read to `primaryPreferred` on that topology. There are no implicit default
connections, credentials, database names, server identities or authority hooks.

## Immutable records and accepted ownership

- `TopologyExecutionEnrollment` stores explicit node/profile, physical machine ID
  and SSH-host-key digest, config-owner generation, nonempty pre-enrolled runner
  predecessor, runner boot ID and external proof/maintenance IDs. This narrow
  contract requires a UUID predecessor; **`none` is never inferred or accepted**.
  Initial/empty-runner enrollment is not implemented.
- Enrollment is globally unique by node/profile, physical-machine/profile and
  SSH-host-key/profile. An alias cannot acquire another slot for the same
  physical profile, including under another server context.
- `TopologyExecutionBinding` inserts an immutable exact executor record plus the
  enrollment/physical-owner/boot/proof metadata. It binds the accepted operation
  ID, canonical host, topology and prior deployed revisions, candidate hash,
  deterministic backup ID, node/profile, numeric claim attempt and owner, and
  **the already-acquired node-lock generation**. Server-generated UUID attempt
  and five distinct command IDs (including `close`) are never accepted from requests.
  The executor projection now also includes enrolled `bootId` and `maintenanceId`;
  every ordinary receipt must match that boot, and maintenance cannot switch
  between enrollment, creation, reads or terminal reconciliation.
- Unique indexes enforce one binding per operation/node/profile and enrollment,
  unique attempt IDs, and cross-record/cross-command ID reuse exclusion through
  a unique multikey `commandTokens` index. There is no update, adopt, reclaim,
  delete, lock acquisition, lock release or admission-decrement API. Model
  updates, replacements, query/document deletion, existing-document saves and
  bulk writes refuse; privileged raw collection access is outside this API's
  trust boundary, not cryptographically protected database storage.
- This is intentionally **one-shot**: a consumed enrollment cannot authorize a
  successor or another attempt. Failed/unknown work retains its rows. Recovery,
  successor enrollment and physical-profile ownership handback require a
  separately reviewed protocol, not deletion/reinsertion of evidence.

`createBinding` and `readVerified` use the actual accepted `TopologyOperation`
schema and the existing production claim-key grammar. Both require an active,
unexpired exact attempt/owner, held topology admission, exact frozen revisions,
a unique matching node/profile, valid canonical candidate bytes and backup
identity. They transactionally CAS that operation, the exact current unexpired
`NodeOperationLock` (including explicit `remoteUncertain: true`), and the paired
`TopologyConfigOwner` in `topology` ownership with matching physical identity,
owner generation and adoption generation. They never replace a generation or
adopt an expired/reacquired lock. Missing, legacy, foreign, cloned, stale or
malformed rows fail before node lookup/SSH. Optional `executionBindingCheck`
nonce fields on the three existing schemas are transaction fences, **not**
remote quiescence evidence and have no read-time defaults.

## External authority is mandatory, not implemented here

`withVerifiedAuthority(challenge, awaitedCallback)` is constructor-injected from
trusted server composition only. Enrollment, creation **and every read** require
its fresh exact challenge proof of held maintenance, all writers drained,
bootstrap exclusion, old backend instance/PID/start identity, old process tree
stopped and future dispatch disabled, physical profile ownership, and exact
pre-enrolled predecessor + boot identity. Returning a boolean/row, supplying a
request proof, calling back later, or starting but not awaiting the callback
cannot grant authority. The challenge and accepted values are copied/frozen;
a callback cannot be reused outside its held scope.

The adapter must actually attest the selected endpoint's machine/host-key and
all aliases; metadata equality is not a live physical attestation. Its exclusion
must be externally sustained across the **whole remote lifecycle**, including
lookup, bootstrap, command dispatch, descendants, terminal reconciliation and
handback—not merely the individual Mongo callback. This slice only checks the
held validation/commit/readback scope and cannot manufacture that larger fence.
The existing resolver/SSH layer does not independently attest/pin that physical
identity for this contract. A callback returning the documented shape without
real verification is untrusted and must never be installed in production.

No such real authority or remote-spanning old-writer/endpoint fence is available
in this slice. Positive tests explicitly simulate it; **PROD is still NO-GO**.

## Transaction and uncertainty behavior

Enrollment inserts and binding inserts/validations use one snapshot transaction
on the shared connection, primary routing and majority commit. The operation,
node lock and config-owner CAS nonce is written in that same transaction;
transaction conflicts/misses abort the entire insertion. There is no retry of
the transaction or regeneration of IDs after an ambiguous commit.

Commit uses a 5-second driver timeout and server commit budget. A reported
`UnknownTransactionCommitResult` permits only one exact primary-majority
readback pass, outside the transaction, with a shared 5-second deadline. It
confirms the immutable record plus the exact transactional owner/claim/lock CAS
nonces and fresh leases. Normal commits require the same confirmation. Absence,
read failure, timeout, changed record or replaced fence cannot acknowledge;
there is no local-read fallback or automatic deletion/release. Individual
transaction I/O and aborts also carry bounded driver/server options.

A successful read proves this local durable acceptance/validation boundary,
not future lease ownership or remote completion. The executor still rechecks
before bootstrap/dispatch and each lifecycle command; node-side enforcement,
external writer exclusion and final handback remain separate requirements.

## Local evidence and remaining prerequisites

`topologyExecutionBindingStore.test.js` starts an actual loopback-only MongoDB
replica set under `TMPDIR`, uses a fresh guarded random scratch database and
actual operation/lock repositories plus all real schemas, then drops only that
DB, verifies absence, terminates its child Mongo and removes scratch files.
There are no skips and no network/SSH transports. The real resolver, executor,
transport factory and V2 transport are assembled with a scratch node model,
local bootstrap and local command receipts. RED→GREEN covered the missing
contract, missing old-backend instance proof, acceptance of a cloned persisted
binding at the assembled boundary, and unsafe direct-connection acceptance.

Tests cover concurrent insert winners, transactional claim/lock CAS races,
physical alias uniqueness, stale/cross-context/forged/missing proof rejection,
unchanged retained fences, primary-majority command monitoring, and **injected**
post-commit unknown/abort/readback failures. GREEN verification: **77 passed** in
this direct+assembled scratch suite, repeated successfully, and **466 passed**
across the relevant operation/lock/model/claim, executor/worker/runtime/recovery,
runner/transport, panel-host and config-transfer suites. Both runs reported zero
failed, cancelled or skipped tests and used no force-exit option. The broader
suite used synthetic non-production config and an unusable loopback fallback
Mongo URI; only explicitly started scratch connections were used for DB tests.
This does not simulate a real multi-member quorum outage or prove production
Mongo failover/network behavior.

Run explicitly (requires local binary; missing opt-in is an error, not a skip):

```sh
NODE_PATH=/home/leon/c3-int-verify/node_modules \
C3_MONGOD=/path/to/local/mongod \
node --test --test-concurrency=1 \
  src/modules/relay-l2tp/tests/topologyExecutionBindingStore.test.js
```

Before any installation/activation, separately deliver and verify:

1. Trustworthy externally sustained old-backend/classic/bootstrap/alias writer
   exclusion and endpoint physical attestation; preserve the currently serving
   backend until a separately authorized, recoverable transfer is proven.
2. Reviewed provisioning and enrollment under that authority, with real owner
   adoption and runner predecessor/boot readback. This code does not migrate or
   bless existing production rows, and cannot enroll an empty runner.
3. An execution-spanning authority/resolver integration, supervised lifecycle,
   successor/recovery protocol and independent review before any runtime reader
   or worker opt-in; this file is not a rollout instruction.
4. The [dormant terminal proof](topology-v2-terminal-proof.md) now binds persisted
   close IDs and returns fresh close/status proof under one held authority scope.
   Durable terminal-result/restart reconciliation, safe user/PPP/ingress
   integration, atomic physical ownership handback and exact lock/admission
   release are still absent. Existing V2 refusal/retention gates stay closed.
