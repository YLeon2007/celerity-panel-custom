# Legacy cascade write boundaries

## MCP draft changes

`manage_cascade` actions `create`, `update`, and `delete` require an explicit
`expectedTopologyRevision` (non-negative safe integer). Obtain it from
`get_topology.topologyRevision`; successful writes return the new
`topologyRevision` and existing `deployedRevision`. These actions use the same
validated, transactional topology draft write service as HTTP link CRUD. They
never deploy or reconnect nodes. A stale revision, replacement reservation, or
counted topology admission prevents the mutation; a concurrent admission rolls
the entire draft transaction back.

`deploy` and `reconnect` remain disabled legacy actions. This change does not
add a general topology Sync or change the exact deployment/finalization CAS.

## Legacy HTTP and MCP undeploy

`POST /api/cascade/links/:id/undeploy` and MCP `undeploy` are **not queue-aware**.
They reject with `LEGACY_CASCADE_UNDEPLOY_BUSY` (HTTP 409) **before external
teardown** if any topology operation is active, an operation retains counted
admission, an intent is waiting/claimed/admitted/blocked, an outstanding queue
count is nonzero/unknown, or a node-operation lock exists. A foreign reservation,
remote drain, or nonzero/missing topology/remote admission counter also rejects.
Do not delete operations/intents or reset counters to make this check pass.
Finish the owning work or use its explicit operator recovery procedure first.

The authorized quiescent path is retained:

1. A snapshot transaction checks quiescence and atomically claims the existing
   non-expiring `replacementReservation` with a unique `legacy-undeploy:` owner
   token and monotonically increasing `replacementEpoch`. The claim uses exact
   revision/deployed-revision/epoch predicates, explicit zero admission counts,
   and no upsert. It advances the topology revision and resets deployedRevision
   to zero **before** teardown, invalidating old client/deployment proof.
2. Only after that transaction commits does the caller reread the link's current
   metadata and invoke the legacy teardown. The reservation stays held for the
   entire asynchronous call. Draft mutations, new topology admissions, intent
   materialization, and counted remote admissions cannot cross it. A newly
   accepted intent may wait behind this fence; it is not permission to execute.
3. Normal return releases only the exact owner token, epoch, revision and zero
   admission counts. Existing operation history and intent bindings are never
   deleted. The next deploy targets the new revision, avoiding reuse of an old
   operation without purging evidence.

Missing legacy singleton/counter/epoch initialization fails closed; there is no
automatic normalization. A transaction failure or uncertain acquisition causes
zero teardown calls. A crash/throw after acquisition, lost release predicate,
or ambiguous release does not authorize automatic retry or a blind fence clear.
An operator must inspect the exact reservation identity, process/remote state,
operation and intent history, and admission owners before any recovery. Never
clear another owner's token or reuse an old epoch.

The underlying legacy teardown remains best-effort: it logs and swallows some
node errors. Its normal response is **not** a connectivity, client-readiness,
or verified-remote-completion claim. This fence fixes admission/queue bypasses;
it does not add transport verification or make unrelated legacy node writers
participate in the topology worker protocol.

## Local regression evidence

`src/routes/tests/cascadeLegacyWriters.test.js` starts an isolated loopback
MongoDB replica set below `$TMPDIR`, uses real transactions and the assembled
HTTP/MCP handlers, and replaces the teardown/cache boundaries with local spies.
It never connects to the configured panel MongoDB or performs SSH/node writes.
Set `C3_MONGOD` to a local mongod binary to run it. The suite checks real Mongo
write-conflict rollback, active queue binding preservation, zero external calls
on denial, ownership across a suspended teardown, safe quiescent draft changes,
and retention of failed/foreign reservations. This is local orchestration
proof, not a live deployed-network test.
