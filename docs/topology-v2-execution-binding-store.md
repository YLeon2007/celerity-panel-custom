# Durable V2 execution binding — dormant, one-shot storage/reader contract

## Scope and non-activation

`TopologyExecutionBindingStore` implements the executor's server-only
`readVerified(expected)` and `readVerifiedConnection(expected, verifiedBinding)`
capabilities. It is **not imported or constructed** by runtime/host composition,
routes, MCP or workers. No production flag, pre-claim bypass, migration, remote
write, deployment, worker/runner/SSH/pool change or ownership release is included.
Default executors still refuse without a reader. The PROD worker pre-claim gate
and all retained-lock/admission/handback gates remain closed: **PROD is NO-GO**.

The constructor requires the exact canonical production context, a trusted
`withVerifiedAuthority` function, and **six actual models** (`Operation`, `Lock`,
`Owner`, `Enrollment`, `Binding`, `HyNode`) on one connected discovered MongoDB
replica set with a primary. `directConnection` is rejected because the driver
can rewrite primary reads to primaryPreferred. There are no default models,
connections, identities, credentials, authority adapters or endpoint fallbacks.

## Immutable enrollment and binding

Enrollment accepts exactly:

```js
{
    nodeId, targetProfile,
    endpoint: { ip, port, username },
    nodeIdentity: { machineId, sshHostKeySha256 },
    ownerGeneration, predecessorGeneration, bootId,
}
```

The IP must be an IP literal, port an integer in 1..65535, username a bounded
Linux-style account name, machine ID 32 lowercase hex characters, and host-key
digest 64 lowercase hex characters. Digests identify the **raw SSH public-key
wire blob**, not PEM or base64 text. No coercion or normalization occurs; missing,
extra, array-valued, changed and malformed authority is refused. Predecessor and
boot must be explicit UUIDs; neither an empty runner nor `none` is adopted.

These caller-supplied values are a **proposal**, not trusted evidence. The store
requires an independently supplied external server attestation matching them
before its transactional writes. A matching mutable HyNode selection cannot
substitute for that attestation.

Both immutable records snapshot the exact endpoint, physical identity, owner
generation, predecessor, boot and proof/maintenance metadata. The binding also
stores the exact accepted operation, canonical host, revisions, candidate,
deterministic backup, claim owner/attempt and **already-acquired lock generation**.
Attempt IDs and five distinct command IDs, including close, are server-generated.
The public executor binding projection deliberately stays unchanged; endpoint
and physical trust are returned only through the separate connection capability.

Unique enrollment indexes enforce node/profile and physical-machine/profile /
SSH-key/profile isolation, plus **global** machine-ID, SSH-host-key and IP/SSH-port
listener isolation. A different profile or username cannot acquire an alias slot.
This is intentionally conservative: shared/cloned machine IDs, reused host keys
or multi-profile physical enrollment must be resolved by separately reviewed
provisioning, not an exception or index removal. Unique binding indexes enforce
operation/node/profile, enrollment and attempt uniqueness and cross-record /
cross-command token exclusion.

The API is one-shot and insert-only. Model updates, replacements, query/document
deletion, existing-document saves and bulk writes refuse. Raw administrative
collection access is outside its trust boundary, not cryptographically protected
storage. There is no adopt, reclaim, successor, lock-release, admission-decrement
or handback API, and failed/unknown work retains records and ownership.

## Explicit external authority — required, not implemented

`withVerifiedAuthority(challenge, awaitedCallback)` is constructor-injected by
trusted server code only. Every enrollment, creation and read requires a fresh
exact challenge and existing `external-execution-maintenance-v1` proof: held
maintenance, writers drained, bootstrap writers excluded, old backend instance /
PID / process-start identity with process tree stopped and dispatch disabled,
physical topology ownership, and exact predecessor + boot. It additionally must
supply **exactly** this connection attestation:

```js
connectionAttestation: {
    authority: 'server-physical-ssh-endpoint-v1',
    endpoint: { ip, port, username },
    physicalIdentity: { machineId, sshHostKeySha256 },
    maintenanceId, // identical to the enclosing proof and original enrollment
    aliases: 'excluded',
    endpointReassignment: 'excluded',
    hostKeyDigest: 'raw-ssh-public-key-sha256',
}
```

The adapter must independently establish these facts. Copying the challenge,
reading user/database endpoint fields, returning the shape, or freezing an object
is **not** physical attestation. The store cannot prove physical machine-ID /
host-key correspondence, old-PID quiescence or endpoint reassignment exclusion
itself. No real adapter is delivered; all positive local tests explicitly
simulate this authority with separately fixed fixture inventory.

The authority must hold the awaited callback through commit/readback and sustain
old-writer/bootstrap/alias/endpoint-reassignment exclusion externally across the
**entire remote lifecycle**, including gaps between store calls. Ordinary Mongo
CAS/readback does not exclude a writer immediately after its last read. A DB
nonce, lease or earlier fresh read cannot replace that execution-spanning fence.
Booleans, late callbacks and callbacks whose work is not awaited fail closed.
Challenge/accepted values are copied and deeply frozen; original maintenance
identity cannot switch between enrollment, binding, reads or terminal scope.

## Majority CAS, readback and connection reader

Enrollment transactionally CASes the paired adopted config owner and current
selected HyNode before inserting its immutable snapshot. Binding creation and
all reads additionally CAS the exact active operation and unexpired acquired
node lock (`remoteUncertain: true`). Accepted candidate bytes, backup identity,
node/profile, revisions, claim attempt/owner, owner adoption/restoration evidence
and physical owner generation must all match.

HyNode is a **selection to compare**, not a source of trust. Its exact ID,
active/type/profile role, IP, SSH port and username must agree with the enrollment.
BSON aggregation `$type` and literal equality enforce scalar/object types; query
equality that merely matches an array element cannot authorize a connection.
The optional `executionBindingCheck` fields on operation/lock/owner/HyNode are
transactional CAS nonces with no defaults, not physical or quiescence authority.
The HyNode marker is excluded from ordinary selects; its confirmation projects
only ID, eligibility and endpoint fields, never SSH credentials.

One snapshot transaction uses primary routing and majority commit. Transaction
conflicts/misses roll back the losing nonces and insert; there is no transaction
retry or regenerated authority ID. Normal commits and unknown commit results
require one bounded outside-transaction primary-majority confirmation pass per
transaction. Commit, inserts, transaction I/O and aborts carry five-second
budgets. Exact immutable row equality, each CAS nonce, ownership and fresh leases
must confirm. The earliest observed claim/lock expiry caps remaining reads;
freshness is rechecked after final read delivery, session cleanup and authority
return. Absence, uncertainty, failed confirmation and elapsed leases refuse
without deleting durable rows or releasing ownership.

`readVerifiedConnection` revalidates the currently accepted binding and requires
the supplied deeply frozen exact executor record to equal it. It returns exactly,
with every level frozen:

```js
{
    binding: verifiedBinding,
    connection: {
        expectedEndpoint: { ip, port, username },
        expectedHostKeySha256: sshHostKeySha256,
    },
}
```

Connection values come only from immutable enrollment validated under external
authority, never from the mutable selected row. The real executor/resolver passes
that pin separately to its SSH adapter and refuses later endpoint/key changes.
The existing pin transport validates the raw host key before authentication;
that pin does not independently attest machine ID or quiescence.

During `withVerifiedBinding`, private async-local context reuses the **same held
terminal authority** for connection rechecks rather than reacquiring a potentially
non-reentrant adapter. Each recheck still performs exact transactional/majority
ownership and endpoint verification. Escaped async contexts cannot use this
capability once the original scope closes. Terminal proof remains data only;
worker release and classic handback remain unauthorized.

## Local verification and remaining blockers

`topologyExecutionBindingStore.test.js` starts a loopback-only single-member
replica set under `TMPDIR`, creates a guarded random scratch database, uses all
six real schemas and the real operation/lock repositories, and verifies cleanup.
It assembles the **actual store without a connection-authority wrapper**, executor,
resolver and V2 transport with simulated external physical authority and local-only
SSH/bootstrap/runner adapters. No production DB, remote SSH or deployment occurs.

RED→GREEN demonstrated missing endpoint enrollment, missing real-store reader,
unsafe nested terminal authority, cross-profile physical alias acceptance,
array-valued hidden proof acceptance and absent endpoint-reassignment exclusion.
Tests cover real Mongo CAS/reassignment races, concurrent physical alias winners,
immutable/malformed/changed evidence, exact primary-majority verification, unknown
commit and real failCommand insert stalls, lease expiry/cleanup, retained ownership,
and real fake-root terminal runner status. This is local orchestration evidence,
not live physical attestation, multi-member quorum/failover proof or production
connectivity. Missing local Mongo opt-in is an error; no tests are skipped.

Final direct run: **290 passed**. Broader assembled/claim/worker/runtime/lock /
recovery/runner/panel-host/real-loopback-host-key regression run: **682 passed**,
including the direct suite. Both runs reported zero failed, skipped or cancelled
tests and used no force-exit option. Syntax checks and `git diff --check` pass.

```sh
NODE_PATH=/home/leon/c3-int-verify/node_modules \
C3_MONGOD=/path/to/local/mongod \
node --test --test-concurrency=1 \
  src/modules/relay-l2tp/tests/topologyExecutionBindingStore.test.js
```

Before installation/activation, separately deliver and independently verify:

1. Real independently attested physical machine / raw-host-key / exact endpoint
   inventory and externally sustained old-backend, classic, bootstrap, alias and
   endpoint-reassignment exclusion. The current serving backend is untouched.
2. Recoverable provisioning: index conflict resolution, real owner adoption and
   restoration evidence, explicit predecessor/boot readback, and reviewed initial
   enrollment. No migration or existing-row blessing is delivered here.
3. Execution-spanning authority wiring, supervised lifecycle, successor/restart
   recovery and independent review before any runtime reader or worker opt-in.
4. Durable terminal-result reconciliation, safe user/PPP/ingress integration,
   atomic physical handback and exact lock/admission release. Existing PROD
   pre-claim and V2 retention gates must stay closed until these are proven.
