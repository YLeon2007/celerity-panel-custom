# Any-order HTTP slice — integration handoff

This slice uses the existing v2 `TopologyIntentService`, draft service/repository,
job endpoint and operation endpoint. It adds no queue, endpoint, execution flag,
worker, owner authority, or native runtime activation.

## Required runtime composition (owned by admission/runtime slice)

Publish the **same real service instance** either as
`activeHost.selectedTopologyIntentService` (preferred), or inject
`topologyIntentService` into both `createCascadeLinksRouter()` and
`createCascadeTopologyDeployRouter()`. The older `activeHost.topologyIntentService`
remains a compatibility fallback. Native configuration alone does not construct
or authorize this service; absent service returns 503 before desired mutation.
Classic-production selection and its synchronous response remain unchanged.

Construct the service with its existing signatures:

- Same-connection models: `TopologyState`, `TopologyOperation`, `CascadeLink`,
  `HyNode`, `CascadeRouteGroup`, `TopologyCreateIntent`, `TopologyIntentQueueState`,
  plus the actual draft/runtime prerequisites from the owning factory.
- `executionContext`: the canonical frozen server-selected context; never derive
  it from HTTP input. Preserve the immutable host environment/context pairing.
- `resolveIntentResources({kind,linkId,link,session,executionContext})`:
  fresh selected old/new resource union. A missing resolver refuses admission.
- `intentDraftWriter({link,expectedTopologyRevision,session})`: the real
  transaction-aware joined draft writer. Do not substitute an unlocked write or
  `work => work(session)` for a scoped writer whose lock/ledger lifetime must
  extend through the outer acceptance commit.
- `prepareLink(normalizedLink)`: perform credential generation only after
  persisted-key replay. This route module exports `prepareIntentLink(link,
  targetNode = null)`; a runtime adapter can pass the trusted bridge node to keep
  its existing REALITY destination/SNI defaults. Native REALITY create without
  this preparation dependency refuses rather than saving missing credentials.
- `deleteIntentWriter`: use
  `CascadeLink.createDeleteIntentWriter({CascadeLink})`. Its existing v2 callback
  signature is `({link,linkId,desiredVersion,jobId,session})`. It writes only
  `lifecycle:{state:'deleting',deleteJobId:jobId,desiredVersion}` in that exact
  outer session. The original descriptor/status/credentials remain present.
- `intentOperationAdmission`: real `{db, queue({...session,mutation,
  expectedTopologyRevision,resourceNodeIds})}` adapter. This HTTP slice never
  invokes the direct coordinator queue for native link mutations.

`link.create` carries normalized user content, `link.apply` carries the actual
`linkDesiredVersion()` pin, and `link.delete` uses that same pin. All carry the
literal validated `Idempotency-Key` (1–128 ASCII alphanumeric/underscore/dot/
colon/hyphen). Create UUID/REALITY generation happens inside real acceptance,
not in HTTP before replay.

Explicit PUT Auto now calls the same v2 acceptance protocol once:
`accept({version:2,kind:'link.apply',linkId,changes,expectedTopologyRevision,requestKey})`.
`changes` is the normalized requested patch, not a desired-content pin calculated
from today's row. Acceptance fingerprints that patch before credentials or row
lookup, replays a matching persisted key first, then joins the actual draft
update, desired revision CAS, resource resolution, queue counter and intent
insert in **one transaction**. The persisted job still has kind `link.apply` and
an actual `linkDesiredVersion()` configuration pin; its private payload also
retains the normalized requested changes. No schema/version/consumer change is
needed. A reused key with different requested content refuses before mutation.
Replay also works after later save-only edits or deletion of the desired row.

The existing real `intentDraftWriter` object must now expose both:

```js
createLink({expectedTopologyRevision,link,session})
updateLink({expectedTopologyRevision,linkId,changes,session})
```

`TopologyDraftRepository.createIntentDraftWriter({selectedTopologyRepository})`
implements both through the same DB-only joined commit and exact active-session
check. Runtime already publishes that complete object; **do not wrap/forward only
`createLink`**. Missing/foreign/create-only writers fail closed with
`TOPOLOGY_INTENT_DRAFT_TRANSACTION_UNAVAILABLE` before mutation. No scoped
`work => work(session)` substitution, second transaction, legacy fallback, worker
start or remote preflight is added. REALITY edits require the already documented
local `prepareLink` dependency; absent preparation refuses with
`TOPOLOGY_INTENT_PREPARATION_UNAVAILABLE`. Blank UUID/REALITY key/short-ID controls
preserve the existing tuple. The deleting-row check is repeated by the real
draft repository inside the same outer transaction.

Save-only create and PUT still issue no intent, even when stored `autoDeploy`
metadata is true. Classic-production PUT retains its previous synchronous flow.
Queue overflow or any precommit draft/resource/intent refusal leaves neither
edit nor accepted job; the response no longer claims a separately saved edit.

## Delete/finalizer handoff

No `pending`/health-based draft-only shortcut exists. Without an actual injected
applied/dispatch-history authority, every native DELETE is durable `link.delete`.
Repeated keys return the existing job, including after the desired row has been
removed. No receipt of admission physically deletes the row.

The owning selected snapshot builder must exclude `lifecycle.state='deleting'`
from desired-effective selection while retaining the immutable applied baseline.
Finalization must bind `deleteJobId` to the intent (not confuse it with operation
ID), check the content pin, prove old/new-union cleanup, and only then remove the
row. Draft writers must reject a concurrently marked row inside their actual
transaction; the route's early check is not a lock/transaction substitute.

## Trusted public-state adapters

Both can be injected on router factories or published on the active host:

- `readLinkApplicationState({links:[{linkId,desiredVersion}]}) -> rows` where each
  unique row has exact scalar `linkId`, `desiredVersion`, `operationId`,
  `applicationState`, `routeState`, `tunnelState`, and optional separate
  `pppReadiness`/`xrayReadiness`. This is a **trusted server adapter**: validate
  settled selected-owner/profile pins before returning state. HTTP checks exact
  link/content identity, duplicate rows and bounded enums; request data and a
  global revision pair are not such authority. Supported application enums are
  `not_applied/applying/applied/deleting/reconcile_required`; route enums are
  `complete/no_portal_input/no_bridge_exit/policy_ambiguous`; proof enums are
  `verified/unverified/pending/failed/not_applicable`.
- `readPublicOperation(operationId) -> safe operation | null`: selected-aware
  repository projection with real identity/pins/proof and bounded status data.
  The existing default operation repository only has global-revision freshness,
  so the HTTP fallback conservatively forces selected operation client proof to
  `unverified`. It reads persisted kind/link identity rather than inventing them.
  Retained terminal admission is `phase:'reconcile_required'`; PPP wait is
  separate `phase:'waiting',waitingReason:'PPP_SYNC_PENDING'`. Worker status enums
  are not changed.

Without a trusted application-state reader, link health only yields conservative
application/tunnel projection; `routeState:'unknown'` and unverified readiness
explicitly mark the closed dependency. Mutable desired neighbors do not establish
an applied path. Selected operations never become fresh from panel revision.
The root host/runtime publication and selected authority implementation are
**not implemented or proved by this HTTP slice**.

## Verification boundary

`cascadeAnyOrderHttp.test.js` sends real loopback HTTP requests through the actual
Express handlers, `TopologyIntentService`, draft service and draft repository.
Its persistence is a transaction-shaped local fixture with real link schema
normalization, not Mongo, replica-set rollback, unique-index/unknown-commit proof,
remote dispatch, cleanup, or assembled default-host activation. Manually written
job-operation bindings and finalizer removal are explicitly modeled.

Legacy route/queue-double tests are labeled classic and remain compatibility
checks, not native acceptance. The unchanged historical classic lifecycle and
deletion harnesses remain RED; replay uses a scratch module loader to substitute
only this slice's HTTP modules, never coordinator/core doubles or assertions.
No remote systems, DB, SSH, MCP, production environment, dependency installation,
asset build, deployment or service operation was used.

Historical HTTP-slice baseline execution (before the atomic-edit extension;
Node v22.23.1, shared installed dependencies via scoped `NODE_PATH`, explicit
dummy import configuration, serial Node test runner):

- Six focused suites (`cascadeLinks`, `cascadeLinksAutoDeploy`,
  `cascadeLinksIntentAcceptance`, `cascadeTopologyDeploy`, `cascadeAnyOrderHttp`,
  `cascadeAnyOrderIntent`): **120 tests / 120 pass / 0 fail / 0 cancelled /
  0 skipped; exit 0**. The new real-HTTP fixture suite contributes 15 cases.
- Historical unchanged classic lifecycle/deletion harness replay against these
  HTTP route modules: **62 tests / 18 pass / 44 fail / 0 cancelled / 0 skipped;
  exit 1**, preserving the mission's original RED cardinality. This is not a
  completed native worker/apply/delete acceptance claim.
- Logs: `/home/leon/.hermes/cache/scratch/anyorder-http-green-final.log` and
  `/home/leon/.hermes/cache/scratch/anyorder-http-historical-red-final.log`.

### Atomic-edit extension verification and remaining fixture handoff

`cascadeAnyOrderEditIntent.test.js` uses the actual Express PUT handler, real
link and intent schemas, `TopologyIntentService`, `TopologyDraftWriteService`,
`TopologyDraftRepository.createIntentDraftWriter` and
`TopologyDeploymentRepository.assertSelectedAvailable`. Only persistence and
transaction outcomes are modeled. The first regression failed because queue
rejection left the edited row and advanced revision behind; the joined path
passes it. Coverage includes exact-session writes, requested-content replay
across reconstructed services and later desired drift/removal, blank credential
preservation, no-fallback gates, late deleting markers, save-only exclusion,
precommit refusals, mixed-mode listener collision, and uncertain commit/readback.
This does **not** prove actual Mongo rollback, concurrent unique-key admission,
worker execution or remote configuration.

Normal serial Node runs (no force-exit):

- New edit-intent suite plus `cascadeAnyOrderIntent`,
  `cascadeAnyOrderSelectedApply`, `cascadeLinks`, `cascadeLinksAutoDeploy`, and
  `cascadeLinksIntentAcceptance`: **99 tests / 99 pass / 0 fail / 0 cancelled /
  0 skipped; exit 0**. Log:
  `/home/leon/.hermes/cache/scratch/anyorder-edit-intent-green-complete.log`.
- Historical `cascadeAnyOrderHttp` fixture without its newly required joined
  writer: **12/15 pass**, three PUT cases safely refuse 503. It still constructs
  only the old unscoped draft service and supplies neither an active session
  marker nor local edit credential preparation. Do not loosen the product gate.
  The integration-owner fixture fix is: add `inTransaction:()=>true` to its local
  session; supply `prepareLink:prepareIntentLink`; construct the real draft and
  deployment repositories over its existing model dependencies and set
  `dependencies.intentDraftWriter = draftRepository.createIntentDraftWriter({
  selectedTopologyRepository: deploymentRepository })`.
  This exact proposed fixture-only adapter, with assertions and product source
  unchanged, passes **15/15** through scratch loader
  `/home/leon/.hermes/cache/scratch/anyorder-edit-http-fixture-adapter.cjs`;
  log `anyorder-edit-http-proposed-fixture.log` in the same directory. It is not
  an integrated test-fixture change or default-host activation claim.
- `topologyDraftRepository.test.js`: **14/15 pass**; its old direct persistence
  double lacks `CascadeLink.findById`, required by the existing deleting-row
  check. Exact repository bytes from baseline
  `6576ac59b153442eb38d54527e4e5bb89253b920` reproduce the same targeted failure
  (log `anyorder-edit-repository-baseline-red.log`). No tombstone protection was
  removed to accommodate that fixture.

No coordinator, worker, consumer, runtime/host, model, queue or endpoint was
added/rewritten for this extension. The runtime owner must retain the full
joined writer and existing local `prepareLink` injection; a runtime that omits
the REALITY preparation capability stays closed. Actual Mongo validation and
assembled-host/worker acceptance remain with their separately owned slices.
