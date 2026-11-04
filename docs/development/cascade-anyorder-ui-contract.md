# Any-order cascade UI: shipped behavior and contract handoff

## Scope and evidence

This is a test/report-only first wave at base `ef3f04773271e01b0011e8164ae7b5fdc62760e6`, not a declaration that any-order deployment works. The implementation contract remains owned by the common-contract slice.

`scripts/test-network-anyorder-ui.js` executes the actual `public/js/network.js` IIFE in a local VM, following the existing edit/layout harness pattern. It exposes real handlers at the existing startup boundary, injects a small linked-control DOM and Cytoscape model, and disables only particle animation. **The real form payload builders, response consumers, `loadTopology`, `refreshStatuses`, `renderGraph`, drawer, deletion and polling run unchanged.** Every mutation response is explicitly configured; unknown requests fail the harness. There is no substitute backend that implements graph admission, generation, deletion or readiness.

Source SHA-256: `b608f37a35cfa28c1b260a052764436400a8b4b40515f3a4e6204ce6b6d0e187` (`public/js/network.js`). Existing minified asset SHA-256: `8e96aa3172b05bf9678252258460c6fbcfc2e62785f08a9eba3059c710c5e527`. The new tests exercise the source, not the minified bundle or an authenticated browser. Neither asset, templates, locale files, package scripts nor backend files were changed.

No browser login, HTTP server, real HTTP requests, SSH, MCP, MongoDB, node transport, deployment, services or broad builds were used. Fixture responses are UI orchestration evidence only; they do not prove backend acceptance, remote preservation, tunnel connectivity or client traffic.

## Run and actual results

Run from the worktree root with Node (observed `v22.23.1`):

```sh
# Working current-contract characterization only:
node --test --test-name-pattern='\[shipped\]' scripts/test-network-anyorder-ui.js
# Includes intentionally unskipped failing acceptance regressions:
node --test scripts/test-network-anyorder-ui.js
# Only the reproducible product gaps:
node --test --test-name-pattern='\[spec-red\]' scripts/test-network-anyorder-ui.js
```

| Actual command | Exit | Result |
| --- | --- | --- |
| New suite, `[shipped]` filter | 0 | 26 tests, 26 pass, 0 fail/cancelled/skipped/todo |
| New suite, unfiltered | 1 | 37 tests, 26 pass, 11 fail, 0 cancelled/skipped/todo; failures are the `[spec-red]` cases below |
| `node scripts/test-network-ui.js` | 0 | `test-network-ui: OK` |
| `node scripts/test-network-layout-preservation.js` | 0 | `network layout preservation and dangling-edge projection: OK` |
| `node --test scripts/test-network-edit-ui.js` | 1 | 31 tests, 30 pass, 1 fail: local environment has no `ejs` dependency for the existing template-render test (`MODULE_NOT_FOUND`), not a new product failure |

Final new-suite TAP logs were captured at `/home/leon/.hermes/cache/scratch/c3-anyorder-ui-final-hc7emqzz/{shipped,full}.tap` (scratch retention applies). The initial new-harness setup failures were missing optional loading selectors and counting advisory port timers as operation timers; those were corrected in the test harness, not product code.

Two in-memory source-mutation probes additionally failed for their intended reason, one test each: replacing manual `linkId` with `domainLinkId` fails the exact request-body assertion; removing restoration of previous node positions fails the drag-position assertion. These probes did not edit checked-out product files. They establish that the characterization reaches real request targeting and graph reload behavior, not just configured replies.

The new file is deliberately not registered in `npm test` yet: it is an explicit RED acceptance artifact and changing package scripts is outside this slice.

## Order matrix actually exercised

The generator enumerates **9 graph orders**, each through main-form AutoDeploy and save-only plus selected manual Deploy: **18 matrix tests**. All manual deployments are requested in reverse creation order. The API responses are fixtures: these are request-targeting tests, not claims that the server permits those graphs.

| Graph | Creation orders (each exercised by both intent variants) |
| --- | --- |
| G1 | `P→B1` |
| G2 | `P→R; R→B1` / `R→B1; P→R` |
| G3 | `P→R; R→B1; R→B2` / `P→R; R→B2; R→B1` / `R→B1; P→R; R→B2` / `R→B1; R→B2; P→R` / `R→B2; P→R; R→B1` / `R→B2; R→B1; P→R` |

G1 is reverse. G2/G3 deliberately mix modes: `R→B1` is forward; the other edges are reverse. The tests assert original source/destination, mode, revision and activation intent on each create; manual requests contain exactly `{ expectedTopologyRevision, linkId }`, not a sibling list, domain request or full Sync. No all-forward/all-reverse backend matrix is claimed.

The remaining eight passing tests cover quick-form job→operation tracking; save-only edit of a persisted AutoDeploy preference; synchronous classic completion without readiness; wrong operation identity/newer global revisions and bounded polling; applied/unverified versus degraded/failed/rolled-back completion; drawer status versus revision-bound client proof; checked deletion refusal and successful middle-edge delete/recreate; idempotency-key reuse/change on explicit main-form retry; and saved-but-blocked AutoDeploy without a fallback POST. (The edit and classic checks share one test.)

The delete/recreate fixture removes `P→R`, retains an online `R→B1`, and recreates the selected segment on the same port with a new ID. The real reload path preserves dragged node coordinates, pan, zoom and the layout/fit counters. This does **not** prove remote teardown or port release. The dedicated existing layout suite additionally covers virtual Internet-node placement and dangling-edge projection.

## Current public seams — use these, do not invent endpoints

| Action / read | Current request and response consumed by UI | Relevant source |
| --- | --- | --- |
| Main/quick create | `POST /api/cascade/links`; body includes endpoints, mode, port, `autoDeploy`, `expectedTopologyRevision`. Main AutoDeploy sends `Idempotency-Key`; quick does not. | `network.js:onAddLinkSubmit/onQuickLinkSubmit`; `cascadeLinks.js` POST |
| Save-only create | HTTP 201 snapshot `{ topologyRevision, deployedRevision, links, createdLinkId }`; no operation or activation. | `cascadeLinks.js:890–900` |
| Classic AutoDeploy create | HTTP 201 snapshot plus `createdLinkId`; checked completion is `autoDeployResult: { status: 'succeeded', executionMode: 'classic', topologyRevision }`, otherwise operation or explicit saved/blocked fields. Not a synthetic durable job. | `cascadeLinks.js:817–875`, `queueAutoDeploy` |
| Non-classic AutoDeploy create | HTTP 202 `{ autoDeployJob, acceptedTopologyRevision }`; `autoDeployJob` identifies durable intent, not necessarily an already-created link. | `cascadeLinks.js:877–888`; `topologyIntentService.js:publicIntent` |
| Edit | `PUT /api/cascade/links/:id`; ordinary edit omits `autoDeploy`, even if persisted preference is true. Explicit opt-in sends true. Snapshot can include `autoDeployOperation` or blocked fields. | `network.js:1329–1332`; `cascadeLinks.js` PUT |
| Manual selected apply | `POST /api/cascade/topology/deploy`, exact `{ expectedTopologyRevision, linkId }`; queued result uses operation ID plus `kind: 'link.apply'`. Succeeded classic result is applied, not client-ready. | `cascadeTopologyDeploy.js` POST; `network.js:deployTopology` |
| Domain / full Sync | Same deploy endpoint with `domainLinkId` or no selection respectively; separate explicit actions. These must not be used as hidden create/manual fallbacks. | `network.js:_cascadeDeployChain/_cascadeDeployFull` |
| Intent read | `GET /api/cascade/links/auto-deploy-jobs/:jobId`; response wraps `autoDeployJob`. Current public projection can include status, acceptance revision, ordinal/attempts, eventual `createdLinkId`, `operationId`, topology revision and safe `errorCode`. | `cascadeLinks.js:600–605`; `topologyIntentService.js:12–20` |
| Operation read | `GET /api/cascade/topology/operations/:operationId`; allowlisted ID, lifecycle status, topology revision, `clientReadiness`, conditional `clientProofState`. It does **not** currently project `kind`, detailed phase, wait reason or arbitrary diagnostics. | `cascadeTopologyDeploy.js:150–182` |
| Map / snapshot refresh | `GET /api/cascade/topology` and `GET /api/cascade/links`; refresh uses the first for edge status and proof, reload uses both. Drawer proof is revision-bound; `online` alone is not proof. | `network.js:365–408`; `cascadeLinks.js:readLinkSnapshot` |
| Delete | `DELETE /api/cascade/links/:id`, exact revision body; successful current response is a completed snapshot, not a queued delete envelope. Classic selects checked coordinator deletion; non-classic selects draft write service. | `cascadeLinks.js:1149–1183`; `network.js:_cascadeDelete` |
| Undeploy | Existing `POST /api/cascade/links/:id/undeploy`; success `{ success: true, message }`, HTTP 409 `LEGACY_CASCADE_UNDEPLOY_BUSY` or HTTP 500 errors are possible. | `cascade.js:58–88`; `network.js:_cascadeUndeploy` |

Idempotency clarification: `TopologyIntentService.accept` defaults an omitted request key to a newly generated UUID. Quick create is **not** proven to be rejected for missing a header; it loses replay identity because subsequent deliveries receive different server-generated keys. The failing test requires parity with the existing main-form behavior, not a new backend requirement.

Operation polling already checks the returned operation ID, never treats a newer global revision as scoped success, and never re-POSTs. A `succeeded`/unverified operation continues until verified, degraded or budget expiry. The current loop makes 41 reads for `OPERATION_POLL_MAX_ATTEMPTS = 40`; tests characterize that finite existing behavior, not an exact wall-clock deadline. Verification is separately required before any client-ready message.

## Reproducible REDs and smallest necessary changes

All eleven failures are assertions against the shipped JS and **current** response shapes, not missing invented endpoints.

| RED coverage | Observed gap | Smallest UI change / dependency |
| --- | --- | --- |
| Save-only confirmation (1) | Successful snapshot only closes/reloads the form; no explicit saved result. | Show localized saved/not-applied feedback, without scheduling work. |
| Quick idempotency (1) | Quick form omits the existing request-key header. | Share main-form logical request-key reuse/invalidation with quick create. No new endpoint. |
| Accepted AutoDeploy states (3: `preparing`, `committing`, `succeeded`) | `queueAutoDeploy` accepts these states, but `handleLinkAutoDeploy` handles only `queued` and otherwise reports not started. | Consume accepted ID across the existing lifecycle and obtain proof from exact-ID reads; do not infer ready from succeeded. |
| Incomplete prefix summary (1) | `staged P→R` renders `Client → Portal → Relay → Internet`. | Stop unconditional Internet suffix. Until a backend route projection exists, display the selected segment and unknown/incomplete readiness honestly. |
| Save-only sibling summary (1) | Applied `P→R` drawer follows pending `R→B1` as though its path were active. | Distinguish desired from applied path; do not traverse every drawn edge as deployed. No graph-based authorization. |
| Mixed-mode summary (1) | Reverse `P→R`, forward `R→B1` displays only `Portal→Relay→Internet`. | Do not use transport mode as traffic-path continuity. Render backend policy/path evidence when available; avoid replacing this with another first-edge heuristic. |
| Exit deletion warning (1) | Current confirm asks to remove the link/deploy but does not warn of traffic/route interruption. | Add a safe general consequence warning now; precise affected-user/last-exit details require backend impact evidence. Cancellation must send nothing. |
| Rejected undeploy (1) | `fetch` resolves HTTP 409; handler ignores `response.ok` and announces success. | Check response status, render safe error and refresh state; never call it removed/applied on refusal. |
| Concurrent accepted operations (1) | Single global operation timer cancels tracking of the earlier accepted operation. | Track every accepted operation identity (map or multiplexing), without replaying POSTs. The test requires reads for both IDs, not a particular timer implementation. |

The raw drawer currently keeps `pending`, `deployed`, `online`, `staged` distinct and labels unverified client readiness. This is useful, but not an explanation of **saved / applied / connected / incomplete / queued**. In particular, `staged` has no missing-entry/missing-exit explanation, and a successful SSH/service result cannot supply one by itself.

## Minimal API information still required (semantics, not a new JSON schema)

Preserve existing endpoints where possible. The common backend contract must define the following additive public information before the UI can implement the rest of the spec. **Names/enums and any new envelope remain undecided here; no such fake fields or delete endpoint are implemented by this test file.**

1. **Durable action identity and saved fact.** Return the selected link identity and accepted operation/job identity, or an explicit pre-acceptance refusal. State whether the desired link is already saved. Current non-classic 202 can precede link creation; current synchronous classic result has no durable operation ID. Reconcile those differences in the shared lifecycle rather than making UI fabricate an operation or claim the draft exists.
2. **Independent evidence dimensions.** Expose confirmed application/baseline identity, tunnel connected/unconfirmed, route completeness (including a safe missing-entry/missing-exit/ambiguous-policy reason), and client-proof state independently. Current `status`/global revisions alone cannot express these distinctions. Retain revision/operation binding; client proof must not collapse PPP and Xray readiness into a guessed universal green.
3. **Policy-aware desired/applied path.** If the UI shows a full route or selected exit, supply the authoritative route/policy projection or clearly bound path information. The browser's `find` over same-mode arrows, array order and pending edges is not exit policy. Do not add a second client-side cascade planner to repair the displayed summary.
4. **Progress and safe actions.** Current operation status is sufficient for exact-ID polling, but not phase/node/wait diagnostics. Specify allowlisted phase, safe reason code, relevant node/link IDs and permitted next action, plus discoverable operation/job references after a page reload. Do not leak SSH output, config, user identifiers, credentials or stack traces through new fields.
5. **Durable removal.** Define how the existing DELETE lifecycle reports acceptance, retained selected-link identity, progress, unknown result and confirmed physical absence. Only that final confirmation permits the completed-deletion UI. Current snapshot response has no queued-delete contract: this slice intentionally does not mock one. Retain existing checked synchronous behavior where appropriate; a pending status alone must not authorize removal without dispatch-history proof.
6. **Impact warning.** Supply affected routes/users or an allowlisted warning sufficient to identify last-exit/user impact when precise guidance is required. Until then, use a generic honest interruption warning, not fabricated user counts.

A 409 saved/blocked response is not an accepted queued operation. A 202 accepted intent is not a saved/applied/connected/ready link. Ordinary CRUD must not invoke full Sync to paper over either distinction.

## Next bounded UI implementation slice

After the common contract is fixed, change only the UI caller/response adapter, necessary Russian/English labels and their template wiring, plus generated asset/cache version under that slice's ownership. First close the current-contract REDs: explicit save feedback, quick request identity, accepted-state consumption, identity-preserving multi-operation tracking, honest segment summary, deletion consequence warning and checked undeploy response handling. Keep selection payloads and layout-preserving reload unchanged.

Then bind incomplete reasons, desired/applied route details and asynchronous deletion to the **actual accepted backend projection**, adding exact response tests at that point. Do not introduce a pretend `link.delete` API or infer a completed route from staged/online arrows. Run this focused suite plus existing UI/layout checks and an asset build only in the implementation slice; real browser/minified-asset and isolated Xray/PPP acceptance remain separate, unperformed requirements.
