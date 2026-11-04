# Any-order cascade UI: actual v2 jobs and retained deletion

## Scope and authority

Continues UI base `b21c66fda1fbe0b1efb7d2b4465c4c4cdeebb4f4`. HTTP authority is the read-only worktree `/home/leon/c3-anyorder-http-20261104` at **`51fd18d441ba6018235de71f1519388cdaaf8d5c`**, specifically:

- `src/routes/cascadeLinks.js`: `acceptedIntentResponse`, job GET, selected projection and DELETE lifecycle contract.
- `src/routes/cascadeTopologyDeploy.js`: selected apply acceptance and `publicOperationStatus`.
- `src/modules/relay-l2tp/services/topologyIntentService.js`: `publicIntent`.
- Its `cascadeAnyOrderHttp.test.js` and `docs/development/cascade-anyorder-http-integration.md`.

No backend code was imported or modified. No new endpoint, runtime authority, service, automatic mutation replay, browser feature, or infrastructure controller is introduced.

## Consumed contract

| Action | Actual response and UI behavior |
| --- | --- |
| Auto create, main/quick | `202 {linkId,desiredSaved:true,job,acceptedTopologyRevision,...}`; existing `autoDeployJob` alias is also supported. Acceptance is not parsed as a draft snapshot or client-ready result. |
| Explicit PUT Auto | Same v2 envelope, kind `link.apply`; an unsuccessful acceptance with `desiredSaved:true` explicitly says the edit was saved, apply acceptance is unconfirmed, and refreshes. The backend's save/accept are two transactions, not UI-claimed atomicity. |
| Manual selected Deploy | Existing POST `/api/cascade/topology/deploy`, exact selected-link/revision body; consumes a v2 job even when no operation exists yet. Does not issue a second apply or full Sync. |
| Job GET | Existing `/api/cascade/links/auto-deploy-jobs/:jobId`, `{job,autoDeployJob}` aliases. Exact job ID plus v2 kind/link identity are checked. An admitted/succeeded job hands off only its actual operation ID. Create maps to operation `link.apply`; delete stays `link.delete`. |
| Operation GET | Existing `/api/cascade/topology/operations/:operationId`; v2 handoff requires exact operation ID, kind and link. Public phase/reason/node/next-action are shown through bounded allowlists, never backend prose. PPP wait remains waiting. `phase:reconcile_required` or its waiting reason overrides nominal `status:succeeded` and never produces a successful-apply toast. |
| Save-only | Existing synchronous snapshot; no new intent or apply request. Ordinary edit still omits activation even when the stored Auto preference is true. |
| Classic | Existing synchronous completed apply and checked `200` DELETE snapshot remain supported, without invented jobs or operations. Delete success additionally requires target absence from that completed snapshot. Existing checked undeploy is unchanged. |

Request identity is per logical main/quick create, per-link explicit edit, selected apply and delete. Revision refresh alone does not replace an unresolved key. Independent controls/links do not overwrite each other's key. Confirmed acceptance retires the submission key; changed create/edit content starts a new identity. DELETE retries retain the original key even after the list no longer contains the desired row. Keys use `crypto.randomUUID`, or `getRandomValues` where secure-context restrictions omit `randomUUID`, and conform to the real ASCII header grammar. No key is placed in the request body.

## Deletion: visible until the real terminal intersection

1. A v2 DELETE accepts a **job**, not row removal. The selected segment is retained and labeled **Удаляется**, or **Ожидает сверки** for an already blocked/reconcile response. Other links, positions, viewport and zoom remain unchanged.
2. `lifecycle:{state:'deleting',deleteJobId,desiredVersion}` from the real list restores exact-job tracking after reload. The marker's job ID is not confused with operation ID. The inventory is merged onto graph edges because the independently cached `/topology` response does not carry these lifecycle/proof fields.
3. A repeat Delete click with an accepted/marked delete sends **no new DELETE or job**. Jobs and operation timers remain independently tracked; one terminal delete removes only its own tombstone.
4. In-page loss/malformed acceptance or server error retains the original segment as unconfirmed, without manufacturing a job ID or persisted marker. An explicit retry uses the same key. There is no automatic mutation retry.
5. List absence alone is not deletion success. Removal requires an exact bound `link.delete` operation with `status:'succeeded'`, `phase:'completed'`, no reconcile flag, **and a successful fresh list read proving this link absent**. A failed list read is not an empty list. A terminal operation while the row remains present continues bounded polling.
6. Failed, blocked, reconcile, unavailable and exhausted outcomes never hide the retained segment or produce `deleteSuccess`. Independently cached topology cannot resurrect a deletion after that terminal/absence intersection.

Job reads are bounded to 80 attempts and six consecutive failures; exact-operation reads retain the existing 41-read maximum for its configured 40-continuation budget. Exhaustion reports unconfirmed/background work, not cancellation or permission to replay. Completed job tracking is retained in-page so a surviving marker does not continually restart its old job poll.

## Application, route, tunnel, PPP and Xray are separate

The UI now consumes the actual **link-list** projection rather than hoping these fields appear on `/topology`:

- `applicationState`: not applied / applying / applied / deleting / reconcile required.
- `routeState`: complete / no portal input / no bridge exit / ambiguous policy / unknown.
- `tunnelState`: connected / disconnected / unknown.
- Independent `pppReadiness` and `xrayReadiness`. PPP success does not turn Xray green; Xray display requires the public applied-operation identity plus applied/complete/connected state. Refresh explicitly clears absent/stale proof fields.
- Existing legacy revision-bound client proof remains separate where no selected Xray projection is provided. A panel-wide revision never authenticates selected proof.

The drawer **still shows only the selected segment in traffic direction**, including mixed forward/reverse. Even `routeState:'complete'` does not supply an applied node sequence or default/geo policy. The note now specifically qualifies the full node path and exit policy; desired neighbors are never traversed as proof or silently activated. The original full mixed-route acceptance requirement therefore remains API-dependent, not claimed delivered by these conservative display tests.

All new visible lifecycle/readiness/phase/wait/action text is RU/EN-localized and bound through the actual `views/nodes.ejs` loader. Public diagnostic codes and exact IDs remain visible; SSH output, arbitrary error messages, credentials and private config are never interpolated.

## Local evidence and preserved regressions

`scripts/test-network-anyorder-ui.js` executes the shipped `network.js` IIFE, actual main/quick/edit/Delete/Deploy handlers, loaders, drawer, renderer and timers in a local DOM/Cytoscape VM. Network replies are explicit fixtures matching the implemented HTTP contract, **not an HTTP server, backend persistence/admission, physical cleanup, browser, Xray or PPP acceptance**. The graph fixture deliberately omits the new projection fields, as the real topology serializer does; they must arrive from the list. Only graph boot and particle animation are bypassed. Unconfigured requests fail, and expected list-read failure logging is explicitly asserted.

The original **45 tests** are retained, with **10 v2 controls/regressions** added: main/quick/PUT acceptance and edit retries; selected manual acceptance and independent jobs; deletion terminal intersection; list projection and proof clearing; wrong-kind acceptance with preserved retry identity; marker reload and wrong binding; blocked/reconcile deletes; lost delete acceptance; concurrent deletions plus failed list read; and the browser crypto compatibility path. Original G1–G3 targeting matrix remains 9 orders × Auto/save-manual = 18 UI fixtures, not backend graph acceptance.

Observed Node: `v22.23.1`. Natural process exits; no test force-exit, cancellation, skip or todo:

| Command | Exit | Result |
| --- | --- | --- |
| `node --test scripts/test-network-anyorder-ui.js` | 0 | **55 tests / 55 pass / 0 fail/cancelled/skipped/todo** |
| `NODE_PATH=/home/leon/celerity-panel-custom/node_modules node --test scripts/test-network-edit-ui.js` | 0 | **31 tests / 31 pass / 0 fail/cancelled/skipped/todo**; reused installed EJS, no install |
| `node scripts/test-network-layout-preservation.js` | 0 | `network layout preservation and dangling-edge projection: OK` |
| `node scripts/test-network-ui.js` | 1 | All preceding source assertions pass; unchanged final freshness assertion fails: `network.min.js must not be older than network.js` |
| `node --check public/js/network.js` and `node --check scripts/test-network-anyorder-ui.js` | 0 | Syntax valid |
| `git diff --check` | 0 | No whitespace errors |

Focused RED→GREEN runs reproduced missing job-alias consumption, missing mutation keys, wrong-kind acceptance, missing localized projection, stale cached deletion resurrection, lost-acceptance disappearance and the missing-randomUUID regression. Green characterization controls additionally exercise already-correct retained/bound behavior rather than deleting working implementation to manufacture a RED.

Logs: `/home/leon/.hermes/cache/scratch/anyorder-ui-v2-tests.log` and `/home/leon/.hermes/cache/scratch/anyorder-ui-v2-edit-tests.log`.

Source SHA-256: `91da73fab4dc7d4645644ab10e1425d32f5969d59397936be6434a1dfb388bb8`. Unchanged minified asset SHA-256: `8e96aa3172b05bf9678252258460c6fbcfc2e62785f08a9eba3059c710c5e527`.

## Exact remaining integration blockers

- The HTTP slice documents **no default-host selected intent service or trusted selected application/operation authority publication**. Without the owning runtime composition, native mutations refuse, and list readiness stays conservative (`routeState:'unknown'`, unverified clients). This UI does not activate or fabricate those services.
- The HTTP contract supplies **no authoritative applied node path / default+geo policy descriptor**. Full mixed-mode route display is still blocked on that data, not reconstructed from desired traversal.
- Real worker cleanup/finalizer removal and selected readiness publication are separately owned. This suite models their public terminal records/list absence; it does not prove actual remote teardown or complete backend lifecycle.
- The existing job GET requires a known ID; no create/apply job-discovery endpoint exists. In-page keys/tracking and reload recovery from an existing delete marker are implemented, not durable browser recovery or rediscovery after both marker and in-page state are lost.
- **Assets intentionally not built**. The integrating owner must perform the single planned build, bind the resulting loader cache key and rerun freshness/browser checks. The current browser bundle is not claimed updated.

Modified files only: `public/js/network.js`, `scripts/test-network-anyorder-ui.js`, `src/locales/{ru,en}.json`, `views/nodes.ejs`, and this document. No minified assets, backend files, package scripts or endpoints changed. No browser/network/SSH/MCP/DB, `.env`, service/deployment, dependency installation or heavy test/build was used. Real browser, isolated native HTTP/runtime/cleanup, Xray/SSH/REALITY/PPP, migration/rollback and production verification remain outside this local UI slice.
