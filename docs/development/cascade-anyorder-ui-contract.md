# Any-order cascade UI: bounded lifecycle repair and API handoff

## Scope and evidence

Implementation continues the existing UI worktree at `4b5000517efbddef473afc9dbbcb5146bba9d2a0`, against §8 of `cascade-anyorder-contract.md`. It repairs shipped response handling, not the backend any-order implementation. Future asynchronous deletion and richer readiness/path projections are **explicit later wiring**, not simulated working APIs.

`scripts/test-network-anyorder-ui.js` executes the actual `public/js/network.js` IIFE in a local VM with linked form controls and a small Cytoscape model. Only graph startup and particle animation are bypassed. Actual payload builders, response consumers, `loadTopology`, `refreshStatuses`, `renderGraph`, drawers, deletion, undeploy and polling run. Every mutation reply is explicitly configured; unknown requests fail the harness. This is local DOM/API orchestration evidence, not authenticated browser, backend admission, remote teardown or client connectivity evidence.

No live browser/network requests, SSH, MCP, MongoDB, deployment, service changes, `.env` loading, heavy installs or minified asset build were used.

## Product changes

- Main and quick save-only create, and ordinary edit, explicitly confirm **saved; deployment not started**. No operation, extra POST, full Sync or client-ready claim is introduced.
- Both create forms use the existing `Idempotency-Key` header for AutoDeploy. Each form retains its own logical request key across rejected/unknown deliveries and revision refresh. Changed payload creates a new key; confirmed acceptance retires it. A main-form edit does not retire an unresolved create key. This is in-page retry identity, not persistent browser recovery or a claim about backend idempotency.
- AutoDeploy and manual Deploy consume `queued`, `preparing`, `committing`, `rolling_back` and `succeeded` operation results. Active work is not mislabeled as unstarted or newly queued. `succeeded` means applied, **not client-ready**. Existing exact-ID reads still decide proof/terminal outcome; synchronous classic completion still has no invented job/operation.
- Operation polling is keyed by operation ID. Duplicate tracking does not reset a poll; another operation does not cancel it; completion removes only that operation. Existing identity checks and finite attempt budget remain. No mutation is replayed.
- Drawer summaries now show **only the selected segment**, in traffic direction for either transport mode, plus an explicit full-applied-route/exit-unconfirmed note. They no longer append Client/Internet, follow save-only siblings, or choose the first branch as exit policy. Existing status and revision-bound client proof remain separate.
- Delete confirmation warns that routes/user traffic can be interrupted and that no alternative permitted exit means no exit. This is a general warning, not an inferred affected-user count or last-exit calculation. Cancellation sends nothing; checked synchronous DELETE behavior remains.
- Undeploy requires HTTP success and the existing `{success:true}` receipt. HTTP refusal, non-JSON/error replies or absent success cannot produce a success toast. Safe code-only diagnostics are used; prior optimistic status is restored and topology is refreshed on failure.

## Disposition of all 11 original REDs

Before edits, `node --test --test-name-pattern='\[spec-red\]' scripts/test-network-anyorder-ui.js` returned **exit 1: 11 tests, 0 pass, 11 fail**, each at its intended product assertion.

| Original RED | Disposition in this slice | Remaining API dependency |
| --- | --- | --- |
| 1. Save-only confirmation | Fixed; main/quick create and ordinary edit explicitly acknowledge save without apply/connected claims. | None for current snapshots. |
| 2. Quick create idempotency | Fixed; shared key builder, independent per-form retry identities. | Backend durable persistence remains backend-owned; browser restart recovery is not added. |
| 3. Accepted `preparing` | Fixed; exact operation polling, active-work feedback. | Detailed phase/node/wait projection is later. |
| 4. Accepted `committing` | Fixed; exact operation polling, active-work feedback. | Same. |
| 5. Accepted `succeeded` | Fixed; exact operation/proof polling, no inferred ready. | Independent PPP/Xray outcomes are later. |
| 6. Incomplete prefix falsely reaches Internet | Fixed; selected `Portal → Relay` segment only, full route unconfirmed. | Exact `no_bridge_exit`/other completeness reason requires a bound backend projection. |
| 7. Save-only sibling shown as applied route | Fixed; no sibling traversal. | Full desired/applied path comparison requires applied descriptors. |
| 8. Mixed-mode full-route summary | False route claim removed. **Original full-chain acceptance remains API-dependent**, not claimed green. | Original test demanded `Portal → Relay → Bridge 1` from graph statuses alone. That would require another browser planner. It is replaced by a conservative segment-display regression for both mixed-mode segments and explicit unconfirmed route. |
| 9. Exit deletion warning | Fixed; localized general consequence warning before dispatch, cancellation tested. | Precise route/user impact is later. |
| 10. Rejected undeploy false success | Fixed; checked HTTP/current receipt, safe error, refresh, no success. | None for current undeploy contract. |
| 11. Concurrent accepted operations | Fixed; independent exact-ID timers and terminal cleanup; duplicate tracking covered. | Discoverability after page reload remains later API wiring. |

Thus **10 original current-contract assertions are repaired without changing their required outcome**. The mixed-route case deliberately stops claiming a full route rather than inventing its proof. The green suite does not close the API-dependent full-route requirement. Repaired tests are labeled `[regression]`, not `[spec-red]`.

## Preserved contracts and exercised order matrix

Existing endpoints and legacy envelopes remain:

- Create/update: `/api/cascade/links`, `/api/cascade/links/:id`; save-only current snapshot; AutoDeploy `autoDeployJob`, `autoDeployOperation`, checked classic `autoDeployResult`, or saved/blocked diagnostics.
- Selected manual apply: `/api/cascade/topology/deploy`, exact `{expectedTopologyRevision,linkId}`. Domain/full Sync remain separate explicit commands.
- Intent read: `/api/cascade/links/auto-deploy-jobs/:jobId`, current `autoDeployJob` envelope; handoff to its actual operation ID.
- Operation read: `/api/cascade/topology/operations/:operationId`; no global revision impersonates success. Applied/unverified polls until verified/degraded/budget expiry. Existing budget still allows 41 reads for the configured 40-attempt continuation limit.
- Delete: current completed snapshot from `DELETE /api/cascade/links/:id`; no pretend delete endpoint/job.
- Undeploy: current `POST /api/cascade/links/:id/undeploy` and `{success:true}` receipt.

Generated request-targeting matrix remains **9 graph orders × 2 intent variants = 18 tests**:

| Graph | Orders, each AutoDeploy and save-only/manual |
| --- | --- |
| G1 | `P→B1` |
| G2 | `P→R; R→B1` / `R→B1; P→R` |
| G3 | `P→R; R→B1; R→B2` / `P→R; R→B2; R→B1` / `R→B1; P→R; R→B2` / `R→B1; R→B2; P→R` / `R→B2; P→R; R→B1` / `R→B2; R→B1; P→R` |

G1 is reverse. G2/G3 mix reverse with forward `R→B1`. Manual apply runs reverse creation order, targets only the selected link, and never supplies a sibling list or unscoped fallback. These are explicit UI fixtures, not backend acceptance claims. Existing delete/recreate checks retain a neighboring edge, dragged node coordinates, pan/zoom and layout/fit counters.

## Verification actually run

Node observed: `v22.23.1`. Commands run from the worktree root:

| Exact command | Exit | Result |
| --- | --- | --- |
| `node --test scripts/test-network-anyorder-ui.js` | 0 | 45 tests, 45 pass, 0 fail/cancelled/skipped/todo. Includes 26 preserved shipped cases and 19 repair/control cases. |
| `NODE_PATH=/home/leon/celerity-panel-custom/node_modules node --test scripts/test-network-edit-ui.js` | 0 | 31 tests, 31 pass, 0 fail/cancelled/skipped/todo. Reused already-installed EJS `3.1.10`, compatible with declared `^3.1.9`; no install or copied dependency. |
| `node scripts/test-network-layout-preservation.js` | 0 | `network layout preservation and dangling-edge projection: OK`. |
| `node scripts/test-network-ui.js` | 1 | All preceding source assertions pass; final freshness assertion fails: `network.min.js must not be older than network.js`. Expected integration-build dependency; not hidden or weakened. |
| `node --check public/js/network.js` | 0 | Syntax valid. |
| `node --check scripts/test-network-anyorder-ui.js` | 0 | Syntax valid. |
| `git diff --check` | 0 | No whitespace errors. |

Additional focused RED→GREEN runs covered original failures plus newly expanded quick-retry, save/edit, manual active-operation, duplicate/concurrent polling, conservative mixed summary and undeploy-receipt cases. RU/EN controls verify actual handler output and template key bindings. The full suite has no skipped/todo API fiction.

Source SHA-256: `91a8a577a279a5486df5b140ae6c5e441af4b91872d9479d0384228532a771e2` (`public/js/network.js`). Unchanged minified asset SHA-256: `8e96aa3172b05bf9678252258460c6fbcfc2e62785f08a9eba3059c710c5e527`.

## Modified files and integration handoff

- `public/js/network.js` — lifecycle repairs above.
- `scripts/test-network-anyorder-ui.js` — actual-handler regressions and controls.
- `docs/development/cascade-anyorder-ui-contract.md` — this report.
- `src/locales/ru.json`, `src/locales/en.json` — necessary visible strings and consequence warning only.
- `views/nodes.ejs` — six added locale bindings only; asset/cache key unchanged.

No backend, package script, other template/locale, minified asset or infrastructure file changed. The integrating owner must run the single planned assets build, bind the loader cache key to the resulting bundle, and rerun the freshness check. No source-only test claims that the browser is already receiving these changes.

Later wiring requires actual accepted backend data: `desiredSaved` and `job` aliases; bound `applicationState`, `routeState`, `tunnelState`, separate PPP/Xray outcomes; authoritative applied path/policy; phase/wait/node/next-action diagnostics; persisted operation discovery; and asynchronous delete/tombstone acceptance, retained identity and terminal physical absence. **None is manufactured or activated here.** Current snapshot validation is not a delete-finalization protocol. Precise impact warnings and missing-input/exit explanations must consume that evidence, not infer it from role/status/array order.

Real browser/minified-asset, backend lifecycle, isolated Xray/SSH, REALITY and PPP, migration/rollback and production verification are unperformed and remain outside this local UI slice.
