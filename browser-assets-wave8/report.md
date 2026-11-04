# Wave 8 browser assets and isolated UI acceptance

## Outcome

- **Build/install PASS.** Private, real-directory `node_modules` populated with lock-exact `npm ci`; `npm run build:assets` executed against real sources. A second clean-environment, entirely cached/offline install/build replay exited 0. Lockfile is unchanged from base `8eb7b4d5d6ab8bde18eddf21374c3408a42c84d7`.
- **Scoped browser result: 12 cases, 11 PASS, 1 FAIL. Overall acceptance remains RED (exit 1), not a full acceptance claim.** Actual Firefox ESR **140.16.0**, headless native WebDriver BiDi pointer/confirm/wheel/drag actions, a fresh disposable profile and actual loopback HTTP application.
- **Blocker:** reverse last-exit R→B deletion after completing P→R→B rolls back at the real worker PPP gate: `PPP_UNKNOWN`, `routeState:no_bridge_exit`, operation `rolled_back`, job `failed`. Its arrow is correctly retained; reverse same-port recreation is not claimed. See `backend-handoff.md`. The independent forward delete/recreate control passes.
- Additional actual UI findings: the tall drawer's close button is covered by `#btnAutoLayout`; the optional edgehandles CDN script throws a missing-lodash `memoize` error. Neither was patched or counted as a passing feature. See `ui-handoff.md`.

## Asset identity and dependencies

| Item | Verified value |
| --- | --- |
| Base | `8eb7b4d5d6ab8bde18eddf21374c3408a42c84d7` |
| Node / npm | `v22.23.1` / `10.9.8` |
| `package-lock.json` SHA-256 | `5298202cf6ca2ce8da44f0578bd54c1146def29fd698c41bc62ac3b5982e6eac` |
| `public/js/network.min.js` SHA-256 | `5ea9f38d112a0a5cb362e3b080f104d0bd83b13854caf05b22fcfe8651381444` |
| Cache suffix in both actual templates | `5ea9f38d112a0a5c` |
| Project dependencies | 399 installed entries; every installed version matches the lock and has integrity metadata; 10 other-platform optional omissions from 409 locked package entries |
| Browser graph dependency | Actual Cytoscape loaded by the real nodes-page loader (version recorded in final evidence) |
| Builder qualification | Existing package script invokes **esbuild 0.28.2 via npx outside the project lock**; its cached npm integrity/URL/optional binary provenance is recorded separately in `esbuild-build-tool.json`. Do not call that tool a project-lock dependency. |

Disk bytes, actual HTTP 200 response bytes, and Firefox's own fetch/WebCrypto digest all equal the SHA-256 above. The post-browser offline build replay reproduced the same bytes, and final checksum verification passed. CSS build outputs were rebuilt but byte-identical to baseline; no gratuitous CSS change is committed. `public/js/network.js`, package manifests/lock, backend and product UI feature sources are unmodified.

`dependency-evidence.json`, `dependency-summary.json`, `installed-tree.json` and `assets.sha256` preserve detailed provenance. `build.log` retains the first successful install/minification followed by a genuinely failing stale-cache-key regression; cache references were corrected. `build-replay.log` is the final complete exit-0 install/build/test replay, not a rewritten original log.

## Browser case ledger (run 11)

1. PASS — actual layout/nodes template and minified bundle boot; browser-served digest verified.
2. PASS — save-only native button persists pending P→R with no job or executor calls.
3. PASS — native Auto creates two independent jobs; each is polled by its own exact identity without a UI create repost.
4. PASS — actual source-less R→B worker result is staged `no_portal_input`; saved pending P→R is not implicitly included; drawer separates route/tunnel/PPP/Xray readiness.
5. PASS — selected manual Deploy on P→R completes P→R→B; exact `linkId`, one selected deploy POST, no Full Sync.
6. PASS — actual native drag and wheel change position and zoom, then refresh preserves node positions, pan and zoom.
7. PASS — real stale-revision DELETE returns HTTP 409 `STALE_TOPOLOGY_REVISION`; no new job; arrow retained.
8. PASS — all accepted DELETE responses (including Firefox's transport retransmissions) are dropped after real route execution; actual network-error toast shown, arrow retained, all attempts replay the same key and one durable job; a further UI click adds no request/job.
9. **FAIL — requested reverse last-exit delete/same-port recreation positive:** real delete operation rolls back, so no terminal success/list absence or reverse recreation is asserted.
10. PASS — failed reverse delete keeps its arrow and failed job visible, without a deletion-success claim.
11. PASS — independent forward delete reaches real terminal success and actual list absence, removes only its own arrow after exact polling, preserves graph layout, then recreates on the same port with a new ID and successful actual runtime operation.
12. PASS — all recorded mutations remain selected/expected scope, independently completed operations were polled, no `/chain/deploy` or `fullSync` request, and actual browser-served bytes hash matches disk.

The loss test saw 3 transport attempts in final run 11. These are Firefox HTTP retransmissions after connection reset, not three UI submissions; all retain the same idempotency key and job ID. The final evidence and source checks distinguish them explicitly.

## What is real versus modeled

**Real:** installed Firefox with sandbox intact, native button/checkbox/confirm/backdrop/graph actions, actual `views/layout.ejs` and `views/nodes.ejs`, RU locale, built CSS/minified JS, public Express route modules, topology serialization, default host/queue/coordinator/worker/finalizer and polling, a loopback ephemeral listener, and actual HTTP response-loss faults after route acceptance. No static fake success API responses are used. Gate/diagnostic wrappers only observe delegated actual results; they do not replace decisions.

**Modeled by the existing shared runtime fixture:** in-memory Mongo-like queries and transactions (including lack of real rollback/atomicity proof), synthetic adoption/original records, node executor/SSH/readback receipts, controlled finite scheduler ticks, empty user-resync edge, no-op subscription/topology invalidation hooks, in-memory settings/position persistence, and synthetic fixture session/CSRF identity. The source-port SSH probe deliberately refuses real SSH; unknown warning state is not physical proof of a free port. NonPPP relay state is explicitly absent/not-installed. No real account or login credentials are used.

**Not covered:** real MongoDB atomicity/indexes, physical adoption transfer, remote SSH/node ownership, Xray/PPP/client traffic or readiness, `index.js` full bootstrap, real authentication/authorization/CSRF, cron/background-writer compatibility, edgehandles interactions, all responsive sizes, EN browser interaction, or an authenticated production stand. EN/RU lifecycle strings are covered by source tests, not claimed as two-locale browser acceptance.

The composed application binds only `127.0.0.1`; no external port is published. The real loader's ordinary public CDN dependencies were used; this is not an offline-browser claim. Production `.env`, accounts, services, deployment hooks and remote hosts were not used.

## Tests and resource/cleanup evidence

- `node scripts/test-network-ui.js` — PASS.
- `node scripts/test-network-layout-preservation.js` — PASS.
- `node --test scripts/test-network-edit-ui.js` — 31/31 PASS.
- `node --test scripts/test-network-anyorder-ui.js` — 55/55 PASS. Those 86 Node subtests plus the two standalone scripts do not replace browser acceptance.
- `run-11/evidence.json` — complete actual 12-case browser ledger, request keys/results, graph/backend snapshots, console findings, engine identity and cleanup; overall `success:false`.
- `final-verification.json` — independent reread of exact case ledger, bundle and lock identity, dependency evidence, exact browser PID/profile absence and owned loopback listener closure. `evidenceVerified:true` and **`acceptancePassed:false`** are deliberately separate.
- Earlier attempts retain their real failing logs and compact `run-01`…`run-10/summary.json` files with original raw evidence digests. Large raw attempt JSON remains locally ignored, not falsely counted as committed final evidence.
- Every install/build/browser run used the existing separate `hermes-heavy` scope, RAM high 1536M/max 2G, swap max 512M, CPU 100%, finite timeout, and approved scratch. No concurrent build, system configuration change, browser sandbox removal or shared dependency mutation was used. Exact final browser PID/profile and local listener were independently checked closed; no global browser/process kill was used.

## Reproduction

From `/home/leon/c3-anyorder-browser-assets-20261104`:

```bash
# A NEW output directory is required. RED/nonzero is expected until the reverse
# last-exit backend blocker is fixed; the forward control is not a substitute.
bash browser-assets-wave8/run-browser.sh browser-assets-wave8/FRESH-RUN

# Evidence-only verification of the preserved RED final run, not acceptance PASS.
python3 browser-assets-wave8/verify-evidence.py browser-assets-wave8/run-11 --allow-known-blocker

# Private reinstall/build/source-test replay (existing log is never overwritten).
HERMES_HEAVY_MEMORY_HIGH=1536M HERMES_HEAVY_MEMORY_MAX=2G \
HERMES_HEAVY_MEMORY_SWAP_MAX=512M HERMES_HEAVY_CPU_QUOTA=100% \
HERMES_HEAVY_TMP_ROOT=/home/leon/.hermes/cache/scratch/browser-wave8-heavy \
/home/leon/.local/bin/hermes-heavy timeout 300 env -i \
PATH="$PATH" HOME=/home/leon TMPDIR="$TMPDIR" NODE_ENV=test \
BUILD_LOG_PATH=browser-assets-wave8/build-FRESH.log \
bash browser-assets-wave8/build.sh
```

The completed replay additionally used `npm_config_offline=true`, proving the existing cache sufficed. That option can be omitted for normal registry fallback. `build.sh` updates only content-bound template cache references after actual minification and verifies unchanged lock/package versions; never run another build concurrently or reuse another worktree's mutable dependencies.
