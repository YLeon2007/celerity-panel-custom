# Classic conversion and persistent empty PPP ingress

## Delivered source slice

- `frozenTopologyDeploymentPlanComposer.js` uses the existing exact `legacyProfileArtifacts` matcher for classic before-profile ownership. Portal matching adds checked client ownership and only exactly matched base members; runtime clients, unrelated inbounds/outbounds/rules, policy and log configuration survive. Empty absent bridge `inbounds` is normalized on a private copy, never on imported bytes or adoption digests.
- The transition retains a surviving reverse link's observed original domain suffix instead of forcing its synthetic reference into an established handshake domain. Original UUIDs, transport and REALITY keys remain descriptor inputs on both sides. New/unobserved links retain the existing synthetic convention. Final suffix collisions refuse rather than merge identities.
- Classic generic `bridge-up`/`tunnel-up`, `portal-down-*`/`conn-down-*`, older `bridge`/`tunnel` and combined/shared bridge artifacts are removed using their matched before-delta. Ordinary modern fallback also checks expected tunnel/dialer/reverse artifacts and ordered exact rules; a failed classic dialer match cannot be silently treated as validated modern ownership. Separately owned same-profile ingress rules sharing an outbound are preserved rather than incorrectly claimed by that rule check.
- Installed empty paths retain their deterministic loopback listener and an unconditional first `-> block` rule across later deletions, including G5's intermediate relay with no complete default exit. The existing exact blocked readback path also remains first. A later attach reuses the listener and removes the stale block. Global reverse-control and unrelated transit/geo rules remain active behind that scoped block.
- The materializer accepts an **internal** `installedPath` input, verifies its node/group/key and exact old/new path arrays against trusted descriptors, and forwards only `{ownerNodeId, groupId, pathKey}` to the composer. Arbitrary empty peers do not create installed ingress. This is input propagation, not new adoption, terminal authority or routing policy.

No owner/adoption/deployment repository, coordinator, worker, executor or gate source was changed in this slice. Existing protocols and V1 scope remain: imported reverse none/REALITY without groups only; forward/TLS/group imports are explicitly unsupported. No DB, SSH, MCP, remote services, production environment, install or build was used.

## Two concrete separately owned caller/reader dependencies

These are **remaining integration blockers**, not a claim that the selected runtime now completes either lifecycle.

1. **Coordinator input:** `TopologyOperationCoordinator.queue`, at its actual `planMaterializer.materialize` call, currently passes only the two selected descriptor snapshots. It must also pass the already checked selected installed-path record:

   ```diff
   - ...(selected ? { baselineTopology: selected.baselineTopology, effectiveTopology: selected.effectiveTopology } : {}),
   + ...(selected ? { baselineTopology: selected.baselineTopology, effectiveTopology: selected.effectiveTopology,
   +     installedPath: selected.installedPath } : {}),
   ```

   The persistent-ingress regressions call the real materializer with that existing reader output shape. Without this narrowly owned forwarding hunk, a second empty-path deletion with no profile readback still cannot identify the installed relay/key. The composer deliberately does not guess from all empty group paths. Re-run the real default HTTP G5 fixture after integrating this hunk and the separately owned incomplete-path worker/gate closure.

2. **Current settled profile:** the imported `node.profileConfig` is an original adoption readback, not an everlasting current profile. `TopologyDeploymentRepository.readSelected` currently adds `componentAt(durableSelectedTopology(operation.effectiveTopology), node)` after settlement without replacing stale imported `profileConfig` from the validated committed operation node candidates. The existing operation has private canonical candidate bytes/hash and owner/terminal checks; the reader owner must provide current profile evidence through that existing checked source (including cleaned detached endpoints), not a new successful-operation pointer or mutable desired flag. This slice does not change the reader.

   Concrete local reproduction: public `initializeClassic → adopt → readSelected`, actual initial conversion and a first G2 exit-delete candidate succeed; composing the next deletion from unchanged original raw descriptor profiles refuses `TOPOLOGY_PROFILE_BASELINE_MISMATCH`. Evidence: `$TMPDIR/c3-conversion/stale-profile-repro.cjs` / `.tap`. That refusal is **not** completed migration. The positive runner tests instead feed the actual freshly read candidate bytes into each next local materialization and explicitly do not forge settlement pointers. Finish the reader-to-worker selected lifecycle before operational import.

## Local executable evidence

All final commands exited naturally with zero cancellation/skips; no force-exit was used. Read-only dependencies were borrowed via `NODE_PATH=/home/leon/celerity-test-cascade-v2/node_modules`; this is not a fresh install or lock-exact bundle claim. Older source tests require only dummy `PANEL_DOMAIN`, `ACME_EMAIL`, `ENCRYPTION_KEY`, `SESSION_SECRET`; there is no `.env` in this worktree. The first unconfigured regression invocation failed that required-environment check and is preserved separately.

- `cascadeAnyOrderLegacyConversion.test.js`: **35 passed**, including the inherited 25 public import/handback prerequisites and **10 dedicated conversion tests**. Eight generated scenarios are `combined|single|relay|shared × none|REALITY`: actual classic generators → public adoption reader → actual materializer → actual typed executor/transport/fenced fake-root runner apply/repeat/delete-all/recreate. Exact candidate readback bytes, unchanged runtime client UUID/email/flow, original surviving tunnel domains/UUIDs/keys, other-profile bytes, no duplicate listeners, byte-identical replay and no extra modeled restart are asserted. Additional tests cover absent `inbounds` and mismatched dialer refusal. Logs: `conversion-final2.tap`.
- Composer/materializer/PPP/geo area: **203 passed**: 15 persistent-ingress tests, 82 existing geo/installed worker tests (including user/peer/group fingerprints) and 106 existing composition/materialization tests. Eight G5 scenarios are four explicit mode vectors × deletion orders `middle→exit→input` and `exit→middle→input`; assertions include block-first control-domain behavior, unchanged listener identity and transit geo policy. Logs: `area-final.tap`.
- Existing selected-delete regression: **334 passed**, `selected-delete-final.tap` (contains its own inherited tests; do not add these overlapping counts into a total).
- Existing actual cleanup executor/runner regression: **30 passed**, `cleanup-regression-final.tap`.

RED evidence is preserved in the same scratch directory: `legacy-red.tap` (classic baseline mismatch), `replay-red.tap` (duplicate private-IP block on replay), `matcher-red.tap` (unchecked changed dialer), `ppp-red-corrected.tap` (all eight G5 repeated-empty cases lose the listener). The first PPP test draft incorrectly expected a geo-only peer ingress that this generator never installs; that fixture error is retained as `ppp-red.tap`, and the corrected RED asserts real transit geo preservation. `geo-regression.tap` preserves the overly broad initial rule-ownership check; the final check preserves the genuine same-profile peer and the full area is green.

The fake-root runner executes the real protocol and returns its actual receipts. Its DB binding/physical-maintenance authority, systemd, Xray and socket observations remain explicitly modeled local seams. This is neither Mongo atomicity proof nor live tunnel, PPP-client, remote writer exclusion, adoption activation or deployment evidence.
