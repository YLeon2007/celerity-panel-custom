# Native UI obstruction regressions — integration handoff

Only two product changes are in this slice:

- Release the embedded `#viewNetwork` wrapper's stacking context, retaining the
  original z-index 1 on its map surface. Fixed modal siblings can then use the
  existing z-index 1000 above the sticky toolbar/topbar. No positions, dimensions,
  Cytoscape handlers, zoom, fit or layout code changes.
- Remove the unused edgehandles loader entry from `nodes.ejs`. The shipped
  `network.js` never registers or invokes edgehandles. Its existing core
  `dragfree` → position-save binding, Add Link form and quick-form handlers remain
  unchanged. There is no currently wired edgehandles drag-to-create opener to
  preserve or expand; this change does not implement one.

## Source-only check

```bash
node --test scripts/test-network-ui-obstructions.js
```

This checks the narrow stacking policy and runs the actual lazy loader in a VM
(including each existing script-error continuation). It is not browser proof.

## Required fresh native verification (integration owner only)

After importing this commit, rebuild assets using the integration owner's private
lock-exact dependencies and existing sole-heavy budget. In particular,
`public/css/style.min.css` in the canonical source-only import was unchanged;
**do not test the old CSS and call that a fix verification**.

The isolated harness uses the current `anyorder-browser-acceptance/firefox.cjs`
native-form wrapper and imports the frozen base driver and `local-app.cjs`
read-only. It neither modifies nor writes into the frozen wave 8 packet.
Run it from the integrated repository, **inside the already-approved
bounded `hermes-heavy` scope**, with a fresh absolute evidence directory:

```bash
timeout 300 env -i PATH="$PATH" HOME=/home/leon TMPDIR="${TMPDIR:?}" \
  NODE_ENV=test PANEL_DOMAIN=panel.test.invalid ACME_EMAIL=admin@test.invalid \
  ENCRYPTION_KEY=test-encryption-key-32-characters-long SESSION_SECRET=test-session-secret \
  node scripts/test-network-ui-obstructions-browser.cjs \
  /home/leon/c3-anyorder-execution-20261104/ui-final-wave10/native-FRESH
```

The fixed synthetic values above are the existing local fixture's test-only
configuration, not account credentials. No real login, `.env`, Mongo connection,
SSH, cron, remote host or physical client is used. All form edits use native
pointer/keyboard input, including Tab/Home/ArrowDown on closed selects.

### Exact assertions (three native cases)

1. **Loader:** the real nodes page boots in Firefox at the driver's native
   1440×1000 viewport, with real Cytoscape. No edgehandles script tag/request or
   edgehandles/memoize console exception. Browser-computed layers must be wrapper
   `auto`, map surface `1`, modal `1000`; stale generated CSS fails. Served built
   asset digests must match disk in both HTTP-client and browser WebCrypto
   readback of the actual template URLs. The layout style cache suffix must
   equal the rebuilt CSS digest prefix.
2. **Existing open button:** `document.elementFromPoint` at the rounded center of
   `#btnAddLink` must be the button or its descendant; native pointer input opens
   `#addLinkModal`. The same check/input on `#modalClose` dismisses it. No link is
   created and node positions, pan and zoom are identical before/after.
3. **Drawer close:** create a single real R→B Auto link through the existing native
   form, then let the actual loopback host/worker produce `no_portal_input` staged
   state. Open that edge by native graph pointer. Require a genuinely tall card
   (at least 75% viewport height), the real readiness rows and close center inside
   the original Auto Layout toolbar's vertical overlap band. The rounded center
   hit must reach `#nodeInfoClose` or its descendant, **not `#btnAutoLayout`**.
   Native close must remove the active drawer without changing node positions,
   pan or zoom (catching accidental Auto Layout execution).

There is no DOM `.click()`, handler call, forced click, backdrop dismissal,
synthetic readiness, DOM padding or CSS/stacking override in this harness.
Failures and exact hit/geometry/console/cleanup data go into the fresh directory's
`evidence.json`. A short popup is not accepted as the tall-drawer regression.
Keep any failed attempt and use a different fresh directory for a retry.

These checks supplement, not replace, the existing full native lifecycle matrix
under `scripts/anyorder-browser-acceptance/`. That current-source matrix requires
successful reverse and forward deletion/recreation, independently of the old
frozen failure expectation. Neither harness establishes physical Xray/PPP
readiness; the full application/auth/bootstrap and physical boundaries remain
outside this local modeled-backend acceptance.
