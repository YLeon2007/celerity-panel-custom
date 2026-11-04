# Browser findings for UI owner (no product fix in this branch)

## Tall selected-link drawer: close control can be covered

- Actual `views/layout.ejs` + `views/nodes.ejs`, built CSS/JS, Firefox ESR 140.16.0, native 1440×1000 viewport.
- Open a staged R→B edge with all readiness/progress rows. The close control `#nodeInfoClose` is around (905,107.5); the native hit test does not hit that control. Run 04 stopped rather than silently invoking a JS click.
- `public/css/style.css` puts `#viewNetwork` in `.main-content > *:not(.toast):not(.sticky-header)` at z-index 1, while the sticky header is z-index 40 and the topbar 50. The fixed modal remains inside the lower stacking context. This is a suspected stacking cause, not a repaired or independently reviewed fix.
- The harness records `#btnAutoLayout` as the covering native hit target (`uiObstructions`) and uses a real native backdrop click as the ordinary user-visible dismissal alternative. No style, DOM, bundle or handler patch is used. Other action buttons are still exercised by native pointer input. The close-button defect is not counted as a passing feature.

## Optional edgehandles CDN script throws during actual loader startup

- In the real loader, `https://cdn.jsdelivr.net/npm/cytoscape-edgehandles@4.0.1/cytoscape-edgehandles.min.js` throws `TypeError: can't access property "memoize", e._ is undefined`.
- Neither the actual layout nor nodes template supplies a lodash global. `network.js` contains no edgehandles registration/use; the map and tested main-form/drawer flows still boot.
- Console error is preserved in each browser evidence file. This is not an all-console-clean or edgehandles/drag-to-create acceptance claim. UI owner should decide whether to remove an unused loader or supply its actual dependency; no feature edit made here.

## Harness-only failures retained separately

Run 01 used a case-sensitive text assertion despite CSS uppercase rendering; run 02 awaited a native pointer command before handling its blocking native confirm; run 03 clicked during changing warning/modal geometry. These are harness failures, not attributed product defects. Run 04 added a native hit test and exposed the close-control obstruction above. Later harness corrections avoid JSON-serializing Cytoscape's cyclic `.fit()` return, account separately for Firefox's keyed DELETE retransmission, avoid restarting an intentionally terminal stopped host, wait for the next real terminal-job poll before removing a tombstone, and verify checkbox state after warning layout stabilizes before submitting save-only. Run 08's actual backend rollback is retained as a product/runtime-boundary finding rather than reclassified as a harness problem. Each attempt retains its real statuses/log/cleanup summary; no earlier failed run is presented as passing.
