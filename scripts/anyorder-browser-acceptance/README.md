# Integrated any-order Firefox acceptance

This is a new current-source integration test. `browser-assets-wave8/` is the
unchanged canonical historical import, including its older failure expectations.
This test reuses its actual local application composition and native BiDi driver;
it does not rewrite that evidence or change product UI/CSS/templates.

Run from the repository root in a bounded `hermes-heavy` scope with a clean test
environment, a private lock-exact `npm ci`, no repository `.env`, and freshly
rebuilt assets. Pass a **new**, nonexistent evidence directory below
`/home/leon/c3-anyorder-execution-20261104/wave8-integration/`:

```sh
node scripts/anyorder-browser-acceptance/acceptance.cjs "$NEW_EVIDENCE_DIR"
python3 scripts/anyorder-browser-acceptance/verify.py "$NEW_EVIDENCE_DIR/evidence.json"
```

The evidence job specifications and bounded launcher in that wave8 integration
directory record exact commands, source HEAD/tree/status, quotas, logs and exits.
Do not infer acceptance from the launcher's allowed diagnostic exits.

All form edits use native BiDi pointer/keyboard actions. Closed selects are
focused using native Tab and selected with Home/ArrowDown; no DOM value/event
injection is used. Graph edge coordinates are inspected and hit-tested, then
native clicks are retried at most three times after asynchronous layout settles.
A covered close button is recorded as a UI defect; an actual native backdrop
click is a separate user-visible dismissal, not a passing close-button test.

The twelve cases require save-only, two independent auto jobs/polls, incomplete
source-less status, selected manual apply, native drag/zoom preservation, stale
revision refusal, lost-response/idempotent retention, **successful reverse and
forward deletion/recreation**, an independent explicit worker verification fault,
and served-asset/extra-mutation checks. The failure case throws only at the
explicitly modeled node executor boundary, then requires the actual worker's
rollback, failed job, retained arrow and untouched neighbor records. It does not
reuse the old expectation that ordinary reverse deletion fails.

## Limits and UI-owner handoff

Firefox and application route/runtime/consumer/worker/finalizer code are real.
DB queries/transactions, config adoption, node executor/readback and empty user
sync remain modeled. This is not Mongo atomicity, SSH/Xray/PPP/client traffic,
full `index.js` startup, auth/CSRF, responsive-layout or production acceptance.

Console `memoize` initialization errors and invalid Cytoscape shadow-style
warnings remain disclosed. Sticky toolbar coverage of `nodeInfoClose` remains a
UI-owner issue. The verifier fails on unrelated console errors; it does not turn
these known UI defects into a clean-console claim.

The separately imported `scripts/anyorder-runtime-xray/` harness does not supply
native physical authority. Its construction-only authority probe must continue
to refuse fresh rootless pins before channels, observations or capture spawn;
this integration does not open that path or contact external endpoints.
