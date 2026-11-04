# Backend owner handoff: reverse last-exit delete stays RED

**Observed against the actual default host / queue / coordinator / worker / finalizer, with the shared in-memory DB/node-executor fixture. This is not real MongoDB or real-node acceptance and is not a claim that production has the same failure. No backend source fix or guard bypass was made.**

## Reproduction

1. Save P→R reverse on port 24501 with Auto unchecked; no job/executor activity.
2. Create R→B reverse on 24502 with Auto checked and create an independent P2→B2 forward on 24503 with Auto checked.
3. Tick the actual runtime. R→B succeeds as staged `no_portal_input`; independent forward succeeds. The saved P→R is not silently included.
4. Use selected-link manual Deploy on P→R. Actual admitted operation succeeds `complete` with effective P→R→B.
5. Delete R→B through the actual public DELETE route. Acceptance returns 202 and a durable delete job. The worker prepares/commits modeled node candidates but its real PPP gate returns `{ok:false, verifiedRelayCount:0, reason:'PPP_UNKNOWN'}` for `kind:'link.delete', routeState:'no_bridge_exit'`.
6. Exact operation becomes `rolled_back`, job `failed`, link remains present/deleting, and the browser correctly retains its arrow instead of announcing deletion. No reverse recreation positive is claimed.

Fixture Relay R is explicitly `not_installed`, desired `absent`, secret revision 0, with empty L2TP users/operations and no installed route group. Its imported originals and modeled node receipts are the shared fixture's setup, not real physical adoption evidence. The remaining ordinary reverse prefix after last-exit removal needs investigation by the backend owner; do not weaken PPP/unknown ownership guards to make this test green.

## Evidence

- `run-08/evidence.json` (local raw) and `run-08/summary.json`: genuine browser backend rollback, before added observation hooks.
- `delete-diagnostic.json` and `.log`: fast actual HTTP/runtime reproduction **without** the stale-revision injection, socket-response fault or browser; still reaches `worker.ppp` → `TOPOLOGY_DEPLOYMENT_FAILED` / rolled_back. This rules out those browser fault injections as a necessary trigger but is not extra browser acceptance.
- Later final browser evidence includes the delegated actual gate return and the actual secret-free formatter's phase/code. Observation-only wrappers do not replace results or throw conditions; the production `/app` diagnostic file sink is not enabled.
- The harness retains this requested positive as `FAIL`, keeps a nonzero overall exit, and separately exercises failed-arrow retention and an independent forward delete/recreate. A successful forward control does not close the reverse last-exit gate.

Run `bash browser-assets-wave8/run-browser.sh browser-assets-wave8/FRESH-RUN` after the owning repair. The harness will require reverse delete plus same-port recreation to succeed; it never seeds terminal jobs, removes the arrow itself, or injects successful API JSON.
