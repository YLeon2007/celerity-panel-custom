# Distinct finite fresh owner composition (source only)

This is a separate trusted-root composition, not a panel/HTTP/MCP route, request
field, environment flag, activationSet switch or accepted operational policy.
No installed/live files or policies are modified by these sources or tests.

## Fixed source closure

- `coordinated_fresh_restore.py` accepts no arguments and requires root. It reads
  the fixed root-owned fresh policy, checks the coordinator against its accepted
  `inventory.sourceSha256`, and executes only the fixed coordinator source.
- `Coordinator.serve_fresh_owner` loads only the fixed fresh launcher bytes pinned
  by `files['/usr/local/libexec/c3-test-fresh-classic.py']`. It injects its exact
  currently running coordinator module (including `__main__` identity), and calls
  `FreshLaunch(self).run(proof)` without a substitute Coordinator or client channel.
  Exact `type(held) is c.Coordinator` validation remains enforced.
- `fresh_owner_restoration_channel.py` verifies the separate root-owned fresh
  settlement config's `freshBridgeSha256` and legacy `bridgeSha256`, then runs
  the pinned bridge in its distinct internal fresh mode. The bridge independently
  checks `coordinatorSha256`. No arbitrary module path is accepted.
- `settle-fresh-held-owner.js` is a separate finite root-only entry. Its config is
  `/etc/celerity/topology-test-fresh-owner-settlement.json`; all prior fields and
  original-byte pins remain mandatory, with the additional fresh bridge pin.

## Grammar and ordering

The fresh pipe admits `check` and terminal `fresh-handback` only. Its UDS peer
admits `check-restoration` and terminal `fresh-handback` only. Existing legacy
verbs and results retain their separate grammar. No legacy activate/thaw/keep
or completion call is made after fresh launch releases the held resources.

`HeldTestOwnerSettlement.freshHandback` uses the unchanged public five-owner
handback CAS, majority readbacks, enrollment/generation checks, zero admission/
lock checks, original-byte verification and durable no-replay settlement journal.
Only after all five are confirmed does it invoke the terminal capability. A
second call on the same service refuses before opening another bridge. The
existing durable journal and root intent prevent a fresh process from replaying
an already-started handback; there is no automatic recovery/reopen path.

The root defers its positive terminal acknowledgement until required coordinator,
listener and outer-lock disposal. The JS adapter joins natural Python process
exit. Lost reply, terminal timeout, journal/required cleanup error or uncertain
terminal completion is `COMMITTED_ACTIVATION_UNKNOWN`, never evidence of no
activation or permission to retry/rollback. Before-send validation can still
refuse without activation. Required cleanup preserves the original failure.

## Readiness

Both fixed HTTP probes and ingress validation now require `/classic-ready`, with
exact body `c3-classic-ready-v1\n` and SHA-256
`437210538daa3691735d03ab798dbba7bef28404e621f17ea569a6b28c370da6`.
The two-key environment, root, capabilities, cgroup, exact IPv4 ingress eligibility
and all sealed-thaw guards are unchanged. This is not HTTPS/Caddy ingress proof.

## Local evidence and unimplemented operational gates

Focused tests exercise the actual JS adapter, Python pipe/UDS bridge, retained
five-node Coordinator, pinned FreshLaunch, real subprocess exec, `/proc` socket
binding and HTTP serving. The assembled Mongo fixture provisions owners through
public initializeClassic/adopt/preEnroll, not raw owner rows, then checks the
actual final owner documents in the root commit. It covers each of five lost
holds and stale generations, post-terminal reply loss, real deadline expiry,
required cleanup failure, exactly one exec and no service-level channel reopen.
Physical/root/UID/SSH/systemd/namespace/cgroup inventory is explicitly simulated.

The bridge fixture starts its supervisor before public Mongo provisioning. Its
listener's preparation wait is modeled at 70 seconds; production's five-second
prepared accept remains unchanged. Actual operational supervisor scheduling is
therefore an explicit unproven prerequisite, not a widened product timeout.

Separate real-application tests execute the actual index twice with disposable
Mongo/Redis, read-only source permissions and lock-exact dependencies. That
application proof is not execution of the real application inside the fresh
physical root. Accepted root construction, UID/namespace/mount/fd inventory,
independent producer acceptance, physical ingress, restored operational database
compatibility, root installation/policy acceptance and live TEST/PROD activation
remain unperformed. Source success is not physical GO.
