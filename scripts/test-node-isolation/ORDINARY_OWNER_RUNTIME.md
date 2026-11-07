# Existing TEST ordinary network owner: source checkpoint

This checkpoint implements the selected path inside the existing freezer,
Coordinator and `c3-test-fresh-network.service`; it is **not end-to-end ordinary
ownership acceptance or permission to install/start it**. Legacy operation stays
selected when the accepted fresh v2 root input has no `networkPlanSha256`.

## Implemented source

- Original locked journal OFD and live capabilities cross authenticated
  SCM_RIGHTS into escrow. Original surrender is passive; the receiver consumes
  the original succession intent, without reopening/adopting a journal.
- Docker-live construction drains before the original pre-arm rendezvous. Held
  checks use the original Fence; ordinary authority has no holder, guard, Docker
  RPC or supervisor liveness prerequisite.
- Existing root main has PID1 notify/barrier/full-Dump custody, exact named
  subtraction, inherited-capability checking and same-generation association.
- Same Coordinator prepares the recipient, adds the closed `networkHandoff` to
  its original COMMIT, transfers actual serving descriptors, cuts over through
  the existing Caddy consumer, receives ownership and performs final readback.
- New terminal internal result is exactly
  `{commitSha256,networkOwnershipSha256}`; the public bridge ACK adds only
  `networkOwnershipSha256`. Legacy result remains a string and its ACK unchanged.
  `inventory.coordinatorSha256` binds canonical restore configuration;
  `inventory.sourceSha256` binds Coordinator source; `files[FRESH]` binds fresh
  source. No public proof selector is added.
- Empty stop derives the unique accepted upstream handler's fixed 503 response;
  live/uncertain application state retains resources instead of killing the app
  or returning OLD. Historical fixed-entry/profile pins remain historical.

## Existing-anchor installation contract (parent-owned, runtime-only)

The existing active `multi-user.target` must actually have a manager-side Wants
edge to this exact existing service, with matching WantedBy on the service.
A later explicitly authorized installer may publish only the runtime Wants
symlink under `/run/systemd/system/multi-user.target.wants/`; it must not enable
a boot link, create a target/daemon, or change global/product start limits.
Installation/loading/readback/start remain separate parent-owned actions. This
source slice performs none of them and does not claim that the edge is deployed.

Before escrow/acceptance, the source checks exact anchor/service names,
fragments, no drop-ins/client refs, active/running main PID and InvocationID,
NotifyAccess, preserved bounded FD store and existing rate-limit availability.
The anchor must remain active while any owned or unknown store entries remain.
No reset-failed, automatic restart, store clean or administrative fallback is
part of this implementation.

## Runtime finish: verified local scope

- The control entry takes inherited PID1 descriptors into close-once owned state
  before its first plan, grant or manager read. Rejected parsing/association closes only those
  owned local numbers, preserving the primary error and PID1's retained copies.
- Stop writes a full residual checkpoint retaining the original grant, accepted
  full manifest and original live host offer. Residual restart checks only that
  original Fence/OFD plus exact PID1 custody; it neither needs a fresh namespace,
  serving process, Docker RPC, holder nor the old temporary sockets/deadline.
- A durable `network-cleanup-pending` snapshot precedes the first named PID1
  subtraction. Restart accepts only the exact full pre-Dump or exact residual
  post-Dump: pre completes only the proven-unperformed named subtraction, post
  skips it. Partial/foreign Dump, incomplete journal or other unknown state
  refuses. Network/resource removal is never replayed. EMPTY and exact stopped
  Caddy config plus public 503 are still required before initial cleanup.
- Explicit holder abandon before preparation/capture/COMMIT authenticates the
  original network unit to the still-live original host producer. A virgin host
  may restore immediately; a partial node must first complete its existing
  same-live-engine `abort-return`. Its host waits finitely for the original
  network consumer. Only the authenticated exact restored OLD reply permits
  switching back to fresh Docker-live checks and then holder resource abandon.
  Lost restoration ACK, changed peer, downstream/candidate work or failed Docker
  readback is unknown/nonreplayable, never a post-COMMIT OLD fallback. The bound
  is the original network deadline and at most 120 seconds; no implicit thaw.

`test_ordinary_owner_runtime.py` exercises real journal/OFD sharing, inherited
FD disposal, pidfds, AF_UNIX framing, original live `Fence.restore`, the real
host dispatcher/peer association and the existing partial-node apply/return
consumer. Root UID/path authority, manager/cgroup/netns/Docker/HTTPS physical
facts are explicitly modeled. Recovery state/grant snapshots are fixtures,
not evidence of genuine producer-to-COMMIT acceptance. The first RED logs and
focused natural-exit results are in the separately owned wave109 evidence.
Legacy no-network selected paths and historical fixed pins remain unchanged.

The independently owned **new integration-test file** remains responsible for
the genuine original producer -> same Coordinator -> receiving owner -> natural
host/holder disposal -> terminal ACK positive, without seeded COMMIT/grant or a
loader substitute. These local runtime tests do not claim that acceptance or
physical/PID1 installation. No service/network/deployment action was performed.
