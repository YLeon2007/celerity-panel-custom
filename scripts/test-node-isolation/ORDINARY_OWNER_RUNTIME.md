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

## Verified scope and remaining finish-only work

Focused evidence exercises real files, journal flock/OFD sharing, AF_UNIX,
SCM_RIGHTS, pidfds, real legacy Coordinator/prepared supervisor/bridge consumers
and current fixed loaders. Cgroup/netns/Docker/PID1 facts are explicitly modeled;
no physical source acceptance is claimed. The joined ordinary path has **not**
yet been exercised from its genuine producer through the same Coordinator.

Finish-only ownership split:

1. `fresh_network_control.py`, `fresh_network.py`: take inherited descriptors
   into ownership before reading grant semantics; complete residual-only restart
   after network removal and exact pending cleanup pre/post reconciliation.
2. `shared_host.py`, `fresh_network_control.py`, `fresh_network.py`: close and
   exercise authenticated finite known-OLD restoration -> Docker-live -> holder
   abandon. Current fresh succession is not an OLD fallback.
3. A separate new focused integration-test file can independently exercise the
   genuine original producer -> same Coordinator -> receiving owner -> natural
   host/holder disposal, expiry-independent checks and terminal ACK, with only
   privileged/PID1 seams modeled. No seeded COMMIT/grant or loader substitute
   qualifies. Existing source ownership need not overlap this test writer.

These are remaining implementation/acceptance gaps, not new platform research.
Do not describe this checkpoint as full ordinary-owner GO.
