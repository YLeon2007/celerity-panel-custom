# TEST all-five durable capture — same-holder source composition

**PARTIAL / NOT deployment, live authority or combined handback approval.**
The capture/observer lock mismatch is closed in the bounded source enrollment
path. The default capture-bound controller now reads the actual installed
observer inside each capture holder's retained outer OFD, rather than launching
a second observer that would contend for that lock. External SSH, UID, physical,
kernel, systemd and shared-host facts in source fixtures remain **simulated**.
No restoration, thaw, ownership release or dispatch reopening is introduced.

## Same-holder contract

* The installed helper still has only three fixed verbs: `capture`, `node-hold`,
  `owner-channel`. Five independent foreground SSH channels acquire all five
  real outer flocks **before the first** actual `NodeOriginals.capture()` call.
  Its publication/fsync/no-overwrite/readback implementation is unchanged.
  Both profiles on `104.143.201.72` are captured. No runner fence files are
  created to make empty enrollment appear valid.
* Every node's separately accepted `files` pins now **require `attestor`**, for
  `/usr/local/libexec/c3-test-physical-attestor`. Production loads exactly those
  verified bytes, then rechecks the installed bytes on every node request.
  No current observation or freshly produced bundle may supply acceptance pins.
* `physical_attestor.attest(..., held=CaptureHold)` executes the existing actual
  `observe(engine, module, shared, predecessor)` with live holder checks before
  and after it. The holder must belong to this exact in-process engine. It is
  never a request-provided FD, boolean, historical observation or lock receipt.
  No unlock/relock is performed. A separate `serve` process still attempts its
  normal exclusive flock and **correctly refuses** against a retained holder.
* Finite `observe` / `observe-all` requests carry fresh nonce/sequence checks
  through NodeServer, coordinator, exact-PID/start/UID root-peer UDS and the app
  pipe. Each `observe-all` freshly invokes the actual observer on all five nodes;
  the selected predecessor goes only to the selected node. Bundle/current byte,
  xattr, service, guard, operator, source and lock-inode checks remain active.
  Idle node/coordinator loops also recheck retained authority. No historical
  observation is used to answer a new assertion.
* Capture uses its own fixed **8-MiB** framed codec for the five observations
  (each profile can carry two 512-KiB original blobs). It streams one bounded
  frame in bounded fragments, checks deadlines, rejects duplicate/pipelined
  frames and EOF, and never repeats a logical operation. The separately owned
  restoration codec is unchanged.
* The default root factory opens the installed `owner-channel` **before its
  first** physical/controller/lifecycle assertion and keeps it through public
  enrollment, the lifecycle's final `assertHeld`, the controller's final
  `assertHeld` and the adapter's final durable check. No separate observer SSH
  session or cached-observer fallback is used in this capture-bound scope.
  The default path is deliberately one-shot maintenance; subsequent execution,
  DB settlement and post-dispatch authority are not authorized by capture.
* The complete application owner challenge must equal the independently fixed
  root challenge before the first candidate DB write. This remains independent
  of captured state. Intent/bundle/`.next` uncertainty, channel EOF, guard/source/
  lock drift, nonce error or timeout revoke the scope; repairing bytes cannot
  resurrect it. Cleanup never restores originals, unmasks, thaws or hands back.

## Independent operator acceptance — never auto-published

No installer or acceptance producer is supplied. A later authorized installation
still requires independently accepted:

1. Root-owned isolation plans, live recovery/shared-host guards, exact fixed five
   endpoints/profiles, machine IDs and raw ed25519 wire-key digests.
2. Existing `/etc/c3-test-node-originals.json` pins for all original files,
   metadata, services and runtime snapshots, including both profiles on `.72`.
3. `/etc/c3-test-coordinated-capture.json` on coordinator and nodes, with exactly
   the schema enforced by `validate`: context, 80–120 second lifetime, root
   origin machine/boot/cgroup, private operator-key and protocol-source hashes,
   `self/originals/isolation/accepted/attestor` source pins per node (plus
   `shared/freezer` on the shared node), raw canonical keys, guards and complete
   `ownerChallenge`. A successful observation cannot replace these pins.
4. App `/etc/celerity/topology-test-capture.json` with exactly
   `{version:1, helperSha256:<independently accepted installed helper hash>}`
   and the independent `/etc/celerity/topology-test-physical.json` pins.
5. Private state/locks/key paths and independent fresh operator SSH access.
   Sticky intent/socket/known-host/bundle state needs explicit reconciliation;
   it is never automatically removed or accepted after restart.

Restoration pins/bundle approval, DB settlement, global/owner/shared-host
handback, `SHARED_HANDBACK_UNAVAILABLE`, thaw, live TEST and PROD activation stay
outside this slice. A passing source enrollment does not authorize them.

## Source evidence and reproduction

The focused Python tests exercise actual installed observer `serve` and
`observe`, real Engine journal/read/assert logic, actual filesystem snapshots,
fsync, flocks and child pipes. The independent UID/SSH/kernel/systemd/physical
read adapters are explicitly simulated. Controls cover the separate-observer
lock conflict, same-holder observations, EOF, loss, original drift, missing
last guard, replay and original-publication fsync failure.

The optional Mongo test in `testDurableOriginals.test.js` exercises the actual
default root controller → root UDS → actual observer/Engine/capture composition
and the actual owner entry → public `initializeClassic → adopt → preEnroll`
for all five nodes using public schemas and the real binding store. It checks
five persisted owners/enrollments and exact identities/snapshots/generations;
each candidate DB mutation also probes all five real flocks with an independent
competitor. Guard loss before entry causes **zero candidate DB commands**.
No raw-seeded adopted owners or fabricated observation replies are used.
Mongo listens only on a unique loopback port beneath the approved scratch root;
its exact scratch database/process/files are cleaned and absence read back.

Run serially only when the parent releases the heavy-test budget:

```sh
(cd scripts/test-node-isolation && PYTHONDONTWRITEBYTECODE=1 \
  HERMES_HEAVY_TMP_ROOT=/home/leon/.hermes/cache/scratch/heavy \
  ~/.local/bin/hermes-heavy python3 -m unittest -v test_coordinated_capture)
NODE_PATH=/home/leon/celerity-panel-custom/node_modules \
C3_MONGOD=/home/leon/celerity-prod-release-20261019/toolchain/mongodb-linux-x86_64-debian12-8.0.16/bin/mongod \
HERMES_HEAVY_TMP_ROOT=/home/leon/.hermes/cache/scratch/heavy \
  ~/.local/bin/hermes-heavy node --test --test-concurrency=1 \
  src/modules/relay-l2tp/tests/testDurableOriginals.test.js
```

Evidence is outside the source tree under
`/home/leon/celerity-prod-release-20261019/evidence-durable-capture-composition-20261020`.
The manifest identifies the exact source HEAD/tree and distinguishes completed
acceptance runs from earlier failing/intermediate runs. No real Xray, fixed-port
fixtures, live SSH, root installation, deployment or push is part of this slice.
