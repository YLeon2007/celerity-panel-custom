# TEST all-five durable capture — bounded partial implementation

**NOT default-owner operational closure. NOT installation or live authorization.**
The capture protocol below is implemented and exercised with real local files,
fsync, flock, subprocess pipes and a root-peer-shaped UDS (UID/SSH/kernel/systemd
facts are explicitly simulated). The normal installed physical observer still
cannot coexist with this hold. The default owner command therefore remains
fail-closed before candidate database writes. No restoration/handback capability
is introduced.

## Exact unresolved composition dependency

`physical_attestor.py:serve` opens `/var/lib/c3-test-node-isolation/lock` and takes
an exclusive nonblocking flock for **each** observation. `CaptureHold` must keep
that same outer lock's open-file description across actual capture, all owner
writes and awaited cleanup. A separate observer SSH process cannot reacquire it.
`TopologyExecutionAuthorityLifecycle.run` and the controller request physical
observations before entering `withCapturedTestOwnerEnrollment`, and around every
awaited public operation. Thus adding the finite capture hook alone does **not**
make the ordinary default enrollment operational.

The test
`test_installed_observer_cannot_reacquire_capture_outer_lock_known_default_blocker`
executes the real observer `serve` against the actual capture-held file and
requires `BlockingIOError`, no observation and no success output. This is a
known-negative acceptance boundary, not a passing deployment criterion.

The smallest remaining dependency is a reviewed finite observation operation
inside the **same capture-holder process/OFD**, carrying the actual installed
physical observer's current observations and accepted helper pins to the default
controller for the entire outer lifecycle (including its final checks). It must
not unlock/relock, substitute cached observations, or let a second process claim
the lock. That protocol/default observation composition is **not implemented** in
this bounded slice. No automatic fallback weakens the present refusal.

## Implemented source contract

* `scripts/test-node-isolation/coordinated_capture.py` has only three installed
  fixed verbs: `capture`, `node-hold`, `owner-channel`. Root only, Python isolated
  mode, no environment-selected roots/helpers/configs or arbitrary operation.
* A separately started foreground `capture` coordinator opens **five independent
  fresh** fixed SSH channels, not multiplexed connections or historical receipts.
  All five helpers acquire their actual outer lock and freshly check accepted
  node/boot/machine/key/plan/maintenance/recovery-guard/operator-session identities
  **before the first bundle is published on any node**.
* Only then does each held helper call the actual `NodeOriginals.capture()`.
  Its original write/fsync/no-overwrite publication/readback executes unchanged.
  The adapter reuses the already-held outer OFD instead of acquiring a second
  flock. Both `xray-main` and `xray-bridge` are captured on `104.143.201.72`.
  No runner locks or journals are created: initial public enrollment requires
  them absent, and outer exclusion is the existing dispatch authority.
* Fresh checks compare exact stored bundle bytes, accepted originals metadata,
  config/unit bytes/xattrs, services and supported runtime snapshots, plus live
  guards, current operator session and exact lock inode. Shared-node checks bind
  the accepted host owner/guard/backend identity through the existing shared
  freezer/guard readback. No new freezer, restore or release implementation.
* Coordinator intent is fsynced **before channel launch**; in-flight node and
  captured progress are durably retained. Any partial capture, unknown startup,
  unfinished `.next`, existing bundle/intent, EOF, timeout, nonce/sequence error,
  changed pin/lock/guard or uncertain acceptance refuses. There is no retry,
  cleanup, adoption of old bundles, thaw or dispatch admission reopen.
* Only after all five fresh checks does the coordinator offer its fixed private
  UDS. `CaptureChannel` checks SO_PEERCRED against the exact coordinator
  PID/start/UID and immutable held intent; the server pins the peer PID/start and
  rotates challenges. Both ends revoke on failure. `check()` returns no receipt
  or boolean. A historical `captured-held` journal is insufficient without the
  live root process/socket and all five current channels.
* `owner-channel` compares the complete application owner challenge against the
  separately accepted root configuration and services bounded nonce/sequence
  checks. The JS adapter launches only `/usr/bin/python3 -I
  /usr/local/libexec/c3-test-coordinated-capture.py owner-channel`, verifies its
  independently accepted installed-source hash, keeps it through the awaited
  callback, and revokes escaped checkers. The root factory now selects this
  finite hook; it still uses the separate observer, so the blocker above remains.

## Independent operator acceptance — never auto-published

No installer or pin acceptance command is provided. Before any authorized later
installation/run, the operator must independently provision/review:

1. Existing root-owned node isolation plans and held recovery/shared-host guards;
   exact five fixed node/endpoint/profile identities, distinct machine IDs and
   raw SSH ed25519 wire-key hashes (including accepted shared aliases).
2. Existing `/etc/c3-test-node-originals.json` on every node: **all originals**
   file metadata/digests, exact service states and runtime snapshot digests,
   reviewed isolation/Xray source hashes. On `.72` this includes both profiles.
   These accepted values must precede capture. Never derive acceptance from the
   bundle produced by this helper or mutable database node documents.
3. `/etc/c3-test-coordinated-capture.json` on coordinator and nodes: exact schema
   enforced by `validate`, fixed context, finite lifetime (80–120 seconds), root
   origin machine/boot/cgroup, private operator-key hash, protocol-source hash,
   five nodes' original/isolation/self/accepted-file hashes (plus shared/freezer
   hashes on the shared node), raw canonical ed25519 public keys, guards and
   exact complete `ownerChallenge`. No captured response can replace these pins.
4. `/etc/celerity/topology-test-capture.json` on the app host with exactly
   `{version:1, helperSha256:<independently accepted installed source hash>}`.
   All source/config/key paths are fixed and descriptor-walked root-controlled;
   private app trust files and installed app helper must not be world-accessible.
5. Fixed private state directories/locks/operator-key paths, independent fresh
   operator SSH access and matching origin cgroup. Socket/intent/known-host files
   left by attempts require explicit reconciliation; they are never auto-deleted.

Restoration accepted pins/bundle approval, DB settlement, owner handback,
`SHARED_HANDBACK_UNAVAILABLE`, thaw and live TEST/PROD activation stay outside this
slice. No source test or successful capture authorizes them.

## Reproduce local source checks

From the repository root, use the approved scratch TMPDIR and serial scope:

```sh
NODE_PATH=/home/leon/celerity-panel-custom/node_modules \
  ~/.local/bin/hermes-heavy node --test --test-concurrency=1 \
  src/modules/relay-l2tp/tests/testDurableOriginals.test.js \
  src/modules/relay-l2tp/tests/testPhysicalController.test.js \
  scripts/test-topology-owner.test.js scripts/test-topology-owner-authority.test.js
(cd scripts/test-node-isolation && PYTHONDONTWRITEBYTECODE=1 \
  ~/.local/bin/hermes-heavy python3 -m unittest -v test_coordinated_capture)
```

The new JS positive uses the real default factory, actual owner entry and actual
capture UDS, **with a simulated independent physical observer**; it intentionally
stops at the first public model boundary. It is not real-Mongo five-node
initialize/adopt/preEnroll evidence and not the installed-observer positive.
The older optional actual-Mongo owner fixture remains a separate parent serial
check (`C3_MONGOD=/home/leon/celerity-prod-release-20261019/toolchain/mongodb-linux-x86_64-debian12-8.0.16/bin/mongod`).
Do not run its heavy Mongo/Xray fixtures concurrently with the parent.
