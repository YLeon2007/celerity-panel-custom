# Ordinary TEST execution after durable owner enrollment

Source-only implementation and disposable local evidence, **not live physical
acceptance, deployment permission or PROD activation**.

## Two trusted root compositions

`createL2tpRootLifecycle().enrollTestOwnersAfterDatabase()` selects the internal
`ownerEnrollment: true` composition. Only this explicit maintenance entry opens
`testDurableOriginals` / the fixed `owner-channel`. Its existing all-five retained
capture/OFD path remains unchanged: actual durable capture precedes the first
candidate database mutation and spans public `initializeClassic → adopt →
preEnroll`, final assertions and final durable readback. This root cannot start
workers or repeat enrollment.

Ordinary `index.js → startAfterDatabase()` uses `ownerEnrollment: false` (the
default). This is a trusted composition argument, not a request field,
environment flag, missing-pin detector or persisted enrollment receipt. It
creates the existing operational physical controller with five ordinary pinned
read-only attestor channels. It never opens the capture adapter, retries capture,
rewrites a bundle, seeds an owner or imports a cached observation/capability.
Missing original pins refuse rather than selecting maintenance automatically.

After successful enrollment the operator must let the foreground capture
coordinator finish and its temporary capture-holder OFDs close **before** starting
an ordinary backend. The independently held node recovery SSH channels, kernel
exclusion and shared-host freezer remain continuously held across that transition
and the complete runtime. Closing capture/observer channels never releases those
external guards. An overlapping capture holder causes ordinary attestation to
refuse; there is no lock retry, delayed GO or inference from a missing lock.

## Fresh authority, including after dispatch

Every ordinary fresh all-five observation calls the installed attestor under its
ordinary outer observation lock. It verifies the existing private
`originals/originals.json` against `/etc/c3-test-node-originals.json`: exact
identity/plan/boot/guard, canonical captured bundle, accepted-pins hash, all
profile file metadata and actual secret bytes, service snapshots and runtime
snapshot hashes. The dual-profile relay requires **both** captured profiles.
Missing/partial/restoring bundles refuse. Only hashes and original service states
are projected; secret bytes remain private. Current candidate config/runtime may
legitimately differ from the originals and are never recaptured.

Fresh before/after actual Engine checks continue to validate exclusion and the
live recovery protocols. Each observation verifies the same outer lock inode;
the existing dispatcher obtains that same mutex for each real command. External
kernel/recovery holds, not a historical observation or a permanently retained
observation flock, sustain the scope between reads and dispatches.

The ordinary root passes the actual controller into the unchanged private
lifecycle, public connected binding store, default worker and default typed
executor. Provisioning remains after exact claim/locks. Subsequent operations
use persisted settlement/binding predecessors plus independently read current
runner head and the exact prior close/status receipt. The observer does not
create runner journals or relax their unfinished-command fences. Ordinary checks
allow existing dispatch history; the capture-only `dispatchCount === 0` rule is
not repurposed as a post-enrollment authority.

All-five backup or guard loss permanently poisons the controller. Repairing the
file cannot resurrect an escaped checker or that backend's capability. No SFTP,
shell bootstrap, receipt-only fallback, owner rewrite, release, restore or thaw
path is added.

## Executed local evidence

`topologyTestHostBinding.test.js` has a distinct postcapture assembly. It runs real
scratch replica-set Mongo, the explicit root owner entry, real public owner and
enrollment models/store, then a **new ordinary default root/controller** with the
actual installed Python observer. No raw owner row or simulated proof wrapper is
used on that path. It completes two serial generations through actual
`Engine.dispatch` (same isolation journal/outer mutex as capture), the real V2
runner and nonempty disposable Xray user RPC, with exact predecessor links,
close/status, unchanged original bundles and normal Mongo settlement. Removing a
nonselected node's original then blocks the default worker before **any** Mongo
command; repair remains refused. A separate post-commit guard-loss case verifies
zero further dispatch and retained exact lock/admission ownership.

The capture/observer/dispatcher filesystem and protocol execution, public Mongo
transactions and runner behavior are real. Physical identity, UID/root metadata,
kernel/systemd/SSH/recovery/freezer facts remain explicitly **SIMULATED** local
adapters. No claim of live external physical exclusion or client traffic follows.
Existing production, serving rollback, coordinated restoration and shared-host
handback gates remain separate and unchanged.
