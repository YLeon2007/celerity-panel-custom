# Fresh classic exec SOURCE primitive — dormant, not physical activation

This slice adds a real one-shot exec and serving primitive, not another
ordinary-Node refusal characterization. **It does not authorize active TEST.**
No physical resource, service, namespace, route, ingress, credential, deployment,
freezer or owner was provisioned or changed. PROD and JS/schema are untouched.

## Construction

`fresh_classic_launch.py` adds two source entry points:

- `FreshLaunch` accepts only the actual already-live `Coordinator`, rechecks all
  five held node peers, validates the same ownership-generation contract, and
  writes a distinct durable all-five COMMIT with activation set
  `['fresh-classic-process']`. It never calls the existing classic preflight or
  thaw; the old sealed predicate and its existing-classic activation remain
  byte-for-byte unchanged. The exact original peer identities, generation,
  restoration intent, config, accepted fresh policy and supervisor are bound in
  that COMMIT. File/directory fsync and readback precede exec dispatch.
- `supervise` is the separately supervised one-shot process. Its installed
  finite grammar is `supervisor`, with independently prebound control socket
  fd3. It accepts one root peer, receives one root-owned mode-0600 COMMIT FD via
  SCM_RIGHTS, checks the exact current root peer PID/start and supervisor
  PID/start, and rejects old activation sets. Its private journal and real flock
  precede one actual `Popen` of fixed Node and app paths. It never retries exec.
  New anonymous regular-file stdio replaces inherited stdio; all other child
  FDs close. There is no shell, Docker, containerd, updater or old-Node fallback.

The operational policy is intentionally restrictive and fixed: TEST context,
`/runtime/node /app/index.js`, `/etc/classic.json`, fixed two-key environment,
UID/GID 65531, empty supplementary groups, all five capability sets zero and
NNP, and `/system.slice/c3-test-fresh-classic.service`. Separate accepted
mount/net/ipc/uts namespaces, root inode/device, exact mount and route pins,
whole symlink-free executable/interpreter/library/application/settings root
manifest, file-backed mapping identities and inherited descriptor pins are
required. Only read-only nodev/nosuid root and proc plus private nodev/nosuid/
noexec tmpfs `/state` are supported. No host cgroup/control socket or original
Node root/cwd/FD/map is adopted. Policy/source/unit and loaded supervisor state
are checked; a service-file receipt alone does not establish Restart=no.

Serving evidence is actual PID/start/cgroup, PID-owned listening socket inode,
and an HTTP response with an established reverse-tuple socket actually owned
by that PID while the keepalive connection remains open. A digest or readiness
reply alone is insufficient. The fixed source ingress is direct TEST
`212.119.42.100:3000`, `/classic-ready`; this is **not** a claim that existing HTTPS/Caddy
TEST ingress has been restored. A separately accepted direct mapping must be
physically established before this construction can be used. The source does
not create or repair it.

The root launch channel and all five coordinator peers complete finitely. A
separate supervisor stays alive waiting for the sole serving child; it does not
restart it and is not tied to the finite controller's stdio/lifetime.

## Deliberately dormant integration / exact remaining gates

There is no new owner-bridge command, JS lifecycle switch, installer, or existing
`activate-classic` extension. `FreshLaunch` is an internal trusted-root source
composition, not an exposed active cutover. Existing coordinator/guard source is
unchanged. Local tests compose it with actual five-node protocol/OFD holders;
physical root/kernel/SSH/systemd facts are explicitly modeled.

`INDEPENDENT_TEST_CLASSIC_LAUNCH_RESOURCE_BOUNDARY` now has a concrete source
policy and actual exec path, but these physical and integration gates remain:

1. Independently construct and accept a fresh symlink-free root containing the
   *real* classic application, all libraries/interpreters/dependencies, settings,
   Python launcher and pinned coordinator source. No running old process is an
   artifact or resource source. This task intentionally supplies no live pins.
2. Independently provision and accept the dedicated supervisor, UID, anonymous
   stdio, prebound root-owned socket, private journal/lock tmpfs, namespaces,
   cgroup and direct TEST ingress. Source installs none of these.
3. Exact-source review and physical validation of the restrictive inventory
   reader are still required. Its full privileged policy has no local positive
   kernel/root installation proof. Existing old host/node allowlists have not
   been widened to admit this new supervisor/service. The operational adapter
   and existing HTTP/JS owner bridge must remain disabled until a reviewed
   distinct activation composition proves those same-held physical allowlists.
4. Real classic app settings semantics and serving have not been validated here:
   positive tests run generated Node fixture source, not the full panel app or
   its databases. The existing `index.js` is not modified to consume the fixed
   C3_SETTINGS test convention. A compatible independently accepted real bundle
   must establish settings/environment compatibility or this policy must be
   revised and reviewed; do not call fixture serving real classic readiness.

These are not inferred from missing deployed pins, nor fabricated isolation.
The source exec primitive works locally; safe operational classic return is
**not claimed complete**. No night maintenance hold or user-dependent recovery
is initiated.

## Failure and replay

Before COMMIT, source/settings/identity/closure/generation/old-permit refusal
has zero exec and no launch attempt. Unknown COMMIT fsync is
`COMMIT_UNKNOWN_NO_ACTIVATION`. After known COMMIT, timeout, EOF, fsync failure,
supervisor SIGKILL or cleanup failure is `COMMITTED_ACTIVATION_UNKNOWN`.
Actual execution may have happened: never retry/replay, refreeze, rollback,
reopen candidate or claim retained classic exclusion. Root COMMIT/attempt files,
private supervisor journal/lock and one-shot live object remain sticky. There
is no recovery command and no automatic repair/adoption. Test-only disposal
kills disposable children and is not implementation recovery.

## Executed local evidence

`test_fresh_classic_launch.py` exercises real Node exec, real source/settings
hash reads, real HTTP, `/proc` PID/start/cgroup and socket ownership, real UDS /
SCM_RIGHTS, actual COMMIT/attempt journals and fsync, real five-node subprocess
protocols and original/runner flocks. It covers source/settings and malformed
policy/generation/old-permit refusal, independent serving lifetime after finite
handoff completion, and actual-postexec EOF/timeout/fsync/SIGKILL/cleanup with
one recorded execution and forbidden second invocation.

Only UID/root/kernel/resource/namespace/cgroup/ingress placement and SSH/systemd
inventory are simulated; executable invocation and success are not. Existing
irreversible and coordinator regression tests are also run. RED and final GREEN
logs and hashes are recorded in the external `fresh-launch/result.json`.

## Controller-only accepted-netns observation

This is a later **source-only** correction to the reachable `FreshLaunch._run`
caller, not an installation, publisher or operator architecture decision. The
reviewed **9e full pack remains frozen**: changed launcher bytes require a NEW,
later independently reviewed artifact and installation policy. No profile,
accepted pin, resource-plan producer or previous candidate is updated here.

Before either prepared SIGCONT or COMMIT, the original host-side controller
retains the fixed `/run/netns/c3-test-fresh-classic` FD, opened through a trusted
parent with `O_NOFOLLOW|O_CLOEXEC`. It compares `fstat` with the independently
accepted positive exact-int `networkNamespace.device/inode` in the trusted fixed
`/var/lib/c3-test-fresh-input/resource-plan.json`; bool/float pins do not qualify.
The plan's files must equal the accepted policy closure. `NS_GET_NSTYPE` must be
`CLONE_NEWNET`, the identity must be non-host, and accepted policy net plus live
accepted supervisor PID/start/net must agree. No scan produces acceptance. Raw
policy/plan bytes and inode metadata, retained FD, fixed pathname identity and
supervisor pidfd are checked before/after observation and final confirmation.
In-memory policy drift is also refusal, not a new acceptance.

Only the root-controller observation is replaced by a fixed probe-only fork.
There is no callback, executable/path/command dispatcher or new CLI. Before any
work, it closes every inherited FD except its exact result writer, retained net
FD and supervisor/serving liveness pidfds, including inherited stdio, SSH/owner/
lease/lock/hold descriptors. It rechecks root/host PID/mount view, joins ONLY NET,
and verifies membership and unchanged non-net namespaces BEFORE creating a new
TCP connection. It then runs the existing unchanged literal listener-inode,
PID/start/cgroup, owned reverse ESTABLISHED tuple and keepalive HTTP-body proof.
It neither checks a copied Coordinator nor acts as network holder, signals a
supervisor, dispatches exec, writes source acceptance, or enters mount/PID/user
namespaces. The original parent PID/start, five original channels, COMMIT origin,
path UDS and SCM_RIGHTS dispatch remain host-side. Supervisor `Platform.observe`
is still direct in its already-fresh namespace: no added root/CAP or resource-plan
lookup.

Probe IPC is at most 4096 bytes. EOF, malformed/oversize result, nonzero exit,
timeout, inherited/owned close error and reap uncertainty refuse. IO reserves a
small portion of the EXISTING minimum wire/Coordinator/all-five deadline for
owned-child kill/reap; a child timer shares that budget. No deadline is extended.
A stuck uninterruptible kernel task can yield REAP_UNKNOWN; no unbounded wait or
success is inferred. Filesystem/proc/close/fsync syscall return latency is not a
hard real-time guarantee. Strict startup still begins BEFORE Popen with `<deadline`
and 3 seconds; prepared LISTEN still has 3 seconds, accept still 5 seconds. Wire,
lease, durable COMMIT/readback, fsync and one-shot rules are unchanged.

Any postexec failure stays `COMMITTED_ACTIVATION_UNKNOWN`, never retry, rollback
or a success reply. Confirmation is checked on both sides of durable readback;
retained-FD/lifetime closes must succeed before handoff. On later failure the
controller latches unconfirmed and attempts to persist an unknown journal. A
failed fsync may leave the earlier on-disk phase visible: that phase is never
terminal authority and cannot override the unknown exception/one-shot state.

`test_controller_namespace_probe.py` exercises the actual same-held prepared
caller with real stopped PID, five fixture channels, UDS, SCM_RIGHTS, fork/pipe,
FD disposal, reaping, HTTP and proc socket ownership. Namespace topology, nsfs,
CAP/root/UID and cgroup placement are explicitly MODELED; tests perform no setns,
mount, Docker, SSH, DNS, live database, route/firewall or service action. Existing
fixture updates only publish the newly mandatory independently modeled plan and
real supervisor PID before launch, and supply the fixture-gated kernel boundary;
no previous assertion or production timeout is weakened. Owner-bridge and
strict-deadline regressions are separate named tests, not physical evidence.
The owner-bridge fixture's operator thread triggers Python's fork-from-threaded-
process DeprecationWarning; its real fork/protocol passes, but this is not a
claim of general multithreaded fork safety or hard real-time syscall completion.

Independent review is required before parent integration. Real nsfs/setns/CAP,
privileged fixed literal ingress, independent installation/runtime/resource/lease
publishers and exclusion, all-five operational acceptance, remote SSH/DNS and
public ingress remain unexercised. **strict 3s repeatability is NOT proven**.
No physical acceptance, active TEST/PROD mission or PROD GO is claimed.

## Bounded review corrections (source only)

Five accepted source blockers are addressed without changing existing sealed
thaw/coordinator files or widening any operational gate:

- The controller compares the independently accepted `inventory.coordinatorSha256`
  with canonical `held.config` before connection/COMMIT/attempt. The supervisor
  independently repeats the config-pin check, including in the simulated positive
  fixture; that fixture now supplies a real canonical config digest.
- UID, GID and ingress port require exact integer scalars, not floats or booleans.
  The directly consumed policy/inventory/proof containers and digest types are
  checked before use; the inherited ownership proof protocol is not redesigned.
- Loaded systemd properties require both `Restart=no` and an empty
  `RestartForceExitStatus`. A pinned unit containing a force-restart override is
  insufficient even if its ordinary restart policy says no.
- COMMIT reception collects rights from every ancillary record before semantic
  rejection. All collected descriptors are disposed despite earlier close errors;
  disposal preserves a primary refusal rather than replacing its classification.
- Root admission opens the actual retained proc root magic link with
  `O_PATH|O_DIRECTORY|O_CLOEXEC`, obtains `fstat` and its owned `fdinfo` mount ID,
  and keeps that FD open through comparison with the unique checked `/` mount
  record. Device/inode matching is still necessary but is never a mount-ID
  fallback. The same check runs before `prepared` and again before exec.
  Its owned FD is disposed on stat/read/parse/check failures; a cleanup error
  cannot replace the primary error. There is no extra inherited-cwd requirement:
  the child explicitly replaces cwd.

The bounded correction run uses only `python3 -B -m unittest -v
 test_fresh_classic_launch`, with bytecode disabled and TMPDIR set to the Hermes
scratch directory, and exits naturally. It includes the existing four fresh tests
and eight regression tests (12 total), without a full/heavy/Mongo/privileged
suite. Actual socketpair `SO_PASSCRED` delivers credentials before received rights;
multiple-rights records and close-error disposal also have focused coverage.
Ordinary scratch directories and proc magic links exercise real O_PATH/fstat/
fdinfo and FD disposal; root mount topology and physical flags remain modeled.
A same-device/inode different-mount-ID fixture refuses before COMMIT/exec;
post-prepared mount-ID drift retains committed-unknown/no-replay semantics.
No mount, namespace, service or live host operation was performed.

Initial RED/FAIL logs are preserved, not overwritten by GREEN logs. The first
config-pin probe exposed an asynchronous fixture-policy mismatch; a consistent
both-peer fixture and in-memory baseline controller replay additionally reproduce
actual irreversible COMMIT before config refusal. Root RED initially demonstrates
the absent retained-root enforcement method; subsequent real-FD and assembled
protocol assertions exercise its positive, alias, failure-cleanup and drift paths.
The unchanged review probe is characterization, not a green regression test.
Exact source commit/tree/parent, log hashes, closed IDs, evidence qualifications
and unresolved gates are in external `fresh-launch/fix-result.json`.

These are source fixes, **not operational closure**. Real application/settings
compatibility, independently accepted resources/pins/loaded service, physical
acceptance, direct TEST mapping, same-held allowlists and distinct trusted-root
owner/HTTP-JS bridge composition remain separately unresolved.
