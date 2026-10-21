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
`212.119.42.100:3000`, `/health`; this is **not** a claim that existing HTTPS/Caddy
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
