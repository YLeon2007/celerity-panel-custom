# Fixed TEST physical resource constructor — source, not physical acceptance

`fresh_physical_exec.py` and `fresh_physical_watch.py` are separate fixed,
root-only, no-argument entries. Both load only the digest-pinned, root-owned
`/usr/local/libexec/c3-test-fresh-physical.py`, refuse other cgroups, and ignore
request/environment paths. Install intents are in `fresh_install_source_pack.py`;
this change installs/starts nothing. The unit sources have no boot activation.

## Implemented boundary

The classic unit's MainPID is the constructor and, via exec, the original fixed
preparer. The constructor registers this exact process with an external watchdog
in **another** unit/cgroup before scanning/copying the input. The watchdog owns a
pidfd, an exclusively created resource directory, and both newly bound sockets.
Existing paths are refused, never unlinked/adopted. It first joins the independently pinned private TEST network namespace, so the
control socket is CREATED in the same network namespace as its eventual
supervisor (required for the real `/proc/PID/net/unix` readiness predicate).
It passes one *bound but not listening* root-owned mode-0600 stream socket via
SCM_RIGHTS; the preparer alone
calls listen, preserving the existing SO_PEERCRED protocol.

The constructor actually invokes Linux unshare/setns/mount/pivot_root, copies and
rehashes the complete input into its own stage, creates the bootstrap policy with
only the immutable files map, provisions the private tmpfs state and launch.lock,
detaches the old root and makes the root and whole proc read-only. Only `/`,
`/proc`, `/state` remain mounted. It creates empty anonymous supervisor stdio,
remaps the control socket to fd3, closes all extra descriptors, drops all saved
UIDs/GIDs to 65531 and groups/capabilities/bounding/ambient sets to empty, sets NNP,
and execs the fixed preparer with isolated Python, bytecode disabled, LC_ALL=C.
It does not replace the preparer's real held-flock self-SIGSTOP or consumers.

The stage is fixed at `/var/lib/c3-test-fresh-resources` on the independently
provisioned disk filesystem, never selected by arguments or environment. The
read-only TEST capacity capture found a 233001194-byte payload versus only
206155776 bytes free in `/run`; `/var/lib` had 86427234304 bytes free. Moving the
stage avoids that confirmed tmpfs capacity blocker, not a physical capacity
acceptance for a future invocation. Socket/netns paths remain under `/run` and
private `/state` remains the bounded tmpfs above; no tmpfs is enlarged.

The service keeps `UMask=0077`. The constructor explicitly `fchmod`s the new
bootstrap policy to root-owned `0644` before identity drop: UID65531 can read,
but cannot write, the immutable files map; the final root remount is read-only.
The private **host root-control ancestor** stays `0700` and is outside the root
after pivot. Payload root and source directories retain the independently
accepted source-pack `0755` modes through `copytree`/copystat, including under
umask `0077`; these directory modes remain an independent input prerequisite.
The new `proc`, `state` and `.old-root` underlay directories are initially `0700`
under that umask. They do not require broadening: proc is covered by its root-owned
readable/searchable proc mount, state by the `mode=0700,uid=65531,gid=65531` tmpfs,
and `.old-root` is removed before drop. The lock is explicitly chowned to
UID/GID65531 with mode `0600`. Never chmod the outer control directory or weaken
`trusted_read` to make these paths reachable.

The external watcher bounds registration/construction by 120 seconds from its
start, then allows 600 seconds after observing the actual stopped held-lock
barrier for independent acceptance. Deadline, unexpected continuation, malformed
acceptance, source-map drift, process loss or SIGTERM/SIGINT before release
abandon through the owned pidfd. Cleanup requires observed process death and
matching resource/socket identities. Unknown death or replacement retains foreign
resources; cleanup uncertainty is refused. No SIGCONT, COMMIT, child start,
handback, inventory capture, GO, rollback, restart or retry exists here.

## Fixed independently supplied prerequisites (not generated)

- A separate root-owned, non-writable, no-symlink input tree at
  `/var/lib/c3-test-fresh-input/root`, copied from a **new independently staged**
  artifact, never an existing candidate modified in place. It contains exactly
  the final payload files, not the final policy, proc, state or `.old-root`.
  Runtime executables must retain their accepted executable modes. No xattrs,
  hardlinks, devices, suid/sgid or writable payload entries are supported.
- `/var/lib/c3-test-fresh-input/resource-plan.json`: closed JSON object with
  integer `version:1`, `context:"test.infograd.online"`, the complete independently
  pinned `files` SHA-256 map, and `networkNamespace:{device,inode}` with positive
  integer independently accepted nsfs identity. No policy self-hash is allowed.
- **Already independently provisioned private TEST network namespace** at
  `/run/netns/c3-test-fresh-classic`, with real literal TEST ingress/routes/data
  access. The constructor checks nsfs network type and exact device/inode and
  refuses the host network namespace. It joins it; it does **not** invent veths,
  routes, host firewall changes, host inventory or accepted network pins.
- Reviewed installed source/host Python/runtime closure, the exact two loaded
  units with no foreign drop-ins/restarts, private cgroup admission and UID65531
  exclusivity. These are not established by this offline source export.

## Independent final acceptance and signal-ownership handoff

All potential resumers/Coordinators MUST remain externally excluded throughout
preparation and until the watcher has **naturally exited with Result=success**.
Writing the acceptance input alone is not release. This exclusion is an external
acceptance prerequisite, not a newly weakened or synthesized consumer guard.
Otherwise deadline-kill versus concurrent SIGCONT is inherently racy: the old
consumer has no atomic preparation-lease arbitration protocol.

While the process is stopped, the independent operator finalizes only the policy
at `/var/lib/c3-test-fresh-resources/root/etc/c3-test-fresh-classic.json` through the
host staging alias. The sealed namespace sees the same replacement; its root
mount is already read-only. `files` must remain exactly the original map. The
operator installs the identical full policy at host `/etc/c3-test-fresh-classic.json`
and independently accepts all consumer predicates: PID/start, actual root/mount
IDs, routes, namespaces, mappings, descriptors, unit/cgroup and full source bytes.
The constructor/watchdog never derives these accepted inventory fields.

Only after that independent acceptance, its private external input
`/etc/c3-test-fresh-physical-acceptance.json` may contain this **closed** schema:
`version`, `context`, `supervisor:{pid,start}`, `generation`, `filesSha256`,
`policySha256`. Version/context must be the fixed values above; PID/start and
random generation must match this invocation's *unaccepted* `generation.json`;
files/policy digests use this module's sorted compact `encode` including its
trailing newline. Policy must still have the exact original `files` and TEST
context. Existing acceptance at watchdog startup is refused. No sample accepted
pins are supplied. The input is external authority, not an observation report
that this code promotes to GO.

Successful watcher termination relinquishes its preparation kill/cleanup rights
and leaves the process stopped, root and control socket intact. It never resumes
it. The separate independently accepted same-Coordinator flow can later perform
its original one-shot prepared resume, physical rechecks and handback. All old
strict deadlines and sticky unknown/no-replay rules remain unchanged.

A killed/crashed watchdog, lost terminal unit result, post-release cleanup error,
unexpected external resume or stale leftover generation is **not** recoverable
by re-running these helpers. Preserve unknown state for separate reviewed
recovery. These sources do not implement a crash-durable installer, cleanup after
accepted serving, or a race-free SIGCONT arbiter. Preparation must finish before
any all-five hold; release is not physical GO or TEST/PROD activation authority.

## Verification and remaining gates

`python3 -B -m unittest test_fresh_physical test_fresh_install_source_pack -v`
uses disposable unprivileged files/processes. Real evidence covers SCM_RIGHTS,
prebound fd3, anonymous stdio, extra-FD exclusion, original preparer SIGSTOP and
flock, exact separate acceptance, finite pidfd abandon, owned cleanup and source
pin export/refusal. Constructor copy/bootstrap/lock writes and `umask(0077)` are
real. The regression checks policy `0644`, preserved payload directory `0755`,
private outer ancestor `0700`, covered proc/state underlay `0700` and exact mounted
state/lock ownership contract **before the modeled identity drop**. This is
mode-bit and mount-call-order evidence, **not an actual dropped-UID65531 read**.
Privileged mount/namespace/cgroup/nsfs/UID/capability and installed-root facts are
explicitly **modeled** in that test. No fixture is physical or actual-application
evidence.

Unexercised: privileged end-to-end construction; physical network provisioning;
installed/loaded units; independent full inventory/acceptance; literal ingress,
actual application return and all-five handback. Source pack reports included
constructor/unit/lifecycle source but still `provisioningImplemented:false`,
`physicalAccepted:false`, `operationalGO:false`, and no resource policy. Existing
candidate/source-base pins remain immutable and are not silently repinned here;
a parent-owned fresh artifact/source-pack acceptance is still required.
