# Bounded shared TEST-panel / LocalXray isolation

**Source-only; not installed, not live-verified, not application authority.**

For the subsequent one-way candidate/dispatch closure and its explicit unknown
remote-effect boundary, see [CLOSURE.md](CLOSURE.md). No handback is authorized.
The dedicated validator and its four-node allowlist remain separate and unchanged.
The normal `c3-test-node-isolation` entry point selects this mode only with an
explicit `mode: "shared-test"` plan and the trusted fixed shared module installed.

## Exact boundary

Only node `6ab189dc63913ebd4a917399`, literal endpoint `212.119.42.100`,
context `test.infograd.online`, profile `xray-main`, machine
`7fa266f995fe4aa69e96cf7d01359e34` is supported. A hostname from a database
record is not silently resolved into accepted endpoint authority.

A shared plan is the dedicated plan shape plus:

```text
mode: shared-test
hostHold:
  owner: independently selected canonical UUID
  freezerSha256: SHA256 of independently reviewed installed freezer bytes
  expected: complete independently accepted panel-host-freezer capture object
```

There is deliberately no ready-to-apply plan or accepted live inventory in this
commit. Historical rollout diagnostics are not accepted plans. The full host
capture must be independently reviewed, including images, payload identities,
mount/capability exclusions, runtime/shims, supervisor policy and cgroup inodes.
Two fresh exact captures must equal that object before the host hold starts.

The plan must preserve exact native `/system.slice/xray.service` and
`/system.slice/xl2tpd.service` groups. Existing policy forbids isolating Xray,
PPP/L2TP/IPsec/network units. Other actually required native survivor units still
need independently reviewed keep entries; role names are not inventory.
Do not keep Docker/containerd service roots in the plan: those are frozen roots,
not ordinary trusted native survivors. The shared helper never stops/restarts
native data-plane units and never edits their config or credentials.

## Parent-only installation and use (not executed here)

Keep the dedicated toolkit's independent 2222 accounts, keys, effective sshd
policy, runtime-directory preservation, original-unit pins and backup requirements.
Before installing anything, snapshot every changed path/account as described in
[README.md](README.md). In addition stage root-owned, non-writable files:

* `shared_host.py` → `/usr/local/libexec/c3-test-shared-host.py`;
* independently reviewed `../panel-host-freezer.py` →
  `/usr/local/libexec/c3-panel-host-freezer.py`, with its exact accepted SHA256 in
  `hostHold.freezerSha256`;
* updated `isolation.py` → the existing fixed
  `/usr/local/libexec/c3-test-node-isolation` entry point.

Do not install a historical freezer to bypass a separately reviewed accepted-work
fix. The shared helper adds its own init-lineage refusal, but is not a substitute
for reviewing/testing the complete freezer after that fix is integrated.
No `PYTHONPATH`, arbitrary import/root path, shell or Docker API is CLI-selectable.

Using independent fresh operator SSH connections through port 2222:

1. Start the existing foreground `guard` with its real bidirectional recovery
   echo client. Leave this independent recovery channel running.
2. In a distinct operator connection run `sudo -n
   /usr/local/libexec/c3-test-node-isolation host-hold`. Keep stdin open; no stdin
   control commands exist. This foreground process owns the real freezer Fence,
   its exclusive journal and the `host.sock` supervisor socket.
3. From another independent operator connection run `apply`. It refuses before
   mask/stop mutations unless the real host hold and recovery are currently valid.
4. Authenticate **again after drain** and run `confirm-access`. Earlier/pooled
   connections and connections from the drain tick cannot satisfy this boundary.
5. `status` and finite forced V2 `dispatch` require both live guards and current
   exclusions. Bootstrap, SFTP and generic shell remain forbidden.

The recovery guard, host-hold channel and fresh confirmation login are distinct.
Do not detach them or run the owner from the normal SSH tree being drained.

## Enforcement, not a held-boolean wrapper

`host-hold` directly reuses the original `LinuxKernel`, `SystemdRelaunchBarrier`,
`Journal` and `Fence.arm/check/unknown`. It freezes exactly updater → Docker →
containerd → old backend; preserves Mongo/Redis/Caddy and optional candidate
payloads, and splits only original exact docker-proxy identities into the
owner-specific proxy scope. Relaunch refusal must be loaded in the actual
systemd manager. No restore, thaw, backend-kill or old-service-start API is added.

At each use the node helper requires a fresh random socket challenge, root
SO_PEERCRED with exact supervisor PID/start, exact owner/plan/session identities,
a live independent recovery SSH roundtrip, and the exact journal digest. It then
**independently invokes current LinuxKernel verification**, including host/boot,
all runtime identities, frozen policy/acknowledgements, cgroup inodes,
backend PID/start/executor members, unfrozen payload init identities, exact proxy
members and systemd prefork/restart barriers. It rereads the journal after the
kernel walk. A previous `held` JSON or an arbitrary root echo server cannot
replace these kernel checks.

Only this checked scope internally admits the exact accepted payload/control/proxy
cgroups into process classification. No Docker wildcard, `/`, `/system.slice`,
user-slice exception or permanent expansion of `keepCgroups` is introduced.
Unreviewed replicas, timers, units/drop-ins or cgroups still refuse. Old SSH,
agent, cron/at, ACME, timers and reviewed session/root-manager trees use the
existing persistent-mask, synchronous-stop, pinned SSH cgroup.kill and old-PID
join enforcement. Pending work or a surviving pooled session refuses the hold.

An additional shared check requires every current survivor payload member to be
its exact pinned init or have a stable current ancestry to that init. A generic
accepted shim-exec sibling in the same known unfrozen payload scope is refused;
merely matching a Docker cgroup is insufficient. Disappearing, reused or moving
lineages refuse. This is conservative present-kernel exclusion, not a claim to
recover pre-capture process provenance after historical reparenting.

EOF, signal, owner/boot/PID/inode/policy/supervisor drift, recovery loss or unknown
state denies further use and leaves all existing fences/masks intact. Failed or
uncertain dispatch remains journaled in-flight. Shared `restore-masks` always
refuses (`SHARED_HANDBACK_UNAVAILABLE`): combined host/node handback is not
implemented, and cannot be inferred from a terminal runner receipt.

## Verification and residual release gates

`test_shared_host.py` is local-only: real journals, process identities and Unix
socket roundtrips; explicitly simulated UID/root, SSH and systemd/kernel seams;
real LinuxKernel adapter against disposable proc/cgroup files. It covers missing
and lost guard, wrong owner/start, retained unknown on channel EOF, exact frozen
policy, boot/PID/inode/freeze/supervisor drift, alien payload/SSH/agent/timer,
post-drain fresh login, native survivors and zero subprocess dispatch on lost hold.
The existing dedicated and freezer suites remain mandatory regressions.

This commit does not establish live 2222 recovery/login, old pooled SSH rejection,
traffic survival, accepted independently pinned TEST inventory, or integration
with the separately owned freezer accepted-work fix. Those require parent-only
rehearsal after source review; unknown host state must refuse. This is not a
provenance detector for already reparented pre-capture work: reject inventories
whose old accepted work cannot independently be classified.

It also does not wire root application authority, alias/reassignment reservations,
owner adoption, endpoint enrollment, preinstalled executor/side effects, serving
handoff or combined restoration. These remain separate activation gates. No
application authority receipt is exported; no PROD host is supported.
