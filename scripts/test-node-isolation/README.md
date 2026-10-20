# Dedicated TEST node maintenance toolkit — review/install candidate

**Not installed or activated. No PROD changes. Not application authority.**

`isolation.py` is an executable, root-operator-controlled node enforcement slice,
not an implementation of `topologyExecutionAuthority.withHeldAuthority`.
The authority/enrollment contract in
[`docs/topology-v2-execution-binding-store.md`](../../docs/topology-v2-execution-binding-store.md)
still applies. This helper deliberately does **not** produce
`external-execution-maintenance-v1` proofs or enroll/adopt database records.

## Exact scope / remaining boundary

Only these independently reviewed dedicated TEST hosts can pass plan validation:

| Node | Physical endpoint | Restricted profile |
|---|---|---|
| `6ab18adc63913ebd4a917471` | `132.243.230.19` | `xray-main` |
| `6ab93ad2646b4b7d2f43c907` | `94.103.2.186` | `xray-main` |
| `6ab18d9c63913ebd4a917670` | `50.114.160.63` | `xray-bridge` |
| `6ab4b53bc4c0304573e06c72` | `104.143.201.72` | `xray-bridge` |

The shared LocalXray/panel machine (`6ab189dc63913ebd4a917399`,
`test.infograd.online` / `212.119.42.100`) is **refused by the dedicated mode**,
not added to its allowlist. A separate bounded [shared mode](SHARED.md) requires
an actual live host freezer plus the node masks/drain and independent 2222
recovery; its source-only delivery is not full TEST activation evidence.
This dedicated slice alone cannot authorize the full TEST topology.

Root operator and physical/hypervisor administrators are trusted TCB. There is no
attempt to defend against a malicious root administrator. Conversely, an old
backend retaining its old root SSH credential is **not** permitted to reconnect:
normal SSH listeners/socket activation are persistently masked and stopped;
existing root SSH session scopes and root user-manager trees must be separately
contained and joined. No password/key rotation or firewall mutation is needed.

The replacement transport is a **separate pre-provisioned sshd on port 2222**,
allowing only independent key-only `c3-test-operator` and `c3-test-runner` accounts.
UsePAM=no keeps its sessions in its own service cgroup. It never inherits the
normal sshd config. The operator has root sudo and is TCB; runner has exactly one
sudo command and a forced command. The helper accepts only finite V2 runner argv,
the fixed node/profile/TEST context, and bounded stdin. No `sh -c`, arbitrary
upload, SFTP, scp, environment-selected root, or bootstrap API exists.

This intentionally blocks the existing generic root bootstrap path. Parent runtime
integration must use the already-installed pinned artifact through the restricted
identity/endpoint, re-attest the changed port/username, and preserve all durable
store/claim/lock requirements. This change does not modify runtime, schemas,
worker release, PPP writers, owner handback, or the PROD gate.

## What enforcement actually does

* Requires exact machine-ID, boot-ID, and SHA256 of the raw Ed25519 SSH public-key
  wire blob read on the host, plus approved runner/interpreter/config/unit hashes.
  An operator must first independently accept those observations; the current
  HyNode row is selection only, never authority.
* Requires **two fresh independent operator SSH connections** through the separate
  daemon. A foreground recovery guard binds a root-only Unix socket, PID/start
  identity and its live sshd connection ancestor. Apply challenges the actual
  socket with a random nonce and checks SO_PEERCRED, process start, session identity
  and a distinct SSH connection. The guard additionally sends that nonce across
  the **actual SSH stdio channel** and requires its response within two seconds;
  a locally surviving sshd PID is not mistaken for usable remote recovery. A
  supplied boolean or PID alone cannot pass.
* Pins all discovered service/socket/timer unit fragments/drop-ins. Every process
  must belong to an explicitly reviewed retained service cgroup or an exact unit
  being drained. Broad `/`, `/system.slice`, and user-slice keep exceptions refuse.
  The keep list is an **operator audit**, not an automatically trusted process scan.
  Do not blindly copy inventory into it. Audit services capable of root execution
  (guest agent, D-Bus, polkit, package/updater services) and their activation paths.
* Requires legacy SSH units, `cc-agent`, cron, atd, certbot/ACME variants, root user
  manager, all timers **and their triggered services** to be isolated when present.
  Socket-activated `sshd@`/AF_UNIX/vsock variants must be included too. It refuses
  unknown activation units, unknown cgroups, missing reviewed unit bytes, or
  pending systemd jobs, rather than auto-adopting them.
* Write-ahead journals every original touched `/etc/systemd/system/<unit>` file,
  alias or absence, including bytes, uid/gid, mode and xattrs/ACLs, observed unit
  states/cgroups and PID/start identities. Fsyncs before first mutation.
* Installs persistent masks atomically, reloads systemd, stops socket/timer
  activators first, then services and exact old SSH session scopes. No `--no-block`.
  Requires service/socket/timer LoadState=masked, inactive/failed state, no job,
  mask symlink readback, empty original cgroup.events and no descendants or old
  PID/start survivors. Transient `.scope` units may become not-found/loaded rather
  than masked; they must still be inactive, empty, have the on-disk mask, and have
  no surviving old identity. Their original SSH/user-manager entry paths stay
  masked, so no old credential can create replacement login scopes.
* Before and after dispatch, rechecks physical identity, pinned runtime, effective
  maintenance sshd policy, recovery guard, masks/jobs, descendants and reviewed
  process cgroups. The persistent exclusion remains between calls and across a
  panel crash. Guard loss denies further calls; it never unmasks anything.
* Holds an inherited exclusive flock and writes a durable dispatch-in-flight
  marker **before** launching the pinned existing V2 artifact. Existing V2 journal
  rules prevent command-ID/generation replay. Nonzero/malformed/foreign receipts,
  process death, boot drift or post-command hold loss leave the marker sticky.
  A timeout is never cancellation. No retry, replacement command or auto-recovery.
* A known successful `restore-masks` requires a live hold and an empty/closed,
  boot/node/context-bound V2 journal under its own nonblocking flock. It restores
  mask snapshots and verifies exact readback. It **never starts any old service**,
  and is not database/classic handback permission. Unknown states have no automated
  unfreeze/restore API.

Xray, xray-bridge, PPP, IPsec, L2TP and network units cannot be listed for isolation.
The helper never edits their configs/users, flushes networking or stops their
services during maintenance. Restricted V2 lifecycle operations still have their
normal explicitly authorized profile effects. Existing data-plane operation has
not been live-smoke-tested under this candidate.

## Read-only evidence collected

`collect-readonly.js` uses native `ssh2` inside the already-serving TEST backend,
raw MongoClient reads and existing `cryptoService.decryptPrivateKey/decryptSafe`
credentials in memory. It has four fixed IPs/IDs, refuses changed endpoint fields,
does not import timed serving SSH singletons, and prints no private keys/passwords,
process argv, agent tokens, config bodies or raw errors. It never installs files,
stops services, changes authentication or writes Mongo.

Run from this checkout (reads only; needs existing operator authorization):

```sh
ssh -i /home/leon/.ssh/celerity_test_l2tp_ed25519 -o BatchMode=yes \
  root@212.119.42.100 'docker exec -i hysteria-backend node' \
  < scripts/test-node-isolation/collect-readonly.js
```

Actual collection succeeded for all four nodes. Raw Ed25519 handshake digests
agreed with each node's independently read public-key file digest; machine IDs
and raw key digests were distinct across all four. The compact observed identities
are in `observed-physical-20261020.json`. **First-observation handshake acceptance
is diagnostic, not authenticated enrollment or alias/reassignment exclusion.**
Parent must cross-check pins through an independently trusted operator/control
channel before accepting a plan. Full sanitized process/unit/scheduler inventory
is local scratch evidence at:
`/home/leon/.hermes/cache/scratch/c3-node-isolation-readonly-20261020.json`.

All four had active cc-agent, cron, normal SSH, root SSH session scopes and root
user managers. Ubuntu hosts had active ssh.socket. `94.103.2.186` additionally
had active `sshd-unix-local.socket` and **active not-found** `sshd-vsock.socket`;
ignoring not-found units would miss a live entry path. `104.143.201.72` had **both**
xray.service and xray-bridge.service active; preserve both, not only role-derived
service. All had timer activity. No node was found already isolated.

The exact maintenance config template was also passed **in memory through
`/dev/stdin`** to each node's existing `sshd -T` for operator, runner and root.
All twelve parser/effective-policy invocations returned exit 0 with no stderr,
including root disabled and the runner forced command. ListenAddress used loopback
for this read-only parser test, not an installed listener. OpenSSH emits repeated
`allowusers` lines; the helper regression preserves both entries and refuses
multiple scalar listener/key values. This is parser evidence only, **not a live
login/auth rejection or service-install test**.

## Distro compatibility corrections after rejected ff893553

The reviewed predecessor remains immutable at
`ff89355397b761130aec8ecfc8cac43ef4123d6d` (tree
`266e80377a3bd950b5617144b30223d731bb68f0`). Its tests missed two preinstall
blockers; this delta changes only those boundaries:

* **Normal SSH `KillMode=process`:** only `ssh.service`/`sshd.service`, with one of
  those exact canonical IDs and the exact `/system.slice/<Id>` cgroup, may use the
  exception. Before any mutation the helper opens that cgroup, requires
  `cgroup.kill`, and journals its device/inode. After **all** old activators,
  services and separately listed SSH session scopes have been masked/stopped,
  it rechecks the persistent mask, inactive/no-job/zero-MainPID state, opens the
  snapshot path with `O_NOFOLLOW`, compares device/inode and writes `cgroup.kill`.
  It joins population before the existing complete old-PID/cgroup checks. A
  replaced cgroup, missing kernel support or failed drain retains unknown state.
  Other active services with `KillMode=process` still refuse before mutation.
* **Independent `/run/sshd`:** the maintenance unit now explicitly owns
  `RuntimeDirectory=sshd`, mode 0755, root:root, with preservation enabled. **Both
  the old and maintenance units must preserve it. Shared RuntimeDirectory alone
  is insufficient:** a real systemd 257 local RED probe removed the directory
  when the old unit stopped despite maintenance remaining active. The supplied
  `normal-ssh-runtime.conf` is a concrete, pinned parent-install prerequisite,
  not a suggestion to create `/run/sshd` with ExecStartPre. The helper verifies
  effective preservation on every active old SSH unit sharing `sshd`, as well as
  maintenance runtime ownership. It never installs this prerequisite itself.

`collect-readonly.js` now requests fixed **named** SSH units and runtime properties.
The earlier no-unit `systemctl show` returned manager properties, not target
KillMode; the archived earlier collection does **not** establish target KillMode
or runtime preservation. This updated collector has not been run on the targets.

## Parent-only install prerequisites (not executed here)

1. Keep trusted console/out-of-band access available. Confirm these are still
   dedicated TEST hosts, no PROD role/profile co-residency, and accept the complete
   physical inventory independently. Freeze endpoint reassignment, physical aliases
   and backend/container dispatch externally for the entire lifecycle. The node
   helper is only one part of that fence.
2. Before provisioning, snapshot every path/account state you will change:
   `/etc/ssh/c3-test-maintenance.conf`, `/etc/ssh/c3-test-keys`, maintenance service,
   sudoers drop-in, helper/config/state path presence and permissions, runner
   artifact and public/private account provisioning metadata (do not copy private
   keys into reports). Keep backups root-only. Provisioning rollback is a separate
   reviewed parent operation; helper snapshots cover its mask changes only.
3. Create the two dedicated non-root accounts with valid `/bin/sh`, no legacy
   authorized keys, and **separate newly generated Ed25519 keys**, not keys or
   passwords available to the old backend. Determine account-lock semantics on the
   installed OpenSSH; prove key login actually works rather than assuming a locked
   account can log in with UsePAM=no. Runner must have no other sudo group/rules.
   Store public keys root-owned under `/etc/ssh/c3-test-keys/<username>` (directory
   0755, files 0644 so unprivileged sshd auth can read them); no account may modify
   this directory or its parents. Keep private keys only in the operator's vault.
4. Stage `isolation.py` as `/usr/local/libexec/c3-test-node-isolation`, root:root
   0755. Its `#!/usr/bin/python3 -I` intentionally ignores Python user/env injection.
   Install the exact existing V2 artifact as
   `/usr/local/bin/celerity-topology-node-runner`, root-owned 0750. Do not bootstrap
   or replace it while held. Verify runner bytes against the accepted source hash.
5. Render `maintenance-sshd.conf.in` with the exact allowlisted host IPv4 at
   `TEST_ENDPOINT_IP`, install root:root 0600 to `/etc/ssh/c3-test-maintenance.conf`.
   Install the supplied maintenance service root:root 0644. **Before stopping any
   normal SSH unit**, record its canonical `Id`, `RuntimeDirectory`,
   `RuntimeDirectoryPreserve`, `FragmentPath`, `DropInPaths` and exact existing
   drop-in bytes/absence. For every old SSH service sharing `sshd`, install the
   exact supplied `normal-ssh-runtime.conf` root:root 0644 at
   `/etc/systemd/system/<observed-canonical-Id>.d/c3-test-runtime.conf`, without
   overwriting any existing file. Run `systemctl daemon-reload` (no SSH restart),
   then require `systemctl show <canonical-Id> --property=Id,RuntimeDirectory,RuntimeDirectoryMode,RuntimeDirectoryPreserve,DropInPaths`
   to show `RuntimeDirectoryPreserve=yes` and the exact new drop-in path. Preserve
   before/after output; include its exact SHA256 in the post-provisioning
   `unitFilePins` (supplied file SHA256:
   `bd154bb1a033768ecf715cc48e03134083f7a8cc3899b91d82f36b3f8a41301a`).
   A local real-systemd probe verified this no-restart reload path;
   failure on a target is a hard stop, not permission to kill SSH. Snapshot and
   separately review restoration of this provisioning drop-in: `restore-masks`
   intentionally does not remove it. Do not remove it while either daemon relies
   on the shared directory. Validate `sshd -t` and
   effective `-T -C` for all three users. Stage `sudoers.in`, run `visudo -cf`, then
   install a root:root 0440 drop-in. Do not weaken the exact runner command or allow
   SETENV/general sudo. `SSH_ORIGINAL_COMMAND` is data parsed by the root helper,
   never evaluated by a shell.
6. Start/enable **only the new maintenance daemon**, parent-authorized. Keep normal
   SSH untouched. Open a fresh independent key-only connection to the new port and
   prove `sudo -n id -u` = 0, pinned host key, account separation, and operator
   recovery. Prove runner shell/SFTP/scp requests are refused by its forced command.
   Prove legacy root keys/passwords cannot log in to this daemon. No live auth
   probes using stored node secrets are provided by this child.
7. Use the installed helper's `inventory` to refresh all units, triggers, cgroups,
   process start identities, scheduler digests and unit-file hashes **after**
   provisioning the new daemon. Inspect cron/at/ACME hooks locally as root (do not
   print secret bodies). Include all extant old root login scopes, `user@0.service`,
   all SSH aliases/templates/sockets, timer child services and custom writers.
   If a writer cannot be separated from a retained data-plane service, **stop here**.
8. Independently review and install `/etc/c3-test-node-isolation.json`, root:root
   0600, exact fields below. Create `/var/lib/c3-test-node-isolation`, root:root 0700,
   initially empty. No generator turns a current DB/process scan into an accepted
   plan. All ancestor paths, unit/config/key files and binaries must be root-owned
   and not group/world writable; pin resolved distro interpreter targets.

Exact plan fields (no defaults, extra fields, or fabricated accepted example):

* `version: 1`, `context: "test.infograd.online"`.
* `nodeId`, `endpointIp`, `targetProfile`: exact table tuple.
* `machineId`: accepted 32-lowercase-hex; `bootId`: current lowercase UUID;
  `sshHostKeySha256`: 64-lowercase-hex digest of raw Ed25519 SSH key wire blob.
* `maintenanceId`: unique operator-owned bounded `[A-Za-z0-9][A-Za-z0-9._-]{0,127}`.
* `runnerSha256`, `maintenanceConfigSha256`, `maintenanceUnitSha256`: exact accepted
  local bytes' 64-lowercase-hex SHA256 (no `sha256:` prefix).
* `runtimePins`: exactly `/bin/bash` and `/usr/bin/python3` mapped to accepted
  resolved binary SHA256 digests.
* `isolateUnits`: unique exact unit names, including required entries
  `cc-agent.service`, `certbot.service`, `certbot.timer`, `atd.service`, `ssh.socket`,
  at least one of `ssh.service`/`sshd.service`, at least one of cron/crond.service,
  and all additionally required reviewed activation/session/writer units. Missing
  optional packages still get persistent masks; loaded variants cannot be omitted.
* `keepCgroups`: explicit audited service cgroup paths and optionally `/init.scope`;
  must include `/system.slice/c3-test-maintenance-sshd.service`. No user-slice keeps.
  `systemd-udevd.service/udev` processes require the audited parent service cgroup.
* `unitFilePins`: every discovered service/socket/timer unit fragment/drop-in path
  mapped to accepted byte SHA256. Read-only hashes alone are not a nonwriter audit.

No service-account, private-key, password or agent token belongs in this plan.

## Exact apply / hold / recovery protocol (parent only)

Use `ControlMaster=no`, `ControlPath=none`, `IdentitiesOnly=yes`, host-key pinning
and `-T`; do not multiplex the guard/apply connections. Operator SSH examples below
omit only local key/known_hosts paths, which parent must supply explicitly.

1. In **connection A**, run the local foreground responder:
   `python3 scripts/test-node-isolation/guard-client.py APPROVED_IP LOCAL_OPERATOR_KEY_FILE PINNED_KNOWN_HOSTS_FILE`.
   It opens its own nonmultiplexed SSH connection and runs
   `sudo -n /usr/local/libexec/c3-test-node-isolation guard` remotely. Leave the
   responder connected so it can answer live channel nonce challenges; do not use
   `ssh -n`, closed stdin, or a bare idle sshd PID as recovery evidence. The guard
   records PID/start/socket and its SSH-session identity. Do not detach it, timeout
   it or reuse a stale socket. An existing socket/guard is a stop-and-investigate
   condition; the helper never replaces it.
2. In fresh **connection B** through the same independently pinned daemon, run
   `sudo -n /usr/local/libexec/c3-test-node-isolation apply`. Apply refuses a shared
   SSH connection or failed guard. It snapshots before masking/stopping old entry
   paths and writers; any uncertainty leaves `isolating` and all acquired masks.
   Do not retry apply, run unfreeze, or restart the old backend on failure.
   Successful drain returns **`awaiting-fresh-login`, NOT held**; dispatch, status
   and mask restoration are still refused.
3. After that return, open a genuinely new **connection C** (no ControlMaster) to
   port 2222 with the independent operator key and pinned host key. Run
   `sudo -n /usr/local/libexec/c3-test-node-isolation confirm-access` through C.
   The helper requires C's sshd connection PID/start to be distinct from B and
   newer than the recorded post-drain boot-tick boundary, rechecks the full drain
   and distinct live guard A, and only then persists `held`. An existing channel
   echo or preopened third connection cannot pass. This is the mandatory real
   post-stop authentication gate, not a supplied boolean. If fresh authentication
   fails, retain masks and use A/console to investigate; never restart old SSH as
   an automatic recovery. This live target login has **not** been executed here.
   Independently verify normal SSH/old shell/SFTP/bootstrap attempts now fail,
   pre-existing old pooled SSH connections cannot execute/upload, and detached old
   children/session/root-user cgroups are gone. Verify agent HTTP writes fail
   because the entire service is stopped/masked and joined, not just denied at HTTP.
   Check cron/at/timers/ACME cannot reactivate. Verify xray/PPP/client data plane
   remains good, independent operator connection A is still usable, and fresh
   connection C successfully authenticated after old SSH stopped. These are
   **required live acceptance checks, not yet executed**.
4. `sudo -n /usr/local/libexec/c3-test-node-isolation status` performs fresh checks,
   not a cached caller boolean. Runner SSH sends only the existing exact V2 runner
   command line and prepare payload; the forced command routes it to `dispatch`.
   Shell/SFTP/bootstrap remain disabled. Parent must maintain backend exclusion and
   bind node evidence to its awaited authority lifecycle; status JSON cannot be
   relabeled as the full store proof.
5. Keep the guard and permanent masks throughout preparation, all command gaps,
   user/PPP verification, close/status, persistence/settlement and cleanup.
   A guard disconnect, changed boot/identity/unit, pending job or in-flight journal
   requires retained operation locks/admission and operator reconciliation.
6. Only after a separately reviewed physical/classic handback and known V2 terminal
   state may fresh connection B invoke
   `sudo -n /usr/local/libexec/c3-test-node-isolation restore-masks`.
   It restores exact original config/alias/absence, verifies readback, and **does
   not start SSH, agent, cron, certbot or any backend**. Parent decides each restart
   separately after confirming no retained owner/writer. Archive state; helper
   will not start another maintenance lifecycle over its existing journal.

**Unknown/partial recovery:** inspect root-only `journal.json`/`.next`, snapshots,
old PID/start/cgroups, inherited lock holders, V2 fence/journal and current jobs via
independent operator or console. Do not delete journals, clear in-flight fields,
replace boot IDs, manufacture a close receipt, or unmask/restart merely because a
client timed out. There is intentionally no force flag. If root must perform a
manual recovery, first prove all writer descendants and jobs joined, preserve the
unknown evidence and retained application ownership, and separately review the
exact snapshot restoration. A crashed helper does not revoke persistent masks.
A reboot changes boot identity and refuses dispatch; masks persist. Boot recovery
of the dedicated daemon/accounts must be tested before activation.

## Local verification / evidence limits

```sh
python3 scripts/test-node-isolation/test_isolation.py -v
node --test src/modules/relay-l2tp/tests/topologyRunnerFence.test.js
node --check scripts/test-node-isolation/collect-readonly.js
git diff --check
```

Local result on this correction: **20 Python tests passed**, and the unchanged
V2 runner fence suite reported **22 passed, zero failed/skipped/cancelled**. Python
compile, JavaScript syntax and whitespace checks passed. No Mongo/full suite was
run. Read-only collection/parser checks above are separate from these fixture tests.

Local tests exercise actual fsync/rename/modes/xattrs/flock/process-start syscalls
and the real V2 artifact in a disposable fake root over two serial generations,
close/status and stale replay. Other tests explicitly simulate the physical,
SSH, systemd/cgroup adapter: they prove controller ordering, sticky unknown,
receipt binding, boot/guard refusal, restored file/alias/absence readback, no old
service restart, and unsupported command/profile/context/activation rejection.
The separate explicit local root probe `test-systemd-local.py` exercised real
systemd 257 (`257.13-1~deb13u1`) and the local cgroup-v2 kernel with randomly named
transient units, a private runtime directory and scratch files only. It verified
an old `KillMode=process` child survives stop then joins via pinned `cgroup.kill`,
the supplied preservation drop-in changes `no` to `yes` after daemon-reload
**without restart**, the shared directory survives old mask/reload/stop, and the
maintenance unit alone recreates it from absence and across restart. It read back
inactive units and absent private runtime directory after cleanup. It touched no
real SSH service, account, authentication, `/run/sshd`, network or remote host.
Run it only with explicit local-root authorization:

```sh
/usr/local/bin/hermes-admin /usr/bin/python3 -I \
  /home/leon/c3-test-node-isolation-20261020/scripts/test-node-isolation/test-systemd-local.py
```

The first non-preserving real-systemd probe failed as expected; the corrected
preserving probe passed. This is actual local platform evidence, **not** evidence
of Ubuntu/systemd versions not exercised, a target reboot, or a real SSH login.
The regular Python fixtures and runner suite do **not** prove deployed SSH rejection,
positive operator recovery, data-plane connectivity, provisioning/owner restoration,
endpoint reservations, backend isolation or a complete live node lifecycle.
Those remain parent review/install acceptance boundaries; none are hidden behind
an authority-shaped wrapper or TEST boolean.
