# TEST panel-host kernel isolation

`scripts/panel-host-freezer.py` implements **real host cgroup-v2 freeze and exact
old-backend cgroup kill**, not the advisory model in
[panel-maintenance-preflight.md](panel-maintenance-preflight.md). This separate
entrypoint is pinned to TEST machine ID `7fa266f995fe4aa69e96cf7d01359e34`;
there is no PROD override. It changes no application, worker, database, node,
Compose configuration or Docker restart policy. It temporarily adds checked
TEST-only runtime systemd drop-ins for the two launch services. Deployment and
runtime wiring belong to the rollout owner. Development used **read-only TEST
capture only**, with all real mutations confined to disposable local experiments.

## Kernel fence and trust boundary

The accepted inventory pins boot ID, full container/image IDs, image references,
Compose project/service, start/restart metadata, PID/start ticks/executable/comm,
recursive control/executor members, exact cgroup paths and cgroup-directory
inodes. Required running roles are `hysteria-{backend,updater,mongo,redis,caddy}`.
One separately accepted running `c3-test-candidate` is allowed; it must be
started **before** the hold. Arbitrary extra/stopped replicas, privileged or
host-PID/cgroup containers, added capabilities, dangerous host mounts and runtime
socket mounts outside the updater refuse. The optional candidate is not
independently authorized to execute node work by this tool.

`capture` only reads Docker `container ls --all --quiet --no-trunc` and
`container inspect`, each with a ten-second timeout, plus proc/cgroup files and
read-only `systemctl show` supervisor properties. An
independently reviewed capture must match two new captures before arm. A copied
current observation is not independent approval. After arm starts there are
**no Docker/containerd API calls**, including during termination and rollback.

Arm first installs and reads back the supervisor relaunch refusal below, then
writes durable intent and freezes, in order:

1. Exact updater payload cgroup (including its recursively admitted children).
2. `/system.slice/docker.service` (dockerd and inherited accepted work).
3. `/system.slice/containerd.service` (**all shims and inherited runc work**).
4. Exact old-backend payload cgroup.

Every transition checks actual `cgroup.freeze` and **`cgroup.events frozen=1`**,
identity, recursive membership, all Docker scopes and runtime executable
inventory. `/proc/comm` plus `/proc/PID/exe` are used, not `pgrep -x` with names
longer than Linux's comm limit. Shims must use the `moby` namespace and correspond
one-to-one to the exact accepted running containers. Runtime helpers outside the
held roots, foreign shims, unknown Docker scopes, populated Docker/BuildKit/runc /
containerd cgroups outside the inventory, generic escaped control-process
children, changing inventories and unacknowledged freezer requests refuse.
Unaccounted already-running build payloads are **not** silently treated as host
services or adopted into authority. This supports the inspected TEST daemon
layout, not arbitrary custom runtime/cgroup placements.

Freezing these roots stops process execution, including accepted requests and
runtime children already running there. The live daemon and shim identities
remain present, so restart managers do not observe a voluntary daemon stop.
New and pre-opened socket connections can remain queued in the kernel; they
**cannot execute through frozen daemons/shims**. Do not describe connection
acceptance/timeouts as proof that a job was cancelled. Pending work remains
suspended and could execute upon a later thaw; there is **no post-kill thaw API**.

Mongo, Redis, Caddy and a pre-started candidate have independent payload scopes
and remain unfrozen. Their init identities are rechecked without requiring their
legitimate child-process inventories to remain static. Native Xray/PPP services
are not targeted. LocalXray's alias on the TEST panel machine is the **same
physical machine**, not a separate remote exclusion boundary.

### Prevent service-cgroup recreation

A real local `Restart=always, KillMode=process` experiment disproved service-only
freezing: main-PID SIGKILL caused systemd to recreate the same-named cgroup with
a new inode and `frozen=0`. Keeping the original PID frozen does not fence that
natural/automatic replacement path after its unexpected death.

Before arm, the implementation therefore creates exclusive owner-journaled
`/run/systemd/system/{docker,containerd}.service.d/90-c3-test-host-isolation.conf`
files with **`ConditionPathExists=!/run`, `Restart=no`, and an exact
`ExecCondition=/usr/bin/false`** (after requiring no preexisting ExecCondition).
The loaded non-trigger, negated `/run` condition is checked via typed D-Bus
`busctl --json=short` because `systemctl show Conditions` is unprintable on the
tested systemd. `/run` is necessarily present on this pinned host; its negated
condition rejects activation **before PID1 forks** into a frozen service cgroup.
The false ExecCondition is defense in depth, not the pre-fork barrier by itself.
A bounded daemon-reload and fresh loaded property/byte readback are required
before a held result. Restart suppression covers natural daemon loss; the
manager-enforced condition rejects socket/dependency activation without
launching replacement daemon code. This is
an enforced service-manager launch barrier, not a cooperative lock or a supplied
authority flag. Original kernel control roots still suspend already-accepted
work. Unexpected loss poisons dispatch even while replacement stays inhibited.

The real disposable systemd drill verifies exact nondestructive configuration
restoration, then separately kills its frozen main PID, waits beyond RestartSec,
tries an explicit start, and requires exactly one initial worker marker plus an
inactive/failed service and responsive PID1. A preaccepted child remains in the
original frozen cgroup after main-PID death and activation refusal; its heartbeat
cannot grow and `cgroup.events frozen=1` must persist. The final mechanism does **not** put future
systemd children into a pre-frozen parent slice: that rejected local experiment
can block PID1 in its fork/exec setup. All probe-owned units/slices were cleaned
up; no such slice is part of the delivered host mechanism.

Every held check rereads the exact refusal files and loaded supervisor policy.
Nondestructive restore removes only its exact files, removes an empty directory
only if this owner created it, reloads, and requires exact original supervisor
properties before thawing the original processes. No removal is permitted after
old-backend kill, unknown state, or loss of the original control identities.

### Preserve published-port data plane

On inspected TEST, four `docker-proxy` processes live in `docker.service`.
Leaving them frozen would also stall published-port traffic despite live
container payloads. After the launch roots are frozen, the tool moves **only the
exact pinned `docker-proxy` identities** into a new owner-specific sibling
`/system.slice/c3-test-host-proxies-OWNER.scope`, which stays unfrozen. Every move
has durable intent and exact membership/start-identity readback. All other
control-plane processes remain frozen. The proxy group admits no arbitrary
helper, shim, runc or BuildKit process. Original groups/members are retained in
the journal and restored before nondestructive thaw. A successful local drill
verified new HTTP requests through the real Docker 26 proxy into an unfrozen
container while dockerd, containerd, shims and accepted runc work stayed frozen.

The host administrator is trusted. Root manually thawing, moving/replacing
cgroups, restarting units, introducing a custom direct runtime or rebooting is
**outside** the fence's security boundary, not a claimed adversarial-root
protection. Administrators must not perform such operations during the hold.
Readback detects observed identity/freezer drift and poisons the guard, but is
not a substitute for that administrator exclusion. Concurrent ordinary API
clients are not required to cooperate with a file lock.

## Held controller protocol

Run on the real TEST host in the host PID/mount/cgroup namespaces as root. These
are operator examples, **not commands run on live TEST during development**:

```sh
python3 -B scripts/panel-host-freezer.py capture > observed.json
# Independently review/accept all identities, image and candidate configuration.
# Retain that accepted JSON separately, rather than auto-enrolling this capture.
python3 -B -u scripts/panel-host-freezer.py hold \
  --expected /root/maintenance/accepted-test.json \
  --state-dir /root/maintenance/new-owner-directory \
  --owner 11111111-2222-3333-4444-555555555555
```

Keep stdin/stdout and this exact controller process alive across the **entire**
lifecycle. The first JSON line is `hostFence: "held", oldExecutor: "frozen"`
only after acknowledged kernel isolation and a final check. The controller
checks the held inventory every 200 ms plus the duration of the bounded scan.
Send newline-delimited JSON frames and await the matching reply serially:

```json
{"owner":"11111111-2222-3333-4444-555555555555","command":"check"}
{"owner":"11111111-2222-3333-4444-555555555555","command":"kill","ack":"KILL_EXACT_OLD_BACKEND"}
```

`kill` first revalidates the held fence, persists intent, writes `1` only to the
pinned frozen old-backend `cgroup.kill`, and requires recursive `populated=0`,
empty members and no surviving executable old PID/start-ticks identities. An
unreaped `Z` zombie may remain because its shim is frozen; the tool does not
claim the zombie's proc row disappeared. The result becomes `oldExecutor:
"empty"`; updater, daemons, shims and the old backend cgroup stay frozen.
Queued restart/create/exec work cannot resurrect it while that fence is held.

A **known nondestructive abort only**, before any node mutation or kill:

```json
{"owner":"11111111-2222-3333-4444-555555555555","command":"restore","ack":"NO_DESTRUCTIVE_OR_NODE_MUTATION"}
```

This returns exact proxy membership to the original frozen daemon group,
requires the original saved projection to match, and thaws in reverse order,
updater last, with checked readback. Docker restart policies remain untouched;
the original systemd restart/condition configuration must be restored exactly.
Pending original work may resume after an explicit safe abort. Any ambiguity,
identity change, incomplete acknowledgement or journal failure becomes sticky
unknown rather than authorizing further restoration. Restore is forbidden after
kill. Unknown is sticky even if a later observation looks normal.

The private 0700 journal directory is created exclusively, fsynced, owner-bound,
flocked, and never adopted/reused. Intent and state files use 0600 exclusive /
non-following opens, fsync, atomic rename, directory fsync and exact readback.
The flock only serializes controllers; kernel freezing supplies exclusion.
EOF, SIGINT/TERM/HUP, timeout, corrupt/unwritable state, foreign control frames or
lost guard **never automatically thaw anything**. SIGKILL may leave a historical
`held`/`intent` record: no record or saved reply is a bearer capability. A caller
must treat process/pipe loss as unknown, keep its admissions/locks and stop new
dispatch. Recovery after uncertainty or destruction needs separately reviewed
owner-specific host recovery; deleting a directory or rerunning arm is not it.

## Not external node authority

All live replies retain `nodeState: "unknown"`. This tool does **not** implement
`external-execution-maintenance-v1`, the physical SSH endpoint attestation, node
writer/agent/scheduler exclusion, SSH/SFTP/systemd completion, backups, alias
ownership or terminal handoff in
[topology-v2-execution-binding-store.md](topology-v2-execution-binding-store.md).
Old local cgroup emptiness cannot retract previously sent remote work. LocalXray
host aliasing also needs the parent's node-side writer inventory/exclusion while
preserving its Xray/PPP data plane. Do not wire this host result alone into an
external authority callback or enable production execution.

## Verification and limits

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s scripts/tests -p test_panel_host_freezer.py -v
```

The offline suite exercises real fake-root proc/cgroup parsing and the actual
held-pipe entry loop, including PID reuse/boot/inode/freezer drift, replicas,
long shim names, accepted descendant escape, foreign runtime/build payloads,
proxy type restriction, identity-pinned kill, sticky unknown, exclusive journals,
SIGTERM/SIGKILL/EOF and exact nondestructive restoration. These are **offline**
tests, not claims about deployed services.

`tests/panel_host_freezer_drill.py` (under `scripts/`) is an opt-in disposable
**local** root experiment. It refuses to run outside `hermes-heavy` and a private
mount namespace, uses explicit static Docker 26 binaries without downloads,
private `/run`, separate daemon sockets/state, cgroupfs test payloads, no bridge
or firewall changes, and no live host Docker. Example using a separately retained
binary directory and a **new** scratch workspace:

```sh
HERMES_HEAVY_TMP_ROOT=/home/leon/.hermes/cache/scratch/freezer-heavy \
  /home/leon/.local/bin/hermes-heavy /usr/local/bin/hermes-admin \
  /usr/bin/unshare --mount --propagation private /usr/bin/python3 \
  scripts/tests/panel_host_freezer_drill.py \
  --bin-dir /absolute/path/to/docker26/bin \
  --workspace /home/leon/.hermes/cache/scratch/new-freezer-drill
# A separate new workspace plus --restore-only exercises real safe restoration.
```

The drill runs the actual `serve` controller in a separate process and injects
a compiled runc-exec gate **after real Docker/containerd/shim acceptance**. It
releases that gate while the kernel roots remain frozen, probes old/new Docker
and containerd sockets, queues restart/create requests, kills the restart-always
old payload, checks continued emptiness/no marker/no resurrection, and verifies
survivor heartbeat and new proxied HTTP requests. The restore variant returns
the exact proxy/control/freezer projection and confirms the daemon API resumes.
Its only adapters change local discovery and proxy-group placement for isolated
cgroupfs fixtures; freezer, process identity, kill, journal and held protocol
are the delivered implementation. The local Docker fixture does not install
the real host's systemd policies; the separate real systemd drill exercises the
supervisor barrier. This is bounded local evidence for the tested
runc-exec phase plus kernel inheritance/closure and fail-closed inventory—not an
empirical test of every possible Docker build phase, custom runtime placement,
remote node writer or malicious administrator. Disposable teardown kills owned
local groups; it never uses production restoration after destruction.

Run the separate systemd experiment only on a disposable non-TEST local host
with root, systemd and cgroup v2:

```sh
SYSTEMD_BYPASS_USERDB=1 /usr/local/bin/hermes-admin /usr/bin/python3 -B \
  scripts/tests/panel_host_freezer_systemd_drill.py \
  /home/leon/.hermes/cache/scratch/new-freezer-systemd-drill
```

It creates one exclusive `c3-freezer-relaunch-drill-PID.service` and removes
only its own exact unit/drop-in bytes, killing its own frozen disposable helper
for cleanup. This is not a post-kill restoration route for the host mechanism.
`SYSTEMD_BYPASS_USERDB=1` avoids optional NSS userdb resolution in the local
privilege wrapper; it does not disable authentication or the host identity gate.

The delivered verification record is
[panel-host-freezer-evidence-20261020.json](panel-host-freezer-evidence-20261020.json).
It records local-only artifacts and read-only TEST inventory, not a live TEST
fence, node-side maintenance authority or production approval.
