# Panel maintenance preflight and offline hold drill

**Delivered boundary: precheck/read-only drill only. Not maintenance authority,
not rollout, not production dispatch exclusion.** No runtime, worker, database,
Compose file or node service is changed. There is no daemon, timer, startup hook,
real `arm` command, real termination command, or runtime-consumable authority
export. Do not wire these results into topology execution or transfer admission.

`python3 scripts/panel-maintenance-guard.py` defaults to local **read-only**
precheck. All operational results exit **2**, including a consistent capture and
successful offline drill. Help exits normally. An empty `findings` array means
only that the supplied observations passed diagnostics; `blockers` still deny
real execution. Every result retains `dispatchAuthorized: false`,
`nodeState: "unknown"`, and `holdRequired: true`. A rehearsal receipt's `hold`
field describes only its simulated hold, never a real host fence.

## Why real arm and kill are deliberately absent

The inspected updater can submit independent `docker compose up -d backend`
requests (`updater/server.js`, `performHubUpdate` / `performSourceUpdate`). Freezing
its client process cannot retract requests already accepted by Docker, join
BuildKit/daemon work, or exclude other socket clients, host cron, external CI,
Compose operators and replacement replicas. A per-container `restart=no` does
not inhibit `compose up`, daemon-level replacement, or another supervisor.
Two equal reads cannot close the race after the second read. An idle-looking
Node process or updater `/status` result is not a daemon-work completion receipt.

The available interfaces provide neither an independently enforced,
execution-spanning Docker/supervisor exclusion contract nor an attested drain of
already submitted updater work. Therefore no sequence of ordinary Docker
pause/update/inspect calls can presently prove the requested real authority.
The tool's filesystem lock coordinates only other invocations using the **same
receipt directory**; it cannot exclude Docker clients or even a second drill
in another directory. Its checksum detects accidental receipt corruption, not a
malicious same-user/root operator. Do not promote this advisory rehearsal lock
into a production authority.

Separately, the old backend's forced shutdown/pool teardown is not an adequate
remote drain. Local cgroup freeze or even verified local emptiness does **not**
join remote SSH descendants, detached systemd jobs, SFTP writes, node-local
cc-agent startup/heal/config writers, cron/at/ACME/certbot hooks, or other node
operators. No local result ever reports `node-quiescent`. Unknown/missing remote
evidence retains the real maintenance requirement. Existing transfer and V2
execution gates remain closed; this tool cannot resolve missing node backup,
unconfirmed/offline bridges, node enrollment, or ownership/terminal handoff.

## Read-only capture and exact identity checks

Fixed names and Compose service labels (not configurable by CLI):

| Container | Service |
| --- | --- |
| `hysteria-backend` | `backend` |
| `hysteria-updater` | `updater` |
| `hysteria-caddy` | `caddy` |

The collector only calls `docker --host unix:///var/run/docker.sock container ls
--all --quiet --no-trunc` and `container inspect FULL_IDS...`, each with a
10-second subprocess timeout. It never invokes Docker exec, stop, pause, kill,
update, Compose, SSH, HTTP endpoints or systemctl. `DOCKER_HOST`/context cannot
redirect this fixed Unix-socket command to a remote daemon. It must be run in the
panel **host** namespace with read access to its `/proc`, unified cgroup v2, and
Docker socket. Do not add it to the backend container or grant new privileges.

Two complete observations capture and compare inventory, state, processes and
freezer data. Capture projects allowlisted metadata out of inspect; raw
configuration, environment, credentials and stderr are never emitted. Limits:
128 containers, 4096 observed processes per selected container, 4 MiB regular
non-symlink JSON file input/receipt. Unreadable files, disappearing processes, unsupported cgroup
layout, changing observations or command failures produce an unknown capture.
These bounds are diagnostic safeguards, not an end-to-end execution deadline.

Selected containers require exact full container ID, immutable `sha256:` image
ID, image reference, host PID, `/proc/PID/stat` start ticks, host boot ID, exact
`/system.slice/docker-FULL_ID.scope`, Docker start time/restart count, Compose
project/service, restart policy, and process inventory. Start ticks are parsed
after the final `)` in proc stat. Every recursive child-cgroup PID is included
and its membership checked. All three must share a boot/project identity and
be running, non-restarting, non-dead, unpaused, with `cgroup.freeze=0`,
`cgroup.events frozen=0 populated=1`. Preexisting pause/freezer state is refused,
not adopted or unpaused. Updater must have exactly its single `node` process;
extra/nested processes are in-flight-or-unknown, not evidence of safe idleness.

A separately retained `--expected` capture pins exact identities and the full
container inventory. Missing expected evidence does not auto-enroll the current
host. ID/image/PID/startTicks/boot/cgroup/start/restart drift refuses a drill.
Unexpected replicas sharing a service label, image ID or image reference refuse,
including stopped candidates. Differently named/unlabelled/differently imaged
writers cannot be exhaustively identified from these facts; exclusivity remains
unproven even when no candidate is observed. Caddy is always included in the
model: no unproved ingress-isolation exemption is offered.

Future operator examples, **not run against PROD/TEST during development**:

```sh
# On the panel host, observation only. Expected status is 2, NOT success/ready.
python3 scripts/panel-maintenance-guard.py capture > observed.json
python3 scripts/panel-maintenance-guard.py precheck \
  --snapshot observed.json --expected independently-retained.json
```

Capture JSON has `schema: 1`, `containers: [...]`, `errors: []`, plus explicit
non-authority fields. Per-container fields are documented above; the test
`snapshot()` fixture shows the exact offline schema without real host secrets.
Do not use a freshly copied observation as independent operator acceptance.

## Offline-only state machine

No drill action reads Docker or cgroups. It only transforms JSON under an
explicit private state directory. Nothing in a receipt describes a verified
real pause, restart-policy change, process kill, or remote mutation.

```sh
# Use fixture/previously collected files; this never arms the real host.
python3 scripts/panel-maintenance-guard.py drill begin \
  --state-dir /path/to/private/new-drill \
  --owner 11111111-2222-3333-4444-555555555555 \
  --snapshot fixture.json --expected independently-retained-fixture.json
# Repeat step once per modeled transition; never continue on an unknown receipt.
python3 scripts/panel-maintenance-guard.py drill step \
  --state-dir /path/to/private/new-drill \
  --owner 11111111-2222-3333-4444-555555555555
# Inspect without creating/changing receipt state.
python3 scripts/panel-maintenance-guard.py drill status \
  --state-dir /path/to/private/new-drill \
  --owner 11111111-2222-3333-4444-555555555555
# Known pre-destructive abort only. Restores the exact original JSON model.
python3 scripts/panel-maintenance-guard.py drill rollback \
  --state-dir /path/to/private/new-drill \
  --owner 11111111-2222-3333-4444-555555555555
```

Modeled order: freeze updater; freeze backend; disable updater restart; disable
backend restart; freeze Caddy; disable Caddy restart; verify exact frozen model.
A further `step` cannot implicitly terminate anything. The distinct **offline**
`drill terminate --ack SIMULATED_DESTRUCTION_ONLY` action (same directory/owner
arguments) requires all transitions and only empties the fake backend cgroup.
It preserves updater/Caddy freeze, exact terminated identity, simulated hold,
remote uncertainty and execution refusal. It cannot run a real kill. Rollback
is refused after this irreversible simulated phase.

Receipts use a private owner-only directory, directory-fd advisory flock,
non-following file opens, owner UUID, checksummed JSON, fsync(file), atomic
rename, fsync(directory), and exact readback. One command at a time; one
persistent owner; no time-based lease expiry. Exiting the operator command does
not discard the simulated hold. Every transition writes durable intent before
model change. SIGTERM/SIGINT mark unknown; SIGKILL can leave pending intent,
which status reports as unknown with hold retained. Unknown state, corrupt
receipt, identity drift, foreign owner or failed readback cannot authorize an
automatic rollback/unfreeze. Preserve the directory for investigation. Do not
manually erase a receipt to obtain a ready result. A closed drill cannot be
reused; use a new directory for an unrelated rehearsal.

The intended real rollback ordering is to restore saved restart policies/retry
counts while frozen, then backend/Caddy state, then updater last. The offline
rollback is one atomic model reset: it checks exact final JSON equality only,
not that intermediate host ordering. It closes only the **simulated** hold before
any node mutation and does not exercise those host APIs.

## Required future real-arm contract (unimplemented)

Only a separately reviewed host-maintenance implementation, explicitly approved
for an outage, could implement the following. This is an acceptance contract,
not a runnable rollout recipe:

1. Accept exact independent host/container pins, app **and node** backup/restore
   evidence, authorized graph and recovery access. Acquire a durable real owner
   hold and externally enforce exclusion of every relevant Docker client,
   updater ingress, alternate supervisor/operator and recreate path. Resolve
   already accepted daemon/updater jobs. Unknown ownership/work is a stop.
2. Revalidate full inventory and pinned process/cgroup identity before effects.
   Refuse preexisting pauses, replicas, restarts and in-flight/unknown updater
   jobs. Persist original policy/retry/freezer/ingress state and intent.
3. Freeze exact updater then exact old backend; do not send the old application's
   shutdown signal as a drain proof. Verify actual `cgroup.events frozen=1` on
   exact recursive groups and unchanged PID/startTicks/boot/image/ID at every
   boundary. Disable restart on exact IDs and verify policy readback while the
   external daemon/recreate exclusion remains held. Isolate/freeze exact Caddy
   unless independently proven ingress exclusion makes that unnecessary.
4. Publish only a **held panel-host dispatch exclusion** receipt. Keep it bound
   to the real owner and maintained external exclusion; not just a stale
   observation or a callback that has already returned. Remote scope stays
   unknown. Signal/disconnection/partial API/unknown readback retains hold;
   never add an expiry that resumes dispatch automatically.
5. Before node mutation, known reversible abort restores only this owner's
   exact prior states while revalidating identities: policies while frozen,
   backend/Caddy last-mile state, updater last. Confirm every restoration
   before releasing local ownership. Unknown outcomes require held recovery,
   not best-effort thaw. Preexisting pauses were refused, never reversed.
6. A distinct destructive approval may terminate **only the already pinned,
   verified frozen old-backend cgroup**, not by name/PID alone or a broad
   process pattern. Require a proven exact-cgroup kill interface and verify
   recursive `populated=0`, no descendant processes, and disappearance of every
   old PID/startTicks identity; forbid replacement/auto-restart throughout.
   Reboot/identity drift/API ambiguity retains hold. Freeze is reversible;
   death is not. No automatic rollback/restart after this boundary.
7. Independently establish authenticated node-host writer exclusion and remote
   command/systemd completion, agent/scheduler inhibition, final flush and
   exact node backups before any transfer mutation. Local old-cgroup emptiness
   alone never advances this gate. Offline/unconfirmed nodes remain blocked.

## Verification

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s scripts/tests -p test_panel_maintenance_guard.py -v
```

Tests use fake Docker responses and disposable fake proc/cgroup trees, plus
self-signalled isolated **test subprocesses**, never real services. They cover
mid-observation recreate drift, ID drift, existing pause/freeze, nested updater
work, replica detection, read-only command allowlisting, durable ownership,
foreign/concurrent invocations, rollback from every known partial step,
SIGTERM/SIGKILL retained intent, corrupt/symlinked receipts and separate simulated
termination. These are local controller/model tests, **not** Docker freezer
integration, deployed maintenance, remote quiescence or rollout proof.
