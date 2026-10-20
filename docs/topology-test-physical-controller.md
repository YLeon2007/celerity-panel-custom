# TEST physical controller and read-only installed-runner attestor

Source-only. No host/node installation, SSH, live TEST mutation or PROD activation
was performed by this change. This adapter does **not** close serving rollback,
shared-host handback, nonempty user/PPP acceptance or production activation.

## Executable path

`index.js` already calls `createL2tpRootLifecycle()` with its ordinary defaults.
The default `createL2tpRootHostDependencies` now lazily selects
`createRootTestPhysicalAuthority`. That selector requires all of:

* exact TEST `PANEL_DOMAIN=test.infograd.online`;
* `L2TP_EXECUTION_ENABLED=true` and `TOPOLOGY_TEST_EXECUTION_ENABLED=true`;
* neither production execution opt-in;
* a private, independently accepted root-owned configuration at the **fixed**
  `/etc/celerity/topology-test-physical.json` path.

Flags only select eligibility. They do not authorize anything, choose the config
path, supply physical pins, mint a controller, adopt owners or enroll nodes.
Missing config returns no authority; malformed/untrusted config refuses. Disabled,
wrong-host, missing-authority and conflicting-PROD paths make zero adapter SSH
calls. No SSH is opened at module import or dependency construction.

The same `topologyExecutionAuthority` flows through the existing panel host,
`TopologyExecutionAuthorityLifecycle`, actual binding store and default executor.
It selects only `preinstalled-attested-v1`. No bootstrap, SFTP, shell inspection,
runner install, node mask/stop, host kill, thaw or restoration fallback exists.

On first held use the adapter opens five separately pinned maintenance SSH
channels to the exact four dedicated TEST addresses and shared
`212.119.42.100`. They use `c3-test-operator:2222` and the **fixed** command:

```
/usr/bin/sudo -n /usr/local/libexec/c3-test-physical-attestor
```

This is a read-only operator channel, **not** the command transport. The executor
still uses its separate existing credential source for `c3-test-runner:2222` and
the unchanged fixed V2 forced-command parser. Parent installation must provision
both keys correctly; this adapter does not rewrite HyNode credentials/endpoints.
Raw SSH host-key wire bytes are SHA-256 verified before authentication. Auth,
connect and readback have bounded deadlines; an app observation request has 15s,
and the finite helper interrupts an entered request after 12s without restoring
external state.

Each fresh nonce exchange runs the actual installed isolation engine's
`assert_held`: current process/unit/session exclusion and live root-peer
nonce/PID/start recovery roundtrip, not its historical status JSON. Shared mode
requires the separately reviewed shared helper's real `host_hold()`:
owner-bound host socket, actual live freezer supervisor, current independent
kernel/cgroup/systemd readback, original backend identity and survivor policy.
The app pins the **same** recovery and host supervisor identities for its entire
lifetime. Replacing a guard, boot, plan or endpoint cannot silently reconnect.
The shared helper must be installed separately by the parent; the dedicated-only
baseline intentionally returns `SHARED_HOST_ATTESTATION_HOOK_REQUIRED` internally
(and a redacted retained-unknown public result), not a fake shared proof.

The external operator must already own and maintain the real `guard` channels,
bidirectional recovery echo clients, shared `host-hold`, persistent isolation and
post-drain `confirm-access` boundary. This adapter **attaches only to a currently
held scope**, it neither recreates/adopts guards nor establishes fresh exclusion
from old receipts. Existing enforcement guards remain responsible for the kernel
hold between app checks. App observer channels remain open across serial worker
invocations; their EOF/error/timeout permanently poisons this controller.

## Independently accepted private pins

The root config is JSON, version 1, with this shape. Placeholders are deliberately
not supplied as a runnable inventory:

```text
version: 1
executionContext: { target: test, hostIdentity: test.infograd.online }
nodes: exactly one entry for EACH of the five fixed TEST node IDs
  nodeId, targetProfile
  endpoint: { ip: exact literal TEST address, port: 2222, username: c3-test-runner }
  physical: { machineId, bootId, sshHostKeySha256 }
  maintenanceId: canonical UUID used by the installed node plan
  planHash: SHA256 of installed accepted isolation plan's canonical sorted JSON
  guard: { pid, start, socket: /var/lib/c3-test-node-isolation/recovery.sock }
  operatorKeyPath: absolute private key path beneath /etc/celerity/
host:
  owner: canonical UUID of the held shared freezer
  guard: complete accepted host-guard identity
    { pid, start, socket, owner, planHash, session: { pid, start } }
  backend: { instanceId: exact container ID, pid, processStartTime: startTicks }
```

All config/key ancestors must be root-owned, non-symlinked, non-group/world
writable; files must be regular, bounded and not world accessible. A read-only
root-owned group-readable mount may supply them to the app account. Treat root
administrators and the independent operator as the existing trusted computing
base. Do not automatically capture a response and bless it as the accepted pins.
Review the complete host capture, source hashes, physical inventory, alias and
endpoint reservations and installed plans first. Unique machine/key reservations
and the exact five-node selection exclude cross-paired aliases; the actual
binding store still supplies global immutable enrollment and same-transaction
mutable-node checks. No database/request/environment fields replace these pins.

Parent-only provisioning must additionally install `physical_attestor.py` as
root-owned, non-writable `/usr/local/libexec/c3-test-physical-attestor`, grant only
that fixed no-argument sudo command to the operator and retain backups of each
changed path/policy. The forced runner account's grammar is **not widened**.
The helper uses fixed paths/imports and offers no fake-root/environment/command
selector. This repository does not install or enable any of those files.

## Observed proofs, not expected-value echo

`physical_attestor.py` reads physical machine/boot/raw host-key identity afresh,
then descriptor-walks current installed files without symlinks/writable ancestors.
It hashes the **installed runner bytes**, observes root:root mode 0750, and checks
the role's root:root mode 0755 configuration directory. For bridge/relay it hashes
the current bridge unit and observes the actual loaded fragment/no-drop-in state.
The app validates those observations using the existing exact shipped
`withAttestedPreinstalledRunner` contract. It does not substitute the shipped
hash into a missing observation. Portal never inspects an unrelated bridge unit.

The helper reads the real runner journal under the actual runner flock, refuses
unfinished/uncertain commands and reports the current head. Initial pre-enrollment
requires absent journal/lock and the runner's same finite legacy-state absence
check. For a successor it reads the exact persisted predecessor close command and
returns the runner's exact read-only `status` projection. The app validates every
terminal field/command ID/binding/boot against the actual durable challenge and
checks the current head, not merely a historical closed generation. Observation
never invokes the runner or creates journal/lock files.

The callback's binding/challenge data are correlation only; independent node,
endpoint, boot, maintenance, old-backend and installation facts come from current
accepted-and-checked observations. Proof IDs are fresh receipt identifiers, not
physical facts. The scoped checker rereads current installation/exclusion before
and after awaited work; escaped checks cannot authorize later dispatch. Failed
readback, unexpected reply/nonce, guard loss or uncertainty poisons the scope and
controller. Runtime stop first joins work, then closes only observer channels.
No failure, EOF, timeout or stop touches external holds, admissions or locks.

## Local verification and remaining gates

Tests explicitly label UID/physical/kernel/systemd/SSH fixtures as simulated.
They run real subprocess nonce channels, current file hashes/metadata and actual
schemas. The root integration test goes through `createL2tpRootLifecycle` → real
startup/panel host/runtime/store/default executor/worker, with local Mongo and the
real fake-root runner, and completes two serial generations with close/status
and an exact predecessor readback. Its pre-existing owner fixture is simulated;
this is not a live owner-transfer or nonempty user/PPP/client-traffic acceptance.
Python tests separately exercise the actual finite installed-file readback.

Remaining parent gates are explicit:

* independently review/install/pin the shared helper, this helper, all five node
  plans and current guards; maintain all external foreground recovery channels;
* supported owner adoption and explicit `preEnroll` before worker execution.
  This controller implements binding and preinstalled-runner authority, **not**
  `TopologyConfigTransfer.withVerifiedMaintenance`. That separate operator hook
  must retain original config/unit bytes and actual service-state readback under
  the same hold; no raw adopted-row seed or copied snapshot is an alternative;
* literal shared endpoint and correct separate runner credentials in real HyNode;
* separately integrated finite nonempty user/PPP side-effect closure;
* actual live TEST physical/traffic, serving rollback and unchanged-services tests;
* **safe owner-specific shared-host recovery/handback**. Current shared
  `restore-masks` refuses `SHARED_HANDBACK_UNAVAILABLE`; ordinary freezer restore
  is valid only for its nondestructive pre-node-work abort, never after kill.
  This adapter adds no post-kill control-plane handoff and cannot authorize thaw,
  old-writer restart or lock/admission release from a receipt. A full live cycle
  remains NO-GO until that separate enforced handback/recovery path is delivered.

PROD remains unsupported and closed at its existing startup/preclaim gates.
