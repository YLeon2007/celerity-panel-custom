# Bounded natural watcher-release observation — UNACCEPTED source slice

This is source and local process evidence, not installation, physical acceptance,
TEST/PROD activation, network ownership handoff, or GO. No existing resume guard,
resource policy, acceptance schema, Coordinator or all-five protocol is changed.

## Exact missing caller contracts now implemented

An independent operator must select and install the **fixed** input
`/etc/c3-test-fresh-physical-run.json` before starting the original watcher and
constructor. Its closed JSON object contains only:

- `version`: exact integer `1` (not boolean/float).
- `context`: `"test.infograd.online"`.
- `bootId`: the current kernel boot UUID from `/proc/sys/kernel/random/boot_id`.
- `deadlineMonotonicNs`: positive exact integer absolute **CLOCK_MONOTONIC**
  nanoseconds, chosen independently before launch. It must be in the future and
  no more than 600 seconds from initial capture. CLOCK_BOOTTIME/wall-clock values
  are not substitutes.

All path components must be root-owned, non-group/other-writable, no-symlink and
without xattrs. The leaf must be a single-link regular file with **no write bits**
(e.g. root:root `0444`), at most 16384 bytes. Duplicate keys, missing/extra fields,
foreign boot, stale/over-ceiling/type-coerced deadlines, same-byte inode replacement,
metadata or byte drift refuse. The captured raw-byte digest and inode/metadata
snapshot are rechecked; checks do not select or renew a deadline. There is no plan
publisher, installation command, default timeout fallback or environment override.
Root/operator must preserve the original input throughout the run.

`exec_main` and `watch_main` consume this input before rendezvous. Each preparation
phase ends at `min(original absolute deadline, its entry + 120 seconds)`; the
watcher's registration, stopped acceptance wait, finally readback and observer
all stay under the original ceiling. The old post-stop `monotonic()+600` renewal
is removed. Constructor source verification cannot authorize construction after
its preparation ceiling. The watchdog still bounds the preparer via its existing
pidfd and owned-only abandonment path. No kernel/proc syscall hard latency bound
is asserted: these are checked cooperative ceilings with bounded socket/systemctl
waits, and unknown outcomes remain refusal.

The existing unaccepted `generation.json` additionally contains
`watcherObservation:{pid,start,bootId,invocationId,deadlineMonotonicNs,runPlanSha256}`.
Its enclosing generation still binds the supervisor PID/start and complete files
map digest, with `accepted:false`. The watcher derives its own real PID/start,
requires actual loaded fixed-unit `MainPID == ExecMainPID == self`, and reads the
actual `InvocationID` through a fixed read-only `/usr/bin/systemctl show` query.
Unchecked `INVOCATION_ID` environment values are never authority. Unit type,
restart policy, fragment, drop-ins, daemon-reload state and cgroup are checked.
This is **observation**, not a new acceptance field or an inventory producer.

## Observer and caller ordering

`fresh_physical_observe.py` is a fixed root-only **no-argument** source entry,
intended fixed installed pathname
`/usr/local/libexec/c3-test-fresh-physical-observe.py`. No pack/install intent or
service activation is added here; a separate reviewed installer/acceptance owner
must provision it and its pinned closure. It loads only embedded digest-pinned,
trusted physical/wrapper/unit/coordinator/fresh-consumer bytes. It never creates a
Coordinator or calls its network/protocol paths. Missing, changed or mismatched
installed closure refuses; the current-source pins do not repin any old pack.

Required independent ordering (not implemented by an automatic controller):

1. Hold external exclusion of **all** possible resumers/Coordinators. Independently
   provision source closure, resources, private network and original run plan.
2. Start the original fixed watcher and constructor through independently reviewed
   unit handling. This source task does not start/stop/install units.
3. At the stopped held-lock barrier, independently finalize the full existing
   accepted policy in the host and supervisor root. Preserve its original files.
4. Start the observer **while the original watcher is alive** and before releasing
   external exclusion. The observer captures its original pidfd/start, immutable
   generation, independent policy/resource plan, root/control path identities and
   original deadline. It cannot adopt an already dead or restarted watcher. A
   missing/not-finalized policy refuses, rather than capturing inventory itself.
5. Independently supply the existing exact physical acceptance input. Neither
   watcher nor observer writes that input or policy. Observer can wait concurrently
   while acceptance is visible and watcher finally is still running.
6. Only natural successful original watcher death may yield
   `WATCHER_NATURAL_RELEASE_OBSERVED_UNACCEPTED` with `physicalAccepted:false` and
   `operationalGO:false`. This remains observational data. Independent final
   physical acceptance and external resumer exclusion remain mandatory through the
   unchanged separate one-shot resume/physical recheck flow.

Terminal observation requires original pidfd death, exact retained InvocationID
and ExecMainPID, `MainPID=0`, `ActiveState=active`, `SubState=exited`, numeric
`ExecMainCode=1` (**CLD_EXITED**, not string `exited`), `ExecMainStatus=0`, and
`Result=success`. An empty terminal ControlGroup is permitted only with MainPID0
and a terminal substate: local read-only real-systemd probes found active/exited
oneshot units with this representation. Running identity still requires the fixed
nonempty cgroup. `Result=success` on a running service is not termination.
A running property snapshot can precede original pidfd death or PID1's terminal
publication. That exact already-pinned invocation is reobserved under the same
original deadline; this never accepts a running result, adopts a replacement or
renews the budget. Death racing the subsequent live proc read crosses to the
same terminal query path only when the original held pidfd independently reports
death. Missing terminal publication still expires/refuses.

Natural success is interpreted against the pinned actual watch_main source:
return occurs only after checked finally disposal, with no swallowed cleanup
errors. Observer also requires absent registration socket, unchanged retained
resource/control paths, exact acceptance/policy digest, repeated terminal property
readback and original supervisor still stopped. The existing read-only
`fresh_classic_launch.validate`, `Platform.prepared` (source/files, root/mounts,
routes, namespaces, unit/cgroup, identity and descriptors), plus physical
held-lock/preparation predicates are reused. The latter performs only its existing
nonblocking lock-presence probe (opens lock read/write but writes no bytes); it
never acquires release/cleanup authority. Source/input/deadline checks bracket
awaited queries and consumer readbacks. Rechecks are observations, not a substitute
for independently held resumer exclusion or continuous physical authority.

Lost/failed/signaled/crashed invocation, foreign MainPID/ExecMainPID/start/boot,
replacement InvocationID, plan/generation/source/policy drift, early resume,
deadline, cleanup failure, missing/late capture or incomplete consumer evidence
means **unknown retained/refusal**. No SIGCONT, COMMIT, acceptance/policy write,
resource cleanup, unit mutation, arbitrary shell/verb dispatch, network write,
daemon, heartbeat, mutation retry/adoption or terminal ownership handoff is provided.

## Local regression evidence and immutable old pack

Tests run with isolated Python (`-I -B`) and naturally exit under a finite external
budget, serialized exclusively by the prescribed heavy lock/scope. They exercise
real `exec_main -> watch_main -> finally -> observer` orchestration with real
processes/pidfds/start ticks, seqpacket registration, SCM_RIGHTS/control FD,
held flock, SIGSTOP, files and cleanup. They pause finally after independent
fixture acceptance is visible while the original watcher remains alive; release
is not returned until natural death. Negative cases include post-acceptance
cleanup failure, SIGTERM/SIGKILL, stale/replaced invocation/PID/start, early external
fixture resume, original deadline expiry/no renewal, immutable input drift,
resource-path replacement, malformed schemas, and constructor preparation overrun.

Root ownership/UID/GID, installed paths, systemd responses and privileged
namespace/mount/cgroup facts are explicitly **modeled** in those fixtures. They
are not actual installed-unit or physical-kernel acceptance. The older constructor
umask/source-copy/anonymous-FD/preparer tests remain separate real local evidence.
New negative tests that already passed existing checks are characterization,
not invented RED runs; preserved RED logs cover newly missing source behaviors.

The legacy `fresh_install_source_pack.py` and its accepted PHYSICAL_SOURCE_PINS,
BASE/candidate and network pins remain **unchanged**. Building from these current
changed physical sources against that old pack intentionally refuses
`PHYSICAL_SOURCE_DRIFT` before export. The old frozen compatible positive is
replayed from commit `af7cadc5c72369c03ff15949aa44d85c3121466e`, checked against the
unchanged old pins, and built in an isolated fixture. That is OLD pack compatibility,
not export/delivery of the new observer or new runtime sources. The complete legacy
pack suite can be replayed only with that explicit frozen-physical fixture adapter;
its original current-byte fixture is no longer a compatible positive.

Remaining external gates: independently reviewed new-source artifact/installation,
actual loaded systemd invocation rehearsal, privileged full constructor/network and
application execution, independent full physical policy/acceptance, resumer
exclusion, existing resume/all-five handback, and post-lease network ownership.
None is authorized by the observer output.
