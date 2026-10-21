# Irreversible combined TEST handback: bounded activation

Implementation only. This document is **not** installation, release, live thaw,
or candidate-admission permission. Public ownership schemas and
`TopologyConfigTransfer.handback` are unchanged. The earlier
`COMBINED_HANDBACK_BLOCKER.md` describes the superseded requirement that even a
failed acknowledgement after a writer-enable write retain classic exclusion;
its release-boundary characterization remains valid.

## Executable composition

The explicit root operator entry `settle-held-owner.js` calls
`HeldTestOwnerSettlement.handback`, using the pinned operational restoration
adapter, finite Python owner bridge and actual five-node coordinator. The
existing `settle` method remains a retained-hold checkpoint, not activation.
There is no HTTP switch, shell/SFTP/bootstrap fallback or runner grammar change.

1. Durably close candidate dispatch and retain the original per-node isolation
   and descendant-inherited runner flock descriptions. Restore all five originals
   with fresh guard checks; retain shared-host kernel/relaunch barriers.
2. Under that same authority, use the existing public generation-fenced owner
   transfer. Read all five exact owners/enrollments back with primary-majority
   reads, reject every outstanding lock/admission/work item, and preserve immutable
   enrollment/binding/adoption history. A partial owner transfer cannot activate.
3. Recheck all five live restoration holds and bounded shared-host eligibility.
   Write `handoff-commit.json` without replacement, fsync file and directory,
   and read back the exact all-five settlement proof, pins, current node peer
   PID/start identities, restoration intent and sole activation set.
4. Only after that irreversible COMMIT is acknowledged, persist the settlement
   journal's commit binding and `handoff-activation.json` attempt. Mark the live
   node protocols committed, then request the existing shared-host root guard
   to enable **only the pre-existing accepted classic backend cgroup**. Both the
   node holder and guard check the local commit bytes and same-holder identity.
5. Verify candidate/runtime/updater/relaunch exclusion and bounded activation,
   durably record confirmation, then explicitly complete the committed protocol.
   Node helpers, owner bridge and operator CLI have finite natural exit paths;
   no process.exit, unref or abandoned cleanup is used. Original node masks,
   candidate cgroup/admission and Docker/containerd/updater/relaunch barriers
   are not returned or reopened.

`LocalXray` is the shared physical panel host, not a sixth host. Existing native
Xray/PPP restoration and the dual-profile node path remain unchanged.

## Narrow supported activation set

Only a still-live accepted classic backend in its existing container can be
resumed. The safety preflight checks separate mount/PID/cgroup/network/**IPC**
namespaces, container-local proc and dangerous capability exclusion for every
existing payload process. Eligibility is deliberately narrower than ordinary
Docker defaults:

- Exactly one whole `/proc` mount must be **read-only**. Every other proc mount,
  subtree or alias is refused, including a read-only alias. Writable unmasked
  `sysrq-trigger` and `proc/sys` therefore refuse before COMMIT; no complicated
  mask or LSM inference is used. Duplicate mount targets also refuse.
- Accepted inventory now retains exact Docker `Mounts`, `Binds`, `VolumesFrom`,
  `Tmpfs`, `IpcMode` and `ShmPath` provenance. Missing provenance, any explicit
  bind/volume/tmpfs declaration or non-private IPC refuses. Old inventory pins
  cannot silently acquire new defaults.
- Every allowed tmpfs/devpts/mqueue mount must have a device identity absent
  from the host PID1 mount inventory, and `stat(2)` through the payload's root
  must confirm that exact major:minor. In particular, a host `/dev/shm` bind
  refuses even though its mountinfo type is `tmpfs`, root is `/` and target is
  `/dev/shm`. **Even Docker-private shm is refused if its superblock is visible
  in the host inventory.** A namespace-private, non-host-visible tmpfs with
  matching stat and accepted no-bind/private-IPC provenance is the positive case.
- Exact accepted inventory also pins `Devices`, `DeviceCgroupRules`,
  `DeviceRequests`, `Privileged`, `CapAdd`, `CapDrop`, `SecurityOpt` and `Runtime`.
  Device grants and added capabilities must be absent/null or explicitly empty
  lists (not arbitrary falsey values); privileged mode must be false. Missing
  `devicePolicy` in an old inventory refuses activation. These declarations are
  **not** treated as proof of Docker's effective device-cgroup/BPF defaults.
- The finite effective device policy is **no usable character/block devices**,
  not Docker's usual default-device allowlist. Every mount in the payload's
  current mount namespace, including the overlay root, private `/dev`, proc,
  masked files and any allowed file mount, must expose the **per-mount `nodev`**
  flag in actual `/proc/PID/mountinfo` (before `-`, not superblock options).
  Mount inventory is bounded to 1 MiB / 4096 records and fails closed on excess
  or read failure. Mounts must be private/unbindable: shared, slave/master and
  propagation tags refuse, preventing later incoming device mounts.
  This is an enforceable alternative to a recursive node scan or decoding
  device-cgroup BPF: it denies opening every device `st_rdev`, including
  preexisting nodes buried anywhere in the overlay or on a private tmpfs.
  `st_dev` alone proves none of this. There are **no exceptions for `/dev/null`,
  random devices or PTYs**; ordinary Docker `/dev` and overlay defaults refuse.
- All five actual per-process capability sets (`CapInh`, `CapPrm`, `CapEff`,
  `CapBnd`, `CapAmb`) must be zero and `NoNewPrivs` must be exactly 1. This
  excludes `CAP_MKNOD`, `CAP_SYS_ADMIN`, `CAP_SETPCAP` and capability regain by
  exec, UID changes or capset in the existing user namespace. NNP is inherited
  and irreversible. A new subordinate user namespace cannot unlock inherited
  `nodev` mounts; new superblocks owned by a noninitial user namespace are
  kernel-marked `SB_I_NODEV`. No claim is made that subordinate namespaces can
  never acquire their own namespace-local capability bits. Effective host
  device access remains denied even if new nodes are subsequently introduced.
  These capability/mount checks run before COMMIT, again before thaw, and in
  postactivation verification; no policy is installed or repaired by the guard.
- Before COMMIT, while the backend is acknowledged frozen, **every existing
  backend process must have exactly one task and zero descriptors** in both
  `fd` and `fdinfo`. For each process, **both root and cwd must have the exact
  mount ID of the unique checked overlay `/` mount**; same `st_dev`, inode or
  pathname is not mount identity. The guard follows each proc magic link with
  `O_PATH|O_CLOEXEC`, reads `mnt_id` from its own exact still-open
  `/proc/self/fdinfo/FD` and uses `fstat` on that same FD. Missing, malformed,
  duplicate inventory or unknown IDs refuse; detached/hidden same-superblock
  bind aliases refuse even with identical inode/device. Owned path FDs close in
  `finally`, including stat/read/parse failure; fdinfo reads are bounded to 4 KiB
  and only one path FD is held at a time. There is no `st_dev` fallback.
  Root inode and overlay device checks remain additional constraints.
  No socket, pipe, logging FD, `anon_inode`/io_uring or stdio
  exception is inferred safe. A retained descriptor to candidate `cgroup.freeze`
  refuses before activation, without writing or closing that descriptor. The
  same entry policy is repeated before the irreversible thaw. The internal
  committed projection skips this entry-only resource check afterward: runtime
  may legitimately create private descriptors/tasks; there is no retroactive
  repair, descriptor-closing operation or automatic refreeze.

Host bind/volume mounts, Docker/control sockets, writable cgroup mounts, killed
backends and missing candidate/relaunch barriers refuse **before COMMIT**. There
is no dead-backend relaunch, clean-container creation, unconditional
Docker/updater thaw or COMMIT-to-legacy-restore shortcut.

This is deliberately not a general host restoration mechanism or a full sandbox
sealing/physical-provenance proof from mountinfo. It relies on independently
accepted inventory and the existing trusted host-root/held-writer boundary;
retrospective memory-mapping or already-issued asynchronous kernel-work provenance
is not established here. Ordinary existing Node backends with threads, open
listeners or Docker logging FDs are **not eligible** for this variant. We do not
close their FDs, drop their threads or claim the deployed backend satisfies the
policy. A useful broader activation of such a backend needs separately reviewed
resource provenance or a clean activation primitive, outside this local slice.

## Failure semantics

- Before durable COMMIT: classic remains physically excluded. Per-node DB
  transfer can be partial; retain exact progress and do not roll it back or retry.
- Unknown COMMIT acknowledgement/fsync: `COMMIT_UNKNOWN_NO_ACTIVATION`; no
  activation command is sent. Inspect exact durable evidence independently.
- Known COMMIT followed by activation timeout, EOF, fsync/verification failure,
  controller death or partial completion: `COMMITTED_ACTIVATION_UNKNOWN`.
  Classic is now the legitimate owner and might have executed. Do **not** claim
  retained classic exclusion, automatically refreeze/rollback, retry release,
  reopen candidate admission or report full restoration success.
- Confirmed result: `COMMITTED_BOUNDED_ACTIVATION_CONFIRMED`, explicitly limited
  to `existing-classic-backend`; the returned retained set is not host release.

Existing commit/activation/restore intents, pending journal files and sticky
admission markers prevent replay; no recovery path adopts them as permission.
Independent reconciliation is required after any unknown result.

## Local evidence and limits

`test_irreversible_handback.py` exercises actual journal writes, fsync boundaries,
flock/OFD retention, finite node subprocesses, owner bridge grammar, root-guard
UDS dispatch and the actual `LinuxKernel.freeze` write/ack primitive against a
disposable proc/cgroup filesystem. An independent subprocess records execution
after the actual `freeze=0` file write; timeout and SIGKILL preserve durable
attempt/no-replay evidence without pretending the classic writer stayed frozen.
Kernel scheduling, physical host facts, UID/root and SSH are **SIMULATED**.

Kernel policy references: [`mount(2)` MS_NODEV/per-mount flags](https://man7.org/linux/man-pages/man2/mount.2.html),
[`PR_SET_NO_NEW_PRIVS`](https://man7.org/linux/man-pages/man2/PR_SET_NO_NEW_PRIVS.2const.html),
and Linux v6.12 `fs/namespace.c` (`lock_mnt_tree`, `can_change_locked_flags`),
`fs/super.c` (`SB_I_NODEV` for noninitial user namespaces), `fs/namei.c`
(`may_open_dev` and character/block open refusal). Retrieved source excerpts
are retained as `device-fix-kernel-reference.txt` alongside the test evidence.
Those references explain the alternative; local fixtures do not demonstrate
physical device denial. Tests create only ordinary scratch files and simulate
mount/capability/default-device facts. A constrained positive still reaches
actual `Fence.activate_classic`, retains all other fences and permits ordinary
file IO/new private runtime FDs/tasks. No device is created or opened, and no
Docker command, root operation, install or live activation is exercised.
The retained-mount regression additionally executes real Linux read-only
`O_PATH`/`fstat`/owned-fdinfo against an ordinary scratch directory through a
proc magic link, checks FD closure on malformed/missing IDs and read/stat faults,
models init/child root/cwd aliases at both entry boundaries, and exercises the
actual root guard's refusal with no COMMIT plus bounded positive activation.
The payload mount/proc topology remains simulated; no bind/detach mount or
physical device-denial experiment is claimed.

`heldTestOwnerSettlement.test.js` exercises public generation-fenced transfers
and exact all-five readbacks against isolated local MongoDB, including partial
DB settlement, postcommit journal/fsync/EOF faults, and the actual finite CLI +
JS/Python codec. Its physical/restoration authority is **SIMULATED**. Separate
five-node protocol tests exercise the real coordinator with disposable local
restorers; they are not a live Mongo-to-SSH cutover proof.

Evidence logs and source/log SHA-256 manifest are retained outside the repository
under `/home/leon/celerity-prod-release-20261019/evidence-irreversible-handback-20261021`.
Independent exact-source review, parent integration tests, accepted live physical
pins/eligibility and explicit release authorization remain required. No live
operation or installation was performed by this change.
