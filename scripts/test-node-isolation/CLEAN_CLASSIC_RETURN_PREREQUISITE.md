# Clean classic return: unresolved trusted launch construction

**Status: BLOCKED / NOT IMPLEMENTED.** This is a bounded prerequisite report and
executable refusal characterization, not a new launcher, acceptance PASS,
installation instruction or authorization for active TEST. PROD is unchanged.

## Exact unresolved prerequisite

`INDEPENDENT_TEST_CLASSIC_LAUNCH_RESOURCE_BOUNDARY`:

Supply and independently accept one concrete, root-owned, one-shot launch
construction for shared TEST, independent of frozen Docker/containerd/updater
and the old Node. Its input must be an independently pinned fresh root/resource
set, not a copy of an old process's root/cwd, open descriptors, mappings or a
receipt claiming readiness. The current accepted inventory supplies **none** of
this new construction. In particular it does not designate:

- A fresh executable + ELF interpreter/libraries + full application/dependency
  source root + settings/environment closure, protected against replacement
  through exec and startup. An executable hash alone does not pin Node code.
- A launch UID/GID/capability/NNP and filesystem/device/control-socket policy
  which cannot write the retained candidate/admission/relaunch fences. A root
  `Popen` with `close_fds=True` clears neither host-root filesystem authority nor
  writable host mounts. A mere cwd change is not a new root boundary.
- A separately owned fresh cgroup and exact network namespace/listen/ingress
  mapping. A frozen old Node can still own its listening socket. A new host
  loopback port is not evidence of restored TEST ingress. Reusing an old
  cgroup/path or old Docker root is not independent fresh acceptance.
- An independently supervised lifetime for the new process after the finite
  handoff channel exits; exact new PID/start/cgroup identity and a serving
  observation bound to that process/socket while candidate remains excluded.

**Named additional operational scope:** provisioning and accepting that exact
TEST-only fresh execution root, identity, cgroup/network/ingress and independent
supervision boundary, including its artifact pins. No such system changes are
permitted by this local-only task. This report does not assert that source
implementation is impossible; it states that a *safe supported construction was
not established or implemented in this slice*. Adding a simulated constructor
would not resolve the named prerequisite. Do not substitute arbitrary executable
paths, caller-supplied launch callbacks, success receipts or existing Compose.

After this prerequisite is resolved, the narrow source slice is to implement
and review an actual exec/serving path through the **same held** coordinator and
root guard, before physical rehearsal. No general launch framework is proposed.
The local test below is not that source implementation.

## Current concrete source boundary

- `shared_host.validate_plan` accepts only the original exact Docker cgroups and
  accepted inventory. `verify_record` derives exact permitted projections; it
  cannot admit an unlisted freshly launched writer.
- `coordinated_restore.Coordinator.commit_handoff` checks fresh all-five holds,
  then `activation-preflight`, then durably commits the sole activation set
  `['existing-classic-backend']`. Node peers and the root guard bind that COMMIT
  to the same held PID/start/plan. A new launch must not reuse this activation
  set or turn its existing acknowledgement into fresh-process authority.
- `shared_host.serve_hold` has no launch operation. Its prepare/activate path
  calls the unchanged sealed-container predicate and existing-backend thaw.
- `Fence.activate_classic` refuses threads/descriptors **before** its journal
  write and enable effect. Its ordinary Node ineligibility is intentional.
- Existing restoration, public DB owner settlement, durable COMMIT and
  postcommit unknown/no-replay behavior are not missing and are not modified.

The proposed shortcut of simply execing Node beside these retained holds has
no independently accepted root/resource/ingress construction. No such shortcut
was added. No ordinary-Node eligibility predicate was weakened.

## Executed local characterization

`test_clean_classic_return_gate.py` invokes a real installed Node executable on
an actual generated JS source/settings pair, verifies `/proc/PID/exe` inode
identity, and makes two real HTTP requests bound to that PID and a fresh token.
It records executable/source/settings digests, PID/start/cgroup, root/cwd inode
observations and actual task/FD counts. Each Node exits naturally after its
second response. The target is disposable **test serving**, not classic return.
It has no COMMIT/owner authority. These observations are not durable source pins
for a new production or TEST launcher.

The unchanged actual eligibility predicate separately reads this live Node's
real task and descriptor directories in the existing simulated payload fixture:

1. Real Node threads refuse with unchanged guard journal and no enable write.
2. Real Node descriptors refuse even when task topology is explicitly modeled
   as single-task, again without altering the original hold.
3. Five real node-restoration subprocesses hold actual original/runner OFDs;
   the shared peer runs that actual predicate over the real Node task directory.
   It refuses preflight before COMMIT or activation intent. All five flocks are
   checked while the peers are alive; after the refusing peer exits its OFDs
   really close. The other four remain held until coordinator teardown. This is
   **not** a claim that flocks survive process death. Sticky admission and modeled
   kernel freezes remain closed; original node files/restoration code are used.

Physical namespaces/mounts/freezer, root/SSH/systemd authority and settlement
proofs are explicitly **SIMULATED**. Actual processes, exec, HTTP, proc-resource
reads, journals/fsync and flocks are real. No mount, namespace, kernel-freezer,
Docker, SSH, live DB, install or service operation is performed.

## Unmet acceptance and stop rule

There is no implemented clean launch, hence no clean-launch RED→GREEN or
postlaunch timeout/EOF/fsync/signal/death/cleanup/replay acceptance result.
Passing refusal characterization and old thaw regressions do **not** satisfy
those criteria. Before COMMIT retain the full original physical hold; after any
future known COMMIT and possible launch classify failures as committed activation
unknown, never success, rollback, retry, refreeze or candidate reopening.

Keep active TEST blocked. Do not start a maintenance hold requiring the user to
recover it at night. No PROD or parent integration worktree changes are made.
