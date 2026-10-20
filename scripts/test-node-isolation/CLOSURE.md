# One-way TEST candidate/dispatch closure — no handback

**Source/local tests only. No installation, SSH, live host changes, thaw, old
writer restart, ownership/admission release or combined handback.**

This adds two finite **root-operator** commands to the existing helper. They are
not runner opcodes and are not available to the forced-command application user.
The existing runner argument and readiness payload/receipt policies are unchanged.
The operator, installed source pins and root-owned authority paths remain TCB.

## `close-dispatch` on each TEST node

The existing independent recovery guard, post-drain confirmed maintenance and old
writer exclusion must still be held. The command acquires/retains the exact
`/var/lib/c3-test-node-isolation/lock`, requires another independent operator
session and challenges recovery, then durably closes forced dispatch by creating
root-owned mode-0600 `/var/lib/c3-test-node-isolation/restore-admission.json`:

```text
{version: 1, planHash, maintenanceId, nodeId, bootId, state: "closed"}
```

Those are exactly the keys; no caller-supplied acceptance booleans or operation
IDs. The existing atomic write fsyncs the file, renames it and fsyncs its parent.
An unfinished `restore-admission.json.next` is a sticky refusal. Any existing
marker (including invalid/empty/foreign/dangling-symlink markers) blocks actual
`Engine.dispatch` before journal mutation or subprocess effects. This includes
requests delivered over an already authenticated SSH channel, `status` and every
finite readiness opcode. A valid existing marker can only be **read** by another
close attempt; it is never replaced, erased or reopened automatically.

While the outer lock is still held, the command acquires the actual runner's
profile-global `/var/lib/celerity/topology/fences/<profile>/lock` and reads the
**current on-disk head**, not an old generation's `status` receipt. All known
generations must be closed, all commands completed, and each generation must
have an exact bound close receipt with terminal/quiescence fields. Missing
journals/locks, unfinished writes, live inherited runner locks, pending/unknown
commands, missing completion evidence, boot/binding/head drift and corrupt state
refuse. Even a missing/virgin runner is **not** a positive default. No runner
journal is manufactured by the observer. Live systemd-job exclusion is also
rechecked through the ordinary maintenance hold.

The runner mutex spans the final recovery/exclusion/marker readback and final
unchanged-head readback. A positive `nodeEffects: "drained"` covers only
protocol-admitted effects on **this node**; it is diagnostic data, not transferable
restoration authority. Unknown completion leaves the durable admission marker
closed. `assert_held` remains read-only usable for the independent controller's
restoration reader, but the legacy `restore-masks` path refuses any closure
marker. This slice implements no new restoration path.

## `close-candidate` on the shared TEST host

The same owner-bound foreground `host-hold` supervisor receives one finite
root-peer UDS frame: `nonce`, `command: "close-candidate"`, `owner`, `planHash`.
No arbitrary host commands, restore, thaw or owner release are accepted. Fresh
SO_PEERCRED PID/start, nonce, live session/recovery and independent kernel/journal
checks remain mandatory. The old `nonce`-only check frame remains unchanged.

The owning real `Fence` writes/fsyncs `freeze-candidate` intent **before** writing
`cgroup.freeze=1` on the exact accepted `c3-test-candidate` scope. It waits for
kernel acknowledgement, proves the final accepted descendant tree using the
existing pinned init, inherited-session and stable ancestry rules, pins the final
members, and verifies every old fence again. Mongo, Redis, Caddy, original proxy
survivors and native Xray/PPP remain outside this additional freeze operation.
The candidate cannot execute new ingress or dispatch; network connections may
remain queued, and nothing in this primitive ever thaws it to execute that queue.

The held journal allows only one additional projection: the exact candidate
closure/group and its independently checked final members. Future checks require
that exact tree to stay frozen. An orphaned Docker exec in a distinct session
still refuses; no payload/cgroup-wide exemption replaces the existing B1 rules.
EOF, timeout, signals, failed intent/readback/fsync and partial kernel transition
retain old fences and any candidate freeze already performed. Once the candidate
is closed, even standalone `Fence.restore` refuses.

The shared helper then performs the actual **local** node `close-dispatch` under
the same outer lock. It does **not** infer remote effect completion from freezing
the candidate. This implementation has no trusted live remote lock/head reader;
therefore its assembled result is explicitly `partial-unknown-retained`,
`candidate: "closed"`, `localNodeEffects: "drained"`, `nodeEffects: "unknown"`,
`unknownNodes` containing the four dedicated TEST IDs, and
`handbackAllowed: false`. CLI exit status is **75**, not success. If even local
closure cannot be established, it refuses outright and keeps the fences.

Calling each dedicated node's `close-dispatch` can establish its local primitive;
copying those replies into a shared JSON file cannot turn them into a combined
execution-spanning proof. A separately reviewed controller must hold/observe the
actual remote closed markers, outer locks and current runner heads/flocks across
any future restoration. Remote evidence is never mocked positive by default.
Original-byte restoration and durable control-plane owner/lock/admission
settlement belong to other slices. `SHARED_HANDBACK_UNAVAILABLE` remains intact,
including after destructive old-backend termination.

## Reproduce local evidence

```sh
C3_XRAY=/home/leon/xray-v26.3.27/xray PYTHONDONTWRITEBYTECODE=1 \
  python3 -m unittest discover -s scripts/test-node-isolation -p 'test_*.py' -v
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s scripts/tests -p test_panel_host_freezer.py -v
```

New tests exercise actual disk/fsync/flock and actual V2 runner code in a local
user namespace; actual Unix socket nonce/PID/start and foreground owner framing;
the real Linux verifier against disposable proc/cgroup **file fixtures**; sticky
marker and partial transition failures; inherited-session/orphan refusal; local
versus unknown remote results. UID, SSH, systemd and kernel acknowledgements are
explicitly simulated where stated. No disposable privileged kernel drill or live
maintenance was run. Existing nonempty Xray RPC/PPP dispatch regressions are real
local tests, not deployed-host authority.

RED/GREEN logs and pinned source copies are preserved outside TTL scratch under
`/home/leon/celerity-prod-release-20261019/evidence-candidate-drain-20261020/`.
