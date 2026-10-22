# Network installation source closure — offline delivery only

This additive closure starts at parent `5546d0f0a1b3193a1d02576f250fbfb8d7c650e3`
(tree `db1b8102cc239cbf17065d787144c143371523ea`). It delivers the already
SOURCEPASS network implementation without modifying its five frozen source,
test and contract files. The new unit and pack changes still require independent
parent review before integration. No installation, activation or physical GO is
provided. Historical omission statements in `FRESH_INSTALL_SOURCE_PACK.md` and
`FRESH_NETWORK_CONSTRUCTOR.md` describe their earlier slices; this document
supersedes **only** their network source-pack/unit omission.

## Fixed source delivery, not new payload acceptance

The real `fresh_install_source_pack.py` producer now has 45 host-source entries.
Exactly these four entries are added to its previous 41-entry mapping:

| Source under `scripts/test-node-isolation/` | Fixed installed path intent | SHA-256 |
|---|---|---|
| `fresh_network.py` | `/usr/local/libexec/c3-test-fresh-network.py` | `6c6c5e3b528f12e5c2d578922c50fa2982906c1e97389948ecff7d55c4cb08ec` |
| `fresh_network_control.py` | `/usr/local/libexec/c3-test-fresh-network-control.py` | `ced8d6264424f65f5f9d6f5c9b1f9de731953d196026e513ed6e3f13a0cd88ac` |
| `fresh_network_exec.py` | `/usr/local/libexec/c3-test-fresh-network-exec.py` | `5fdb07e09177ce1b616d8506d325089e48e50560fee9a03757e4bc0850760167` |
| `c3-test-fresh-network.service` | `/etc/systemd/system/c3-test-fresh-network.service` | `c137ec5e3b156276cf4953bb866a03c8cd565cd5c913e3fc6426e9eebc3b9a1a` |

`NETWORK_SOURCE_PINS` is a separate source authority from `PHYSICAL_SOURCE_PINS`
and the old BASE. No digest is learned from a live scan, candidate or CLI input.
For these four sources only, committed blobs must match these fixed SHA-256s;
raw worktree bytes and executable modes must still match the committed blobs.
All other source acceptance remains unchanged. The entry's existing literal
`PINS` exactly match the first two rows; tests parse its AST without executing it.

The producer emits `network-source-pins.json` outside `candidate/root`, covered
by the complete pack manifest. The actual checker additionally requires that
map to equal its fixed authority, rehashes all four delivered blobs independently,
requires their stored mode 0600, and checks the complete fixed host-intent record
with type-exact canonical JSON. Rehashing the pack control manifest cannot
reauthorize changed network bytes, pins or destinations. Missing network closure
also refuses. This checker is for the new complete closure, not a migration or
relabeling of old packs. It is not a signature or installed-host verifier; the
checker source itself must be trusted independently.

The old controls are unchanged:

- BASE `eefa46f65943e6923f9fec6b43b44b7efd494c9f`;
  BUILT_FROM `df4ba411782f8ffa99daddd732d60e3da7272a27`.
- Payload manifest `b9793014e4fda7a53034394f2d02a077d645b49af9d08e70679e13ce85a614f6`.
- Original report `801866bbd3c8a603ac8d6949afe75cce33a988d88f7fafc845697c2783547079`.
- File modes `01fd43553623f672a910841908aef1271dde4df43fd16f7a1b52d9ec4de383fb`.
- Directory membership/modes `fbe8f45b5d7db3dace90086462af7f5b5338ea25bb1bf1402e5cf869980b9ac5`.

The original candidate and any earlier pack are never rewritten. The complete
payload, original candidate controls and bootstrap files map stay byte-identical;
new network source/control metadata stays outside the payload. Git non-converting
plumbing, disabled replace/hooks/fsmonitor/lazy-fetch, raw-byte cleanliness,
no-follow paths, single-link/xattr/mode checks, boundary rechecks, private staging,
fsync and `renameat2(RENAME_NOREPLACE)` publication/readback are unchanged.
Unknown publication retains the output; no overwrite or weaker rename fallback.

## Manual-only unit contract and prerequisites

`c3-test-fresh-network.service` runs exactly:

```
/usr/bin/python3 -I -B /usr/local/libexec/c3-test-fresh-network-exec.py
```

The installed entry receives **no arguments**. It requires real root identity and
isolated Python; neither environment nor protocol selects a path or command.
The unit has no Install section, WantedBy, activation dependency, automatic start,
Restart directive, ExecStartPre, ExecStop, ExecStopPost or cleanup/rollback hook.
There is no target attachment, timer, socket unit or restart-on-failure policy.
`Type=exec` confirms only interpreter exec, not constructor readiness or eligibility.
Manual start remains a future separately authorized operation, not a step here.

The operator must independently install trusted root-owned plan and lease at
`/etc/c3-test-fresh-network.json` and `/etc/c3-test-fresh-network-lease.json` and
retain the exact live root control-holder process. The lease binds the raw plan
bytes, generation, boot, holder PID/start and deadline. Fixed path existence
assertions are **not** validation or external writer exclusion. The unchanged
entry/control implementation checks the full trusted inputs and exact root
SO_PEERCRED holder; no network construction precedes its connection. Serving
and optional return pins still require separate explicit provision when needed.
No plan, lease, accepted physical resource policy, permission, GO or scan-derived
acceptance is manufactured or shipped by this closure.

Independently preinstall `/var/lib/c3-test-fresh-network` as root:root **0700**, and
trusted `/run/netns` with the required host namespace view. Preserve private
plan/config files and their trusted ancestors. The unit deliberately creates,
chmods and removes no directories: no StateDirectory/RuntimeDirectory management
can adopt, expose or delete a previous generation. The unchanged helper checks
trusted root paths (not exact 0700 on the existing state ancestor); independent
installation acceptance must verify that stronger private ancestor mode.
Generation directories are exclusively created 0700, journals 0600, and the
fixed socket `/run/c3-test-fresh-network.sock` is 0600. `UMask=0077` is retained,
`LimitCORE=0` disables core dumps, `PrivateMounts=no` avoids imposing a new mount
namespace incompatible with the entry's host-namespace contract. No guessed
capability, seccomp, private-network or filesystem sandbox profile is asserted.

`KillMode=process` and `TimeoutStopSec=5` do not prove child/writer quiescence:
manual stop or manager death is unknown and retains kernel resources/tombstones.
The unit supplies no memory, task, aggregate journal-size or serving-lifetime
budget. The implementation separately bounds input/reply frames to 1 MiB,
request frames to 4096 bytes, an initial owner connection to at most 3 seconds,
idle requests to at most 30 seconds and the independently supplied lease to at
most 600 seconds. These are protocol bounds, not hard systemd resource limits.
No RuntimeMaxSec kill is substituted for authority or safe recovery. Only the
existing explicit authenticated confirmed-abandon protocol may perform its
exact-owned cleanup; errors/EOF/timeouts never invoke automatic cleanup/rollback.

## Evidence and non-claims

Evidence is written only under
`/home/leon/celerity-prod-release-20261019/full-production-20261022/network-install-closure-child/`.
The fresh actual-candidate output name is `network-source-pack` there. Build it
from a clean committed source with the unchanged producer CLI and fixed original
candidate `/home/leon/.hermes/cache/scratch/c3-current-root-jaxwrjtj/candidate`.
There is no alternate-pin/count/source/destination CLI or fixture override in
that actual build. **The actual full-candidate CLI refuses with exit 2,
`REFUSAL BASE_SOURCE_DRIFT`; no new full pack is published.** Independent bounded
diagnostics identify four pre-existing parent-vs-BASE source mismatches:
`index.js`, `scripts/test-node-isolation/coordinated_restore.py`,
`scripts/test-node-isolation/fresh_classic_launch.py`, and
`src/modules/l2tpModelIndexReadiness.js`. The candidate still pins the old BASE
application bytes. All four new network-source pins validate independently;
these unrelated mismatches must not be repaired by widening this slice's
allowlist, changing old pins, substituting old worktree bytes, or fabricating a
successful publication. `actual-refusal-diagnostics.json` records exact old,
current and candidate digests. `actual-verification.json` records fixed-pin and
unchanged-candidate verification plus the actual refusal, **not** build success.
Resolving this full-artifact provenance bridge requires separately authorized
parent work. The disposable producer/checker regression packs do pass, but are
explicitly tiny test-only fixtures, not substitutes for the refused actual pack.

On admissible input, the producer verifies the stage and exact published inode;
subsequent independent offline readback uses `verify_pack` and checks entry pins.

Regression evidence records RED omitted source/unit mapping → GREEN actual
producer closure; RED checker accepted rehashed drift in each of helper/control/
entry/unit → GREEN fixed-pin refusal; RED bool/int/float intent coercion → GREEN
type-exact refusal. Additional tests cover committed source drift before
publication, map/destination/missing-intent drift, exact entry pins and unit
contract. Disposable tiny candidate pins are test-only, never actual-build proof.
The affected source-pack, network, physical and preparer unittest modules and
AST/diff checks are local-only. `systemd-analyze --generators=no --man=no verify`
checks unit syntax/dependencies without loading or starting a host service;
static validity is **not privileged eligibility**.

Still explicitly missing: independent installed runtime/source/unit acceptance;
operational controller entry into fresh netns; eligibility and independently
accepted lease/resource-plan publishers with execution-spanning writer exclusion;
privileged namespace/veth/nft/Caddy/data-path rehearsal; worker remote SSH,
external DNS/egress; actual serving/public HTTPS and all-five hold/handback;
crash/partial-generation recovery and independent final acceptance. Source
closure does not solve these gates. No SSH/network requests, Docker execution,
sudo/root action, host service activation or mount/netns/route/firewall effects
are performed. `physicalAccepted=false`, `networkPhysicalAccepted=false`,
`operationalGO=false`, `installed=false`, `provisioningImplemented=false` remain.
