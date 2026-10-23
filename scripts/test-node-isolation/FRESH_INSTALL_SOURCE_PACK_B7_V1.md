# Fixed-b7 offline source delivery, v1

**Offline bytes only. No installation, host access, activation, physical acceptance,
controller, policy/run-plan/lease issuance, release, or operational GO.** Every
report keeps `installed`, `physicalAccepted`, and `operationalGO` false.

## Fixed authority

Explicit entry: `fresh_install_source_pack_b7_v1.py --profile fixed-b7-v1`.
No default profile, environment acceptance, caller pin override, or HEAD-derived
acceptance exists. The sibling profile is fixed by SHA-256 in this entry.

- Exact accepted source: `b7be583ee6d8b095ed3f1556ec5906af3627b85d`
- Exact source tree: `6ad53c77a733ec44cdafae19f6f58ee178a405af`
- Profile SHA-256: `5dc8e440151007c2d10c59154f931669d3834428d2b23eb5f1a258e08451eb27`
- Candidate manifest: `8773ae45cbe1fac5b53f7b4f5a438dda0c3cbab1d7ed6ff0c4a179c4b3a8928d`
- Candidate report: `5935374bc3605fbf9fe9ffd97accde04df03aa79376c0c9dc111d66b63e4adbf`
- File modes: `297212bda303017252f3a1e1a4cfd0fcfe045ff29fd407dbb9bc5f07867e02cf`
- Directory modes/membership: `fbe8f45b5d7db3dace90086462af7f5b5338ea25bb1bf1402e5cf869980b9ac5`

The actual unchanged bundler builds 10,518 payload files: 328 exact committed
application/supervisor sources, 9,509 dependency files, 680 runtime files, and
one private fixed TEST settings input. There are 409 lock packages, 399 installed
versions, and 10 explicit platform-optional absences. The explicit application
inventory includes all current non-test `src/**/*.js` sources, including the
production maintenance runtime modules; no new application source was missing
from the previous inventory. Changed b7 sources are actually rebuilt, not old
payload bytes relabeled with a new revision/report.

The profile additionally fixes every source/host mapping, installed mode intent,
dependency and runtime inventory hashes, runtime target membership, settings
hash, observer pins, and network source closure. Observer `SOURCE_PINS` match the
mapped b7 physical/wrapper/unit/coordinator/fresh bytes exactly. Added host intents:

| Source | Fixed intended destination |
|---|---|
| `fresh_physical_observe.py` | `/usr/local/libexec/c3-test-fresh-physical-observe.py` |
| `fresh_network_client.py` | `/usr/local/libexec/c3-test-fresh-network-client.py` |
| `fresh_network_client_exec.py` | `/usr/local/libexec/c3-test-fresh-network-client-exec.py` |

These are **intents**, not installed facts. The independent fixed
`/etc/c3-test-fresh-physical-run.json`, its deadline, resource policy, acceptance,
network plan and lease remain external inputs. None is manufactured or packaged.

## Deliberate composition boundary

Both earlier producers, the fixed9e profile, tests, pins and source refusals remain
byte-for-byte unchanged. The new entry hash-checks and compiles the immutable
legacy `fresh_install_source_pack.py` solely for its nofollow raw IO, nonexecuting
Git plumbing, JSON codec, scanning, fsync and Linux RENAME_NOREPLACE primitives.
It never mutates acceptance globals or invokes legacy build/candidate acceptance.
The new publication orchestration is explicitly copied from fixed9e because that
entry resolves authority through module globals. Deltas are the separately named
profile/source/tree/schema/CLI, new fixed closure inventories and observer control.
No arbitrary acceptance map is exposed.

The source checkout must have clean raw HEAD/index/worktree state and descend
from the fixed accepted source. Every shipped source is fetched from that exact
b7 object, SHA-bound and compared with nofollow raw worktree bytes. Git executable
mode semantics are retained for checkout files (0644/0664 and 0755/0775); payload,
control, intended-installed and directory modes are independently exact-pinned.
No filters, hooks, fsmonitor, replacement objects or application imports execute
for source admission.

Output parent and pack are private 0700; host blobs/controls 0600; candidate
payload directories 0755 and regular files exactly pinned 0644/0755. The complete
private stage is checked, fsynced, published no-replace, and read back through its
exact published inode. A racing empty destination survives. Lost rename reply,
postpublication parent-fsync or target-readback faults remain unknown-retained:
no overwrite, rollback, installation, release or GO can follow from those faults.
An outer manifest rewritten to match an attack is not acceptance authority.

## Durable real artifacts and reproduction

All paths below are beneath:

`/home/leon/celerity-prod-release-20261019/full-production-20261023/fixed-b7-source-pack-child/`

- Full new candidate: `candidate-b7/`
- Full public producer output: `pack-fixed-b7-v1/`
- `build-inputs.json`, `recover_and_build.py`, `candidate-build.log`
- `candidate-verification.json`, `verify_candidate_and_profile.py`, and its log
- `recovered-snapshot.json`, `recovered-runtime-inputs.json`, `elf.json`, `source-allowlist.json`
- Producer/checker/test logs and final exact file/evidence hashes

The vanished historical scratch inputs are **not** claimed present. Recovery
first runs the unchanged fixed9e checker over the durable parent-reproduced pack:
`full-production-20261022/current-source-pack-profile-parent/reproduced-pack-fixed9e-v1/`.
Every borrowed byte is checked against that accepted pack and original historical
input hashes from `current-source-pack-profile-child/candidate-verification.json`.
The dependency snapshot is explicitly derived from its real alias-inclusive
installed bytes and sizes, never fabricated npm integrity. The original durable
runtime proposal hash is checked; only source pathnames are rebound to already
verified durable pack targets, retaining every target/hash/executable value.
Node, settings, lock, bundler and runtime-verifier hashes match original evidence.
Both dependency input and new copied output pass all 399 lock-exact versions.
The private settings file is never printed; only its hash is evidence.

The unchanged real `classic_root_bundle.py` is executed with these explicit
reconstructed inputs. Postbuild verification checks every source/raw mode,
dependency byte/size, runtime target/hash/mode, settings hash, and complete file
and directory inventory before fixing the profile. Final verification explicitly
flushes every payload inode as well. The initial evidence helper inherited a
**directory-only** `fsync_tree` yet labeled payload fsync complete; that initial
JSON is retained as `candidate-verification-initial-directory-fsync-only.json`
and is not payload-durability proof. The corrected helper performs checked
nofollow per-payload `os.fsync`, then directory fsync; its successful actual rerun
is `candidate-verification-final.log` and the final `candidate-verification.json`.
No candidate/profile bytes changed. Every new pack payload was separately fsynced
by the producer's checked writer. Older durable packs remain read-only provenance.

```sh
# Existing output refuses. Choose a genuinely fresh private output parent/name.
python3 -I -B scripts/test-node-isolation/fresh_install_source_pack_b7_v1.py \
  --profile fixed-b7-v1 build \
  --repo /home/leon/c3-watcher-release-review-20261023 \
  --candidate /home/leon/celerity-prod-release-20261019/full-production-20261023/fixed-b7-source-pack-child/candidate-b7 \
  --output /ABSOLUTE/PRIVATE0700/PARENT/FRESH-NAME
python3 -I -B scripts/test-node-isolation/fresh_install_source_pack_b7_v1.py \
  --profile fixed-b7-v1 check \
  --pack /home/leon/celerity-prod-release-20261019/full-production-20261023/fixed-b7-source-pack-child/pack-fixed-b7-v1
```

Run tests serially with the prescribed exclusive `heavy.lock`, `hermes-heavy`,
isolated Python and finite external timeout. Temporary adversarial copies live
only under `$TMPDIR`; the complete deliverables above are outside TTL scratch.
Tests use the actual full candidate/pack without pin or acceptance monkeypatches.
IO-only fault injection changes no acceptance authority.

## Final local verification

`full-tests-final.log`: **32/32 pass**, 610.236 seconds, natural Python exit 0
under the exclusive heavy lock/scope and 1100-second bound. All exact test names
are in `final-test-names.json`; `final-test-run-inputs.json` pins the implementation,
profile and test bytes and records the actual `/usr/bin/python3` 3.13.5 runner.
The public real producer and final separate public checker exit zero. Coverage
includes full source provenance, identical-payload wrong commit/tree, edited/raw
worktree and symlinks, profile/outer-manifest rewrites, host/observer/network maps,
host and dependency bool/int/float intent drift, payload/runtime/dependency bytes,
file/control/directory modes and exact membership, explicit profile/no override,
legacy refusals, existing/racing output, prepublication write/fsync refusal, lost
rename ACK, postrename parent fsync, and published readback unknown retention.
The first full run's one invalid old-artifact positive remains separate failed
evidence, not included in the final passing count.

## TDD and evidence qualifications

`tdd-01-red.log` observes the missing separately versioned product as a failing
assertion; `tdd-01-green.log` verifies the actual complete b7 candidate. Subsequent
full-artifact cases characterize preserved IO/publication contracts and new fixed
inputs; they are not represented as independent new RED cycles.

Retained mode experiment logs (`tdd-02-*`) are **not passing evidence**: a 0600
checkout was already refused by the reused safe-file reader; requiring literal
Git 0644 for every checkout then wrongly rejected the existing 0664 frozen
checkout. That experimental change was removed. The final test explicitly
characterizes 0600 refusal while preserving original Git executable semantics.
Exact output/intended modes remain mandatory and tested independently.

No broad legacy-positive suite is run against incompatible b7 source. The
unchanged fixed9e checker accepts its durable parent-reproduced artifact; its
producer refuses the new candidate with `CANDIDATE_PIN_MISMATCH`. The original
legacy producer still refuses b7 source without publication. The other historical
`active-enable-20261021/install-sourcepack/full-pack/` predates the current legacy
checker's `network-source-pins.json` control: its checker correctly refuses
`PACK_VERIFICATION_REFUSED`. `full-tests-01.log` retains the initial invalid
historical-positive expectation (29 successes, one error, natural exit 1); the
final test names that compatibility refusal explicitly rather than mutating the
old pack or weakening the checker. Independent parent source review/reproduction
is still required before integration.
Physical source/runtime/loaded-unit acceptance, UID/capability/mount/proc/netns/FD
rehearsal, trusted external plans/leases/exclusion, physical startup, actual serving,
worker SSH, public HTTPS, all-five hold/handback, post-lease ownership, crash recovery
and final operator acceptance remain unexercised. Nothing here changes strict-3s.
