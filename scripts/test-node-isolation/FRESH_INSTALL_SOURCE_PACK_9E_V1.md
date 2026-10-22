# Fixed9e offline source-pack product, v1

**Dormant offline publication only. Independent parent review is required before
integration. Nothing here installs, provisions, activates, accepts a physical
resource, establishes strict-3-second readiness, or authorizes PROD/GO.**

## Explicit selection and authority

The new entry is `fresh_install_source_pack_9e_v1.py --profile fixed9e-v1`.
There is no default profile, caller-supplied pin map, environment-based acceptance,
HEAD-derived source baseline, or acceptance auto-discovery. The sibling fixed
`fresh_install_source_pack_9e_v1_profile.json` is SHA-256-bound in product source.
It was fixed **after** the actual unchanged bundler built and independently
raw-byte-verified the new candidate:

- Source/builtFrom: `9e1b9897539750c3fef02b98055967d1a7edbbec`
- Source tree: `97c29e780e82a9cf8f102f984b7dc5deb872a368`
- Candidate manifest: `32b3c0fa25a490113e5c2ad8f96d805d2e0e33c651c4ee22b62ee45718e4802e`
- Candidate report: `3e83bdca1e347a0936610e23f63871638ef839a9121d9224378a3fe61408469b`
- File-mode inventory: `297212bda303017252f3a1e1a4cfd0fcfe045ff29fd407dbb9bc5f07867e02cf`
- Directory inventory: `fbe8f45b5d7db3dace90086462af7f5b5338ea25bb1bf1402e5cf869980b9ac5`
- 10,518 payload files: 328 committed sources, 9,509 dependency files,
  680 runtime files, no separate ELF files, plus fixed settings.
- Lock: 409 packages, 399 installed, 10 explicit platform-optional absences.

The earlier 7f47 diagnostic candidate happens to have the **same payload
manifest**. It is not this candidate: its source/report provenance differs and
is refused. No artifact has been relabeled. Both candidates and the older
10,516-file candidate remain separate and unmodified.

The profile explicitly enumerates every source-to-payload binding and every
host-source installation *intent*, including the network unit. Its manifest,
report, full path/mode/directory/count pins authorize offline bytes only. All
host intents and dependency intents must match the product exactly, including
JSON types; a rewritten outer manifest cannot authorize new content, mappings,
extra/missing files, or changed modes/directories. Host-source blobs are private
0600; payload modes are the original 0644/0755, directories 0755, outer pack 0700.

## Composition and audit boundary

The legacy producer/test and their BASE, builtFrom, pins, source exceptions,
guards and refusal semantics are untouched. This entry hash-checks and compiles
the unchanged legacy producer bytes solely to reuse its nonexecuting Git,
nofollow/raw-file IO, JSON, inventory, fsync and renameat2 no-replace primitives.
It does not invoke legacy `build`, `verify_candidate` or `verify_pack`, mutate
legacy globals, monkeypatch acceptance, or import application code.

Safe direct composition with legacy `build` is not possible: it resolves BASE,
candidate pins/counts, source exceptions and checker through module globals.
Changing those would silently alter the legacy acceptance boundary. Therefore
this new version openly duplicates the legacy publication orchestrator (the
`build` function), retaining its source/candidate identity snapshots, final
rereads, private complete stage, directory fsync, descriptor-relative Linux
RENAME_NOREPLACE, exact published-target readback, owned-only cleanup and
visible-but-durability/readback-unknown refusal. Candidate/source verification,
full pack checker, report and CLI are separate fixed9e implementations. This is
not a full copy of the old 641-line producer and is not an old guard relaxation.

The current repository HEAD is checked only for clean raw index/worktree state
and ancestry of the explicit source revision. It cannot choose acceptance.
Every included source is fetched from the fixed 9e object, checked against its
fixed profile pin, and compared to raw nofollow worktree bytes. Clean/process
filters, hooks, fsmonitor and replacement objects are not executed for admission.

## Actual artifact production and provenance

Evidence lives at:
`/home/leon/celerity-prod-release-20261019/full-production-20261022/current-source-pack-profile-child/`.
`build-inputs.json` records the exact CLI and all fixed input hashes;
`candidate-verification.json` records the complete raw source map, counts,
mode/directory pins and four intentional changes from legacy BASE:

| Source | SHA-256 of committed 9e bytes |
|---|---|
| `index.js` | `f991dc50765eb96104cb666c79005d1c0e4a55c393ca12635826108c13918c4d` |
| `scripts/test-node-isolation/coordinated_restore.py` | `8b8f8565b1d337a1f44a6554115b0e60f0a3d86dd24bfc3853e003dd481b2a76` |
| `scripts/test-node-isolation/fresh_classic_launch.py` | `63004840c16663d3c436866d8822b7a50d74de10076fdd5f897ccd8d04bd9e8d` |
| `src/modules/l2tpModelIndexReadiness.js` | `bf094ba8c6197ed39516b0ec197655ab256028e2cc5f5f124028b0d408c07f60` |

The two added dormant authority JS files remain part of the explicit 328-source
builder input. Source packaging is not an independent approval of their runtime
activation. The actual unchanged bundler hash is
`b5ab31238790df6dd1adb49623c4117503700c5666bf7fde1d10185ebf071f40`.
Dependencies use the old candidate's exact installed-tree bytes and the existing
snapshot; lock, runtime proposal, ELF map and settings are unchanged fixed
inputs. Snapshot membership/hash/size, every runtime target/hash/mode, settings,
full raw inventory, all source bytes and modes were checked after real build.
Installed snapshot pins do not claim npm archive integrity. The evidence
verifier initially expected ELF JSON `[]`, but the real empty map is `{}`;
that evidence-only assertion was corrected without rebuilding or touching the
published candidate. The first failed verification is not counted as success.

Actual candidate:
`/home/leon/.hermes/cache/scratch/c3-fixed9e-jxaruiv1/candidate`

Actual public CLI (run serially under `heavy.lock` and `hermes-heavy`, TMPDIR in
scratch; the output parent must already be private 0700):

```sh
python3 -B scripts/test-node-isolation/fresh_install_source_pack_9e_v1.py \
  --profile fixed9e-v1 build \
  --repo /home/leon/c3-current-source-pack-profile-20261022 \
  --candidate /home/leon/.hermes/cache/scratch/c3-fixed9e-jxaruiv1/candidate \
  --output /home/leon/.hermes/cache/scratch/c3-fixed9e-jxaruiv1/pack-fixed9e-v1
python3 -B scripts/test-node-isolation/fresh_install_source_pack_9e_v1.py \
  --profile fixed9e-v1 check \
  --pack /home/leon/.hermes/cache/scratch/c3-fixed9e-jxaruiv1/pack-fixed9e-v1
```

Do not reuse an existing output or recalculate pins to admit drift. Unknown
publication/readback remains unknown and never authorizes overwrite, rollback,
install, physical acceptance or GO. Tests use the real full candidate/pack, not
synthetic tiny acceptance fixtures. Legacy fixture tests remain explicitly
legacy tests, not proof of this actual artifact.

## Unexercised gates

No SSH, network request, live database, Docker, sudo, host service activation,
netns, mount, route or performance probe is performed. Installed host runtime,
loaded units, physical resource eligibility, controller namespace entry,
independent lease/resource publication, writer exclusion, privileged network and
data paths, remote worker SSH, DNS/egress, actual serving/public HTTPS, all-five
hold/handback, crash recovery and final acceptance remain unproven. The strict
3-second threshold is unchanged and awaits the operator's separate choice.
