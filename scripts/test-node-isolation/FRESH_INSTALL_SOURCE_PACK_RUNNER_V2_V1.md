# Fixed runner V2 offline source delivery, v1

**Conditional offline preparation only.** No installation, remote/root operation,
source acceptance, integration, activation, physical acceptance or operational GO.
All reports retain `installed=false`, `physicalAccepted=false`, `operationalGO=false`.

## Fixed source and closure

Explicit entry: `fresh_install_source_pack_runner_v2_v1.py --profile fixed-runner-v2-v1`.
No default, environment acceptance, arbitrary pin override or HEAD-derived authority.

- Fixed payload source: `0d46025b1aad315c995d175531fe5e8fdfa66287`
- Fixed payload source tree: `0e5c341817564d3f25e0306009e2618073c17e38`
- Profile SHA-256: `94c0a2d1d14081299be239d8c0502d48702431a7332a9b9db3db2ca831de3e9c`
- Candidate manifest: `e512481ef5ac24e3dc6b37f1d1e60637e192a229712582e1e707263c16ed5336`
- Candidate report: `a978343d6739b2b8031854727effcc5db9b632bdab79127cefd052aafb962302`
- Payload file modes: `297212bda303017252f3a1e1a4cfd0fcfe045ff29fd407dbb9bc5f07867e02cf`
- Payload directory inventory/modes: `fbe8f45b5d7db3dace90086462af7f5b5338ea25bb1bf1402e5cf869980b9ac5`
- Dependencies: `bdc08227d1d4c77962ab680a2fb247d174b31cf74daf403a7a747e3480b5a7d7`
- Runtime: `d316b6c9af820ecbe58b6e509c2f342a8b10da3ef07852874c035c072e2011b6`
- Private fixed TEST settings: `74b94aed1a5999234aa6102e77f84c86cb1d0599a780a614016454a493d05d38` (bytes never printed).

The actual unchanged bundler builds 10518 files: 328 committed
application/supervisor sources, 9509 dependency files, 680 runtime files,
and one settings file. All current non-test `src/**/*.js` files are included.
All 399 installed package versions match the 409 lock entries;
10 explicit cross-platform optional absences are unchanged.
Payload bytes are rebuilt from the exact fixed source, not relabeled historical bytes.
The producer commit intentionally descends from that earlier fixed payload source.

Exactly one host destination changes: topology `runner.sh` maps ONLY to
`/usr/local/bin/celerity-topology-node-runner-v2`, not the legacy destination.
Runner SHA-256 remains `442663660ec974646b7969c457efd94cc17c57fe0e7a518be8a494480cf26765`.
The two host source byte changes are `isolation.py` and `physical_attestor.py`.
All other host mappings/pins are checked against actual fixed-source bytes.
The application also carries the actual current `topologyNodeTransport.js` and
`topologyRunnerBootstrapper.js`; all four literal consumers target V2.
This is an installed-path **intent**, never installed-state evidence.

## Frozen historical boundary

Legacy, fixed9e and b7 producers, profiles, tests, documentation, bundler,
runtime verifier and physical guards are unchanged. Historical b7 retains its old
runner mapping and accepts only its own full artifact. It refuses this current
source with `SOURCE_WORKTREE_DRIFT`; that refusal is preserved, not repinned.

The new entry copies b7 publication orchestration because legacy acceptance uses
module globals. It hash-checks and compiles unchanged legacy code solely for raw
nofollow IO, JSON, nonexecuting Git plumbing, scanning, fsync and atomic Linux
RENAME_NOREPLACE primitives. No legacy acceptance globals are changed.
Every source is fetched from the fixed object and checked against clean raw
worktree bytes/mode semantics; exact payload, control, directory and intended
installed modes remain independently bound. Rewritten outer inventories cannot
supply authority. Racing destination winners survive; lost rename replies and
postrename durability/readback failures retain unknown output, without rollback.

## Real durable reconstruction and invocation

Evidence root:
`/home/leon/celerity-prod-release-20261019/full-production-20261023/runner-v2-source-pack-child/`

`recover_and_build.py` first verifies the untouched historical b7 pack with its
unchanged checker and candidate pins. It checks durable reconstructed inputs
against the b7 build-input hashes and original builder/runtime-verifier/lock/Node/
settings hashes. Runtime targets/hash/executable fields are preserved; only their
source paths are rebound to verified durable bytes. Dependency snapshots are
real alias-inclusive byte/size inventories, never invented npm archive integrity.
`verify_candidate_and_profile.py` checks every actual source/hash/mode, payload
membership, directory modes, dependency bytes/sizes, lock versions and runtime
closure, then fsyncs every payload inode and directory before fixing this profile.

```sh
python3 -I -B scripts/test-node-isolation/fresh_install_source_pack_runner_v2_v1.py \
  --profile fixed-runner-v2-v1 build \
  --repo /home/leon/c3-runner-v2-pack-20261024 \
  --candidate /home/leon/celerity-prod-release-20261019/full-production-20261023/runner-v2-source-pack-child/candidate-runner-v2 \
  --output /ABSOLUTE/PRIVATE0700/PARENT/FRESH-NAME
python3 -I -B scripts/test-node-isolation/fresh_install_source_pack_runner_v2_v1.py \
  --profile fixed-runner-v2-v1 check \
  --pack /home/leon/celerity-prod-release-20261019/full-production-20261023/runner-v2-source-pack-child/pack-fixed-runner-v2-v1
```

Existing outputs refuse; use a new name. Producer and checker are exercised
against the real full artifact, not fixture pins. Selected unchanged b7 regression
bodies are reused only in a private NEW test namespace with V2 test inputs; no
historical file or producer globals are modified. Fixture directory permissions
are explicitly set before membership tests, including under umask 0077.
Run only the new suite serially through the shared heavy lock and `hermes-heavy`.

TDD: `tdd-01-red.log` records the missing separately named product assertion;
`tdd-01-green.log` records its addition. Reused adversarial cases characterize
preserved IO/refusal contracts rather than pretending new independent RED cycles.
Final producer/checker, focused/full-suite counts and complete artifact/source/log
hashes are recorded in the durable result packet after logs have closed.

Independent source review/reproduction remains external and pending. No source
acceptance, integration, live file copy, execution, controller/lease issuance,
privileged physical rehearsal, strict-3s acceptance, live worker SSH, public HTTPS
or all-five hold/handback is performed or claimed by this offline product.
