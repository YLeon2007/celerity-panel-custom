# Fixed runner V2 offline source delivery, v2

**Offline source implementation only.** Installed, activated, physicalAccepted,
operationalGO, provisioningImplemented and strict3sAccepted remain false.
Independent parent review, reproduction and integration are pending.

## Narrow accepted decision

Decision `test-v2-ppp-mode-decision/result.json` SHA-256
`53af4761e57c31379edd94f3e9774265ce3fab971a0edfd49c20ef74e14e2216`
authorizes only this separately versioned metadata correction. Relative to frozen
`fixed-runner-v2-v1`, exactly one semantic host mapping field changes:

`hostSources[src/modules/relay-l2tp/node-artifacts/l2tp/verify-users.sh].modeIntent`
changes from integer 488 (0750) to integer 493 (0755). All 47 other mappings and
all other fields of all 48 mappings are type/byte exact. The fixed producer's
mode expression has a single literal PPP exception; changing the profile alone
would leave the old /usr0750 derivation and fail `PACK_AUTHORITY_DRIFT`.
The checker remains exact, with no mode/config/pin/CLI override.

The canonical shared path remains
`/usr/local/lib/celerity/relay-l2tp/verify-users.sh`, root:root intent, unchanged
SHA `135a366b9cebcdbc3c08b0c605b91f14db39c61d7190f758dab4707eca22d6d3`.
Offline host-source storage remains0600. Inode425605/root0755 is inherited audit
observation, **not a fresh readback or installed acceptance**; no live shared
inode, bytes, mode, xattrs or ownership is touched. Legacy installer requires0755.
The actual V2 verifier consumer retains root/no022/type/hash predicates; no
independent PPP-specific0750 security predicate was found in the pinned decision.
Exact0750 for `/usr/local/bin/celerity-topology-node-runner-v2` is unchanged.
No runtime source, credentials0600 guards or authority gates are relaxed.

## Fixed full payload (reused, not rebuilt)

- SOURCE: `0d46025b1aad315c995d175531fe5e8fdfa66287`
- SOURCE tree: `0e5c341817564d3f25e0306009e2618073c17e38`
- New fixed profile SHA: `93a80650a751ba833371f997b2b3f7d297e289684d631c5a0e053525c11309c8`
- Candidate manifest: `e512481ef5ac24e3dc6b37f1d1e60637e192a229712582e1e707263c16ed5336`
- Candidate report: `a978343d6739b2b8031854727effcc5db9b632bdab79127cefd052aafb962302`
- File modes: `297212bda303017252f3a1e1a4cfd0fcfe045ff29fd407dbb9bc5f07867e02cf`
- Directory modes: `fbe8f45b5d7db3dace90086462af7f5b5338ea25bb1bf1402e5cf869980b9ac5`
- Dependencies: `bdc08227d1d4c77962ab680a2fb247d174b31cf74daf403a7a747e3480b5a7d7`
- Runtime: `d316b6c9af820ecbe58b6e509c2f342a8b10da3ef07852874c035c072e2011b6`
- Settings: `74b94aed1a5999234aa6102e77f84c86cb1d0599a780a614016454a493d05d38`

The complete accepted candidate has10518 files:328 source,9509 dependency,
680 runtime and one settings file. No application/dependency/runtime rebuild,
install, full host restaging or new executable path is needed or performed.
All payload bytes/paths/modes/directories, host bytes and dependency intents stay
unchanged. Only profile/report identity, host-intents and outer manifest change.
The v1 manifest stays
`1c33499c79a22115645b32c5862235b68a6e931f69bc26b61d77af59b1ea4dfc`.

## Implementation and invocation

This product copies the bounded v1 publication/check orchestration, hash-checks
and compiles unchanged legacy low-level IO/Git/fsync/RENAME_NOREPLACE primitives,
and never patches historical module globals. Original759 tracked files,
including legacy/9e/b7/v1 products, profiles, pins, tests and docs remain frozen.
New profile schema/product report/pack schema use v2 identities, so v1 rejects
this pack. Rewritten outer inventories never supply acceptance authority.
Unknown publication outcomes remain retained, and racing destinations survive.

```sh
python3 -I -B scripts/test-node-isolation/fresh_install_source_pack_runner_v2_v2.py \
  --profile fixed-runner-v2-v2 build \
  --repo /home/leon/c3-runner-v2-ppp-mode-v2-20261024 \
  --candidate /home/leon/celerity-prod-release-20261019/full-production-20261023/runner-v2-source-pack-child/candidate-runner-v2 \
  --output /ABSOLUTE/PRIVATE0700/PARENT/FRESH-NAME
python3 -I -B scripts/test-node-isolation/fresh_install_source_pack_runner_v2_v2.py \
  --profile fixed-runner-v2-v2 check --pack /ABSOLUTE/NEW-PACK
```

The real full producer/checker and new suite run serially under `hermes-heavy`
and the shared exclusive `full-production-20261022/heavy.lock` (180s lock wait),
with finite deadlines and a task-local read-only disk reserve adapter. No
privileged cleanup, SSH, project helper dispatch, root execution or PROD access.

## Evidence and limits

Evidence only in `full-production-20261023/runner-v2-ppp-mode-pack-child/`.
`tdd-01-red.log` records the missing-product assertion, followed by GREEN.
The focused suite tests actual full0755 checker acceptance, all48 type-exact
mapping comparisons, producer derivation,0750/493.0/bool/path/hash tampering after
outer rehash, runner0750/wrong-path refusal, fixed profile/CLI and unchanged v1
positive plus new-product refusal. Historical b7/9e compatible-pack positives,
current-source refusals and legacy pre-network refusal are qualified historical
coverage, never new-source positives or repins.

Selected immutable b7 adversarial/publication/closure bodies run only in a private
new test namespace with new inputs. Those reused contracts are not independent
new RED cycles. Directory fixture modes are explicitly set despite umask0077;
focused membership checks also run with umask0022. Actual unchanged `verify_ppp`
AST covers0755 and0750, writable group/world, foreign UID, symlink and byte drift.
Its stat/open seam is modeled, subprocess dispatch intercepted before execution:
**not real root execution, PPP readiness or physical acceptance**.

`result.json` binds exact commit/tree/file SHA values, real pack manifest/report,
all candidate pins, exact expected/started/completed/passed test names, closed log
hashes, earlier failures and gateway identity. Parent independent review,
reproduction, integration, installed mapping acceptance, exclusion, policy/receipt/
lease/deadline authority, physical rehearsal and operational GO remain external.
