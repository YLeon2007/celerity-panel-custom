# Fixed fresh TEST installation source-pack — OFFLINE ONLY

`fresh_install_source_pack.py` implements only L1 of
`physical-next-20261022.json: minimal_next_local_source_stage`.
L2 (`same Coordinator → run_prepared → pidfd resume → non-consuming listen
observation → one authenticated connection`) is already committed in `eefa46f`.
This tool does not change or replay L2, loosen a guard, thaw a legacy writer,
start the candidate, install anything, or export an install/accept/execute API.
Every result retains **physicalAccepted=false, operationalGO=false**.

## Fixed input authority and provenance

The CLI accepts only the location of a clean committed repository, the existing
candidate, and an absent output name under an existing private owner-only (0700)
parent. It accepts **no source allowlist, installed destination map, command,
settings, policy, inventory, alternate digest, runtime or activation flag**.
Paths must already be absolute/canonical; malformed tokens are refused, not
normalized. All path components are opened with `O_NOFOLLOW`.

The fixed source base is `eefa46f65943e6923f9fec6b43b44b7efd494c9f`, tree
`f95df8a1759e892377774265598d0614bebcc5c7`. A descendant clean HEAD may contain this
additive tool, but every shipped source must still equal both its HEAD blob and
its base blob. Worktree bytes are independently read even if Git's
assume-unchanged flag hides edits. Nothing is exported from an uncommitted blob.
Source files must be ordinary single-link, xattr-free files; Git executable bits
must agree. Every Git invocation disables replacement objects, repository-local
fsmonitor and hooks, recursive submodule handling and lazy object fetching.
Cleanliness uses only tree/index plumbing plus independent raw-byte blob hashes
and executable-mode checks for every tracked file; it never invokes `status`,
`diff`, index refresh or attribute conversion. Thus arbitrary `filter.*.clean`
and `filter.*.process` commands selected even by `.git/info/attributes` are not
invoked. Index entries must exactly equal HEAD, and nonignored untracked files
refuse. SHA-1 repositories with only regular tracked files are supported;
committed symlinks/submodules refuse rather than following or inspecting them.
A clean revision does not authenticate `.git/config`, attributes or `refs/replace`.
The command environment excludes inherited Git configuration. These bounded
read-only plumbing calls do not execute repository hooks or use replacement bytes.
Ordinary developer 0644/0664 and 0755/0775 worktree modes are allowed:
these are NOT installed ownership/mode acceptance. Host storage files are 0600;
root:root 0640/0750 is recorded only as a fixed future **intent**.

The actual candidate is expected at
`/home/leon/.hermes/cache/scratch/c3-current-root-jaxwrjtj/candidate`.
The original candidate/report are not rewritten or relabeled. Its builtFrom is
`df4ba411782f8ffa99daddd732d60e3da7272a27`, tree
`f68fe64b8c398bc5a56cf4d99f0c6b2618627581`. All 326 shipped source files are checked
against eefa46f and the current committed source, preserving this provenance
bridge instead of claiming the candidate was built from the newer commit.

Fixed candidate controls, established by the parent's
`integrated-current-root/result.json` and
`integrated-current-root/final-source-eefa46f.json`:

- manifest SHA256 `b9793014e4fda7a53034394f2d02a077d645b49af9d08e70679e13ce85a614f6`
- original report SHA256 `801866bbd3c8a603ac8d6949afe75cce33a988d88f7fafc845697c2783547079`
- additional offline path→mode SHA256 `01fd43553623f672a910841908aef1271dde4df43fd16f7a1b52d9ec4de383fb`
- additional offline directory→mode SHA256 `fbe8f45b5d7db3dace90086462af7f5b5338ea25bb1bf1402e5cf869980b9ac5`

The last two pins come from the same actual candidate, not from a physical
installation. They bind 10,516 file modes (10,421×0644, 95×0755) and 1,876
root-inclusive directories (0755). Encoding is sorted indent-2 JSON plus LF,
absolute image paths, integer modes; directory `/` has no trailing slash added.
The input contains 326 source files, 9,509 dependency files, 680 runtime files,
one private settings file, 399 installed/409 lock packages and 10 expected
optional platform absences. The accepted manifest/report supply offline snapshot
integrity, NOT fresh npm archive integrity or live runtime/mount acceptance.

## Exact source / import / loader / subprocess closure

The finite `HOST_SOURCES` table has **36** committed files, all copied separately
under `host-source/` with source path→SHA256→fixed installed path/mode/uid/gid
**intent** in `host-intents.json`:

- Eleven Python modules map to their existing fixed `/usr/local/libexec/` names:
  `coordinated_fresh_restore`, `coordinated_restore`, `coordinated_capture`,
  `fresh_classic_launch`, `prepare_fresh_supervisor`,
  `fresh_owner_restoration_channel`, `owner_restoration_channel`, `node_originals`,
  `physical_attestor`, `isolation`, `shared_host`.
- `scripts/panel-host-freezer.py`, the actual topology `runner.sh`, and its
  independently hardcoded-digest `verify-users.sh` dependency map to the existing
  freezer/runner/verifier installed names. Copying these bytes does not admit
  their remote commands or grant their installation/dispatch authority.
- The fixed fresh JS entry, its **20-file** complete repository require closure
  (including itself), `package.json` and `package-lock.json` map to the explicitly
  proposed, NOT observed installed tree `/opt/celerity-fresh-owner/`. Relative
  `../../src/...` model imports retain their source layout. There is no generic
  module/path resolver at runtime in this pack tool.

Trace of the existing code (not invoked by packing):

1. `settle-fresh-held-owner.js` requires mongoose plus
   `heldTestOwnerSettlement`, `heldOwnerSettlementJournal`,
   `heldRestorationChannel`; its only dynamic require is `bind(name, location)`
   for the ten literal model paths. The closure test traverses literal requires
   and those exact bind roots, requires exact equality with `JS_SOURCES`, and
   permits only mongoose plus Node child_process/crypto/fs/path/util builtins.
   The entire actual lock-exact dependency tree is present in `candidate/root`;
   `host-dependency-intents.json` separately maps all 9,509 actual dependency bytes
   to `/opt/celerity-fresh-owner/node_modules/...`, without duplicating or
   inventing a second dependency inventory.
2. The actual JS adapter spawns `/usr/bin/python3 -I` with the fixed fresh bridge.
   That bridge digest-loads `owner_restoration_channel`; the latter digest-loads
   `coordinated_restore`. The separate no-argument root fresh entry loads that
   same coordinator source too. Within the live Coordinator, the fresh loader
   injects the exact running coordinator module into `FreshLaunch`, not another
   class/module or a serialized GO callback. The preparer loads the same pinned
   coordinator and fresh launcher from the three immutable bootstrap files.
3. Coordinator node-hold loads originals → isolation; the shared node additionally
   loads shared_host → panel-host-freezer. Coordinated capture adds the actual
   physical attestor loader → isolation. Isolation dispatch invokes the pinned
   topology runner with bash; the runner's only additional shipped source is
   the exact fixed verifier. No product sources are imported/executed by packing.
4. Privileged-host **external prerequisites remain unprovisioned/unaccepted**:
   Python stdlib/dynamic loader, Node and its OS loader/shared libraries, ssh,
   systemctl, busctl, docker, sshd, sudo/false, bash and runner utilities
   cat/chmod/install/mkdir/mktemp/mv/rm/sha256sum/ss/stat, plus Xray and its assets.
   These are actual subprocess roots in the existing code, not shipped host
   binary facts. The candidate's Node/Python/ELF/stdlib closure is fresh-root
   input only; copying it does not establish a privileged-host interpreter.

## Pack layout and non-self-referential bootstrap

- `candidate/root/`: complete independently hashed actual root, with exact
  file and directory membership/modes, including empty directories.
- `candidate/{manifest,report}.json`: original pinned bytes, not a new provenance.
- `bootstrap-files.json`: exactly the candidate's complete immutable files map,
  including coordinator, fresh launcher and preparer. This is **not a policy**:
  there is no `inventory`, PID/ns/fd/route/unit pin or fabricated accepted GO.
- `host-source/`, `host-intents.json`, `host-dependency-intents.json`: the separate
  privileged-host source/dependency mapping described above.
- `report.json`: redacted source identities, pins, counts, false acceptance and
  explicit missing physical implementation. No settings/secret values are copied
  into reports/stdout. Settings bytes stay only inside the private root copy.
- `pack-manifest.json`: hashes/modes/sizes for every other pack file and exact
  directory membership/modes. Only this control manifest excludes itself. ALL
  control documents stay outside `candidate/root/`; the fresh policy path is
  deliberately absent. `verify_pack()` is an offline integrity readback, not a
  physical acceptance or independent authenticity signature.

## Publication and fault semantics

A private same-parent randomly named stage is created with 0700. Every new file
uses `O_EXCL`, is fully written and file-fsynced. Every staged directory is
fsynced bottom-up before publication. Candidate/source bytes, metadata,
provenance, membership, mode pins and clean HEAD/tree are rechecked; replaced
input directory namespaces refuse. The fixed candidate controls also recheck
identity, not just matching bytes. The complete staged manifest is verified.
Linux `renameat2(RENAME_NOREPLACE)` uses an owned parent descriptor and has **no
ordinary-rename fallback**. Even a racing empty destination must win unchanged.
Success additionally requires parent-directory fsync and a readback of the exact
published inode and full pack closure. Publication/result/readback uncertainty
retains the visible output and refuses; it must never be overwritten or treated
as accepted. Before publication, only a stage with the recorded owned inode is
cleaned; a substituted directory/winner is not deleted. Cleanup failure is a
redacted refusal retaining the stage. Parent 0700 is a prerequisite, not a sandbox
against a malicious process with the same UID or root. There is no crash-time
or stale-stage automatic adoption/deletion.

## Offline usage / tests

From a clean committed source tree, with the existing output parent already 0700:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -I -B \
  scripts/test-node-isolation/fresh_install_source_pack.py \
  --repo /home/leon/c3-install-sourcepack-20261022 \
  --candidate /home/leon/.hermes/cache/scratch/c3-current-root-jaxwrjtj/candidate \
  --output /home/leon/celerity-prod-release-20261019/active-enable-20261021/install-sourcepack/full-pack

cd scripts/test-node-isolation
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest -v test_fresh_install_source_pack
```

Tests use real Linux files, FDs, Git fixture repositories, renameat2 and fsync,
with finite injected late write/fsync/publication/readback faults. Tiny candidate
pin replacements exist ONLY inside test mocks; the production CLI has no such
option, and these fixtures are never actual-app/full-candidate evidence. Scratch
fixtures live exclusively under `/home/leon/.hermes/cache/scratch`. RED/GREEN,
final tests, full-pack build and readback evidence live outside the repository
under `.../active-enable-20261021/install-sourcepack/`. No old full app/Mongo suite
is required or claimed by this additive offline tool.

## Explicitly absent physical installation boundary

There is **no fresh systemd unit**, **no fixed resource exec helper**, **no
resource policy/inventory**, **no operational host interpreter provisioning**,
**no direct-ingress construction**, and no install/accept/execute export here.
A unit referencing a nonexistent helper would be misleading, so none is emitted.
Loaded units/admission before the affected hold, real ownership/UID/capabilities,
root/proc/state mounts and namespaces, stdio/fd3 and lock lifecycle, independently
accepted policy pins, finite external preparation deadline, restored-data/startup
budgets and direct literal `212.119.42.100:3000` ingress still require separate
physical/network facts and authorization. No services, SSH, root/mount/ns/network,
DB/config, candidate exclusion or legacy thaw state is changed by this tool.
