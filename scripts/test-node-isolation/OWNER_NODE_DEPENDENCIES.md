# Owner Node dependency staging v1 — offline only

The existing fixed-runner-v2-v2 source pack already carries all 9,509
lock-exact dependency files and host-dependency-intents.json. No existing
source-pack consumer in this source tree materializes that mapping. The new
owner_node_dependencies.py consumes those exact bytes; it does not rebuild a
bundle, adopt a mutable node_modules tree, invoke npm or modify package versions.
Legacy producers/checkers/profiles and all owner source bytes remain unchanged.

Explicit local invocation (OWNER_COPY is a disposable copy, not /opt):

    python3 -I -B scripts/test-node-isolation/owner_node_dependencies.py \
      --pack /home/leon/celerity-prod-release-20261019/full-production-20261023/runner-v2-ppp-mode-pack-child/pack-fixed-runner-v2-v2 \
      --owner-root "$OWNER_COPY"

The owner copy must already contain all owner-root sources from the fixed v2
profile, with exact bytes and mode intents. Only owner-root/node_modules is
published. There is no default destination, overwrite, merge, install mode,
permission/ownership acceptance, policy, unit, runtime plan or activation.
Private ancestors can remain 0700; dependency directories are pinned 0755.
The caller must provide a quiescent owner copy. This is not protection against
an adversarial same-UID writer after publication, nor an accepted live inventory.

Bindings:

- Existing pack-manifest SHA256:
  1a6eaf39a27424a4f52d2ce3bc788a64bd86003726466e24c2ff9223a1fa8568
- Existing dependency-intents SHA256:
  d7a635cb9a7208176119d730e3a5e7e8fb7d507fe7207aa3e0044b81266c6a8a
- package-lock SHA256:
  5298202cf6ca2ce8da44f0578bd54c1146def29fd698c41bc62ac3b5982e6eac
- Candidate manifest/report, source commit/tree, profile, dependency metadata
  digest, membership, sizes, modes and directories remain bound to the existing
  fixed-runner-v2-v2 profile. No caller-supplied acceptance pins are supported.

Only finite controls and the dependency subtree are read/hashed; the unrelated
runtime/settings payload is not scanned. Frozen reads and enumerations require
O_NOATIME and O_NOFOLLOW. Ancestor traversal uses O_PATH without reading them.
No EPERM fallback reads frozen records normally. Symlinks, hardlinks, xattrs,
special files, missing/extra dependency entries and writable directories refuse.
Owner-source and dependency payload identities are rechecked before publication;
donor controls are rechecked by exact bytes/pins, not stored stat identities.
Bootstrap reads only the existing pinned legacy primitives and fixed v2 profile
with NOATIME|NOFOLLOW, hashes those bytes, and compiles the same checked legacy
bytes in a private namespace. It does not import the fixed runner's ordinary
loader or read pyc. Metadata comes from the unchanged pinned profile. Synthetic
compile filenames prevent traceback/linecache reopening frozen source paths.
Publication uses fsync and renameat2(RENAME_NOREPLACE), followed by exact inode
and content readback. An existing empty directory or dangling link wins unchanged.
Publication uncertainty retains visible output and refuses; do not retry by
removing/replacing it. Independent parent review is required before any TEST use.

All owned stage descriptors receive one best-effort close attempt; uncertain
close replies are never retried. Directory traversal transfers ownership to an
opened child before closing its parent; a failed parent close also disposes the
unreturned child/read FD without retrying the old descriptor number. Real-FD
regressions cover a separately opened sentinel reusing that number and a final
close failure after opening the return descriptor. Cleanup failures are aggregated without masking
the primary error (retained as exception cause). After publication or an ambiguous
rename, failures always use DEPENDENCY_PUBLICATION_UNKNOWN_RETAIN_OUTPUT and
never delete output. Before publication, cleanup/close uncertainty uses
DEPENDENCY_CLEANUP_UNKNOWN. Created stage identity is recorded immediately after
mkdir, before open/fchmod, and checked against both the opened FD and cleanup
pathname. Unknown/mismatched identity refuses without deleting another inode;
there is no global cleanup or automatic retry.

Focused verification:

    OWNER_RUNTIME_EVIDENCE=/path/to/new/private/evidence \
      python3 -I -B scripts/test-node-isolation/test_owner_node_dependencies.py -v

Tests use the real immutable payload and a disposable owner copy. They reproduce
MODULE_NOT_FOUND before staging, exercise the actual CLI, then createRequire from
the actual owner entry resolves/loads mongoose and loads every pinned owner JS
source (including literal bind models). main is never invoked and no DB connection
is opened. Negative cases cover source/lock drift, donor manifest/payload mismatch,
symlinks and no-replace. Existing frozen test suites are intentionally not rerun.
The original eight test bodies remain unchanged. Three focused regressions add
real-directory/FD resource-fault coverage with an empty synthetic payload, plus
true CLI bootstrap on a disposable frozen source/profile copy with old atimes.
They cover close after success/refusal/readback, remaining close attempts,
rmtree refusal, lost rename reply, postpublish fsync/readback, open/fchmod faults
before staging and unprovable/replaced identity. These tiny cases are not real
pack publication evidence; only the combined original CLI/load test uses all
9,509 dependencies and all 20 pinned owner JS sources.
Local Node is discovered from PATH; this does not prove TEST /usr/bin/node, native
addon ABI closure, return closure, installed acceptance or permission for a canary.
All acceptance/GO fields remain false. No remote changes are performed.
