#!/usr/bin/python3 -I
"""Fixed offline source-pack only. No install, acceptance or execution capability."""
import argparse
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import uuid

sys.dont_write_bytecode = True


class Refusal(Exception):
    """Stable redacted refusal code, never input values."""


def need(ok, code):
    if not ok:
        raise Refusal(code)


def publish_noreplace(parent_fd, stage, output):
    """Linux renameat2(RENAME_NOREPLACE); no weaker rename fallback."""
    rename = getattr(ctypes.CDLL(None, use_errno=True), 'renameat2', None)
    need(rename is not None, 'ATOMIC_PUBLICATION_UNAVAILABLE')
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                       ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(parent_fd, os.fsencode(stage), parent_fd, os.fsencode(output), 1):
        error = ctypes.get_errno()
        raise Refusal('OUTPUT_EXISTS' if error in (errno.EEXIST, errno.ENOTEMPTY)
                      else 'ATOMIC_PUBLICATION_REFUSED')


BASE = 'eefa46f65943e6923f9fec6b43b44b7efd494c9f'
BUILT_FROM = 'df4ba411782f8ffa99daddd732d60e3da7272a27'
MANIFEST_PIN = 'b9793014e4fda7a53034394f2d02a077d645b49af9d08e70679e13ce85a614f6'
REPORT_PIN = '801866bbd3c8a603ac8d6949afe75cce33a988d88f7fafc845697c2783547079'
# Additional offline path/mode and directory-membership pins read from the same
# actual candidate; no ownership, mount or physical acceptance is inferred.
MODE_PIN = '01fd43553623f672a910841908aef1271dde4df43fd16f7a1b52d9ec4de383fb'
DIRECTORY_PIN = 'fbe8f45b5d7db3dace90086462af7f5b5338ea25bb1bf1402e5cf869980b9ac5'
COUNTS = dict(sourceFiles=326, dependencyFiles=9509, runtimeFiles=680,
              elfFiles=0, payloadFiles=10516, installedPackages=399,
              lockPackages=409, expectedOptionalAbsences=10)
PREFIX = 'scripts/test-node-isolation/'
OWNER_ROOT = '/opt/celerity-fresh-owner/'
# Finite reviewed loader roots, not an arbitrary source/target/command API.
PYTHON_SOURCES = {
    'coordinated_fresh_restore.py': 'c3-test-coordinated-fresh-restore.py',
    'coordinated_restore.py': 'c3-test-coordinated-restore.py',
    'coordinated_capture.py': 'c3-test-coordinated-capture.py',
    'fresh_classic_launch.py': 'c3-test-fresh-classic.py',
    'prepare_fresh_supervisor.py': 'c3-test-fresh-prepare.py',
    'fresh_owner_restoration_channel.py': 'c3-test-fresh-owner-restoration-channel.py',
    'owner_restoration_channel.py': 'c3-test-owner-restoration-channel.py',
    'node_originals.py': 'c3-test-node-originals.py',
    'physical_attestor.py': 'c3-test-physical-attestor',
    'isolation.py': 'c3-test-node-isolation',
    'shared_host.py': 'c3-test-shared-host.py',
}
JS_SOURCES = (
    'scripts/test-node-isolation/settle-fresh-held-owner.js',
    'src/models/cascadeLinkModel.js', 'src/models/topologyConfigOwnerModel.js',
    'src/modules/relay-l2tp/domain/l2tpExecutionAuthorization.js',
    'src/modules/relay-l2tp/domain/topologyExecutionContext.js',
    'src/modules/relay-l2tp/models/cascadeTopologyStateModel.js',
    'src/modules/relay-l2tp/models/l2tpOperationModel.js',
    'src/modules/relay-l2tp/models/nodeOperationLockModel.js',
    'src/modules/relay-l2tp/models/topologyCreateIntentModel.js',
    'src/modules/relay-l2tp/models/topologyExecutionBindingContract.js',
    'src/modules/relay-l2tp/models/topologyExecutionBindingModel.js',
    'src/modules/relay-l2tp/models/topologyExecutionContextSchema.js',
    'src/modules/relay-l2tp/models/topologyExecutionEnrollmentModel.js',
    'src/modules/relay-l2tp/models/topologyIntentQueueStateModel.js',
    'src/modules/relay-l2tp/models/topologyOperationModel.js',
    'src/modules/relay-l2tp/services/topologyNodeRef.js',
    'src/services/heldOwnerSettlementJournal.js',
    'src/services/heldRestorationChannel.js', 'src/services/heldTestOwnerSettlement.js',
    'src/services/topologyConfigTransfer.js',
)
HOST_SOURCES = {PREFIX + source: '/usr/local/libexec/' + target
                for source, target in PYTHON_SOURCES.items()}
HOST_SOURCES.update({
    'scripts/panel-host-freezer.py': '/usr/local/libexec/c3-panel-host-freezer.py',
    'src/modules/relay-l2tp/node-artifacts/topology/runner.sh': '/usr/local/bin/celerity-topology-node-runner',
    'src/modules/relay-l2tp/node-artifacts/l2tp/verify-users.sh': '/usr/local/lib/celerity/relay-l2tp/verify-users.sh',
})
HOST_SOURCES.update({source: OWNER_ROOT + source for source in (*JS_SOURCES, 'package.json', 'package-lock.json')})
SUPERVISORS = {'/usr/local/libexec/' + PYTHON_SOURCES[n]: PREFIX + n for n in
               ('coordinated_restore.py', 'fresh_classic_launch.py', 'prepare_fresh_supervisor.py')}
POLICY = '/etc/c3-test-fresh-classic.json'
MAX_BYTES = 256 * 1024 * 1024
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def path_parts(value, absolute=False):
    need(type(value) is str and value and '\x00' not in value and
         value.startswith('/') == absolute, 'INVALID_PATH')
    parts = value.split('/')[1:] if absolute else value.split('/')
    need(all(p not in ('', '.', '..') and not any(ord(c) < 32 or ord(c) == 127 for c in p)
             for p in parts), 'INVALID_PATH')
    return parts


def open_directory(path):
    parts = path_parts(path, True)
    fd = os.open('/', DIR_FLAGS)
    try:
        for part in parts:
            child = os.open(part, DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def identity(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size,
            s.st_mtime_ns, s.st_ctime_ns, s.st_uid, s.st_gid)


def read_file(root_fd, relative, worktree=False):
    parts = path_parts(relative)
    fd = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            child = os.open(part, DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
        child = os.open(parts[-1], FILE_FLAGS, dir_fd=fd)
        os.close(fd)
        fd = child
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
             before.st_size <= MAX_BYTES and not os.listxattr(fd), 'UNSAFE_FILE')
        modes = (0o644, 0o664, 0o755, 0o775) if worktree else (0o600, 0o640, 0o644, 0o750, 0o755)
        need(stat.S_IMODE(before.st_mode) in modes, 'UNSAFE_FILE_MODE')
        chunks = []
        total = 0
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            total += len(block)
            need(total <= MAX_BYTES, 'FILE_TOO_LARGE')
            chunks.append(block)
        need(identity(before) == identity(os.fstat(fd)), 'FILE_CHANGED_DURING_READ')
        return b''.join(chunks), before
    finally:
        os.close(fd)


def scan(root_fd, exact_directory_mode=None):
    files, snapshot = {}, {}

    def walk(fd, prefix):
        before = os.fstat(fd)
        need(stat.S_ISDIR(before.st_mode) and not os.listxattr(fd) and
             not before.st_mode & 0o022, 'UNSAFE_DIRECTORY')
        if exact_directory_mode is not None:
            need(stat.S_IMODE(before.st_mode) == exact_directory_mode, 'DIRECTORY_MODE_DRIFT')
        snapshot[prefix] = identity(before)
        for name in sorted(os.listdir(fd)):
            path_parts(name)
            relative = prefix + name
            st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(st.st_mode):
                child = os.open(name, DIR_FLAGS, dir_fd=fd)
                try:
                    need(identity(st) == identity(os.fstat(child)), 'DIRECTORY_CHANGED')
                    walk(child, relative + '/')
                finally:
                    os.close(child)
            else:
                raw, info = read_file(fd, name)
                need(identity(st) == identity(info), 'FILE_CHANGED')
                files[relative] = dict(sha256=sha(raw), size=len(raw), mode=stat.S_IMODE(info.st_mode))
                snapshot[relative] = identity(info)
        need(identity(before) == identity(os.fstat(fd)), 'DIRECTORY_CHANGED')
    walk(root_fd, '')
    return files, snapshot


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'DUPLICATE_JSON_KEY')
            result[key] = value
        return result
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                          parse_constant=lambda _: need(False, 'INVALID_JSON'))
    except (ValueError, UnicodeError):
        raise Refusal('INVALID_JSON') from None


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def git(repo, *args, data=None):
    # Neither clean HEAD nor a fixed revision authenticates repository-local
    # executable config or refs/replace. Apply these overrides to EVERY command;
    # repo_state uses only non-converting plumbing, never status or diff.
    result = subprocess.run(['/usr/bin/git', '--no-replace-objects',
                            '-c', 'core.fsmonitor=false',
                            '-c', 'core.hooksPath=/dev/null',
                            '-c', 'submodule.recurse=false', '-C', repo, *args], input=data,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60,
                            env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C',
                                 'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_NO_LAZY_FETCH': '1',
                                 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'})
    need(result.returncode == 0, 'GIT_REFUSED')
    return result.stdout


def repo_state(repo):
    # Never use status/diff/index refresh: these run arbitrary clean/process
    # filters selected by worktree or info attributes, even with hooks disabled.
    need(git(repo, 'rev-parse', '--show-toplevel').decode().strip() == repo, 'REPOSITORY_ROOT_REQUIRED')
    need(git(repo, 'rev-parse', '--show-object-format').strip() == b'sha1', 'SOURCE_OBJECT_FORMAT')
    head = git(repo, 'rev-parse', 'HEAD').decode().strip()
    tree = git(repo, 'rev-parse', head + '^{tree}').decode().strip()
    tracked = {}
    for row in git(repo, 'ls-tree', '-rz', '--full-tree', tree).split(b'\x00')[:-1]:
        meta, sep, name = row.partition(b'\t')
        fields = meta.split()
        need(sep and len(fields) == 3 and fields[0] in (b'100644', b'100755') and
             fields[1] == b'blob' and name not in tracked, 'SOURCE_NOT_REGULAR_COMMITTED')
        tracked[name] = (fields[0], fields[2])
    indexed = {}
    for row in git(repo, 'ls-files', '--stage', '-z').split(b'\x00')[:-1]:
        meta, sep, name = row.partition(b'\t')
        fields = meta.split()
        need(sep and len(fields) == 3 and fields[2] == b'0' and name not in indexed, 'DIRTY_SOURCE')
        indexed[name] = (fields[0], fields[1])
    need(indexed == tracked and not git(repo, 'ls-files', '--others', '--exclude-standard', '-z'), 'DIRTY_SOURCE')
    fd = open_directory(repo)
    try:
        for name, (mode, oid) in tracked.items():
            raw, info = read_file(fd, os.fsdecode(name), worktree=True)
            digest = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\x00' + raw).hexdigest().encode()
            need(digest == oid and bool(info.st_mode & 0o111) == (mode == b'100755'), 'DIRTY_SOURCE')
    finally:
        os.close(fd)
    return head, tree


def committed(repo, revision, relative):
    path_parts(relative)
    row = git(repo, 'ls-tree', '-z', revision, '--', relative).split(b'\x00')
    need(len(row) == 2 and row[1] == b'', 'SOURCE_NOT_COMMITTED')
    meta, sep, name = row[0].partition(b'\t')
    fields = meta.split()
    need(sep and name == relative.encode() and len(fields) == 3 and
         fields[0] in (b'100644', b'100755') and fields[1] == b'blob', 'SOURCE_NOT_REGULAR_COMMITTED')
    return git(repo, 'cat-file', 'blob', fields[2].decode()), int(fields[0], 8) & 0o777


def source_bytes(repo, repo_fd, head, relative):
    raw, mode = committed(repo, head, relative)
    need(raw == committed(repo, BASE, relative)[0], 'BASE_SOURCE_DRIFT')
    actual, info = read_file(repo_fd, relative, worktree=True)
    need(actual == raw and bool(info.st_mode & 0o111) == bool(mode & 0o111), 'SOURCE_WORKTREE_DRIFT')
    return raw


def write_file(root_fd, relative, raw, mode=0o600):
    parts = path_parts(relative)
    fd = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            try:
                os.mkdir(part, 0o700, dir_fd=fd)
            except FileExistsError:
                pass
            child = os.open(part, DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
        child = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=fd)
        try:
            os.fchmod(child, mode)
            with os.fdopen(child, 'wb', closefd=False) as stream:
                need(stream.write(raw) == len(raw), 'SHORT_WRITE')
                stream.flush()
                os.fsync(child)
        finally:
            os.close(child)
    finally:
        os.close(fd)


def directory_modes(snapshot):
    return {name: stat.S_IMODE(info[2]) for name, info in snapshot.items()
            if not name or name.endswith('/')}


def make_directory(root_fd, relative, mode=0o700):
    fd = os.dup(root_fd)
    try:
        for part in path_parts(relative):
            try:
                os.mkdir(part, mode, dir_fd=fd)
            except FileExistsError:
                pass
            child = os.open(part, DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
        os.fchmod(fd, mode)
    finally:
        os.close(fd)


def fsync_tree(fd):
    for name in sorted(os.listdir(fd)):
        st = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if stat.S_ISDIR(st.st_mode):
            child = os.open(name, DIR_FLAGS, dir_fd=fd)
            try:
                fsync_tree(child)
            finally:
                os.close(child)
    os.fsync(fd)


def verify_candidate(repo, repo_fd, head, candidate_fd):
    need(set(os.listdir(candidate_fd)) == {'manifest.json', 'report.json', 'root'}, 'CANDIDATE_MEMBERSHIP')
    manifest_raw, _ = read_file(candidate_fd, 'manifest.json')
    report_raw, _ = read_file(candidate_fd, 'report.json')
    need(sha(manifest_raw) == MANIFEST_PIN and sha(report_raw) == REPORT_PIN, 'CANDIDATE_PIN_MISMATCH')
    manifest, report = decode(manifest_raw), decode(report_raw)
    need(type(manifest) is dict and len(manifest) == COUNTS['payloadFiles'], 'MANIFEST_SCHEMA')
    for key, pin in manifest.items():
        path_parts(key, True)
        need(type(pin) is str and re.fullmatch('[a-f0-9]{64}', pin), 'MANIFEST_SCHEMA')
    need(POLICY not in manifest and set(SUPERVISORS) <= manifest.keys(), 'BOOTSTRAP_CLOSURE')
    need(type(report) is dict and report.get('schema') == 'c3-classic-root-candidate-report/v1' and
         report.get('physicalAccepted') is False and report.get('candidate') is True and
         report.get('runtimeProposal') is True and report.get('sourceCommit') == BUILT_FROM and
         report.get('counts') == COUNTS, 'CANDIDATE_REPORT_MISMATCH')
    need(git(repo, 'rev-parse', BUILT_FROM + '^{tree}').decode().strip() == report.get('sourceTree'), 'CANDIDATE_PROVENANCE')
    git(repo, 'merge-base', '--is-ancestor', BUILT_FROM, BASE)
    root = os.open('root', DIR_FLAGS, dir_fd=candidate_fd)
    try:
        files, snapshot = scan(root, 0o755)
    finally:
        os.close(root)
    need({'/' + key: value['sha256'] for key, value in files.items()} == manifest, 'CANDIDATE_ROOT_MISMATCH')
    need(all(v['mode'] in (0o644, 0o755) for v in files.values()), 'CANDIDATE_FILE_MODE')
    need(sha(encode({'/' + key: value['mode'] for key, value in files.items()})) == MODE_PIN,
         'CANDIDATE_MODE_PIN_MISMATCH')
    need(sha(encode({'/' + key.rstrip('/'): value for key, value in directory_modes(snapshot).items()}))
         == DIRECTORY_PIN, 'CANDIDATE_DIRECTORY_PIN_MISMATCH')
    source_count = 0
    for key, digest in manifest.items():
        relative = SUPERVISORS.get(key)
        if key.startswith('/app/') and not key.startswith('/app/node_modules/'):
            relative = key[len('/app/'):]
        if relative is not None:
            need(sha(source_bytes(repo, repo_fd, head, relative)) == digest, 'CANDIDATE_SOURCE_MISMATCH')
            source_count += 1
    need(source_count == COUNTS['sourceFiles'], 'CANDIDATE_SOURCE_COUNT')
    return manifest, report, files, snapshot


def intent(pack_path, installed, digest, mode):
    return dict(packPath=pack_path, sha256=digest, installedPathIntent=installed,
                modeIntent=mode, uidIntent=0, gidIntent=0, installed=False)


def verify_pack_fd(fd):
    raw, _ = read_file(fd, 'pack-manifest.json')
    doc = decode(raw)
    need(type(doc) is dict and doc.get('schema') == 'c3-fixed-install-source-pack/v1' and
         doc.get('physicalAccepted') is False and doc.get('operationalGO') is False, 'PACK_SCHEMA')
    files, snapshot = scan(fd)
    del files['pack-manifest.json']  # The control manifest cannot hash itself.
    need(files == doc.get('files') and directory_modes(snapshot) == doc.get('directories'), 'PACK_CONTENT_DRIFT')
    report = decode(read_file(fd, 'report.json')[0])
    need(report.get('physicalAccepted') is False and report.get('operationalGO') is False, 'PACK_REPORT')
    return report


def verify_pack(output):
    try:
        fd = open_directory(output)
        try:
            need(stat.S_IMODE(os.fstat(fd).st_mode) == 0o700, 'PACK_NOT_PRIVATE')
            return verify_pack_fd(fd)
        finally:
            os.close(fd)
    except Refusal:
        raise
    except Exception:
        raise Refusal('PACK_VERIFICATION_REFUSED') from None


def build(repo, candidate, output):
    """Offline export only. Fixed source closure and accepted candidate pins."""
    parent_fd = repo_fd = candidate_fd = stage_fd = None
    stage = stage_identity = None
    published = publication_attempted = False
    try:
        parts = path_parts(output, True)
        path_parts(repo, True)
        path_parts(candidate, True)
        parent = '/' + '/'.join(parts[:-1])
        need(len(parts) > 1, 'OUTPUT_PARENT_REQUIRED')
        parent_fd = open_directory(parent)
        info = os.fstat(parent_fd)
        need(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700, 'PRIVATE_OUTPUT_PARENT_REQUIRED')
        need(parts[-1] not in os.listdir(parent_fd), 'OUTPUT_EXISTS')
        repo_fd = open_directory(repo)
        candidate_fd = open_directory(candidate)
        initial = repo_state(repo)
        head, tree = initial
        git(repo, 'merge-base', '--is-ancestor', BASE, head)
        manifest, candidate_report, root_files, root_snapshot = verify_candidate(repo, repo_fd, head, candidate_fd)
        controls = {name: read_file(candidate_fd, name)[0] for name in ('manifest.json', 'report.json')}
        host = {source: source_bytes(repo, repo_fd, head, source) for source in HOST_SOURCES}
        source_names = set(host) | set(SUPERVISORS.values()) | {
            key[len('/app/'):] for key in manifest
            if key.startswith('/app/') and not key.startswith('/app/node_modules/')}
        source_snapshot = {source: identity(read_file(repo_fd, source, worktree=True)[1]) for source in source_names}
        candidate_snapshot = (identity(os.fstat(candidate_fd)),
                              {name: identity(read_file(candidate_fd, name)[1]) for name in controls})
        stage = '.' + parts[-1] + '.partial-' + uuid.uuid4().hex
        os.mkdir(stage, 0o700, dir_fd=parent_fd)
        stage_identity = os.stat(stage, dir_fd=parent_fd, follow_symlinks=False)
        stage_fd = os.open(stage, DIR_FLAGS, dir_fd=parent_fd)
        need((os.fstat(stage_fd).st_dev, os.fstat(stage_fd).st_ino) ==
             (stage_identity.st_dev, stage_identity.st_ino), 'OWNED_STAGE_CHANGED')
        host_intents = {}
        for source, raw in sorted(host.items()):
            installed = HOST_SOURCES[source]
            target = 'host-source' + installed
            write_file(stage_fd, target, raw)
            mode = 0o750 if installed.startswith('/usr/') else 0o640
            host_intents[source] = intent(target, installed, sha(raw), mode)
        dependency_intents = {}
        for relative, mode in sorted(directory_modes(root_snapshot).items()):
            make_directory(stage_fd, 'candidate/root' + ('/' + relative[:-1] if relative else ''), mode)
        root_fd = os.open('root', DIR_FLAGS, dir_fd=candidate_fd)
        try:
            for relative, spec in sorted(root_files.items()):
                raw, _ = read_file(root_fd, relative)
                need(sha(raw) == spec['sha256'], 'CANDIDATE_CHANGED')
                target = 'candidate/root/' + relative
                write_file(stage_fd, target, raw, spec['mode'])
                if relative.startswith('app/node_modules/'):
                    dependency_intents['/' + relative] = intent(target, OWNER_ROOT + relative[len('app/'):], sha(raw), spec['mode'])
            need(scan(root_fd, 0o755)[1] == root_snapshot, 'CANDIDATE_CHANGED')
        finally:
            os.close(root_fd)
        for name, raw in controls.items():
            need(read_file(candidate_fd, name)[0] == raw, 'CANDIDATE_CONTROL_CHANGED')
            write_file(stage_fd, 'candidate/' + name, raw)
        write_file(stage_fd, 'bootstrap-files.json', encode(manifest))
        write_file(stage_fd, 'host-intents.json', encode(host_intents))
        write_file(stage_fd, 'host-dependency-intents.json', encode(dependency_intents))
        report = dict(schema='c3-fixed-install-source-pack-report/v1', physicalAccepted=False,
                      operationalGO=False, installed=False, sourceHead=head, sourceTree=tree,
                      acceptedSourceBase=BASE, candidateBuiltFrom=candidate_report['sourceCommit'],
                      candidateBuiltTree=candidate_report['sourceTree'],
                      candidateManifestSha256=MANIFEST_PIN, candidateReportSha256=REPORT_PIN,
                      candidateModeSha256=MODE_PIN, candidateDirectoriesSha256=DIRECTORY_PIN,
                      counts={**COUNTS, 'hostSources': len(host), 'hostDependencyIntents': len(dependency_intents)},
                      unitIncluded=False, resourcePolicyIncluded=False, provisioningImplemented=False,
                      directIngressAccepted=False,
                      bootstrap='files map only; not a policy, inventory or accepted authority',
                      hostRuntime='Host Python/Node/OS tools and their loaders are NOT provisioned or accepted; candidate runtime is only fresh-root input.',
                      unimplemented=['fixed resource helper and fresh unit', 'root ownership and loaded units',
                                     'private root/proc/state mounts, UID/capabilities/namespaces/fds',
                                     'independent final policy and before-hold cgroup/unit admission',
                                     'direct literal ingress, physical network/data facts and finite preparation deadline'])
        write_file(stage_fd, 'report.json', encode(report))
        files, snapshot = scan(stage_fd)
        write_file(stage_fd, 'pack-manifest.json', encode(dict(schema='c3-fixed-install-source-pack/v1',
                   physicalAccepted=False, operationalGO=False, files=files, directories=directory_modes(snapshot),
                   selfExcluded='pack-manifest.json; all control metadata remains OUTSIDE candidate/root')))
        verify_pack_fd(stage_fd)
        # Re-read every finite source, plus repository and candidate identities at the boundary.
        need(repo_state(repo) == initial, 'SOURCE_REVISION_CHANGED')
        for source, raw in host.items():
            need(source_bytes(repo, repo_fd, head, source) == raw, 'SOURCE_CHANGED')
        current = verify_candidate(repo, repo_fd, head, candidate_fd)
        need(current[3] == root_snapshot, 'CANDIDATE_CHANGED')
        need((identity(os.fstat(candidate_fd)),
              {name: identity(read_file(candidate_fd, name)[1]) for name in controls}) == candidate_snapshot,
             'CANDIDATE_CONTROL_CHANGED')
        need({source: identity(read_file(repo_fd, source, worktree=True)[1]) for source in source_names}
             == source_snapshot, 'SOURCE_METADATA_CHANGED')
        for path, held_fd in ((repo, repo_fd), (candidate, candidate_fd)):
            check = open_directory(path)
            try:
                held = os.fstat(held_fd)
                now = os.fstat(check)
                need((held.st_dev, held.st_ino) == (now.st_dev, now.st_ino), 'INPUT_DIRECTORY_CHANGED')
            finally:
                os.close(check)
        fsync_tree(stage_fd)
        # No pathname-ancestor substitution can redirect publication or cleanup.
        check = open_directory(parent)
        try:
            need((os.fstat(check).st_dev, os.fstat(check).st_ino) == (info.st_dev, info.st_ino), 'OUTPUT_PARENT_CHANGED')
        finally:
            os.close(check)
        now = os.stat(stage, dir_fd=parent_fd, follow_symlinks=False)
        need((now.st_dev, now.st_ino) == (stage_identity.st_dev, stage_identity.st_ino), 'OWNED_STAGE_CHANGED')
        publication_attempted = True
        publish_noreplace(parent_fd, stage, parts[-1])
        published = True
        os.fsync(parent_fd)  # Failure now is visible-but-durability-unknown, never safe to overwrite/retry.
        # Read back the exact published target, not merely the retained stage descriptor.
        check = os.open(parts[-1], DIR_FLAGS, dir_fd=parent_fd)
        try:
            need(os.fstat(check).st_ino == stage_identity.st_ino and
                 os.fstat(check).st_dev == stage_identity.st_dev, 'PUBLISHED_TARGET_CHANGED')
            verify_pack_fd(check)
        finally:
            os.close(check)
        return Path(output)
    except Exception as error:
        if published or (publication_attempted and not
                         (isinstance(error, Refusal) and str(error) == 'OUTPUT_EXISTS')):
            raise Refusal('PACK_PUBLICATION_DURABILITY_OR_READBACK_UNKNOWN') from None
        if isinstance(error, Refusal):
            raise
        raise Refusal('PACK_BUILD_REFUSED') from None
    finally:
        cleanup_failed = False
        try:
            if stage is not None and not published and parent_fd is not None and stage_identity is not None:
                try:
                    now = os.stat(stage, dir_fd=parent_fd, follow_symlinks=False)
                except FileNotFoundError:
                    now = None  # A completed rename with lost reply must not trigger rollback.
                if now is not None and (now.st_dev, now.st_ino) == (stage_identity.st_dev, stage_identity.st_ino):
                    shutil.rmtree(stage, dir_fd=parent_fd)
        except Exception:
            cleanup_failed = True
        finally:
            for fd in (stage_fd, candidate_fd, repo_fd, parent_fd):
                if fd is not None:
                    try:
                        os.close(fd)
                    except OSError:
                        cleanup_failed = True
        if cleanup_failed:
            raise Refusal('PACK_PUBLICATION_DURABILITY_OR_READBACK_UNKNOWN' if publication_attempted
                          else 'PACK_CLEANUP_REFUSED') from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', required=True)
    parser.add_argument('--candidate', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args(argv)
    try:
        build(args.repo, args.candidate, args.output)
    except Refusal as error:
        print('REFUSAL ' + str(error), file=sys.stderr)
        return 2
    print('OFFLINE_SOURCE_PACK_ONLY physicalAccepted=false operationalGO=false')
    return 0


if __name__ == '__main__':
    sys.exit(main())
