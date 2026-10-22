#!/usr/bin/python3 -I
"""Explicit fixed9e v1 OFFLINE export/check; never install, execute or GO.

Reuses only unchanged legacy IO/Git/publication primitives. The publication
orchestrator is deliberately duplicated (see FRESH_INSTALL_SOURCE_PACK_9E_V1.md),
not a mutation of legacy globals or a configurable acceptance-pin API.
"""
import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import stat
import sys
import uuid
sys.dont_write_bytecode = True

HERE = Path(__file__).resolve().parent
# Product code dependencies are fixed too; never import repository application.
def fixed_product_file(name, pin):
    fd = os.open(HERE / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise RuntimeError('UNSAFE_PRODUCT_SOURCE')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read()
        if hashlib.sha256(raw).hexdigest() != pin:
            raise RuntimeError('PRODUCT_SOURCE_DRIFT')
        return raw
    finally:
        os.close(fd)

LEGACY_PIN = 'af2fa0abe183faadb86ea724bbad0a2236cfcd0e9678d8dcae264808f873cea6'
# Compile the checked bytes, not a second pathname read/import or cached pyc.
core = type(sys)('fixed_legacy_source_pack_primitives')
exec(compile(fixed_product_file('fresh_install_source_pack.py', LEGACY_PIN),
             str(HERE / 'fresh_install_source_pack.py'), 'exec'), core.__dict__)
Refusal, need, sha, encode, decode = core.Refusal, core.need, core.sha, core.encode, core.decode
path_parts, open_directory, read_file = core.path_parts, core.open_directory, core.read_file
identity, scan, directory_modes = core.identity, core.scan, core.directory_modes
git, repo_state, committed = core.git, core.repo_state, core.committed
write_file, make_directory = core.write_file, core.make_directory
fsync_tree, publish_noreplace = core.fsync_tree, core.publish_noreplace
intent, DIR_FLAGS = core.intent, core.DIR_FLAGS
PROFILE_PIN = '6f9bbb669ab2b10138ce9cccafa10eab95d978098839234813ede5acc4a76ab9'
PROFILE_RAW = fixed_product_file('fresh_install_source_pack_9e_v1_profile.json', PROFILE_PIN)
PROFILE = decode(PROFILE_RAW)
SOURCE = '9e1b9897539750c3fef02b98055967d1a7edbbec'
SOURCE_TREE = '97c29e780e82a9cf8f102f984b7dc5deb872a368'
BASE = BUILT_FROM = SOURCE
MANIFEST_PIN = PROFILE['manifestPin']
REPORT_PIN = PROFILE['reportPin']
MODE_PIN = PROFILE['modePin']
DIRECTORY_PIN = PROFILE['directoryPin']
COUNTS = PROFILE['counts']
HOST_SOURCES = {source: spec['installed'] for source, spec in PROFILE['hostSources'].items()}
OWNER_ROOT = '/opt/celerity-fresh-owner/'
SUPERVISORS = dict(core.SUPERVISORS)
NETWORK_SOURCE_PINS = dict(core.NETWORK_SOURCE_PINS)


def source_bytes(repo, repo_fd, revision, relative):
    need(revision == SOURCE, 'FIXED_SOURCE_REQUIRED')
    raw, mode = committed(repo, SOURCE, relative)
    actual, info = read_file(repo_fd, relative, worktree=True)
    need(actual == raw and bool(info.st_mode & 0o111) == bool(mode & 0o111), 'SOURCE_WORKTREE_DRIFT')
    return raw


def candidate_content(candidate_fd, packed=False):
    need(set(os.listdir(candidate_fd)) == {'manifest.json', 'report.json', 'root'}, 'CANDIDATE_MEMBERSHIP')
    need(stat.S_IMODE(os.fstat(candidate_fd).st_mode) == 0o700, 'CANDIDATE_NOT_PRIVATE')
    controls = {}
    for name, pin in (('manifest.json', MANIFEST_PIN), ('report.json', REPORT_PIN)):
        raw, info = read_file(candidate_fd, name)
        need(sha(raw) == pin, 'CANDIDATE_PIN_MISMATCH')
        need(stat.S_IMODE(info.st_mode) == (0o600 if packed else 0o644), 'CANDIDATE_CONTROL_MODE')
        controls[name] = decode(raw)
    manifest, report = controls['manifest.json'], controls['report.json']
    need(report['sourceCommit'] == SOURCE and report['sourceTree'] == SOURCE_TREE and
         encode(report['counts']) == encode(COUNTS) and report['physicalAccepted'] is False,
         'CANDIDATE_PROVENANCE')
    root = os.open('root', DIR_FLAGS, dir_fd=candidate_fd)
    try:
        files, snapshot = scan(root, 0o755)
    finally:
        os.close(root)
    need(len(files) == COUNTS['payloadFiles'] and
         {'/' + k: v['sha256'] for k, v in files.items()} == manifest, 'CANDIDATE_ROOT_MISMATCH')
    need(sha(encode({'/' + k: v['mode'] for k, v in files.items()})) == MODE_PIN,
         'CANDIDATE_MODE_PIN_MISMATCH')
    need(sha(encode({'/' + k.rstrip('/'): v for k, v in directory_modes(snapshot).items()})) == DIRECTORY_PIN,
         'CANDIDATE_DIRECTORY_PIN_MISMATCH')
    return manifest, report, files, snapshot


def verify_candidate(repo, repo_fd, revision, candidate_fd):
    need(revision == SOURCE and git(repo, 'rev-parse', SOURCE + '^{tree}').decode().strip() == SOURCE_TREE,
         'FIXED_SOURCE_REQUIRED')
    result = candidate_content(candidate_fd)
    manifest = result[0]
    need(len(PROFILE['sourceFiles']) == COUNTS['sourceFiles'], 'PROFILE_SOURCE_COUNT')
    for target, spec in PROFILE['sourceFiles'].items():
        raw = source_bytes(repo, repo_fd, SOURCE, spec['source'])
        need(sha(raw) == spec['sha256'] == manifest[target] and
             result[2][target[1:]]['mode'] == spec['mode'], 'CANDIDATE_SOURCE_MISMATCH')
    return result


def pack_report():
    return dict(schema='c3-fixed9e-offline-source-pack-report/v1', profile='fixed9e-v1',
                profileSha256=PROFILE_PIN, sourceHead=SOURCE, sourceTree=SOURCE_TREE,
                acceptedSourceBase=SOURCE, candidateBuiltFrom=BUILT_FROM,
                candidateManifestSha256=MANIFEST_PIN, candidateReportSha256=REPORT_PIN,
                candidateModeSha256=MODE_PIN, candidateDirectoriesSha256=DIRECTORY_PIN,
                counts={**COUNTS, 'hostSources': len(HOST_SOURCES),
                        'hostDependencyIntents': COUNTS['dependencyFiles']},
                networkUnitIncluded=True, resourcePolicyIncluded=False,
                installed=False, physicalAccepted=False, operationalGO=False,
                provisioningImplemented=False, strict3sAccepted=False,
                requiredGates=['independent parent source review before integration',
                    'independent installed source/runtime/loaded-unit and eligibility acceptance',
                    'physical root/proc/state/UID/capability/netns/FD rehearsal',
                    'accepted network lease/resource publishers and held writer exclusion',
                    'controller netns entry, literal ingress and network/data-path rehearsal',
                    'worker remote SSH, external DNS/egress, public HTTPS, all-five hold/handback',
                    'crash/unknown recovery, operator strict3s choice and final acceptance'])


def expected_host_intents():
    return {source: intent('host-source' + spec['installed'], spec['installed'],
                           spec['sha256'], spec['modeIntent'])
            for source, spec in PROFILE['hostSources'].items()}


def verify_pack_fd(fd):
    need(stat.S_IMODE(os.fstat(fd).st_mode) == 0o700, 'PACK_NOT_PRIVATE')
    raw, info = read_file(fd, 'pack-manifest.json')
    need(stat.S_IMODE(info.st_mode) == 0o600, 'PACK_CONTROL_MODE')
    doc = decode(raw)
    need(type(doc) is dict and doc.get('schema') == 'c3-fixed9e-offline-source-pack/v1' and
         doc.get('profile') == 'fixed9e-v1' and doc.get('physicalAccepted') is False and
         doc.get('operationalGO') is False, 'PACK_SCHEMA')
    cfd = os.open('candidate', DIR_FLAGS, dir_fd=fd)
    try:
        manifest, report, root_files, snapshot = candidate_content(cfd, packed=True)
    finally:
        os.close(cfd)
    expected = {'candidate/root/' + k: v for k, v in root_files.items()}
    def control(name, value):
        actual, st = read_file(fd, name)
        need(actual == value and stat.S_IMODE(st.st_mode) == 0o600, 'PACK_AUTHORITY_DRIFT')
        expected[name] = dict(sha256=sha(value), size=len(value), mode=0o600)
    for name, pin in (('manifest.json', MANIFEST_PIN), ('report.json', REPORT_PIN)):
        value, _ = read_file(fd, 'candidate/' + name)
        need(sha(value) == pin, 'CANDIDATE_PIN_MISMATCH')
        control('candidate/' + name, value)
    control('profile.json', PROFILE_RAW)
    control('report.json', encode(pack_report()))
    control('bootstrap-files.json', encode(manifest))
    control('host-intents.json', encode(expected_host_intents()))
    control('network-source-pins.json', encode(NETWORK_SOURCE_PINS))
    dependency_intents = {('/' + relative): intent('candidate/root/' + relative,
        OWNER_ROOT + relative[len('app/'):], spec['sha256'], spec['mode'])
        for relative, spec in root_files.items() if relative.startswith('app/node_modules/')}
    control('host-dependency-intents.json', encode(dependency_intents))
    for source, spec in PROFILE['hostSources'].items():
        target = 'host-source' + spec['installed']
        value, st = read_file(fd, target)
        need(sha(value) == spec['sha256'] and stat.S_IMODE(st.st_mode) == 0o600, 'HOST_SOURCE_DRIFT')
        expected[target] = dict(sha256=spec['sha256'], size=len(value), mode=0o600)
    files, pack_snapshot = scan(fd)
    del files['pack-manifest.json']
    need(encode(files) == encode(expected), 'PACK_EXACT_MEMBERSHIP_OR_MODE_DRIFT')
    # Finite directory closure, including candidate empty directories; never trust
    # the caller-rewritable outer manifest as an acceptance inventory.
    directories = {'': 0o700}
    for relative in expected:
        parts = relative.split('/')
        for n in range(1, len(parts)):
            directories['/'.join(parts[:n]) + '/'] = 0o700
    for relative, mode in directory_modes(snapshot).items():
        directories['candidate/root/' + relative] = mode
    need(encode(directory_modes(pack_snapshot)) == encode(directories), 'PACK_DIRECTORY_DRIFT')
    need(encode(doc) == encode(dict(schema='c3-fixed9e-offline-source-pack/v1',
         profile='fixed9e-v1', physicalAccepted=False, operationalGO=False,
         files=expected, directories=directories,
         selfExcluded='pack-manifest.json; integrity metadata is not acceptance authority')),
         'PACK_CONTENT_DRIFT')
    return pack_report()


def verify_pack(output):
    try:
        fd = open_directory(output)
        try:
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
        head, tree = SOURCE, SOURCE_TREE
        git(repo, 'merge-base', '--is-ancestor', SOURCE, initial[0])
        manifest, candidate_report, root_files, root_snapshot = verify_candidate(repo, repo_fd, head, candidate_fd)
        controls = {name: read_file(candidate_fd, name)[0] for name in ('manifest.json', 'report.json')}
        host = {source: source_bytes(repo, repo_fd, SOURCE, source) for source in HOST_SOURCES}
        need(all(sha(raw) == PROFILE['hostSources'][source]['sha256'] for source, raw in host.items()), 'HOST_SOURCE_DRIFT')
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
            mode = (0o750 if installed.startswith('/usr/') else
                    0o644 if installed.startswith('/etc/systemd/system/') else 0o640)
            host_intents[source] = intent(target, installed, sha(raw), mode)
        dependency_intents = {}
        # Keep the control ancestor private; root payload traversal is 0755.
        make_directory(stage_fd, 'candidate', 0o700)
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
        write_file(stage_fd, 'network-source-pins.json', encode(NETWORK_SOURCE_PINS))
        write_file(stage_fd, 'host-dependency-intents.json', encode(dependency_intents))
        write_file(stage_fd, 'profile.json', PROFILE_RAW)
        report = pack_report()
        write_file(stage_fd, 'report.json', encode(report))
        files, snapshot = scan(stage_fd)
        write_file(stage_fd, 'pack-manifest.json', encode(dict(schema='c3-fixed9e-offline-source-pack/v1',
                   profile='fixed9e-v1', physicalAccepted=False, operationalGO=False,
                   files=files, directories=directory_modes(snapshot),
                   selfExcluded='pack-manifest.json; integrity metadata is not acceptance authority')))
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
    parser.add_argument('--profile', required=True, choices=['fixed9e-v1'])
    sub = parser.add_subparsers(dest='action', required=True)
    producer = sub.add_parser('build')
    producer.add_argument('--repo', required=True)
    producer.add_argument('--candidate', required=True)
    producer.add_argument('--output', required=True)
    checker = sub.add_parser('check')
    checker.add_argument('--pack', required=True)
    args = parser.parse_args(argv)
    try:
        if args.action == 'build':
            build(args.repo, args.candidate, args.output)
        else:
            verify_pack(args.pack)
    except Refusal as error:
        print('REFUSAL ' + str(error), file=sys.stderr)
        return 2
    print('FIXED9E_V1_OFFLINE_ONLY installed=false physicalAccepted=false operationalGO=false')
    return 0

if __name__ == '__main__':
    sys.exit(main())
