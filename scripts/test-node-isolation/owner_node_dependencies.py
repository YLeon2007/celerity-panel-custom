#!/usr/bin/python3 -I
"""Stage only pinned owner Node dependencies offline; never acceptance or GO.

Consumes the existing immutable fixed-runner-v2-v2 pack, not a live donor or
npm. Explicit owner-root must already contain the exact accepted owner sources.
No sources, units, policies, binaries or authority records are written.
"""
import argparse
import os
from pathlib import Path
import shutil
import stat
import sys
import uuid

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
# Reuse checked primitives in a PRIVATE namespace, without changing old products.
# Every input descriptor, including directory enumeration, requires NOATIME;
# EPERM is a refusal, never a fallback to an ordinary read of frozen evidence.
# Only the legacy primitives and fixed profile are needed. The fixed runner's
# bootstrap imports no local modules beyond those two inputs; do not execute its
# ordinary file loader (or consult pyc). Pins are identical to that runner.
import hashlib
from types import SimpleNamespace

_PRODUCT_PINS = {
    'fresh_install_source_pack.py': 'af2fa0abe183faadb86ea724bbad0a2236cfcd0e9678d8dcae264808f873cea6',
    'fresh_install_source_pack_runner_v2_v2_profile.json': '93a80650a751ba833371f997b2b3f7d297e289684d631c5a0e053525c11309c8',
}


def product_bytes(name):
    pin = _PRODUCT_PINS[name]  # Finite names, not an arbitrary module loader.
    fd = os.open(HERE/name, os.O_RDONLY | os.O_NOATIME | os.O_NOFOLLOW |
                 os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise RuntimeError('UNSAFE_PRODUCT_SOURCE')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read()
        after = os.fstat(fd)
        if before != after or hashlib.sha256(raw).hexdigest() != pin:
            raise RuntimeError('PRODUCT_SOURCE_DRIFT')
        return raw
    finally:
        os.close(fd)


io = type(sys)('owner_dependency_io')
# Synthetic filename prevents traceback/linecache ordinary reopening of inputs.
exec(compile(product_bytes('fresh_install_source_pack.py'),
             '<verified-owner-dependency-primitives>', 'exec'), io.__dict__)
io.DIR_FLAGS |= os.O_NOATIME
io.FILE_FLAGS |= os.O_NOATIME
_profile = io.decode(product_bytes('fresh_install_source_pack_runner_v2_v2_profile.json'))
fixed = SimpleNamespace(PROFILE=_profile,
    PROFILE_PIN=_PRODUCT_PINS['fresh_install_source_pack_runner_v2_v2_profile.json'],
    SOURCE=_profile['sourceCommit'], SOURCE_TREE=_profile['sourceTree'],
    MANIFEST_PIN=_profile['manifestPin'], REPORT_PIN=_profile['reportPin'],
    COUNTS=_profile['counts'], OWNER_ROOT=io.OWNER_ROOT)
DONOR_MANIFEST_PIN = '1a6eaf39a27424a4f52d2ce3bc788a64bd86003726466e24c2ff9223a1fa8568'
DEPENDENCY_INTENTS_PIN = 'd7a635cb9a7208176119d730e3a5e7e8fb7d507fe7207aa3e0044b81266c6a8a'
LOCK_PIN = '5298202cf6ca2ce8da44f0578bd54c1146def29fd698c41bc62ac3b5982e6eac'
PREFIX = 'candidate/root/app/node_modules/'


def open_directory(path):
    # O_PATH traverses unowned ancestors without reading/enumerating them (and
    # without needing CAP_FOWNER for /). The actual read descriptor is NOATIME.
    parts = io.path_parts(path, True)
    flags = os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = result = None
    primary = None
    cleanup_errors = []
    try:
        fd = os.open('/', flags)
        for part in parts:
            child = os.open(part, flags, dir_fd=fd)
            previous, fd = fd, child  # Own child before any uncertain close.
            try:
                os.close(previous)  # Ownership retired; never retry this number.
            except OSError as error:
                cleanup_errors.append(error)
                raise
        result = os.open('.', io.DIR_FLAGS, dir_fd=fd)
    except Exception as error:
        primary = error
    finally:
        if fd is not None:
            handle, fd = fd, None
            try:
                os.close(handle)
            except OSError as error:
                cleanup_errors.append(error)
    if primary is not None or cleanup_errors:
        if result is not None:
            handle, result = result, None
            try:
                os.close(handle)  # Unreturned read FD still belongs to us.
            except OSError as error:
                cleanup_errors.append(error)
        if cleanup_errors:
            refusal = io.Refusal('DEPENDENCY_CLEANUP_UNKNOWN')
            for error in cleanup_errors:
                refusal.add_note('cleanup: '+type(error).__name__)
            raise refusal from (primary if primary is not None else cleanup_errors[0])
        if primary is not None:
            raise primary
    return result


io.open_directory = open_directory


def owner_sources():
    return {source: spec for source, spec in fixed.PROFILE['hostSources'].items()
            if spec['installed'] == fixed.OWNER_ROOT+source}


def checked_owner(fd):
    info = os.fstat(fd)
    io.need(info.st_uid == os.geteuid() and not info.st_mode & 0o022 and
            not os.listxattr(fd), 'UNSAFE_OWNER_ROOT')
    snapshot = {}
    for source, spec in owner_sources().items():
        raw, st = io.read_file(fd, source)
        io.need(io.sha(raw) == spec['sha256'] and
                stat.S_IMODE(st.st_mode) == spec['modeIntent'], 'OWNER_SOURCE_MISMATCH')
        snapshot[source] = io.identity(st)
    io.need(fixed.PROFILE['hostSources']['package-lock.json']['sha256'] == LOCK_PIN,
            'LOCK_PROFILE_MISMATCH')
    return snapshot


def donor_controls(fd):
    raw, _ = io.read_file(fd, 'pack-manifest.json')
    io.need(io.sha(raw) == DONOR_MANIFEST_PIN, 'DONOR_MANIFEST_MISMATCH')
    doc = io.decode(raw)
    for name, pin in (('candidate/manifest.json', fixed.MANIFEST_PIN),
                      ('candidate/report.json', fixed.REPORT_PIN),
                      ('profile.json', fixed.PROFILE_PIN),
                      ('host-dependency-intents.json', DEPENDENCY_INTENTS_PIN)):
        value, _ = io.read_file(fd, name)
        io.need(io.sha(value) == pin, 'DONOR_CONTROL_MISMATCH')
    manifest = io.decode(io.read_file(fd, 'candidate/manifest.json')[0])
    report = io.decode(io.read_file(fd, 'candidate/report.json')[0])
    io.need(report['sourceCommit'] == fixed.SOURCE and report['sourceTree'] == fixed.SOURCE_TREE
            and report['physicalAccepted'] is False, 'DONOR_SOURCE_MISMATCH')
    expected = {name[len(PREFIX):]: spec for name, spec in doc['files'].items()
                if name.startswith(PREFIX)}
    dep = {'/app/node_modules/'+name: spec for name, spec in expected.items()}
    io.need(len(expected) == fixed.COUNTS['dependencyFiles'] and
            io.sha(io.encode(dep)) == fixed.PROFILE['dependencyPin'], 'DEPENDENCY_BINDING_MISMATCH')
    io.need(all(manifest['/app/node_modules/'+name] == spec['sha256']
                for name, spec in expected.items()) and
            manifest['/app/package-lock.json'] == LOCK_PIN, 'LOCK_MANIFEST_MISMATCH')
    intents = {'/app/node_modules/'+name: io.intent(PREFIX+name,
               fixed.OWNER_ROOT+'node_modules/'+name, spec['sha256'], spec['mode'])
               for name, spec in expected.items()}
    io.need(io.read_file(fd, 'host-dependency-intents.json')[0] == io.encode(intents),
            'DEPENDENCY_INTENT_MISMATCH')
    directories = {name[len(PREFIX):]: mode for name, mode in doc['directories'].items()
                   if name.startswith(PREFIX)}
    return expected, directories


def same_path(path, fd):
    check = io.open_directory(path)
    try:
        io.need(io.identity(os.fstat(check)) == io.identity(os.fstat(fd)), 'INPUT_DIRECTORY_CHANGED')
    finally:
        os.close(check)


def stage(pack, owner_root):
    """Finite dependency-only publication, explicit root, atomic NOREPLACE.

    A successful local staging is NOT installed/physical/runtime acceptance.
    Post-publication uncertainty retains the output; no automatic replacement.
    """
    donor = owner = dependencies = staged = None
    partial = marker = None
    created = False
    attempted = published = False
    primary = result = None
    cleanup_errors = []
    try:
        io.path_parts(pack, True)
        io.path_parts(owner_root, True)
        io.need(not (pack == owner_root or pack.startswith(owner_root+'/') or
                     owner_root.startswith(pack+'/')), 'INPUT_OUTPUT_OVERLAP')
        donor = io.open_directory(pack)
        owner = io.open_directory(owner_root)
        io.need('node_modules' not in os.listdir(owner), 'OUTPUT_EXISTS')
        sources = checked_owner(owner)
        expected, directories = donor_controls(donor)
        dependencies = io.open_directory(pack+'/candidate/root/app/node_modules')
        files, before = io.scan(dependencies, 0o755)
        io.need(files == expected and io.directory_modes(before) == directories,
                'DEPENDENCY_PAYLOAD_MISMATCH')
        partial = '.owner-node-dependencies-'+uuid.uuid4().hex
        os.mkdir(partial, 0o755, dir_fd=owner)
        created = True
        marker = os.stat(partial, dir_fd=owner, follow_symlinks=False)
        io.need(stat.S_ISDIR(marker.st_mode), 'OWNED_STAGE_CHANGED')
        staged = os.open(partial, io.DIR_FLAGS, dir_fd=owner)
        opened = os.fstat(staged)
        io.need((opened.st_dev, opened.st_ino) == (marker.st_dev, marker.st_ino), 'OWNED_STAGE_CHANGED')
        os.fchmod(staged, 0o755)
        for name, mode in sorted(directories.items()):
            if name:
                io.make_directory(staged, name.rstrip('/'), mode)
        for name, spec in sorted(expected.items()):
            raw, st = io.read_file(dependencies, name)
            io.need(io.identity(st) == before[name] and io.sha(raw) == spec['sha256'],
                    'DEPENDENCY_CHANGED')
            io.write_file(staged, name, raw, spec['mode'])
        actual, snapshot = io.scan(staged, 0o755)
        io.need(actual == expected and io.directory_modes(snapshot) == directories,
                'STAGED_DEPENDENCY_MISMATCH')
        io.need(io.scan(dependencies, 0o755)[1] == before, 'DEPENDENCY_CHANGED')
        io.need(donor_controls(donor) == (expected, directories), 'DONOR_CHANGED')
        io.need(checked_owner(owner) == sources, 'OWNER_SOURCE_CHANGED')
        same_path(pack, donor)
        same_path(pack+'/candidate/root/app/node_modules', dependencies)
        same_path(owner_root, owner)
        io.fsync_tree(staged)
        now = os.stat(partial, dir_fd=owner, follow_symlinks=False)
        io.need((now.st_dev, now.st_ino) == (marker.st_dev, marker.st_ino), 'OWNED_STAGE_CHANGED')
        attempted = True
        io.publish_noreplace(owner, partial, 'node_modules')
        published = True
        os.fsync(owner)
        check = os.open('node_modules', io.DIR_FLAGS, dir_fd=owner)
        try:
            st = os.fstat(check)
            io.need((st.st_dev, st.st_ino) == (marker.st_dev, marker.st_ino), 'PUBLISHED_TARGET_CHANGED')
            actual, snapshot = io.scan(check, 0o755)
            io.need(actual == expected and io.directory_modes(snapshot) == directories,
                    'PUBLISHED_DEPENDENCY_MISMATCH')
        finally:
            try:
                os.close(check)  # Exactly one attempt, even on an uncertain reply.
            except OSError as error:
                cleanup_errors.append(error)
        result = dict(schema='c3-owner-node-dependency-stage/v1', dependencyFiles=len(expected),
                    sourceCommit=fixed.SOURCE, sourceTree=fixed.SOURCE_TREE,
                    profileSha256=fixed.PROFILE_PIN, donorManifestSha256=DONOR_MANIFEST_PIN,
                    dependencySha256=fixed.PROFILE['dependencyPin'], lockSha256=LOCK_PIN,
                    installedAccepted=False, physicalAccepted=False, GO=False)
    except Exception as error:
        primary = error
    finally:
        try:
            # Never roll back after an ambiguous rename, including a lost reply.
            known_unpublished = not attempted or (isinstance(primary, io.Refusal) and
                                                  str(primary) == 'OUTPUT_EXISTS')
            if created and known_unpublished and not published:
                io.need(marker is not None, 'OWNED_STAGE_IDENTITY_UNKNOWN')
                try:
                    now = os.stat(partial, dir_fd=owner, follow_symlinks=False)
                except FileNotFoundError:
                    now = None
                if now is not None:
                    io.need((now.st_dev, now.st_ino) == (marker.st_dev, marker.st_ino),
                            'OWNED_STAGE_CHANGED')
                    shutil.rmtree(partial, dir_fd=owner)
        except Exception as error:
            cleanup_errors.append(error)
        finally:
            for fd in (staged, dependencies, owner, donor):
                if fd is not None:
                    try:
                        os.close(fd)
                    except OSError as error:
                        cleanup_errors.append(error)
    uncertain = published or (attempted and not (isinstance(primary, io.Refusal) and
                                                str(primary) == 'OUTPUT_EXISTS'))
    if primary is not None or cleanup_errors:
        if uncertain:
            refusal = io.Refusal('DEPENDENCY_PUBLICATION_UNKNOWN_RETAIN_OUTPUT')
        elif cleanup_errors:
            refusal = io.Refusal('DEPENDENCY_CLEANUP_UNKNOWN')
        elif isinstance(primary, io.Refusal):
            raise primary
        else:
            refusal = io.Refusal('DEPENDENCY_STAGE_REFUSED')
        # Preserve primary without exposing paths in CLI output; aggregate every failure.
        for error in cleanup_errors:
            refusal.add_note('cleanup: '+type(error).__name__)
        raise refusal from primary
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pack', required=True)
    parser.add_argument('--owner-root', required=True)
    args = parser.parse_args()
    try:
        report = stage(args.pack, args.owner_root)
    except io.Refusal as error:
        print('REFUSAL '+str(error), file=sys.stderr)
        return 2
    print(io.encode(report).decode(), end='')
    return 0


if __name__ == '__main__':
    sys.exit(main())
