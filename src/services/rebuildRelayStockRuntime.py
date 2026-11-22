#!/usr/bin/env python3
"""Explicit rebuild-only xl2tpd prerequisite, before stock install-runtime.sh."""

import hashlib
import json
import os
from pathlib import Path
import runpy
import stat
import subprocess
import sys


SERVICE = 'xl2tpd.service'
ALIAS = 'l2tpd.service'  # LSB Provides in the original init script.
NAMES = {SERVICE, ALIAS}
NATIVE_DIR = '/etc/systemd/system'
LATE_DIR = '/run/systemd/generator.late'
NATIVE = f'{NATIVE_DIR}/{SERVICE}'
GENERATED = f'{LATE_DIR}/{SERVICE}'
INIT = '/etc/init.d/xl2tpd'
DEFAULTS = '/etc/default/xl2tpd'
DAEMON = '/usr/sbin/xl2tpd'
ROOT_OWNER = (0, 0)

# From the signed Debian trixie amd64 xl2tpd 1.3.18-1+b1 archive.
PACKAGE_ID = 'xl2tpd\tinstall ok installed\tamd64\t1.3.18-1+b1'
PACKAGE_FILES = {
    INIT: (0o755, '5d8342a68119d1b25daf55d4e6d8dfac6b4443103eef4c17f267461433afc914',
           '65b9d6566a0eb3ba4078b72e08ab38a0'),
    DEFAULTS: (0o644, '37b5938f462ec60b4f8c179b34f70b548c09da4691c938e88ce111ce41268833',
               'fadc31f26078d8c3fb033d7d4516500b'),
}
# Exact output of Debian trixie's amd64 systemd 257.13-1~deb13u1 generator
# for the pinned script at INIT: (normal runlevels 2/3/4/5, no start links).
SYSV_GENERATOR_SHA = '662f91830e6f76e08a47be605ba2480ae87add1eac44aa095629bc0a4484cb11'
GENERATED_HASHES = {
    'aaca316b0955a3ba75f9909a63826d3a5ba2cc46a39ca2690b7043d68b1e8ec7': True,
    '02a7d3131dd4be414a8cc025ca4144edd904f01d644572aec4722b14182ca2a3': False,
}
GENERATED_LINKS = {
    f'{LATE_DIR}/{ALIAS}': SERVICE,
    f'{LATE_DIR}/graphical.target.wants/{SERVICE}': f'../{SERVICE}',
    f'{LATE_DIR}/multi-user.target.wants/{SERVICE}': f'../{SERVICE}',
}
UNIT_DIRS = {
    '/etc/systemd/system.control', '/run/systemd/system.control', '/run/systemd/transient',
    '/run/systemd/generator.early', NATIVE_DIR, '/etc/systemd/system.attached',
    '/run/systemd/system', '/run/systemd/system.attached', '/run/systemd/generator',
    '/usr/local/lib/systemd/system', '/usr/lib/systemd/system', '/lib/systemd/system', LATE_DIR,
}
SYSTEMCTL = '/usr/bin/systemctl'
DPKG_QUERY = '/usr/bin/dpkg-query'
DPKG_DIVERT = '/usr/bin/dpkg-divert'
QUIESCENT = dict(ActiveState='inactive', SubState='dead', MainPID='0', ControlPID='0',
                 Job='', NeedDaemonReload='no', Transient='no', DropInPaths='', TriggeredBy='')
NO_OVERRIDES = dict(ExecCondition='', ExecStartPre='', ExecStartPost='', ExecReload='', ExecStopPost='',
                    Environment='', EnvironmentFiles='', RootDirectory='', RootImage='', User='', Group='')
# systemctl 257 doesn't print empty exec command lists or EnvironmentFiles
# even with --all. Every other requested key must have an actual record.
OMITTED_IF_EMPTY = {'ExecCondition', 'ExecStartPre', 'ExecStart', 'ExecStartPost',
                    'ExecReload', 'ExecStop', 'ExecStopPost', 'EnvironmentFiles'}
UNIT_KEYS = tuple(QUIESCENT) + tuple(NO_OVERRIDES) + (
    'Id', 'Names', 'LoadState', 'UnitFileState', 'FragmentPath', 'SourcePath', 'Type',
    'KillMode', 'Restart', 'RemainAfterExit', 'RuntimeDirectory', 'RuntimeDirectoryMode', 'ExecStart', 'ExecStop',
)


class Refusal(Exception):
    """Fixed, secret-free refusal code."""


def need(condition, code):
    if not condition:
        raise Refusal(code)


def checked(result, code, statuses=(0,)):
    need(result.returncode in statuses and not result.stderr, code)
    return result.stdout


def command(*argv, timeout=30):
    # Never inherit bus, dpkg-root, pager or locale overrides.
    return subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                          encoding='utf-8', timeout=timeout,
                          env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})


def ctl(run, *argv):
    return run(SYSTEMCTL, '--system', '--no-pager', '--no-ask-password', '--full', *argv)


def props(text, keys, omitted_if_empty=()):
    result = {}
    for line in text.splitlines():
        key, sep, value = line.partition('=')
        need(sep and key in keys and key not in result, 'UNIT_STATE')
        result[key] = value
    missing = set(keys) - result.keys()
    need(missing <= set(omitted_if_empty), 'UNIT_STATE')
    result.update(dict.fromkeys(missing, ''))
    return result


def owner_ok(info):
    return (info.st_uid, info.st_gid) == ROOT_OWNER


def lstat(path):
    try:
        return path.lstat()
    except FileNotFoundError:
        return None


def directory(root, name, code, protected=False):
    """Walk a fixed absolute path without following directory symlinks."""
    current = root
    for component in Path(name).parts[1:]:
        current /= component
        info = lstat(current)
        if info is None:
            return None
        need(stat.S_ISDIR(info.st_mode), code)
        if protected:
            need(owner_ok(info) and not info.st_mode & 0o022, code)
    return current


def regular_bytes(path, mode, code, limit=4096):
    info = lstat(path)
    if info is None or not stat.S_ISREG(info.st_mode):
        raise Refusal(code)
    # O_NONBLOCK prevents a substituted FIFO from blocking before fstat.
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as handle:
        info = os.fstat(handle.fileno())
        need(stat.S_ISREG(info.st_mode) and owner_ok(info) and info.st_nlink == 1
             and stat.S_IMODE(info.st_mode) == mode and info.st_size <= limit, code)
        data = handle.read(limit + 1)
        need(len(data) == info.st_size, code)
        return data


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def verify_package(root, run):
    result = checked(run(DPKG_QUERY, '-W', r'-f=${binary:Package}\t${Status}\t${Architecture}\t${Version}\n${Conffiles}\n',
                         'xl2tpd'), 'PACKAGE_FACTS')
    identity, _, conffiles = result.partition('\n')
    need(identity == PACKAGE_ID, 'PACKAGE_FACTS')
    rows = [row.split() for row in conffiles.splitlines() if row]
    for name, (mode, digest, md5) in PACKAGE_FILES.items():
        wanted = [row for row in rows if row and row[0] == name]
        need(wanted == [[name, md5]], 'PACKAGE_FACTS')
        need(checked(run(DPKG_QUERY, '-S', name), 'PACKAGE_FACTS') == f'xl2tpd: {name}\n'
             and checked(run(DPKG_DIVERT, '--truename', name), 'PACKAGE_FACTS') == f'{name}\n', 'PACKAGE_FACTS')
        path = root / name[1:]
        need(directory(root, str(Path(name).parent), 'PACKAGE_FILES', protected=True) is not None
             and lstat(path) is not None, 'PACKAGE_FILES')
        need(sha256(regular_bytes(path, mode, 'PACKAGE_FILES')) == digest, 'PACKAGE_FILES')


def merged_lib(root):
    info = lstat(root / 'lib')
    if info is None or stat.S_ISDIR(info.st_mode):
        return False
    need(stat.S_ISLNK(info.st_mode) and owner_ok(info)
         and os.readlink(root / 'lib') in ('usr/lib', '/usr/lib'), 'UNIT_FILES')
    return True


def alias_to_stock(path):
    return path.name.endswith('.service') and path.is_symlink() and Path(os.readlink(path)).name in NAMES


def unit_files(root, native_bytes, run, *, evidence=None):
    manager = props(checked(ctl(run, 'show', '--all', '--property=UnitPath'), 'UNIT_STATE'), ('UnitPath',))
    paths = set(manager['UnitPath'].split())
    need(NATIVE_DIR in paths and paths <= UNIT_DIRS, 'UNIT_STATE')
    need(directory(root, NATIVE_DIR, 'UNIT_FILES', protected=True) is not None, 'UNIT_FILES')
    merged = merged_lib(root)
    native = False
    generated = None
    links = set()
    forbidden = {'service.d'} | {name + suffix for name in NAMES
                                 for suffix in ('.d', '.wants', '.requires', '.upholds')}
    forbidden |= {f'{name[:-8]}.{suffix}' for name in NAMES for suffix in ('socket', 'timer', 'path')}
    for base in sorted(UNIT_DIRS):
        if merged and base == '/lib/systemd/system':
            continue
        folder = directory(root, base, 'UNIT_FILES')
        if folder is None:
            continue
        for entry in folder.iterdir():
            name = entry.name
            where = f'{base}/{name}'
            need(name not in forbidden, 'UNIT_FILES')
            if where == NATIVE:
                need(regular_bytes(entry, 0o644, 'UNIT_FILES') == native_bytes, 'UNIT_FILES')
                native = True
            elif where == GENERATED:
                directory(root, base, 'UNIT_FILES', protected=True)
                digest = sha256(regular_bytes(entry, 0o644, 'UNIT_FILES'))
                need(digest in GENERATED_HASHES and LATE_DIR in paths, 'UNIT_FILES')
                generated = GENERATED_HASHES[digest]
            elif where in GENERATED_LINKS:
                links.add(where)
            elif name in NAMES:
                raise Refusal('UNIT_FILES')
            elif name.endswith(('.wants', '.requires', '.upholds')):
                dependencies = directory(root, where, 'UNIT_FILES')
                if dependencies is None:
                    raise Refusal('UNIT_FILES')
                for dependency in dependencies.iterdir():
                    if dependency.name in NAMES or alias_to_stock(dependency):
                        relative = f'{where}/{dependency.name}'
                        need(relative in GENERATED_LINKS, 'UNIT_FILES')
                        links.add(relative)
            elif alias_to_stock(entry):
                # Catch shadow aliases, including a dangling alias to a known name.
                raise Refusal('UNIT_FILES')
    expected_links = set() if generated is None else (
        set(GENERATED_LINKS) if generated else {f'{LATE_DIR}/{ALIAS}'})
    need(not (native and generated is not None) and links == expected_links, 'UNIT_FILES')
    for name in links:
        directory(root, str(Path(name).parent), 'UNIT_FILES', protected=True)
        link = root / name[1:]
        info = link.lstat()
        need(stat.S_ISLNK(info.st_mode) and owner_ok(info) and os.readlink(link) == GENERATED_LINKS[name], 'UNIT_FILES')
    if evidence is not None:
        evidence['unitPath'] = manager['UnitPath']
        evidence['layout'] = {name: generation(root / name[1:]) for name in sorted(
            links | ({GENERATED} if generated is not None else {NATIVE} if native else set()))}
        evidence['wrapper'] = generated
    return 'native' if native else 'generated' if generated is not None else 'missing'


def match(info, **values):
    need(all(info[k] == v for k, v in values.items()), 'UNIT_STATE')


def argv_matches(value, path, argv):
    # systemctl includes changing execution timestamps; bind the whole argv and
    # disallow extra commands. The exact fragment bytes are checked separately.
    return (value.startswith(f'{{ path={path} ; argv[]={argv} ; ignore_errors=no ; ')
            and value.endswith(' }') and value.count('{') == value.count('}') == 1)


def verify_manager(run, state):
    for name in (SERVICE, ALIAS):
        result = ctl(run, 'show', '--all', '--property=' + ','.join(UNIT_KEYS), name)
        info = props(checked(result, 'UNIT_STATE', (0, 1)), UNIT_KEYS, OMITTED_IF_EMPTY)
        match(info, **QUIESCENT)
        if state == 'generated':
            need(result.returncode == 0 and set(info['Names'].split()) == NAMES, 'UNIT_STATE')
            match(info, **NO_OVERRIDES, Id=SERVICE, LoadState='loaded', UnitFileState='generated',
                  FragmentPath=GENERATED, SourcePath=INIT, Type='forking', KillMode='process',
                  Restart='no', RemainAfterExit='yes', RuntimeDirectory='')
            need(argv_matches(info['ExecStart'], INIT, INIT + ' start')
                 and argv_matches(info['ExecStop'], INIT, INIT + ' stop'), 'UNIT_STATE')
        elif state == 'native' and name == SERVICE:
            need(result.returncode == 0, 'UNIT_STATE')
            match(info, **NO_OVERRIDES, Id=SERVICE, Names=SERVICE, LoadState='loaded', UnitFileState='disabled',
                  FragmentPath=NATIVE, SourcePath='', Type='simple', KillMode='control-group', Restart='on-failure',
                  RemainAfterExit='no', RuntimeDirectory='xl2tpd', RuntimeDirectoryMode='0755', ExecStop='')
            need(argv_matches(info['ExecStart'], DAEMON, DAEMON + ' -D'), 'UNIT_STATE')
        else:
            match(info, Id=name, Names=name, LoadState='not-found', FragmentPath='', SourcePath='',
                  ExecStart='', ExecStop='')
            need(info['UnitFileState'] in ('', 'not-found'), 'UNIT_STATE')
    # A queued job need not appear in an earlier per-unit snapshot. Require the
    # system manager's queue to be empty, including jobs through aliases.
    need(checked(ctl(run, 'list-jobs', '--no-legend', '--plain'), 'UNIT_STATE') == '', 'PENDING_JOBS')


def generator_input(root, *, missing, strict):
    # If SysV generation is possible, installing another runtime package can
    # regenerate the wrapper before install-runtime.sh checks LoadState.
    bases = ('/run/systemd/system-generators', '/etc/systemd/system-generators',
             '/usr/local/lib/systemd/system-generators', '/usr/lib/systemd/system-generators',
             '/lib/systemd/system-generators')
    merged = merged_lib(root)
    for base in bases:
        if merged and base.startswith('/lib/'):
            continue
        folder = directory(root, base, 'UNIT_FILES', protected=strict)
        if folder is None:
            continue
        generator = folder / 'systemd-sysv-generator'
        info = lstat(generator)
        if info is None:
            continue
        masked = stat.S_ISLNK(info.st_mode) and owner_ok(info) and os.readlink(generator) == '/dev/null'
        path = '/' + str(generator.relative_to(root))
        if masked:
            return [path, 'masked', generation(generator)]
        # The exact output pins authorize the generated layout, not an
        # operator generator executable that could run on daemon-reload.
        need(not missing and base in ('/usr/lib/systemd/system-generators', '/lib/systemd/system-generators'),
             'UNIT_STATE')
        digest = sha256(regular_bytes(generator, 0o755, 'UNIT_FILES', limit=1024 * 1024))
        need(digest == SYSV_GENERATOR_SHA, 'UNIT_FILES')
        return [path, digest, generation(generator)]
    return None


def generation(path):
    info = path.lstat()
    return [info.st_dev, info.st_ino, info.st_ctime_ns]


def observe(root, run, helper):
    """Strict read-only DIRECT witness; no standalone fallback/import."""
    release_path = '/usr/lib/os-release'
    need(directory(root, '/usr/lib', 'UNSUPPORTED_OS', protected=True) is not None, 'UNSUPPORTED_OS')
    release = regular_bytes(root / release_path[1:], 0o644, 'UNSUPPORTED_OS')
    rows = [line.split(b'=', 1) for line in release.splitlines() if b'=' in line]
    for key, value in ((b'ID', b'debian'), (b'VERSION_CODENAME', b'trixie')):
        need([row[1] for row in rows if row[0] == key] == [value], 'UNSUPPORTED_OS')
    verify_package(root, run)
    evidence = {}
    state = unit_files(root, helper['UNIT'], run, evidence=evidence)
    verify_manager(run, state)
    evidence['state'] = state
    # The missing route must not have an effective generator. Bind the same
    # generator path and bytes (if present) through the later native readback.
    generator = generator_input(root, missing=state == 'missing', strict=True)
    need(state != 'generated' or (generator is not None and generator[1] == SYSV_GENERATOR_SHA), 'UNIT_STATE')
    evidence['inputs'] = {
        'release': sha256(release),
        'generator': generator,
        'files': {name: generation(root / name[1:]) for name in (*PACKAGE_FILES, release_path)},
    }
    return evidence


def create_native(root, run, helper):
    """Reserved DIRECT writer; the caller owns intent and full readback."""
    try:
        helper['ensure'](root)
        folder = root / NATIVE_DIR[1:]
        fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        target = root / NATIVE[1:]
        need(regular_bytes(target, 0o644, 'UNIT_FILES') == helper['UNIT'], 'UNIT_FILES')
        created = generation(target)
    except OSError as exc:
        raise Refusal('CREATE_FAILED') from exc
    checked(ctl(run, 'daemon-reload'), 'RELOAD_FAILED')
    return created


def prepare(root, run):
    verify_package(root, run)
    helper = runpy.run_path(str(Path(__file__).resolve().parents[1]
                               / 'modules/relay-l2tp/node-artifacts/l2tp/ensure-xl2tpd-unit.py'))
    state = unit_files(root, helper['UNIT'], run)
    verify_manager(run, state)
    if state == 'native':
        return 'native-present'
    if state == 'missing':
        generator_input(root, missing=True, strict=False)
        return 'stock-not-found'

    # Only this branch writes. The existing helper opens the fixed destination
    # with O_EXCL | O_NOFOLLOW; an intervening occupant is never adopted.
    try:
        helper['ensure'](root)
    except OSError as exc:
        raise Refusal('CREATE_FAILED') from exc
    checked(ctl(run, 'daemon-reload'), 'RELOAD_FAILED')
    need(unit_files(root, helper['UNIT'], run) == 'native', 'UNIT_FILES')
    verify_manager(run, 'native')
    return 'created'


def main():
    try:
        need(len(sys.argv) == 1, 'INVALID_ARGUMENTS')
        need((os.geteuid(), os.getegid()) == ROOT_OWNER, 'ROOT_REQUIRED')
        root = Path('/')
        release = set((root / 'usr/lib/os-release').read_text(encoding='utf-8').splitlines())
        need({'ID=debian', 'VERSION_CODENAME=trixie'} <= release, 'UNSUPPORTED_OS')
        action = prepare(root, command)
    except (Refusal, OSError, ValueError, subprocess.SubprocessError) as exc:
        reason = str(exc) if isinstance(exc, Refusal) else 'OBSERVATION_FAILED'
        print(json.dumps({'status': 'error', 'code': reason}), file=sys.stderr)
        return 1
    print(json.dumps({'status': 'ok', 'action': action}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
