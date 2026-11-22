"""Read-only admission and one-shot Debian package preparation for DIRECT.

No entry point or ambient command runner. The caller must serialize DIRECT
writers and run argv in the same host/namespaces as root, with C locale, clean
system environment, no stdin, a deadline and bounded capture. A successful
mutating run must mean the invocation is settled (not merely a lost/closed
transport). On any uncertain result we leave the fences for manual review.

This consumes root-owned APT indexes previously authenticated by Debian APT;
it does not refresh or independently re-authenticate them. It trusts Debian's
maintainer scripts to use the normal service helpers, not arbitrary scripts,
a hostile root, or concurrent administrative writers. Linux does not provide
an atomic transaction across dpkg, PID 1 and the filesystem. A private root is
a filesystem test seam, not a chroot: only a modeled runner may be used with it.
"""

import ctypes
import fcntl
import hashlib
import json
import os
import re
import stat
import struct
import uuid
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Literal, overload


REQUESTED = ('strongswan', 'strongswan-starter', 'strongswan-charon', 'xl2tpd', 'ppp', 'nftables')
LIBCHARON = 'strongswan-libcharon'  # Debian's version-matched charon library, not another IKE daemon.
NATIVE = {'strongswan-starter.service': 'strongswan-starter', 'nftables.service': 'nftables'}
IKE_ALIAS = 'ipsec.service'
IKE_PRIMARY = 'strongswan-starter.service'
SYSV = {'xl2tpd': 'xl2tpd', 'ipsec': 'strongswan-starter', 'strongswan-starter': 'strongswan-starter',
        'nftables': 'nftables'}
UNITS = tuple(sorted(set(NATIVE) | {n + '.service' for n in SYSV} | {
    'strongswan.service', 'strongswan-swanctl.service', 'charon-systemd.service', 'charon.service', 'charon-nm.service',
    'libreswan.service', 'openswan.service', 'pluto.service', 'racoon.service', 'racoon2.service',
    'iked.service', 'openiked.service', 'isakmpd.service', 'l2tpd.service',
    'openl2tp.service', 'kl2tpd.service', 'celerity-rebuild-l2tp-network.service',
}))
FOREIGN = (set(n[:-8] for n in UNITS) - set(REQUESTED)) | {'ike', 'ike-scan', 'openiked'}
DAEMONS = (set(n[:-8] for n in UNITS) | {'starter', 'charon-systemd', 'charon-nm', 'pluto', 'pppd',
            'nft', 'apt', 'apt-get', 'apt.systemd.dai', 'dpkg', 'dpkg-deb', 'unattended-upgr',
            'packagekitd', 'invoke-rc.d', 'deb-systemd-inv', 'update-rc.d'})
SYSTEM = '/etc/systemd/system'
VENDOR = '/usr/lib/systemd/system'
LATE = '/run/systemd/generator.late'
UNIT_DIRS = (SYSTEM, VENDOR, LATE, '/etc/systemd/system.control', '/run/systemd/system.control',
             '/run/systemd/transient', '/run/systemd/generator.early', '/etc/systemd/system.attached',
             '/run/systemd/system', '/run/systemd/system.attached', '/run/systemd/generator',
             '/usr/local/lib/systemd/system', '/usr/lib/systemd/system.attached')
POLICY = '/usr/sbin/policy-rc.d'
RCD = tuple(f'/etc/rc{i}.d' for i in 'S0123456')
KEYRING = '/usr/share/keyrings/debian-archive-keyring.gpg'
CTL = ('/usr/bin/systemctl', '--system', '--no-pager', '--no-ask-password', '--full')
DPKG = '/usr/bin/dpkg'
QUERY = '/usr/bin/dpkg-query'
FORMAT = '-f=${binary:Package}\\t${db:Status-Abbrev}\\t${Architecture}\\t${Version}\\n'
PROPS = ('Id', 'Names', 'LoadState', 'FragmentPath', 'SourcePath', 'UnitFileState', 'ActiveState',
         'SubState', 'MainPID', 'ControlPID', 'Job', 'NeedDaemonReload', 'Transient', 'DropInPaths', 'TriggeredBy')
NAME = r'[a-z0-9][a-z0-9+.-]+'
VERSION = r'[0-9][A-Za-z0-9.+:~\-]*'
ARCH = 'amd64'  # The surrounding DIRECT stock-package predicates are amd64.
# C-locale apt-get simulation labels, not independent source authentication.
RELEASE = r'(?:Debian:13(?:\.[0-9]+)?/stable(?:-updates)?|Debian-Security:13/stable-security)'
LEGACY_SOURCE = re.compile(r'(deb|deb-src)[ \t]+(?:\[signed-by=' + re.escape(KEYRING) + r'\][ \t]+)?'
                           r'(\S+)[ \t]+(\S+)[ \t]+(.+)')
MAX_PLAN = 48
LIMIT = 8 * 1024 * 1024
APT_TIMEOUT = 78
XL_GENERATED = {
    # Also pinned by rebuildRelayStockRuntime.py, from the Debian 257 generator.
    '02a7d3131dd4be414a8cc025ca4144edd904f01d644572aec4722b14182ca2a3': False,
    'aaca316b0955a3ba75f9909a63826d3a5ba2cc46a39ca2690b7043d68b1e8ec7': True,
}


class Refusal(Exception):
    """Fixed diagnostics; command output, settings and paths are not returned."""


def need(value, code):
    if not value:
        raise Refusal(code)


def _owner(info):
    return (info.st_uid, info.st_gid) == (0, 0)


def _trusted(info):
    return _owner(info) and not info.st_mode & 0o022


def _snapshot(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)


def _id(info):
    return (info.st_dev, info.st_ino)


def _stat(path, fd=None):
    try:
        return os.stat(path, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


@overload
def _dir(root: Path, name: str, required: Literal[True] = True) -> Path: ...


@overload
def _dir(root: Path, name: str, required: Literal[False]) -> Path | None: ...


def _dir(root: Path, name: str, required: bool = True):
    path = root
    for part in Path(name).parts[1:]:
        path /= part
        info = _stat(path)
        if info is None and not required:
            return None
        need(info is not None and stat.S_ISDIR(info.st_mode) and _trusted(info), 'PACKAGE_DIRECTORY')
    return path


def _regular(path, limit=LIMIT):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as f:
        info = os.fstat(f.fileno())
        need(stat.S_ISREG(info.st_mode) and _trusted(info) and info.st_nlink == 1
             and info.st_size <= limit, 'PACKAGE_FILE')
        data = f.read(limit + 1)
        need(len(data) == info.st_size and _snapshot(os.fstat(f.fileno())) == _snapshot(info), 'PACKAGE_FILE')
        return data


def _idle_lock(path, code):
    info = _stat(path)
    if info is None:
        return
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        need(stat.S_ISREG(info.st_mode) and _trusted(info) and info.st_nlink == 1
             and _snapshot(os.fstat(fd)) == _snapshot(info), code)
        # Linux amd64 struct flock. Query conflicts without taking/releasing a
        # lock or creating its file; apt/dpkg take their own native locks.
        fmt = '=hh4xqqi4x'
        query = struct.pack(fmt, fcntl.F_WRLCK, os.SEEK_SET, 0, 0, 0)
        mode, *_ = struct.unpack(fmt, fcntl.fcntl(fd, fcntl.F_GETLK, query))
        need(mode == fcntl.F_UNLCK and _snapshot(path.lstat()) == _snapshot(info), code)
    finally:
        os.close(fd)


def _command(run, argv, code, statuses=(0,), timeout=6, quiet=True):
    try:
        reply = run(tuple(argv), timeout)
        need(type(reply) is tuple and len(reply) == 3, code)
        rc, out, err = reply
        if (type(rc) is not int or type(out) is not bytes or type(err) is not bytes or rc not in statuses
                or len(out) + len(err) > LIMIT or (quiet and err)):
            raise Refusal(code)
        return rc, out
    except Exception:
        raise Refusal(code) from None


def _text(data, code):
    try:
        text = data.decode('utf-8')
    except UnicodeError:
        raise Refusal(code) from None
    need(not re.search(r'[\x00-\x08\x0b-\x1f\x7f]', text), code)
    return text


def _out(run, argv, code):
    return _text(_command(run, argv, code)[1], code)


def _environment(root):
    need(root.is_absolute() and '..' not in root.parts and root.resolve() == root
         and stat.S_ISDIR(root.lstat().st_mode) and _trusted(root.lstat()), 'PACKAGE_ROOT')
    for name in ('/usr/lib', '/etc', '/usr/bin', '/usr/sbin', SYSTEM, VENDOR, '/var/lib/dpkg',
                 '/var/lib/dpkg/info', '/var/lib/dpkg/updates', '/run/systemd'):
        _dir(root, name)
    link = _stat(root / 'lib')
    need(link is not None and stat.S_ISLNK(link.st_mode) and _owner(link)
         and os.readlink(root / 'lib') in ('usr/lib', '/usr/lib'), 'PACKAGE_ROOT')
    osrel = root / 'etc/os-release'
    info = _stat(osrel)
    need(info is None or (stat.S_ISLNK(info.st_mode) and _owner(info)
         and os.readlink(osrel) in ('../usr/lib/os-release', '/usr/lib/os-release')), 'PACKAGE_OS')
    text = _text(_regular(root / 'usr/lib/os-release', 8192), 'PACKAGE_OS')
    for k, value in (('ID', 'debian'), ('VERSION_ID', '13'), ('VERSION_CODENAME', 'trixie')):
        values = [row.partition('=')[2] for row in text.split('\n') if row.startswith(k + '=')]
        need(values == [value] or values == ['"' + value + '"'], 'PACKAGE_OS')
    for path in ('/etc/systemd/system-generators', '/run/systemd/system-generators',
                 '/usr/local/lib/systemd/system-generators', '/run/systemd/system.control'):
        folder = _dir(root, path, False)
        need(folder is None or not any(folder.iterdir()), 'PACKAGE_OVERRIDE')
    _dir(root, '/usr/lib/systemd/system-generators', False)
    # Relevant Debian helpers can follow diversions and local init defaults.
    for path in (POLICY, '/usr/sbin/policy-rc.d.distrib', '/etc/alternatives/policy-rc.d'):
        parent = _dir(root, str(Path(path).parent), False)
        need(parent is None or _stat(root / path[1:]) is None, 'PACKAGE_POLICY')
    # deb-systemd-helper unmask treats these records as its authority to unlink
    # even a /dev/null link just created by this operation.
    marked = _dir(root, '/var/lib/systemd/deb-systemd-helper-masked', False)
    need(marked is None or all(_stat(marked / unit) is None for unit in UNITS), 'PACKAGE_POLICY')
    for path in ('/usr/sbin', SYSTEM):
        need(not any(file.name.startswith('.relay-package-') for file in _dir(root, path).iterdir()), 'PACKAGE_POLICY')
    _overrides(root)


def _overrides(root):
    for filename in ('diversions', 'statoverride'):
        path = root / 'var/lib/dpkg' / filename
        if _stat(path) is not None:
            for line in _text(_regular(path), 'PACKAGE_OVERRIDE').split('\n'):
                leaf = Path(line.rsplit(' ', 1)[-1]).name
                need(leaf not in set(UNITS) | set(SYSV) | DAEMONS | {
                    'policy-rc.d', 'invoke-rc.d', 'deb-systemd-helper', 'deb-systemd-invoke', 'systemctl',
                    'dpkg-query', 'apt-cache', 'apt-get', 'systemd-sysv-generator', 'start-stop-daemon',
                    'update-alternatives', 'service', 'init-system-helpers', 'ppp', 'ipsec.conf',
                } and not leaf.startswith('policy-rc.d.'), 'PACKAGE_OVERRIDE')
    for parent, filename in (('/etc/dpkg', 'dpkg.cfg'), ('/etc/dpkg/dpkg.cfg.d', None)):
        folder = _dir(root, parent, False)
        if folder is None:
            continue
        paths = [folder / filename] if filename else sorted(folder.iterdir())
        for file in paths:
            if _stat(file) is not None:
                for line in _text(_regular(file, 16384), 'PACKAGE_OVERRIDE').split('\n'):
                    line = line.strip()
                    need(not line or line.startswith('#') or line in {'no-debsig', 'log /var/log/dpkg.log'},
                         'PACKAGE_OVERRIDE')


def _packages(root, run):
    need(not any(_dir(root, '/var/lib/dpkg/updates').iterdir()), 'PACKAGE_DATABASE')
    triggers = _dir(root, '/var/lib/dpkg/triggers', False)
    if triggers is not None and _stat(triggers / 'Unincorp') is not None:
        need(not _regular(triggers / 'Unincorp'), 'PACKAGE_DATABASE')
    for name in ('lock', 'lock-frontend'):
        _idle_lock(root / 'var/lib/dpkg' / name, 'PACKAGE_DATABASE')
    status = root / 'var/lib/dpkg/status'
    initial = _snapshot(status.lstat())
    digest = hashlib.sha256(_regular(status)).hexdigest()
    need(_out(run, (DPKG, '--print-architecture'), 'PACKAGE_DATABASE') == ARCH + '\n'
         and not _out(run, (DPKG, '--print-foreign-architectures'), 'PACKAGE_DATABASE')
         and not _out(run, (DPKG, '--audit'), 'PACKAGE_DATABASE'), 'PACKAGE_DATABASE')
    rows = _out(run, (QUERY, '-W', FORMAT), 'PACKAGE_DATABASE')
    result = {}
    seen = set()
    for line in rows.rstrip('\n').split('\n'):
        match = re.fullmatch(fr'({NAME})(?::({ARCH}))?\t(ii |rc )\t({ARCH}|all)\t({VERSION})', line)
        if match is None:
            raise Refusal('PACKAGE_DATABASE')
        name, qualifier, state, arch, version = match.groups()
        need(qualifier is None or qualifier == arch, 'PACKAGE_DATABASE')
        need(name not in seen and (name in REQUESTED or not _foreign(name)), 'PACKAGE_FOREIGN')
        seen.add(name)
        if state == 'ii ':
            result[name] = [version, arch]
        else:
            need(name not in REQUESTED and name != LIBCHARON, 'PACKAGE_DATABASE')
    need({'dpkg', 'apt', 'systemd', 'base-files', 'init-system-helpers'} <= result.keys(), 'PACKAGE_DATABASE')
    need(LIBCHARON not in result or _charon_pair(result), 'PACKAGE_FOREIGN')
    need(initial == _snapshot(status.lstat()), 'PACKAGE_DATABASE')
    return result, digest, initial


def _foreign(name):
    return name != LIBCHARON and (name in FOREIGN or name.startswith(
        ('strongswan-', 'charon-', 'libreswan-', 'openswan-', 'xl2tpd-')))


def _charon_pair(packages):
    return packages[LIBCHARON][1] == ARCH and packages.get('strongswan-charon') == packages[LIBCHARON]


def _quiet(run):
    ps = _out(run, ('/usr/bin/ps', '-e', '-o', 'pid=,comm='), 'PACKAGE_PROCESSES')
    pids = set()
    for line in ps.rstrip('\n').split('\n'):
        match = re.fullmatch(r'\s*([1-9][0-9]*) +([^\t]+)', line)
        if match is None or match[1] in pids or match[2].lower() in DAEMONS:
            raise Refusal('PACKAGE_PROCESSES')
        pids.add(match[1])
        if match[1] == '1':
            need(match[2] == 'systemd', 'PACKAGE_PROCESSES')
    need('1' in pids, 'PACKAGE_PROCESSES')
    need(not _out(run, CTL + ('list-jobs', '--no-legend', '--plain'), 'PACKAGE_JOBS'), 'PACKAGE_JOBS')
    need(not _out(run, ('/usr/bin/ss', '-H', '-aun', '( sport = :500 or sport = :4500 or sport = :1701 )'),
                  'PACKAGE_LISTENERS'), 'PACKAGE_LISTENERS')


def _properties(run, args, keys, statuses=(0,)):
    rc, out = _command(run, CTL + ('show', '--all', '--property=' + ','.join(keys), *args),
                       'PACKAGE_UNIT_STATE', statuses)
    data = {}
    for line in _text(out, 'PACKAGE_UNIT_STATE').rstrip('\n').split('\n'):
        k, sep, v = line.partition('=')
        need(sep and k in keys and k not in data, 'PACKAGE_UNIT_STATE')
        data[k] = v
    need(data.keys() == set(keys), 'PACKAGE_UNIT_STATE')
    return rc, data


def _shipped(root, run, path, package, installed):
    need(package in installed, 'PACKAGE_UNIT_OWNER')
    arch = installed[package][1]
    names = [package] + ([package + ':' + arch] if arch != 'all' else [])
    data = _regular(root / path[1:], 256 * 1024)
    if path.startswith('/etc/init.d/'):
        text = _out(run, (QUERY, '-W', '-f=${Conffiles}\\n', package), 'PACKAGE_UNIT_OWNER')
    else:
        text = ''
        for name in names:
            manifest = root / f'var/lib/dpkg/info/{name}.md5sums'
            if _stat(manifest) is not None:
                need(not text, 'PACKAGE_UNIT_OWNER')
                text = _text(_regular(manifest), 'PACKAGE_UNIT_OWNER')
    # Only compare the public init/fragment file; never read package conffiles such as secrets.
    variants = {path.lstrip('/'), path.removeprefix('/usr/'), path, path.removeprefix('/usr')}
    matches = set()
    want = hashlib.md5(data, usedforsecurity=False).hexdigest()
    for line in text.split('\n'):
        fields = line.split()
        if len(fields) == 2 and fields[0] in variants:
            matches.add(fields[1])
        if len(fields) == 2 and fields[1] in variants:
            matches.add(fields[0])
    need(matches == {want}, 'PACKAGE_UNIT_OWNER')
    if path.startswith('/etc/init.d/'):
        need((root / path[1:]).lstat().st_mode & 0o111, 'PACKAGE_UNIT_OWNER')
    return hashlib.sha256(data).hexdigest()


def _listed_alias(root, installed, path):
    # dpkg md5sums cover the regular primary, not a shipped symlink. Bind
    # the alias pathname separately to the same installed package's file list.
    pkg = NATIVE[IKE_PRIMARY]
    arch = installed[pkg][1]
    files = [root / f'var/lib/dpkg/info/{name}.list' for name in (pkg, f'{pkg}:{arch}')]
    lists = [file for file in files if _stat(file) is not None]
    need(len(lists) == 1, 'PACKAGE_UNIT_OWNER')
    rows = _text(_regular(lists[0]), 'PACKAGE_UNIT_OWNER').split('\n')
    need(sum(row in (path, path.removeprefix('/usr')) for row in rows) == 1, 'PACKAGE_UNIT_OWNER')


def _tracked(leaf):
    return (leaf in UNITS or leaf == 'service.d'
            or any(leaf.startswith((unit + '.', unit[:-8] + '@'))
                   or leaf in {unit[:-8] + '.' + k for k in ('timer', 'socket', 'path')}
                   for unit in UNITS)
            or leaf in {'strongswan-.service.d', 'charon-.service.d', 'celerity-.service.d',
                        'celerity-rebuild-.service.d', 'celerity-rebuild-l2tp-.service.d'})


def _layout(root, run, installed, owned=None, new=()):
    """Inventory fragments plus attributable postinst start links, without removing any."""
    _, p = _properties(run, (), ('UnitPath',))
    paths = p['UnitPath'].split()
    need(len(paths) == len(set(paths)) and {SYSTEM, VENDOR} <= set(paths)
         and set(paths) <= set(UNIT_DIRS) | {'/lib/systemd/system'}, 'PACKAGE_UNIT_PATH')
    evidence, scripts, vendor, generated, starts, aliases = {}, {}, {}, {}, [], {}
    # Check the native fragments first so native postinst links can be joined
    # to a verified [Install] WantedBy=, not a guessed default target.
    wanted = {}
    for unit, pkg in NATIVE.items():
        rel = f'{VENDOR}/{unit}'
        if _stat(root / rel[1:]) is not None:
            vendor[unit] = _shipped(root, run, rel, pkg, installed)
            text = _text(_regular(root / rel[1:], 256 * 1024), 'PACKAGE_UNIT_OWNER')
            need(hashlib.sha256(text.encode()).hexdigest() == vendor[unit], 'PACKAGE_UNIT_OWNER')
            section = ''
            for line in text.split('\n'):
                if line.startswith('['):
                    section = line
                elif section == '[Install]' and line.startswith('WantedBy='):
                    targets = line.partition('=')[2].split()
                    need(all(re.fullmatch(r'[a-zA-Z0-9_.-]+\.target', t) for t in targets), 'PACKAGE_UNIT_OWNER')
                    wanted.setdefault(unit, set()).update(t + '.wants' for t in targets)
    init = _dir(root, '/etc/init.d')
    for entry in init.iterdir():
        name = entry.name
        if name in SYSV:
            scripts[name] = _shipped(root, run, '/etc/init.d/' + name, SYSV[name], installed)
        else:
            target = Path(os.readlink(entry)).name if entry.is_symlink() else ''
            need(name not in DAEMONS and target not in DAEMONS, 'PACKAGE_UNIT_OWNER')
    for base in RCD:
        folder = _dir(root, base)
        for entry in folder.iterdir():
            name = entry.name[3:]
            target = Path(os.readlink(entry)).name if entry.is_symlink() else ''
            if name not in DAEMONS and target not in DAEMONS:
                continue
            need(re.fullmatch(r'[SK][0-9]{2}', entry.name[:3]) and name in scripts and
                 _owner(entry.lstat()) and os.readlink(entry) == '../init.d/' + name, 'PACKAGE_SYSV')
            if entry.name.startswith('S'):
                need(name in scripts and SYSV[name] in new, 'PACKAGE_SYSV_ENABLED')
                need(base[-3] in 'S2345' and _stat(entry.with_name('K' + entry.name[1:])) is None,
                     'PACKAGE_SYSV')
                starts.append(str(entry.relative_to(root)))
            evidence[str(entry.relative_to(root))] = _snapshot(entry.lstat())
    for base in UNIT_DIRS:
        folder = _dir(root, base, False)
        if folder is None:
            continue
        for entry in folder.iterdir():
            name = entry.name
            rel = f'{base}/{name}'
            info = entry.lstat()
            target = os.readlink(entry) if stat.S_ISLNK(info.st_mode) else ''
            if owned is not None and rel in owned:
                owned[rel].check(root)
            elif base == VENDOR and name in vendor:
                pass  # Verified before traversing local boot links.
            elif base == VENDOR and name == IKE_ALIAS:
                need(IKE_PRIMARY in vendor and _owner(info) and info.st_nlink == 1 and target in (
                    IKE_PRIMARY, f'{VENDOR}/{IKE_PRIMARY}', f'/lib/systemd/system/{IKE_PRIMARY}'),
                    'PACKAGE_UNIT_OWNER')
                _listed_alias(root, installed, rel)
                aliases[name] = IKE_PRIMARY
            elif base == LATE and name == 'l2tpd.service' and 'xl2tpd' in scripts:
                need(base in paths and _owner(info) and target == 'xl2tpd.service', 'PACKAGE_UNIT_OWNER')
                aliases[name] = 'xl2tpd.service'
            elif base == LATE and name in {'xl2tpd.service', 'ipsec.service', 'strongswan-starter.service',
                                          'nftables.service'} and name[:-8] in scripts:
                # Exact source, no additional commands: native SysV wrapper generated by PID 1.
                data = _regular(entry, 16384)
                src = '/etc/init.d/' + name[:-8]
                text = _text(data, 'PACKAGE_UNIT_OWNER')
                execs = [line for line in text.split('\n') if line.startswith('Exec')]
                need(base in paths and text.startswith('# Automatically generated by systemd-sysv-generator\n')
                     and [line for line in text.split('\n') if line.startswith('SourcePath=')] == ['SourcePath=' + src]
                     and execs == [f'ExecStart={src} start', f'ExecStop={src} stop'], 'PACKAGE_UNIT_OWNER')
                if name == 'xl2tpd.service':
                    digest = hashlib.sha256(data).hexdigest()
                    need(digest in XL_GENERATED and (not XL_GENERATED[digest] or 'xl2tpd' in new),
                         'PACKAGE_UNIT_OWNER')
                generated[name] = src
            elif name.endswith(('.wants', '.requires', '.upholds')) and not _tracked(name):
                for link in _dir(root, rel).iterdir():
                    dest = os.readlink(link) if link.is_symlink() else ''
                    if not _tracked(link.name) and not _tracked(Path(dest).name):
                        continue
                    # Only stock enablement created by this install, never disable a previous owner.
                    allowed = (base == SYSTEM and name in wanted.get(link.name, ()) and
                               NATIVE.get(link.name) in new and
                               dest in (VENDOR + '/' + link.name, '/lib/systemd/system/' + link.name))
                    gen = (base == LATE and name in ('multi-user.target.wants', 'graphical.target.wants') and
                           SYSV.get(link.name.removesuffix('.service')) in new and dest == '../' + link.name)
                    need((allowed or gen) and dest and _owner(link.lstat()), 'PACKAGE_UNIT_ENABLED')
                    if allowed:
                        starts.append(str(link.relative_to(root)))
                    evidence[str(link.relative_to(root))] = _snapshot(link.lstat())
            else:
                need(not _tracked(name) and not (name.endswith('.service') and _tracked(Path(target).name)),
                     'PACKAGE_UNIT_OWNER')
            if _tracked(name):
                evidence[rel] = _snapshot(info)
    if owned is not None:
        for art in owned.values():
            art.check(root)
    need(not (vendor.keys() & generated.keys()) and not (aliases.keys() & generated.keys())
         and ('l2tpd.service' not in aliases or 'xl2tpd.service' in generated)
         and vendor_or_names(installed) == vendor.keys() and ('xl2tpd' not in installed or 'xl2tpd' in scripts),
         'PACKAGE_UNIT_OWNER')
    return evidence, scripts, vendor, generated, aliases, sorted(starts), paths


def vendor_or_names(installed):
    return {name for name, package in NATIVE.items() if package in installed}


def _units(run, layout, masked=False):
    _, _, vendor, gen, aliases, _, _ = layout
    evidence = {}
    for unit in UNITS:
        rc, p = _properties(run, (unit,), PROPS, (0, 1))
        need(all(p[k] == v for k, v in {'ActiveState': 'inactive', 'SubState': 'dead', 'MainPID': '0',
                 'ControlPID': '0', 'Job': '', 'NeedDaemonReload': 'no', 'Transient': 'no', 'DropInPaths': '',
                 'TriggeredBy': ''}.items()), 'PACKAGE_UNIT_ACTIVE')
        name = aliases.get(unit, unit) if not masked else unit
        names = {name} | {n for n, primary in aliases.items() if primary == name and not masked}
        shown_names = p['Names'].split()
        need(p['Id'] == name and set(shown_names) == names and len(shown_names) == len(names), 'PACKAGE_UNIT_OWNER')
        if masked:
            need(rc == 0 and p['LoadState'] == 'masked' and p['UnitFileState'] == 'masked'
                 and p['FragmentPath'] in (SYSTEM + '/' + unit, '/dev/null')
                 and not p['SourcePath'], 'PACKAGE_MASK_STATE')
        elif name in vendor:
            need(rc == 0 and p['LoadState'] == 'loaded' and p['UnitFileState'] == 'disabled'
                 and p['FragmentPath'] in (VENDOR + '/' + name, '/lib/systemd/system/' + name)
                 and not p['SourcePath'], 'PACKAGE_UNIT_ENABLED')
        elif name in gen:
            need(rc == 0 and p['LoadState'] == 'loaded' and p['UnitFileState'] == 'generated'
                 and p['FragmentPath'] == f'{LATE}/{name}' and p['SourcePath'] == gen[name], 'PACKAGE_UNIT_ENABLED')
        else:
            need(p['LoadState'] == 'not-found' and p['UnitFileState'] in ('', 'not-found')
                 and not p['FragmentPath'] and not p['SourcePath'], 'PACKAGE_UNIT_OWNER')
        evidence[unit] = p
    return evidence


def _stanzas(text, code):
    fields = {}
    previous = None
    for line in (text + '\n\n').split('\n'):
        if not line:
            if fields:
                yield fields
                fields = {}
            previous = None
        elif line[0] in ' \t':
            need(previous is not None, code)
            fields[previous] += ' ' + line.strip()
        else:
            key, sep, value = line.partition(':')
            key = key.lower()
            need(sep and re.fullmatch(r'[a-z0-9][a-z0-9-]*', key) and key not in fields, code)
            fields[key] = value.strip()
            previous = key


def _sources(root):
    etc = _dir(root, '/etc/apt')
    parts = _dir(root, '/etc/apt/sources.list.d', False)
    _dir(root, str(Path(KEYRING).parent))
    keyring = (root / KEYRING[1:]).lstat()
    need(stat.S_ISREG(keyring.st_mode) and _trusted(keyring), 'PACKAGE_SOURCES')
    files = [etc / 'sources.list'] if _stat(etc / 'sources.list') else []
    if parts is not None:
        files += sorted(p for p in parts.iterdir() if p.suffix in ('.list', '.sources'))
    sources = set()

    def add(uri, suite, components, binary):
        need(re.fullmatch(r'https?://(?:deb\.debian\.org/(?:debian|debian-security)|security\.debian\.org/debian-security)/?', uri)
             and suite in {'trixie', 'trixie-updates', 'trixie-security'}
             and (suite == 'trixie-security') == ('debian-security' in uri)
             and 'main' in components and set(components) <= {'main', 'contrib', 'non-free', 'non-free-firmware'},
             'PACKAGE_SOURCES')
        # Keep main only, no source-supplied trust/targets/options.
        if binary:
            sources.add((uri.rstrip('/'), suite))

    for file in files:
        data = _text(_regular(file, 64 * 1024), 'PACKAGE_SOURCES')
        if file.suffix == '.sources':
            # In DEB822 a comment is a whole line. An inline suffix is part of
            # the value (notably for Signed-By), and must not be discarded.
            lines = [line.rstrip() for line in data.split('\n') if not line.startswith('#')]
            for f in _stanzas('\n'.join(lines), 'PACKAGE_SOURCES'):
                need(f.keys() <= {'types', 'uris', 'suites', 'components', 'signed-by', 'architectures'}
                     and f.get('types', '').split() in (['deb'], ['deb', 'deb-src'])
                     and f.get('signed-by', KEYRING) == KEYRING
                     and f.get('architectures', ARCH) == ARCH, 'PACKAGE_SOURCES')
                uris, suites = f.get('uris', '').split(), f.get('suites', '').split()
                need(len(uris) == 1 and bool(suites), 'PACKAGE_SOURCES')
                for suite in suites:
                    add(uris[0], suite, f.get('components', '').split(), True)
        else:
            for raw in data.split('\n'):
                line = raw.split('#', 1)[0].strip()
                if line:
                    match = LEGACY_SOURCE.fullmatch(line)
                    if match is None:
                        raise Refusal('PACKAGE_SOURCES')
                    kind, uri, suite, components = match.groups()
                    add(uri, suite, components.split(), kind == 'deb')
    suites = {suite for _, suite in sources}
    need('trixie' in suites and len(suites) == len(sources), 'PACKAGE_SOURCES')
    lists = _dir(root, '/var/lib/apt/lists')
    archives = _dir(root, '/var/cache/apt/archives')
    _dir(root, '/usr/lib/apt/methods')
    # Do not let this path reuse pre-existing .debs or partial downloads.
    need(all(p.name in {'lock', 'partial'} for p in archives.iterdir()), 'PACKAGE_ARCHIVE_CACHE')
    for lock in (archives / 'lock', lists / 'lock'):
        _idle_lock(lock, 'PACKAGE_SOURCES')
    for dirname in ('/var/lib/apt/lists/partial', '/var/cache/apt/archives/partial'):
        # Stock APT sandboxes acquisition in _apt-owned partial dirs; their
        # parents, not their sandbox owner, are the trust boundary.
        info = _stat(root / dirname[1:])
        need(info is None or stat.S_ISDIR(info.st_mode) and info.st_gid == 0 and not info.st_mode & 0o077,
             'PACKAGE_DIRECTORY')
        if dirname.startswith('/var/cache/') and info is not None:
            need(not any((root / dirname[1:]).iterdir()), 'PACKAGE_ARCHIVE_CACHE')
    indexes = {}
    for file in sorted(lists.iterdir()):
        if file.name in ('partial', 'auxfiles', 'lock'):
            continue
        info = file.lstat()
        need(stat.S_ISREG(info.st_mode) and _trusted(info) and info.st_nlink == 1, 'PACKAGE_SOURCES')
        indexes[file.name] = _snapshot(info)
    need(bool(indexes), 'PACKAGE_SOURCES')
    return sorted(sources), indexes, _snapshot(keyring), _id(lists.lstat()), _id(archives.lstat())


@contextmanager
def _memfile(stack, name, data):
    """Sealed argument files without a disk write or an inherited child FD."""
    fd = os.memfd_create(name, os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
    stack.callback(os.close, fd)
    raw = data.encode('ascii')
    need(os.write(fd, raw) == len(raw), 'PACKAGE_APT_CONFIG')
    fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
    yield f'/proc/{os.getpid()}/fd/{fd}'


@contextmanager
def _apt(sources, pins=None):
    # APT_CONFIG is read before the default configuration snippets. Isolation
    # relies on APT honoring the empty paths before loading any snippets, and
    # on its source/preference readers opening the live, absolute proc-fd paths.
    with ExitStack() as stack:
        def mem(name, text):
            return stack.enter_context(_memfile(stack, name, text))
        source = mem('relay-debian-sources', ''.join(f'deb [signed-by={KEYRING}] {uri} {suite} main\n'
                                                   for uri, suite in sources))
        prefs = '/dev/null'
        if pins is not None:
            rules = ''.join(f'Package: {name}\nPin: version {version}\nPin-Priority: 990\n\n'
                            for name, (version, _) in sorted(pins.items()))
            prefs = mem('relay-package-versions', rules + 'Package: *\nPin: version *\nPin-Priority: -1\n')
        config = mem('relay-apt-config', f'''
Dir::Etc::Parts "";
Dir::Etc::Main "";
Dir::Etc::sourcelist "{source}";
Dir::Etc::sourceparts "";
Dir::Etc::preferences "{prefs}";
Dir::Etc::preferencesparts "";
Dir::Etc::netrc "/dev/null";
Dir::Etc::netrcparts "";
Dir::Etc::trusted "{KEYRING}";
Dir::Etc::trustedparts "";
Dir::Cache::pkgcache "";
Dir::Cache::srcpkgcache "";
APT::Architecture "{ARCH}";
APT::Install-Recommends "false";
APT::Install-Suggests "false";
APT::Get::AllowUnauthenticated "false";
Acquire::AllowInsecureRepositories "false";
Acquire::AllowWeakRepositories "false";
Acquire::AllowDowngradeToInsecureRepositories "false";
Acquire::Check-Valid-Until "true";
Acquire::Retries "0";
Acquire::http::Timeout "12";
Acquire::https::Timeout "12";
DPkg::Lock::Timeout "0";
Dpkg::Use-Pty "false";
''')
        yield ('/usr/bin/env', '-i', 'PATH=/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL=C',
               'DEBIAN_FRONTEND=noninteractive', 'UCF_FORCE_CONFFOLD=1', 'APT_CONFIG=' + config)


def _apt_args(missing):
    return ('--no-install-recommends', '--no-install-suggests', '--no-remove', '--no-upgrade', 'install', *missing)


def _simulation(apt, run, specs):
    raw = _out(run, apt + ('/usr/bin/apt-get', '-s') + _apt_args(specs), 'PACKAGE_APT_PLAN')
    installs, configs = {}, {}
    totals = []
    for line in raw.split('\n'):
        match = re.fullmatch(r'0 upgraded, ([0-9]+) newly installed, 0 to remove and [0-9]+ not upgraded\.', line)
        if match:
            totals.append(int(match[1]))
        elif line.startswith(('Inst ', 'Conf ')):
            m = re.fullmatch(fr'(Inst|Conf) ({NAME}) \(({VERSION}) ({RELEASE}(?:, {RELEASE})*) \[({ARCH}|all)\]\)', line)
            if m is None:
                raise Refusal('PACKAGE_APT_PLAN')
            action, name, version, release, arch = m.groups()
            target = installs if action == 'Inst' else configs
            need(name not in target and (action == 'Inst' or name in installs), 'PACKAGE_APT_PLAN')
            target[name] = (version, arch, release)
        else:
            need(not re.match(r'(?:Inst|Conf|Remv|Purg)\b|\d+ upgraded|WARNING', line), 'PACKAGE_APT_PLAN')
    need(len(installs) <= MAX_PLAN and totals == [len(installs)] and installs == configs, 'PACKAGE_APT_PLAN')
    return {name: [version, arch] for name, (version, arch, _) in installs.items()}


def _metadata(apt, run, plan, installed, missing):
    edges = {}
    records = {}
    for name, (version, arch) in plan.items():
        raw = _out(run, apt + ('/usr/bin/apt-cache', 'show', f'{name}={version}'), 'PACKAGE_DEPENDENCY')
        legal = set()
        for row in _stanzas(raw, 'PACKAGE_DEPENDENCY'):
            need(row.get('package') == name and row.get('version') == version and row.get('architecture') == arch
                 and re.fullmatch(r'pool/main/[a-zA-Z0-9+./~_\-]+\.deb', row.get('filename', ''))
                 and '..' not in row['filename'].split('/')
                 and re.fullmatch(r'[0-9a-f]{64}', row.get('sha256', '')),
                 'PACKAGE_DEPENDENCY')
            legal.add((row['sha256'], row['filename'], row.get('depends', ''), row.get('pre-depends', '')))
        need(len(legal) == 1, 'PACKAGE_DEPENDENCY')
        digest, filename, *clauses = legal.pop()
        records[name] = [digest, filename, *clauses]
        edges[name] = []
        for clause in filter(None, clauses):
            for group in clause.split(','):
                alternatives = set()
                for item in group.split('|'):
                    match = re.fullmatch(fr'\s*({NAME})(?::(?:any|native|{ARCH}))?\s*'
                                         fr'(?:\((?:<<|<=|=|>=|>>)\s+{VERSION}\))?\s*', item)
                    if match is None:
                        raise Refusal('PACKAGE_DEPENDENCY')
                    alternatives.add(match[1])
                edges[name].append(alternatives)
    # APT evaluates versions and OR alternatives. Independently require each
    # selected new package to be justified by a hard edge from the requested
    # closure (never accept arbitrary recommendations or virtual providers).
    reached = set(missing)
    pending = list(missing)
    while pending:
        for group in edges[pending.pop()]:
            selected = group & plan.keys()
            need(len(selected) <= 1 or selected <= set(missing), 'PACKAGE_DEPENDENCY')
            for dep in selected - reached:
                reached.add(dep)
                pending.append(dep)
    need(reached == plan.keys() and not plan.keys() & installed.keys()
         and not any(n not in REQUESTED and _foreign(n) for n in plan), 'PACKAGE_DEPENDENCY')
    if LIBCHARON in plan:
        need(_charon_pair(plan) and {LIBCHARON} in edges['strongswan-charon'], 'PACKAGE_DEPENDENCY')
    return records


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def _observe(root, run):
    _environment(root)
    _quiet(run)
    installed, digest, status = _packages(root, run)
    layout = _layout(root, run, installed)
    units = _units(run, layout)
    need('xl2tpd' not in installed or 'xl2tpd.service' in layout[3], 'PACKAGE_UNIT_OWNER')
    missing = [name for name in REQUESTED if name not in installed]
    sources, plan, records = None, {}, {}
    if missing:
        sources = _sources(root)
        with _apt(sources[0]) as apt:
            _command(run, apt + ('/usr/bin/apt-get', '-s', 'check'), 'PACKAGE_APT_CHECK')
            plan = _simulation(apt, run, missing)
            need(set(missing) <= plan.keys() and not plan.keys() & installed.keys(), 'PACKAGE_APT_PLAN')
            records = _metadata(apt, run, plan, installed, missing)
        need(_sources(root) == sources and _snapshot((root / 'var/lib/dpkg/status').lstat()) == status,
             'PACKAGE_PLAN_CHANGED')
    _quiet(run)
    proof = hashlib.sha256(_json([installed, status, digest, layout, units, sources, plan, records,
                                  _id(root.lstat()), _id((root / SYSTEM[1:]).lstat()),
                                  _id((root / 'usr/sbin').lstat())]).encode()).hexdigest()
    observation = dict(missing=missing, proof=proof)
    return observation, installed, plan, sources, layout


def observe(root: Path, run) -> dict:
    """Return an opaque, JSON-roundtrippable freshness proof or refuse."""
    try:
        return _observe(root, run)[0]
    except (OSError, ValueError, TypeError, RecursionError):
        raise Refusal('PACKAGE_OBSERVATION') from None


class _Artifact:
    """Hold directory and inode descriptors to prevent path redirection/reuse."""

    def __init__(self, root, rel, stack, create=None):
        self.rel = '/' + rel.lstrip('/')
        self.folder, self.leaf = self.rel.rsplit('/', 1)
        d = _dir(root, self.folder)
        self.parent = os.open(d, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        stack.callback(os.close, self.parent)
        self.dir_id = _id(os.fstat(self.parent))
        need(self.dir_id == _id(d.lstat()) and _trusted(os.fstat(self.parent)), 'PACKAGE_CONTAINMENT_RACE')
        self.body = create if isinstance(create, bytes) else None
        if create is None:
            self.fd = self._pin(stack, self.parent, self.leaf)
        else:
            with self._stage() as stage:
                try:
                    if self.body is not None:
                        fd = os.open('item', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                     0o700, dir_fd=stage)
                        try:
                            need(os.write(fd, self.body) == len(self.body), 'PACKAGE_CONTAINMENT')
                            os.fchmod(fd, 0o755)
                            os.fsync(fd)
                        finally:
                            os.close(fd)
                    else:
                        os.symlink(create, 'item', dir_fd=stage)
                    self.fd = self._pin(stack, stage, 'item')
                    _move(stage, 'item', self.parent, self.leaf)
                finally:
                    if _stat('item', stage) is not None:
                        os.unlink('item', dir_fd=stage)
        info = os.fstat(self.fd)
        self.identity = _id(info)
        self.state = _snapshot(info)
        if self.body is None:
            need(stat.S_ISLNK(info.st_mode) and _owner(info), 'PACKAGE_CONTAINMENT_RACE')
            self.target = os.readlink(self.leaf, dir_fd=self.parent)
            need(create is None or create == self.target, 'PACKAGE_CONTAINMENT_RACE')
        else:
            need(stat.S_ISREG(info.st_mode) and _trusted(info), 'PACKAGE_CONTAINMENT_RACE')
        self.check(root)
        if create is not None:
            os.fsync(self.parent)

    @staticmethod
    def _pin(stack, parent, leaf):
        fd = os.open(leaf, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        stack.callback(os.close, fd)
        return fd

    @contextmanager
    def _stage(self):
        name = '.relay-package-' + uuid.uuid4().hex
        os.mkdir(name, 0o700, dir_fd=self.parent)
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.parent)
        try:
            info = os.fstat(fd)
            need(_trusted(info) and stat.S_IMODE(info.st_mode) == 0o700
                 and _id(info) == _id(_stat(name, self.parent)), 'PACKAGE_CONTAINMENT_RACE')
            yield fd
        finally:
            try:
                if not os.listdir(fd):
                    need(_id(os.fstat(fd)) == _id(_stat(name, self.parent)), 'PACKAGE_CONTAINMENT_RACE')
                    os.rmdir(name, dir_fd=self.parent)
            finally:
                os.close(fd)

    def check(self, root):
        need(_id(_dir(root, self.folder).lstat()) == self.dir_id, 'PACKAGE_CONTAINMENT_RACE')
        info = _stat(self.leaf, self.parent)
        need(info is not None and _snapshot(info) == self.state, 'PACKAGE_CONTAINMENT_RACE')
        if self.body is None:
            need(os.readlink(self.leaf, dir_fd=self.parent) == self.target, 'PACKAGE_CONTAINMENT_RACE')
        else:
            fd = os.open(self.leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=self.parent)
            with os.fdopen(fd, 'rb') as f:
                need(_snapshot(os.fstat(f.fileno())) == self.state and f.read(len(self.body) + 1) == self.body,
                     'PACKAGE_CONTAINMENT_RACE')

    def disable_sysv(self, root):
        self.check(root)
        # Match Debian's Snn→Knn convention without update-rc.d's overwriting
        # rename, systemctl disable, or optional insserv/OpenRC side effects.
        disabled = 'K' + self.leaf[1:]
        _move(self.parent, self.leaf, self.parent, disabled)
        moved = _stat(disabled, self.parent)
        if (moved is None or _snapshot(moved)[:7] != self.state[:7] or moved.st_nlink != self.state[-1]
                or os.readlink(disabled, dir_fd=self.parent) != self.target):
            _move(self.parent, disabled, self.parent, self.leaf)
            raise Refusal('PACKAGE_CONTAINMENT_RACE')
        os.fsync(self.parent)
        need(_stat(self.leaf, self.parent) is None, 'PACKAGE_CONTAINMENT_RACE')

    def remove(self, root):
        self.check(root)
        # Linux has no compare-and-unlink. Move without replacement to a private
        # quarantine, then compare the MOVED inode before removing it. On collision
        # restore without clobbering; if restoration itself races, retain evidence.
        with self._stage() as d:
            _move(self.parent, self.leaf, d, 'item')
            moved = _stat('item', d)
            if (moved is None or _id(moved) != self.identity or _snapshot(moved)[:7] != self.state[:7]
                    or moved.st_nlink != self.state[-1]):
                _move(d, 'item', self.parent, self.leaf)
                raise Refusal('PACKAGE_CONTAINMENT_RACE')
            os.unlink('item', dir_fd=d)
        os.fsync(self.parent)
        need(_stat(self.leaf, self.parent) is None, 'PACKAGE_CONTAINMENT_RACE')


def _move(src, name, dst, leaf):
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.renameat2(src, os.fsencode(name), dst, os.fsencode(leaf), 1)  # RENAME_NOREPLACE
    if result != 0:
        raise OSError(ctypes.get_errno(), 'renameat2')


def _reload(run):
    need(not _command(run, CTL + ('daemon-reload',), 'PACKAGE_RELOAD', timeout=12)[1], 'PACKAGE_RELOAD')


def _remove_owned(root, arts):
    for art in arts:
        art.check(root)
    for art in reversed(arts):
        art.remove(root)


def _prepare(root, run, expected, enter):
    observed, installed, plan, sources, baseline = _observe(root, run)
    need(type(expected) is dict and _json(expected) == _json(observed), 'PACKAGE_PLAN_CHANGED')
    missing = observed['missing']
    if not missing:
        return None
    if sources is None:
        raise Refusal('PACKAGE_PLAN_CHANGED')
    permits = installed | plan
    # Pin every installed tuple as well as every permitted new tuple; everything
    # else is negatively pinned. Only the six originating requests are explicit,
    # so Debian retains automatic dependency markings.
    specs = [f'{name}={plan[name][0]}' for name in missing]
    with ExitStack() as stack:
        apt = stack.enter_context(_apt(sources[0], permits))
        need(_simulation(apt, run, specs) == plan and _observe(root, run)[0] == observed, 'PACKAGE_PLAN_CHANGED')
        enter()
        arts, masks = [], {}
        dispatched = False
        try:
            # Policy is installed first and removed last, including on a setup failure.
            marker = ('#!/bin/sh\n# c3 relay package containment ' + uuid.uuid4().hex + '\nexit 101\n').encode('ascii')
            policy = _Artifact(root, POLICY, stack, marker)
            arts.append(policy)
            for name in UNITS:
                rel = SYSTEM + '/' + name
                mask = _Artifact(root, rel, stack, '/dev/null')
                arts.append(mask)
                masks[rel] = mask
            _reload(run)
            layout = _layout(root, run, installed, masks)
            _units(run, layout, masked=True)
            need(layout[1:3] == baseline[1:3] and _packages(root, run)[0] == installed
                 and _sources(root) == sources, 'PACKAGE_PLAN_CHANGED')
            _quiet(run)
            policy.check(root)
            for mask in masks.values():
                mask.check(root)
            dispatched = True
            _command(run, apt + ('/usr/bin/apt-get', '-y') + _apt_args(specs), 'PACKAGE_APT_UNSETTLED',
                     timeout=APT_TIMEOUT, quiet=False)
            _quiet(run)
            now, _, _ = _packages(root, run)
            need(now == permits, 'PACKAGE_APT_READBACK')
            postinst = _layout(root, run, now, masks, plan.keys())
            _units(run, postinst, masked=True)
            need(all(postinst[1].get(n) == digest for n, digest in baseline[1].items()) and
                 all(postinst[2].get(n) == digest for n, digest in baseline[2].items()) and
                 all(postinst[0].get(n) == state for n, state in baseline[0].items()
                     if n.startswith('etc/rc') or n == f'{VENDOR}/{IKE_ALIAS}'), 'PACKAGE_UNIT_OWNER')
            for link in postinst[5]:
                art = _Artifact(root, link, stack)
                need(art.state == postinst[0][link], 'PACKAGE_CONTAINMENT_RACE')
                if link.startswith('etc/rc'):
                    art.disable_sysv(root)
                else:
                    art.remove(root)
            _reload(run)
            layout = _layout(root, run, now, masks)
            _units(run, layout, masked=True)
            alias_path = f'{VENDOR}/{IKE_ALIAS}'
            need(layout[1:3] == postinst[1:3] and layout[0].get(alias_path) == postinst[0].get(alias_path),
                 'PACKAGE_UNIT_OWNER')
            _quiet(run)
            policy.check(root)
            _remove_owned(root, list(masks.values()))
            _reload(run)
            unmasked = _layout(root, run, now)
            need(unmasked[1:3] == layout[1:3] and unmasked[0].get(alias_path) == layout[0].get(alias_path),
                 'PACKAGE_UNIT_OWNER')
            _units(run, unmasked)
            _quiet(run)
            need(_packages(root, run)[0] == permits and ('xl2tpd' not in now or 'xl2tpd.service' in unmasked[3]),
                 'PACKAGE_APT_READBACK')
            policy.remove(root)
        except BaseException as error:
            # APT may have left an unpacked or half-configured package, or a
            # maintainer child that outlived its parent. Never infer settlement
            # from a timeout, a nonzero exit, or disappearance from ps alone.
            if not dispatched:
                try:
                    _remove_owned(root, arts[1:])
                    if masks:
                        _reload(run)
                    _remove_owned(root, arts[:1])
                except Exception:
                    error.add_note('PACKAGE_CONTAINMENT_CLEANUP_UNCERTAIN')
            raise


def prepare(root: Path, run, expected, enter) -> None:
    """Re-observe, enter once just before effects, return only on verified quiet state."""
    try:
        return _prepare(root, run, expected, enter)
    except (OSError, ValueError, TypeError, RecursionError):
        raise Refusal('PACKAGE_PREPARE') from None
