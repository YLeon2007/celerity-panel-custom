"""Private-root filesystem regressions; no program is executed by the fake runner.

Includes a replay of historical Debian 13 solver action rows and the checked-in
xl2tpd-generated fragment. Other command replies (including apt-cache/package
metadata) are modeled, not an authenticated APT replay.
"""

import fcntl
import hashlib
import importlib.util
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('package_guard', HERE.parent / 'rebuildRelayPackageGuard.py')
assert spec is not None and spec.loader is not None
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)

SIX = ['strongswan', 'strongswan-starter', 'strongswan-charon', 'xl2tpd', 'ppp', 'nftables']
SYSTEM = '/etc/systemd/system'
VENDOR = '/usr/lib/systemd/system'
LATE = '/run/systemd/generator.late'
POLICY = '/usr/sbin/policy-rc.d'
PROPS = ('Id,Names,LoadState,FragmentPath,SourcePath,UnitFileState,ActiveState,SubState,'
         'MainPID,ControlPID,Job,NeedDaemonReload,Transient,DropInPaths,TriggeredBy')
CTL = ('/usr/bin/systemctl', '--system', '--no-pager', '--no-ask-password', '--full')

# Public action rows from the sanitized Debian 13 historical solver probe
# (historical-solver-uid0.log). The apt-cache metadata seam below is modeled.
STOCK_INST = b'''Inst libstrongswan (6.0.1-6+deb13u7 Debian-Security:13/stable-security [amd64])
Inst strongswan-starter (6.0.1-6+deb13u7 Debian-Security:13/stable-security [amd64])
Inst strongswan-libcharon (6.0.1-6+deb13u7 Debian-Security:13/stable-security [amd64])
Inst strongswan-charon (6.0.1-6+deb13u7 Debian-Security:13/stable-security [amd64])
Inst libjansson4 (2.14-2+b3 Debian:13.7/stable [amd64])
Inst libnftnl11 (1.2.9-1 Debian:13.7/stable [amd64])
Inst libnftables1 (1.1.3-1 Debian:13.7/stable [amd64])
Inst nftables (1.1.3-1 Debian:13.7/stable [amd64])
Inst libpcap0.8t64 (1.10.5-2 Debian:13.7/stable [amd64])
Inst ppp (2.5.2-1+1 Debian:13.7/stable [amd64])
Inst strongswan (6.0.1-6+deb13u7 Debian-Security:13/stable-security [all])
Inst xl2tpd (1.3.18-1+b1 Debian:13.7/stable [amd64])
'''
STOCK_PLAN = (b'0 upgraded, 12 newly installed, 0 to remove and 0 not upgraded.\n'
              + STOCK_INST + STOCK_INST.replace(b'Inst ', b'Conf '))


class Host:
    def __init__(self, test, root, *, seed=True):
        self.t, self.root = test, root
        self.calls, self.effects = [], []
        self.apt_count = 0
        self.apt_mode = 'ok'
        self.update_mode = 'ok'
        self.after_update = lambda: None
        self.error_stage: str | None = None
        self.active = self.enabled = self.listener = self.job = self.process = self.bad_audit = False
        self.broken = False
        self.installed = {n: ('1.0-1', 'amd64') for n in ('apt', 'dpkg', 'systemd', 'base-files',
                                                        'init-system-helpers', 'libc6', 'libnftnl11')}
        self.candidates = {
            'libstrongswan': ('6.0.1-6+deb13u7', 'amd64', 'libc6 (>= 2.38)'),
            'strongswan-charon': ('6.0.1-6+deb13u7', 'amd64', 'libstrongswan (= 6.0.1-6+deb13u7)'),
            'strongswan-starter': ('6.0.1-6+deb13u7', 'amd64', 'strongswan-charon'),
            'strongswan': ('6.0.1-6+deb13u7', 'all', 'strongswan-starter, strongswan-charon'),
            'ppp': ('2.5.2-1', 'amd64', 'libc6'),
            'xl2tpd': ('1.3.18-1+b1', 'amd64', 'ppp, libc6'),
            'nftables': ('1.1.3-1', 'amd64', 'libnftnl11'),
        }
        self.replacement = None
        self.pin_plan_drift = False
        self.sim_extra = ''
        self.sim_stdout: bytes | None = None
        if not seed:
            return
        for path in ('/usr/bin', '/usr/sbin', '/usr/lib/apt/methods', VENDOR, SYSTEM, LATE,
                     '/usr/share/keyrings', '/etc/init.d', '/etc/dpkg/dpkg.cfg.d',
                     '/var/lib/dpkg/info', '/var/lib/dpkg/updates', '/var/cache/apt/archives',
                     '/etc/apt/sources.list.d', '/var/lib/apt/lists', *(f'/etc/rc{i}.d' for i in 'S0123456')):
            self.p(path).mkdir(parents=True, exist_ok=True)

        self.link('/lib', 'usr/lib')
        self.link('/etc/os-release', '../usr/lib/os-release')
        self.put('/usr/lib/os-release', 'PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\n'
                 'VERSION_ID="13"\nVERSION_CODENAME=trixie\nID=debian\n')
        self.put('/usr/share/keyrings/debian-archive-keyring.gpg', 'synthetic keyring marker')
        self.put('/var/lib/apt/lists/deb.debian.org_debian_dists_trixie_InRelease', 'fixture label')
        self.put('/etc/apt/sources.list.d/debian.sources', '''Types: deb
URIs: http://deb.debian.org/debian
Suites: trixie trixie-updates
Components: main non-free-firmware
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg

Types: deb
URIs: http://deb.debian.org/debian-security
Suites: trixie-security
Components: main non-free-firmware
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
''')
        self.put('/etc/dpkg/dpkg.cfg', '# comments\nno-debsig\nlog /var/log/dpkg.log\n')
        self.put('/var/lib/dpkg/lock-frontend', '', 0o640)
        self.put('/var/lib/apt/lists/lock', '', 0o640)
        self.status()

    def p(self, path):
        return self.root / path.lstrip('/')

    def put(self, path, text, mode=0o644):
        file = self.p(path)
        file.parent.mkdir(exist_ok=True, parents=True)
        file.write_text(text)
        file.chmod(mode)
        return file

    def link(self, path, target):
        file = self.p(path)
        file.parent.mkdir(exist_ok=True, parents=True, mode=0o755)
        file.symlink_to(target)
        return file

    def status(self):
        self.put('/var/lib/dpkg/status', ''.join(f'Package: {n}\nStatus: install ok installed\n'
                 f'Version: {v}\nArchitecture: {a}\n\n' for n, (v, a) in sorted(self.installed.items())))

    def stock_solver(self):
        deps = {
            'libstrongswan': 'libc6 (>= 2.38)',
            'strongswan-starter': 'libstrongswan (= 6.0.1-6+deb13u7), libc6 (>= 2.38)',
            'strongswan-libcharon': 'libstrongswan (= 6.0.1-6+deb13u7)',
            'strongswan-charon': 'strongswan-libcharon (= 6.0.1-6+deb13u7), libc6 (>= 2.38)',
            'libjansson4': 'libc6', 'libnftnl11': 'libc6', 'libnftables1': 'libjansson4, libnftnl11',
            'nftables': 'libnftables1 (= 1.1.3-1)', 'libpcap0.8t64': 'libc6', 'ppp': 'libc6',
            'strongswan': 'strongswan-starter, strongswan-charon',
            'xl2tpd': 'libc6 (>= 2.34), libpcap0.8t64 (>= 0.9.8), ppp, lsb-base (>= 3.0-6)',
        }
        self.candidates = {name: (version, arch, deps[name]) for name, version, arch in re.findall(
            r'^Inst (\S+) \((\S+) \S+ \[(\S+)\]\)$', STOCK_INST.decode(), re.M)}
        del self.installed['libnftnl11']
        self.installed['lsb-base'] = ('11.6', 'all')
        self.status()
        self.sim_stdout = STOCK_PLAN

    def containment(self):
        self.t.assertEqual(0o755, self.p(POLICY).stat().st_mode & 0o777)
        self.t.assertRegex(self.p(POLICY).read_text(), r'^#!/bin/sh\n# c3 relay package containment [a-f0-9]{32}\nexit 101\n$')
        for unit in (g.UNITS + ('nftables.service', 'strongswan.service', 'strongswan-swanctl.service',
                                'ipsec.service', 'l2tpd.service')):
            self.t.assertEqual(os.readlink(self.p(SYSTEM + '/' + unit)), '/dev/null')

    def enter(self):
        self.t.assertEqual(self.effects, [])
        self.t.assertFalse(self.p(POLICY).exists())
        self.t.assertTrue(all(not self.p(f'{SYSTEM}/{unit}').is_symlink() for unit in g.UNITS))
        self.effects.append('enter')

    def _install(self):
        old = self.installed.copy()
        self.installed.update({n: (v, arch) for n, (v, arch, _) in self.candidates.items() if n not in old})
        self.status()
        # For both native services model helper-created enablement, even if a
        # particular Debian release uses --no-enable for nftables.
        for pkg, target in (('strongswan-starter', 'multi-user.target'), ('nftables', 'sysinit.target')):
            if pkg not in old and pkg in self.installed:
                unit = pkg + '.service'
                frag = self.put(f'{VENDOR}/{unit}', f'[Unit]\nDescription=fixture\n[Service]\n'
                                f'ExecStart={self.native_exec(pkg)}\n[Install]\nWantedBy={target}\n')
                self.put(f'/var/lib/dpkg/info/{pkg}.md5sums',
                         f'{hashlib.md5(frag.read_bytes()).hexdigest()}  {VENDOR[1:]}/{unit}\n')
                self.link(f'{SYSTEM}/{target}.wants/{unit}', VENDOR + '/' + unit)
        if 'xl2tpd' not in old and 'xl2tpd' in self.installed:
            self.put('/etc/init.d/xl2tpd', '#!/bin/sh\nexit 0\n', 0o755)
            for i in '2345':
                self.link(f'/etc/rc{i}.d/S01xl2tpd', '../init.d/xl2tpd')
            for i in '016':
                self.link(f'/etc/rc{i}.d/K01xl2tpd', '../init.d/xl2tpd')
        if self.error_stage == 'foreign-link':
            self.link(f'{SYSTEM}/multi-user.target.wants/foreign.service', VENDOR + '/strongswan-starter.service')
        if self.error_stage == 'changed-mask':
            dest = self.p(SYSTEM + '/strongswan.service')
            dest.unlink()
            dest.symlink_to('/dev/null')  # same link text, different pinned inode
            self.replacement = dest.lstat().st_ino
        if self.error_stage == 'changed-policy':
            policy = self.p(POLICY)
            body = policy.read_bytes()
            policy.rename(self.p('/usr/sbin/private-policy-preimage'))
            policy.write_bytes(body)
            policy.chmod(0o755)
            self.replacement = policy.stat().st_ino

    def native_exec(self, package) -> str:
        return '/usr/bin/true'

    def _show(self, unit):
        mask = self.p(f'{SYSTEM}/{unit}').is_symlink()
        p = dict(Id=unit, Names=unit, LoadState='not-found', FragmentPath='', SourcePath='', UnitFileState='',
                 ActiveState='inactive', SubState='dead', MainPID='0', ControlPID='0', Job='',
                 NeedDaemonReload='no', Transient='no', DropInPaths='', TriggeredBy='')
        if mask:
            p.update(LoadState='masked', FragmentPath=f'{SYSTEM}/{unit}', UnitFileState='masked')
        elif self.p(f'{VENDOR}/{unit}').is_file():
            enabled = self.enabled or any(self.p(SYSTEM).glob(f'*.wants/{unit}'))
            p.update(LoadState='loaded', FragmentPath=f'{VENDOR}/{unit}', UnitFileState='enabled' if enabled else 'disabled')
        elif unit in ('xl2tpd.service', 'l2tpd.service') and self.p(LATE + '/xl2tpd.service').is_file():
            p.update(Id='xl2tpd.service', Names='xl2tpd.service l2tpd.service', LoadState='loaded',
                     FragmentPath=LATE + '/xl2tpd.service', SourcePath='/etc/init.d/xl2tpd', UnitFileState='generated')
        if unit == 'strongswan-starter.service' and (self.active or self.apt_count and self.error_stage == 'active'):
            p.update(ActiveState='active', SubState='running', MainPID='735')
        if (self.apt_count and not mask and unit == 'strongswan-starter.service'
                and self.error_stage == 'unmasked-enabled'):
            p['UnitFileState'] = 'enabled'
        return (1 if p['LoadState'] == 'not-found' else 0), ''.join(f'{k}={v}\n' for k, v in p.items()).encode(), b''

    def _reload(self):
        # A native/masked name wins over the late generator. The no-start-link
        # xl2tpd fragment is the checked-in trixie SysV generator fixture.
        self.effects.append('reload')
        self.t.assertTrue(self.p(POLICY).exists())
        alias, source = self.p(LATE + '/l2tpd.service'), self.p(LATE + '/xl2tpd.service')
        if alias.is_symlink():
            alias.unlink()
        if source.is_file():
            source.unlink()
        if self.p('/etc/init.d/xl2tpd').is_file() and not self.p(SYSTEM + '/xl2tpd.service').is_symlink():
            self.t.assertFalse(any(self.p('/etc').glob('rc?.d/S??xl2tpd')))
            source.write_bytes((HERE / 'helpers/trixie-xl2tpd-generated.fixture').read_bytes())
            source.chmod(0o644)
            alias.symlink_to('xl2tpd.service')
        return 0, b'', b''

    def _apt(self, argv, timeout):
        self.t.assertEqual(argv[:6], ('/usr/bin/env', '-i', 'PATH=/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL=C',
                                     'DEBIAN_FRONTEND=noninteractive', 'UCF_FORCE_CONFFOLD=1'))
        self.t.assertTrue(argv[6].startswith('APT_CONFIG=/proc/'))
        config = Path(argv[6].split('=', 1)[1]).read_text()
        self.t.assertIn('APT::Get::AllowUnauthenticated "false";', config)
        self.t.assertIn('Acquire::AllowInsecureRepositories "false";', config)
        self.t.assertIn('Dir::Cache::pkgcache "";', config)
        self.t.assertIn('Dir::Etc::Parts "/dev/null";', config)
        source_match = re.search(r'Dir::Etc::sourcelist "([^"]+)";', config)
        assert source_match is not None
        src = Path(source_match[1]).read_text()
        self.t.assertRegex(src, r'deb \[signed-by=/usr/share/keyrings/debian-archive-keyring.gpg[^\n]*\] '
                           r'http://deb\.debian\.org/debian trixie main\n')
        program, *args = argv[7:]
        if program == '/usr/bin/apt-cache':
            self.t.assertEqual(len(args), 2)
            self.t.assertEqual(args[0], 'show')
            name, version = args[1].split('=')
            v, arch, dep = self.candidates[name]
            self.t.assertEqual(v, version)
            return 0, (f'Package: {name}\nArchitecture: {arch}\nVersion: {v}\nDepends: {dep}\n'
                       f'Filename: pool/main/{name[0]}/{name}/{name}_{v}_{arch}.deb\n'
                       f'SHA256: {hashlib.sha256(name.encode()).hexdigest()}\nDescription: fixture\n'
                       ' multiline comment\n\n').encode(), b''
        self.t.assertEqual(program, '/usr/bin/apt-get')
        if args == ['--error-on=any', 'update']:
            return self._update(config, src)
        if args == ['-s', 'check']:
            return (100, b'', b'Unmet dependencies') if self.broken else (0, b'Reading package lists...\n', b'')
        self.t.assertEqual(args[1:6], ['--no-install-recommends', '--no-install-suggests', '--no-remove',
                                        '--no-upgrade', 'install'])
        names = [n for n in SIX if n not in self.installed]
        plan = {n: (v, a) for n, (v, a, _) in self.candidates.items() if n not in self.installed}
        prefs_match = re.search(r'Dir::Etc::preferences "([^"]+)";', config)
        assert prefs_match is not None
        prefs = prefs_match[1]
        if prefs == '/dev/null':
            self.t.assertEqual(args[6:], names)
        else:
            self.t.assertEqual(args[6:], [f'{name}={plan[name][0]}' for name in names])
            pin = Path(prefs).read_text()
            self.t.assertTrue(pin.endswith('Package: *\nPin: version *\nPin-Priority: -1\n'))
            for name, (v, _) in (self.installed | plan).items():
                self.t.assertIn(f'Package: {name}\nPin: version {v}\nPin-Priority: 990\n', pin)
        if args[0] == '-s':
            if self.pin_plan_drift and prefs != '/dev/null':
                return 0, b'0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n', b''
            if self.sim_stdout is not None:
                return 0, self.sim_stdout, b''
            intro = ('Reading package lists...\nBuilding dependency tree...\nReading state information...\n'
                     'The following NEW packages will be installed:\n  ' + ' '.join(plan) + '\n'
                     f'0 upgraded, {len(plan)} newly installed, 0 to remove and 0 not upgraded.\n')
            lines = [f'{verb} {n} ({v} Debian:13.1/stable [{a}])\n'
                     for verb in ('Inst', 'Conf') for n, (v, a) in plan.items()]
            return 0, (intro + ''.join(lines) + self.sim_extra).encode(), b''
        self.t.assertEqual(args[0], '-y')
        self.t.assertEqual(timeout, 78)
        self.t.assertNotEqual(prefs, '/dev/null')
        self.t.assertEqual([effect for effect in self.effects if effect != 'update'][:2], ['enter', 'reload'])
        self.effects.append('apt')
        self.apt_count += 1
        self.containment()
        if self.apt_mode == 'timeout':
            raise subprocess.TimeoutExpired(argv, timeout)
        if self.apt_mode == 'nonzero':
            return 100, b'Unpacking...', b'Sub-process /usr/bin/dpkg returned an error code (1)'
        if self.apt_mode == 'signal':
            return -15, b'', b''
        self._install()
        return 0, b'Setting up xl2tpd ...\n', b'invoke-rc.d: policy-rc.d denied execution of start.\n'

    def _update(self, config, src):
        self.t.assertEqual(self.effects, ['enter'])
        self.effects.append('update')
        self.t.assertFalse(self.p(POLICY).exists())
        self.t.assertFalse(any(self.p(f'{SYSTEM}/{unit}').is_symlink() for unit in g.UNITS))
        for setting in ('Dir::Etc::Main "/dev/null";', 'Dir::Etc::sourceparts "/dev/null";',
                        'Acquire::http::AllowRedirect "false";', 'Acquire::https::AllowRedirect "false";',
                        '#clear APT::Update;', 'Dir::State::lists "/var/lib/apt/lists/";'):
            self.t.assertIn(setting, config)
        self.t.assertIn('inrelease-path=InRelease', src)
        if self.update_mode == 'timeout':
            raise subprocess.TimeoutExpired((), 1)
        self.p('/var/lib/apt/lists/auxfiles').mkdir(exist_ok=True)
        self.p('/var/lib/apt/lists/auxfiles').chmod(0o755)
        for uri, suite in re.findall(r'\] https?://([^ ]+) ([a-z-]+) main\n', src):
            base = '/var/lib/apt/lists/' + uri.replace('/', '_') + '_dists_' + suite
            payload = 'Package: fixture\nVersion: 1\nArchitecture: amd64\n\n'
            checksum = hashlib.sha256(payload.encode()).hexdigest()
            release = ('-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nOrigin: Debian\n'
                       f'Codename: {suite}\nSHA256:\n {checksum} {len(payload)} main/binary-amd64/Packages\n'
                       '-----BEGIN PGP SIGNATURE-----\nfixture\n-----END PGP SIGNATURE-----\n')
            self.put(base + ('_Release' if self.update_mode == 'unsigned' else '_InRelease'), release)
            if suite != 'trixie-security' or self.update_mode != 'partial':
                contents = {'empty': '', 'tampered': payload.replace('fixture', 'corrupt')}.get(self.update_mode, payload)
                self.put(base + '_main_binary-amd64_Packages', contents)
        self.after_update()
        if self.update_mode == 'bad-signature':
            return 100, b'', b'The following signatures were invalid'
        if self.update_mode == 'warning':
            return 0, b'', b'W: failed to fetch'
        if self.update_mode == 'staged':
            self.put('/var/lib/apt/lists/partial/incomplete', 'staged fixture')
            self.p('/var/lib/apt/lists/partial').chmod(0o700)
        return 0, b'Reading package lists...\n', b''

    def run(self, argv, timeout):
        self.t.assertIs(type(argv), tuple)
        self.t.assertIs(type(timeout), int)
        self.t.assertTrue(0 < timeout <= 78)
        self.calls.append(argv)
        if argv[0] == '/usr/bin/env':
            return self._apt(argv, timeout)
        if argv == ('/usr/bin/dpkg', '--print-architecture'):
            return 0, b'amd64\n', b''
        if argv == ('/usr/bin/dpkg', '--print-foreign-architectures'):
            return 0, b'', b''
        if argv == ('/usr/bin/dpkg', '--audit'):
            return 0, b'Packages have been unpacked but not configured.\n' if self.bad_audit else b'', b''
        if argv == ('/usr/bin/dpkg-query', '-W', '-f=${binary:Package}\\t${db:Status-Abbrev}\\t${Architecture}\\t${Version}\\n'):
            return 0, ''.join(f'{n}\tii \t{a}\t{v}\n' for n, (v, a) in sorted(self.installed.items())).encode(), b''
        if argv[:3] == ('/usr/bin/dpkg-query', '-W', '-f=${Conffiles}\\n') and len(argv) == 4:
            scripts = {'xl2tpd': ('xl2tpd',), 'strongswan-starter': ('ipsec', 'strongswan-starter'),
                       'nftables': ('nftables',)}[argv[3]]
            paths = [f'/etc/init.d/{name}' for name in scripts]
            return 0, ''.join(f' {p} {hashlib.md5(self.p(p).read_bytes()).hexdigest()}\n'
                              for p in paths).encode(), b''
        if argv[:5] == CTL:
            args = argv[5:]
            if args == ('show', '--all', '--property=UnitPath'):
                return 0, f'UnitPath=/etc/systemd/system /run/systemd/system {VENDOR} {LATE}\n'.encode(), b''
            if len(args) == 4 and args[:3] == ('show', '--all', '--property=' + PROPS):
                return self._show(args[3])
            if args == ('list-jobs', '--no-legend', '--plain'):
                return 0, b'112 strongswan-starter.service start waiting\n' if self.job else b'', b''
            if args == ('daemon-reload',):
                self.t.assertIn('enter', self.effects)
                return self._reload()
        if argv == ('/usr/bin/ps', '-e', '-o', 'pid=,comm='):
            return 0, b'      1 systemd\n    847 sshd\n' + (b'    878 charon\n' if self.process else b''), b''
        if argv == ('/usr/bin/ss', '-H', '-aun', '( sport = :500 or sport = :4500 or sport = :1701 )'):
            return 0, b'UNCONN 0 0 0.0.0.0:500 0.0.0.0:*\n' if self.listener else b'', b''
        raise AssertionError(f'Unexpected modeled argv {argv!r}')


class TestPackageGuard(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='.package-fixture-')
        self.addCleanup(tmp.cleanup)
        self.h = Host(self, Path(tmp.name))
        # Project only the owner predicate; all mode, inode, link, fsync and
        # rename operations are real and confined to the private tree.
        ownership = patch.object(g, '_owner', side_effect=lambda st: (st.st_uid, st.st_gid) == (os.getuid(), os.getgid()))
        ownership.start()
        self.addCleanup(ownership.stop)

    def observe(self):
        return json.loads(json.dumps(g.observe(self.h.root, self.h.run)))

    def prepare(self, proof):
        return g.prepare(self.h.root, self.h.run, proof, self.h.enter)

    def no_effects(self):
        self.assertEqual(self.h.effects, [])
        self.assertEqual(self.h.apt_count, 0)

    def no_apt(self):
        self.no_effects()
        self.assertFalse(any('/usr/bin/apt-get' in a or '/usr/bin/apt-cache' in a for a in self.h.calls))

    def empty_indexes(self):
        self.h.p('/var/lib/apt/lists/deb.debian.org_debian_dists_trixie_InRelease').unlink()

    def test_empty_lists_only_update_after_enter_then_use_normal_plan_and_readback(self):
        self.empty_indexes()
        source = self.h.p('/etc/apt/sources.list.d/debian.sources')
        before = source.read_bytes(), source.stat().st_mtime_ns
        proof = self.observe()
        self.assertEqual(proof['missing'], SIX)
        self.no_apt()
        self.assertEqual([p.name for p in self.h.p('/var/lib/apt/lists').iterdir()], ['lock'])
        self.assertIsNone(self.prepare(proof))
        self.assertEqual(self.h.effects, ['enter', 'update', 'reload', 'apt', 'reload', 'reload'])
        apt = [a[7:] for a in self.h.calls if a[0] == '/usr/bin/env']
        self.assertEqual(apt[0], ('/usr/bin/apt-get', '--error-on=any', 'update'))
        self.assertEqual(apt[1], ('/usr/bin/apt-get', '-s', 'check'))
        self.assertEqual(apt.count(apt[0]), 1)
        self.assertEqual((source.read_bytes(), source.stat().st_mtime_ns), before)
        self.assertFalse(self.h.p(POLICY).exists())
        self.assertEqual(self.observe()['missing'], [])

    def test_empty_lists_bootstrap_proof_binds_source_bytes_before_enter(self):
        self.empty_indexes()
        proof = self.observe()
        source = self.h.p('/etc/apt/sources.list.d/debian.sources')
        source.write_text(source.read_text() + '\n# another comment\n')
        with self.assertRaisesRegex(g.Refusal, 'PACKAGE_PLAN_CHANGED'):
            self.prepare(proof)
        self.no_apt()

    def test_empty_lists_bad_or_incomplete_update_never_plans(self):
        for mode in ('timeout', 'bad-signature', 'warning', 'unsigned', 'partial', 'empty', 'tampered', 'staged'):
            with self.subTest(mode=mode):
                self.h = Host(self, self.h.root / mode)
                self.empty_indexes()
                proof = self.observe()
                self.h.update_mode = mode
                reason = {'timeout': 'UPDATE', 'bad-signature': 'UPDATE_REJECTED',
                          'warning': 'UPDATE_REJECTED'}.get(mode, 'INDEXES')
                with self.assertRaisesRegex(g.Refusal, rf'^PACKAGE_APT_{reason}$'):
                    self.prepare(proof)
                self.assertEqual(self.h.effects, ['enter', 'update'])
                self.assertEqual([a[-1] for a in self.h.calls if a[0] == '/usr/bin/env'], ['update'])

    def test_empty_lists_with_staged_residue_refuse_without_enter(self):
        self.empty_indexes()
        self.h.put('/var/lib/apt/lists/partial/stale', 'stale fixture')
        self.h.p('/var/lib/apt/lists/partial').chmod(0o700)
        with self.assertRaisesRegex(g.Refusal, 'PACKAGE_APT_INDEXES'):
            self.observe()
        self.no_apt()

    def test_empty_lists_non_index_state_is_rechecked_before_solver(self):
        for change, code in (('sources', 'PLAN_CHANGED'), ('keyring', 'PLAN_CHANGED'),
                             ('active', 'UNIT_ACTIVE'), ('installed', 'PLAN_CHANGED')):
            with self.subTest(change=change):
                self.h = Host(self, self.h.root / change)
                self.empty_indexes()
                proof = self.observe()
                def drift():
                    if change == 'sources':
                        source = self.h.p('/etc/apt/sources.list.d/debian.sources')
                        source.write_text(source.read_text() + '\n# changed\n')
                    elif change == 'keyring':
                        self.h.put('/usr/share/keyrings/debian-archive-keyring.gpg', 'changed')
                    elif change == 'installed':
                        self.h.installed['libc6'] = ('2.0-1', 'amd64')
                        self.h.status()
                    else:
                        self.h.active = True
                self.h.after_update = drift
                with self.assertRaisesRegex(g.Refusal, 'PACKAGE_' + code):
                    self.prepare(proof)
                self.assertEqual(self.h.effects, ['enter', 'update'])
                self.assertEqual([a[-1] for a in self.h.calls if a[0] == '/usr/bin/env'], ['update'])

    def test_empty_lists_unauthorized_post_fetch_plan_never_installs(self):
        self.empty_indexes()
        proof = self.observe()
        self.h.after_update = lambda: setattr(self.h, 'sim_extra', 'Remv libc6 [1.0-1]\n')
        with self.assertRaisesRegex(g.Refusal, 'PACKAGE_APT_PLAN'):
            self.prepare(proof)
        self.assertEqual(self.h.effects, ['enter', 'update'])

    def test_stock_shaped_success_disables_sysv_and_native_only_after_apt(self):
        proof = self.observe()
        self.assertEqual(proof['missing'], SIX)
        self.no_effects()
        survivor = self.h.link(SYSTEM + '/multi-user.target.wants/operator.service', '/opt/operator.service')
        self.assertIsNone(self.prepare(proof))
        self.assertEqual(self.h.effects, ['enter', 'reload', 'apt', 'reload', 'reload'])
        self.assertEqual(survivor.readlink(), Path('/opt/operator.service'))
        self.assertFalse(self.h.p(POLICY).exists())
        self.assertFalse(any(self.h.p(SYSTEM).glob('*.wants/strongswan-starter.service')))
        self.assertFalse(any(self.h.p(SYSTEM).glob('*.wants/nftables.service')))
        self.assertFalse(any(self.h.p(SYSTEM).glob('*.service')))
        self.assertFalse(any(self.h.p('/etc').glob('rc?.d/S??xl2tpd')))
        for i in '0123456':
            self.assertEqual(self.h.p(f'/etc/rc{i}.d/K01xl2tpd').readlink(), Path('../init.d/xl2tpd'))
        self.assertFalse(any(self.h.root.rglob('.relay-package-*')))
        ready = self.observe()
        self.assertEqual(ready['missing'], [])
        self.assertIsNone(self.prepare(ready))
        self.assertEqual(self.h.apt_count, 1)

    def test_partial_stock_preserves_already_installed_disabled_owners(self):
        self.h._install()
        self.h.p(SYSTEM + '/multi-user.target.wants/strongswan-starter.service').unlink()
        self.h.p(SYSTEM + '/sysinit.target.wants/nftables.service').unlink()
        for leaf in self.h.p('/etc').glob('rc?.d/S??xl2tpd'):
            leaf.rename(leaf.with_name('K01xl2tpd'))
        self.h.put(POLICY, 'model setup only')
        self.h._reload()
        self.h.p(POLICY).unlink()
        self.h.effects.clear()
        del self.h.installed['ppp']
        self.h.status()
        inode = self.h.p(VENDOR + '/strongswan-starter.service').stat().st_ino
        stops = {leaf: (leaf.lstat().st_ino, leaf.readlink())
                 for leaf in self.h.p('/etc').glob('rc?.d/K??xl2tpd')}
        proof = self.observe()
        self.assertEqual(proof['missing'], ['ppp'])
        self.assertIsNone(self.prepare(proof))
        self.assertFalse(any(self.h.p('/etc').glob('rc?.d/S??xl2tpd')))
        self.assertEqual({leaf: (leaf.lstat().st_ino, leaf.readlink())
                          for leaf in self.h.p('/etc').glob('rc?.d/K??xl2tpd')}, stops)
        self.assertEqual(self.h.p(VENDOR + '/strongswan-starter.service').stat().st_ino, inode)

    def test_index_replacement_causes_plan_drift_without_enter(self):
        proof = self.observe()
        self.h.put('/var/lib/apt/lists/deb.debian.org_debian_dists_trixie_InRelease', 'replacement')
        with self.assertRaisesRegex(g.Refusal, 'PACKAGE_PLAN_CHANGED'):
            self.prepare(proof)
        self.no_effects()

    def test_pinned_simulation_must_match(self):
        proof = self.observe()
        self.h.pin_plan_drift = True
        with self.assertRaisesRegex(g.Refusal, 'PACKAGE_PLAN_CHANGED'):
            self.prepare(proof)
        self.no_effects()

    def test_preexisting_policy_is_not_even_read(self):
        policy = self.h.link(POLICY, '/nonexistent-operator-policy')
        with self.assertRaisesRegex(g.Refusal, 'PACKAGE_POLICY'):
            self.observe()
        self.no_apt()
        self.assertEqual(policy.readlink(), Path('/nonexistent-operator-policy'))

    def test_foreign_masks_aliases_and_overrides(self):
        for rel, target in (('/run/systemd/system/ipsec.service', '/dev/null'),
                            (SYSTEM + '/alias.service', VENDOR + '/xl2tpd.service'),
                            (SYSTEM + '/strongswan-starter.service.d', '/invalid')):
            with self.subTest(rel=rel):
                leaf = self.h.link(rel, target)
                with self.assertRaises(g.Refusal):
                    self.observe()
                self.no_apt()
                self.assertEqual(str(leaf.readlink()), target)
                leaf.unlink()

    def test_untrusted_directory_and_broken_dpkg_never_reach_apt(self):
        vendor = self.h.p(VENDOR)
        vendor.chmod(0o777)
        with self.assertRaisesRegex(g.Refusal, 'PACKAGE_DIRECTORY'):
            self.observe()
        vendor.chmod(0o755)
        self.h.bad_audit = True
        with self.assertRaisesRegex(g.Refusal, 'PACKAGE_DATABASE'):
            self.observe()
        self.no_apt()

    def test_package_manager_lock_is_observed_without_acquiring_it(self):
        # An OFD lock conflicts with POSIX F_GETLK even within this one process.
        with self.h.p('/var/lib/dpkg/lock-frontend').open('r+b') as lock:
            request = struct.pack('=hh4xqqi4x', fcntl.F_WRLCK, os.SEEK_SET, 0, 0, 0)
            fcntl.fcntl(lock.fileno(), fcntl.F_OFD_SETLK, request)
            with self.assertRaisesRegex(g.Refusal, 'PACKAGE_DATABASE'):
                self.observe()
            self.no_apt()
        self.assertEqual(self.observe()['missing'], SIX)

    def test_trust_override_and_cached_archive_refused_without_apt(self):
        cache = self.h.put('/var/cache/apt/archives/operator.deb', 'not a real archive')
        with self.assertRaisesRegex(g.Refusal, 'PACKAGE_ARCHIVE_CACHE'):
            self.observe()
        self.no_apt()
        cache.unlink()
        file = self.h.p('/etc/apt/sources.list.d/debian.sources')
        file.write_text(file.read_text() + 'Trusted: yes\n')
        with self.assertRaisesRegex(g.Refusal, '^PACKAGE_SOURCES_CONFIG$'):
            self.observe()
        self.no_apt()

    def test_preexisting_live_unit_jobs_listeners_and_processes(self):
        for attr, code in (('active', 'UNIT_ACTIVE'), ('job', 'JOBS'), ('listener', 'LISTENERS'),
                           ('process', 'PROCESSES')):
            with self.subTest(attr=attr):
                setattr(self.h, attr, True)
                with self.assertRaisesRegex(g.Refusal, 'PACKAGE_' + code):
                    self.observe()
                self.no_apt()
                setattr(self.h, attr, False)

    def test_preexisting_sysv_enabled_remains_untouched(self):
        self.h._install()
        link = self.h.p('/etc/rc2.d/S01xl2tpd')
        with self.assertRaisesRegex(g.Refusal, 'PACKAGE_SYSV_ENABLED'):
            self.observe()
        self.no_apt()
        self.assertTrue(link.is_symlink())

    def test_bad_apt_check_never_plans_or_enters(self):
        self.h.broken = True
        with self.assertRaisesRegex(g.Refusal, 'PACKAGE_APT_CHECK'):
            self.observe()
        self.no_effects()
        self.assertFalse(any('install' in a for a in self.h.calls))

    def test_trixie_legacy_sources_list_with_stock_signed_by(self):
        self.h.p('/etc/apt/sources.list.d/debian.sources').unlink()
        self.h.put('/etc/apt/sources.list', '''deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] http://deb.debian.org/debian trixie main non-free-firmware
deb http://deb.debian.org/debian trixie-updates main
deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] http://deb.debian.org/debian-security trixie-security main
''')
        self.assertEqual(self.observe()['missing'], SIX)
        self.no_effects()

    def test_signed_by_does_not_admit_other_keys_or_extra_options(self):
        listing = self.h.p('/etc/apt/sources.list.d/debian.sources')
        deb822 = listing.read_text()
        for suffix in (' ABCDEF0123456789ABCDEF0123456789ABCDEF01', ' #not-a-deb822-comment'):
            with self.subTest(suffix=suffix):
                self.h.calls.clear()
                listing.write_text(deb822.replace('.gpg\n', '.gpg' + suffix + '\n'))
                with self.assertRaisesRegex(g.Refusal, '^PACKAGE_SOURCES_CONFIG$'):
                    self.observe()
                self.no_apt()
        listing.unlink()
        for options in ('signed-by=/tmp/operator.gpg',
                        'signed-by=/usr/share/keyrings/debian-archive-keyring.gpg trusted=yes',
                        'signed-by=/usr/share/keyrings/debian-archive-keyring.gpg arch=amd64'):
            with self.subTest(options=options):
                self.h.calls.clear()
                self.h.put('/etc/apt/sources.list',
                           f'deb [{options}] http://deb.debian.org/debian trixie main\n')
                with self.assertRaisesRegex(g.Refusal, '^PACKAGE_SOURCES_CONFIG$'):
                    self.observe()
                self.no_apt()

    def test_legacy_source_only_entry_cannot_become_a_binary_source(self):
        self.h.p('/etc/apt/sources.list.d/debian.sources').unlink()
        self.h.put('/etc/apt/sources.list', 'deb-src http://deb.debian.org/debian trixie main\n')
        with self.assertRaisesRegex(g.Refusal, '^PACKAGE_SOURCES_CONFIG$'):
            self.observe()
        self.no_apt()

    def test_trixie_solver_stock_libcharon_is_a_hard_dependency(self):
        self.h.stock_solver()
        self.assertEqual(self.observe()['missing'], SIX)
        self.no_effects()

    def test_libcharon_without_stock_charon_dependency_still_refuses(self):
        self.h.stock_solver()
        # Still reachable through a requested package, but no longer paired to
        # its stock charon hard dependency; this must not authorize the library.
        self.h.candidates['strongswan-charon'] = ('6.0.1-6+deb13u7', 'amd64', 'libc6')
        self.h.candidates['strongswan'] = ('6.0.1-6+deb13u7', 'all',
                                          'strongswan-starter, strongswan-charon, strongswan-libcharon')
        with self.assertRaisesRegex(g.Refusal, 'PACKAGE_DEPENDENCY'):
            self.observe()
        self.no_effects()

    def test_installed_libcharon_needs_matching_stock_charon_and_no_other_ike(self):
        self.h.installed['strongswan-libcharon'] = ('6.0.1-6+deb13u7', 'amd64')
        for daemon, version in ((None, None), ('strongswan-charon', '6.0.1-6+deb13u6'),
                                ('charon-systemd', '6.0.1-6+deb13u7')):
            with self.subTest(daemon=daemon):
                if daemon is not None and version is not None:
                    self.h.installed[daemon] = (version, 'amd64')
                self.h.status()
                with self.assertRaisesRegex(g.Refusal, 'PACKAGE_FOREIGN'):
                    g._packages(self.h.root, self.h.run)
                if daemon is not None:
                    del self.h.installed[daemon]
        self.h.installed['strongswan-charon'] = ('6.0.1-6+deb13u7', 'amd64')
        self.h.status()
        packages, _, _ = g._packages(self.h.root, self.h.run)
        self.assertEqual(packages['strongswan-libcharon'], ['6.0.1-6+deb13u7', 'amd64'])
        self.no_apt()

    def test_trixie_simulation_rejects_foreign_release_even_with_debian_token(self):
        for release in (b'OtherDebian:13/stable', b'Debian:13.7/stable, External:1/stable',
                        b'Debian:12/oldstable'):
            with self.subTest(release=release):
                data = STOCK_PLAN.replace(b'Debian:13.7/stable', release)
                with self.assertRaisesRegex(g.Refusal, 'PACKAGE_APT_PLAN'):
                    g._simulation((), lambda *_: (0, data, b''), SIX)

    def test_dpkg_native_multiarch_query_and_stock_config(self):
        def read(arch, suffix):
            def run(argv, timeout):
                rc, out, err = self.h.run(argv, timeout)
                if argv[0] == '/usr/bin/dpkg-query':
                    out = out.replace(b'libc6\tii \tamd64\t', f'libc6:{suffix}\tii \t{arch}\t'.encode())
                return rc, out, err
            return g._packages(self.h.root, run)[0]

        self.assertEqual(read('amd64', 'amd64')['libc6'], ['1.0-1', 'amd64'])
        for arch, suffix in (('amd64', 'i386'), ('all', 'amd64'), ('i386', 'amd64')):
            with self.subTest(arch=arch, suffix=suffix), self.assertRaisesRegex(g.Refusal, 'PACKAGE_DATABASE'):
                read(arch, suffix)
        g._overrides(self.h.root)
        self.h.put('/etc/dpkg/dpkg.cfg.d/99unsafe', 'force-confnew\n')
        with self.assertRaisesRegex(g.Refusal, 'PACKAGE_OVERRIDE'):
            g._overrides(self.h.root)

    def test_upgrade_removal_or_unrelated_package_cannot_be_authorized(self):
        for action in ('Remv libc6 [1.0-1]\n', 'Inst libc6 [1.0-1] (2.0 Debian:13.1/stable [amd64])\n'):
            self.h.sim_extra = action
            with self.assertRaisesRegex(g.Refusal, 'PACKAGE_APT_PLAN'):
                self.observe()
        self.h.sim_extra = ''
        self.h.candidates['unrelated'] = ('1.0-1', 'amd64', 'libc6')
        with self.assertRaisesRegex(g.Refusal, 'PACKAGE_DEPENDENCY'):
            self.observe()
        self.no_effects()

    def test_nonzero_apt_keeps_containment(self):
        self.h.apt_mode = 'nonzero'
        with self.assertRaisesRegex(g.Refusal, 'PACKAGE_APT_UNSETTLED'):
            self.prepare(self.observe())
        self.h.containment()
        self.assertEqual(self.h.effects, ['enter', 'reload', 'apt'])

    def test_timeout_apt_keeps_containment(self):
        self.h.apt_mode = 'timeout'
        with self.assertRaisesRegex(g.Refusal, 'PACKAGE_APT_UNSETTLED'):
            self.prepare(self.observe())
        self.h.containment()

    def test_signalled_apt_keeps_containment(self):
        self.h.apt_mode = 'signal'
        with self.assertRaisesRegex(g.Refusal, 'PACKAGE_APT_UNSETTLED'):
            self.prepare(self.observe())
        self.h.containment()

    def test_postread_active_keeps_containment_without_stopping(self):
        self.h.error_stage = 'active'
        with self.assertRaisesRegex(g.Refusal, 'PACKAGE_UNIT_ACTIVE'):
            self.prepare(self.observe())
        self.h.containment()
        self.assertEqual(self.h.effects, ['enter', 'reload', 'apt'])

    def test_postread_enabled_never_returns_success(self):
        self.h.error_stage = 'unmasked-enabled'
        with self.assertRaisesRegex(g.Refusal, 'PACKAGE_UNIT_ENABLED'):
            self.prepare(self.observe())
        self.assertTrue(self.h.p(POLICY).is_file())

    def test_foreign_enablement_after_apt_is_not_removed(self):
        self.h.error_stage = 'foreign-link'
        with self.assertRaisesRegex(g.Refusal, 'PACKAGE_UNIT_ENABLED'):
            self.prepare(self.observe())
        foreign = self.h.p(SYSTEM + '/multi-user.target.wants/foreign.service')
        self.assertEqual(str(foreign.readlink()), VENDOR + '/strongswan-starter.service')
        self.h.containment()

    def test_identical_replacement_mask_is_not_removed(self):
        self.h.error_stage = 'changed-mask'
        with self.assertRaisesRegex(g.Refusal, 'PACKAGE_CONTAINMENT_RACE'):
            self.prepare(self.observe())
        self.assertEqual(self.h.p(SYSTEM + '/strongswan.service').lstat().st_ino, self.h.replacement)
        self.assertTrue(self.h.p(POLICY).exists())

    def test_identical_replacement_policy_is_not_removed(self):
        self.h.error_stage = 'changed-policy'
        with self.assertRaisesRegex(g.Refusal, 'PACKAGE_CONTAINMENT_RACE'):
            self.prepare(self.observe())
        self.assertEqual(self.h.p(POLICY).stat().st_ino, self.h.replacement)
        self.h.containment()

    def test_replacement_at_quarantine_move_is_restored_not_unlinked(self):
        dest = self.h.p(SYSTEM + '/strongswan-starter.service')
        real = g._move
        replacement = []

        def race(src, name, dst, leaf):
            if name == dest.name and leaf == 'item' and not replacement:
                dest.unlink()
                dest.symlink_to('/opt/operator.service')
                replacement.append(dest.lstat().st_ino)
            return real(src, name, dst, leaf)

        with patch.object(g, '_move', side_effect=race):
            with self.assertRaisesRegex(g.Refusal, 'PACKAGE_CONTAINMENT_RACE'):
                self.prepare(self.observe())
        self.assertEqual(dest.lstat().st_ino, replacement[0])
        self.assertEqual(str(dest.readlink()), '/opt/operator.service')
        self.assertTrue(self.h.p(POLICY).exists())

    def test_exclusive_create_refuses_and_preserves_racing_mask(self):
        proof = self.observe()
        mask = self.h.p(SYSTEM + '/nftables.service')

        def enter():
            self.h.enter()
            mask.symlink_to('/opt/operator.service')

        with self.assertRaises(g.Refusal):
            g.prepare(self.h.root, self.h.run, proof, enter)
        self.assertEqual(str(mask.readlink()), '/opt/operator.service')
        self.assertFalse(self.h.p(POLICY).exists())
        self.assertEqual([f.name for f in self.h.p(SYSTEM).glob('*.service')], [mask.name])
        self.assertEqual(self.h.apt_count, 0)


    def test_bootstrap_apt_config_and_sealed_source_readable_by_exec_child(self):
        rows, _, _ = g._sources(self.h.root)
        # Same credentials, separate exec, no inherited descriptors. This
        # verifies the proc carrier, not APT parsing or privilege dropping.
        reader = '''
import fcntl, os, pathlib, re, stat
def sealed(path):
    assert stat.S_ISREG(os.stat(path).st_mode)
    with open(path) as stream:
        assert fcntl.fcntl(stream, fcntl.F_GET_SEALS) == 15
        return stream.read()
config = sealed(os.environ['APT_CONFIG'])
for key in ('Parts', 'Main', 'sourceparts', 'preferencesparts', 'netrc', 'netrcparts', 'trustedparts'):
    assert f'Dir::Etc::{key} "/dev/null";' in config
assert not pathlib.Path('/dev/null').is_file() and not pathlib.Path('/dev/null').is_dir()
assert 'KeepCompressed "false";' in config and '#clear Acquire::IndexTargets;' in config
for key in ('sourcelist', 'preferences'):
    print(sealed(re.search(rf'Dir::Etc::{key} "([^"]+)";', config)[1]), end='')
'''
        with g._apt(rows, {'ppp': ('2.5.2-1+1', 'amd64')}, bootstrap=True) as apt:
            result = subprocess.run(apt + (sys.executable, '-I', '-B', '-c', reader),
                                    check=True, capture_output=True, close_fds=True, timeout=5)
        self.assertTrue(result.stdout.startswith(b''.join(
            f'deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg inrelease-path=InRelease] '
            f'{uri} {suite} main\n'.encode() for uri, suite in rows)))
        self.assertIn(b'Package: ppp\nPin: version 2.5.2-1+1\n', result.stdout)

    def test_trixie_updates_solver_uses_signed_version_and_suite(self):
        row = b'tzdata (2026f-0+deb13u1 Debian:13-updates/stable-updates [all])\n'
        summary = b'0 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.\n'
        data = summary + b'Inst ' + row + b'Conf ' + row
        self.assertEqual(g._simulation((), lambda *_: (0, data, b''), ['tzdata']),
                         {'tzdata': ['2026f-0+deb13u1', 'all']})
        bad = data.replace(b'/stable-updates', b'/stable')
        with self.assertRaisesRegex(g.Refusal, 'PACKAGE_APT_PLAN'):
            g._simulation((), lambda *_: (0, bad, b''), ['tzdata'])

    def test_stock_keyring_alias_binds_link_and_target(self):
        alias = self.h.p('/usr/share/keyrings/debian-archive-keyring.gpg')
        target = alias.with_suffix('.pgp')
        alias.rename(target)
        alias.symlink_to(target.name)
        proof = self.observe()  # APT's packaged debian.sources still says .gpg.
        alias.rename(alias.with_name('old-link'))
        alias.symlink_to(target.name)
        with self.assertRaisesRegex(g.Refusal, 'PACKAGE_PLAN_CHANGED'):
            self.prepare(proof)
        proof = self.observe()
        target.write_bytes(b'changed public keyring fixture')
        with self.assertRaisesRegex(g.Refusal, 'PACKAGE_PLAN_CHANGED'):
            self.prepare(proof)
        self.no_effects()

    def test_keyring_refuses_other_aliases_and_unsafe_targets(self):
        alias = self.h.p('/usr/share/keyrings/debian-archive-keyring.gpg')
        target = alias.with_suffix('.pgp')
        alias.rename(target)
        for text in (str(target), './' + target.name, '../keyrings/' + target.name, 'operator.gpg'):
            with self.subTest(text=text):
                alias.symlink_to(text)
                with self.assertRaises(g.Refusal):
                    self.observe()
                alias.unlink()
        alias.symlink_to(target.name)
        target.chmod(0o666)
        with self.assertRaises(g.Refusal):
            self.observe()
        target.rename(target.with_name('other.pgp'))
        target.symlink_to('other.pgp')
        with self.assertRaises(g.Refusal):
            self.observe()
        self.no_apt()

    def test_stock_empty_updates_and_security_targets(self):
        # APT can omit a signed empty uncompressed Packages target even
        # though its compressed representation is nonempty.
        for empty in ('missing', 'present', 'wrong-digest', 'wrong-bytes', 'compressed', 'base-missing'):
            with self.subTest(empty=empty):
                self.h = Host(self, self.h.root / empty)
                self.empty_indexes()
                def stock_targets():
                    for release in self.h.p('/var/lib/apt/lists').glob('*_InRelease'):
                        suite = release.name.split('_dists_')[1].removesuffix('_InRelease')
                        packages = release.with_name(release.name.replace('_InRelease', '_main_binary-amd64_Packages'))
                        if suite == 'trixie':
                            if empty == 'base-missing':
                                packages.unlink()
                            release.write_text(release.read_text().replace('SHA256:',
                                'Architectures: all amd64 arm64\nNo-Support-for-Architecture-all: Packages\nSHA256:'))
                            continue
                        fields = ('Label: Debian-Security\nSuite: stable-security\n'
                                  'Components: updates/main updates/non-free-firmware\nArchitectures: amd64 arm64\n'
                                  if suite == 'trixie-security' else
                                  'Label: Debian\nSuite: stable-updates\nVersion: 13-updates\n'
                                  'Architectures: all amd64 arm64\nNo-Support-for-Architecture-all: Packages\n')
                        digest = '1' * 64 if empty == 'wrong-digest' else hashlib.sha256(b'').hexdigest()
                        release.write_text(re.sub(r'(?m)^SHA256:\n .*$', fields + 'SHA256:\n'
                            f' {digest}        0 main/binary-amd64/Packages\n'
                            ' 0040f94d11d0039505328a90b2ff48968db873e9e7967307631bf40ef5679275'
                            '       32 main/binary-amd64/Packages.xz', release.read_text()))
                        if empty == 'present':
                            packages.write_bytes(b'')
                        elif empty == 'compressed':
                            packages.rename(packages.with_suffix('.lz4'))
                        elif empty != 'wrong-bytes':
                            packages.unlink()
                self.h.after_update = stock_targets
                proof = self.observe()
                if empty in ('missing', 'present'):
                    self.assertIsNone(self.prepare(proof))
                    self.assertEqual(self.h.effects, ['enter', 'update', 'reload', 'apt', 'reload', 'reload'])
                else:
                    with self.assertRaisesRegex(g.Refusal, 'PACKAGE_APT_INDEXES'):
                        self.prepare(proof)
                    self.assertEqual(self.h.effects, ['enter', 'update'])

    def test_trixie_security_package_main_pool_path(self):
        # Archived trixie-security main/binary-amd64/Packages record fields.
        filename = 'pool/updates/main/s/strongswan/strongswan_6.0.1-6+deb13u7_all.deb'
        def records(leaf):
            return (f'Package: strongswan\nVersion: 6.0.1-6+deb13u7\nArchitecture: all\n'
                    f'Filename: {leaf}\nSize: 95460\n'
                    'SHA256: 40c5a40bdb95f71dc412222aaa061d16cd943bc46b796aa0714e5732cfe1462a\n'
                    'Depends: charon-systemd | strongswan-charon, strongswan-swanctl | strongswan-starter\n\n').encode()
        plan = {'strongswan': ['6.0.1-6+deb13u7', 'all']}
        self.assertEqual(g._metadata((), lambda *_: (0, records(filename), b''), plan, {}, plan)
                         ['strongswan'][1], filename)
        for leaf in (filename.replace('/main/', '/contrib/'), filename.replace('/main/', '/main/../'),
                     filename.replace('/updates/', '/mirror/'), '/' + filename):
            with self.subTest(leaf=leaf), self.assertRaisesRegex(g.Refusal, 'PACKAGE_DEPENDENCY'):
                g._metadata((), lambda *_: (0, records(leaf), b''), plan, {}, plan)


if __name__ == '__main__':
    unittest.main()
