"""Private-root filesystem regressions; no program is executed by the fake runner.

The command formats and known xl2tpd-generated fragment are Debian-shaped.
Solver input beyond repository-pinned versions/fragment is synthetic, not a
claim of an exact trixie dependency lock or an authenticated apt replay.
"""

import fcntl
import hashlib
import importlib.util
import json
import os
import re
import struct
import subprocess
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


class Host:
    def __init__(self, test, root):
        self.t, self.root = test, root
        self.calls, self.effects = [], []
        self.apt_count = 0
        self.apt_mode = 'ok'
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
        for path in ('/usr/bin', '/usr/sbin', '/usr/lib/apt/methods', VENDOR, SYSTEM, LATE,
                     '/usr/share/keyrings', '/etc/init.d', '/etc/dpkg/dpkg.cfg.d',
                     '/var/lib/dpkg/info', '/var/lib/dpkg/updates', '/var/cache/apt/archives',
                     '/etc/apt/sources.list.d', '/var/lib/apt/lists', *(f'/etc/rc{i}.d' for i in 'S0123456')):
            self.p(path).mkdir(parents=True, exist_ok=True)
        for path in self.root.rglob('*'):
            path.chmod(0o755)
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
            if pkg not in old:
                unit = pkg + '.service'
                frag = self.put(f'{VENDOR}/{unit}', f'[Unit]\nDescription=fixture\n[Service]\n'
                                f'ExecStart=/usr/bin/true\n[Install]\nWantedBy={target}\n')
                self.put(f'/var/lib/dpkg/info/{pkg}.md5sums',
                         f'{hashlib.md5(frag.read_bytes()).hexdigest()}  {VENDOR[1:]}/{unit}\n')
                self.link(f'{SYSTEM}/{target}.wants/{unit}', VENDOR + '/' + unit)
        if 'xl2tpd' not in old:
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
        self.t.assertIn('Dir::Etc::Parts "";', config)
        source_match = re.search(r'Dir::Etc::sourcelist "([^"]+)";', config)
        assert source_match is not None
        src = Path(source_match[1]).read_text()
        self.t.assertIn('deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] '
                        'http://deb.debian.org/debian trixie main\n', src)
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
            intro = ('Reading package lists...\nBuilding dependency tree...\nReading state information...\n'
                     'The following NEW packages will be installed:\n  ' + ' '.join(plan) + '\n'
                     f'0 upgraded, {len(plan)} newly installed, 0 to remove and 0 not upgraded.\n')
            lines = [f'{verb} {n} ({v} Debian:13.1/stable [{a}])\n'
                     for verb in ('Inst', 'Conf') for n, (v, a) in plan.items()]
            return 0, (intro + ''.join(lines) + self.sim_extra).encode(), b''
        self.t.assertEqual(args[0], '-y')
        self.t.assertEqual(timeout, 78)
        self.t.assertNotEqual(prefs, '/dev/null')
        self.t.assertEqual(self.effects[:2], ['enter', 'reload'])
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
        if argv == ('/usr/bin/dpkg-query', '-W', '-f=${Conffiles}\\n', 'xl2tpd'):
            md5 = hashlib.md5(self.p('/etc/init.d/xl2tpd').read_bytes()).hexdigest()
            return 0, f' /etc/init.d/xl2tpd {md5}\n'.encode(), b''
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
        if argv == ('/usr/sbin/update-rc.d', 'xl2tpd', 'disable'):
            self.effects.append('sysv-disable')
            self.containment()
            for leaf in self.p('/etc').glob('rc?.d/S??xl2tpd'):
                leaf.rename(leaf.with_name('K01xl2tpd'))
            return 0, b'', b''
        raise AssertionError(f'Unexpected modeled argv {argv!r}')


class TestPackageGuard(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(dir=HERE, prefix='.package-fixture-')
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

    def test_stock_shaped_success_disables_sysv_and_native_only_after_apt(self):
        proof = self.observe()
        self.assertEqual(proof['missing'], SIX)
        self.no_effects()
        survivor = self.h.link(SYSTEM + '/multi-user.target.wants/operator.service', '/opt/operator.service')
        self.assertIsNone(self.prepare(proof))
        self.assertEqual(self.h.effects, ['enter', 'reload', 'apt', 'sysv-disable', 'reload', 'reload'])
        self.assertEqual(survivor.readlink(), Path('/opt/operator.service'))
        self.assertFalse(self.h.p(POLICY).exists())
        self.assertFalse(any(self.h.p(SYSTEM).glob('*.wants/strongswan-starter.service')))
        self.assertFalse(any(self.h.p(SYSTEM).glob('*.wants/nftables.service')))
        self.assertFalse(any(self.h.p(SYSTEM).glob('*.service')))
        self.assertFalse(any(self.h.p('/etc').glob('rc?.d/S??xl2tpd')))
        self.assertTrue(all(self.h.p(f'/etc/rc{i}.d/K01xl2tpd').is_symlink() for i in '0123456'))
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
        proof = self.observe()
        self.assertEqual(proof['missing'], ['ppp'])
        self.assertIsNone(self.prepare(proof))
        self.assertNotIn('sysv-disable', self.h.effects)
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
        with self.assertRaisesRegex(g.Refusal, 'PACKAGE_SOURCES'):
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


if __name__ == '__main__':
    unittest.main()
