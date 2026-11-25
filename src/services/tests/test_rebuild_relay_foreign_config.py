"""Fresh Install host proof: private files, modeled observers, no native commands."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / 'rebuildRelayDirectHost.py'
MACHINE = 'a' * 32
BOOT = '12345678-1234-1234-1234-123456789abc'
UDP = b'  sl  local_address rem_address st tx_queue rx_queue\n'
LO = {'ifname': 'lo', 'link_type': 'loopback'}
PRESENCE = (
    ('SWAN_PROFILE_PRESENT', '/etc/strongswan.d/celerity-rebuild-l2tp.conf'),
    ('IKE_PROFILE_PRESENT', '/etc/ipsec.d/celerity-rebuild-l2tp.conf'),
    ('OPTIONS_PRESENT', '/etc/ppp/options.xl2tpd'),
    ('MODULES_LOAD_FOREIGN', '/etc/modules-load.d/c3-l2tp.conf'),
)


class ForeignConfig(unittest.TestCase):
    def setUp(self):
        self.h = runpy.run_path(str(SOURCE))['main'].__globals__
        self.temp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(patch.object(os, 'geteuid', return_value=0))
        # Keep real filesystem metadata except for the modeled root owner.
        self.foreign_owner = set()
        def project(stat_fn):
            def owner(*args, **kwargs):
                st = stat_fn(*args, **kwargs)
                if st.st_uid != os.getuid():
                    return st
                class FixtureStat:
                    st_uid, st_gid = (123, 123) if st.st_ino in self.foreign_owner else (0, 0)
                    def __getattr__(self, key):
                        return getattr(st, key)
                return FixtureStat()
            return owner
        self.enterContext(patch.object(os, 'fstat', side_effect=project(os.fstat)))
        self.enterContext(patch.object(os, 'stat', side_effect=project(os.stat)))
        self.enterContext(patch.object(subprocess, 'run', side_effect=AssertionError('unmodeled host command')))
        self.active = set()
        self.net_state = 'static'
        self.net_dropins = ''
        self.tables = []
        self.routes = []
        self.malformed_tables = False
        self.jobs = b''
        self.rules = []
        self.names = [b'systemd', b'ps']
        self.udp, self.udp6 = UDP, UDP
        self.links = [LO]
        self.xfrm = b''
        self.stock, self.status, self.calls = {}, {}, []
        self.put(self.h['SYSTEM'] + '/.fixture', b'')
        self.native_command = self.h['command']
        self.h.update(directory=self.directory, open=self.read_kernel, command=self.command,
                      ppp_device=lambda: True, ppp_registered=lambda: True,
                      missing_network_observers=lambda: [])

    def path(self, path):
        return self.temp / path.lstrip('/')

    def put(self, path, data, mode=0o600):
        path = self.path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)
        return path

    @contextlib.contextmanager
    def directory(self, path, private=False):
        target = self.path(path)
        fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            yield fd
        finally:
            os.close(fd)

    def read_kernel(self, path, mode='r'):
        data = {'/etc/machine-id': (MACHINE + '\n').encode(), '/proc/sys/kernel/random/boot_id': (BOOT + '\n').encode(),
                '/proc/net/udp': self.udp, '/proc/net/udp6': self.udp6}[path]
        return io.BytesIO(data) if mode == 'rb' else io.StringIO(data.decode())

    def command(self, *args, **opts):
        self.calls.append(args)
        if args[0] == '/usr/bin/dpkg-query':
            assert len(args) == 4 and args[1] == '-W', args
            if args[2] == '-f=${db:Status-Abbrev}':
                return b'ii '
            assert args[2] == r'-f=${Status}\n${Conffiles}', args
            return self.status.get(args[3], b'install ok installed\n') + self.stock.get(args[3], b'')
        if args[:4] == ('/usr/bin/systemctl', '--no-pager', 'show', '--all'):
            if args[-1] == self.h['NET_UNIT']:
                present = self.path(self.h['NET']).is_file()
                active = 'active' if args[-1] in self.active else 'inactive'
                return (f'LoadState={"loaded" if present else "not-found"}\nActiveState={active}\n'
                        f'FragmentPath={self.h["NET"] if present else ""}\n'
                        f'UnitFileState={self.net_state if present else ""}\n'
                        f'DropInPaths={self.net_dropins}\nMainPID=0\n').encode()
            state = 'not-found' if args[-1] == 'strongswan.service' else 'loaded'
            return ('LoadState=' + state + '\nActiveState=' + ('active' if args[-1] in self.active else 'inactive') + '\n').encode()
        if args[0] == '/usr/bin/systemctl' and 'list-jobs' in args:
            return self.jobs
        if args == ('/usr/sbin/nft', '-j', 'list', 'tables'):
            assert opts.get('quiet') is True
            return json.dumps({'nftables': {} if self.malformed_tables else [{'table': row} for row in self.tables]}).encode()
        if args == ('/usr/sbin/ip', '-j', '-N', '-4', 'route', 'show', 'table', 'all'):
            return json.dumps(self.routes).encode()
        if args == ('/usr/bin/ps', '-ww', '-e', '-o', 'pid=', '-o', 'comm='):
            return b''.join(str(i).encode() + b' ' + name + b'\n' for i, name in enumerate(self.names, 1))
        if args == ('/usr/sbin/ip', '-j', '-details', 'link', 'show'):
            return json.dumps(self.links).encode()
        if args == ('/usr/sbin/ip', 'xfrm', 'policy', 'list', 'nosock'):
            return b''
        if args == ('/usr/sbin/ip', 'xfrm', 'state', 'list', 'nokeys'):
            return self.xfrm
        if args in (('/usr/sbin/ip', '-j', '-N', '-4', 'rule', 'show'), ('/usr/sbin/ip', '-j', '-N', '-6', 'rule', 'show')):
            return json.dumps(self.rules).encode()
        raise AssertionError(args)

    def run_host(self, action='preflight', machine=MACHINE, **kwargs):
        wire = json.dumps({'action': action, 'machineId': machine, **kwargs}).encode()
        out, err = io.StringIO(), io.StringIO()
        with patch.object(sys, 'stdin', io.TextIOWrapper(io.BytesIO(wire))), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = self.h['main']()
        return code, out.getvalue(), err.getvalue()

    def snapshot(self):
        return {p.relative_to(self.temp).as_posix(): (stat.S_IMODE(p.lstat().st_mode), os.readlink(p) if p.is_symlink()
                else p.read_bytes() if p.is_file() else None) for p in self.temp.rglob('*')}

    def seed(self):
        for key, package in [('starter', 'strongswan-starter'), ('secrets', 'strongswan-starter'), ('lns', 'xl2tpd')]:
            path = self.h['NAMES'][key]
            data = f'# synthetic {key}\n'.encode()
            self.put(path, data)
            md5 = hashlib.md5(data, usedforsecurity=False).hexdigest()
            self.stock[package] = self.stock.get(package, b'') + f' {path} {md5}\n'.encode()
        self.put(self.h['NAMES']['chap'], b'  # comment\n\t\n')
        want = self.path(self.h['SYSTEM'] + '/multi-user.target.wants/strongswan.service')
        want.parent.mkdir(parents=True)
        want.symlink_to('/missing/unit')
        self.put('/etc/ipsec.d/private/unrelated.pem', b'not inspected')

    def assert_foreign(self, *keys):
        before = self.snapshot()
        self.assertEqual(self.run_host(), (70, '', 'DIRECT_L2TP_FOREIGN_CONFIG ' + ','.join(keys) + '\n'))
        self.assertEqual(self.snapshot(), before)

    def test_absent_service_systemctl_status_one_is_a_valid_idle_observation(self):
        original = self.command

        def command(*args, **opts):
            if args[:4] == ('/usr/bin/systemctl', '--no-pager', 'show', '--all'):
                return self.native_command(*args, **opts)
            return original(*args, **opts)

        def systemctl_show(args, **_):
            assert args[:4] == ('/usr/bin/systemctl', '--no-pager', 'show', '--all')
            data = original(*args)
            return subprocess.CompletedProcess(args, int(b'LoadState=not-found\n' in data), data, b'')

        with patch.object(subprocess, 'run', side_effect=systemctl_show):
            self.h['command'] = command
            self.assertEqual(self.run_host()[0], 0)

    def test_each_exact_file_in_isolation(self):
        for key, path in PRESENCE:
            with self.subTest(path=path):
                leaf = self.put(path, b'')
                try:
                    self.assert_foreign(key)
                finally:
                    leaf.unlink()
                self.assertEqual(self.run_host()[0], 0)

    def test_orphan_ipsec_state_is_not_a_config_only_refusal(self):
        self.put(PRESENCE[0][1], b'')
        original = self.snapshot()
        self.xfrm = b'synthetic SA without a daemon\n'
        self.assertEqual(self.run_host(), (70, '', 'DIRECT_L2TP_DAEMON_ACTIVE\n'))
        self.assertEqual(self.snapshot(), original)

    def test_static_orphan_and_legacy_nft_keep_the_whole_list(self):
        for _, path in PRESENCE[:3]:
            self.put(path, b'')
        self.put(self.h['NAMES']['chap'], b'fixture fixture fixture *\n')
        self.put(self.h['NET'], b'[Service]\nType=oneshot\n')
        expected = ('SWAN_PROFILE_PRESENT', 'IKE_PROFILE_PRESENT', 'OPTIONS_PRESENT', 'CHAP_NOT_EMPTY')
        self.assert_foreign(*expected, 'NETWORK_UNIT_ORPHANED')
        self.put(self.h['LEGACY_NFT'], b'# synthetic legacy\n')
        self.assert_foreign(*expected, 'NETWORK_UNIT_ORPHANED', 'LEGACY_NFT_PRESENT')
        self.path(self.h['NET']).unlink()
        self.assert_foreign(*expected, 'LEGACY_NFT_PRESENT')

    def test_old_network_runtime_or_owned_state_prevents_replacement(self):
        self.put(self.h['NET'], b'[Service]\nType=oneshot\n')
        self.put(PRESENCE[0][1], b'')
        for name, value in [('active', {self.h['NET_UNIT']}), ('net_state', 'enabled'),
                            ('net_dropins', '/fixture/local.conf'), ('jobs', f'10 {self.h["NET_UNIT"]} start waiting\n'.encode()),
                            ('rules', [{'priority': 80, 'table': 150, 'fwmark': '0x64'}]),
                            ('rules', [{'priority': 10077, 'table': 100, 'fwmark': '0x4d'}]),
                            ('routes', [{'type': 'local', 'dev': 'lo', 'dst': 'default', 'table': 100}]),
                            ('malformed_tables', True),
                            ('tables', [{'family': 'inet', 'name': self.h['TABLE']}])]:
            with self.subTest(observer=name):
                old = getattr(self, name)
                setattr(self, name, value)
                before = self.snapshot()
                self.assertEqual(self.run_host(), (70, '', 'DIRECT_L2TP_DAEMON_ACTIVE\n'))
                self.assertEqual(self.snapshot(), before)
                setattr(self, name, old)
        self.path(self.h['VAULT']).mkdir(parents=True)
        self.assertEqual(self.run_host(), (70, '', 'DIRECT_L2TP_DAEMON_ACTIVE\n'))

    def test_each_custom_conffile_in_isolation(self):
        self.seed()
        for key, name in [('STARTER_NOT_STOCK', 'starter'), ('SECRETS_NOT_EMPTY', 'secrets'),
                          ('CHAP_NOT_EMPTY', 'chap'), ('LNS_NOT_STOCK', 'lns')]:
            with self.subTest(name=name):
                path = self.h['NAMES'][name]
                original = self.path(path).read_bytes()
                self.put(path, b'fixture-active\n')
                self.assert_foreign(key)
                self.put(path, original)

    def test_unproved_package_evidence_refuses_even_with_exact_leftover(self):
        self.seed()
        package = 'strongswan-starter'
        self.put('/etc/ipsec.conf', b'conn fixture\n')
        self.put(PRESENCE[2][1], b'')
        original = self.stock[package]
        for status, rows in [(b'unknown ok not-installed\n', original), (b'deinstall ok config-files\n', original),
                             (b'install reinstreq installed\n', original),
                             (b'install ok installed\n', b''), (b'install ok installed\n', original * 2),
                             (b'install ok installed\n', original.replace(b'\n', b' obsolete\n', 1)),
                             (b'install ok installed\n', b' /etc/ipsec.conf bad\n')]:
            with self.subTest(status=status, size=len(rows)):
                self.status[package], self.stock[package] = status, rows
                self.assert_foreign('OPTIONS_PRESENT', 'CONFFILE_UNKNOWN')
                self.assertIsNone(self.h['foreign_config_observation']()[1])

    def test_dirs_and_nonexact_unit_modes_diagnose_without_fingerprint(self):
        for key, leaf in [('NFT_DIR_PRESENT', self.h['NFT_DIR']), ('DROPIN_PRESENT', self.h['DROP_DIR'])]:
            with self.subTest(leaf=leaf):
                p = self.put(leaf + '/arbitrary-contents', b'ignored')
                self.assert_foreign(key)
                self.assertEqual(self.h['foreign_config_observation'](), ((key,), None))
                p.unlink()
                p.parent.rmdir()
        for unit, exact in [('xray.service', 'XRAY_UNIT_0666'), ('xray-bridge.service', 'XRAY_BRIDGE_UNIT_0666')]:
            for mode, key in [(0o666, exact), (0o664, 'UNIT_WRITABLE'), (0o646, 'UNIT_WRITABLE')]:
                with self.subTest(unit=unit, mode=mode):
                    p = self.put(self.h['SYSTEM'] + '/' + unit, b'[Service]\n', mode)
                    self.assert_foreign(key)
                    keys, fingerprint = self.h['foreign_config_observation']()
                    self.assertEqual(keys, (key,))
                    self.assertEqual(fingerprint is not None, mode == 0o666)
                    p.unlink()
        self.put(PRESENCE[0][1], b'')
        self.put(self.h['DROP_DIR'] + '/local.conf', b'')
        self.assert_foreign('SWAN_PROFILE_PRESENT', 'DROPIN_PRESENT')
        self.assertIsNone(self.h['foreign_config_observation']()[1])

    def test_unknown_included_path_and_unsafe_owner_veto_exact_leftover(self):
        self.put(PRESENCE[2][1], b'')
        for path, key in [('/etc/ipsec.d/custom.conf', 'IPSEC_D_FOREIGN_CONF'),
                          ('/etc/strongswan.d/custom.conf', 'SWAN_TREE_NOT_STOCK'),
                          ('/etc/strongswan.conf', 'SWAN_TREE_NOT_STOCK')]:
            p = self.put(path, b'')
            self.assert_foreign('OPTIONS_PRESENT', key)
            self.assertIsNone(self.h['foreign_config_observation']()[1])
            p.unlink()
        self.foreign_owner.add(self.path(PRESENCE[2][1]).stat().st_ino)
        self.assertEqual(self.run_host(), (70, '', 'DIRECT_PREREQUISITE\n'))

    def test_only_stock_starter_include_is_in_scope(self):
        self.seed()
        path = '/etc/ipsec.conf'
        stock = self.path(path).read_bytes()
        self.put(path, stock + b'\ninclude /etc/ipsec.d/*.conf\n')
        self.assertEqual(self.h['foreign_config_observation'](), ((), None))
        self.put(path, stock + b'\ninclude /etc/custom-vpn.conf\n')
        self.put(PRESENCE[2][1], b'')
        self.assert_foreign('OPTIONS_PRESENT', 'INCLUDE_FOREIGN')
        self.assertIsNone(self.h['foreign_config_observation']()[1])

    def test_stock_then_foreign_exact_keys_private_fingerprint(self):
        self.seed()
        before = self.snapshot()
        self.assertEqual(self.h['foreign_config_observation'](), ((), None))
        code, stdout, stderr = self.run_host()
        self.assertEqual((code, stderr), (0, ''))
        self.assertTrue(json.loads(stdout)['pppPreparation'])
        self.assertEqual(self.snapshot(), before)
        for name in ('starter', 'secrets', 'lns'):
            self.put(self.h['NAMES'][name], b'PRIVATE-FIXTURE bytes\n')
        self.put(self.h['NAMES']['chap'], b'  # comment\n\tlogin server value *\n')
        for key in ('ike', 'options'):
            self.put(self.h['NAMES'][key], b'')
        self.put('/etc/modules-load.d/c3-l2tp.conf', b'ppp_generic\n')
        for key in ('X', 'B'):
            self.put(self.h['SYSTEM'] + '/' + self.h[key], b'[Service]\n', 0o666)
        keys, digest = self.h['foreign_config_observation']()
        self.assertEqual(keys, ('IKE_PROFILE_PRESENT', 'OPTIONS_PRESENT', 'STARTER_NOT_STOCK', 'SECRETS_NOT_EMPTY',
                                'CHAP_NOT_EMPTY', 'LNS_NOT_STOCK', 'XRAY_UNIT_0666', 'XRAY_BRIDGE_UNIT_0666',
                                'MODULES_LOAD_FOREIGN'))
        self.assertRegex(digest, r'^[0-9a-f]{64}$')
        before = self.snapshot()
        self.assertEqual(self.run_host(), (70, '', 'DIRECT_L2TP_FOREIGN_CONFIG ' + ','.join(keys) + '\n'))
        self.assertEqual(self.snapshot(), before)
        self.put(self.h['NAMES']['chap'], b'  # comment\n\tlogin server other *\n')
        self.assertNotEqual(self.h['foreign_config_observation'](), (keys, digest))

    def test_runtime_priority_and_wrong_machine(self):
        self.seed()
        self.put(self.h['NAMES']['chap'], b'login server value *\n')
        self.active = {'charon-systemd.service'}
        self.udp6 += b'    1: 00000000000000000000000000000000:1194 00000000000000000000000000000000:0000 07\n'
        self.links.append({'ifname': 'renamed', 'link_type': 'ppp'})
        self.assertEqual(self.run_host(machine='b' * 32), (70, '', 'DIRECT_IDENTITY\n'))
        self.assertEqual(self.run_host(), (70, '', 'DIRECT_L2TP_DAEMON_ACTIVE\n'))
        self.active.clear()
        self.names.append(b'charon')
        self.assertEqual(self.run_host(), (70, '', 'DIRECT_L2TP_DAEMON_ACTIVE\n'))
        self.names.pop()
        self.assertEqual(self.run_host(), (70, '', 'DIRECT_L2TP_UDP_BOUND\n'))
        self.udp6 = UDP
        for port in (500, 4500, 1701):
            with self.subTest(port=port):
                self.udp = UDP + f' 1: 00000000:{port:04X} 00000000:1234 01\n'.encode()
                self.assertEqual(self.run_host(), (70, '', 'DIRECT_L2TP_UDP_BOUND\n'))
        self.udp = UDP
        self.assertEqual(self.run_host(), (70, '', 'DIRECT_L2TP_PPP_ACTIVE\n'))
        self.links = [LO]
        self.names.append(b'pppd')
        self.assertEqual(self.run_host(), (70, '', 'DIRECT_L2TP_PPP_ACTIVE\n'))
        self.names.pop()
        self.rules = [{'priority': 220, 'src': 'all', 'table': 220}]
        self.assertEqual(self.run_host(), (70, '', 'DIRECT_RULE_220_CONFLICT\n'))
        self.active = {self.h['IKE']}
        self.h['missing_network_observers'] = lambda: ('inet_diag',)
        self.assertEqual(self.run_host(), (70, '', 'DIRECT_IKE_ACTIVE_UNMANAGED\n'))
        self.active.clear()
        self.rules = []
        self.assert_foreign('CHAP_NOT_EMPTY')
        self.udp = b'malformed\n'
        self.assertEqual(self.run_host(), (70, '', 'DIRECT_PREREQUISITE\n'))

    def test_unsafe_candidates_never_become_keys(self):
        self.seed()
        old = self.path(self.h['NAMES']['ike'])
        old.symlink_to(self.path('/etc/ipsec.d/unrelated.conf'))
        before = self.snapshot()
        self.assertEqual(self.run_host(), (70, '', 'DIRECT_PREREQUISITE\n'))
        self.assertEqual(self.snapshot(), before)
        old.unlink()
        other = self.put(self.h['SYSTEM'] + '/unrelated.service', b'unit', 0o666)
        exact = self.path(self.h['SYSTEM'] + '/' + self.h['X'])
        exact.symlink_to(other)
        self.assertEqual(self.run_host(), (70, '', 'DIRECT_PREREQUISITE\n'))
        exact.unlink()
        self.put(self.h['SYSTEM'] + '/' + self.h['X'], b'unit', 0o644)
        self.assertEqual(self.h['foreign_config_observation'](), ((), None))

    def test_fresh_recheck_refuses_without_effect_nonfresh_does_not_scan(self):
        self.seed()
        self.put('/etc/modules-load.d/c3-l2tp.conf', b'ppp_generic\n')
        kwargs = dict(network={'clientCidr': '10.255.1.0/24', 'tproxyPort': 12345, 'fwmark': 77, 'routeTable': 177},
                      backupId='b' * 32, baseline='c' * 64)
        before = self.snapshot()
        for action in ('prepare', 'check', 'install'):
            with self.subTest(action=action):
                prefix = 'DIRECT_NO_WRITE_' if action == 'install' else 'DIRECT_'
                self.assertEqual(self.run_host(action, **kwargs), (70, '', prefix + 'L2TP_FOREIGN_CONFIG MODULES_LOAD_FOREIGN\n'))
        # Existing nonfresh Verify takes its existing guarded manifest path,
        # never a first-Install conflict classification.
        self.h['require_network_observers'] = lambda: None
        def no_manifest(_):
            raise self.h['Refusal']('BASELINE_CHANGED')
        self.h['bound_manifest'] = no_manifest
        self.calls.clear()
        self.assertEqual(self.run_host('verify', **kwargs), (70, '', 'DIRECT_BASELINE_CHANGED\n'))
        self.assertNotIn(('/usr/bin/ps', '-ww', '-e', '-o', 'pid=', '-o', 'comm='), self.calls)
        self.assertEqual(self.snapshot(), before)

    def test_boot_drift_does_not_publish_refusal(self):
        self.seed()
        self.active = {'xl2tpd.service'}
        reads = iter((BOOT, 'b' * 36))
        self.h['boot'] = lambda: next(reads)
        self.assertEqual(self.run_host(), (70, '', 'DIRECT_BASELINE_CHANGED\n'))


if __name__ == '__main__':
    unittest.main()
