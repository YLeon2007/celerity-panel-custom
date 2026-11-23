"""Focused local file lifecycle; never dispatch Install or run systemctl."""
import argparse
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
from types import SimpleNamespace
from typing import Any
import unittest
from unittest.mock import Mock

args = argparse.ArgumentParser()
args.add_argument('source', type=Path)
args.add_argument('etc_archive', type=Path)
args.add_argument('fixture', type=Path)
args.add_argument('parent_netns')
args.add_argument('--test', action='append', default=[], help='unittest case to run (repeatable)')
a = args.parse_args()
assert os.geteuid() == 0 and os.readlink('/proc/self/ns/net') != a.parent_netns
assert a.fixture.is_absolute() and a.fixture.is_dir() and not list(a.fixture.iterdir())

ROOT = a.fixture
FILE = '/etc/strongswan.d/celerity-rebuild-l2tp.conf'
PAYLOAD = b'charon {\n    routing_table = 0\n    install_routes = no\n}\n'
MACHINE, TOKEN = 'a' * 32, 'b' * 32
NET = dict(clientCidr='10.255.1.0/24', tproxyPort=12345, fwmark=77, routeTable=177)
NETWORK_FIXTURE = runpy.run_path(str(Path(__file__).with_name('helpers') / 'rebuildRelayNetworkFixture.py'))


class Files(unittest.TestCase):
    def setUp(self):
        h: dict[str, Any] = {'__name__': 'fixture'}
        self.h = h
        exec(compile(a.source.read_bytes(), str(a.source), 'exec'), h)
        h['install'] = Mock(side_effect=AssertionError('Install forbidden'))
        self.root = ROOT / self._testMethodName
        self.root.mkdir(mode=0o755)
        h['NETWORK_RUN'] = str(self.root / 'run')
        self.req = dict(machineId=MACHINE, backupId=TOKEN, network=NET, nodeId='c' * 24)
        self.path = self.real(FILE)
        # Preserve real openat, O_NOFOLLOW, mode/owner checks, atomic file ops,
        # and stat identity. Map only the initial directory FD and absolute stats.
        root = self.root
        class FixtureOS:
            def __getattr__(self, key):
                return getattr(os, key)

            def open(self, path, flags, *mode, dir_fd=None):
                if dir_fd is None:
                    assert path == '/' and flags & os.O_DIRECTORY
                    return os.open(root, flags)
                assert '/' not in path and path not in ('.', '..')
                return os.open(path, flags, *mode, dir_fd=dir_fd)

            def lstat(self, path):
                return os.lstat(root / path.lstrip('/'))

            path = SimpleNamespace(split=os.path.split, basename=os.path.basename, dirname=os.path.dirname,
                                   join=os.path.join, lexists=lambda p: os.path.lexists(root / p.lstrip('/')))

        h.update(os=FixtureOS(), boot=lambda: 'fixture-boot')
        self.real('/etc').mkdir(mode=0o755)
        self.real('/etc/machine-id').write_text(MACHINE + '\n', encoding='ascii')
        shutil.copy2(a.etc_archive / 'strongswan.conf', self.real('/etc/strongswan.conf'))
        shutil.copytree(a.etc_archive / 'strongswan.d', self.real('/etc/strongswan.d'))
        self.real(h['SYSTEM']).mkdir(mode=0o755, parents=True)
        self.real(h['VAULT']).parent.mkdir(mode=0o755, parents=True)
        self.real('/etc/ipsec.d').mkdir(mode=0o755)
        self.original_units = {name: dict(ActiveState='inactive', SubState='dead', MainPID='0',
            InvocationID='', LoadState='loaded', FragmentPath='/usr/lib/systemd/system/' + name,
            DropInPaths='', UnitFileState='enabled', NeedDaemonReload='no', PrivateNetwork='no', KillMode='control-group',
            User='', Group='', Requires='', After='', RequiredBy='', BoundBy='', ConsistsOf='', PropagatesStopTo='',
            Conflicts='shutdown.target', ConflictedBy='', Wants='', BindsTo='', Upholds='')
            for name in h['UNITS']}
        self.X, self.IKE, self.XL, self.B, self.N = (h[k] for k in ('X', 'IKE', 'XL', 'B', 'NET_UNIT'))
        self.original_units[self.N].update(LoadState='not-found', FragmentPath='')
        self.original_units[self.X].update(ActiveState='active', SubState='running', MainPID='7', InvocationID='main-before')
        self.original_units[self.IKE]['ExecStart'] = '{ path=/usr/sbin/ipsec ; argv[]=/usr/sbin/ipsec start --nofork ; }'
        self.original_units[self.XL]['ExecStart'] = '{ path=/usr/sbin/xl2tpd ; argv[]=/usr/sbin/xl2tpd -D ; }'
        for k in ('lns', 'chap', 'secrets', 'starter', 'main'):
            p = self.real(h['NAMES'][k]); p.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            p.write_bytes({
                'starter': b'config setup\ninclude /etc/ipsec.d/*.conf\n',
                'main': h['encode'](dict(inbounds=[dict(tag='API_INBOUND', protocol='dokodemo-door',
                    port=8080, listen='127.0.0.1')], outbounds=[], routing={'rules': []})),
            }.get(k, b'# stock\n'))
        self.policy: dict[str, Any] = dict(nft=None, rule=False, route=False)
        self.sock = [['tcp', '127.0.0.1', 8080]]
        self.units = {k: v.copy() for k, v in self.original_units.items()}
        self.native_command = h['command']
        h.update(unit=lambda n: self.units[n].copy(), no_jobs=lambda *_: None, vpn_empty=lambda **kw: True,
                 preflight=lambda machine: dict(machineId=machine, ppp=True, unitsLoaded=True, masked=False),
                 observe_ppp_preparation=lambda: dict(missing=[], persist=False, builtin=[], policy='fixture'),
                 require_network_observers=lambda: None,
                 sock_rows=lambda: [], ip=lambda *args: [], xray_users=lambda *args: self.sock,
                 nft_tables=lambda: [], network_projection=lambda *_, **kw: self.policy.copy(),
                 command=Mock(side_effect=self.command), sc=Mock(side_effect=self.systemctl),
                 validate_profiles=lambda *_: None)
        self.backup_path = h['manifest_path'](TOKEN)
        # Python executes in a private user/net namespace, no host paths/procs are opened for writes.

    def real(self, absolute):
        return self.root / absolute.lstrip('/')

    def command(self, *argv, **kwargs):
        if argv == ('/usr/bin/systemctl', '--no-pager', 'show-environment'):
            return b'LANG=C\n'
        if argv == ('/usr/sbin/ip', '-j', '-N', '-6', 'rule', 'show'):
            return b'[{"priority":0,"src":"all","table":"255"},{"priority":32766,"src":"all","table":"254"}]'
        if argv == ('/usr/sbin/ipsec', 'statusall'):
            return b'Connections:\n  celerity-l2tp: transport\nSecurity Associations (0 up, 0 connecting):\n  none\n'
        if argv == ('/usr/sbin/ip', 'xfrm', 'state', 'list', 'nokeys'):
            # A modeled idle daemon does not prove kernel emptiness. Read the
            # real XFRM table in the private netns, with the normal error checks.
            return self.native_command(*argv, **kwargs)
        if argv[:4] == ('/usr/sbin/ip', '-4', 'rule', 'del'):
            self.policy['rule'] = False
        elif argv[:4] == ('/usr/sbin/ip', '-4', 'route', 'del'):
            self.policy['route'] = False
        elif argv == ('/usr/sbin/nft', 'delete', 'table', 'inet', self.h['TABLE']):
            self.policy['nft'] = None
        else:
            self.fail(f'unexpected command: {argv}')

    def systemctl(self, op, *name, **kwargs):
        if op == 'daemon-reload':
            assert not self.real(self.h['NET']).exists()
            for n in (self.N, self.XL, self.IKE):
                self.units[n] = self.original_units[n].copy()
        elif op == 'restart' and name == (self.X,):
            self.units[self.X]['InvocationID'] = 'restored-main'
        elif op == 'stop' and name[0] in (self.XL, self.IKE, self.N):
            self.units[name[0]].update(ActiveState='inactive', SubState='dead', MainPID='0', InvocationID='')
        else:
            self.fail(f'unexpected manager operation {op, name}')

    def before(self):
        return self.h['observe'](MACHINE, NET)

    def candidate(self, before):
        h = self.h
        payload = {'main': h['encode']({'inbounds': [{'tag':'relay-l2tp-a','port':12345},
            {'tag':'rebuild-relay-ingress','listen':'127.0.0.1','port':23456}]}),
            'nft': NETWORK_FIXTURE['nft_source'](Path(__file__).resolve().parents[1] / 'rebuildRelayDirectHost.py', NET, TOKEN),
            'lns': (b'[global]\nport = 1701\n\n[lns default]\n'
                    b'ip range = 10.255.1.10-10.255.1.19\nlocal ip = 10.255.1.1\n'
                    b'require authentication = yes\npppoptfile = /etc/ppp/options.xl2tpd\nlength bit = yes\n'),
            # candidate() appends the managed block to the stock CHAP preimage.
            'chap': (b'# BEGIN CELERITY MANAGED L2TP USERS\n'
                     b'"alice" l2tpd "local-fixture-only" 10.255.1.10\n'
                     b'# END CELERITY MANAGED L2TP USERS\n'),
            **{k: b'# fixture\n' for k in ('ike','options','secrets')}}
        after = h['candidate']({**self.req,'files':{k: h['b64'](v) for k,v in payload.items()}}, before)
        self.assertIsNone(before['files']['swan'])
        self.assertEqual(h['operation_files'](after)['swan'], FILE)
        self.assertEqual(after['swan'], h['entry'](PAYLOAD, 0o644))
        self.assertEqual(after['starter'], before['files']['starter'])
        return after

    def stage(self, before, after):
        h = self.h
        backup: dict[str, Any] = dict(machineId=MACHINE, backupId=TOKEN, before=before, network=NET,
            after={k: {**r, 'data': h['digest'](h['raw'](r))} for k, r in after.items()}, phase='applying')
        h['mkdir'](h['VAULT'], 0o700)
        h['mkdir'](h['VAULT'] + '/' + TOKEN, 0o700)
        old = h['entry'](h['encode'](backup))
        h['write'](self.backup_path, None, old)
        return backup, old

    def create(self):
        h = self.h
        before = self.before()
        after = self.candidate(before)
        backup, old = self.stage(before, after)
        h['write_swan_profile'](self.backup_path, old, backup, after)
        path, persisted, stored = h['read_manifest'](TOKEN)
        self.assertEqual(path, self.backup_path)
        self.assertEqual(stored, backup)
        self.assertEqual(backup['swanGeneration'], h['remove_generation'](FILE))
        return before, after, backup, persisted

    def rollback(self, before, backup, persisted):
        h = self.h
        self.assertEqual(h['read_manifest'](TOKEN)[1:], (persisted, backup))
        request = {**self.req, 'action': 'rollback', 'baseline': h['digest'](h['encode'](before))}
        h['dispatch'](request)

    def stage_installed(self, verified=True, xl_listener=True):
        # Seed startup without invoking Install. Manager, kernel and Xray inputs are modeled.
        h = self.h
        before, after, backup, persisted = self.create()
        for key in ('NFT_DIR', 'DROP_DIR'):
            h['mkdir'](h[key], 0o755)
        for key, path in h['NAMES'].items():
            if after[key] != before['files'][key]:
                h['write'](path, before['files'][key], after[key])
        self.units[self.X].update(InvocationID='main-installed', MainPID='10')
        self.units[self.XL].update(InvocationID='1' * 32, ActiveState='active', SubState='running', MainPID='11',
            DropInPaths=h['DROP'], Requires=self.N + ' ' + self.IKE, After=self.N + ' ' + self.IKE)
        self.units[self.IKE].update(InvocationID='2' * 32, ActiveState='active', SubState='running', MainPID='12',
            RequiredBy=self.XL)
        # Project the generated unit as systemctl show would, without loading it.
        net = dict(line.split('=', 1) for line in self.real(h['NET']).read_text().splitlines()
                   if line.startswith(('Type=', 'Requires=', 'Wants=', 'After=', 'ExecStartPre=')))
        pre = net['ExecStartPre']
        self.units[self.N].update(InvocationID='3' * 32, ActiveState='active', SubState='exited', LoadState='loaded',
            FragmentPath=h['NET'], Type=net['Type'], UnitFileState='static', RequiredBy=self.XL,
            Requires=net.get('Requires', ''), Wants=net['Wants'], After=net['After'],
            ExecStartPre=f'{{ path={pre.split()[0]} ; argv[]={pre} ; ignore_errors=no ; }}',
            ExecStart=NETWORK_FIXTURE['systemctl_start'](h['raw'](after['net'])))
        self.real(h['XRAY']).parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        self.real(h['XRAY']).write_bytes(b'modeled binary identity\n')
        self.policy.update(nft={'marker': TOKEN}, rule=True, route=True)
        h.update(validate_profiles=lambda profiles: self.assertEqual(profiles, {'main': before['files']['main']}),
                 xray_argv=lambda info: info['MainPID'], in_cgroup=lambda p, info: p == info['MainPID'],
                 removal_profiles=lambda *_: ({'main': before['files']['main']}, 23456, self.X))

        def rows():
            pid = self.units[self.X]['MainPID']
            out = [(*self.sock[0], [pid])]
            if h['read'](h['MAIN']) == after['main']:
                out += [(p, a, port, [pid]) for p in ('tcp', 'udp')
                        for a, port in [('0.0.0.0', 12345), ('127.0.0.1', 23456)]]
            for name, ports in ((self.XL, (1701,)), (self.IKE, (500, 4500))):
                if self.units[name]['ActiveState'] == 'active' and (name != self.XL or xl_listener):
                    out += [('udp', '0.0.0.0', port, [self.units[name]['MainPID']]) for port in ports]
            return out

        h['sock_rows'] = rows
        backup['swanStart'] = h['swan_started_units'](before)
        if verified:
            backup.update(phase='installed', runtime={'nft': self.policy['nft'],
                'invocations': [self.units[n]['InvocationID'] for n in (self.X, self.XL, self.IKE, self.N)],
                'files': h['file_generations'](after), 'bootEnrollment': None})
            self.assertEqual(backup['runtime']['files']['swan'], backup['swanGeneration'])
        h['write'](self.backup_path, persisted, h['entry'](h['encode'](backup)))
        return before, backup, h['read_manifest'](TOKEN)[1]

    def replace_same_profile(self):
        old_inode = self.path.stat().st_ino
        other = self.path.with_name('replacement')
        other.write_bytes(PAYLOAD)
        other.chmod(0o644)
        other.replace(self.path)
        self.assertNotEqual(self.path.stat().st_ino, old_inode)

    def refusal_no_write(self, action, expected):
        h = self.h
        write, sc = h['write'], h['sc']
        h['write'] = Mock(side_effect=AssertionError('unexpected write'))
        sc.reset_mock()
        try:
            with self.assertRaisesRegex(h['Refusal'], '^' + expected + '$'):
                action()
            sc.assert_not_called()
            h['write'].assert_not_called()
        finally:
            h['write'] = write

    def test_managed_file_readback_and_normal_applying_rollback(self):
        h = self.h
        before, after, backup, old = self.create()
        self.assertEqual(h['load_after'](backup)['swan'], after['swan'])
        self.assertEqual(self.path.read_bytes(), PAYLOAD)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o644)
        self.rollback(before, backup, old)
        self.assertFalse(self.path.exists())
        self.assertEqual(h['read_manifest'](TOKEN)[2]['phase'], 'rolled-back')
        self.assertEqual(h['swan_inputs'](False, 'DRIFT'), before['swanInputs'])
        self.assertTrue(self.path.parent.is_dir())
        self.assertFalse(any(call.args[:2] in (('stop', self.IKE), ('restart', self.IKE), ('start', self.IKE))
                             for call in h['sc'].call_args_list))

    def test_foreign_identical_target_refuses_prepare_without_adoption(self):
        self.path.write_bytes(PAYLOAD)
        self.path.chmod(0o644)
        st = self.path.stat()
        self.refusal_no_write(lambda: self.h['dispatch'](dict(self.req, action='prepare')), 'PREREQUISITE')
        self.assertEqual(self.path.stat(), st)
        self.assertFalse(self.real(self.h['VAULT']).exists())

    def test_manager_settings_override_refuses_prepare(self):
        h = self.h
        h['command'].side_effect = lambda *argv, **kw: (
            b'STRONGSWAN_CONF=/fixture/alternate.conf\n' if argv[-1] == 'show-environment' else self.command(*argv, **kw))
        self.refusal_no_write(lambda: h['dispatch'](dict(self.req, action='prepare')), 'PREREQUISITE')
        self.assertFalse(self.path.exists())

    def test_ike_conflicts_with_foreign_unit_refuses_prepare(self):
        self.units[self.IKE]['Conflicts'] += ' foreign.service'
        self.refusal_no_write(lambda: self.h['dispatch'](dict(self.req, action='prepare')), 'ROLLBACK_DRIFT')
        self.assertFalse(self.real(self.h['VAULT']).exists())

    def test_foreign_include_refuses_prepare(self):
        foreign = self.path.with_name('operator.conf')
        foreign.write_bytes(b'charon {\n routing_table = 220\n}\n')
        self.refusal_no_write(self.before, 'PREREQUISITE')
        self.assertFalse(self.path.exists())
        self.assertTrue(foreign.exists())

    def test_existing_profile_at_link_boundary_is_not_replaced_or_claimed(self):
        h = self.h
        before = self.before()
        after = self.candidate(before)
        backup, old = self.stage(before, after)
        fixture_os = h['os']
        foreign = b'# other writer arrived at link\n'

        def link(src, dst, **kwargs):
            self.assertEqual(dst, self.path.name)
            self.path.write_bytes(foreign)
            return os.link(src, dst, **kwargs)

        fixture_os.link = link
        with self.assertRaises(FileExistsError):
            h['write_swan_profile'](self.backup_path, old, backup, after)
        self.assertEqual(self.path.read_bytes(), foreign)
        self.assertNotIn('swanGeneration', h['read_manifest'](TOKEN)[2])
        self.assertFalse(any(p.name.startswith('.direct-') for p in self.path.parent.iterdir()))

    def test_stock_top_level_config_drift_refuses_prepare(self):
        global_config = self.real('/etc/strongswan.conf')
        altered = global_config.read_bytes() + b'\n# local drift\n'
        global_config.write_bytes(altered)
        self.refusal_no_write(self.before, 'PREREQUISITE')
        self.assertEqual(global_config.read_bytes(), altered)

    def test_debian_conffile_closure_is_fingerprinted(self):
        # Run with either extracted Debian 6.0.1-6+deb13u7 conffile tree. The full
        # fixture adds libcharon-extra-plugins, charon-systemd and strongswan-swanctl.
        n = len(list((self.path.parent / 'charon').iterdir()))
        expected = {
            21: 'ddc103e3bab4b312ab390428dd64ec6606ea6793d715d536d2fa2c0025e5d77e',
            44: '96e6ee8439e324f56cb9e1cc3eb10871c3ef32d0b653b3aa407ed5ce3af7866b',
        }
        self.assertIn(n, expected)
        before, _, backup, saved = self.create()
        h = self.h
        self.assertEqual(before['swanInputs'], expected[n])
        self.assertEqual(h['swan_inputs'](True, 'ROLLBACK_DRIFT'), expected[n])
        if n == 44:
            # One missing conffile is not a stock package set. Removing both
            # strongswan-swanctl conffiles yields a valid but different set:
            # fresh preflight could accept it; this transaction must refuse it.
            top = self.path.with_name('swanctl.conf')
            vici = top.parent / 'charon' / 'vici.conf'
            self.assertTrue(self.path.with_name('charon-systemd.conf').is_file())
            self.assertTrue(self.path.with_name('tnc.conf').is_file())
            files = {p: p.read_bytes() for p in (top, vici)}
            top.write_bytes(files[top] + b'\ninclude /etc/alternate.conf\n')
            self.refusal_no_write(lambda: h['load_after'](backup), 'ROLLBACK_DRIFT')
            top.unlink()
            self.refusal_no_write(lambda: h['swan_inputs'](True, 'ROLLBACK_DRIFT'), 'ROLLBACK_DRIFT')
            vici.unlink()
            self.assertNotEqual(h['swan_inputs'](True, 'ROLLBACK_DRIFT'), expected[n])
            self.refusal_no_write(lambda: h['load_after'](backup), 'ROLLBACK_DRIFT')
            self.assertEqual(h['read_manifest'](TOKEN)[1], saved)
            self.assertEqual(self.path.read_bytes(), PAYLOAD)
            for path, data in files.items():
                path.write_bytes(data)
        self.rollback(before, backup, saved)
        self.assertEqual(h['swan_inputs'](False, 'ROLLBACK_DRIFT'), expected[n])

    def test_foreign_settings_refuse_before_write(self):
        for leaf, suffix in (
            ('strongswan.conf', b'\ninclude /etc/alternate/*.conf\n'),
            ('strongswan.d/charon.conf', b'\ncharon { routing_table_prio = 220 }\n'),
            ('strongswan.d/charon/openssl.conf', b'\ninclude ../alternate.conf\n'),
            ('strongswan.d/charon/kernel-netlink.conf', b'\ncharon { install_routes = yes }\n'),
            ('strongswan.d/local.conf', b'# unowned even if inert\n'),
            ('strongswan.d/.hidden.conf', b'charon { install_virtual_ip = no }\n'),
        ):
            with self.subTest(leaf=leaf):
                path = self.real('/etc/' + leaf)
                original = path.read_bytes() if path.exists() else None
                path.write_bytes((original or b'') + suffix)
                try:
                    self.refusal_no_write(self.before, 'PREREQUISITE')
                    self.assertFalse(self.path.exists())
                finally:
                    if original is not None:
                        path.write_bytes(original)
                    else:
                        path.unlink()

    def test_stock_leaf_must_be_single_link_regular_file_with_stock_mode(self):
        leaf = self.path.parent / 'charon' / 'openssl.conf'
        data = leaf.read_bytes()
        leaf.chmod(0o600)
        self.refusal_no_write(self.before, 'PREREQUISITE')
        leaf.chmod(0o644)
        outside = self.real('/etc/outside.conf')
        leaf.rename(outside)
        leaf.symlink_to(outside)
        self.refusal_no_write(self.before, 'PREREQUISITE')
        leaf.unlink()
        os.link(outside, leaf)
        self.refusal_no_write(self.before, 'PREREQUISITE')
        self.assertEqual(outside.read_bytes(), data)

    def test_unrecorded_file_after_creation_gap_not_owned(self):
        h = self.h
        before = self.before()
        after = self.candidate(before)
        backup, old = self.stage(before, after)
        h['write'](FILE, None, after['swan'])
        self.refusal_no_write(lambda: self.rollback(before, backup, old), 'ROLLBACK_DRIFT')
        self.assertEqual(self.path.read_bytes(), PAYLOAD)
        self.assertEqual(h['read_manifest'](TOKEN)[2], backup)

    def test_applying_rollback_refuses_identical_inode_replacement(self):
        before, _, backup, old = self.create()
        self.replace_same_profile()
        self.refusal_no_write(lambda: self.rollback(before, backup, old), 'ROLLBACK_DRIFT')
        self.assertEqual(self.path.read_bytes(), PAYLOAD)

    def test_applying_rollback_refuses_existing_unowned_ike(self):
        before, _, backup, old = self.create()
        self.units[self.IKE].update(ActiveState='active', SubState='running', MainPID='42', InvocationID='foreign')
        self.refusal_no_write(lambda: self.rollback(before, backup, old), 'ROLLBACK_DRIFT')
        self.assertEqual(self.path.read_bytes(), PAYLOAD)

    def test_applying_rollback_refuses_existing_unowned_xl_and_net(self):
        before, _, backup, old = self.create()
        for name in (self.XL, self.N):
            with self.subTest(unit=name):
                self.units[name].update(ActiveState='active', SubState='running', MainPID='42', InvocationID='foreign')
                self.refusal_no_write(lambda: self.rollback(before, backup, old), 'ROLLBACK_DRIFT')
                self.units[name] = self.original_units[name].copy()

    def test_ipv6_rule_conflicts_before_prepare_write(self):
        self.h['command'].side_effect = lambda *argv, **kw: b'[{"priority":220,"src":"all","table":"220"}]'
        self.refusal_no_write(lambda: self.h['dispatch'](dict(self.req, action='prepare')), 'RULE_220_CONFLICT')
        self.assertFalse(self.path.exists())

    def test_already_running_idle_ike_is_not_restarted_or_adopted(self):
        self.units[self.IKE].update(ActiveState='active', SubState='running', MainPID='42', InvocationID='foreign')
        self.refusal_no_write(self.before, 'IKE_ACTIVE_UNMANAGED')
        self.assertFalse(self.path.exists())

    def test_applying_rollback_before_profile_creation_restores_absence(self):
        before = self.before()
        backup, old = self.stage(before, self.candidate(before))
        self.rollback(before, backup, old)
        self.assertFalse(self.path.exists())
        self.assertEqual(self.h['read_manifest'](TOKEN)[2]['phase'], 'rolled-back')

    def test_installed_rollback_restores_profile_and_keeps_baseline_ike_stopped(self):
        before, backup, old = self.stage_installed()
        h = self.h
        h['nft_projection'] = lambda token: self.policy['nft']
        self.rollback(before, backup, old)
        self.assertFalse(self.path.exists())
        self.assertEqual(h['read_manifest'](TOKEN)[2]['phase'], 'rolled-back')
        self.assertEqual([c.args for c in h['sc'].call_args_list if self.IKE in c.args], [('stop', self.IKE)])

    def test_applying_rollback_with_exact_start_receipt_but_no_runtime_receipt(self):
        before, backup, old = self.stage_installed(verified=False)
        h = self.h
        h['nft_projection'] = lambda token: self.policy['nft']
        self.assertNotIn('runtime', backup)
        self.rollback(before, backup, old)
        self.assertFalse(self.path.exists())
        self.assertEqual(h['read_manifest'](TOKEN)[2]['phase'], 'rolled-back')
        self.assertEqual([c.args[1] for c in h['sc'].call_args_list if c.args[0] == 'stop'], [self.XL, self.IKE, self.N])

    def test_applying_rollback_returns_preimage_without_xl_listener(self):
        before, backup, old = self.stage_installed(verified=False, xl_listener=False)
        h = self.h
        h['nft_projection'] = lambda token: self.policy['nft']
        self.assertEqual(self.units[self.XL]['ActiveState'], 'active')
        self.assertNotIn(1701, {port for _, _, port, _ in h['sock_rows']()})
        self.assertIn(4500, {port for _, _, port, _ in h['sock_rows']()})
        self.rollback(before, backup, old)
        self.assertEqual(h['read_manifest'](TOKEN)[2]['phase'], 'rolled-back')
        paths = h['operation_files'](backup['after'])
        self.assertEqual({key: h['read'](p) for key, p in paths.items()}, before['files'])
        self.assertEqual(h['swan_inputs'](False, 'DRIFT'), before['swanInputs'])
        self.assertEqual(self.policy, {'nft': None, 'rule': False, 'route': False})
        self.assertEqual([c.args for c in h['sc'].call_args_list if c.args[0] == 'stop'],
                         [('stop', n) for n in (self.XL, self.IKE, self.N)])

    def assert_applying_refusal_unchanged(self, before, backup, old, code):
        h = self.h
        files = {p: h['read'](p) for p in h['operation_files'](backup['after']).values()}
        policy = self.policy.copy()
        units = {name: info.copy() for name, info in self.units.items()}
        h['command'].reset_mock()
        self.refusal_no_write(lambda: self.rollback(before, backup, old), code)
        self.assertEqual(h['read_manifest'](TOKEN)[1:], (old, backup))
        self.assertEqual({p: h['read'](p) for p in files}, files)
        self.assertEqual(self.policy, policy)
        self.assertEqual(self.units, units)
        self.assertFalse(any(any(arg in ('del', 'delete') for arg in c.args) for c in h['command'].call_args_list))

    def test_applying_rollback_refuses_foreign_socket_without_xl_listener(self):
        before, backup, old = self.stage_installed(verified=False, xl_listener=False)
        h = self.h
        own_rows = h['sock_rows']
        for row in (('udp', '0.0.0.0', 1701, ['42']), ('udp', '0.0.0.0', 1701, []),
                    ('tcp', '0.0.0.0', 1701, ['11']), ('udp', '0.0.0.0', 500, ['42'])):
            with self.subTest(row=row):
                h['sock_rows'] = lambda: own_rows() + [row]
                self.assert_applying_refusal_unchanged(before, backup, old, 'RUNTIME_UNPROVED')

    def test_applying_rollback_refuses_ike_connection_or_sa_without_xl_listener(self):
        before, backup, old = self.stage_installed(verified=False, xl_listener=False)
        h = self.h
        for status in (b'Connections:\n  foreign: tunnel\nSecurity Associations (0 up, 0 connecting):\n  none\n',
                       b'Connections:\n  celerity-l2tp: transport\nSecurity Associations (1 up, 0 connecting):\n',
                       b'Connections:\n  celerity-l2tp: transport\nSecurity Associations (0 up, 1 connecting):\n'):
            with self.subTest(status=status):
                h['command'].side_effect = lambda *argv, **kw: (
                    status if argv == ('/usr/sbin/ipsec', 'statusall') else self.command(*argv, **kw))
                self.assert_applying_refusal_unchanged(before, backup, old, 'ROLLBACK_DRIFT')

    def test_applying_rollback_refuses_ppp_without_xl_listener(self):
        before, backup, old = self.stage_installed(verified=False, xl_listener=False)
        self.h['vpn_empty'] = lambda **kw: False
        self.assert_applying_refusal_unchanged(before, backup, old, 'ROLLBACK_DRIFT')

    def test_applying_rollback_refuses_replaced_start_invocation(self):
        before, backup, old = self.stage_installed(verified=False, xl_listener=False)
        self.units[self.XL]['InvocationID'] = 'f' * 32
        self.assert_applying_refusal_unchanged(before, backup, old, 'ROLLBACK_DRIFT')

    def test_applying_rollback_refuses_active_xl_without_start_receipt(self):
        before, backup, old = self.stage_installed(verified=False, xl_listener=False)
        h = self.h
        backup.pop('swanStart')
        no_receipt = h['entry'](h['encode'](backup))
        h['write'](self.backup_path, old, no_receipt)
        self.assert_applying_refusal_unchanged(before, backup, no_receipt, 'ROLLBACK_DRIFT')

    def test_applying_rollback_refuses_foreign_rule_without_xl_listener(self):
        before, backup, old = self.stage_installed(verified=False, xl_listener=False)
        self.h['command'].side_effect = lambda *argv, **kw: (
            b'[{"priority":220,"src":"all","table":"220"}]'
            if argv == ('/usr/sbin/ip', '-j', '-N', '-6', 'rule', 'show') else self.command(*argv, **kw))
        self.assert_applying_refusal_unchanged(before, backup, old, 'NETWORK_CONFLICT')

    def test_applying_rollback_rechecks_xl_generation_after_final_socket_check(self):
        before, backup, old = self.stage_installed(verified=False, xl_listener=False)
        h = self.h
        samples = 0

        def command(*argv, **kw):
            nonlocal samples
            if argv == ('/usr/sbin/ipsec', 'statusall'):
                samples += 1
                if samples == 2:
                    self.units[self.XL].update(InvocationID='f' * 32, MainPID='42')
            return self.command(*argv, **kw)

        h['command'].side_effect = command
        files = {p: h['read'](p) for p in h['operation_files'](backup['after']).values()}
        policy = self.policy.copy()
        with self.assertRaisesRegex(h['Refusal'], '^ROLLBACK_DRIFT$'):
            self.rollback(before, backup, old)
        self.assertEqual(samples, 2)
        h['sc'].assert_not_called()
        self.assertEqual(h['read_manifest'](TOKEN)[2]['phase'], 'rolling-back')
        self.assertEqual({p: h['read'](p) for p in files}, files)
        self.assertEqual(self.policy, policy)

    def test_applying_rollback_refuses_changed_pid_under_same_invocation_after_intent(self):
        before, backup, old = self.stage_installed(verified=False, xl_listener=False)
        h = self.h
        write = h['write']
        files = {p: h['read'](p) for p in h['operation_files'](backup['after']).values()}
        policy = self.policy.copy()

        def changed_pid(path, previous, after):
            # Inject between the durable intent and the first fresh unit observation.
            write(path, previous, after)
            if path == self.backup_path and json.loads(h['raw'](after))['phase'] == 'rolling-back':
                self.units[self.XL]['MainPID'] = '42'  # InvocationID deliberately unchanged.

        h['write'] = changed_pid
        h['nft_projection'] = lambda token: self.policy['nft']
        with self.assertRaisesRegex(h['Refusal'], '^ROLLBACK_DRIFT$'):
            self.rollback(before, backup, old)
        h['sc'].assert_not_called()
        self.assertEqual(self.units[self.XL]['InvocationID'], backup['swanStart'][0])
        self.assertEqual(self.units[self.XL]['MainPID'], '42')
        self.assertEqual(h['read_manifest'](TOKEN)[2]['phase'], 'rolling-back')
        self.assertEqual({p: h['read'](p) for p in files}, files)
        self.assertEqual(self.policy, policy)

    def test_installed_rollback_and_remove_still_require_xl_listener(self):
        before, backup, old = self.stage_installed(xl_listener=False)
        self.assert_applying_refusal_unchanged(before, backup, old, 'RUNTIME_UNPROVED')
        self.refusal_no_write(lambda: self.h['dispatch']({**self.req, 'action': 'prepare-remove'}), 'RUNTIME_UNPROVED')

    def test_installed_rollback_refuses_foreign_connection_in_same_ike_generation(self):
        before, backup, old = self.stage_installed()
        h = self.h
        h['command'].side_effect = lambda *argv, **kw: (
            b'Connections:\n  foreign: tunnel\nSecurity Associations (0 up, 0 connecting):\n  none\n'
            if argv == ('/usr/sbin/ipsec', 'statusall') else self.command(*argv, **kw))
        self.refusal_no_write(lambda: self.rollback(before, backup, old), 'ROLLBACK_DRIFT')
        self.assertEqual(self.path.read_bytes(), PAYLOAD)

    def test_remove_restores_preimage_and_keeps_receipt(self):
        before, _, saved = self.stage_installed()
        h = self.h
        baseline = h['dispatch']({**self.req, 'action': 'prepare-remove'})['baseline']
        self.assertTrue(h['dispatch']({**self.req, 'action': 'remove', 'baseline': baseline})['removed'])
        self.assertFalse(self.path.exists())
        self.assertEqual(h['swan_inputs'](False, 'DRIFT'), before['swanInputs'])
        self.assertEqual(h['read_manifest'](TOKEN)[1], saved)
        self.assertEqual([c.args for c in h['sc'].call_args_list if self.IKE in c.args], [('stop', self.IKE)])
        self.assertEqual(h['read'](h['NAMES']['starter']), before['files']['starter'])

    def test_remove_refuses_same_bytes_other_generation_before_intent(self):
        self.stage_installed()
        h = self.h
        baseline = h['dispatch']({**self.req, 'action': 'prepare-remove'})['baseline']
        self.replace_same_profile()
        st = self.path.stat()
        self.refusal_no_write(lambda: h['dispatch']({**self.req, 'action': 'remove', 'baseline': baseline}), 'ROLLBACK_DRIFT')
        self.assertEqual(self.path.stat(), st)
        self.assertFalse(self.real(self.backup_path).with_name('remove-attempt.json').exists())

    def test_remove_refuses_stock_plugin_drift_without_touching_profile(self):
        self.stage_installed()
        h = self.h
        baseline = h['dispatch']({**self.req, 'action': 'prepare-remove'})['baseline']
        plugin = self.path.parent / 'charon' / 'kernel-netlink.conf'
        altered = plugin.read_bytes() + b'\n# local drift\n'
        plugin.write_bytes(altered)
        self.refusal_no_write(lambda: h['dispatch']({**self.req, 'action': 'remove', 'baseline': baseline}), 'ROLLBACK_DRIFT')
        self.assertEqual(plugin.read_bytes(), altered)
        self.assertEqual(self.path.read_bytes(), PAYLOAD)

    def test_rpdb_live_foreign_rules_refused_without_writes(self):
        h = self.h
        ip = '/usr/sbin/ip'
        def rules(family):
            return subprocess.check_output([ip, '-j', '-N', family, 'rule', 'show'], timeout=3)
        h['ip'] = lambda *argv: json.loads(rules('-4')) if argv == ('rule', 'show') else []
        real_command = self.command
        h['command'].side_effect = lambda *argv, **kw: (rules('-6') if argv == (ip, '-j', '-N', '-6', 'rule', 'show')
                                                       else real_command(*argv, **kw))
        self.before()
        for family in ('-6', '-4'):
            subprocess.run([ip, family, 'rule', 'add', 'priority', '220', 'table', '220'], check=True, timeout=3)
            snapshot = [rules(f) for f in ('-4', '-6')]
            self.assertIn(dict(priority=220, src='all', table='220'), json.loads(rules(family)))
            for table in (177, 220):
                request = {**self.req, 'action': 'prepare', 'network': {**NET, 'routeTable': table}}
                self.refusal_no_write(lambda: h['dispatch'](request), 'RULE_220_CONFLICT')
                self.assertEqual([rules(f) for f in ('-4', '-6')], snapshot)
                self.assertFalse(self.real(h['VAULT']).exists())
            # Only the fixture's own rule in the disposable netns.
            subprocess.run([ip, family, 'rule', 'del', 'priority', '220', 'table', '220'], check=True, timeout=3)


if __name__ == '__main__':
    os.umask(0o022)
    unittest.main(argv=['file-regressions', *a.test], verbosity=2)
