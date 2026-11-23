"""Execute the rendered net-unit with a command-denying kernel/manager model."""

import hashlib
import io
import json
import os

import runpy
import shlex
import subprocess
import sys
import tempfile
import types
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch


HOST = Path(__file__).resolve().parents[1] / 'rebuildRelayDirectHost.py'
D = dict(clientCidr='10.255.1.0/24', tproxyPort=12345, fwmark=77, routeTable=177)
TOKEN = 'd' * 32
FIXTURE = runpy.run_path(str(Path(__file__).with_name('helpers') / 'rebuildRelayNetworkFixture.py'))


class NetworkUnit(unittest.TestCase):
    def setUp(self):
        self.host = runpy.run_path(str(HOST))['network_unit'].__globals__
        h = self.host
        # Render the producer's real fixed template with synthetic inputs.
        self.nft = FIXTURE['nft_source'](HOST, D, TOKEN)
        self.nft_sha = hashlib.sha256(self.nft).hexdigest()
        foreign = dict(family='ip', name='foreign', handle=5)
        self.foreign = {'table': foreign}
        # Native nft -j -s -a output for this exact template in a private netns.
        self.nft_policy = FIXTURE['nft_rows'](D, TOKEN)[1:]
        self.rule = dict(priority=h['PRIORITY'], src='10.255.1.0', srclen=24, fwmark='0x4d', table='177')
        self.route = dict(type='local', dst='default', dev='lo', scope='host', table='177', flags=[])
        self.stock = [dict(priority=i, src='all', table=t) for i, t in ((0, 'local'), (32766, 'main'), (32767, 'default'))]
        self.tables, self.rules, self.routes = [], deepcopy(self.stock), []
        self.effects = []
        self.fail_rule = False
        self.fail_observer = False
        # Keep all generated files and native calls private to the fixture.
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        h['NETWORK_RUN'] = str(self.root)
        self.state = self.root / f'celerity-rebuild-l2tp-network-{TOKEN}'
        self.ingress = self.root / 'ingress.nft'
        self.ingress.write_bytes(self.nft)
        self.ingress.chmod(0o644)

    def render(self, sidecar=False):
        return self.host['network_unit'](D, sidecar, backup_id=TOKEN, nft_sha256=self.nft_sha).decode()

    def command(self, argv, **kw):
        argv = tuple(argv)
        h = self.host
        name = h['TABLE']
        meta = [{'metainfo': {'json_schema_version': 1}}]
        ret = 0
        stdout = b''
        if argv == ('/usr/bin/systemctl', 'is-active', '--quiet', h['X']):
            pass
        elif argv == ('/usr/sbin/nft', '-j', 'list', 'tables'):
            stdout = json.dumps({'nftables': meta + [self.foreign] + self.tables[:1]}).encode()
            ret = int(self.fail_observer)
        elif argv in (('/usr/sbin/nft', '-j', '-s', '-a', 'list', 'table', 'inet', name),
                      ('/usr/sbin/nft', '-j', '-s', 'list', 'table', 'inet', name)):
            assert self.tables
            stdout = json.dumps({'nftables': meta + self.tables}).encode()
        elif argv == ('/usr/sbin/ip', '-j', '-N', '-4', 'rule', 'show'):
            stdout = json.dumps(self.rules).encode()
        elif argv == ('/usr/sbin/ip', '-j', '-N', '-4', 'route', 'show', 'table', 'all'):
            stdout = json.dumps(self.routes).encode()
        elif argv in (('/usr/sbin/nft', '-f', '-'), ('/usr/sbin/nft', '-f', h['NFT_FILE'])):
            data = kw.get('input') if argv[-1] == '-' else self.ingress.read_bytes()
            assert data == self.nft
            self.effects.append('create nft')
            ret = int(bool(self.tables))
            if not ret:
                self.tables = deepcopy(self.nft_policy)
        elif argv == ('/usr/sbin/ip', '-4', 'route', 'add', 'local', '0.0.0.0/0', 'dev', 'lo', 'table', '177'):
            self.effects.append('add route')
            ret = int(bool(self.routes))
            if not ret:
                self.routes.append(deepcopy(self.route))
        elif argv == ('/usr/sbin/ip', '-4', 'rule', 'add', 'priority', str(h['PRIORITY']), 'from', D['clientCidr'],
                      'fwmark', '77', 'table', '177'):
            self.effects.append('add rule')
            ret = int(self.fail_rule)
            if not ret:
                self.rules.append(deepcopy(self.rule))
        elif argv[:4] == ('/usr/sbin/ip', '-4', 'rule', 'del'):
            assert argv[4:] == ('priority', str(h['PRIORITY']), 'from', D['clientCidr'], 'fwmark', '77', 'table', '177')
            self.effects.append('delete rule')
            self.rules.remove(self.rule)
        elif argv[:4] == ('/usr/sbin/ip', '-4', 'route', 'del'):
            assert argv[4:] == ('local', '0.0.0.0/0', 'dev', 'lo', 'table', '177')
            self.effects.append('delete route')
            self.routes.remove(self.route)
        elif argv == ('/usr/sbin/nft', 'delete', 'table', 'inet', name):
            assert self.tables
            self.effects.append('delete nft')
            self.tables.clear()
        else:
            raise AssertionError(f'unmodeled native command: {argv}')
        return subprocess.CompletedProcess(argv, ret, stdout, b'')

    def start(self, unit):
        open_fd, fstat = os.open, os.fstat

        def open_fixture(path, flags, *args, **kwargs):
            if path == self.host['NFT_FILE']:
                path = self.ingress
            else:
                raise AssertionError(f'unmodeled open: {path}')
            return open_fd(path, flags, *args, **kwargs)

        def fstat_fixture(fd):
            actual = fstat(fd)
            return types.SimpleNamespace(st_uid=0, st_gid=0, st_mode=actual.st_mode, st_nlink=actual.st_nlink)

        for line in unit.splitlines():
            if line.startswith(('ExecStart=', 'ExecStartPre=')):
                argv = shlex.split(line.split('=', 1)[1])
                if argv[:5] != ['/usr/bin/python3', '-I', '-B', '-S', '-c']:
                    code = self.command(argv).returncode
                    if code:
                        return code
                    continue
                with (patch.object(subprocess, 'run', side_effect=self.command),
                      patch.object(os, 'open', side_effect=open_fixture),
                      patch.object(os, 'fstat', side_effect=fstat_fixture),
                      patch.object(sys, 'argv', ['-c', *argv[6:]]),
                      patch.object(sys, 'stderr', io.StringIO())):
                    try:
                        exec(compile(argv[5], '<rendered ExecStart>', 'exec'), {'__name__': '__main__'})
                    except SystemExit as e:
                        return e.code
        return 0

    def snapshot(self):
        return deepcopy((self.foreign, self.tables, self.rules, self.routes))

    def host_command(self, *argv, **kwargs):
        result = self.command(argv, **kwargs)
        assert result.returncode == 0
        return result.stdout

    def projection(self):
        with patch.dict(self.host, command=self.host_command):
            return self.host['network_projection'](D, TOKEN, pinned=True)

    def test_candidate_joins_pinned_startup(self):
        h = self.host
        main = h['entry'](h['encode'](dict(inbounds=[
            dict(tag='relay-l2tp-synthetic', port=D['tproxyPort']),
            dict(tag='rebuild-relay-ingress', listen='127.0.0.1', port=12400)])))
        before = dict(sockets=None, files=dict(main=main, starter=h['entry'](b''),
                                               chap=h['entry'](b''), secrets=h['entry'](b'')))
        files = {k: h['b64'](b'fixture') for k in ('ike', 'lns', 'options', 'secrets', 'chap')}
        files.update(main=main['data'], nft=h['b64'](self.nft))
        result = h['candidate'](dict(network=D, backupId=TOKEN, files=files), before)
        unit = h['raw'](result['net']).decode()
        self.assertEqual(unit, self.render())
        self.assertEqual(self.start(unit), 0)
        self.assertEqual(self.start(unit), 0)
        self.assertEqual(self.effects, ['create nft', 'add route', 'add rule'])
        self.state.symlink_to('nonexistent')
        with self.assertRaisesRegex(h['Refusal'], '^NETWORK_CONFLICT$'):
            h['candidate'](dict(network=D, backupId=TOKEN, files=files), before)

    def test_old_runtime_witness_is_not_read_or_adopted(self):
        unit = self.render()
        self.state.symlink_to('nonexistent')
        original = self.snapshot()
        self.assertNotEqual(self.start(unit), 0)
        with self.assertRaisesRegex(self.host['Refusal'], '^ROLLBACK_DRIFT$'):
            self.projection()
        self.assertEqual(self.snapshot(), original)
        self.assertEqual(os.readlink(self.state), 'nonexistent')

    def test_loaded_execstart_keeps_literal_quotes_in_the_encoded_command(self):
        h, unit = self.host, self.render().encode()
        record = h['entry'](unit, 0o644)
        for presentation in ('native', 'quoted'):
            with self.subTest(presentation=presentation):
                display = FIXTURE['systemctl_start'](unit, presentation)
                self.assertTrue(h['network_loaded_starts']({'ExecStart': display}, record))
                for other in (display.replace(' -I ', ' -E '), display.replace('ignore_errors=no', 'ignore_errors=yes'),
                              display.replace('bytes.fromhex', 'bytes.from_hex'), display + ' ' + display):
                    self.assertFalse(h['network_loaded_starts']({'ExecStart': other}, record))

    def test_iproute_numeric_and_inet_variants(self):
        self.stock = [{**r, 'table': str(t)} for r, t in zip(self.stock, (255, 254, 253))]
        self.rules = deepcopy(self.stock)
        self.route.update(type='2', scope='254')
        self.routes = [dict(dst='192.0.2.0/24', dev='lo', scope='253', flags=[])]
        unit = self.render()
        self.tables, self.rules = deepcopy(self.nft_policy), [*self.stock, deepcopy(self.rule)]
        self.routes.append(deepcopy(self.route))
        self.assertEqual(self.start(unit), 0)
        for row in [*self.rules, *self.routes]:
            row['family'] = 'inet'
        self.assertEqual(self.start(unit), 0)
        self.assertEqual(self.effects, [])

    def test_owned_policy_restart_is_read_only(self):
        unit = self.render(sidecar=True)
        self.assertEqual(self.start(unit), 0)
        self.assertEqual(self.effects, ['create nft', 'add route', 'add rule'])
        original = self.snapshot()
        self.assertNotRegex(unit, r'(?m)^ExecStop(?:Post)?=')
        self.assertEqual(self.start(unit), 0, 'second start tried to create resident policy')
        self.assertEqual(self.snapshot(), original)
        self.assertEqual(self.effects, ['create nft', 'add route', 'add rule'])

    def test_fresh_boot_recreates_without_a_witness(self):
        unit = self.render()
        self.assertEqual(self.start(unit), 0)
        original = self.projection()
        self.assertFalse(self.state.exists())
        self.tables, self.rules, self.routes = [], deepcopy(self.stock), []
        self.nft_policy[0]['table']['handle'] += 50
        self.assertEqual(self.start(unit), 0)
        self.assertEqual(self.start(unit), 0)
        self.assertEqual(self.effects, ['create nft', 'add route', 'add rule'] * 2)
        self.assertEqual(self.projection(), original)
        self.assertFalse(self.state.exists())

    def test_foreign_or_partial_policy_is_rejected_without_kernel_writes(self):
        for case in ('foreign marker', 'same marker', 'same name ip6', 'occupied priority', 'occupied table', 'aliased table', 'observer failure'):
            with self.subTest(case=case):
                self.tables, self.rules, self.routes = [], deepcopy(self.stock), []
                if case in ('foreign marker', 'same marker', 'same name ip6'):
                    self.tables = deepcopy(self.nft_policy)
                    if case == 'foreign marker':
                        self.tables[0]['table']['comment'] = 'foreign'
                    elif case == 'same name ip6':
                        self.tables[0]['table']['family'] = 'ip6'
                    else:
                        self.rules.append(deepcopy(self.rule))
                        self.routes.append(deepcopy(self.route))
                        self.tables.pop()  # Comment and RPDB alone are not ownership.
                if case == 'occupied priority':
                    self.rules.append({**self.rule, 'fwmark': '0x7a'})
                if case == 'occupied table':
                    self.routes.append({**self.route, 'dev': 'foreign'})
                if case == 'aliased table':
                    self.routes.append({**self.route, 'table': 'operator-table'})
                self.fail_observer = case == 'observer failure'
                original = self.snapshot()
                self.assertNotEqual(self.start(self.render()), 0)
                self.assertEqual(self.effects, [])
                self.assertEqual(self.snapshot(), original)

    def test_resident_policy_drift_is_rejected_without_writes(self):
        unit = self.render()
        self.assertEqual(self.start(unit), 0)
        initial = self.snapshot()
        for case in ('rule missing', 'route missing', 'nft missing', 'extra nft rule', 'reordered input rules',
                     'changed forward action', 'rule mask', 'extra route', 'inet6', 'nft input drift'):
            with self.subTest(case=case):
                self.foreign, self.tables, self.rules, self.routes = deepcopy(initial)
                if case == 'nft missing':
                    self.tables.clear()
                if case == 'route missing':
                    self.routes.clear()
                if case == 'rule missing':
                    self.rules.pop()
                if case == 'extra nft rule':
                    self.tables.append(deepcopy(self.tables[-1]))
                if case == 'reordered input rules':
                    self.tables[5], self.tables[6] = self.tables[6], self.tables[5]
                if case == 'changed forward action':
                    self.tables[-1]['rule']['expr'][-1] = {'accept': None}
                if case == 'rule mask':
                    self.rules[-1]['fwmask'] = '0xff'
                if case == 'extra route':
                    self.routes.append({**self.route, 'dst': '10.0.0.0/8'})
                if case == 'inet6':
                    self.routes[0]['family'] = 'inet6'
                if case == 'nft input drift':
                    self.ingress.write_bytes(self.nft + b'\n')
                before = self.snapshot()
                self.assertNotEqual(self.start(unit), 0)
                self.assertEqual(self.snapshot(), before)
                self.assertEqual(self.effects, ['create nft', 'add route', 'add rule'])

    def test_partial_failed_start_leaves_cleanup_to_actual_host_rollback(self):
        h = self.host
        unit = self.render()
        self.fail_rule = True
        self.assertNotEqual(self.start(unit), 0)
        self.assertEqual(self.effects, ['create nft', 'add route', 'add rule'])
        self.assertFalse(self.rules[len(self.stock):])
        self.assertEqual(self.routes, [self.route])
        self.assertNotRegex(unit, r'(?m)^ExecStop(?:Post)?=')
        self.assertNotEqual(self.start(unit), 0)
        self.assertEqual(self.effects, ['create nft', 'add route', 'add rule'])
        self.assertFalse(self.state.exists())
        x, xl, ike, net = (h[key] for key in ('X', 'XL', 'IKE', 'NET_UNIT'))
        inactive = dict(ActiveState='inactive', LoadState='loaded', FragmentPath='fixture', DropInPaths='')
        units = {x: inactive, xl: inactive, ike: inactive,
                 net: dict(ActiveState='failed', LoadState='loaded', FragmentPath=h['NET'])}
        before = dict(units=units, files={'main': None})
        current = dict(main=None, starter=None, ike=None, net=h['entry'](unit.encode(), 0o644),
                       nft=h['entry'](self.nft, 0o644))
        backup = dict(before=before, phase='applying', after={
            key: {**current[key], 'data': h['digest'](h['raw'](current[key]))} for key in ('net', 'nft')})
        host_commands = []

        def sc(action, *args, **kw):
            host_commands.append((action, *args))
            if action == 'stop':
                assert args == (net,)
                # No unit-owned cleanup can run when rollback temporarily stops it.
                assert self.tables and self.routes
                units[net] = {**units[net], 'ActiveState': 'inactive'}

        def command(*argv, **kw):
            result = self.command(argv, **kw)
            assert result.returncode == 0
            return result.stdout

        writes = []
        h.update(module_boot_owner=lambda _: None, check_module_boot_owner=lambda _: None,
                 runtime_before=lambda _: before, no_jobs=lambda _: None, neighbors=lambda *_: None,
                 load_after=lambda *_, **kw: current,
                 ike_include_matches=lambda *_: True, vpn_empty=lambda **kw: True,
                 unit=lambda n: units[n], sock_rows=lambda: [], retained_xray_dropin=lambda *_: None,
                 working=lambda info: info is units[x] and ('daemon-reload',) in host_commands,
                 native_vpn=lambda *_: True, write=lambda p, b, a: writes.append(a),
                 operation_order=lambda _: [], original_files=lambda *_: {}, directory_absent=lambda _: True,
                 sc=sc, command=command,
                 verify_rollback=lambda *_: self.assertEqual(self.projection(), dict(nft=None, route=False, rule=False)),
                 read=lambda *args: writes[-1], release_module_boot=lambda _: None)
        units[xl]['UnitFileState'] = units[ike]['UnitFileState'] = 'disabled'
        h['rollback'](dict(network=D, backupId=TOKEN), 'fixture-manifest', None, backup)
        self.assertEqual(backup['phase'], 'rolled-back')
        self.assertEqual(host_commands, [('stop', net), ('daemon-reload',)])
        self.assertEqual(self.effects, ['create nft', 'add route', 'add rule', 'delete route', 'delete nft'])
        self.assertEqual(self.snapshot(), ({'table': dict(family='ip', name='foreign', handle=5)}, [], self.stock, []))
        self.assertFalse(self.state.exists())
        self.fail_rule = False
        self.assertEqual(self.start(unit), 0)

    def test_remove_temporary_stop_keeps_policy_for_host_cleanup(self):
        class StoppedWithPolicy(Exception):
            pass

        h, unit = self.host, self.render()
        self.assertEqual(self.start(unit), 0)
        starts = list(self.effects)
        self.assertNotRegex(unit, r'(?m)^ExecStop(?:Post)?=')
        x, xl, ike, net = (h[key] for key in ('X', 'XL', 'IKE', 'NET_UNIT'))
        units = {name: dict(ActiveState='active', SubState='exited', MainPID='0') for name in (x, xl, ike, net)}
        manager = deepcopy(units)
        stops = []

        def sc(action, name, **kw):
            assert action == 'stop'
            stops.append(name)
            manager[name].update(ActiveState='inactive', SubState='dead', MainPID='0')

        def command(*argv, **kw):
            result = self.command(argv, **kw)
            assert result.returncode == 0
            return result.stdout

        def proof_after_stops(_):
            self.assertEqual(stops, [xl, ike, net])
            self.assertEqual(self.effects, starts)
            raise StoppedWithPolicy

        h.update(no_jobs=lambda _: None, unit=lambda n: dict(manager[n]), sc=sc, sock_rows=lambda: [],
                 remove_chap=lambda *_: (None, 'owned'), read=lambda _: None,
                 ipsec_session_sample=lambda _: (0, None), removal_idle=lambda *_: None,
                 check_module_boot_owner=lambda _: None, write=lambda *_: None,
                 removal_dependencies=lambda *_, **kw: None, removal_native=lambda *_, **kw: True,
                 removal_vpn_runtime=lambda *_: None, vpn_empty=lambda: True,
                 removal_neighbors=proof_after_stops, command=command)
        policy = self.projection()
        self.assertTrue(all(policy.values()))
        state = dict(before={}, current={}, profiles={}, units=units, policy=policy, pinned_network=True, reserved=set(), sockets=[],
                     boot_enrollment=None, ike_sockets=[], chap_backup=None, chap_expected=None,
                     chap_digest='owned', intent='fixture-remove-intent', baseline='baseline')
        # Stop after the real Remove implementation re-observes the unchanged
        # policy, before it alters the profiles or starts deleting any policy.
        with self.assertRaises(StoppedWithPolicy):
            h['remove_installation'](dict(backupId=TOKEN, network=D), state)

    def test_historical_templates_are_exact(self):
        f, h = self.host['network_unit'], self.host
        for legacy in (False, True):
            for sidecar in (False, True):
                dependency = 'Requires' if legacy else 'Wants'
                after = h['X'] + (' ' + h['B'] if sidecar else '')
                pre = '' if legacy else f"ExecStartPre=/usr/bin/systemctl is-active --quiet {h['X']}\n"
                expected = f'''[Unit]
Description=Celerity rebuild L2TP TPROXY policy
Before={h['XL']}
{dependency}={h['X']}
After={after} nftables.service

[Service]
Type=oneshot
RemainAfterExit=yes
TimeoutStartSec=20s
{pre}ExecStart=/usr/sbin/nft -f {h['NFT_FILE']}
ExecStart=/usr/sbin/ip -4 route add local 0.0.0.0/0 dev lo table 177
ExecStart=/usr/sbin/ip -4 rule add priority {h['PRIORITY']} from 10.255.1.0/24 fwmark 77 table 177
'''
                self.assertEqual(f(D, sidecar, legacy=legacy), expected.encode())

    def test_install_pins_cannot_authorize_unrelated_nft_commands(self):
        f = self.host['network_unit']
        payload = self.nft + b'flush ruleset\n'
        for kwargs in (dict(backup_id=TOKEN), dict(legacy=True, backup_id=TOKEN, nft_sha256=self.nft_sha),
                       dict(backup_id=TOKEN, nft_sha256=hashlib.sha256(payload).hexdigest())):
            with self.subTest(kwargs=kwargs), self.assertRaisesRegex(self.host['Refusal'], '^CANDIDATE_INVALID$'):
                f(D, False, **kwargs)


if __name__ == '__main__':
    unittest.main()
