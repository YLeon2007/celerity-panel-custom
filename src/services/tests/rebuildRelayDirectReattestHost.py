"""Model only native observers; exercise the actual DIRECT main and file CAS."""
import contextlib
import copy
import fcntl
import io
import json
import os
from pathlib import Path
import runpy
import stat
import sys
import tempfile
from types import SimpleNamespace
from typing import Any
import unittest


SOURCE = (Path(sys.argv.pop(1)) if len(sys.argv) > 1 and not sys.argv[1].startswith('-')
          else Path(__file__).resolve().parents[1] / 'rebuildRelayDirectHost.py')
NETWORK_FIXTURE = runpy.run_path(str(Path(__file__).with_name('helpers') / 'rebuildRelayNetworkFixture.py'))


def deny_native(event, _):
    if event in ('os.system', 'os.exec', 'os.posix_spawn', 'os.kill', 'subprocess.Popen') or event.startswith('socket.'):
        raise AssertionError('unmodeled native dispatch forbidden')


sys.addaudithook(deny_native)
os.umask(0o077)


class RuntimeReattest(unittest.TestCase):
    def physical(self, path):
        assert path.startswith('/') and '..' not in path.split('/')
        return self.root / path[1:]

    @contextlib.contextmanager
    def directory(self, path, private=False):
        fd = os.open(self.physical(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            if private:
                assert stat.S_IMODE(os.fstat(fd).st_mode) == 0o700
            yield fd
        finally:
            os.close(fd)

    def put(self, path, data, mode):
        p = self.physical(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        p.chmod(mode)

    def image(self):
        return {str(p.relative_to(self.root)): (p.lstat().st_ino, p.lstat().st_ctime_ns, p.lstat().st_mode,
                    os.readlink(p) if p.is_symlink() else p.read_bytes())
                for p in self.root.rglob('*') if p.is_symlink() or not p.is_dir()}

    def call(self, action, **kwargs):
        self.h.update(REATTEST_ENTERED=False, REMOVE_ENTERED=False, CHAP_ENTERED=False, NETWORK_UPGRADE_ENTERED=False)
        old_in = sys.stdin
        sys.stdin = SimpleNamespace(buffer=io.BytesIO(json.dumps({**self.request, 'action': action, **kwargs}).encode()))
        out, err = io.StringIO(), io.StringIO()
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                rc = self.h['main']()
        finally:
            sys.stdin = old_in
        self.assertEqual(self.unexpected, [])
        return rc, out.getvalue(), err.getvalue()

    def setUp(self):
        h: dict[str, Any] = {'__name__': 'modeled_direct'}
        self.h = h
        exec(compile(SOURCE.read_bytes(), str(SOURCE), 'exec'), h)
        temp = tempfile.TemporaryDirectory(prefix='.reattest-runtime-', dir=Path.cwd())
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        h['NETWORK_RUN'] = str(self.root / 'run')
        self.unexpected = []
        self.token, self.machine, self.node = 'a' * 32, 'b' * 32, 'c' * 24
        self.old_boot, self.boot = '12345678-1234-1234-1234-123456789abc', '12345678-1234-1234-1234-123456789abd'
        self.network = dict(clientCidr='10.60.0.0/24', tproxyPort=12456, fwmark=805, routeTable=210)
        self.request = dict(backupId=self.token, machineId=self.machine, nodeId=self.node, network=self.network)
        self.watch = [h[k] for k in ('X', 'XL', 'IKE', 'NET_UNIT')]
        x, xl, ike, net = self.watch
        self.tcpudp = [('tcp', '0.0.0.0', 12456, ['11']), ('udp', '0.0.0.0', 12456, ['11']),
                       ('tcp', '127.0.0.1', 12700, ['11']), ('udp', '127.0.0.1', 12700, ['11']),
                       ('udp', '0.0.0.0', 1701, ['12']), ('udp', '0.0.0.0', 500, ['15']),
                       ('udp', '0.0.0.0', 4500, ['15'])]
        self.rows = copy.deepcopy(self.tcpudp)
        self.nft = [{'metainfo': {'json_schema_version': 1}}, {'table': {'family': 'inet', 'name': h['TABLE'], 'comment': self.token}},
                    {'chain': {'family': 'inet', 'table': h['TABLE'], 'name': 'ingress', 'policy': 'drop'}}]
        self.rules = [{'priority': p, 'table': t, 'src': 'all'} for p, t in ((0, 255), (32766, 254), (32767, 253))]
        self.rules.insert(1, dict(priority=h['PRIORITY'], table=210, src='10.60.0.0/24', fwmark='0x325'))
        self.routes = [dict(type='local', dst='default', dev='lo', scope='host', table='210', flags=[])]
        self.nft_reads = 0
        self.rotate_between = False
        self.rotate_pid_between = False
        self.write_at_second_sample = None

        def bad(*args, **kw):
            self.unexpected.append((args, kw))
            raise AssertionError('unexpected observer')

        def command(*args, **kw):
            if args == ('/usr/bin/systemctl', '--no-pager', 'list-jobs', '--no-legend', '--plain'):
                return b''
            if args == ('/usr/sbin/nft', '-j', 'list', 'tables'):
                return h['encode']({'nftables': self.nft[:2]})
            if args in (('/usr/sbin/nft', '-j', '-s', 'list', 'table', 'inet', h['TABLE']),
                        ('/usr/sbin/nft', '-j', '-s', '-a', 'list', 'table', 'inet', h['TABLE'])):
                self.nft_reads += 1
                if self.rotate_between and self.nft_reads == 1:
                    self.units[xl]['InvocationID'] = 'e' * 32
                if self.rotate_pid_between and self.nft_reads == 1:
                    self.starts['12'] += 1
                if self.write_at_second_sample is not None and self.nft_reads == 2:
                    self.write_at_second_sample()
                return h['encode']({'nftables': self.nft})
            if args == ('/usr/sbin/ip', '-j', '-N', '-4', 'rule', 'show'):
                return h['encode'](self.rules)
            if args == ('/usr/sbin/ip', '-j', '-N', '-4', 'route', 'show', 'table', 'all'):
                return h['encode'](self.routes)
            if args == ('/usr/sbin/ipsec', 'statusall'):
                return b'Connections:\n celerity-l2tp: %any...%any IKEv1\nSecurity Associations (0 up, 0 connecting):\n none\n'
            if args == (h['XRAY'], 'api', 'inbounduser', '--server=127.0.0.1:10085', '-tag=client'):
                return b'{}'
            if args in (('/usr/sbin/ip', 'xfrm', 'state', 'list', 'nokeys'),
                        ('/usr/sbin/ip', 'xfrm', 'policy', 'list', 'nosock')):
                return b''
            if args[:3] == ('/usr/bin/setpriv', '--reuid=0', '--regid=0') and args[3:8] == ('--init-groups', h['XRAY'], 'run', '-test', '-format'):
                return b''  # No native validator is started by this fixture.
            return bad(*args, **kw)

        self.starts = {'11': 100, '12': 101, '13': 102, '15': 103}

        def proc_open(path, mode):
            pid = path.removeprefix('/proc/').removesuffix('/stat')
            if path == f'/proc/{pid}/stat' and pid in self.starts and mode == 'rb':
                return io.BytesIO((pid + ' (fixture) S ' + '0 ' * 18 + str(self.starts[pid]) + '\n').encode())
            return bad(path, mode)

        def installed_open(path, mode='r'):
            if path == '/proc/net/dev' and mode == 'r':
                return io.StringIO('Inter-| Receive | Transmit\n face | bytes\n lo: 0\n' + (' ppp0: 0\n' if self.has_ppp_link else ''))
            return proc_open(path, mode)

        real_os = os
        parent = self

        class OwnerStat:
            def __init__(self, value):
                self.value = value
                self.st_uid = 0
                self.st_gid = fixture_gids.get(value.st_ino, 0)

            def __getattr__(self, name):
                return getattr(self.value, name)

        class FixtureOS:
            def __getattr__(self, name):
                return getattr(real_os, name)

            def fstat(self, fd):
                return OwnerStat(real_os.fstat(fd))

            def lstat(self, path):
                return OwnerStat(real_os.lstat(parent.physical(path)))

            def stat(self, path, **kw):
                if path.startswith('/proc/') and path == '/proc/' + parent.units[parent.watch[0]]['MainPID']:
                    return OwnerStat(real_os.stat(parent.physical(h['XRAY'])))
                return OwnerStat(real_os.stat(path, **kw))

            def fchown(self, fd, uid, gid):
                assert uid == 0 and gid in (0, 65534)
                fixture_gids[real_os.fstat(fd).st_ino] = gid

            def geteuid(self):
                return 0

        fixture_gids = {}
        self.has_ppp_link = False
        self.xray_users = h['xray_users']
        h.update(os=FixtureOS(), directory=self.directory, boot=lambda: self.boot,
                 require_machine=lambda m: h['need'](m == self.machine, 'IDENTITY'), require_census_machine=lambda m: h['need'](m == self.machine, 'IDENTITY'),
                 preflight=lambda m: {'ppp': True, 'unitsLoaded': True, 'masked': False},
                 ppp_device=lambda: True, ppp_registered=lambda: True, require_network_observers=lambda: None,
                 command=command, open=installed_open, sock_rows=lambda: copy.deepcopy(self.rows),
                 unit=lambda n: copy.deepcopy(self.units[n]), in_cgroup=lambda pid, u: str(pid) in {'11'} if u.get('ControlGroup') == '/xray' else str(pid) in u.get('ModelCgroup', []),
                 xray_users=lambda *a: [], xray_argv=lambda u, path=None: u['MainPID'])
        records = {k: h['entry'](b'modeled file\n') for k in h['NAMES']}
        starts = h['network_unit'](self.network, False)
        records.update(net=h['entry'](starts, 0o644), nft=h['entry'](f'create table inet {h["TABLE"]} {{\n    comment "{self.token}"\n}}\n'.encode(), 0o644),
                       lns=h['entry'](b'[global]\nport = 1701\n\n[lns default]\nip range = 10.60.0.2-10.60.0.20\n'
                                      b'local ip = 10.60.0.1\nrequire authentication = yes\n'
                                      b'pppoptfile = /etc/ppp/options.xl2tpd\nlength bit = yes\n'),
                       options=h['entry'](b'auth\nrefuse-pap\nrefuse-chap\nrefuse-mschap\nrequire-mschap-v2\nrefuse-eap\n'
                                          b'name l2tpd\nmtu 1400\nmru 1400\nnoipv6\nnodefaultroute\nms-dns 192.0.2.53\n'),
                       chap=h['entry'](h['CHAP_BEGIN'] + b'\n' + h['CHAP_END'] + b'\n'),
                       starter=h['entry'](b'include ' + h['NAMES']['ike'].encode() + b'\n'),
                       main=h['entry'](h['encode']({'outbounds': [], 'routing': {'rules': []},
                                                   'inbounds': [{'tag': 'relay-l2tp-' + self.node, 'port': 12456},
                                                                  {'tag': 'rebuild-relay-ingress', 'listen': '127.0.0.1', 'port': 12700, 'protocol': 'socks'}]})))
        for key, path in h['NAMES'].items():
            self.put(path, h['raw'](records[key]), records[key]['mode'])
        self.put(h['SYSTEM'] + '/' + xl, b'modeled native unit\n', 0o644)
        h['NATIVE_XL_SHA'] = h['digest'](b'modeled native unit\n')
        link = self.physical(h['XL_BOOT'])
        link.parent.mkdir(parents=True)
        link.symlink_to(h['SYSTEM'] + '/' + xl)
        receipt = h['boot_link']()

        def unit(n, pid, argv, **fields):
            return {**dict.fromkeys(('DropInPaths', 'Environment', 'EnvironmentFiles', 'RootDirectory', 'RootImage', 'ExecStartPre',
                                     'ExecStartPost', 'ExecStop', 'ExecStopPost', 'RequiredBy', 'BoundBy', 'ConsistsOf',
                                     'PropagatesStopTo', 'Conflicts', 'ConflictedBy', 'Requires', 'Wants', 'BindsTo', 'Upholds',
                                     'After', 'Group', 'User', 'PartOf'), ''),
                    **dict(LoadState='loaded', UnitFileState='enabled', ActiveState='active', SubState='running', MainPID=str(pid),
                           FragmentPath=h['SYSTEM'] + '/' + n, InvocationID=f'{pid + 10:032x}', NeedDaemonReload='no',
                           PrivateNetwork='no', KillMode='control-group', ControlGroup='/' + n, Type='simple',
                           ExecStart='{ path=' + argv.split(' ')[0] + ' ; argv[]=' + argv + ' ; ignore_errors=no ; pid=' + str(pid) + ' }'),
                    **fields}

        network_starts = ' '.join('{ path=' + cmd.split(' ')[0] + ' ; argv[]=' + cmd + ' ; ignore_errors=no ; pid=0 }'
                                  for line in starts.decode().splitlines() if line.startswith('ExecStart=') for cmd in [line.split('=', 1)[1]])
        self.units = {x: unit(x, 11, h['XRAY'] + ' run -config ' + h['MAIN'], ControlGroup='/xray'),
                      xl: unit(xl, 12, '/usr/sbin/xl2tpd -D', DropInPaths=h['DROP'], Requires=net + ' ' + ike,
                               After=net + ' ' + ike, ModelCgroup=['12']),
                      ike: unit(ike, 13, '/usr/sbin/ipsec start --nofork', FragmentPath='/usr/lib/systemd/system/' + ike,
                                RequiredBy=xl, ModelCgroup=['13', '15']),
                      net: unit(net, 0, 'unused', ExecStart=network_starts, Type='oneshot', SubState='exited',
                                UnitFileState='static', Wants=x, After=x, RequiredBy=xl,
                                ExecStartPre='{ path=/usr/bin/systemctl ; argv[]=' + h['NETWORK_START_CHECK'] + ' ; ignore_errors=no ; pid=0 }'),
                      h['B']: unit(h['B'], 0, 'unused', ActiveState='inactive', SubState='dead', LoadState='not-found')}

        original = copy.deepcopy(self.units)
        original[xl].update(UnitFileState='disabled', ActiveState='inactive', DropInPaths='')
        original[ike].update(ActiveState='inactive', SubState='dead', MainPID='0')
        self.manifest = dict(machineId=self.machine, backupId=self.token, network=self.network, phase='installed',
                             before=dict(boot=self.old_boot, units=original, files={'chap': None}, sockets=[], globalFiles={}, bridge=None,
                                         installBoot=True, ikeSockets=[]),
                             after={k: {**r, 'data': h['digest'](h['raw'](r))} for k, r in records.items()},
                             runtime=dict(nft=h['digest'](h['encode'](self.nft)), files=h['file_generations'](records),
                                          invocations=['d' * 31 + str(i) for i in range(1, 5)], bootEnrollment=receipt),
                             bootEnrollment=receipt)
        self.manifest_path = h['manifest_path'](self.token)
        self.save_manifest()

    def save_manifest(self):
        self.put(self.manifest_path, self.h['encode'](self.manifest), 0o600)

    def reattest(self):
        return self.call('reattest-runtime')

    def stage_pinned_network(self):
        h = self.h
        self.nft = NETWORK_FIXTURE['nft_rows'](self.network, self.token)
        nft = NETWORK_FIXTURE['nft_source'](SOURCE, self.network, self.token)
        unit = h['network_unit'](self.network, False, backup_id=self.token, nft_sha256=h['digest'](nft))
        for key, data in (('nft', nft), ('net', unit)):
            path = h['NAMES'][key]
            self.put(path, data, 0o644)
            self.manifest['after'][key] = dict(h['entry'](data, 0o644), data=h['digest'](data))
            self.manifest['runtime']['files'][key] = h['remove_generation'](path)
        self.units[self.watch[-1]]['ExecStart'] = NETWORK_FIXTURE['systemctl_start'](unit, 'quoted')
        self.manifest['runtime']['nft'] = h['network_projection'](self.network, self.token, pinned=True)['nft']
        self.save_manifest()

    def test_previous_install_new_kernel_nft_handles(self):
        h = self.h
        self.nft = NETWORK_FIXTURE['nft_rows'](self.network, self.token)
        nft = NETWORK_FIXTURE['nft_source'](SOURCE, self.network, self.token)
        path = h['NAMES']['nft']
        self.put(path, nft, 0o644)
        self.manifest['after']['nft'] = dict(h['entry'](nft, 0o644), data=h['digest'](nft))
        self.manifest['runtime']['files']['nft'] = h['remove_generation'](path)
        self.manifest['runtime']['nft'] = h['digest'](h['encode'](self.nft))
        self.save_manifest()
        for row in self.nft:
            value = next(iter(row.values()))
            if 'handle' in value:
                value['handle'] += 37
        self.assertEqual(self.reattest()[0], 0)
        self.assertEqual(h['read_manifest'](self.token)[2]['runtime']['nft'], self.manifest['runtime']['nft'])
        self.request.pop('nodeId')
        self.assertEqual(self.call('check-apply-network')[0], 0)
        self.request['nodeId'] = self.node
        self.nft[-1]['rule']['expr'][-1] = {'accept': None}
        self.assert_foreign()

    def test_pinned_reattest_refuses_changed_loaded_argv(self):
        self.stage_pinned_network()
        unit = self.units[self.watch[-1]]
        unit['ExecStart'] = unit['ExecStart'].replace(' -I ', ' -E ')
        self.assert_foreign()

    def assert_foreign(self):
        image = self.image()
        self.assertEqual(self.reattest(), (70, '', 'DIRECT_RUNTIME_FOREIGN_CHANGE\n'))
        self.assertEqual(self.image(), image)

    def test_legacy_receipt_refreshes_only_runtime_epoch(self):
        before = self.image()
        rc, response, err = self.reattest()
        self.assertEqual((rc, err), (0, ''))
        self.assertEqual(json.loads(response), {'ok': True, 'backupId': self.token})
        expected = copy.deepcopy(self.manifest)
        expected['runtime'].update(boot=self.boot, invocations=[self.units[n]['InvocationID'] for n in self.watch],
                                   pids=[self.units[n]['MainPID'] for n in self.watch])
        self.assertEqual(self.h['read_manifest'](self.token)[2], expected)
        self.assertGreaterEqual(self.nft_reads, 2)
        after = self.image()
        key = self.manifest_path[1:]
        self.assertNotEqual(before.pop(key), after.pop(key))
        self.assertEqual(before, after)
        after = self.image()
        self.assertEqual(self.reattest()[0], 0)
        self.assertEqual(after, self.image())
        self.request.pop('nodeId')
        rc, response, err = self.call('check-apply-network')
        self.assertEqual((rc, err), (0, ''))
        self.assertRegex(json.loads(response)['proof'], r'^[a-f0-9]{64}$')
        self.assertEqual(after, self.image())

    def test_reattest_preserves_requires_template(self):
        h, (x, _, _, net) = self.h, self.watch
        unit = h['network_unit'](self.network, False, legacy=True)
        path = h['NAMES']['net']
        self.put(path, unit, 0o644)
        self.units[net].update(Requires=x, Wants='', ExecStartPre='', ExecStart=NETWORK_FIXTURE['systemctl_start'](unit))
        self.units[x]['RequiredBy'] = net
        self.manifest['after']['net'] = dict(h['entry'](unit, 0o644), data=h['digest'](unit))
        self.manifest['runtime']['files']['net'] = h['remove_generation'](path)
        self.save_manifest()
        image = self.image()
        self.assertEqual(self.reattest()[0], 0)
        after = self.image()
        for state in (image, after):
            state.pop(self.manifest_path[1:])
        self.assertEqual(image, after)
        self.assertEqual(h['read_manifest'](self.token)[2]['after'], self.manifest['after'])

    def test_reattest_refuses_recreated_boot_enrollment_link(self):
        link = self.physical(self.h['XL_BOOT'])
        target = os.readlink(link)
        replacement = link.with_name('foreign-link')
        replacement.symlink_to(target)
        replacement.replace(link)
        self.assert_foreign()

    def test_chap_writer_then_boot_reattest(self):
        self.boot = self.old_boot
        self.manifest['runtime']['invocations'] = [self.units[n]['InvocationID'] for n in self.watch]
        self.save_manifest()
        users = [dict(login='synthetic', password='fixture-only', ipAddress='10.60.0.4', enabled=True)]
        self.assertEqual(self.call('sync-chap', currentUsers=[], desiredUsers=users)[0], 0)
        self.boot = '12345678-1234-1234-1234-123456789abb'
        self.assertEqual(self.call('inspect-chap', currentUsers=users, desiredUsers=users),
                         (70, '', 'DIRECT_RUNTIME_REATTEST_REQUIRED\n'))
        self.assertEqual(self.reattest(), (0, '{"ok":true,"backupId":"' + self.token + '"}\n', ''))
        self.assertEqual(self.call('inspect-chap', currentUsers=users, desiredUsers=users)[0], 0)
        current = self.h['read_manifest'](self.token)[2]
        self.assertEqual(current['before'], self.manifest['before'])
        self.assertEqual(current['after'], self.manifest['after'])
        path = self.h['NAMES']['chap']
        self.put(path + '.replacement', self.physical(path).read_bytes(), 0o600)
        self.physical(path + '.replacement').replace(self.physical(path))
        self.assert_foreign()

    def test_chap_writer_preserves_unpinned_neighbors_without_reattesting_them(self):
        h = self.h
        self.boot = self.old_boot
        self.manifest['runtime']['invocations'] = [self.units[n]['InvocationID'] for n in self.watch]
        self.save_manifest()
        path = h['NAMES']['chap']
        neighbor = b'# additional administrator-owned content\n'
        self.put(path + '.replacement', neighbor + self.physical(path).read_bytes(), 0o600)
        self.physical(path + '.replacement').replace(self.physical(path))
        users = [dict(login='synthetic', password='fixture-only', ipAddress='10.60.0.4', enabled=True)]
        self.assertEqual(self.call('sync-chap', currentUsers=[], desiredUsers=users)[0], 0)
        self.assertTrue(self.physical(path).read_bytes().startswith(neighbor))
        self.assertNotIn('currentChap', h['read_manifest'](self.token)[2])
        self.boot = '12345678-1234-1234-1234-123456789abb'
        self.assert_foreign()

    def apply_fixture(self, *, bridge=False):
        if self.boot != self.old_boot:
            self.boot = self.old_boot
            self.manifest['runtime']['invocations'] = [self.units[n]['InvocationID'] for n in self.watch]
            self.save_manifest()
        h = self.h
        ppp, socks, hop, block = ('relay-l2tp-' + self.node, h['FOLLOW_RELAY_SOCKS'], 'rebuild-l2tp-handoff', 'rebuild-l2tp-block')
        port = 18000 + int(h['digest'](f'cascade-path-ingress:{self.node}:follow-relay-v1'.encode())[:8], 16) % 2000
        profile = dict(api=dict(tag='API', services=['HandlerService']),
                       inbounds=[dict(tag='client', protocol='vless', listen='0.0.0.0', port=443, settings=dict(clients=[])),
                                 dict(tag='API_INBOUND', protocol='dokodemo-door', listen='127.0.0.1', port=10085),
                                 dict(tag='synthetic-fixed-udp', protocol='dokodemo-door', listen='127.0.0.1', port=5300,
                                      settings=dict(network='udp')),
                                 h['follow_relay_tproxy'](ppp, self.network['tproxyPort']),
                                 dict(tag=socks, port=port, listen='127.0.0.1', protocol='socks',
                                      settings=dict(auth='noauth', udp=True, ip='127.0.0.1'),
                                      sniffing=dict(enabled=True, destOverride=['http', 'tls', 'quic'], routeOnly=False))],
                       outbounds=[dict(tag='block', protocol='blackhole'), dict(tag=block, protocol='blackhole'), h['follow_relay_hop'](port)],
                       routing=dict(rules=[dict(type='field', inboundTag=[tag], outboundTag=block, ip=['geoip:private']) for tag in (ppp, socks)]
                                    + [dict(type='field', inboundTag=[ppp], outboundTag=hop),
                                       dict(type='field', inboundTag=['client', socks], outboundTag='block', ruleTag='rebuild-policy-default')]))
        stage_id = '12345678-1234-4234-8234-123456789abc'
        stages, targets = {}, {'main': h['MAIN'], 'bridge': h['BRIDGE']}
        side = dict(inbounds=[dict(tag='bridge-test', protocol='vless', listen='127.0.0.1', port=9443)] if bridge else [],
                    outbounds=[], routing=dict(rules=[]))
        for key, data in [('main', profile), ('bridge', side)]:
            wire = h['encode'](data)
            self.put(targets[key] + '.rebuild-' + stage_id + '.json', wire, 0o600)
            stages[key] = h['digest'](wire)
        self.request.pop('nodeId')
        before = self.call('prepare-apply-network')
        self.assertEqual((before[0], before[2]), (0, ''))
        source = SOURCE.with_name('configGenerator.js').read_text()
        bridge_unit = source.split('function generateBridgeSystemdService() {', 1)[1].split('`', 2)[1]
        params = dict(nodeId=self.node, stageId=stage_id, profiles=stages, bridgeUnit=bridge_unit,
                      proof=json.loads(before[1])['proof'])
        return params, port

    def model_apply_main_restart(self, port):
        h, x = self.h, self.watch[0]
        systemctl = h['sc']
        def restart(*args, **options):
            if args != ('restart', x):
                return systemctl(*args, **options)
            self.units[x].update(MainPID='21', InvocationID='1' * 32)
            self.starts['21'] = 201
            self.rows = [(p, a, port if n == 12700 else n, ['21'] if ids == ['11'] else ids) for p, a, n, ids in self.rows]
            self.rows.extend([('tcp', '0.0.0.0', 443, ['21']), ('tcp', '127.0.0.1', 10085, ['21']),
                              ('udp', '127.0.0.1', 5300, ['21']), ('udp', '0.0.0.0', 34000, ['21'])])
        h['sc'] = restart
        h['xray_users'] = self.xray_users
        h['in_cgroup'] = lambda pid, u: pid == self.units[x]['MainPID'] if u['ControlGroup'] == '/xray' else pid in u['ModelCgroup']

    def model_idle_ppp_census(self):
        h = self.h
        xl = self.units[self.watch[1]]
        pid = int(xl['MainPID'])
        group = '/sys/fs/cgroup' + h['SESSION_GROUP']
        self.put(group + '/cgroup.procs', f'{pid}\n'.encode(), 0o644)
        self.put(group + '/cgroup.stat', b'nr_descendants 0\nnr_dying_descendants 0\n', 0o644)
        self.put('/proc/self/net/pppol2tp', h['SESSION_L2TP_HEADER'], 0o444)
        self.physical('/root').mkdir()
        for path in h['SESSION_STOCK']:
            self.put(path, b'modeled stock executable', 0o755)
        h['SESSION_STOCK'] = dict.fromkeys(h['SESSION_STOCK'], h['digest'](b'modeled stock executable'))

        @contextlib.contextmanager
        def process(proc, task_pid, main, binaries, watch):
            self.assertEqual((task_pid, main), (pid, pid))
            watch()
            yield None, self.starts[str(pid)], b'/usr/sbin/xl2tpd\0-D\0'

        @contextlib.contextmanager
        def route_socket(*args):
            def bind(addr):
                self.assertEqual(addr, (0, 17))
            yield SimpleNamespace(bind=bind)

        h['os'].pidfd_open = lambda task_pid: os.open(self.physical(group), os.O_RDONLY | os.O_DIRECTORY)
        h.update(session_fs=lambda *a: None, session_process=process,
                 socket=SimpleNamespace(AF_NETLINK=0, SOCK_RAW=1, SOCK_NONBLOCK=2, socket=route_socket),
                 select=SimpleNamespace(POLLIN=1, poll=lambda: SimpleNamespace(register=lambda *a: None, poll=lambda n: [])))

    def test_apply_writer_then_same_boot_restart_and_reboot(self):
        self.stage_pinned_network()
        h, (x, xl, ike, net) = self.h, self.watch
        self.units[x]['UnitFileState'] = self.manifest['before']['units'][x]['UnitFileState'] = 'disabled'
        self.units[xl]['ControlGroup'] = h['SESSION_GROUP']
        self.physical('/etc/ppp/ip-pre-up.d').mkdir()
        for path in h['SESSION_GLOBAL']:
            self.put(path, b'modeled stock PPP helper\n', 0o644)
        h['SESSION_GLOBAL'] = dict.fromkeys(h['SESSION_GLOBAL'], h['digest'](b'modeled stock PPP helper\n'))
        self.manifest['before']['globalFiles']['/etc/ppp/options'] = h['read']('/etc/ppp/options')
        self.boot = self.old_boot
        self.manifest['runtime']['invocations'] = [self.units[n]['InvocationID'] for n in self.watch]
        self.save_manifest()
        users = [dict(login='synthetic', password='fixture-only', ipAddress='10.60.0.4', enabled=True)]
        self.assertEqual(self.call('sync-chap', currentUsers=[], desiredUsers=users)[0], 0)
        chap = h['read_manifest'](self.token)[2]['currentChap']
        params, port = self.apply_fixture()
        rc, out, err = self.call('publish-apply-profiles', **params)
        self.assertEqual((rc, err), (0, ''))
        proof = json.loads(out)['proof']
        self.assertNotEqual(proof, params['proof'])
        self.assertEqual(h['read_manifest'](self.token)[2]['phase'], 'apply-profiles-pending')
        pending_image = self.image()
        self.assertEqual(self.call('verify-apply-network', proof=proof), (70, '', 'DIRECT_ROLLBACK_DRIFT\n'))
        self.assertEqual(self.image(), pending_image)
        self.model_apply_main_restart(port)
        self.units[x]['UnitFileState'] = 'enabled'  # The legitimate panel Apply enables MAIN.
        self.assertEqual(self.call('restart-apply-network', proof=proof)[0], 0)
        self.assertEqual(self.call('finalize-apply-profiles', proof=proof)[0], 0)
        finished = h['read_manifest'](self.token)[2]
        self.assertEqual(finished['before'], self.manifest['before'])
        self.assertEqual(finished['after'], self.manifest['after'])
        self.assertNotIn('applyPending', finished)
        self.request['nodeId'] = self.node
        self.units[xl]['InvocationID'] = '2' * 32
        self.assertEqual(self.call('inspect-chap', currentUsers=users, desiredUsers=users)[2], 'DIRECT_RUNTIME_REATTEST_REQUIRED\n')
        self.assertEqual(self.reattest()[0], 0)
        self.boot = '12345678-1234-1234-1234-123456789abb'
        for n, pid, invocation in zip((x, xl, ike, net), ('31', '32', '33', '0'), '4567'):
            self.units[n].update(MainPID=pid, InvocationID=invocation * 32, ModelCgroup=[pid])
        self.units[ike]['ModelCgroup'].append('35')
        pids = {'21': '31', '12': '32', '15': '35'}
        self.starts.update({str(pid): pid + 100 for pid in (31, 32, 33, 35)})
        self.rows = [(p, a, 34100 if n == 34000 else n, [pids[pid] for pid in ids]) for p, a, n, ids in self.rows]
        self.assertEqual(self.reattest()[0], 0)
        self.assertEqual(h['read_manifest'](self.token)[2]['currentApply'], finished['currentApply'])
        self.assertEqual(h['read_manifest'](self.token)[2]['currentChap'], chap)
        self.assertEqual(self.call('inspect-chap', currentUsers=users, desiredUsers=users)[0], 0)
        self.put(h['XRAY'], b'modeled executable', 0o755)
        self.model_idle_ppp_census()
        rc, out, err = self.call('session-count', currentUsers=users)
        self.assertEqual((rc, err), (0, ''))
        self.assertEqual({k: v for k, v in json.loads(out).items() if k != 'census'}, {'activeSessions': 0, 'activeIpsec': 0})
        census = json.loads(out)['census']
        self.assertEqual(len(census), 64)
        self.assertIsNone(json.loads(self.call('session-count', currentUsers=[])[1])['activeSessions'])
        rc, out, err = self.call('prepare-remove', currentUsers=users)
        self.assertEqual((rc, err), (0, ''))
        baseline = json.loads(out)['baseline']
        self.assertEqual(len(baseline), 64)
        self.has_ppp_link = True
        self.assertNotEqual(self.call('prepare-remove', currentUsers=users)[0], 0)
        self.has_ppp_link = False
        original = self.image()
        remove = dict(currentUsers=users, baseline=baseline, expectedCensus=census)
        self.assertEqual(self.call('remove', **{**remove, 'expectedCensus': 'f' * 64}),
                         (70, '', 'DIRECT_REMOVE_REFUSED\n'))
        self.assertEqual(self.image(), original)
        previous = self.rows[:]
        self.rows = [row for row in self.rows if row[2] != 5300]
        self.assert_foreign()
        self.rows = previous

        # Model an otherwise identical file with a new inode. Keep the real
        # positive fixture intact so it can exercise the durable Remove gate.
        path = h['MAIN']
        lstat = h['os'].lstat
        def replaced_stat(p):
            st = lstat(p)
            if p == path:
                st.st_ino = st.st_ino + 1
            return st
        h['os'].lstat = replaced_stat
        self.assert_foreign()
        self.assertEqual(self.call('prepare-remove', currentUsers=users), (70, '', 'DIRECT_ROLLBACK_DRIFT\n'))
        self.assertEqual(self.call('remove', **remove), (70, '', 'DIRECT_REMOVE_REFUSED\n'))
        h['os'].lstat = lstat

        # The actual Remove entry must accept the current proofs under its
        # exclusive lock and publish intent before its first service effect.
        # Stop at that effect: service teardown is not part of this fixture.
        stop, sc = [], h['sc']
        def before_first_stop(*args, **kw):
            if args == ('stop', xl):
                stop.append(args)
                raise OSError('fixture stops at first Remove service effect')
            return sc(*args, **kw)
        h['sc'] = before_first_stop
        self.assertEqual(self.call('remove', **remove), (75, '', ''))
        self.assertEqual(stop, [('stop', xl)])
        intent = str(Path(self.manifest_path).with_name('remove-attempt.json'))
        self.assertEqual(json.loads(self.physical(intent).read_bytes()), {'baseline': baseline})
        after = self.image()
        del after[str(self.physical(intent).relative_to(self.root))]
        self.assertEqual(after, original)

    def test_apply_interrupted_publication_cannot_be_reattested(self):
        params, _ = self.apply_fixture()
        h = self.h
        write = h['write']

        def interrupted(path, *args, **kwargs):
            if path == h['MAIN']:
                raise OSError('modeled interruption between profile writes')
            return write(path, *args, **kwargs)

        h['write'] = interrupted
        self.assertEqual(self.call('publish-apply-profiles', **params), (75, '', ''))
        self.assertTrue(self.physical(h['BRIDGE']).is_file())
        manifest = h['read_manifest'](self.token)[2]
        self.assertEqual(manifest['phase'], 'apply-profiles-pending')
        self.assertNotIn('currentApply', manifest)
        self.boot = '12345678-1234-1234-1234-123456789abb'
        self.request['nodeId'] = self.node
        self.assert_foreign()

    def test_apply_new_active_bridge_is_pinned_across_reboot(self):
        params, port = self.apply_fixture(bridge=True)
        h, b = self.h, self.h['B']
        unit_path = h['SYSTEM'] + '/' + b
        self.assertEqual(self.call('publish-apply-profiles', **{**params, 'bridgeUnit': 'arbitrary fragment'}),
                         (70, '', 'DIRECT_ROLLBACK_DRIFT\n'))
        self.assertFalse(self.physical(unit_path).exists())
        rc, out, err = self.call('publish-apply-profiles', **params)
        self.assertEqual((rc, err), (0, ''))
        proof = json.loads(out)['proof']
        self.assertEqual(self.physical(unit_path).read_bytes(), params['bridgeUnit'].encode())
        self.model_apply_main_restart(port)
        self.assertEqual(self.call('restart-apply-network', proof=proof)[0], 0)
        self.units[b].update(LoadState='loaded', ActiveState='active', SubState='running', User='nobody',
                             UnitFileState='enabled', MainPID='22', InvocationID='3' * 32, ModelCgroup=['22'])
        self.starts['22'] = 202
        self.rows.append(('tcp', '127.0.0.1', 9443, ['22']))
        self.assertEqual(self.call('finalize-apply-profiles', proof=proof)[0], 0)
        self.request['nodeId'] = self.node
        self.boot = '12345678-1234-1234-1234-123456789abb'
        self.assertEqual(self.reattest()[0], 0)
        self.rows[-1][3].append('23')
        self.assert_foreign()  # A shared listener is not equivalent to the old owner.
        self.rows[-1][3].pop()
        self.put(unit_path + '.foreign', self.physical(unit_path).read_bytes(), 0o644)
        self.physical(unit_path + '.foreign').replace(self.physical(unit_path))
        self.assert_foreign()

    def test_apply_refuses_historical_profile_replacement_at_publication(self):
        params, _ = self.apply_fixture()
        target = self.h['MAIN']
        self.put(target + '.foreign', self.physical(target).read_bytes(), 0o600)
        self.physical(target + '.foreign').replace(self.physical(target))
        before = self.image()
        self.assertEqual(self.call('publish-apply-profiles', **params), (70, '', 'DIRECT_ROLLBACK_DRIFT\n'))
        self.assertEqual(before, self.image())

    def test_reattest_refuses_changed_or_replaced_owned_bytes(self):
        for key in ('chap', 'nft'):
            path = self.h['NAMES'][key]
            original = self.physical(path).read_bytes()
            with self.subTest(key=key):
                self.physical(path).write_bytes(original + b'changed\n')
                self.assert_foreign()
                successor = path + '.successor'
                self.put(successor, original, 0o644 if key == 'nft' else 0o600)
                self.physical(successor).replace(self.physical(path))
                self.assert_foreign()
                self.manifest['runtime']['files'][key] = self.h['remove_generation'](path)
                self.save_manifest()

    def test_reattest_refuses_rotating_epoch(self):
        self.rotate_between = True
        self.assert_foreign()
        self.assertGreaterEqual(self.nft_reads, 1)

    def test_reattest_refuses_pid_reuse_between_samples(self):
        self.rotate_pid_between = True
        self.assert_foreign()
        self.assertEqual(self.nft_reads, 2)

    def test_file_changed_during_second_observation_is_not_published(self):
        path = self.physical(self.h['NAMES']['nft'])
        self.write_at_second_sample = lambda: path.write_bytes(path.read_bytes() + b'changed\n')
        before = self.physical(self.manifest_path).read_bytes()
        self.assertEqual(self.reattest(), (70, '', 'DIRECT_RUNTIME_FOREIGN_CHANGE\n'))
        self.assertEqual(self.nft_reads, 2)
        self.assertEqual(self.physical(self.manifest_path).read_bytes(), before)

    def test_refuses_foreign_kernel_policy_and_wrong_owners(self):
        changes: list[tuple[str, Any, Any, str]] = [
                ('token', self.nft[1]['table'], 'comment', 'f' * 32),
                ('nft-policy', self.nft[2]['chain'], 'policy', 'accept'),
                ('rule', self.rules[1], 'fwmark', '0x326'),
                ('route', self.routes[0], 'dev', 'eth0'),
                ('fragment', self.units[self.h['XL']], 'FragmentPath', '/usr/lib/systemd/system/xl2tpd.service'),
                ('unit-inactive', self.units[self.h['NET_UNIT']], 'ActiveState', 'failed'),
                ('lns-owner', self.rows[4][3], 0, '21'),
                ('ike-owner', self.rows[6][3], 0, '139'),
                ('tproxy-owner', self.rows[0][3], 0, '50'),
                ('handoff-owner', self.rows[2][3], 0, '50')]
        for change, item, key, value in changes:
            with self.subTest(change=change):
                old, item[key] = item[key], value
                self.assert_foreign()
                item[key] = old

    def test_requires_matching_node_installed_phase_and_exclusive_lock(self):
        before = self.image()
        self.assertEqual(self.call('reattest-runtime', nodeId='f' * 24), (70, '', 'DIRECT_RUNTIME_FOREIGN_CHANGE\n'))
        self.assertEqual(self.call('reattest-runtime', currentUsers=[]), (70, '', 'DIRECT_CANDIDATE_INVALID\n'))
        with self.directory(self.h['SYSTEM']) as fd:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            self.assertEqual(self.reattest(), (75, '', ''))
        self.assertEqual(self.image(), before)
        self.manifest['phase'] = 'applying'
        self.save_manifest()
        self.assert_foreign()

    def test_same_boot_restart_does_not_reauthorize_install_rollback(self):
        self.boot = self.old_boot
        self.assertEqual(self.reattest()[0], 0)
        self.request.pop('nodeId')
        before = self.image()
        self.assertEqual(self.call('rollback', baseline=self.h['digest'](self.h['encode'](self.manifest['before']))),
                         (70, '', 'DIRECT_ROLLBACK_DRIFT\n'))
        self.assertEqual(self.image(), before)

    def test_inspection_same_boot_requires_proven_epoch_difference(self):
        self.boot = self.old_boot
        xl = self.watch[1]
        self.manifest['runtime']['invocations'] = [self.units[n]['InvocationID'] for n in self.watch]
        self.save_manifest()
        before = self.image()
        params = dict(currentUsers=[], desiredUsers=[])
        self.assertEqual(self.call('inspect-chap', **params)[0], 0)
        self.units[xl]['InvocationID'] = '1' * 32
        self.assertEqual(self.call('inspect-chap', **params), (70, '', 'DIRECT_RUNTIME_REATTEST_REQUIRED\n'))
        self.assertEqual(self.image(), before)
        self.assertEqual(self.reattest()[0], 0)
        before = self.image()
        self.assertEqual(self.call('inspect-chap', **params)[0], 0)
        self.assertEqual(self.image(), before)
        self.units[xl]['FragmentPath'] = '/usr/lib/systemd/system/xl2tpd.service'
        self.assertEqual(self.call('inspect-chap', **params), (70, '', 'DIRECT_INSPECT_CHAP_PROJECTION_UNPROVED\n'))
        self.assertEqual(self.image(), before)

    def test_lost_manifest_write_acknowledgement_is_unknown(self):
        original_write = self.h['write']

        def lost_ack(*a, **kw):
            original_write(*a, **kw)
            raise OSError('fixture acknowledgement loss')

        self.h['write'] = lost_ack
        self.assertEqual(self.reattest(), (75, '', ''))
        self.assertEqual(self.h['read_manifest'](self.token)[2]['runtime']['boot'], self.boot)

    def test_read_actions_report_stale_epoch_without_write(self):
        before = self.image()
        for action in ('session-count', 'retirement-count', 'inspect-chap', 'prepare-remove', 'check-apply-network'):
            with self.subTest(action=action):
                extras = {'currentUsers': [], 'desiredUsers': []} if action == 'inspect-chap' else {}
                request = self.request
                if action == 'check-apply-network':
                    self.request = {k: v for k, v in request.items() if k != 'nodeId'}
                try:
                    self.assertEqual(self.call(action, **extras), (70, '', 'DIRECT_RUNTIME_REATTEST_REQUIRED\n'))
                finally:
                    self.request = request
        self.assertEqual(self.image(), before)


if __name__ == '__main__':
    unittest.main()
