"""Offline DIRECT admission regression; only the observations are modeled."""
import contextlib
import hashlib
import os
import io
import json
from pathlib import Path
import runpy
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / 'rebuildRelayDirectHost.py'
MACHINE = 'a' * 32
NETWORK = dict(clientCidr='10.255.1.0/24', tproxyPort=12345, fwmark=77, routeTable=177)
# ip -j -N emits a numeric priority, string table ID, and no srclen for all-source.
STOCK = dict(priority=220, src='all', table='220')
IDLE = 'Connections:\nSecurity Associations (0 up, 0 connecting):\n  none\n'
BUSY = 'Connections:\nSecurity Associations (1 up, 0 connecting):\n  existing[1]: ESTABLISHED\n'


class IkeAdmission(unittest.TestCase):
    def host(self, rules4=(), rules6=(), *, active=False, custom=False, status=IDLE, xfrm=False, bad_sockets=False):
        h = runpy.run_path(str(SOURCE))['dispatch'].__globals__
        xl, ike, x, b, net = (h[k] for k in ('XL', 'IKE', 'X', 'B', 'NET_UNIT'))
        base = dict(ActiveState='inactive', SubState='dead', MainPID='0', InvocationID='', LoadState='loaded',
                    NeedDaemonReload='no', PrivateNetwork='no', KillMode='control-group', User='', Group='',
                    UnitFileState='enabled', DropInPaths='', RequiredBy='', BoundBy='', ConsistsOf='',
                    PropagatesStopTo='', Conflicts='shutdown.target', ConflictedBy='', Requires='', Wants='',
                    BindsTo='', Upholds='')
        units = {n: dict(base, FragmentPath='/usr/lib/systemd/system/' + n) for n in (xl, ike, x, b, net)}
        units[xl]['ExecStart'] = '{ path=/usr/sbin/xl2tpd ; argv[]=/usr/sbin/xl2tpd -D ; }'
        units[ike]['ExecStart'] = '{ path=/usr/sbin/ipsec ; argv[]=/usr/sbin/ipsec start --nofork ; }'
        units[net].update(LoadState='not-found', FragmentPath='')
        if active:
            units[ike].update(ActiveState='active', SubState='running', MainPID='12', InvocationID='1' * 32,
                              ControlGroup='/system.slice/' + ike)
        if custom:
            units[ike]['DropInPaths'] = '/etc/systemd/system/strongswan-starter.service.d/operator.conf'
        files = {h['NAMES'][k]: h['entry'](v) for k, v in dict(main=b'{}', lns=b'', chap=b'', secrets=b'',
                 starter=b'config setup\ninclude /etc/ipsec.d/*.conf\n').items()}
        flags = ('/usr/sbin/ip', '-j', '-N')
        common = [dict(priority=p, src='all', table=str(t)) for p, t in [(0, 255), (32766, 254), (32767, 253)]]
        replies = {
            (*flags, '-4', 'rule', 'show'): h['encode']([*common, *rules4]),
            (*flags, '-6', 'rule', 'show'): h['encode']([*common[:2], *rules6]),
            (*flags, '-4', 'route', 'show', 'table', 'all'): b'[]',
            (*flags, '-4', 'addr', 'show'): b'[]',
            ('/usr/sbin/ipsec', 'statusall'): status.encode(),
            ('/usr/sbin/ip', 'xfrm', 'policy', 'list', 'nosock'): b'',
            ('/usr/sbin/ip', 'xfrm', 'policy', 'list'): b'',
            ('/usr/sbin/ip', 'xfrm', 'state', 'list', 'nokeys'): b'foreign-state' if xfrm else b'',
            ('/usr/bin/systemctl', '--no-pager', 'show-environment'): b'',
            ('/usr/bin/ps', '-ww', '-e', '-o', 'pid=', '-o', 'comm='): b'1 systemd\n500 ps\n',
            ('/usr/sbin/ip', '-j', '-details', 'link', 'show'): b'[{"ifname":"lo","link_type":"loopback"}]',
            **{('/usr/bin/dpkg-query', '-W', r'-f=${Status}\n${Conffiles}', package): b'install ok installed\n' + b''.join(
                f' {path} {hashlib.md5(h["raw"](files[path]), usedforsecurity=False).hexdigest()}\n'.encode()
                for name in names for path in (h['NAMES'][name],))
               for package, names in [('xl2tpd', ('lns',)), ('strongswan-starter', ('starter', 'secrets'))]},
        }
        calls, forbidden = [], []

        def unexpected(*args, **kwargs):
            forbidden.append(args)
            raise AssertionError(args)

        def command(*args, **kwargs):
            calls.append(args)
            return replies[args] if args in replies else unexpected(*args, **kwargs)

        self.addCleanup(self.assertEqual, forbidden, [])
        h.update(command=command, sc=unexpected, install=unexpected, write=unexpected, mkdir=unexpected,
                 rmdir=unexpected, enroll_boot=unexpected, no_jobs=lambda _: None,
                 require_machine=lambda machine: machine, package_no_pending=lambda: None,
                 fresh_udp_bound=lambda: False, missing_network_observers=lambda: (),
                 unit=lambda n: units.get(n, {'LoadState': 'not-found', 'ActiveState': 'inactive'}).copy(),
                 os=SimpleNamespace(geteuid=lambda: 0, umask=lambda _: None,
                                    fstat=lambda _: SimpleNamespace(st_dev=1, st_ino=17),
                                     stat=lambda *_a, **_kw: (_ for _ in ()).throw(FileNotFoundError()),
                                    path=SimpleNamespace(lexists=lambda _: False, split=os.path.split,
                                                         basename=os.path.basename, dirname=os.path.dirname),
                                    scandir=lambda _: contextlib.nullcontext(iter(()))),
                 directory=lambda _: contextlib.nullcontext(17), fcntl=SimpleNamespace(flock=lambda *_: None,
                            LOCK_EX=1, LOCK_NB=2), directory_absent=lambda _: True, read=lambda p, *_, **__: files.get(p),
                 preflight=lambda machine, *, fresh=False: dict(machineId=machine, ppp=True, unitsLoaded=True, masked=False),
                 observe_ppp_preparation=lambda: dict(missing=[], persist=False, builtin=[], policy='fixture'),
                 require_network_observers=lambda: None,
                 ike_include_matches=lambda *_: True, xray_users=lambda *_: [['tcp', '127.0.0.1', 8080]],
                 swan_inputs=lambda *_: 'fixture-tree', nft_tables=lambda: [], ppp_empty=lambda: True,
                 remove_generation=lambda path: None if path == h['BRIDGE'] else unexpected(path),
                 in_cgroup=lambda pid, _: pid == '13', boot=lambda: 'fixture-boot',
                 sock_rows=lambda: [('udp', '0.0.0.0', p, ['99' if bad_sockets else '13']) for p in (500, 4500)] if active else [])
        return h, calls

    def receipt(self, h, action):
        payload = dict(action=action, machineId=MACHINE, network=NETWORK, backupId='b' * 32, baseline='c' * 64)
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(sys, 'stdin', io.TextIOWrapper(io.BytesIO(json.dumps(payload).encode()))), \
                contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(stdout):
            result = h['main']()
        return result, stdout.getvalue(), stderr.getvalue()

    def assertRefused(self, code, **kwargs):
        h, calls = self.host(**kwargs)
        for action in ('prepare', 'check', 'install'):
            with self.subTest(action=action, code=code):
                prefix = 'DIRECT_NO_WRITE_' if action == 'install' else 'DIRECT_'
                self.assertEqual(self.receipt(h, action), (70, '', prefix + code + '\n'))
        return calls

    def test_native_idle_stock_shape_in_either_or_both_families(self):
        for r4, r6 in [([STOCK], []), ([], [STOCK]), ([STOCK], [dict(STOCK, table=220)])]:
            with self.subTest(rules=(r4, r6)):
                calls = self.assertRefused('IKE_ACTIVE_RULE_220', active=True, rules4=r4, rules6=r6)
                self.assertIn(('/usr/sbin/ipsec', 'statusall'), calls)
                self.assertIn(('/usr/sbin/ip', 'xfrm', 'state', 'list', 'nokeys'), calls)

    def test_conflicting_selectors_lookups_and_duplicate_rows(self):
        for family in ('rules4', 'rules6'):
            for rows in [[dict(STOCK, fwmark='0x1')], [dict(STOCK, table='221')],
                         [dict(STOCK, priority=221)], [STOCK, STOCK]]:
                with self.subTest(family=family, rows=rows):
                    self.assertRefused('RULE_220_CONFLICT', active=True, **{family: rows})
            self.assertRefused('RULE_220_CONFLICT', **{family: [STOCK]})

    def test_active_ike_without_idle_native_evidence(self):
        for options in (dict(custom=True), dict(status=BUSY), dict(status=IDLE.replace('0 connecting', '1 connecting')),
                        dict(status=IDLE.replace('Connections:\n', 'Connections:\n  existing: transport\n')),
                        dict(xfrm=True), dict(bad_sockets=True)):
            with self.subTest(options=options):
                self.assertRefused('IKE_ACTIVE_UNMANAGED', active=True, rules4=[STOCK], **options)
        self.assertRefused('IKE_ACTIVE_UNMANAGED', active=True)

    def test_stopped_native_clean_rpdb_can_prepare(self):
        h, calls = self.host()
        rc, stdout, stderr = self.receipt(h, 'prepare')
        self.assertEqual((rc, stderr), (0, ''))
        self.assertRegex(json.loads(stdout)['baseline'], r'^[a-f0-9]{64}$')
        self.assertNotIn(('/usr/sbin/ipsec', 'statusall'), calls)


if __name__ == '__main__':
    unittest.main()
