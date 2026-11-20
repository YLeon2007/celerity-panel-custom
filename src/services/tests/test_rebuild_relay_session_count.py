"""Stock-source-shaped observations, not a live VPN, install, or systemd test."""
import contextlib
import copy
import errno
import fcntl
import io
import ipaddress
from itertools import cycle
import json
import os
from pathlib import Path
import re
import runpy
import stat
import struct
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
from typing import Any
import unittest
from unittest.mock import Mock, patch

HOST = Path(__file__).resolve().parents[1] / 'rebuildRelayDirectHost.py'
REQUEST: dict[str, Any] = dict(action='session-count', machineId='a' * 32, backupId='b' * 32, nodeId='c' * 24,
                              network=dict(clientCidr='10.255.1.0/24', tproxyPort=12345, fwmark=77, routeTable=177))


def inventory(port, tid, sid, peer_tid, peer_sid, name, *, role='LNS', state=3, associated='Y'):
    return (f"  SESSION 'not-for-transport' 00000000/{port} {tid:04X}/{sid:04X} -> "
            f'{peer_tid:04X}/{peer_sid:04X} {state} {associated}\n'
            f'   0/0/-/-/{role} 00000000 0\n   0/0 0/0/0 0/0/0\n   interface {name}\n').encode()


def tunnel(tid):
    return f"\nTUNNEL 'tunl {tid}', Y 3\n 00000000 0/0/0 0/0/0\n".encode()


def argv(tid, sid, peer, fd=10):
    return '\0'.join(('/usr/sbin/pppd', 'plugin', 'pppol2tp.so', 'pppol2tp', str(fd), 'pppol2tp_lns_mode',
                      'pppol2tp_tunnel_id', str(tid), 'pppol2tp_session_id', str(sid), 'passive', 'nodetach',
                      '10.255.1.1:' + peer, 'auth', 'file', '/etc/ppp/options.xl2tpd', '')).encode()


def link(name, index, peer) -> dict[str, Any]:
    return dict(ifname=name, ifindex=index, link_type='ppp', flags=['UP', 'POINTOPOINT', 'LOWER_UP'],
                addr_info=[dict(family='inet', local='10.255.1.1', address=peer, prefixlen=32, scope='global')])


class SessionCount(unittest.TestCase):
    def setUp(self):
        self.g = runpy.run_path(str(HOST))['main'].__globals__
        self.sample_fn = self.g['session_sample']
        self.pool = tuple(ipaddress.IPv4Address(x) for x in ('10.255.1.1', '10.255.1.10', '10.255.1.19'))
        self.owner = ('boot', 'invocation', 500, [1, 2, 3], 'manifest-digest', {}, {}, self.pool)
        self.pids = [500, 501, 502]
        self.peers = {501: '10.255.1.10', 502: '10.255.1.11'}
        self.foreign = inventory(3193, 2, 30, 4, 40, 'ppp19')
        self.data: bytes | None = (self.g['SESSION_L2TP_HEADER'] + tunnel(1)
                     + inventory(1701, 1, 21, 4, 41, 'ppp1') + inventory(1701, 1, 22, 4, 42, 'ppp2')
                     + tunnel(2) + self.foreign)
        self.links = [link('ppp19', 19, self.peers[501]), link('ppp1', 1, self.peers[501]), link('ppp2', 2, self.peers[502])]
        self.refusal = self.g['Refusal']

    @contextlib.contextmanager
    def proc(self, _proc, pid, main, _binaries, watch):
        watch()
        buf = b'/usr/sbin/xl2tpd\0-D\0' if pid == main else argv(1, pid - 480, self.peers[pid])
        yield pid, pid + 10, buf

    def ppp(self, _libc, task, pfd, l2fd, main, tid, sid):
        self.assertEqual((task, pfd, l2fd, main, tid), (pfd, task, 10, 500, 1))
        return task - 500, (tid, sid, 4, sid + 20), task + 100

    def read(self, _fd, name, maximum):
        self.assertEqual((name, maximum), ('self/net/pppol2tp', 2**20))
        if self.data is None:
            raise FileNotFoundError('not-for-transport')
        return self.data

    def command(self, *args, **kwargs):
        self.assertEqual(args, ('/usr/sbin/ip', '-j', '-4', '-details', 'addr', 'show'))
        self.assertEqual(kwargs, {'quiet': True})
        return json.dumps(self.links).encode()

    def sample(self, **kwargs):
        source = dict(session_cgroup=lambda _: self.pids, session_process=self.proc,
                      session_kernel=self.ppp, session_read=self.read, session_pid_stamp=lambda name, pid: [1, pid, 2],
                      command=self.command)
        with patch.dict(self.g, source | kwargs):
            return self.sample_fn(None, 100, 101, self.owner, lambda pid: pid, lambda: None)

    def test_two_and_foreign_same_pool(self):
        start, rows = self.sample()
        self.assertEqual(start, 510)
        self.assertEqual([row[3] for row in rows], [501, 502])

    def test_positive_sample_uses_real_named_ip_json(self):
        parent = os.environ.get('C3_TEST_SESSION_PARENT_NETNS')
        if parent is None:
            unshare = '/usr/bin/unshare'
            ip = '/usr/sbin/ip'
            if not all(Path(path).exists() for path in (unshare, ip, '/dev/net/tun')):
                self.skipTest('unshare, iproute2 and /dev/net/tun required')
            flags = [unshare, '--user', '--map-root-user', '--net']
            probe = subprocess.run([*flags, '/usr/bin/true'], capture_output=True, timeout=4)
            if probe.returncode:
                self.skipTest('private user/network namespace unavailable')
            replay = subprocess.run([*flags, sys.executable, '-I', '-B', str(Path(__file__).resolve()),
                                     f'{type(self).__name__}.{self._testMethodName}'],
                                    env={'C3_TEST_SESSION_PARENT_NETNS': os.readlink('/proc/self/ns/net'),
                                         'LC_ALL': 'C'}, text=True, capture_output=True, timeout=12)
            self.assertEqual(replay.returncode, 0, replay.stderr)
            if 'OK (skipped=1)' in replay.stderr:
                self.skipTest('TUN fixture unavailable in private netns')
            self.assertRegex(replay.stderr, r'(?m)^OK$')
            return

        # Exercise the real iproute2 formatter with an ARPHRD_PPP link in a
        # throwaway netns. TUN supplies the link metadata, not a live PPP/L2TP
        # session; process, socket and PPP inventories below remain modeled.
        self.assertNotEqual(parent, os.readlink('/proc/self/ns/net'))
        ip = '/usr/sbin/ip'

        def dump(*args):
            return json.loads(subprocess.check_output([ip, '-j', *args], timeout=3))

        self.assertEqual([link['ifname'] for link in dump('link', 'show')], ['lo'])
        try:
            tun = os.open('/dev/net/tun', os.O_RDWR)
        except PermissionError as err:
            self.skipTest(f'TUN device unavailable: {err.errno}')
        self.addCleanup(os.close, tun)
        try:
            # TUNSETIFF with IFF_TUN|IFF_NO_PI; TUNSETLINK with ARPHRD_PPP.
            fcntl.ioctl(tun, 0x400454ca, struct.pack('16sH22x', b'ppp1', 0x1001))
            fcntl.ioctl(tun, 0x400454cd, 512)
        except OSError as err:
            if err.errno not in (errno.EACCES, errno.EPERM, errno.ENOTTY, errno.EOPNOTSUPP):
                raise
            self.skipTest(f'TUN fixture unavailable: {err.errno}')
        subprocess.run([ip, 'link', 'set', 'ppp1', 'up'], check=True, timeout=3)
        subprocess.run([ip, '-4', 'addr', 'add', '10.255.1.1', 'peer', '10.255.1.10/32', 'dev', 'ppp1'],
                       check=True, timeout=3)
        args = ('-4', '-details', 'addr', 'show')
        numeric, = dump('-N', *args, 'dev', 'ppp1')
        self.assertEqual(numeric['addr_info'][0]['scope'], '0')
        self.assertNotEqual(numeric['link_type'], 'ppp')
        with self.assertRaises(self.refusal):
            self.g['session_links']([numeric], 'ppp1', '10.255.1.1', '10.255.1.10')

        self.pids = [500, 501]
        self.data = (self.g['SESSION_L2TP_HEADER'] + tunnel(1) + inventory(1701, 1, 21, 4, 41, 'ppp1'))
        calls = []
        command = self.g['command']

        def real_command(*argv, **kwargs):
            raw = command(*argv, **kwargs)
            calls.append((argv, kwargs, json.loads(raw)))
            return raw

        start, rows = self.sample(command=real_command)
        self.assertEqual(start, 510)
        self.assertEqual([row[3] for row in rows], [501])
        (argv, kwargs, observed), = calls
        self.assertEqual(argv, (ip, '-j', *args))
        self.assertEqual(kwargs, {'quiet': True})
        selected, = [link for link in observed if link['ifname'] == 'ppp1']
        self.assertEqual((selected['link_type'], selected['addr_info'][0]['scope']), ('ppp', 'global'))

    def test_zero_with_control_socket_and_foreign(self):
        self.pids = [500]
        self.data = self.g['SESSION_L2TP_HEADER'] + tunnel(1) + tunnel(2) + self.foreign
        self.assertEqual(self.sample(command=Mock(side_effect=AssertionError)), (510, []))

    def test_header_only_can_certify_idle(self):
        self.pids = [500]
        self.data = self.g['SESSION_L2TP_HEADER']
        self.assertEqual(self.sample(), (510, []))

    def test_missing_or_partial_source_is_not_zero(self):
        self.pids = [500]
        self.data = None
        with self.assertRaises(FileNotFoundError):
            self.sample()
        for data in (b'', self.g['SESSION_L2TP_HEADER'] + tunnel(1)[:-1]):
            with self.subTest(data=data), self.assertRaises(self.refusal):
                self.data = data
                self.sample()

    def test_unjoined_owned_session_is_not_zero(self):
        self.pids = [500]
        with self.assertRaises(self.refusal):
            self.sample()

    def test_unjoined_process_or_late_cgroup_member_refuses(self):
        with self.assertRaises(PermissionError):
            self.sample(session_kernel=Mock(side_effect=PermissionError('not-for-transport')))
        with self.assertRaises(self.refusal):
            self.sample(session_cgroup=Mock(side_effect=[self.pids, self.pids + [510]]))

    def test_link_down_or_unexpected_address_refuses(self):
        self.links[1]['flags'].remove('UP')
        with self.assertRaises(self.refusal):
            self.sample()
        self.links[1] = link('ppp1', 1, '10.255.1.18')
        with self.assertRaises(self.refusal):
            self.sample()

    def test_pid_stamp_mismatch_refuses(self):
        stamp = self.g['session_pid_stamp']
        with patch.dict(self.g, dict(remove_generation=lambda p: [1, 2, 3], read=lambda p, cap: self.g['entry'](b'502\n'))):
            with self.assertRaises(self.refusal):
                stamp('ppp1', 501)

    def test_l2tp_row_duplicate_and_not_bound_refuse(self):
        parse = self.g['session_l2tp_interfaces']
        keys = {(1, 21, 4, 41), (1, 22, 4, 42)}
        data = self.data
        assert data is not None
        malformed = (data.replace(tunnel(2), inventory(1701, 1, 21, 4, 41, 'ppp1') + tunnel(2)),
                     data.replace(b'0004/002A 3 Y', b'0004/002A 1 Y'),
                     data.replace(b'interface ppp1', b'interface (null)'), data.replace(tunnel(1), b''))
        for case in malformed:
            with self.subTest(case=case != self.data), self.assertRaises(self.refusal):
                parse(case, keys)

    def test_cgroup_file_parser_real_ordinary_files(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            procs, status = path / 'cgroup.procs', path / 'cgroup.stat'
            procs.write_bytes(b'502\n500\n501\n')
            status.write_bytes(b'nr_descendants 0\nnr_dying_descendants 0\n')
            fd = os.open(temp, os.O_RDONLY | os.O_DIRECTORY)
            try:
                self.assertEqual(self.g['session_cgroup'](fd), self.pids)
                for bad in (b'500\n500\n', b'', b'500\n502'):
                    procs.write_bytes(bad)
                    with self.assertRaises(self.refusal):
                        self.g['session_cgroup'](fd)
                procs.write_bytes(b'500\n')
                status.write_bytes(b'nr_descendants 1\nnr_dying_descendants 0\n')
                with self.assertRaises(self.refusal):
                    self.g['session_cgroup'](fd)
            finally:
                os.close(fd)

    def test_untrusted_argv_or_out_of_pool_refuses(self):
        parse = self.g['session_ppp_argv']
        for case in (argv(1, 21, '10.255.1.21'), argv(1, 21, self.peers[501]) + b'debug\0',
                     b'/usr/sbin/pppd\0/dev/pts/2\0', argv(1, 0, self.peers[501])):
            with self.assertRaises(self.refusal):
                parse(case, self.pool)

    def test_owner_binds_installed_manifest_native_unit_and_file_generations(self):
        g = self.g
        machine, token = REQUEST['machineId'], REQUEST['backupId']
        manifest_path = g['manifest_path'](token)
        lns = (b'[global]\nport = 1701\n\n[lns default]\nip range = 10.255.1.10-10.255.1.19\n'
               b'local ip = 10.255.1.1\nrequire authentication = yes\npppoptfile = /etc/ppp/options.xl2tpd\nlength bit = yes\n')
        options = (b'auth\nrefuse-pap\nrefuse-chap\nrefuse-mschap\nrequire-mschap-v2\nrefuse-eap\nname l2tpd\n'
                   b'mtu 1400\nmru 1400\nnoipv6\nnodefaultroute\nms-dns 192.0.2.53\n')
        records = dict(lns=lns, options=options, drop=b'# drop', net=b'# network',
                       nft=f'create table inet {g["TABLE"]} {{\n    comment "{token}"\n'.encode())
        native = runpy.run_path(str(HOST.parents[1] / 'modules/relay-l2tp/node-artifacts/l2tp/ensure-xl2tpd-unit.py'))['UNIT']
        unit_file = g['SYSTEM'] + '/' + g['XL']
        files = {g['NAMES'][key]: g['entry'](record, 0o644) for key, record in records.items()}
        chap_path = g['NAMES']['chap']
        stock = b'# stock\n'
        begin = b'# BEGIN CELERITY MANAGED L2TP USERS\n'
        end = b'# END CELERITY MANAGED L2TP USERS\n'
        row = b'"alice" l2tpd "original" 10.255.1.10\n'
        installed_chap = stock + b'\n' + begin + row + end
        files[chap_path] = g['entry'](installed_chap)
        files[unit_file] = g['entry'](native, 0o644)
        files['/etc/machine-id'] = g['entry']((machine + '\n').encode(), 0o444)
        global_files = {path: g['entry'](path.encode(), 0o644) for path in g['SESSION_GLOBAL']}
        files.update(global_files)
        invocation = 'd' * 32
        info = dict(FragmentPath=unit_file, LoadState='loaded', ActiveState='active', SubState='running',
                    UnitFileState='enabled', MainPID='500', InvocationID=invocation, PrivateNetwork='no',
                    NeedDaemonReload='no', Type='simple', ControlGroup=g['SESSION_GROUP'], KillMode='control-group',
                    DropInPaths=g['DROP'], ExecStart='{ path=/usr/sbin/xl2tpd ; argv[]=/usr/sbin/xl2tpd -D ; pid=500 }',
                    Requires=g['NET_UNIT'] + ' ' + g['IKE'], After=g['NET_UNIT'] + ' ' + g['IKE'], User='root', Group='root')
        backup: dict[str, Any] = dict(phase='installed', machineId=machine, backupId=token, network=REQUEST['network'],
                      before=dict(boot='boot', units={g['XL']: {**info, 'UnitFileState': 'disabled'}}, installBoot=True,
                                  globalFiles=global_files, files={'chap': g['entry'](stock)}),
                      after={key: {**files[g['NAMES'][key]], 'data': g['digest'](value)} for key, value in records.items()},
                      runtime=dict(invocations=['xray', invocation], files={k: [1, 2, 3] for k in records}))
        backup['after']['chap'] = {**files[chap_path], 'data': g['digest'](installed_chap)}
        leaves = cycle([[], ['0000usepeerdns'], ['0000usepeerdns']])
        with patch.dict(g, dict(directory=lambda _: contextlib.nullcontext(50), unit=lambda _: info,
                                no_jobs=lambda _: None, read=lambda p, *_: files.get(p),
                                read_manifest=lambda _: (manifest_path, g['entry'](g['encode'](backup)), backup),
                                directory_absent=lambda _: True, boot=lambda: 'boot', remove_generation=lambda _: [1, 2, 3],
                                session_binary=lambda _: (1, 2, 3), sock_rows=lambda: [('udp', '*', 1701, ['500'])],
                                SESSION_GLOBAL={p: g['digest'](p.encode()) for p in global_files})), \
                patch('os.listdir', side_effect=lambda _: next(leaves)):
            self.assertEqual(g['session_owner'](REQUEST)[-1], self.pool)
            changed_chap = installed_chap.replace(b'"original"', b'"updated"') + b'# foreign \xff\r\n'
            with patch.dict(files, {chap_path: g['entry'](changed_chap)}):
                with self.assertRaises(self.refusal):
                    g['session_owner'](REQUEST)
                for password in ('original', 'updated'):
                    request = {**REQUEST, 'currentUsers': [dict(login='alice', password=password, ipAddress='10.255.1.10', enabled=True)]}
                    if password == 'original':
                        with self.assertRaises(self.refusal):
                            g['session_owner'](request)
                    else:
                        self.assertEqual(g['session_owner'](request)[-1], self.pool)
            for field, value in (('phase', 'applying'), ('machineId', 'e' * 32), ('backupId', 'f' * 32),
                                 ('network', {**REQUEST['network'], 'fwmark': 78})):
                with patch.dict(backup, {field: value}), self.assertRaises(self.refusal):
                    g['session_owner'](REQUEST)
            for field, value in (('InvocationID', 'f' * 32), ('ControlGroup', '/wrong.slice/xl2tpd.service'),
                                 ('DropInPaths', '/foreign/xl2tpd.conf'), ('ExecStart', info['ExecStart'].replace('-D', '-D -d'))):
                with patch.dict(info, {field: value}), self.assertRaises(self.refusal):
                    g['session_owner'](REQUEST)
            altered = copy.deepcopy(backup['runtime'])
            altered['files']['lns'] = [1, 2, 3.0]
            with patch.dict(backup, runtime=altered), self.assertRaises(self.refusal):
                g['session_owner'](REQUEST)
            altered = copy.deepcopy(backup['after'])
            altered['lns']['gid'] = False
            with patch.dict(backup, after=altered), self.assertRaises(self.refusal):
                g['session_owner'](REQUEST)

    def test_ppp_kernel_getters_and_ownership_failures(self):
        g = self.g
        abi = '=HIii16sHHHH'
        owner, mode, flags = 500, 0, 0

        def getsockname(fd, buf, length):
            self.assertEqual(fd, 110)
            struct.pack_into(abi, buf._obj, 0, 24, 1, owner, 12, b'\x02\x00', 1, 21, 4, 41)
            length._obj.value = struct.calcsize(abi)
            return 0

        def ioctl(fd, cmd, arg):
            if fd == 111:
                self.assertEqual(cmd, 0x80047456)
                raise OSError(errno.ENOTTY, 'channel')
            self.assertEqual(fd, 112)
            match cmd:
                case 0x80047456:
                    return struct.pack('=i', 1)
                case 0xc008744c:
                    return struct.pack('=ii', 0x21, mode)
                case 0x8004745a:
                    return struct.pack('=I', flags)
                case _:
                    self.fail('unexpected /dev/ppp operation')

        with patch.dict(g, session_dup=lambda _libc, _pfd, n: contextlib.nullcontext(n + 100)), \
                patch('os.fstat', side_effect=lambda n: SimpleNamespace(st_mode=stat.S_IFSOCK, st_ino=314) if n == 110
                      else SimpleNamespace(st_mode=stat.S_IFCHR, st_rdev=os.makedev(108, 0))), \
                patch('os.readlink', side_effect=lambda p, **_: 'socket:[314]' if p == 'fd/10' else '/dev/ppp'), \
                patch('os.listdir', return_value=['11', '12']), patch('os.open', return_value=9999), patch('os.close'), \
                patch('fcntl.ioctl', side_effect=ioctl):
            read = lambda: g['session_kernel'](SimpleNamespace(getsockname=getsockname), 101, 102, 10, 500, 1, 21)
            self.assertEqual(read(), (1, (1, 21, 4, 41), 314))
            owner = 503
            with self.assertRaises(self.refusal):
                read()
            owner, mode = 500, 1  # DROP
            with self.assertRaises(self.refusal):
                read()
            mode, flags = 0, 0x200
            with self.assertRaises(self.refusal):
                read()

    def test_main_never_exports_error_payload(self):
        main = self.g['main']
        stdin = io.TextIOWrapper(io.BytesIO(json.dumps(REQUEST).encode()))
        errors, output = io.StringIO(), io.StringIO()
        saved_umask = os.umask(0o077)
        self.addCleanup(os.umask, saved_umask)
        with patch.dict(self.g, {'read_session_count': Mock(side_effect=PermissionError('not-for-transport'))}), \
                patch('os.geteuid', return_value=0), patch('sys.stdin', stdin), patch('sys.stderr', errors), patch('sys.stdout', output):
            self.assertEqual(main(), 70)
        self.assertEqual(output.getvalue(), '')
        self.assertEqual(errors.getvalue(), 'DIRECT_SESSION_COUNT_UNPROVED\n')

    def test_bounded_public_receipt_with_modeled_inventory(self):
        """Real flock, rtnetlink subscription, and pidfd (this task); no live relay IO."""
        if not hasattr(os, 'pidfd_open'):
            self.skipTest('Linux pidfd required')
        expected = re.compile(r'[a-f0-9]{64}')
        pid = os.getpid()

        @contextlib.contextmanager
        def directory(_):
            fd = os.open(temp, os.O_RDONLY | os.O_DIRECTORY)
            try:
                yield fd
            finally:
                os.close(fd)

        def observation(_libc, _proc, _cg, owner, held, watch):
            self.assertIs(owner, self.owner)
            held(pid)
            watch()
            return self.sample()

        with tempfile.TemporaryDirectory() as temp, patch.dict(self.g, {
            'directory': directory, 'SESSION_GROUP': temp.removeprefix('/sys/fs/cgroup'), 'session_fs': lambda *_: None,
            'unit': lambda _: {'ActiveState': 'active', 'SubState': 'running', 'MainPID': str(pid)},
            'session_owner': lambda _: self.owner, 'session_sample': observation, 'DEADLINE': time.monotonic() + 10,
        }), patch('os.lstat', wraps=os.lstat) as stat_call:
            actual = os.stat(temp)
            stat_call.return_value = actual  # modeled cgroup pathname; held FD is real
            self.assertEqual(self.g['read_session_count'](REQUEST)['activeSessions'], 2)
            self.pids = [500]
            self.data = self.g['SESSION_L2TP_HEADER']
            zero = self.g['read_session_count'](REQUEST)
            self.assertEqual(set(zero), {'activeSessions', 'census'})
            self.assertEqual(zero['activeSessions'], 0)
            self.assertRegex(zero['census'], expected)
            self.data = None
            with self.assertRaises(FileNotFoundError):
                self.g['read_session_count'](REQUEST)


if __name__ == '__main__':
    unittest.main()
