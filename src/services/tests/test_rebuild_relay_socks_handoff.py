"""Exercise the DIRECT verifier with modeled socket I/O, not a listener."""
import runpy
import socket
import unittest
from pathlib import Path
from types import SimpleNamespace as NS

HOST = Path(__file__).resolve().parents[1] / 'rebuildRelayDirectHost.py'
PORT, PID, SIDE_PID = 18456, '42', '43'
LO = '127.0.0.1'
GREETING = b'\x05\x01\x00'
ASSOCIATE = b'\x05\x03\x00\x01' + bytes(6)
METHOD, HEADER, BOUND = b'\x05\x00', b'\x05\x00\x00\x01', b'\x7f\x00\x00\x01\xc4\x00'
REPLY = METHOD + HEADER + BOUND


def load_host():
    return runpy.run_path(str(HOST))['installed_runtime'].__globals__


def row(proto, address=LO, port=PORT, pid=PID):
    return proto, address, port, [pid]


class SocksHandoff(unittest.TestCase):
    def setUp(self):
        self.h = load_host()
        self.now = 100.0
        self.sockets = []
        self.command = self.h['command'] = lambda *_a, **_k: self.fail('unexpected host command')
        self.h.update(time=NS(monotonic=lambda: self.now), DEADLINE=200,
                      socket=NS(AF_INET=socket.AF_INET, SOCK_STREAM=socket.SOCK_STREAM,
                                socket=lambda *_: self.fail('unexpected socket open')))

    def stream(self, reply=REPLY, *, fragment=1, step=0.0, error=None):
        test = self

        class Control:
            def __init__(self, af, socktype):
                test.assertEqual((af, socktype), (socket.AF_INET, socket.SOCK_STREAM))
                self.reply = reply
                self.writes = []
                self.timeouts = []
                self.closed = 0
                test.sockets.append(self)

            def __enter__(self): return self

            def __exit__(self, *_): self.closed += 1

            def settimeout(self, remaining):
                test.assertGreater(remaining, 0)
                test.assertLessEqual(remaining, 1)
                self.timeouts.append(remaining)

            def connect(self, endpoint):
                test.assertEqual(endpoint, (LO, PORT))
                if error == 'connect': raise ConnectionRefusedError()

            def sendall(self, data):
                test.assertEqual(data, [GREETING, ASSOCIATE][len(self.writes)])
                self.writes.append(data)
                if error == 'send': raise BrokenPipeError()

            def recv(self, size):
                test.assertLessEqual(size, 6)
                test.now += step
                if error == 'recv': raise TimeoutError()
                n = min(size, fragment)
                chunk, self.reply = self.reply[:n], self.reply[n:]
                return chunk

        self.h['socket'].socket = Control

    def refused(self):
        return self.assertRaisesRegex(self.h['Refusal'], '^RUNTIME_UNPROVED$')

    def install_fixture(self, rows, *, sidecar=False, tproxy_udp=True):
        h = self.h
        x, b, xl, ike, net = (h[n] for n in ('X', 'B', 'XL', 'IKE', 'NET_UNIT'))
        units = {
            x: dict(InvocationID='main-new', MainPID=PID), b: dict(InvocationID='bridge-new', MainPID=SIDE_PID),
            xl: dict(InvocationID='lns-new', MainPID='44', UnitFileState='enabled', DropInPaths=h['DROP'],
                     Requires=net, After=net),
            ike: dict(InvocationID='ike-new', MainPID='45', UnitFileState='enabled'),
            net: dict(InvocationID='net-new', ActiveState='active', SubState='exited', FragmentPath=h['NET']),
        }
        profile = h['entry'](h['encode']({'inbounds': [{'tag': h['FOLLOW_RELAY_SOCKS'],
                             'listen': LO, 'protocol': 'socks', 'port': PORT}]}))
        after = {'net': object(), 'main': object() if sidecar else profile, 'starter': object()}
        if sidecar: after['bridge'] = profile
        before = dict(units={name: {**unit, 'InvocationID': 'old'} for name, unit in units.items()},
                      sockets=[['tcp', LO, 10085]])
        d, token = {'tproxyPort': 12345}, 'model'
        misc = [row('tcp', '0.0.0.0', 12345),
                *[row('udp', '0.0.0.0', port, pid) for port, pid in [(1701, '44'), (500, '45'), (4500, '45')]]]
        if tproxy_udp:
            misc.append(row('udp', '0.0.0.0', 12345))
        files = {'net': h['NET'], 'main': h['MAIN'], 'starter': h['NAMES']['starter']}
        if sidecar: files['bridge'] = h['BRIDGE']
        h.update(no_jobs=lambda _: None, neighbors=lambda *_: None, unit=units.__getitem__,
                 network_unit_loaded=lambda *_: True, legacy_network=lambda *_: False,
                 native_vpn=lambda *_: True, working=lambda _: True, sock_rows=lambda: rows + misc,
                 xray_argv=lambda unit, *_: unit['MainPID'], same_xray_dropin=lambda *_: None,
                 xray_users=lambda *_: before['sockets'], in_cgroup=lambda pid, unit: pid == unit['MainPID'],
                 network_projection=lambda *_: dict(rule=True, route=True, nft='policy'),
                 operation_files=lambda _: files, read={v: after[k] for k, v in files.items()}.__getitem__,
                 command=lambda *a: b'celerity-l2tp: modeled\n' if a == ('/usr/sbin/ipsec', 'statusall')
                 else self.command(*a), ike_include_matches=lambda *_: True, file_generations=lambda _: 'generations')
        return lambda: h['installed_runtime'](d, token, before, after)

    def test_new_install_and_verify_main_and_sidecar(self):
        for sidecar, pid in ((False, PID), (True, SIDE_PID)):
            with self.subTest(sidecar=sidecar):
                self.stream()
                check = self.install_fixture([row('tcp', pid=pid)], sidecar=sidecar)
                self.assertEqual(check()['nft'], 'policy')
                self.assertEqual(self.sockets[-1].writes, [GREETING, ASSOCIATE])
                self.assertEqual(self.sockets[-1].closed, 1)

    def test_bad_new_control_reply_is_runtime_unproved(self):
        replies = [b'', METHOD[:1], b'\x05\xff', b'\x05\x02', b'\x04\x00', METHOD + HEADER[:3],
                   METHOD + b'\x05\x07\x00\x01' + BOUND, METHOD + b'\x05\x00\x01\x01' + BOUND,
                   METHOD + b'\x05\x00\x00\x03' + BOUND, METHOD + b'\x05\x00\x00\x04' + BOUND,
                   REPLY[:-1], METHOD + HEADER + b'\x00' * 4 + BOUND[4:],
                   METHOD + HEADER + b'\x7f\x00\x00\x02' + BOUND[4:],
                   METHOD + HEADER + b'\xc0\x00\x02\x02' + BOUND[4:], REPLY[:-2] + bytes(2)]
        for reply in replies:
            with self.subTest(reply=reply):
                self.stream(reply)
                with self.refused(): self.install_fixture([row('tcp')])()
                self.assertEqual(self.sockets[-1].closed, 1)

    def test_transport_errors_close(self):
        for where in ('connect', 'send', 'recv'):
            with self.subTest(where=where):
                self.stream(error=where)
                with self.refused(): self.install_fixture([row('tcp')])()
                self.assertEqual(self.sockets[-1].closed, 1)

    def test_handoff_does_not_replace_tproxy_udp(self):
        self.stream()
        with self.refused(): self.install_fixture([row('tcp')], tproxy_udp=False)()
        self.assertFalse(self.sockets)

    def test_partial_reads_share_one_total_deadline_including_late_success(self):
        for step in (0.26, 0.09):  # Slow fragments, and the last otherwise-valid byte arriving late.
            with self.subTest(step=step):
                self.now = 100
                self.stream(step=step)
                with self.refused(): self.install_fixture([row('tcp')])()
                sock = self.sockets[-1]
                self.assertEqual(sock.closed, 1)
                self.assertLess(sock.timeouts[-1], sock.timeouts[0])
        self.now = self.h['DEADLINE']
        n = len(self.sockets)
        with self.refused(): self.install_fixture([row('tcp')])()
        self.assertEqual(len(self.sockets), n)

    def test_legacy_exact_and_conflicting_fixed_rows_never_open_a_probe(self):
        check = self.install_fixture([row('tcp'), row('udp')])
        self.assertEqual(check()['nft'], 'policy')
        for rows in ([row('tcp'), row('udp', pid=SIDE_PID)], [row('tcp'), row('udp', address='0.0.0.0')],
                     [row('tcp'), row('udp', address='[::]')], [row('tcp'), row('udp', address='127.0.0.2')],
                     [row('tcp'), row('udp'), row('udp')], [row('tcp'), row('udp'), row('udp', pid=SIDE_PID)],
                     [row('tcp'), row('tcp')], [row('tcp'), row('tcp', pid=SIDE_PID)],
                     [row('tcp', address='*'), row('udp')], [row('tcp', pid=SIDE_PID), row('udp')],
                     [row('tcp'), ('udp', LO, PORT, [])], [row('tcp'), ('udp', LO, PORT, [PID, SIDE_PID])],
                     [row('udp')], []):
            with self.subTest(rows=rows), self.refused(): self.install_fixture(rows)()
        self.assertFalse(self.sockets)

    def test_retained_bridge_keeps_other_listeners_and_legacy_layout(self):
        bridge = {'MainPID': SIDE_PID}
        other = row('udp', port=53111, pid=SIDE_PID)
        tcp = row('tcp', pid=SIDE_PID)
        udp = row('udp', pid=SIDE_PID)
        retained = self.h['removal_bridge_sockets']
        state = dict(retained_handoff=PORT, bridge_sockets=[list(r[:3]) for r in (tcp, other)])
        self.stream()
        retained(state, [other, tcp], bridge)
        self.assertEqual(self.sockets[-1].closed, 1)
        with self.refused(): retained(state, [tcp], bridge)
        self.stream(REPLY[:-1])
        with self.refused(): retained(state, [other, tcp], bridge)
        self.assertEqual(self.sockets[-1].closed, 1)
        state = dict(retained_handoff=PORT, bridge_sockets=[list(r[:3]) for r in (tcp, udp, other)])
        retained(state, [other, tcp, udp], bridge)
        with self.refused(): retained(state, [other, tcp], bridge)
        self.assertEqual(len(self.sockets), 2)


if __name__ == '__main__':
    unittest.main()
